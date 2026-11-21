"""Port Guardian — deployment and infrastructure setup.

Usage:
  python setup.py              Deploy chalice app (syncs config.yaml → config.json)
  python setup.py --sync-sg    Deploy + sync SG ingress rules
  python setup.py --init       Deploy + IAM role + prefix lists + SG sync
  --profile NAME               AWS profile for the primary account (default: default creds)
"""

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

import boto3
import yaml

ROLE_NAME = 'port-guardian-target-role'
PREFIX_LIST_NAME = 'port-guardian-whitelist'
MANAGED_BY_KEY = 'ManagedBy'
MANAGED_BY_VALUE = 'port-guardian'
POLICY_NAME = 'port-guardian-prefix-list-policy'


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

def load_config():
    path = Path(__file__).resolve().parent / 'config.yaml'
    if not path.exists():
        sys.exit(f'Config not found: {path}')
    with open(path) as f:
        return yaml.safe_load(f)


# ---------------------------------------------------------------------------
# EC2 client helpers
# ---------------------------------------------------------------------------

# Primary-account profile; None → default credentials. Set from --profile in main().
PRIMARY_PROFILE = None


def primary_session():
    return boto3.Session(profile_name=PRIMARY_PROFILE) if PRIMARY_PROFILE else boto3


def ec2_client_primary(region):
    return primary_session().client('ec2', region_name=region)


def ec2_client_secondary(region, role_arn):
    """For setup: use 'lab' profile. At Lambda runtime, AssumeRole is used instead."""
    return boto3.Session(profile_name='lab').client('ec2', region_name=region)


def get_all_ec2_clients(cfg):
    """Yield (account_id, region, ec2_client) for all 6 targets."""
    primary = cfg['accounts']['primary']
    secondary = cfg['accounts']['secondary']
    for r in primary['regions']:
        yield primary['id'], r, ec2_client_primary(r)
    for r in secondary['regions']:
        yield secondary['id'], r, ec2_client_secondary(r, secondary['role_arn'])


# ---------------------------------------------------------------------------
# Prefix list helpers
# ---------------------------------------------------------------------------

def find_prefix_list(ec2):
    resp = ec2.describe_managed_prefix_lists(
        Filters=[{'Name': 'prefix-list-name', 'Values': [PREFIX_LIST_NAME]}]
    )
    for pl in resp.get('PrefixLists', []):
        for tag in pl.get('Tags', []):
            if tag['Key'] == MANAGED_BY_KEY and tag['Value'] == MANAGED_BY_VALUE:
                return pl['PrefixListId']
    return None


# ---------------------------------------------------------------------------
# Command: deploy (default)
# ---------------------------------------------------------------------------

def chalice_deploy(cfg):
    """Run chalice deploy, return (Lambda role ARNs, Lambda function names) from deployed state.

    The region comes from config.yaml rather than the caller's shell: chalice
    resolves it through boto3, which otherwise needs AWS_DEFAULT_REGION or a region
    in ~/.aws/config and fails with "No region configured" when neither is set.
    """
    chalice_dir = Path(__file__).resolve().parent / 'app'
    env = {
        **os.environ,
        'AWS_DEFAULT_REGION': cfg.get('lambda', {}).get('deploy_region', 'ap-southeast-1'),
    }
    if PRIMARY_PROFILE:
        env['AWS_PROFILE'] = PRIMARY_PROFILE
    result = subprocess.run(
        ['uv', 'run', 'chalice', 'deploy', '--stage', 'prod'],
        cwd=chalice_dir, capture_output=True, text=True, env=env,
    )
    print(result.stdout)
    if result.stderr:
        print(result.stderr, file=sys.stderr)
    if result.returncode != 0:
        sys.exit(f'chalice deploy failed (exit {result.returncode})')

    # Read deployed state for reliable ARN extraction
    deployed_file = chalice_dir / '.chalice' / 'deployed' / 'prod.json'
    role_arns, function_names = [], []
    api_url = None
    if deployed_file.exists():
        deployed = json.loads(deployed_file.read_text())
        for res in deployed.get('resources', []):
            if res.get('resource_type') == 'iam_role':
                role_arns.append(res['role_arn'])
            if res.get('resource_type') == 'lambda_function':
                function_names.append(res['lambda_arn'].rsplit(':', 1)[-1])
            if res.get('resource_type') == 'rest_api':
                api_url = res.get('rest_api_url')

    print(f'\n  API URL:  {api_url or "not found"}')
    print(f'  Roles:    {", ".join(role_arns) or "not found"}')
    return role_arns, function_names


def ensure_log_retention(cfg, function_names):
    """Apply the configured retention to every deployed function's log group.

    Chalice's own `log_retention_in_days` cannot be used here: it derives the log
    group from the resource name ('<app>-<stage>-api_handler'), but the REST API
    handler's function is renamed to '<app>-<stage>' afterwards for back-compat and
    the log group name is not updated to match. Setting it would put retention on a
    log group nothing writes to and leave the real one never-expiring.
    """
    days = cfg.get('lambda', {}).get('log_retention_days')
    if not days:
        return
    region = cfg.get('lambda', {}).get('deploy_region', 'ap-southeast-1')
    logs = primary_session().client('logs', region_name=region)
    for name in function_names:
        log_group = f'/aws/lambda/{name}'
        groups = logs.describe_log_groups(logGroupNamePrefix=log_group)['logGroups']
        current = next(
            (g.get('retentionInDays') for g in groups if g['logGroupName'] == log_group),
            None,
        )
        if current == days:
            print(f'  Log retention already {days}d on {log_group}')
            continue
        try:
            logs.put_retention_policy(logGroupName=log_group, retentionInDays=days)
        except logs.exceptions.ResourceNotFoundException:
            # Lambda creates the group on first invocation; on a fresh deploy it may
            # not exist yet, and retention has to outlive that ordering.
            logs.create_log_group(logGroupName=log_group)
            logs.put_retention_policy(logGroupName=log_group, retentionInDays=days)
        print(f'  Log retention set to {days}d on {log_group} (was {current or "never expire"})')


def bounce_lambda(cfg):
    """Force a Lambda container roll so it drops cached STS creds and re-assumes the
    target role with the latest permissions. Needed after an IAM policy change, since
    deploy alone won't roll the container when the function config is unchanged."""
    region = cfg.get('lambda', {}).get('deploy_region', 'ap-southeast-1')
    fn = 'port-guardian-prod'
    lam = primary_session().client('lambda', region_name=region)
    env = lam.get_function_configuration(FunctionName=fn).get('Environment', {}).get('Variables', {})
    env['STS_CACHE_BUST'] = str(int(env.get('STS_CACHE_BUST', '0')) + 1)
    lam.update_function_configuration(FunctionName=fn, Environment={'Variables': env})
    lam.get_waiter('function_updated').wait(FunctionName=fn)
    print(f'  Lambda {fn} bounced (STS_CACHE_BUST={env["STS_CACHE_BUST"]})')


def sync_chalice_config(cfg):
    """Sync config.yaml values into .chalice/config.json environment variables."""
    config_path = Path(__file__).resolve().parent / 'app' / '.chalice' / 'config.json'
    if not config_path.exists():
        import shutil
        shutil.copy(str(config_path) + '.example', config_path)
    chalice_cfg = json.loads(config_path.read_text())
    # Rebuild env wholesale so removed keys don't linger from prior deploys.
    chalice_cfg['stages']['prod']['environment_variables'] = {
        'PRIMARY_ACCOUNT_ID': cfg['accounts']['primary']['id'],
        'SECONDARY_ACCOUNT_ID': cfg['accounts']['secondary']['id'],
        'TARGET_ROLE_ARN': cfg['accounts']['secondary']['role_arn'],
        'COGNITO_USER_POOL_ID': cfg['cognito']['user_pool_id'],
        'COGNITO_CLIENT_ID': cfg['cognito']['client_id'],
        'COGNITO_REGION': cfg['cognito']['region'],
        'ADMIN_GROUP': cfg['cognito']['admin_group'],
        'TARGET_REGIONS': ','.join(cfg['accounts']['primary']['regions']),
        'MAX_ENTRIES': str(cfg.get('max_entries', 20)),
        'MAX_PREFIX_LEN': str(cfg.get('max_prefix_len', 16)),
        'APP_VERSION': _project_version(),
    }
    config_path.write_text(json.dumps(chalice_cfg, indent=2) + '\n')


def _project_version():
    """Read version from pyproject.toml (single source of truth)."""
    text = (Path(__file__).resolve().parent / 'pyproject.toml').read_text()
    m = re.search(r'^version\s*=\s*"([^"]+)"', text, re.MULTILINE)
    return m.group(1) if m else 'dev'



# ---------------------------------------------------------------------------
# Infrastructure helpers
# ---------------------------------------------------------------------------

def _trust_policy(lambda_role_arns):
    return {
        'Version': '2012-10-17',
        'Statement': [{
            'Effect': 'Allow',
            'Principal': {'AWS': sorted(lambda_role_arns)},
            'Action': 'sts:AssumeRole',
        }],
    }


def _trusted_principals(role):
    principals = set()
    for st in role['AssumeRolePolicyDocument'].get('Statement', []):
        aws = st.get('Principal', {}).get('AWS', [])
        principals.update([aws] if isinstance(aws, str) else aws)
    return principals


def ensure_target_trust(lambda_role_arns):
    """Make the secondary account's role trust every deployed Lambda role.

    Each Chalice function gets its own role, so adding one (the expiry sweep) means
    a new principal must be trusted before it can reach the secondary account.
    Runs on every deploy; writes only when a deployed role is missing.
    """
    iam = boto3.Session(profile_name='lab').client('iam')
    try:
        role = iam.get_role(RoleName=ROLE_NAME)['Role']
    except iam.exceptions.NoSuchEntityException:
        print(f'  IAM role {ROLE_NAME} not found — run --init to create it')
        return
    if set(lambda_role_arns) <= _trusted_principals(role):
        print(f'  {ROLE_NAME} already trusts all {len(lambda_role_arns)} Lambda roles')
        return
    iam.update_assume_role_policy(RoleName=ROLE_NAME, PolicyDocument=json.dumps(_trust_policy(lambda_role_arns)))
    print(f'  {ROLE_NAME} trust updated to {", ".join(sorted(lambda_role_arns))}')


def ensure_target_role(cfg, lambda_role_arns):
    secondary = cfg['accounts']['secondary']
    iam = boto3.Session(profile_name='lab').client('iam')

    role_exists = True
    try:
        iam.get_role(RoleName=ROLE_NAME)
    except iam.exceptions.NoSuchEntityException:
        role_exists = False

    trust_policy = _trust_policy(lambda_role_arns)
    permissions_policy = {
        'Version': '2012-10-17',
        'Statement': [
            {
                'Sid': 'PrefixListReadWrite',
                'Effect': 'Allow',
                'Action': [
                    'ec2:GetManagedPrefixListEntries',
                    'ec2:ModifyManagedPrefixList',
                    'ec2:DescribeManagedPrefixLists',
                ],
                'Resource': f"arn:aws:ec2:*:{secondary['id']}:prefix-list/pl-*",
                'Condition': {
                    'StringEquals': {f'ec2:ResourceTag/{MANAGED_BY_KEY}': MANAGED_BY_VALUE}
                },
            },
            {
                'Sid': 'PrefixListDescribe',
                'Effect': 'Allow',
                'Action': [
                    'ec2:DescribeManagedPrefixLists',
                    'ec2:DescribeSecurityGroups',
                ],
                'Resource': '*',
            },
            {
                'Sid': 'SgAuthorizeTaggedOnly',
                'Effect': 'Allow',
                'Action': 'ec2:AuthorizeSecurityGroupIngress',
                'Resource': f"arn:aws:ec2:*:{secondary['id']}:security-group/*",
                'Condition': {
                    'Null': {'aws:ResourceTag/port-guardian': 'false'}
                },
            },
            {
                # Revoke needs no tag condition: the exit path removes rules from SGs
                # whose tag is already gone. Code only revokes rules referencing our PL.
                'Sid': 'SgRevokeAnySg',
                'Effect': 'Allow',
                'Action': 'ec2:RevokeSecurityGroupIngress',
                'Resource': f"arn:aws:ec2:*:{secondary['id']}:security-group/*",
            },
        ],
    }

    if not role_exists:
        iam.create_role(
            RoleName=ROLE_NAME,
            AssumeRolePolicyDocument=json.dumps(trust_policy),
            Description='Port Guardian cross-account prefix list access',
        )
    # Detect whether the inline policy actually changes before refreshing it, so callers
    # can skip the (slow) Lambda container bounce when permissions are unchanged.
    try:
        current = iam.get_role_policy(RoleName=ROLE_NAME, PolicyName=POLICY_NAME)['PolicyDocument']
    except iam.exceptions.NoSuchEntityException:
        current = None
    changed = current != permissions_policy
    iam.put_role_policy(
        RoleName=ROLE_NAME, PolicyName=POLICY_NAME,
        PolicyDocument=json.dumps(permissions_policy),
    )
    if not role_exists:
        state = 'created'
    elif changed:
        state = 'policy updated'
    else:
        state = 'policy unchanged'
    print(f'  IAM role {ROLE_NAME} {state}')
    return changed or not role_exists


def ensure_prefix_list(ec2, account_id, region, cfg):
    pl_id = find_prefix_list(ec2)
    if pl_id:
        print(f'  {account_id}/{region}: {pl_id} — exists')
        return pl_id

    resp = ec2.create_managed_prefix_list(
        PrefixListName=PREFIX_LIST_NAME,
        MaxEntries=cfg.get('max_entries', 20),
        AddressFamily='IPv4',
        TagSpecifications=[{
            'ResourceType': 'prefix-list',
            'Tags': [
                {'Key': MANAGED_BY_KEY, 'Value': MANAGED_BY_VALUE},
                {'Key': 'Name', 'Value': PREFIX_LIST_NAME},
            ],
        }],
    )
    pl_id = resp['PrefixList']['PrefixListId']
    print(f'  {account_id}/{region}: {pl_id} — created')
    return pl_id


# ---------------------------------------------------------------------------
# SG sync
# ---------------------------------------------------------------------------

def sync_sg_rules(cfg, allow_exit=False):
    """Reconcile SG ingress against the port-guardian tag (see chalicelib.sg_sync_service)."""
    sys.path.insert(0, str(Path(__file__).resolve().parent / 'app'))
    from chalicelib.sg_sync_service import reconcile_sg_rules

    tag_key = cfg['target_tag']['key']
    default_ports = cfg.get('target_ports', [22, 3389])
    pending_exits = 0

    for account_id, region, ec2 in get_all_ec2_clients(cfg):
        pl_id = find_prefix_list(ec2)
        if not pl_id:
            print(f'  {account_id}/{region}: no prefix list found — skipping')
            continue
        print(f'  {account_id}/{region} (prefix list {pl_id}):')
        for a in reconcile_sg_rules(ec2, pl_id, tag_key, default_ports, allow_exit=allow_exit):
            port = a["port"] if a["port"] is not None else '-'
            print(f'    {a["sg_id"]} port {port} ← {pl_id} — {a["action"]}')
            if a['action'].startswith('would_remove'):
                pending_exits += 1

    if pending_exits:
        print(f'\n  {pending_exits} rule(s) on untagged SGs NOT removed. Verify the tags were '
              f'meant to be gone (IaC runs can wipe them), then re-run with --allow-exit.')



# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description='Port Guardian setup')
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--init', action='store_true', help='Full init: deploy + IAM + prefix lists + SG sync')
    group.add_argument('--sync-sg', action='store_true', help='Sync SG ingress rules')
    parser.add_argument('--allow-exit', action='store_true',
                        help='Allow sync to revoke rules on untagged SGs (exit path); default only reports them')
    parser.add_argument('--profile', help='AWS profile for the primary account (default: default credentials)')
    args = parser.parse_args()

    global PRIMARY_PROFILE
    PRIMARY_PROFILE = args.profile

    cfg = load_config()
    sync_chalice_config(cfg)

    steps = []
    if args.init:
        steps = ['deploy', 'iam', 'prefix_lists', 'sync_sg']
    elif args.sync_sg:
        steps = ['deploy', 'sync_sg']
    else:
        steps = ['deploy']

    total = len(steps)
    step = 0

    if 'deploy' in steps:
        step += 1
        print(f'[{step}/{total}] Deploying chalice app...')
        role_arns, function_names = chalice_deploy(cfg)
        ensure_log_retention(cfg, function_names)
        if 'iam' not in steps:
            ensure_target_trust(role_arns)
        print()

    iam_changed = False
    if 'iam' in steps:
        step += 1
        print(f'[{step}/{total}] Ensuring IAM target role in secondary account...')
        if not role_arns:
            sys.exit('Could not parse Lambda role ARNs from chalice deploy output')
        iam_changed = ensure_target_role(cfg, role_arns)
        ensure_target_trust(role_arns)
        # IAM change lands after deploy, so the running Lambda still holds STS creds
        # signed under the old policy — bounce it before sync uses those creds.
        if iam_changed:
            print('  IAM permissions changed — bouncing Lambda to refresh cross-account creds...')
            bounce_lambda(cfg)
        print()

    if 'prefix_lists' in steps:
        step += 1
        print(f'[{step}/{total}] Creating Prefix Lists...')
        for account_id, region, ec2 in get_all_ec2_clients(cfg):
            ensure_prefix_list(ec2, account_id, region, cfg)
        print()

    if 'sync_sg' in steps:
        step += 1
        print(f'[{step}/{total}] Syncing Security Group rules...')
        sync_sg_rules(cfg, allow_exit=args.allow_exit)
        print()

    print('Done.')


if __name__ == '__main__':
    main()
