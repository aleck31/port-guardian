"""Port Guardian — deployment and infrastructure setup.

Usage:
  python setup.py              Deploy chalice app (syncs config.yaml → config.json)
  python setup.py --sync-sg    Deploy + sync SG ingress rules
  python setup.py --init       Deploy + IAM role + prefix lists + SG sync
  --profile NAME               AWS profile for the primary account (default: default creds)
"""

import argparse
import json
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


def ec2_client_primary(region):
    session = boto3.Session(profile_name=PRIMARY_PROFILE) if PRIMARY_PROFILE else boto3
    return session.client('ec2', region_name=region)


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

def chalice_deploy():
    """Run chalice deploy, return (role_arn, api_url) from deployed state."""
    chalice_dir = Path(__file__).resolve().parent / 'app'
    result = subprocess.run(
        ['uv', 'run', 'chalice', 'deploy', '--stage', 'prod'],
        cwd=chalice_dir, capture_output=True, text=True,
    )
    print(result.stdout)
    if result.stderr:
        print(result.stderr, file=sys.stderr)
    if result.returncode != 0:
        sys.exit(f'chalice deploy failed (exit {result.returncode})')

    # Read deployed state for reliable ARN extraction
    deployed_file = chalice_dir / '.chalice' / 'deployed' / 'prod.json'
    role_arn = None
    api_url = None
    if deployed_file.exists():
        deployed = json.loads(deployed_file.read_text())
        for res in deployed.get('resources', []):
            if res.get('resource_type') == 'iam_role':
                role_arn = res['role_arn']
            if res.get('resource_type') == 'rest_api':
                api_url = res.get('rest_api_url')

    print(f'\n  API URL:  {api_url or "not found"}')
    print(f'  Role ARN: {role_arn or "not found"}')
    return role_arn, api_url


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
        'TARGET_REGIONS': ','.join(cfg['accounts']['primary']['regions']),
        'MAX_ENTRIES': str(cfg.get('max_entries', 20)),
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

def ensure_target_role(cfg, lambda_role_arn):
    secondary = cfg['accounts']['secondary']
    iam = boto3.Session(profile_name='lab').client('iam')

    role_exists = True
    try:
        iam.get_role(RoleName=ROLE_NAME)
    except iam.exceptions.NoSuchEntityException:
        role_exists = False

    trust_policy = {
        'Version': '2012-10-17',
        'Statement': [{
            'Effect': 'Allow',
            'Principal': {'AWS': lambda_role_arn},
            'Action': 'sts:AssumeRole',
        }],
    }
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
                'Sid': 'SgRulesTaggedOnly',
                'Effect': 'Allow',
                'Action': [
                    'ec2:AuthorizeSecurityGroupIngress',
                    'ec2:RevokeSecurityGroupIngress',
                ],
                'Resource': f"arn:aws:ec2:*:{secondary['id']}:security-group/*",
                'Condition': {
                    'Null': {'aws:ResourceTag/port-guardian': 'false'}
                },
            },
        ],
    }

    if not role_exists:
        iam.create_role(
            RoleName=ROLE_NAME,
            AssumeRolePolicyDocument=json.dumps(trust_policy),
            Description='Port Guardian cross-account prefix list access',
        )
    # Always refresh the inline policy so permission additions propagate to existing roles.
    iam.put_role_policy(
        RoleName=ROLE_NAME, PolicyName=POLICY_NAME,
        PolicyDocument=json.dumps(permissions_policy),
    )
    print(f'  IAM role {ROLE_NAME} {"created" if not role_exists else "policy refreshed"}')


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

def sync_sg_rules(cfg):
    """Reconcile SG ingress against the port-guardian tag (see chalicelib.sg_sync_service)."""
    sys.path.insert(0, str(Path(__file__).resolve().parent / 'app'))
    from chalicelib.sg_sync_service import reconcile_sg_rules

    tag_key = cfg['target_tag']['key']
    default_ports = cfg.get('target_ports', [22, 3389])

    for account_id, region, ec2 in get_all_ec2_clients(cfg):
        pl_id = find_prefix_list(ec2)
        if not pl_id:
            print(f'  {account_id}/{region}: no prefix list found — skipping')
            continue
        print(f'  {account_id}/{region} (prefix list {pl_id}):')
        for a in reconcile_sg_rules(ec2, pl_id, tag_key, default_ports):
            port = a["port"] if a["port"] is not None else '-'
            print(f'    {a["sg_id"]} port {port} ← {pl_id} — {a["action"]}')



# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description='Port Guardian setup')
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--init', action='store_true', help='Full init: deploy + IAM + prefix lists + SG sync')
    group.add_argument('--sync-sg', action='store_true', help='Sync SG ingress rules')
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
        role_arn, _ = chalice_deploy()
        print()

    if 'iam' in steps:
        step += 1
        print(f'[{step}/{total}] Ensuring IAM target role in secondary account...')
        if not role_arn:
            sys.exit('Could not parse Lambda role ARN from chalice deploy output')
        ensure_target_role(cfg, role_arn)
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
        sync_sg_rules(cfg)
        print()

    print('Done.')


if __name__ == '__main__':
    main()
