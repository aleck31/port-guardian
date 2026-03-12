"""Port Guardian — deployment and infrastructure setup.

Usage:
  python setup.py              Deploy chalice app (syncs config.yaml → config.json)
  python setup.py --sync-sg    Deploy + sync SG ingress rules
  python setup.py --init       Deploy + IAM role + prefix lists + SG sync
"""

import argparse
import json
import subprocess
import sys
from pathlib import Path

import boto3
import yaml

ROLE_NAME = 'sg-guardian-target-role'
PREFIX_LIST_NAME = 'sg-guardian-whitelist'
MANAGED_BY_KEY = 'ManagedBy'
MANAGED_BY_VALUE = 'sg-guardian'
POLICY_NAME = 'sg-guardian-prefix-list-policy'


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

def load_config():
    path = Path(__file__).resolve().parent.parent / 'config.yaml'
    if not path.exists():
        sys.exit(f'Config not found: {path}')
    with open(path) as f:
        return yaml.safe_load(f)


# ---------------------------------------------------------------------------
# EC2 client helpers
# ---------------------------------------------------------------------------

def ec2_client_primary(region):
    return boto3.client('ec2', region_name=region)


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
    chalice_dir = Path(__file__).resolve().parent.parent / 'chalice_app'
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
    config_path = Path(__file__).resolve().parent.parent / 'chalice_app' / '.chalice' / 'config.json'
    if not config_path.exists():
        import shutil
        shutil.copy(str(config_path) + '.example', config_path)
    chalice_cfg = json.loads(config_path.read_text())
    env = chalice_cfg['stages']['prod']['environment_variables']
    env['PRIMARY_ACCOUNT_ID'] = cfg['accounts']['primary']['id']
    env['SECONDARY_ACCOUNT_ID'] = cfg['accounts']['secondary']['id']
    env['TARGET_ROLE_ARN'] = cfg['accounts']['secondary']['role_arn']
    env['COGNITO_USER_POOL_ID'] = cfg['cognito']['user_pool_id']
    env['COGNITO_CLIENT_ID'] = cfg['cognito']['client_id']
    env['COGNITO_REGION'] = cfg['cognito']['region']
    env['TARGET_REGIONS'] = ','.join(cfg['accounts']['primary']['regions'])
    env['TARGET_PORTS'] = ','.join(str(p) for p in cfg.get('target_ports', [22, 3389]))
    config_path.write_text(json.dumps(chalice_cfg, indent=2) + '\n')



# ---------------------------------------------------------------------------
# Infrastructure helpers
# ---------------------------------------------------------------------------

def ensure_target_role(cfg, lambda_role_arn):
    secondary = cfg['accounts']['secondary']
    iam = boto3.Session(profile_name='lab').client('iam')

    try:
        iam.get_role(RoleName=ROLE_NAME)
        print(f'  IAM role {ROLE_NAME} already exists — skipped')
        return
    except iam.exceptions.NoSuchEntityException:
        pass

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
                'Action': 'ec2:DescribeManagedPrefixLists',
                'Resource': '*',
            },
        ],
    }

    iam.create_role(
        RoleName=ROLE_NAME,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Description='SG Guardian cross-account prefix list access',
    )
    iam.put_role_policy(
        RoleName=ROLE_NAME, PolicyName=POLICY_NAME,
        PolicyDocument=json.dumps(permissions_policy),
    )
    print(f'  Created IAM role {ROLE_NAME}')


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
    tag_key = cfg['target_tag']['key']
    tag_value = cfg['target_tag']['value']
    ports = cfg.get('target_ports', [22, 3389])

    for account_id, region, ec2 in get_all_ec2_clients(cfg):
        pl_id = find_prefix_list(ec2)
        if not pl_id:
            print(f'  {account_id}/{region}: no prefix list found — skipping')
            continue

        print(f'  {account_id}/{region} (prefix list {pl_id}):')

        # --- Add rules to tagged SGs ---
        tagged_sgs = ec2.describe_security_groups(
            Filters=[{'Name': f'tag:{tag_key}', 'Values': [tag_value]}]
        ).get('SecurityGroups', [])

        tagged_sg_ids = {sg['GroupId'] for sg in tagged_sgs}

        for sg in tagged_sgs:
            sg_id = sg['GroupId']
            # Remove stale port rules (ports referencing our PL but no longer in config)
            for rule in sg.get('IpPermissions', []):
                if rule.get('IpProtocol') != 'tcp':
                    continue
                rule_port = rule.get('FromPort')
                matching_pls = [p for p in rule.get('PrefixListIds', []) if p['PrefixListId'] == pl_id]
                if matching_pls and rule_port not in ports:
                    ec2.revoke_security_group_ingress(
                        GroupId=sg_id,
                        IpPermissions=[{
                            'IpProtocol': 'tcp',
                            'FromPort': rule_port,
                            'ToPort': rule.get('ToPort', rule_port),
                            'PrefixListIds': matching_pls,
                        }],
                    )
                    print(f'    {sg_id} port {rule_port} ← {pl_id} — removed (not in config)')
            # Add missing port rules
            for port in ports:
                has_rule = any(
                    r.get('IpProtocol') == 'tcp'
                    and r.get('FromPort') == port
                    and r.get('ToPort') == port
                    and any(p['PrefixListId'] == pl_id for p in r.get('PrefixListIds', []))
                    for r in sg.get('IpPermissions', [])
                )
                if has_rule:
                    print(f'    {sg_id} port {port} ← {pl_id} — exists')
                    continue
                try:
                    ec2.authorize_security_group_ingress(
                        GroupId=sg_id,
                        IpPermissions=[{
                            'IpProtocol': 'tcp',
                            'FromPort': port,
                            'ToPort': port,
                            'PrefixListIds': [{'PrefixListId': pl_id, 'Description': 'sg-guardian'}],
                        }],
                    )
                    print(f'    {sg_id} port {port} ← {pl_id} — added')
                except Exception as e:
                    print(f'    {sg_id} port {port} ← {pl_id} — ERROR: {e}')

        # --- Remove stale rules from untagged SGs ---
        # Find all SGs that reference our prefix list in ingress
        all_sgs_with_pl = ec2.describe_security_groups(
            Filters=[{'Name': 'ip-permission.prefix-list-id', 'Values': [pl_id]}]
        ).get('SecurityGroups', [])

        for sg in all_sgs_with_pl:
            sg_id = sg['GroupId']
            if sg_id in tagged_sg_ids:
                continue
            # Build list of rules to revoke (only those referencing our prefix list)
            rules_to_revoke = []
            for rule in sg.get('IpPermissions', []):
                matching_pls = [p for p in rule.get('PrefixListIds', []) if p['PrefixListId'] == pl_id]
                if matching_pls:
                    rules_to_revoke.append({
                        'IpProtocol': rule['IpProtocol'],
                        'FromPort': rule.get('FromPort', -1),
                        'ToPort': rule.get('ToPort', -1),
                        'PrefixListIds': matching_pls,
                    })
            if rules_to_revoke:
                ec2.revoke_security_group_ingress(
                    GroupId=sg_id, IpPermissions=rules_to_revoke,
                )
                print(f'    {sg_id} — removed {len(rules_to_revoke)} stale rule(s)')



# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description='SG Guardian setup')
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--init', action='store_true', help='Full init: deploy + IAM + prefix lists + SG sync')
    group.add_argument('--sync-sg', action='store_true', help='Sync SG ingress rules')
    args = parser.parse_args()

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
