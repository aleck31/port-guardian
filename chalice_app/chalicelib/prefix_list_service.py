"""Prefix List service — EC2 client factory and prefix list operations.

Provides cross-account EC2 client creation with STS credential caching,
and prefix list lookup / check / add operations.
"""

import ipaddress
import os
import time
from datetime import datetime

import boto3
import requests
from botocore.config import Config

_BOTO_CFG = Config(connect_timeout=5, read_timeout=8, retries={"max_attempts": 1})

MANAGED_BY_TAG = 'sg-guardian'
PREFIX_LIST_NAME = 'sg-guardian-whitelist'
DESCRIPTION_PREFIX = 'sg-guardian'

# Cache: {role_arn: (credentials_dict, expiry_timestamp)}
_sts_cache: dict = {}


# ---------------------------------------------------------------------------
# T-3.1  EC2 client factory
# ---------------------------------------------------------------------------

def _get_cached_credentials(role_arn):
    """Return cached STS credentials if still valid (with 60s buffer)."""
    if role_arn in _sts_cache:
        creds, expiry = _sts_cache[role_arn]
        if time.time() < expiry - 60:
            return creds
    return None


def get_ec2_client(account_id, region):
    """Return an EC2 client for the given account/region.

    Primary account: direct client.
    Secondary account: STS AssumeRole with credential caching.
    """
    primary_account = os.environ.get('PRIMARY_ACCOUNT_ID', '')
    if account_id == primary_account:
        return boto3.client('ec2', region_name=region, config=_BOTO_CFG)

    role_arn = os.environ.get('TARGET_ROLE_ARN', '')
    creds = _get_cached_credentials(role_arn)
    if not creds:
        sts = boto3.client('sts', config=_BOTO_CFG)
        resp = sts.assume_role(
            RoleArn=role_arn, RoleSessionName='sg-guardian-lambda'
        )
        creds = resp['Credentials']
        expiry = creds['Expiration'].timestamp()
        _sts_cache[role_arn] = (creds, expiry)

    return boto3.client(
        'ec2', region_name=region, config=_BOTO_CFG,
        aws_access_key_id=creds['AccessKeyId'],
        aws_secret_access_key=creds['SecretAccessKey'],
        aws_session_token=creds['SessionToken'],
    )


# ---------------------------------------------------------------------------
# BGP route lookup
# ---------------------------------------------------------------------------

def get_bgp_prefix(ip):
    """Return ISP allocation block via RDAP, capped at /16. Falls back to /24 then /32."""
    import ipaddress as _ip
    try:
        resp = requests.get(
            f"https://rdap.arin.net/registry/ip/{ip}",
            timeout=6,
            headers={"User-Agent": "sg-guardian/1.0"},
            allow_redirects=True,
        )
        resp.raise_for_status()
        handle = resp.json().get("handle", "")
        if " - " in handle:
            start, end = handle.split(" - ", 1)
            cidrs = list(_ip.summarize_address_range(
                _ip.ip_address(start.strip()),
                _ip.ip_address(end.strip()),
            ))
            if cidrs:
                net = cidrs[0]
                if net.prefixlen < 16:
                    net = _ip.ip_network(f"{ip}/16", strict=False)
                return str(net)
        if "/" in handle:
            net = _ip.ip_network(handle, strict=False)
            if net.prefixlen < 16:
                net = _ip.ip_network(f"{ip}/16", strict=False)
            return str(net)
    except Exception:
        pass
    return str(_ip.ip_network(f"{ip}/24", strict=False))


# ---------------------------------------------------------------------------
# T-3.2  Prefix List operations
# ---------------------------------------------------------------------------

def get_prefix_list_id(ec2_client):
    """Find the sg-guardian managed prefix list ID by name."""
    resp = ec2_client.describe_managed_prefix_lists(
        Filters=[{'Name': 'prefix-list-name', 'Values': [PREFIX_LIST_NAME]}]
    )
    for pl in resp.get('PrefixLists', []):
        for tag in pl.get('Tags', []):
            if tag['Key'] == 'ManagedBy' and tag['Value'] == MANAGED_BY_TAG:
                return pl['PrefixListId']
    return None


def check_ip_in_prefix_list(ec2_client, prefix_list_id, ip):
    """Check whether any prefix list entry contains the IP."""
    addr = ipaddress.ip_address(ip)
    paginator = ec2_client.get_paginator('get_managed_prefix_list_entries')
    for page in paginator.paginate(PrefixListId=prefix_list_id):
        for entry in page.get('Entries', []):
            if addr in ipaddress.ip_network(entry['Cidr'], strict=False):
                return True
    return False


def _parse_entry_timestamp(description):
    """Parse ISO timestamp from description, or return datetime.min."""
    try:
        ts_str = description.split(DESCRIPTION_PREFIX, 1)[1].strip()
        return datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
    except Exception:
        return datetime.min


def add_ip_to_prefix_list(ec2_client, prefix_list_id, ip):
    """Add BGP prefix for ip to the prefix list with FIFO eviction."""
    if check_ip_in_prefix_list(ec2_client, prefix_list_id, ip):
        return 'already_exists'

    cidr = get_bgp_prefix(ip)
    description = f'{DESCRIPTION_PREFIX} {datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")}'

    resp = ec2_client.describe_managed_prefix_lists(
        PrefixListIds=[prefix_list_id]
    )
    pl = resp['PrefixLists'][0]
    version = pl['Version']
    max_entries = pl['MaxEntries']

    # Count current entries
    entries = []
    paginator = ec2_client.get_paginator('get_managed_prefix_list_entries')
    for page in paginator.paginate(PrefixListId=prefix_list_id):
        entries.extend(page.get('Entries', []))

    modify_args = {
        'PrefixListId': prefix_list_id,
        'CurrentVersion': version,
        'AddEntries': [{'Cidr': cidr, 'Description': description}],
    }

    if len(entries) >= max_entries:
        oldest = min(
            entries,
            key=lambda e: _parse_entry_timestamp(e.get('Description', '')),
        )
        modify_args['RemoveEntries'] = [{'Cidr': oldest['Cidr']}]

    ec2_client.modify_managed_prefix_list(**modify_args)
    return 'added'
