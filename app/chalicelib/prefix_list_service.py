"""Prefix List service — EC2 client factory and prefix list operations.

Provides cross-account EC2 client creation with STS credential caching,
and prefix list lookup / check / add operations.
"""

import ipaddress
import os
import time
from datetime import datetime, timezone

import boto3
import requests
from botocore.config import Config
from botocore.exceptions import ClientError

_BOTO_CFG = Config(connect_timeout=5, read_timeout=8, retries={"max_attempts": 1})

MANAGED_BY_TAG = 'port-guardian'
PREFIX_LIST_NAME = 'port-guardian-whitelist'

# Widest block ever whitelisted: a wider RDAP allocation is clamped to this.
WIDEST_PREFIX_LEN = 16
# Used when RDAP is unavailable, or its data covers the IP in no block.
FALLBACK_PREFIX_LEN = 24

# Cache: {role_arn: (credentials_dict, expiry_timestamp)}
_sts_cache: dict = {}


# ---------------------------------------------------------------------------
# EC2 client factory
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
            RoleArn=role_arn, RoleSessionName='port-guardian-lambda'
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

def _fetch_rdap(ip):
    """Fetch RDAP data for ip. Returns parsed JSON dict or None."""
    try:
        resp = requests.get(
            f"https://rdap.arin.net/registry/ip/{ip}",
            timeout=6,
            headers={"User-Agent": "port-guardian/1.0"},
            allow_redirects=True,
        )
        resp.raise_for_status()
        return resp.json()
    except Exception:
        return None


def _summarize_range(start, end):
    """CIDR blocks covering the inclusive address range [start, end]."""
    return list(ipaddress.summarize_address_range(
        ipaddress.ip_address(start.strip()),
        ipaddress.ip_address(end.strip()),
    ))


def _rdap_candidates(data):
    """Allocation blocks described by an RDAP response's `handle`.

    `handle` is a range ('a - b'), a CIDR, or — for space registered directly to
    ARIN — an opaque id ('NET-52-0-0-0-1') that carries no network at all, in which
    case the caller falls back to a fixed width. The response also has a
    startAddress/endAddress pair that would cover that last case, but adopting it
    widens cloud-hosted client IPs from /24 to a clamped /16 of provider space, so
    it waits on per-provider /32 handling (see .dev/TODO.md).
    """
    handle = data.get("handle", "")
    if " - " in handle:
        return _summarize_range(*handle.split(" - ", 1))
    if "/" in handle:
        return [ipaddress.ip_network(handle, strict=False)]
    return []


def _rdap_cidr(data, ip):
    """Whitelist block for ip: its RDAP allocation block, clamped to /16.

    An address range summarizes into one or more blocks, and only the block that
    actually holds ip is usable as a whitelist entry — the first block often is
    not, and adding it succeeded while never matching the user's IP. So the chosen
    block is always verified to contain ip; if none does, or RDAP is unavailable,
    fall back to ip/24.
    """
    addr = ipaddress.ip_address(ip)
    net = None
    if data:
        try:
            net = next((n for n in _rdap_candidates(data) if addr in n), None)
        except (ValueError, TypeError):
            net = None
    if net is None:
        return str(ipaddress.ip_network(f"{ip}/{FALLBACK_PREFIX_LEN}", strict=False))
    if net.prefixlen < WIDEST_PREFIX_LEN:
        net = ipaddress.ip_network(f"{ip}/{WIDEST_PREFIX_LEN}", strict=False)
    return str(net)


def get_bgp_prefix(ip):
    """Return ISP allocation block via RDAP, capped at /16. Falls back to /24."""
    return _rdap_cidr(_fetch_rdap(ip), ip)


def _rdap_org(data):
    """Extract the ISP/org name from RDAP remarks, or '' if absent."""
    for r in (data or {}).get("remarks", []):
        if r.get("title") == "description" and r.get("description"):
            return r["description"][0]
    return ""


def get_ip_info(ip):
    """Return IP info dict from RDAP: org, network name, country, range, cidr."""
    data = _fetch_rdap(ip)
    info = {"ip": ip, "cidr": _rdap_cidr(data, ip)}
    if not data:
        return info
    info["country"] = data.get("country", "")
    info["name"] = data.get("name", "")
    start = data.get("startAddress", "")
    end = data.get("endAddress", "")
    if start and end:
        info["range"] = f"{start} - {end}"
    org = _rdap_org(data)
    if org:
        info["org"] = org
    return info


# ---------------------------------------------------------------------------
# Prefix List operations
# ---------------------------------------------------------------------------

def get_prefix_list_id(ec2_client):
    """Find the port-guardian managed prefix list ID by name."""
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


PIN_MARKER = '[PIN]'


def is_pinned(description):
    """A pinned entry (description contains [PIN]) is never FIFO-evicted."""
    return PIN_MARKER in (description or '')


def _parse_entry_timestamp(description):
    """Parse the trailing ISO8601 token of an entry description, for FIFO ordering.

    Any leading words are tolerated, so '[Guard] CN China Mobile <ts>', the
    '[PIN] '-prefixed variant and legacy 'port-guardian <ts>' all parse. A
    description with no parseable token (a hand-created entry) sorts oldest and is
    evicted first — pin anything manually added that must survive.
    """
    token = (description or '').rsplit(' ', 1)[-1]
    try:
        dt = datetime.fromisoformat(token.replace('Z', '+00:00'))
    except ValueError:
        # aware sentinel so min() never mixes naive/aware in the FIFO path
        return datetime.min.replace(tzinfo=timezone.utc)
    # Force aware UTC — date-only tokens (e.g. '2026-03-24') parse as naive.
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


# Eviction threshold learned from AWS after a config-vs-MaxEntries mismatch: {pl_id: real MaxEntries}
_max_entries_override: dict = {}


def _eviction_threshold(prefix_list_id):
    """Configured max_entries (MAX_ENTRIES env), unless a real-MaxEntries override was learned."""
    configured = int(os.environ.get('MAX_ENTRIES', '20'))
    return _max_entries_override.get(prefix_list_id, configured)


def add_ip_to_prefix_list(ec2_client, prefix_list_id, ip):
    """Add BGP prefix for ip to the prefix list with FIFO eviction.

    Eviction triggers at the CONFIGURED threshold (decoupled from the PL's real
    MaxEntries). If config exceeds the real capacity and the add fails, learn the
    real value for subsequent calls and raise a clear error for this one.
    """
    if check_ip_in_prefix_list(ec2_client, prefix_list_id, ip):
        return 'already_exists'

    rdap = _fetch_rdap(ip)
    cidr = _rdap_cidr(rdap, ip)
    country = (rdap or {}).get('country', 'unknown') or 'unknown'
    isp = ' '.join(_rdap_org(rdap).split()[:2])  # e.g. 'China Mobile Peoples Telephone...' -> 'China Mobile'
    ts = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    description = f'[Guard] {country} {isp} {ts}'.replace('  ', ' ')

    resp = ec2_client.describe_managed_prefix_lists(
        PrefixListIds=[prefix_list_id]
    )
    pl = resp['PrefixLists'][0]
    version = pl['Version']
    threshold = _eviction_threshold(prefix_list_id)

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

    if len(entries) >= threshold:
        evictable = [e for e in entries if not is_pinned(e.get('Description', ''))]
        if not evictable:
            raise ValueError(
                f'prefix list full ({len(entries)}/{threshold}) and all entries are '
                f'pinned ([PIN]); cannot add {cidr} — unpin an entry or raise max_entries'
            )
        oldest = min(evictable, key=lambda e: _parse_entry_timestamp(e.get('Description', '')))
        modify_args['RemoveEntries'] = [{'Cidr': oldest['Cidr']}]

    try:
        ec2_client.modify_managed_prefix_list(**modify_args)
    except ClientError:
        real_max = pl['MaxEntries']
        if 'RemoveEntries' not in modify_args and len(entries) >= real_max:
            # Config said there was room but the PL is actually full: learn the real
            # capacity so the next add evicts correctly, and surface the mismatch.
            _max_entries_override[prefix_list_id] = real_max
            raise ValueError(
                f'max_entries config ({threshold}) exceeds prefix list MaxEntries '
                f'({real_max}); now using {real_max} — retry the add'
            )
        raise
    return 'added'


def get_all_entries(ec2_client, prefix_list_id):
    """Return all entries in the prefix list."""
    entries = []
    paginator = ec2_client.get_paginator('get_managed_prefix_list_entries')
    for page in paginator.paginate(PrefixListId=prefix_list_id):
        entries.extend(page.get('Entries', []))
    return entries


def remove_cidr_from_prefix_list(ec2_client, prefix_list_id, cidr):
    """Remove a CIDR entry from the prefix list."""
    resp = ec2_client.describe_managed_prefix_lists(PrefixListIds=[prefix_list_id])
    version = resp['PrefixLists'][0]['Version']
    ec2_client.modify_managed_prefix_list(
        PrefixListId=prefix_list_id,
        CurrentVersion=version,
        RemoveEntries=[{'Cidr': cidr}],
    )


def set_pin(ec2_client, prefix_list_id, cidr, pinned):
    """Add or remove the [PIN] marker on a CIDR's description.

    No rename API, but AddEntries with an already-present CIDR overwrites its
    Description in place (verified against a live prefix list) — no RemoveEntries,
    no remove-then-add, no waiting out modify-in-progress between two calls.
    """
    resp = ec2_client.describe_managed_prefix_lists(PrefixListIds=[prefix_list_id])
    pl = resp['PrefixLists'][0]
    entries = get_all_entries(ec2_client, prefix_list_id)
    entry = next((e for e in entries if e['Cidr'] == cidr), None)
    if entry is None:
        raise ValueError(f'{cidr} not found in prefix list')

    desc = entry.get('Description', '')
    if pinned and not is_pinned(desc):
        new_desc = f'{PIN_MARKER} {desc}'.strip()
    elif not pinned and is_pinned(desc):
        new_desc = ' '.join(desc.replace(PIN_MARKER, '').split())
    else:
        return  # already in the desired state

    ec2_client.modify_managed_prefix_list(
        PrefixListId=prefix_list_id,
        CurrentVersion=pl['Version'],
        AddEntries=[{'Cidr': cidr, 'Description': new_desc}],
    )
