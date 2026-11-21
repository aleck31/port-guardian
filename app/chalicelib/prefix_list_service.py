"""Prefix List service — EC2 client factory and prefix list operations.

Provides cross-account EC2 client creation with STS credential caching, the RDAP
and cloud-range lookup that picks a whitelist block, the add / remove / pin writes,
and the diff and sync used to make replica lists match the primary.
"""

import ipaddress
import os
import re
import time
from datetime import date, datetime, timedelta, timezone

import boto3
import requests
from botocore.config import Config
from botocore.exceptions import ClientError

_BOTO_CFG = Config(connect_timeout=5, read_timeout=8, retries={"max_attempts": 1})

MANAGED_BY_TAG = 'port-guardian'
PREFIX_LIST_NAME = 'port-guardian-whitelist'

# Default widest block ever whitelisted; overridden by MAX_PREFIX_LEN.
WIDEST_PREFIX_LEN = 16
# Used when RDAP is unavailable, or its data covers the IP in no block.
FALLBACK_PREFIX_LEN = 24
# Used for cloud-hosted clients, whose address does not move.
EXACT_PREFIX_LEN = 32

AWS_IP_RANGES_URL = 'https://ip-ranges.amazonaws.com/ip-ranges.json'
CLOUD_RANGES_TTL_SECONDS = 6 * 3600

# Cache: {role_arn: (credentials_dict, expiry_timestamp)}
_sts_cache: dict = {}

# Cache: {'networks': [ip_network, ...], 'expires': timestamp}
_cloud_ranges_cache: dict = {}


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


def _cloud_networks():
    """Published cloud provider ranges, or None if they could not be fetched.

    Only AWS is consulted — it is where these clients actually run, and it
    publishes a stable endpoint. Other providers publish equivalents if the gap
    below ever matters. Cached for the container's life: ~8k IPv4 prefixes, a few
    tens of ms to build, and the source changes at most a few times a week.
    """
    if _cloud_ranges_cache.get('expires', 0) > time.time():
        return _cloud_ranges_cache['networks']
    try:
        resp = requests.get(
            AWS_IP_RANGES_URL,
            timeout=6,
            headers={'User-Agent': 'port-guardian/1.0'},
        )
        resp.raise_for_status()
        networks = [
            ipaddress.ip_network(p['ip_prefix']) for p in resp.json()['prefixes']
        ]
    except Exception:
        return None
    _cloud_ranges_cache.update(
        networks=networks, expires=time.time() + CLOUD_RANGES_TTL_SECONDS
    )
    return networks


def _is_cloud_ip(ip):
    """Whether ip sits in a cloud provider's own address space.

    None means undetermined (the range list was unreachable, or the provider is
    one we don't check) — callers must read that as "don't assume either way"
    rather than "not cloud".
    """
    networks = _cloud_networks()
    if networks is None:
        return None
    addr = ipaddress.ip_address(ip)
    return any(addr in net for net in networks)


def _rdap_candidates(data):
    """Allocation blocks described by an RDAP response's `handle`.

    `handle` is a range ('a - b'), a CIDR, or — for space registered directly to
    ARIN — an opaque id ('NET-52-0-0-0-1') that carries no network at all, in which
    case the caller falls back to a fixed width. The response also carries a
    startAddress/endAddress pair that would resolve that last case, but it is left
    alone on purpose: for the opaque-handle IPs seen here it yields provider space
    clamped to a /16 of other tenants' addresses, while the churn it would save
    only applies to ARIN-region consumer ISPs. APNIC allocations, which is what
    these users dial in from, already arrive as a parseable handle range.
    """
    handle = data.get("handle", "")
    if " - " in handle:
        return _summarize_range(*handle.split(" - ", 1))
    if "/" in handle:
        return [ipaddress.ip_network(handle, strict=False)]
    return []


def _clamp_prefix_len():
    """Widest block to whitelist, as a prefix length (MAX_PREFIX_LEN env).

    Trades exposure against churn. The wide default has little to do with ISP
    topology: allocations are often far larger than a /16 (China Mobile's is ~3.5M
    addresses), so the clamp is an arbitrary window around wherever the client
    happened to be — wide enough to admit strangers, not wide enough to contain a
    moving IP. Narrowing costs extra entries, not access: a client that falls
    outside its block re-adds itself through the UI, which is not IP-gated.
    """
    return int(os.environ.get('MAX_PREFIX_LEN', WIDEST_PREFIX_LEN))


def _rdap_cidr(data, ip):
    """The block to whitelist for ip.

    A cloud-hosted IP is whitelisted as a single address: it is static or Elastic,
    so a wider block buys no churn resistance, while the space around it belongs to
    other tenants — a /16 there would admit tens of thousands of strangers'
    instances. Everything else uses the RDAP allocation block containing ip,
    clamped to _clamp_prefix_len().

    An address range summarizes into one or more blocks, and only the block that
    actually holds ip is usable as a whitelist entry — the first block often is
    not, and adding it succeeded while never matching the user's IP. So the chosen
    block is always verified to contain ip; if none does, or RDAP is unavailable,
    fall back to ip/24.
    """
    if _is_cloud_ip(ip):
        return str(ipaddress.ip_network(f"{ip}/{EXACT_PREFIX_LEN}", strict=False))
    addr = ipaddress.ip_address(ip)
    net = None
    if data:
        try:
            net = next((n for n in _rdap_candidates(data) if addr in n), None)
        except (ValueError, TypeError):
            net = None
    if net is None:
        return str(ipaddress.ip_network(f"{ip}/{FALLBACK_PREFIX_LEN}", strict=False))
    clamp = _clamp_prefix_len()
    if net.prefixlen < clamp:
        net = ipaddress.ip_network(f"{ip}/{clamp}", strict=False)
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


def covers(entries, ip):
    """Whether any entry's CIDR contains ip."""
    addr = ipaddress.ip_address(ip)
    return any(addr in ipaddress.ip_network(e['Cidr'], strict=False) for e in entries)


PIN_MARKER = '[PIN]'
GUARD_MARKER = '[Guard]'
# Lifetimes offered when adding or editing; 0 means no expiry (FIFO or a pin decides).
LIFETIME_DAYS = (0, 1, 7, 30, 90, 180)
# Expiry dates are calendar days in the users' timezone (CN/HK/SG): a UTC day would
# start at 08:00 local and make an evening "1 day" entry expire the next morning.
EXPIRY_TZ = timezone(timedelta(hours=8))

_EXP_RE = re.compile(r'\[EXP:(\d{4}-\d{2}-\d{2})\]')
_TS_RE = re.compile(r'\s*\b\d{4}-\d{2}-\d{2}(?:T\d{2}:\d{2}(?::\d{2})?Z?)?$')


def is_pinned(description):
    """A pinned entry (description contains [PIN]) is never FIFO-evicted."""
    return PIN_MARKER in (description or '')


def today_local():
    return datetime.now(EXPIRY_TZ).date()


def parse_description(description):
    """Split a description into its markers, trailing creation time and free text.

    Format: '[PIN] [Guard] [EXP:YYYY-MM-DD] <label> <ISO timestamp>', every part
    optional. [Guard] is written only by Port Guardian, so its absence reliably
    marks an entry added some other way; its presence proves nothing, since a hand
    edit can copy it.
    """
    desc = description or ''
    exp = _EXP_RE.search(desc)
    rest = _EXP_RE.sub('', desc).replace(PIN_MARKER, '').replace(GUARD_MARKER, '')
    ts = _TS_RE.search(rest)
    return {
        'pinned': PIN_MARKER in desc,
        'guard': GUARD_MARKER in desc,
        'expires': date.fromisoformat(exp.group(1)) if exp else None,
        'added': ts.group(0).strip() if ts else None,
        'label': ' '.join(rest[:ts.start()].split() if ts else rest.split()),
    }


def build_description(pinned=False, guard=True, expires=None, label='', added=None):
    parts = [PIN_MARKER if pinned else '', GUARD_MARKER if guard else '',
             f'[EXP:{expires.isoformat()}]' if expires else '', label or '', added or '']
    return ' '.join(p for p in parts if p)[:255]  # AWS description limit


def expiry_for(lifetime_days, today=None):
    """Last valid day for a lifetime in days, or None for no expiry."""
    if lifetime_days not in LIFETIME_DAYS:
        raise ValueError(f'lifetime must be one of {LIFETIME_DAYS} days')
    return (today or today_local()) + timedelta(days=lifetime_days) if lifetime_days else None


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


def _read_list(ec2_client, prefix_list_id):
    """(prefix list, its entries), with the entries read at exactly that version.

    A modify against this version then succeeds only if nothing changed since the
    read, so the read entries plus the modify's own changes are the new contents.
    """
    pl = ec2_client.describe_managed_prefix_lists(PrefixListIds=[prefix_list_id])['PrefixLists'][0]
    entries = []
    paginator = ec2_client.get_paginator('get_managed_prefix_list_entries')
    for page in paginator.paginate(PrefixListId=prefix_list_id, TargetVersion=pl['Version']):
        entries.extend(page.get('Entries', []))
    return pl, entries


def _entry(cidr, description):
    # AddEntries rejects an empty Description; omit the key instead.
    return {'Cidr': cidr, 'Description': description} if description else {'Cidr': cidr}


def _add_entry(ec2_client, prefix_list_id, pl, entries, cidr, description):
    """Add one entry, FIFO-evicting the oldest unpinned entry if the list is full.

    Returns the entries afterwards. Eviction triggers at the CONFIGURED threshold
    (decoupled from the PL's real MaxEntries). If config exceeds the real capacity
    and the add fails, learn the real value for subsequent calls and raise a clear
    error for this one.
    """
    threshold = _eviction_threshold(prefix_list_id)
    modify_args = {
        'PrefixListId': prefix_list_id,
        'CurrentVersion': pl['Version'],
        'AddEntries': [_entry(cidr, description)],
    }
    evicted = None
    if len(entries) >= threshold:
        evictable = [e for e in entries if not is_pinned(e.get('Description', ''))]
        if not evictable:
            raise ValueError(
                f'prefix list full ({len(entries)}/{threshold}) and all entries are '
                f'pinned ([PIN]); cannot add {cidr} — unpin an entry or raise max_entries'
            )
        evicted = min(evictable, key=lambda e: _parse_entry_timestamp(e.get('Description', '')))['Cidr']
        modify_args['RemoveEntries'] = [{'Cidr': evicted}]

    try:
        ec2_client.modify_managed_prefix_list(**modify_args)
    except ClientError:
        real_max = pl['MaxEntries']
        if evicted is None and len(entries) >= real_max:
            # Config said there was room but the PL is actually full: learn the real
            # capacity so the next add evicts correctly, and surface the mismatch.
            _max_entries_override[prefix_list_id] = real_max
            raise ValueError(
                f'max_entries config ({threshold}) exceeds prefix list MaxEntries '
                f'({real_max}); now using {real_max} — retry the add'
            )
        raise
    return [e for e in entries if e['Cidr'] != evicted] + [_entry(cidr, description)]


def _now_stamp():
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def _clean_label(label):
    """User-supplied text without anything that would read as a marker or a timestamp."""
    text = _EXP_RE.sub('', label or '').replace(PIN_MARKER, '').replace(GUARD_MARKER, '')
    return ' '.join(_TS_RE.sub('', text).split())[:120]


def add_ip_to_prefix_list(ec2_client, prefix_list_id, ip, lifetime_days=0):
    """Add the whitelist block for ip. Returns (status, entries afterwards).

    Status is 'added', or 'already_exists' when an entry already covers ip.
    """
    pl, entries = _read_list(ec2_client, prefix_list_id)
    if covers(entries, ip):
        return 'already_exists', entries

    expires = expiry_for(lifetime_days)
    rdap = _fetch_rdap(ip)
    cidr = _rdap_cidr(rdap, ip)
    country = (rdap or {}).get('country', 'unknown') or 'unknown'
    isp = ' '.join(_rdap_org(rdap).split()[:2])  # e.g. 'China Mobile Peoples Telephone...' -> 'China Mobile'
    description = build_description(expires=expires, label=f'{country} {isp}', added=_now_stamp())
    return 'added', _add_entry(ec2_client, prefix_list_id, pl, entries, cidr, description)


def normalize_cidr(text):
    """A public IPv4 CIDR no wider than WIDEST_PREFIX_LEN, host bits cleared."""
    try:
        net = ipaddress.ip_network((text or '').strip(), strict=False)
    except ValueError:
        raise ValueError(f'not a valid CIDR: {text!r}')
    if net.version != 4:
        raise ValueError('only IPv4 CIDRs are supported')
    if not net.is_global:
        raise ValueError(f'{net} is not a public address range')
    if net.prefixlen < WIDEST_PREFIX_LEN:
        raise ValueError(f'{net} is wider than /{WIDEST_PREFIX_LEN}')
    return str(net)


def add_cidr_to_prefix_list(ec2_client, prefix_list_id, cidr, label, lifetime_days=0, pinned=False):
    """Add an arbitrary CIDR with a description. Returns (status, entries afterwards)."""
    cidr = normalize_cidr(cidr)
    expires = None if pinned else expiry_for(lifetime_days)
    pl, entries = _read_list(ec2_client, prefix_list_id)
    if any(e['Cidr'] == cidr for e in entries):
        raise ValueError(f'{cidr} is already in the list — edit it instead')
    description = build_description(pinned=pinned, expires=expires, label=_clean_label(label), added=_now_stamp())
    return 'added', _add_entry(ec2_client, prefix_list_id, pl, entries, cidr, description)


_KEEP = object()


def update_entry(ec2_client, prefix_list_id, cidr, label=_KEEP, expires=_KEEP):
    """Rewrite an entry's label and/or expiry date (None = never). Returns (status, entries afterwards).

    Saving through Port Guardian adopts the entry: it gains [Guard], so an entry
    added some other way stops being flagged once someone has reviewed it here.
    A pinned entry never expires, so an expiry is ignored for it. A date before
    today is refused: the next sweep would delete the entry immediately.
    """
    if expires is not _KEEP and expires is not None and expires < today_local():
        raise ValueError(f'expiry {expires} is in the past')
    pl, entries = _read_list(ec2_client, prefix_list_id)
    entry = next((e for e in entries if e['Cidr'] == cidr), None)
    if entry is None:
        raise ValueError(f'{cidr} not found in prefix list')
    d = parse_description(entry.get('Description', ''))
    expires = d['expires'] if expires is _KEEP else expires
    new_desc = build_description(
        pinned=d['pinned'], expires=None if d['pinned'] else expires,
        label=d['label'] if label is _KEEP else _clean_label(label), added=d['added'],
    )
    if new_desc == entry.get('Description', ''):
        return 'unchanged', entries
    ec2_client.modify_managed_prefix_list(
        PrefixListId=prefix_list_id, CurrentVersion=pl['Version'], AddEntries=[_entry(cidr, new_desc)],
    )
    return 'updated', [_entry(cidr, new_desc) if e['Cidr'] == cidr else e for e in entries]


def expired(entries, today=None):
    """Unpinned entries whose last valid day is before today."""
    today = today or today_local()
    return [e['Cidr'] for e in entries
            if (d := parse_description(e.get('Description', '')))['expires']
            and not d['pinned'] and d['expires'] < today]


def remove_expired(ec2_client, prefix_list_id, today=None):
    """Remove every expired entry in one call. Returns (status, entries afterwards)."""
    pl, entries = _read_list(ec2_client, prefix_list_id)
    gone = expired(entries, today)
    if not gone:
        return 'nothing expired', entries
    ec2_client.modify_managed_prefix_list(
        PrefixListId=prefix_list_id, CurrentVersion=pl['Version'],
        RemoveEntries=[{'Cidr': c} for c in gone],
    )
    return f'removed {len(gone)} expired: {", ".join(gone)}', [e for e in entries if e['Cidr'] not in gone]


def get_all_entries(ec2_client, prefix_list_id):
    """Return all entries in the prefix list."""
    entries = []
    paginator = ec2_client.get_paginator('get_managed_prefix_list_entries')
    for page in paginator.paginate(PrefixListId=prefix_list_id):
        entries.extend(page.get('Entries', []))
    return entries


def remove_cidr_from_prefix_list(ec2_client, prefix_list_id, cidr):
    """Remove cidr if present. Returns (status, entries afterwards)."""
    pl, entries = _read_list(ec2_client, prefix_list_id)
    if not any(e['Cidr'] == cidr for e in entries):
        return 'absent', entries
    ec2_client.modify_managed_prefix_list(
        PrefixListId=prefix_list_id,
        CurrentVersion=pl['Version'],
        RemoveEntries=[{'Cidr': cidr}],
    )
    return 'removed', [e for e in entries if e['Cidr'] != cidr]


def set_pin(ec2_client, prefix_list_id, cidr, pinned):
    """Add or remove the [PIN] marker on a CIDR's description.

    Returns (status, entries afterwards). Pinning also clears any expiry: a pinned
    entry is kept until someone unpins or deletes it. There is no rename API, but
    AddEntries with an already-present CIDR overwrites its Description in place
    (verified against a live prefix list), so this is one call with no RemoveEntries.
    """
    pl, entries = _read_list(ec2_client, prefix_list_id)
    entry = next((e for e in entries if e['Cidr'] == cidr), None)
    if entry is None:
        raise ValueError(f'{cidr} not found in prefix list')

    desc = entry.get('Description', '')
    d = parse_description(desc)
    status = 'pinned' if pinned else 'unpinned'
    if d['pinned'] == pinned:
        return status, entries
    new_desc = build_description(pinned=pinned, guard=d['guard'], expires=None if pinned else d['expires'],
                                 label=d['label'], added=d['added'])

    ec2_client.modify_managed_prefix_list(
        PrefixListId=prefix_list_id,
        CurrentVersion=pl['Version'],
        AddEntries=[_entry(cidr, new_desc)],
    )
    after = [_entry(cidr, new_desc) if e['Cidr'] == cidr else e for e in entries]
    return status, after


def diff_entries(desired, actual):
    """CIDRs to add, remove, or rewrite (description differs) to turn actual into desired."""
    want = {e['Cidr']: e.get('Description', '') for e in desired}
    have = {e['Cidr']: e.get('Description', '') for e in actual}
    return {
        'add': sorted(c for c in want if c not in have),
        'remove': sorted(c for c in have if c not in want),
        'update': sorted(c for c in want if c in have and have[c] != want[c]),
    }


def sync_entries(ec2_client, prefix_list_id, desired, dry_run=False):
    """Make the list's contents equal desired, in one modify call.

    Returns (diff, entries before). Rewrites go through AddEntries, which
    overwrites a present CIDR's description, so no CIDR is ever in both AddEntries
    and RemoveEntries — AWS rejects that combination.
    """
    pl, actual = _read_list(ec2_client, prefix_list_id)
    diff = diff_entries(desired, actual)
    if dry_run or not any(diff.values()):
        return diff, actual
    want = {e['Cidr']: e.get('Description', '') for e in desired}
    args = {'PrefixListId': prefix_list_id, 'CurrentVersion': pl['Version']}
    if diff['add'] or diff['update']:
        args['AddEntries'] = [_entry(c, want[c]) for c in diff['add'] + diff['update']]
    if diff['remove']:
        args['RemoveEntries'] = [{'Cidr': c} for c in diff['remove']]
    ec2_client.modify_managed_prefix_list(**args)
    return diff, actual
