import logging
import os
import re
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from chalice import Chalice, CognitoUserPoolAuthorizer, Response

from chalicelib.prefix_list_service import (
    covers, diff_entries, get_all_entries, get_ec2_client, get_ip_info, get_prefix_list_id,
    add_ip_to_prefix_list, remove_cidr_from_prefix_list, set_pin, sync_entries,
)
from chalicelib.sg_sync_service import list_managed_sgs, reconcile_sg_rules

app = Chalice(app_name='port-guardian')
# API Gateway decides on base64 decoding from the request's first Accept type, and
# browsers lead with image/avif or image/webp, so PNG icons need the wildcard.
app.api.binary_types.append('image/*')
# Chalice defaults to ERROR; the client_ip observations below are INFO.
app.log.setLevel(logging.INFO)

# Required: setup.py writes these from config.yaml; a missing one fails the deploy.
COGNITO_USER_POOL_ARN = (
    f"arn:aws:cognito-idp:{os.environ['COGNITO_REGION']}:"
    f"{os.environ['PRIMARY_ACCOUNT_ID']}:"
    f"userpool/{os.environ['COGNITO_USER_POOL_ID']}"
)

authorizer = CognitoUserPoolAuthorizer(
    'PortGuardianAuth', provider_arns=[COGNITO_USER_POOL_ARN]
)

_HTML_TEMPLATE = None


def _get_html():
    global _HTML_TEMPLATE
    if _HTML_TEMPLATE is None:
        _HTML_TEMPLATE = (Path(__file__).parent / 'chalicelib' / 'index.html').read_text()
    return _HTML_TEMPLATE


def _get_source_ip():
    return app.current_request.context.get('identity', {}).get('sourceIp', 'unknown')


def _get_targets():
    """Return list of (account_id, region) tuples from env vars."""
    primary = os.environ.get('PRIMARY_ACCOUNT_ID', '')
    secondary = os.environ.get('SECONDARY_ACCOUNT_ID', '')
    regions = os.environ.get('TARGET_REGIONS', '').split(',')
    targets = []
    for r in regions:
        r = r.strip()
        if r:
            targets.append((primary, r))
            targets.append((secondary, r))
    return targets


# ---------------------------------------------------------------------------
# Primary list — the single source of truth for whitelist contents
# ---------------------------------------------------------------------------
# Writes happen on the primary list only, then every replica is made identical to
# it. Replaying each change on six lists independently let partial failures (and
# per-list FIFO choices) drift them apart; converging on one list repairs any
# earlier drift on the next write instead of compounding it.

def _primary_target():
    """The primary account's list in the region this Lambda runs in."""
    target = (os.environ['PRIMARY_ACCOUNT_ID'], os.environ['AWS_REGION'])
    if target not in _get_targets():
        raise RuntimeError(f'primary target {target} is not among TARGET_REGIONS')
    return target


def _open_list(account_id, region):
    ec2 = get_ec2_client(account_id, region)
    pl_id = get_prefix_list_id(ec2)
    if not pl_id:
        raise RuntimeError('prefix list not found')
    return ec2, pl_id


def _sync_replicas(desired, dry_run=False, ip=None):
    """Make every non-primary list match desired; one result dict per replica.

    With ip, flags replicas where the sync would remove the caller's own access.
    """
    primary = _primary_target()
    replicas = [t for t in _get_targets() if t != primary]

    def _one(target):
        account_id, region = target
        result = {'account': account_id, 'region': region}
        try:
            diff, before = sync_entries(*_open_list(account_id, region), desired, dry_run=dry_run)
        except Exception as e:
            app.log.error(f'Sync failed for {account_id}/{region}: {e}')
            return {**result, 'status': f'error: {e}'}
        changed = any(diff.values())
        # Description-only differences change nothing about access; they get tidied
        # by any sync but don't make a list "out of sync".
        access = bool(diff['add'] or diff['remove'])
        status = ('in sync' if not changed else 'synced' if not dry_run
                  else 'out of sync' if access else 'descriptions differ')
        result.update(status=status, **diff)
        # What each added or removed CIDR is, so the change can be judged before confirming.
        want = {e['Cidr']: e.get('Description', '') for e in desired}
        have = {e['Cidr']: e.get('Description', '') for e in before}
        result['descriptions'] = {**{c: have[c] for c in diff['remove']}, **{c: want[c] for c in diff['add']}}
        if ip and covers(before, ip) and not covers(desired, ip):
            result['loses_current_ip'] = True
        return result

    with ThreadPoolExecutor(max_workers=6) as pool:
        try:
            return list(pool.map(_one, replicas, timeout=15))
        except TimeoutError:
            return [{'account': a, 'region': r, 'status': 'error: timeout'} for a, r in replicas]


def _write_through(mutate):
    """Run mutate(ec2, pl_id) -> (status, entries) on the primary, then sync replicas.

    If the primary write fails nothing else is touched, so a failed write can never
    leave the lists diverged; replica failures are reported per target.
    """
    account_id, region = _primary_target()
    head = {'account': account_id, 'region': region, 'primary': True}
    try:
        status, entries = mutate(*_open_list(account_id, region))
    except Exception as e:
        app.log.error(f'Primary write failed for {account_id}/{region}: {e}')
        skipped = [{'account': a, 'region': r, 'status': 'skipped: primary write failed'}
                   for a, r in _get_targets() if (a, r) != (account_id, region)]
        return [{**head, 'status': f'error: {e}'}] + skipped
    return [{**head, 'status': status}] + _sync_replicas(entries)


# ---------------------------------------------------------------------------
# GET / — HTML page
# ---------------------------------------------------------------------------

@app.route('/', methods=['GET'])
def index():
    html = _get_html()
    cognito_region = os.environ['COGNITO_REGION']
    html = (
        html
        .replace('{{COGNITO_ENDPOINT}}', f'https://cognito-idp.{cognito_region}.amazonaws.com/')
        .replace('{{COGNITO_CLIENT_ID}}', os.environ['COGNITO_CLIENT_ID'])
        .replace('{{VERSION}}', os.environ.get('APP_VERSION', 'dev'))
    )
    return Response(body=html, status_code=200, headers={'Content-Type': 'text/html'})


# ---------------------------------------------------------------------------
# PWA assets — public: install checks and the service worker fetch them unauthenticated
# ---------------------------------------------------------------------------

_PWA_DIR = Path(__file__).parent / 'chalicelib' / 'pwa'
_PWA_ASSETS = {
    # file: (content type, cache-control)
    'manifest.webmanifest': ('application/manifest+json', 'no-cache'),
    # no-cache so a new worker is picked up on the next load
    'sw.js': ('text/javascript', 'no-cache'),
    'icon.svg': ('image/svg+xml', 'max-age=86400'),
    'icon-192.png': ('image/png', 'max-age=86400'),
    'icon-512.png': ('image/png', 'max-age=86400'),
    'icon-maskable-512.png': ('image/png', 'max-age=86400'),
    'apple-touch-icon.png': ('image/png', 'max-age=86400'),
}


def _pwa_view(filename):
    content_type, cache_control = _PWA_ASSETS[filename]
    body = (_PWA_DIR / filename).read_bytes()

    def view():
        return Response(
            body=body if content_type == 'image/png' else body.decode('utf-8'),
            status_code=200,
            headers={'Content-Type': content_type, 'Cache-Control': cache_control},
        )
    return view


for _filename in _PWA_ASSETS:
    app.route(f'/{_filename}', methods=['GET'],
              name='pwa_' + re.sub(r'\W', '_', _filename))(_pwa_view(_filename))


# ---------------------------------------------------------------------------
# GET /ip — fast public IP lookup
# ---------------------------------------------------------------------------

@app.route('/ip', methods=['GET'])
def ip():
    return {'ip': _get_source_ip()}


# ---------------------------------------------------------------------------
# GET /ipinfo — detailed IP information via RDAP
# ---------------------------------------------------------------------------

@app.route('/ipinfo', methods=['GET'], authorizer=authorizer)
def ipinfo():
    return get_ip_info(_get_source_ip())


# ---------------------------------------------------------------------------
# GET /status
# ---------------------------------------------------------------------------

@app.route('/status', methods=['GET'], authorizer=authorizer)
def status():
    ip = _get_source_ip()
    # The only place the raw client IP is recorded: entry descriptions keep the IP
    # that first created a block, so they say nothing about movement *within* it.
    # /status runs on every page load, so these lines accumulate the series needed
    # to pick max_prefix_len from real data instead of guessing.
    app.log.info(f'client_ip={ip}')
    targets = _get_targets()

    def _check(target):
        account_id, region = target
        try:
            entries = get_all_entries(*_open_list(account_id, region))
        except Exception as e:
            app.log.error(f'Error checking {account_id}/{region}: {e}')
            return {'account': account_id, 'region': region, 'in_prefix_list': False, 'error': str(e)}
        return {'account': account_id, 'region': region, 'in_prefix_list': covers(entries, ip), 'entries': entries}

    with ThreadPoolExecutor(max_workers=6) as pool:
        try:
            regions = list(pool.map(_check, targets, timeout=15))
        except TimeoutError:
            app.log.error('Status check timed out')
            regions = [{'account': a, 'region': r, 'in_prefix_list': False, 'error': 'timeout'} for a, r in targets]

    primary = _primary_target()
    by_target = {(r['account'], r['region']): r for r in regions}
    readable = [r for r in regions if 'error' not in r]
    primary_entries = by_target[primary].get('entries')

    # Every entry from any list, so a replica-only grant stays visible: it still
    # opens ports even though the primary no longer has it.
    entries = {}
    for r in sorted(readable, key=lambda r: (r['account'], r['region']) != primary):
        for e in r['entries']:
            row = entries.setdefault(e['Cidr'], {'cidr': e['Cidr'], 'description': e.get('Description', ''),
                                                 'lists': 0, 'in_primary': False})
            row['lists'] += 1
            row['in_primary'] |= (r['account'], r['region']) == primary

    drift = []
    if primary_entries is not None:
        for r in readable:
            if (r['account'], r['region']) == primary:
                continue
            diff = diff_entries(primary_entries, r['entries'])
            # Drift means a different set of CIDRs, i.e. different access.
            if diff['add'] or diff['remove']:
                drift.append({'account': r['account'], 'region': r['region'], **diff})

    return {
        'current_ip': ip,
        'regions': [{k: v for k, v in r.items() if k != 'entries'} for r in regions],
        'entries': sorted(entries.values(), key=lambda e: e['cidr']),
        'list_count': len(readable),
        'primary': {'account': primary[0], 'region': primary[1], 'readable': primary_entries is not None},
        'drift': drift,
    }


# ---------------------------------------------------------------------------
# POST /update — add the caller's IP on the primary, then sync replicas
# ---------------------------------------------------------------------------

@app.route('/update', methods=['POST'], authorizer=authorizer)
def update():
    ip = _get_source_ip()
    return {'ip': ip, 'results': _write_through(lambda ec2, pl_id: add_ip_to_prefix_list(ec2, pl_id, ip))}


# ---------------------------------------------------------------------------
# POST /sync-entries — make every replica match the primary
# ---------------------------------------------------------------------------

@app.route('/sync-entries', methods=['POST'], authorizer=authorizer)
def sync_entries_route():
    dry_run = bool((app.current_request.json_body or {}).get('dry_run'))
    account_id, region = _primary_target()
    primary = {'account': account_id, 'region': region}
    try:
        desired = get_all_entries(*_open_list(account_id, region))
    except Exception as e:
        app.log.error(f'Reading primary {account_id}/{region} failed: {e}')
        return {'primary': primary, 'error': f'cannot read primary list: {e}', 'results': []}
    results = _sync_replicas(desired, dry_run=dry_run, ip=_get_source_ip())
    return {'primary': primary, 'dry_run': dry_run, 'results': results}


# ---------------------------------------------------------------------------
# GET /sgs — managed SG overview; POST /sync-sg — tag-driven reconcile
# ---------------------------------------------------------------------------

TAG_KEY = 'port-guardian'


def _fanout_sg(fn):
    """Run fn(ec2, pl_id, account, region) across all targets; collect per-target results."""
    def _one(target):
        account_id, region = target
        try:
            ec2 = get_ec2_client(account_id, region)
            pl_id = get_prefix_list_id(ec2)
            if not pl_id:
                return {'account': account_id, 'region': region, 'error': 'prefix list not found', 'sgs': []}
            return {'account': account_id, 'region': region, 'sgs': fn(ec2, pl_id)}
        except Exception as e:
            app.log.error(f'SG op failed for {account_id}/{region}: {e}')
            return {'account': account_id, 'region': region, 'error': str(e), 'sgs': []}

    with ThreadPoolExecutor(max_workers=6) as pool:
        try:
            return list(pool.map(_one, _get_targets(), timeout=25))
        except TimeoutError:
            app.log.error('SG operation timed out')
            return [{'account': a, 'region': r, 'error': 'timeout', 'sgs': []} for a, r in _get_targets()]


@app.route('/sgs', methods=['GET'], authorizer=authorizer)
def sgs():
    return {'targets': _fanout_sg(lambda ec2, pl_id: list_managed_sgs(ec2, pl_id, TAG_KEY))}


@app.route('/sync-sg', methods=['POST'], authorizer=authorizer)
def sync_sg():
    body = app.current_request.json_body or {}
    allow_exit = bool(body.get('allow_exit'))
    dry_run = bool(body.get('dry_run'))
    return {'targets': _fanout_sg(
        lambda ec2, pl_id: reconcile_sg_rules(ec2, pl_id, TAG_KEY, allow_exit=allow_exit, dry_run=dry_run)
    )}


# ---------------------------------------------------------------------------
# DELETE /entries — remove a CIDR on the primary, then sync replicas
# ---------------------------------------------------------------------------

@app.route('/entries', methods=['DELETE'], authorizer=authorizer)
def delete_entry():
    body = app.current_request.json_body or {}
    cidr = body.get('cidr', '').strip()
    if not cidr:
        return Response(body='{"error":"cidr required"}', status_code=400,
                        headers={'Content-Type': 'application/json'})
    # A CIDR only on replicas is 'absent' on the primary; the sync still removes it.
    return {'cidr': cidr, 'results': _write_through(
        lambda ec2, pl_id: remove_cidr_from_prefix_list(ec2, pl_id, cidr))}


# ---------------------------------------------------------------------------
# PATCH /entries — pin/unpin a CIDR on the primary, then sync replicas
# ---------------------------------------------------------------------------

@app.route('/entries', methods=['PATCH'], authorizer=authorizer)
def patch_entry():
    body = app.current_request.json_body or {}
    cidr = body.get('cidr', '').strip()
    pinned = bool(body.get('pinned'))
    if not cidr:
        return Response(body='{"error":"cidr required"}', status_code=400,
                        headers={'Content-Type': 'application/json'})
    return {'cidr': cidr, 'pinned': pinned, 'results': _write_through(
        lambda ec2, pl_id: set_pin(ec2, pl_id, cidr, pinned))}
