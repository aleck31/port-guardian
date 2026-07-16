import ipaddress
import os
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from chalice import Chalice, CognitoUserPoolAuthorizer, Response

from chalicelib.prefix_list_service import get_ec2_client, get_prefix_list_id, check_ip_in_prefix_list, add_ip_to_prefix_list, get_ip_info, get_all_entries, remove_cidr_from_prefix_list, set_pin
from chalicelib.sg_sync_service import list_managed_sgs, reconcile_sg_rules

app = Chalice(app_name='port-guardian')

COGNITO_USER_POOL_ARN = (
    f"arn:aws:cognito-idp:{os.environ.get('COGNITO_REGION', 'ap-southeast-1')}:"
    f"{os.environ.get('PRIMARY_ACCOUNT_ID', '222829864634')}:"
    f"userpool/{os.environ.get('COGNITO_USER_POOL_ID', 'ap-southeast-1_WBHlZF1Zf')}"
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
# GET / — HTML page
# ---------------------------------------------------------------------------

@app.route('/', methods=['GET'])
def index():
    html = _get_html()
    cognito_region = os.environ.get('COGNITO_REGION', 'ap-southeast-1')
    html = (
        html
        .replace('{{COGNITO_ENDPOINT}}', f'https://cognito-idp.{cognito_region}.amazonaws.com/')
        .replace('{{COGNITO_CLIENT_ID}}', os.environ.get('COGNITO_CLIENT_ID', ''))
        .replace('{{VERSION}}', os.environ.get('APP_VERSION', 'dev'))
    )
    return Response(body=html, status_code=200, headers={'Content-Type': 'text/html'})


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
    targets = _get_targets()

    def _check(target):
        account_id, region = target
        try:
            ec2 = get_ec2_client(account_id, region)
            pl_id = get_prefix_list_id(ec2)
            if pl_id:
                all_entries = get_all_entries(ec2, pl_id)
                addr = ipaddress.ip_address(ip)
                in_pl = any(addr in ipaddress.ip_network(e['Cidr'], strict=False) for e in all_entries)
            else:
                all_entries, in_pl = [], False
        except Exception as e:
            app.log.error(f'Error checking {account_id}/{region}: {e}')
            all_entries, in_pl = [], False
        return {'account': account_id, 'region': region, 'in_prefix_list': in_pl, 'entries': all_entries}

    with ThreadPoolExecutor(max_workers=6) as pool:
        try:
            regions = list(pool.map(_check, targets, timeout=15))
        except TimeoutError:
            app.log.error('Status check timed out')
            regions = [{'account': a, 'region': r, 'in_prefix_list': False, 'entries': []} for a, r in targets]

    # Deduplicate entries across all regions (use first occurrence)
    seen = {}
    for r in regions:
        for e in r.get('entries', []):
            if e['Cidr'] not in seen:
                seen[e['Cidr']] = e.get('Description', '')

    return {
        'current_ip': ip,
        'regions': [{k: v for k, v in r.items() if k != 'entries'} for r in regions],
        'entries': [{'cidr': c, 'description': d} for c, d in sorted(seen.items())],
    }


# ---------------------------------------------------------------------------
# POST /update
# ---------------------------------------------------------------------------

@app.route('/update', methods=['POST'], authorizer=authorizer)
def update():
    ip = _get_source_ip()
    targets = _get_targets()

    def _add(target):
        account_id, region = target
        try:
            ec2 = get_ec2_client(account_id, region)
            pl_id = get_prefix_list_id(ec2)
            if not pl_id:
                s = 'error: prefix list not found'
            else:
                s = add_ip_to_prefix_list(ec2, pl_id, ip)
        except Exception as e:
            app.log.error(f'Error updating {account_id}/{region}: {e}')
            s = f'error: {e}'
        return {'account': account_id, 'region': region, 'status': s}

    with ThreadPoolExecutor(max_workers=6) as pool:
        try:
            results = list(pool.map(_add, targets, timeout=15))
        except TimeoutError:
            app.log.error('Update timed out')
            results = [{'account': a, 'region': r, 'status': 'error: timeout'} for a, r in targets]

    return {'ip': ip, 'results': results}


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
# DELETE /entries — remove a CIDR from all prefix lists
# ---------------------------------------------------------------------------

@app.route('/entries', methods=['DELETE'], authorizer=authorizer)
def delete_entry():
    body = app.current_request.json_body or {}
    cidr = body.get('cidr', '').strip()
    if not cidr:
        return Response(body='{"error":"cidr required"}', status_code=400,
                        headers={'Content-Type': 'application/json'})
    targets = _get_targets()

    def _remove(target):
        account_id, region = target
        try:
            ec2 = get_ec2_client(account_id, region)
            pl_id = get_prefix_list_id(ec2)
            if pl_id:
                remove_cidr_from_prefix_list(ec2, pl_id, cidr)
            s = 'removed'
        except Exception as e:
            app.log.error(f'Error removing {cidr} from {account_id}/{region}: {e}')
            s = f'error: {e}'
        return {'account': account_id, 'region': region, 'status': s}

    with ThreadPoolExecutor(max_workers=6) as pool:
        try:
            results = list(pool.map(_remove, targets, timeout=15))
        except TimeoutError:
            results = [{'account': a, 'region': r, 'status': 'error: timeout'} for a, r in targets]

    return {'cidr': cidr, 'results': results}


# ---------------------------------------------------------------------------
# PATCH /entries — pin/unpin a CIDR across all prefix lists
# ---------------------------------------------------------------------------

@app.route('/entries', methods=['PATCH'], authorizer=authorizer)
def patch_entry():
    body = app.current_request.json_body or {}
    cidr = body.get('cidr', '').strip()
    pinned = bool(body.get('pinned'))
    if not cidr:
        return Response(body='{"error":"cidr required"}', status_code=400,
                        headers={'Content-Type': 'application/json'})
    targets = _get_targets()

    def _pin(target):
        account_id, region = target
        try:
            ec2 = get_ec2_client(account_id, region)
            pl_id = get_prefix_list_id(ec2)
            if pl_id:
                set_pin(ec2, pl_id, cidr, pinned)
            s = 'pinned' if pinned else 'unpinned'
        except Exception as e:
            app.log.error(f'Error setting pin={pinned} for {cidr} in {account_id}/{region}: {e}')
            s = f'error: {e}'
        return {'account': account_id, 'region': region, 'status': s}

    with ThreadPoolExecutor(max_workers=6) as pool:
        try:
            results = list(pool.map(_pin, targets, timeout=15))
        except TimeoutError:
            results = [{'account': a, 'region': r, 'status': 'error: timeout'} for a, r in targets]

    return {'cidr': cidr, 'pinned': pinned, 'results': results}
