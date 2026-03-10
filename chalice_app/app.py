import os
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from chalice import Chalice, CognitoUserPoolAuthorizer, Response

from chalicelib.prefix_list_service import get_ec2_client, get_prefix_list_id, check_ip_in_prefix_list, add_ip_to_prefix_list

app = Chalice(app_name='sg-guardian')

COGNITO_USER_POOL_ARN = (
    f"arn:aws:cognito-idp:{os.environ.get('COGNITO_REGION', 'ap-southeast-1')}:"
    f"{os.environ.get('PRIMARY_ACCOUNT_ID', '222829864634')}:"
    f"userpool/{os.environ.get('COGNITO_USER_POOL_ID', 'ap-southeast-1_WBHlZF1Zf')}"
)

authorizer = CognitoUserPoolAuthorizer(
    'SshGuardianAuth', provider_arns=[COGNITO_USER_POOL_ARN]
)

_HTML_TEMPLATE = None


def _get_html():
    global _HTML_TEMPLATE
    if _HTML_TEMPLATE is None:
        _HTML_TEMPLATE = (Path(__file__).parent / 'chalicelib' / 'index.html').read_text()
    return _HTML_TEMPLATE


def _get_api_base():
    ctx = app.current_request.context
    stage = ctx.get('stage', 'api')
    api_id = ctx.get('apiId', '')
    region = os.environ.get('COGNITO_REGION', 'ap-southeast-1')
    if api_id:
        return f"https://{api_id}.execute-api.{region}.amazonaws.com/{stage}"
    headers = app.current_request.headers or {}
    host = headers.get('host', '')
    if host:
        return f"https://{host}/{stage}"
    return ''


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
# T-3.3  GET / — HTML page
# ---------------------------------------------------------------------------

@app.route('/', methods=['GET'])
def index():
    html = _get_html()
    cognito_region = os.environ.get('COGNITO_REGION', 'ap-southeast-1')
    html = (
        html
        .replace('{{COGNITO_ENDPOINT}}', f'https://cognito-idp.{cognito_region}.amazonaws.com/')
        .replace('{{COGNITO_CLIENT_ID}}', os.environ.get('COGNITO_CLIENT_ID', ''))
    )
    return Response(body=html, status_code=200, headers={'Content-Type': 'text/html'})


# ---------------------------------------------------------------------------
# T-3.4  GET /ip — fast public IP lookup
# ---------------------------------------------------------------------------

@app.route('/ip', methods=['GET'])
def ip():
    return {'ip': _get_source_ip()}


# ---------------------------------------------------------------------------
# T-3.4  GET /status
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
            in_pl = check_ip_in_prefix_list(ec2, pl_id, ip) if pl_id else False
        except Exception as e:
            app.log.error(f'Error checking {account_id}/{region}: {e}')
            in_pl = False
        return {'account': account_id, 'region': region, 'in_prefix_list': in_pl}

    with ThreadPoolExecutor(max_workers=6) as pool:
        try:
            regions = list(pool.map(_check, targets, timeout=15))
        except TimeoutError:
            app.log.error('Status check timed out')
            regions = [{'account': a, 'region': r, 'in_prefix_list': False} for a, r in targets]

    return {'current_ip': ip, 'ports': [int(p) for p in os.environ.get('TARGET_PORTS', '').split(',') if p], 'regions': regions}


# ---------------------------------------------------------------------------
# T-3.5  POST /update
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
