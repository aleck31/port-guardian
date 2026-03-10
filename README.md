# Port Guardian

Lightweight remote management port (SSH/RDP) access control for multi-account, multi-region AWS environments.

It provides a serverless web app that allows authenticated users to view their current IP address and update AWS Managed Prefix Lists across all target regions with a single click. Security Groups reference these Prefix Lists, so a single update propagates everywhere.

## Features

- **Web UI** — Login, view IP & whitelist status, one-click update
- **Multi-account** — Primary account (direct) + secondary account (STS AssumeRole)
- **Multi-region** — Concurrent updates across 6 targets (2 accounts × 3 regions)
- **RDAP prefix lookup** — Whitelists ISP allocation block (e.g. /18) instead of /32, reducing churn
- **CIDR containment** — Checks if IP falls within any existing prefix, not just exact match
- **FIFO eviction** — Auto-removes oldest entry when prefix list is full
- **Cognito auth** — API endpoints protected by Cognito User Pool authorizer
- **Fast IP endpoint** — Unauthenticated `/ip` route for instant IP display

## Architecture

```
Browser → API Gateway + Cognito → Lambda → Prefix Lists (multi-accounts × multi-regions)
                                                ↓
                                        Security Groups (auto-synced)
```

| Component | Technology |
|-----------|-----------|
| Backend | AWS Lambda (Python 3.13, ARM64, 256MB) via Chalice |
| API | API Gateway with Cognito authorizer |
| Auth | Cognito User Pool (USER_PASSWORD_AUTH) |
| Network | AWS Managed Prefix Lists → Security Groups |
| Cross-account | STS AssumeRole with credential caching |

## Project Structure

```
├── config.yaml.example    # Configuration template
├── pyproject.toml          # Python dependencies
├── scripts/
│   └── setup.py            # Deployment & SG sync script
└── chalice_app/
    ├── app.py              # Lambda routes (parallel execution)
    ├── chalicelib/
    │   ├── prefix_list_service.py  # EC2 client factory, prefix list ops, RDAP lookup
    │   └── index.html              # Single-page web UI
    └── .chalice/
        ├── config.json     # Chalice deployment config
        └── policy-prod.json # IAM policy
```

## Setup

### Prerequisites

- Python 3.13+
- AWS CLI configured
- Cognito User Pool with an app client (USER_PASSWORD_AUTH enabled)

### Configuration

```bash
cp config.yaml.example config.yaml
# Edit config.yaml with your account IDs, regions, Cognito settings
```

### Deploy

```bash
# Install dependencies
pip install -e .

# Full init: deploy Lambda + API Gateway, create IAM roles, prefix lists, sync SG rules
python scripts/setup.py --init

# Deploy only (no infra changes) — default when no flag is given
python scripts/setup.py

# Re-sync SG ingress rules (e.g. after adding new tagged Security Groups)
python scripts/setup.py --sync-sg
```

| Flag | What it does |
|------|-------------|
| (none) | Deploy Chalice app (Lambda + API Gateway) only |
| `--init` | Full init: deploy + IAM role + prefix lists + SG rule sync |
| `--sync-sg` | Re-sync SG ingress rules to reference prefix lists |

### Custom Domain (Optional)

To use a custom domain instead of the default API Gateway URL:

1. Create a custom domain in API Gateway
2. Map the `/api` stage to `/` (base path)
3. The frontend uses relative paths, so it works on any domain automatically

## API Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/` | No | HTML web UI |
| GET | `/ip` | No | Returns `{"ip": "x.x.x.x"}` |
| GET | `/ipinfo` | Yes | IP details: org, CIDR, range, country (via RDAP) |
| GET | `/status` | Yes | IP status across all regions + ports |
| POST | `/update` | Yes | Add IP to all prefix lists |

## Security

- All mutation endpoints require Cognito authentication
- Lambda IAM role follows least-privilege (ec2:Describe*, ec2:Modify* on prefix lists only)
- Cross-account access via scoped AssumeRole
- Management ports only open to prefix list IPs — no 0.0.0.0/0 rules
- boto3 clients configured with short timeouts and no retries to fail fast
