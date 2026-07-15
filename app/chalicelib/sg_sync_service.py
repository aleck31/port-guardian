"""SG sync service — tag-driven reconcile of SG ingress against the prefix list.

The port-guardian tag on a SG is the single source of truth: its value carries the
desired ports (e.g. '22,8443'). Shared by the Lambda /sgs and /sync-sg endpoints
and by setup.py --sync-sg.
"""


def parse_tag_ports(value, default_ports=None):
    """Parse a tag value into a desired-port set, or None if undeterminable.

    '22,8443' → {22, 8443}; 'none'/'off' → set() (explicit exit while keeping the
    tag for IAM scoping); legacy bare values ('enabled'/'true'/'') → default_ports,
    or None when no default is provided (caller should skip, not revoke).
    """
    value = (value or '').strip().lower()
    if value in ('none', 'off'):
        return set()
    if value in ('', 'enabled', 'true'):
        return set(default_ports) if default_ports else None
    ports = set()
    for part in value.split(','):
        part = part.strip()
        if part.isdigit():
            ports.add(int(part))
    return ports or None


def pl_ports_in_sg(sg, pl_id):
    """Return {port: rule} for TCP ingress rules in sg that reference pl_id."""
    out = {}
    for rule in sg.get('IpPermissions', []):
        if rule.get('IpProtocol') != 'tcp':
            continue
        if any(p['PrefixListId'] == pl_id for p in rule.get('PrefixListIds', [])):
            out[rule.get('FromPort')] = rule
    return out


def _collect_sgs(ec2, pl_id, tag_key):
    """Return {sg_id: sg} for every SG that carries the tag OR references the PL."""
    sgs = {}
    for sg in ec2.describe_security_groups(
        Filters=[{'Name': 'tag-key', 'Values': [tag_key]}]
    ).get('SecurityGroups', []):
        sgs[sg['GroupId']] = sg
    for sg in ec2.describe_security_groups(
        Filters=[{'Name': 'ip-permission.prefix-list-id', 'Values': [pl_id]}]
    ).get('SecurityGroups', []):
        sgs.setdefault(sg['GroupId'], sg)
    return sgs


def _sg_state(sg, pl_id, tag_key, default_ports=None):
    """Compute (tag_value, want, have) for one SG. want is None if undeterminable."""
    tag_val = next((t['Value'] for t in sg.get('Tags', []) if t['Key'] == tag_key), None)
    want = parse_tag_ports(tag_val, default_ports) if tag_val is not None else set()
    have = pl_ports_in_sg(sg, pl_id)
    return tag_val, want, have


def list_managed_sgs(ec2, pl_id, tag_key, default_ports=None):
    """Status of every tagged or PL-referencing SG, for display. No mutations."""
    out = []
    for sg_id, sg in sorted(_collect_sgs(ec2, pl_id, tag_key).items()):
        tag_val, want, have = _sg_state(sg, pl_id, tag_key, default_ports)
        out.append({
            'sg_id': sg_id,
            'name': sg.get('GroupName', ''),
            'tag': tag_val,
            'want': sorted(want) if want is not None else None,
            'have': sorted(have),
            'in_sync': want is not None and set(have) == want,
        })
    return out


def reconcile_sg_rules(ec2, pl_id, tag_key, default_ports=None):
    """Reconcile every SG's PL-referencing rules against its tag. Returns actions.

    Each action: {sg_id, name, port, action} where action is added/removed/exists/
    skipped/error:<msg>. SGs whose desired state is undeterminable (legacy tag, no
    default) are skipped — never revoked on a guess.
    """
    actions = []
    for sg_id, sg in sorted(_collect_sgs(ec2, pl_id, tag_key).items()):
        name = sg.get('GroupName', '')
        tag_val, want, have = _sg_state(sg, pl_id, tag_key, default_ports)
        if want is None:
            actions.append({'sg_id': sg_id, 'name': name, 'port': None,
                            'action': f'skipped (unparseable tag: {tag_val!r})'})
            continue

        for port in sorted(want - set(have)):
            try:
                ec2.authorize_security_group_ingress(
                    GroupId=sg_id,
                    IpPermissions=[{
                        'IpProtocol': 'tcp', 'FromPort': port, 'ToPort': port,
                        'PrefixListIds': [{'PrefixListId': pl_id, 'Description': 'port-guardian'}],
                    }],
                )
                actions.append({'sg_id': sg_id, 'name': name, 'port': port, 'action': 'added'})
            except Exception as e:
                actions.append({'sg_id': sg_id, 'name': name, 'port': port, 'action': f'error: {e}'})

        for port in sorted(set(have) - want):
            rule = have[port]
            try:
                ec2.revoke_security_group_ingress(
                    GroupId=sg_id,
                    IpPermissions=[{
                        'IpProtocol': 'tcp', 'FromPort': port,
                        'ToPort': rule.get('ToPort', port),
                        'PrefixListIds': [{'PrefixListId': pl_id}],
                    }],
                )
                actions.append({'sg_id': sg_id, 'name': name, 'port': port, 'action': 'removed'})
            except Exception as e:
                actions.append({'sg_id': sg_id, 'name': name, 'port': port, 'action': f'error: {e}'})

        for port in sorted(want & set(have)):
            actions.append({'sg_id': sg_id, 'name': name, 'port': port, 'action': 'exists'})
    return actions
