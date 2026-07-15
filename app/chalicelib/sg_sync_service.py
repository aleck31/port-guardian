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


def _collect_sgs(ec2, pl_id, tag_key, tagged_only=False):
    """Return {sg_id: sg} for SGs to consider.

    tagged_only: only SGs carrying the tag (cheap — for the overview). Otherwise also
    include SGs whose ingress references the PL (the PL-id filter is the slow query),
    so exit candidates — tag wiped but rule still present — surface for reconcile.
    """
    sgs = {}
    for sg in ec2.describe_security_groups(
        Filters=[{'Name': 'tag-key', 'Values': [tag_key]}]
    ).get('SecurityGroups', []):
        sgs[sg['GroupId']] = sg
    if not tagged_only:
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
    """Overview of tagged SGs only (cheap, no PL-id scan). No mutations."""
    out = []
    for sg_id, sg in sorted(_collect_sgs(ec2, pl_id, tag_key, tagged_only=True).items()):
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


def reconcile_sg_rules(ec2, pl_id, tag_key, default_ports=None, allow_exit=False, dry_run=False):
    """Reconcile every SG's PL-referencing rules against its tag. Returns actions.

    Each action: {sg_id, name, port, action} where action is added/removed/exists/
    skipped/would_add/would_remove/would_remove_exit/error:<msg>. SGs whose desired
    state is undeterminable (legacy tag, no default) are skipped — never touched.

    dry_run=True computes the plan without calling AWS (would_add/would_remove/...).
    This is also the query that does the slow PL-id scan for exit candidates, so the
    cheap tagged-only overview stays fast.

    Untagged SGs are the exit path, but a missing tag can also mean an IaC run wiped
    it (that once took down a live ALB), so exit revokes run only with allow_exit=True.
    Removals driven by an explicit tag value (port dropped, or 'none'/'off') are normal.
    """
    actions = []

    def _add(sg_id, name, port):
        if dry_run:
            return {'sg_id': sg_id, 'name': name, 'port': port, 'action': 'would_add'}
        try:
            ec2.authorize_security_group_ingress(
                GroupId=sg_id,
                IpPermissions=[{
                    'IpProtocol': 'tcp', 'FromPort': port, 'ToPort': port,
                    'PrefixListIds': [{'PrefixListId': pl_id, 'Description': 'port-guardian'}],
                }],
            )
            return {'sg_id': sg_id, 'name': name, 'port': port, 'action': 'added'}
        except Exception as e:
            return {'sg_id': sg_id, 'name': name, 'port': port, 'action': f'error: {e}'}

    def _remove(sg_id, name, port, rule, exit_path):
        label = 'would_remove_exit' if exit_path else 'would_remove'
        if dry_run:
            return {'sg_id': sg_id, 'name': name, 'port': port, 'action': label}
        try:
            ec2.revoke_security_group_ingress(
                GroupId=sg_id,
                IpPermissions=[{
                    'IpProtocol': 'tcp', 'FromPort': port,
                    'ToPort': rule.get('ToPort', port),
                    'PrefixListIds': [{'PrefixListId': pl_id}],
                }],
            )
            return {'sg_id': sg_id, 'name': name, 'port': port, 'action': 'removed'}
        except Exception as e:
            return {'sg_id': sg_id, 'name': name, 'port': port, 'action': f'error: {e}'}

    for sg_id, sg in sorted(_collect_sgs(ec2, pl_id, tag_key).items()):
        name = sg.get('GroupName', '')
        tag_val, want, have = _sg_state(sg, pl_id, tag_key, default_ports)
        if want is None:
            actions.append({'sg_id': sg_id, 'name': name, 'port': None,
                            'action': f'skipped (unparseable tag: {tag_val!r})'})
            continue

        is_exit = tag_val is None
        if is_exit and not allow_exit:
            # Report only; never revoke an exit candidate without explicit confirmation.
            for port in sorted(have):
                actions.append({'sg_id': sg_id, 'name': name, 'port': port, 'action': 'would_remove_exit'})
            continue

        for port in sorted(want - set(have)):
            actions.append(_add(sg_id, name, port))
        for port in sorted(set(have) - want):
            actions.append(_remove(sg_id, name, port, have[port], is_exit))
        for port in sorted(want & set(have)):
            actions.append({'sg_id': sg_id, 'name': name, 'port': port, 'action': 'exists'})
    return actions
