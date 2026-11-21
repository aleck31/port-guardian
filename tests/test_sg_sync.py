"""SG overview: untagged SGs that use the whitelist must be visible before any sync."""

from chalicelib.sg_sync_service import list_managed_sgs, reconcile_sg_rules

PL = 'pl-1'


def sg(sg_id, ports, tag=None):
    return {'GroupId': sg_id, 'GroupName': sg_id + '-name',
            'Tags': [{'Key': 'port-guardian', 'Value': tag}] if tag is not None else [],
            'IpPermissions': [{'IpProtocol': 'tcp', 'FromPort': p, 'ToPort': p, 'PrefixListIds': [{'PrefixListId': PL}]}
                              for p in ports]}


class FakeEc2:
    def __init__(self, sgs):
        self.sgs = sgs

    def describe_security_groups(self, Filters):
        f = Filters[0]
        if f['Name'] == 'tag-key':
            hits = [s for s in self.sgs if any(t['Key'] in f['Values'] for t in s['Tags'])]
        else:
            hits = [s for s in self.sgs if any(x['PrefixListId'] in f['Values']
                                               for p in s['IpPermissions'] for x in p['PrefixListIds'])]
        return {'SecurityGroups': hits}


SGS = [sg('sg-tagged', [22, 8443], '22,8443'), sg('sg-alb', [443]), sg('sg-unrelated', [])]


def test_overview_lists_untagged_sgs_that_use_the_whitelist():
    rows = {r['sg_id']: r for r in list_managed_sgs(FakeEc2(SGS), PL, 'port-guardian')}
    assert set(rows) == {'sg-tagged', 'sg-alb'}
    assert rows['sg-tagged']['in_sync'] and not rows['sg-tagged']['untagged']
    assert rows['sg-alb']['untagged'] and not rows['sg-alb']['in_sync'] and rows['sg-alb']['have'] == [443]


def test_untagged_rules_are_only_reported_without_allow_exit():
    plan = reconcile_sg_rules(FakeEc2(SGS), PL, 'port-guardian', dry_run=True)
    assert [(a['sg_id'], a['port'], a['action']) for a in plan if a['sg_id'] == 'sg-alb'] == [
        ('sg-alb', 443, 'would_remove_exit')]
