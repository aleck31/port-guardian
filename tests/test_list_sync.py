"""Primary/replica list sync: the write functions, the diff, and the write-through."""

import importlib

import pytest

from chalicelib import prefix_list_service as pls


class FakePrefixList:
    """In-memory managed prefix list with the AWS behaviours the sync relies on.

    Versioned optimistic concurrency, AddEntries overwriting an existing CIDR's
    description, and rejecting a CIDR that appears in both AddEntries and
    RemoveEntries in one request.
    """

    def __init__(self, entries=(), fail=False):
        self.entries = {e['Cidr']: e.get('Description', '') for e in entries}
        self.version = 1
        self.modifies = 0
        self.fail = fail

    def describe_managed_prefix_lists(self, PrefixListIds):
        return {'PrefixLists': [{'PrefixListId': PrefixListIds[0], 'Version': self.version, 'MaxEntries': 25}]}

    def get_paginator(self, name):
        fake = self

        class Paginator:
            def paginate(self, PrefixListId, TargetVersion=None):
                assert TargetVersion in (None, fake.version)
                yield {'Entries': fake.as_entries()}
        return Paginator()

    def modify_managed_prefix_list(self, PrefixListId, CurrentVersion, AddEntries=(), RemoveEntries=()):
        if self.fail:
            raise RuntimeError('simulated AWS failure')
        assert CurrentVersion == self.version, 'stale version'
        added, removed = {e['Cidr'] for e in AddEntries}, {e['Cidr'] for e in RemoveEntries}
        assert not added & removed, 'CIDR in both AddEntries and RemoveEntries'
        for c in removed:
            del self.entries[c]
        for e in AddEntries:
            self.entries[e['Cidr']] = e.get('Description', '')
        self.version += 1
        self.modifies += 1

    def as_entries(self):
        return [pls._entry(c, d) for c, d in sorted(self.entries.items())]


def E(cidr, desc=''):
    return pls._entry(cidr, desc)


class TestDiffEntries:
    def test_identical_lists_have_no_diff(self):
        a = [E('1.0.0.0/24', 'x'), E('2.0.0.0/24', 'y')]
        assert not any(pls.diff_entries(a, list(reversed(a))).values())

    def test_reports_missing_extra_and_rewritten(self):
        desired = [E('1.0.0.0/24', 'keep'), E('2.0.0.0/24', '[PIN] p')]
        actual = [E('2.0.0.0/24', 'p'), E('3.0.0.0/24', 'stale')]
        assert pls.diff_entries(desired, actual) == {
            'add': ['1.0.0.0/24'], 'remove': ['3.0.0.0/24'], 'update': ['2.0.0.0/24']}


class TestSyncEntries:
    def test_converges_in_one_modify(self):
        desired = [E('1.0.0.0/24', 'keep'), E('2.0.0.0/24', '[PIN] p')]
        replica = FakePrefixList([E('2.0.0.0/24', 'p'), E('3.0.0.0/24', 'stale')])
        pls.sync_entries(replica, 'pl-r', desired)
        assert replica.as_entries() == desired
        assert replica.modifies == 1

    def test_second_run_is_a_no_op(self):
        desired = [E('1.0.0.0/24', 'keep')]
        replica = FakePrefixList()
        pls.sync_entries(replica, 'pl-r', desired)
        diff, _ = pls.sync_entries(replica, 'pl-r', desired)
        assert not any(diff.values())
        assert replica.modifies == 1

    def test_dry_run_changes_nothing(self):
        replica = FakePrefixList([E('3.0.0.0/24', 'stale')])
        diff, before = pls.sync_entries(replica, 'pl-r', [E('1.0.0.0/24')], dry_run=True)
        assert diff['remove'] == ['3.0.0.0/24'] and diff['add'] == ['1.0.0.0/24']
        assert replica.modifies == 0 and before == [E('3.0.0.0/24', 'stale')]


class TestWritesReturnResultingContents:
    """Replicas are synced from these return values, so they must equal the list's real state."""

    def test_add_with_eviction(self, monkeypatch):
        monkeypatch.setenv('MAX_ENTRIES', '2')
        monkeypatch.setattr(pls, '_fetch_rdap', lambda ip: None)
        monkeypatch.setattr(pls, '_cloud_networks', lambda: [])
        primary = FakePrefixList([E('1.0.0.0/24', '[Guard] CN 2026-01-01T00:00:00Z'),
                                  E('2.0.0.0/24', '[Guard] CN 2026-06-01T00:00:00Z')])
        status, after = pls.add_ip_to_prefix_list(primary, 'pl-p', '198.51.100.9')
        assert status == 'added'
        assert sorted(e['Cidr'] for e in after) == ['198.51.100.0/24', '2.0.0.0/24']
        assert sorted(after, key=lambda e: e['Cidr']) == primary.as_entries()

    def test_add_when_already_covered(self):
        primary = FakePrefixList([E('198.51.100.0/24', 'x')])
        assert pls.add_ip_to_prefix_list(primary, 'pl-p', '198.51.100.9') == ('already_exists', primary.as_entries())
        assert primary.modifies == 0

    def test_remove_absent_cidr_makes_no_call(self):
        primary = FakePrefixList([E('1.0.0.0/24', 'x')])
        assert pls.remove_cidr_from_prefix_list(primary, 'pl-p', '9.0.0.0/24') == ('absent', primary.as_entries())
        assert primary.modifies == 0

    def test_pin(self):
        primary = FakePrefixList([E('1.0.0.0/24', '[Guard] CN 2026-01-01T00:00:00Z')])
        status, after = pls.set_pin(primary, 'pl-p', '1.0.0.0/24', True)
        assert status == 'pinned' and after == primary.as_entries()
        assert pls.is_pinned(after[0]['Description'])


@pytest.fixture
def deployed(monkeypatch):
    """app.py wired to six fake lists; the primary is 111/ap-southeast-1."""
    env = {'PRIMARY_ACCOUNT_ID': '111', 'SECONDARY_ACCOUNT_ID': '222', 'AWS_REGION': 'ap-southeast-1',
           'TARGET_REGIONS': 'ap-southeast-1,us-west-2,ap-northeast-1', 'COGNITO_REGION': 'ap-southeast-1',
           'COGNITO_USER_POOL_ID': 'ap-southeast-1_test', 'COGNITO_CLIENT_ID': 'client'}
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    app_module = importlib.import_module('app')
    lists = {t: FakePrefixList() for t in app_module._get_targets()}
    monkeypatch.setattr(app_module, 'get_ec2_client', lambda a, r: lists[(a, r)])
    monkeypatch.setattr(app_module, 'get_prefix_list_id', lambda ec2: 'pl-x')
    return app_module, lists


class TestWriteThrough:
    def test_delete_repairs_drift_left_by_an_earlier_partial_write(self, deployed):
        app_module, lists = deployed
        base = [E('1.0.0.0/24', 'a'), E('2.0.0.0/24', 'b')]
        for fake in lists.values():
            fake.entries = {e['Cidr']: e['Description'] for e in base}
        lists[('222', 'us-west-2')].entries['9.9.0.0/16'] = 'orphan'   # e.g. a delete that failed there

        results = app_module._write_through(
            lambda ec2, pl_id: pls.remove_cidr_from_prefix_list(ec2, pl_id, '2.0.0.0/24'))

        assert results[0]['primary'] and results[0]['status'] == 'removed'
        assert all(not r['status'].startswith('error') for r in results)
        assert all(fake.as_entries() == [E('1.0.0.0/24', 'a')] for fake in lists.values())

    def test_failed_primary_write_touches_no_replica(self, deployed):
        app_module, lists = deployed
        lists[('111', 'ap-southeast-1')].fail = True
        lists[('111', 'ap-southeast-1')].entries = {'1.0.0.0/24': 'a'}

        results = app_module._write_through(
            lambda ec2, pl_id: pls.remove_cidr_from_prefix_list(ec2, pl_id, '1.0.0.0/24'))

        assert results[0]['status'].startswith('error')
        assert all(r['status'].startswith('skipped') for r in results[1:])
        assert all(fake.modifies == 0 for fake in lists.values())

    def test_replica_failure_is_reported_not_hidden(self, deployed):
        app_module, lists = deployed
        lists[('222', 'ap-northeast-1')].fail = True
        results = app_module._sync_replicas([E('1.0.0.0/24', 'a')])
        failed = [r for r in results if r['status'].startswith('error')]
        assert [(r['account'], r['region']) for r in failed] == [('222', 'ap-northeast-1')]

    def test_dry_run_flags_lost_access_for_the_caller(self, deployed):
        app_module, lists = deployed
        lists[('222', 'us-west-2')].entries = {'198.51.100.0/24': 'only here'}
        results = app_module._sync_replicas([E('1.0.0.0/24', 'a')], dry_run=True, ip='198.51.100.9')
        flagged = [(r['account'], r['region']) for r in results if r.get('loses_current_ip')]
        assert flagged == [('222', 'us-west-2')]
        assert all(fake.modifies == 0 for fake in lists.values())
        changed = next(r for r in results if (r['account'], r['region']) == ('222', 'us-west-2'))
        assert changed['descriptions'] == {'198.51.100.0/24': 'only here', '1.0.0.0/24': 'a'}

    def test_description_only_difference_is_not_access_drift(self, deployed):
        """Pre-sync writes stamped each list a second apart; that alone must not raise the alarm."""
        app_module, lists = deployed
        for (account, region), fake in lists.items():
            fake.entries = {'1.0.0.0/24': f'[Guard] CN 2026-09-21T08:34:4{len(region) % 10}Z'}
        statuses = {r['status'] for r in app_module._sync_replicas(
            lists[app_module._primary_target()].as_entries(), dry_run=True)}
        assert 'out of sync' not in statuses
