"""Entry descriptions, lifetimes, the expiry sweep, manual adds, edits and the admin gate."""

import importlib
import json
from datetime import date

import pytest

from chalicelib import prefix_list_service as pls
from test_list_sync import E, FakePrefixList

TODAY = date(2026, 11, 22)


class TestDescriptionFormat:
    @pytest.mark.parametrize('desc', [
        '[PIN] [Guard] sg.out-az3 EIP',
        '[Guard] CN CHINANET SHAANXI 2026-09-21T08:34:46Z',
        '[Guard] [EXP:2026-12-21] SG Changi Airport 2026-09-18T06:20:22Z',
        'port-guardian 2026-03-24',
        '[PIN] AWS SG, ec2-peer-access',
        '',
    ])
    def test_existing_descriptions_round_trip_unchanged(self, desc):
        d = pls.parse_description(desc)
        assert pls.build_description(d['pinned'], d['guard'], d['expires'], d['label'], d['added']) == desc

    def test_missing_guard_marks_an_entry_added_outside_port_guardian(self):
        assert pls.parse_description('[PIN] AWS SG, ec2-peer-access')['guard'] is False

    def test_expiry_marker_keeps_fifo_ordering_intact(self):
        desc = '[Guard] [EXP:2026-12-21] SG Changi Airport 2026-09-18T06:20:22Z'
        assert pls._parse_entry_timestamp(desc).isoformat() == '2026-09-18T06:20:22+00:00'


class TestLifetime:
    @pytest.mark.parametrize('days, expected', [(0, None), (1, date(2026, 11, 23)), (180, date(2027, 5, 21))])
    def test_offered_lifetimes(self, days, expected):
        assert pls.expiry_for(days, TODAY) == expected

    def test_other_lifetimes_are_rejected(self):
        with pytest.raises(ValueError):
            pls.expiry_for(14, TODAY)

    def test_entry_is_valid_through_its_last_day(self):
        entries = [E('1.0.0.0/24', '[Guard] [EXP:2026-11-22] a'), E('2.0.0.0/24', '[Guard] [EXP:2026-11-21] b'),
                   E('3.0.0.0/24', '[PIN] [Guard] [EXP:2026-11-01] pinned'), E('4.0.0.0/24', '[Guard] none')]
        assert pls.expired(entries, TODAY) == ['2.0.0.0/24']

    def test_remove_expired_in_one_call(self):
        fake = FakePrefixList([E('1.0.0.0/24', '[Guard] [EXP:2026-11-20] a'), E('2.0.0.0/24', '[Guard] [EXP:2026-11-21] b'),
                               E('3.0.0.0/24', '[Guard] keep')])
        status, after = pls.remove_expired(fake, 'pl', TODAY)
        assert fake.modifies == 1 and after == fake.as_entries() == [E('3.0.0.0/24', '[Guard] keep')]
        assert status.startswith('removed 2')

    def test_nothing_expired_makes_no_call(self):
        fake = FakePrefixList([E('3.0.0.0/24', '[Guard] keep')])
        assert pls.remove_expired(fake, 'pl', TODAY)[0] == 'nothing expired' and fake.modifies == 0


class TestManualAdd:
    @pytest.mark.parametrize('text, expected', [('52.76.10.20', '52.76.10.20/32'), ('45.76.10.9/24', '45.76.10.0/24')])
    def test_normalizes(self, text, expected):
        assert pls.normalize_cidr(text) == expected

    @pytest.mark.parametrize('text', ['10.0.0.0/8', '203.0.113.0/24', '0.0.0.0/0', '8.0.0.0/12', '2001:db8::/32', 'nonsense', ''])
    def test_rejects_private_too_wide_ipv6_and_garbage(self, text):
        with pytest.raises(ValueError):
            pls.normalize_cidr(text)

    def test_markers_typed_into_the_label_are_dropped(self, monkeypatch):
        fake = FakePrefixList()
        pls.add_cidr_to_prefix_list(fake, 'pl', '45.76.10.0/24', '[PIN] office [EXP:2030-01-01]', lifetime_days=7)
        d = pls.parse_description(fake.as_entries()[0]['Description'])
        assert d['label'] == 'office' and not d['pinned'] and d['guard'] and d['expires'] is not None

    def test_pinned_add_has_no_expiry(self):
        fake = FakePrefixList()
        pls.add_cidr_to_prefix_list(fake, 'pl', '45.76.10.0/24', 'office', lifetime_days=7, pinned=True)
        d = pls.parse_description(fake.as_entries()[0]['Description'])
        assert d['pinned'] and d['expires'] is None

    def test_duplicate_is_refused(self):
        fake = FakePrefixList([E('45.76.10.0/24', '[Guard] x')])
        with pytest.raises(ValueError, match='already'):
            pls.add_cidr_to_prefix_list(fake, 'pl', '45.76.10.0/24', 'again')


class TestEdit:
    def test_editing_adopts_an_external_entry_and_keeps_its_time(self):
        fake = FakePrefixList([E('1.0.0.0/24', 'peering link 2026-03-24')])
        status, after = pls.update_entry(fake, 'pl', '1.0.0.0/24', label='peering to vpc-b', expires=date(2099, 1, 31))
        d = pls.parse_description(after[0]['Description'])
        assert status == 'updated' and after == fake.as_entries()
        assert d['guard'] and d['label'] == 'peering to vpc-b' and d['added'] == '2026-03-24'
        assert d['expires'] == date(2099, 1, 31)

    def test_expiry_can_be_cleared(self):
        fake = FakePrefixList([E('1.0.0.0/24', '[Guard] [EXP:2099-12-01] hotel')])
        pls.update_entry(fake, 'pl', '1.0.0.0/24', expires=None)
        assert pls.parse_description(fake.as_entries()[0]['Description'])['expires'] is None

    def test_past_expiry_is_refused(self):
        fake = FakePrefixList([E('1.0.0.0/24', '[Guard] hotel')])
        with pytest.raises(ValueError, match='past'):
            pls.update_entry(fake, 'pl', '1.0.0.0/24', expires=date(2000, 1, 1))
        assert fake.modifies == 0

    def test_pinning_clears_expiry(self):
        fake = FakePrefixList([E('1.0.0.0/24', '[Guard] [EXP:2026-12-01] hotel 2026-11-20T00:00:00Z')])
        pls.set_pin(fake, 'pl', '1.0.0.0/24', True)
        assert fake.as_entries()[0]['Description'] == '[PIN] [Guard] hotel 2026-11-20T00:00:00Z'


@pytest.fixture
def api(monkeypatch):
    env = {'PRIMARY_ACCOUNT_ID': '111', 'SECONDARY_ACCOUNT_ID': '222', 'AWS_REGION': 'ap-southeast-1',
           'TARGET_REGIONS': 'ap-southeast-1', 'COGNITO_REGION': 'ap-southeast-1', 'ADMIN_GROUP': 'admin',
           'COGNITO_USER_POOL_ID': 'ap-southeast-1_test', 'COGNITO_CLIENT_ID': 'client'}
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    m = importlib.import_module('app')
    lists = {t: FakePrefixList() for t in m._get_targets()}
    monkeypatch.setattr(m, 'get_ec2_client', lambda a, r: lists[(a, r)])
    monkeypatch.setattr(m, 'get_prefix_list_id', lambda ec2: 'pl-x')
    return m, lists


class TestAdminGate:
    @pytest.mark.parametrize('raw, groups', [
        ('admin', {'admin'}), ('[admin, ops]', {'admin', 'ops'}), ('[admin ops]', {'admin', 'ops'}),
        (['admin'], {'admin'}), ('', set()),
    ])
    def test_group_claim_formats(self, api, monkeypatch, raw, groups):
        m, _ = api

        class Req:
            context = {'authorizer': {'claims': {'cognito:groups': raw}}}
        monkeypatch.setattr(m.app, 'current_request', Req(), raising=False)
        assert m._caller_groups() == groups

    def _post(self, m, path, body, method='post'):
        from chalice.test import Client
        with Client(m.app) as c:
            r = getattr(c.http, method)(path, headers={'Content-Type': 'application/json'}, body=json.dumps(body))
            return r.status_code, json.loads(r.body or '{}')

    def test_writes_need_the_admin_group(self, api, monkeypatch):
        m, lists = api
        monkeypatch.setattr(m, '_caller_groups', lambda: {'viewers'})
        assert self._post(m, '/entries', {'cidr': '45.76.10.0/24', 'label': 'x'})[0] == 403
        assert self._post(m, '/sync-entries', {'dry_run': False})[0] == 403
        assert self._post(m, '/sync-entries', {'dry_run': True})[0] == 200
        assert all(f.modifies == 0 for f in lists.values())

    def test_admin_can_add_and_bad_lifetime_is_a_400(self, api, monkeypatch):
        m, lists = api
        monkeypatch.setattr(m, '_caller_groups', lambda: {'admin'})
        status, body = self._post(m, '/entries', {'cidr': '45.76.10.9/24', 'label': 'office', 'lifetime_days': 30})
        assert status == 200 and body['results'][0]['status'] == 'added'
        assert [e['Cidr'] for e in lists[('111', 'ap-southeast-1')].as_entries()] == ['45.76.10.0/24']
        assert self._post(m, '/entries', {'cidr': '198.51.100.0/24', 'lifetime_days': 14})[0] == 400
