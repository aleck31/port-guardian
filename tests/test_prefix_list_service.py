"""Regression tests for RDAP prefix selection and entry-description parsing.

RDAP payloads below are trimmed captures of real responses (ARIN, 2026-09), kept
verbatim in the fields under test so the cases stay honest: a range that
summarizes into several blocks, a range that summarizes into one, an allocation
wider than the /16 clamp, and an opaque ARIN id carrying no network.
"""

import ipaddress
from datetime import datetime, timezone

import pytest
import requests

from chalicelib.prefix_list_service import (
    FALLBACK_PREFIX_LEN,
    WIDEST_PREFIX_LEN,
    _cloud_networks,
    _is_cloud_ip,
    _parse_entry_timestamp,
    _rdap_cidr,
    get_bgp_prefix,
    is_pinned,
)

# HKBN: 101.78.129.0 - 101.78.131.255 summarizes to [/24, /23]; the IP is in the /23.
RDAP_MULTI_BLOCK = {'handle': '101.78.129.0 - 101.78.131.255', 'country': 'HK'}
# HKBN: an already-aligned /16, summarizes to exactly one block.
RDAP_SINGLE_BLOCK = {'handle': '61.244.0.0 - 61.244.255.255', 'country': 'HK'}
# China Mobile: a /11-scale allocation, wider than the clamp.
RDAP_WIDER_THAN_CLAMP = {'handle': '223.64.0.0 - 223.117.255.255', 'country': 'CN'}
# AWS space registered to ARIN: handle is an opaque id, not a network.
RDAP_OPAQUE_HANDLE = {
    'handle': 'NET-52-0-0-0-1',
    'startAddress': '52.0.0.0',
    'endAddress': '52.79.255.255',
}
RDAP_CIDR_HANDLE = {'handle': '203.0.113.0/24'}


@pytest.fixture(autouse=True)
def no_cloud_ranges(monkeypatch):
    """Keep the RDAP cases offline: no IP resolves as cloud unless a test says so."""
    monkeypatch.setattr('chalicelib.prefix_list_service._cloud_networks', lambda: [])


class TestRdapCidr:
    def test_picks_the_block_containing_the_ip_not_the_first(self):
        """The regression: a multi-block range whose first block excludes the IP.

        Returning that first block added an entry that could never match, so the
        user stayed un-whitelisted while the update reported success.
        """
        assert _rdap_cidr(RDAP_MULTI_BLOCK, '101.78.130.4') == '101.78.130.0/23'

    def test_single_block_range_is_used_as_is(self):
        assert _rdap_cidr(RDAP_SINGLE_BLOCK, '61.244.10.20') == '61.244.0.0/16'

    def test_allocation_wider_than_clamp_narrows_to_widest_allowed(self):
        assert _rdap_cidr(RDAP_WIDER_THAN_CLAMP, '223.104.1.5') == '223.104.0.0/16'

    def test_opaque_handle_falls_back_to_fixed_width(self):
        """No network in the handle — startAddress is deliberately unused (T-7.6)."""
        assert _rdap_cidr(RDAP_OPAQUE_HANDLE, '52.76.50.151') == '52.76.50.0/24'

    def test_cidr_handle(self):
        assert _rdap_cidr(RDAP_CIDR_HANDLE, '203.0.113.7') == '203.0.113.0/24'

    def test_missing_rdap_falls_back_to_fixed_width(self):
        assert _rdap_cidr(None, '198.51.100.9') == '198.51.100.0/24'

    def test_malformed_handle_falls_back_instead_of_raising(self):
        assert _rdap_cidr({'handle': 'not - an - address'}, '198.51.100.9') == '198.51.100.0/24'

    @pytest.mark.parametrize('data, ip', [
        (RDAP_MULTI_BLOCK, '101.78.130.4'),
        (RDAP_MULTI_BLOCK, '101.78.129.1'),
        (RDAP_SINGLE_BLOCK, '61.244.10.20'),
        (RDAP_WIDER_THAN_CLAMP, '223.104.1.5'),
        (RDAP_OPAQUE_HANDLE, '52.76.50.151'),
        (RDAP_CIDR_HANDLE, '203.0.113.7'),
        (None, '198.51.100.9'),
        ({'handle': 'garbage'}, '198.51.100.9'),
    ])
    def test_result_always_contains_the_ip(self, data, ip):
        """The invariant that makes an entry useful; violating it fails silently."""
        net = ipaddress.ip_network(_rdap_cidr(data, ip))
        assert ipaddress.ip_address(ip) in net

    @pytest.mark.parametrize('data, ip', [
        (RDAP_WIDER_THAN_CLAMP, '223.104.1.5'),
        (RDAP_MULTI_BLOCK, '101.78.130.4'),
        (None, '198.51.100.9'),
    ])
    def test_result_is_never_wider_than_the_clamp(self, data, ip):
        net = ipaddress.ip_network(_rdap_cidr(data, ip))
        assert net.prefixlen >= WIDEST_PREFIX_LEN

    def test_get_bgp_prefix_uses_the_lookup(self, monkeypatch):
        monkeypatch.setattr(
            'chalicelib.prefix_list_service._fetch_rdap', lambda ip: RDAP_MULTI_BLOCK
        )
        assert get_bgp_prefix('101.78.130.4') == '101.78.130.0/23'

    def test_fallback_width_constant_matches_behaviour(self):
        net = ipaddress.ip_network(_rdap_cidr(None, '198.51.100.9'))
        assert net.prefixlen == FALLBACK_PREFIX_LEN


class TestCloudHostedIp:
    """A cloud-hosted client is pinned to its own address.

    The provider's own space is other tenants' instances, and the address is
    static or Elastic, so the churn a wider block would prevent does not happen.
    """

    AWS_RANGES = [ipaddress.ip_network('52.76.0.0/17')]

    def test_cloud_ip_becomes_a_single_address(self, monkeypatch):
        monkeypatch.setattr(
            'chalicelib.prefix_list_service._cloud_networks', lambda: self.AWS_RANGES
        )
        assert _rdap_cidr(RDAP_OPAQUE_HANDLE, '52.76.50.151') == '52.76.50.151/32'

    def test_non_cloud_ip_still_uses_the_rdap_allocation(self, monkeypatch):
        monkeypatch.setattr(
            'chalicelib.prefix_list_service._cloud_networks', lambda: self.AWS_RANGES
        )
        assert _rdap_cidr(RDAP_MULTI_BLOCK, '101.78.130.4') == '101.78.130.0/23'

    def test_undetermined_does_not_widen(self, monkeypatch):
        """Range list unreachable: fall back to the fixed width, never to a /16."""
        monkeypatch.setattr(
            'chalicelib.prefix_list_service._cloud_networks', lambda: None
        )
        assert _rdap_cidr(RDAP_OPAQUE_HANDLE, '52.76.50.151') == '52.76.50.0/24'

    def test_is_cloud_ip_reports_undetermined_as_none(self, monkeypatch):
        monkeypatch.setattr(
            'chalicelib.prefix_list_service._cloud_networks', lambda: None
        )
        assert _is_cloud_ip('52.76.50.151') is None

    def test_fetch_failure_is_undetermined_not_false(self, monkeypatch):
        """A failed fetch must not read as 'not cloud', which would widen the block."""
        def boom(*args, **kwargs):
            raise requests.RequestException('unreachable')

        monkeypatch.setattr('chalicelib.prefix_list_service.requests.get', boom)
        monkeypatch.setattr('chalicelib.prefix_list_service._cloud_ranges_cache', {})
        assert _cloud_networks() is None

    def test_ranges_are_cached_across_calls(self, monkeypatch):
        calls = []

        class Response:
            @staticmethod
            def raise_for_status():
                pass

            @staticmethod
            def json():
                return {'prefixes': [{'ip_prefix': '52.76.0.0/17'}]}

        def counting_get(*args, **kwargs):
            calls.append(1)
            return Response()

        monkeypatch.setattr('chalicelib.prefix_list_service.requests.get', counting_get)
        monkeypatch.setattr('chalicelib.prefix_list_service._cloud_ranges_cache', {})
        assert _cloud_networks() == [ipaddress.ip_network('52.76.0.0/17')]
        assert _cloud_networks() == [ipaddress.ip_network('52.76.0.0/17')]
        assert len(calls) == 1


class TestParseEntryTimestamp:
    EXPECTED = datetime(2026, 7, 16, 4, 53, 48, tzinfo=timezone.utc)

    def test_current_format_with_isp(self):
        desc = '[Guard] CN China Mobile 2026-07-16T04:53:48Z'
        assert _parse_entry_timestamp(desc) == self.EXPECTED

    def test_current_format_without_isp(self):
        assert _parse_entry_timestamp('[Guard] CN 2026-07-16T04:53:48Z') == self.EXPECTED

    def test_pinned_entry_still_parses(self):
        """The regression: a [PIN] prefix hid the [Guard] marker from the parser,
        so a pinned entry read as the oldest-possible sentinel."""
        desc = '[PIN] [Guard] CN China Mobile 2026-07-16T04:53:48Z'
        assert _parse_entry_timestamp(desc) == self.EXPECTED

    def test_legacy_format(self):
        assert _parse_entry_timestamp('port-guardian 2026-03-20T06:08:00Z') == datetime(
            2026, 3, 20, 6, 8, tzinfo=timezone.utc
        )

    def test_date_only_token_is_forced_to_aware_utc(self):
        parsed = _parse_entry_timestamp('port-guardian 2026-03-24')
        assert parsed == datetime(2026, 3, 24, tzinfo=timezone.utc)
        assert parsed.tzinfo is not None

    @pytest.mark.parametrize('desc', ['', None, 'peering link', 'no timestamp here'])
    def test_unparseable_sorts_oldest_and_stays_aware(self, desc):
        parsed = _parse_entry_timestamp(desc)
        assert parsed == datetime.min.replace(tzinfo=timezone.utc)
        assert parsed.tzinfo is not None

    def test_pinned_entry_is_not_the_fifo_victim(self):
        """Ordering check across the mixed formats a real list accumulates."""
        entries = [
            '[PIN] [Guard] CN China Mobile 2026-01-01T00:00:00Z',
            '[Guard] HK 2026-07-16T04:53:48Z',
            'port-guardian 2026-03-24',
        ]
        evictable = [d for d in entries if not is_pinned(d)]
        assert min(evictable, key=_parse_entry_timestamp) == 'port-guardian 2026-03-24'
