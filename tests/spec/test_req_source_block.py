"""Source block list — REQ-SBL-001 to REQ-SBL-033 (20 tests)."""
import pytest


class TestSourceBlockCreation:
    @pytest.mark.skip(reason="REQ-SBL-001")
    def test_t1_detection_adds_source_without_operator(self):
        """REQ-SBL-001: Tier-1 block without operator approval."""
        ...

    @pytest.mark.skip(reason="REQ-SBL-002")
    def test_single_packet_does_not_create_block(self):
        """REQ-SBL-002: Single packet MUST NOT block. UC-03.E1."""
        ...

    @pytest.mark.skip(reason="REQ-SBL-003")
    def test_udp_rate_limited_not_blocked(self):
        """REQ-SBL-003: UDP/ICMP MUST be rate-limited. UC-03.E2."""
        ...

    @pytest.mark.skip(reason="REQ-SBL-004")
    def test_automatic_block_is_slash_32_only(self):
        """REQ-SBL-004: Automatic block MUST be /32. UC-03.E8."""
        ...

    @pytest.mark.skip(reason="REQ-SBL-005")
    def test_operator_prefix_block_requires_audit(self):
        """REQ-SBL-005: Prefix block MUST be audited operator action."""
        ...

    @pytest.mark.skip(reason="REQ-SBL-006")
    def test_full_blocklist_evicts_oldest_last_hit(self):
        """REQ-SBL-006: Overflow evicts oldest last_hit_at. UC-03.E5."""
        ...

    @pytest.mark.skip(reason="REQ-SBL-007")
    def test_ttl_refreshes_on_each_hit(self):
        """REQ-SBL-007: A hit refreshes TTL."""
        ...

    @pytest.mark.skip(reason="REQ-SBL-008")
    def test_blocklist_persists_across_reboot(self):
        """REQ-SBL-008: Blocklist MUST persist, checksummed, atomic."""
        ...

    @pytest.mark.skip(reason="REQ-SBL-009")
    def test_corrupt_blocklist_starts_empty_and_alarms(self):
        """REQ-SBL-009: Corrupt blocklist MUST start empty. UC-15.E3."""
        ...

    @pytest.mark.skip(reason="REQ-SBL-010")
    def test_block_write_is_read_back_and_divergence_alarms(self):
        """REQ-SBL-010 MUST VERIFY: Read back after write. UC-03.E6."""
        ...


class TestNeverBlockList:
    @pytest.mark.skip(reason="REQ-SBL-020")
    def test_never_block_checked_before_insert(self):
        """REQ-SBL-020: Check never-block at insert/apply/boot. UC-03.E3."""
        ...

    @pytest.mark.skip(reason="REQ-SBL-021")
    def test_never_block_floor_includes_control_plane_dns_ntp(self):
        """REQ-SBL-021: Compiled-in floor always present."""
        ...

    @pytest.mark.skip(reason="REQ-SBL-022")
    def test_icmp_pmtud_never_blocked_on_wan(self):
        """REQ-SBL-022: ICMP type 3 code 4 never blocked."""
        ...

    @pytest.mark.skip(reason="REQ-SBL-023")
    def test_policy_narrowing_below_floor_rejected(self):
        """REQ-SBL-023: Policy below floor MUST be rejected at validation."""
        ...

    @pytest.mark.skip(reason="REQ-SBL-024")
    def test_exempt_purges_existing_block_within_2s(self):
        """REQ-SBL-024: Becoming never-block purges block within 2s."""
        ...

    @pytest.mark.skip(reason="REQ-SBL-025")
    def test_never_block_change_goes_through_commit_confirm(self):
        """REQ-SBL-025: Never-block changes are structural."""
        ...


class TestOperatorControl:
    @pytest.mark.skip(reason="REQ-SBL-030")
    def test_release_records_all_audit_fields(self):
        """REQ-SBL-030: Release MUST record actor/timestamp/event/reason."""
        ...

    @pytest.mark.skip(reason="REQ-SBL-031")
    def test_exempt_adds_to_never_block_with_audit(self):
        """REQ-SBL-031: Exempt MUST audit same fields."""
        ...

    @pytest.mark.skip(reason="REQ-SBL-032")
    def test_release_works_locally_when_cloud_unreachable(self):
        """REQ-SBL-032: Local CLI release works offline. UC-14.E1."""
        ...

    @pytest.mark.skip(reason="REQ-SBL-033")
    def test_blocklist_is_readable_through_api(self):
        """REQ-SBL-033: Blocklist MUST be API-readable."""
        ...
