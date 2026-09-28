"""Tier 1 detection — REQ-DET-001 to REQ-DET-013 (13 tests)."""
import pytest


class TestDetectionEngine:
    @pytest.mark.skip(reason="REQ-DET-001")
    def test_detection_names_rule_and_evidence(self):
        """REQ-DET-001: Every detection MUST name the rule that fired and the evidence."""
        ...

    @pytest.mark.skip(reason="REQ-DET-002")
    def test_tier1_response_chain_is_automatic(self):
        """REQ-DET-002: Detect -> Block -> Security Event, no operator approval."""
        ...

    @pytest.mark.skip(reason="REQ-DET-003")
    def test_tier2_response_never_quarantines_automatically(self):
        """REQ-DET-003: Tier 2 MUST NOT quarantine automatically. UC-04."""
        ...

    @pytest.mark.skip(reason="REQ-DET-004")
    def test_rules_individually_enableable_and_tunable(self):
        """REQ-DET-004: Each T1-*/T2-* rule MUST be enableable and tunable."""
        ...

    @pytest.mark.skip(reason="REQ-DET-005")
    def test_suppression_counts_but_no_alarm(self):
        """REQ-DET-005: Suppressed detection counted, no alarm. UC-04.E2."""
        ...

    @pytest.mark.skip(reason="REQ-DET-006")
    def test_dismiss_requires_reason_and_offers_suppression(self):
        """REQ-DET-006: Dismiss MUST require reason from taxonomy. UC-06.E1."""
        ...

    @pytest.mark.skip(reason="REQ-DET-007")
    def test_observe_state_does_not_fire_baseline_rules(self):
        """REQ-DET-007: OBSERVE devices MUST NOT fire baseline rules. UC-04.E3."""
        ...

    @pytest.mark.skip(reason="REQ-DET-008")
    def test_baseline_completion_requires_coverage_not_time(self):
        """REQ-DET-008: Baseline completion needs coverage, not elapsed time. UC-18.E1."""
        ...

    @pytest.mark.skip(reason="REQ-DET-009")
    def test_operator_can_rebaseline_device(self):
        """REQ-DET-009: Operator MUST be able to return device to OBSERVE."""
        ...

    @pytest.mark.skip(reason="REQ-DET-010")
    def test_correlation_key_window_threshold_declared_per_rule(self):
        """REQ-DET-010: Correlation MUST have declared key/window/threshold."""
        ...

    @pytest.mark.skip(reason="REQ-DET-011")
    def test_detection_not_in_packet_forwarding_path(self):
        """REQ-DET-011: Detection MUST be async, not in packet path."""
        ...

    @pytest.mark.skip(reason="REQ-DET-012")
    def test_detection_down_does_not_stop_enforcement(self):
        """REQ-DET-012: Enforcement MUST continue if detection stops. UC-02.E14."""
        ...

    @pytest.mark.skip(reason="REQ-DET-013")
    def test_gateway_detects_attacks_against_itself(self):
        """REQ-DET-013: MUST detect probes of its own management services."""
        ...
