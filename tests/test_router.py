"""Tests for the routing engine module."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from tactical_relay.queues import DLQ_RECIPIENT
from tactical_relay.router import RoutingEngine


class TestRuleLoading:
    """Tests for loading routing rules from YAML."""

    def test_load_from_file(self, routing_engine):
        rules = routing_engine.get_rules()
        assert len(rules) == 3

    def test_missing_file_raises(self):
        with pytest.raises(FileNotFoundError):
            RoutingEngine.from_file("/nonexistent/rules.yaml")

    def test_invalid_action_type_raises(self, tmp_path):
        rules_file = tmp_path / "bad_rules.yaml"
        rules_file.write_text(yaml.dump({
            "rules": [{"name": "bad", "match": {}, "action": {"type": "unknown", "recipients": ["X"]}}]
        }))
        with pytest.raises(ValueError, match="action.type"):
            RoutingEngine.from_file(str(rules_file))

    def test_empty_recipients_raises(self, tmp_path):
        rules_file = tmp_path / "bad_recipients.yaml"
        rules_file.write_text(yaml.dump({
            "rules": [{"name": "bad", "match": {}, "action": {"type": "direct", "recipients": []}}]
        }))
        with pytest.raises(ValueError, match="recipients"):
            RoutingEngine.from_file(str(rules_file))


class TestPriorityMatching:
    """Tests for priority-based rule matching."""

    def test_priority_max_matches(self, routing_engine):
        # Rule 1: priority_max=2, classification=TOP_SECRET, originator=FIELD-*
        result = routing_engine.route("m1", "FIELD-ALPHA", priority=1, classification="TOP_SECRET")
        assert set(result) == {"HQ-PRIMARY", "HQ-BACKUP"}

    def test_priority_max_does_not_match_high_priority_number(self, routing_engine):
        # priority=5 > priority_max=2 → should not match rule 1
        result = routing_engine.route("m2", "FIELD-ALPHA", priority=5, classification="TOP_SECRET")
        # Falls to default rule
        assert result == ["DEFAULT-QUEUE"]

    def test_priority_min_matching(self, tmp_path):
        rules_file = tmp_path / "priority_min.yaml"
        rules_file.write_text(yaml.dump({
            "rules": [
                {"name": "low-priority", "match": {"priority_min": 7}, "action": {"type": "direct", "recipients": ["LOW-Q"]}},
                {"name": "default", "match": {}, "action": {"type": "direct", "recipients": ["DEFAULT-Q"]}},
            ]
        }))
        engine = RoutingEngine.from_file(str(rules_file))
        assert engine.route("m", "S", priority=8, classification="U") == ["LOW-Q"]
        assert engine.route("m", "S", priority=3, classification="U") == ["DEFAULT-Q"]


class TestClassificationMatching:
    """Tests for classification-based rule matching."""

    def test_confidential_routes_to_relay(self, routing_engine):
        result = routing_engine.route("m", "FIELD-ALPHA", priority=5, classification="CONFIDENTIAL")
        assert result == ["RELAY-NODE-1"]

    def test_unclassified_falls_to_default(self, routing_engine):
        result = routing_engine.route("m", "FIELD-ALPHA", priority=5, classification="UNCLASSIFIED")
        assert result == ["DEFAULT-QUEUE"]


class TestOriginatorPattern:
    """Tests for fnmatch originator pattern matching."""

    def test_field_prefix_matches(self, routing_engine):
        result = routing_engine.route("m", "FIELD-GAMMA", priority=1, classification="TOP_SECRET")
        assert "HQ-PRIMARY" in result

    def test_non_field_sender_not_matched(self, routing_engine):
        result = routing_engine.route("m", "ADMIN-CONSOLE", priority=1, classification="TOP_SECRET")
        # originator_pattern=FIELD-* does not match ADMIN-CONSOLE → falls to confidential or default
        assert result == ["DEFAULT-QUEUE"]

    def test_wildcard_pattern(self, tmp_path):
        rules_file = tmp_path / "pattern.yaml"
        rules_file.write_text(yaml.dump({
            "rules": [
                {"name": "hq", "match": {"originator_pattern": "HQ-*"}, "action": {"type": "direct", "recipients": ["ADMIN-Q"]}},
                {"name": "default", "match": {}, "action": {"type": "direct", "recipients": ["DEFAULT-Q"]}},
            ]
        }))
        engine = RoutingEngine.from_file(str(rules_file))
        assert engine.route("m", "HQ-PRIMARY", 5, "U") == ["ADMIN-Q"]
        assert engine.route("m", "FIELD-ALPHA", 5, "U") == ["DEFAULT-Q"]


class TestMulticastRouting:
    """Tests for multicast action type."""

    def test_multicast_returns_multiple_recipients(self, routing_engine):
        result = routing_engine.route("m", "FIELD-ALPHA", priority=2, classification="TOP_SECRET")
        assert len(result) == 2
        assert "HQ-PRIMARY" in result
        assert "HQ-BACKUP" in result


class TestDLQFallback:
    """Tests for dead-letter queue fallback."""

    def test_no_matching_rule_goes_to_dlq(self, tmp_path):
        rules_file = tmp_path / "no_default.yaml"
        rules_file.write_text(yaml.dump({
            "rules": [
                {"name": "specific", "match": {"classification": "SECRET"}, "action": {"type": "direct", "recipients": ["SECRET-Q"]}},
            ]
        }))
        engine = RoutingEngine.from_file(str(rules_file))
        result = engine.route("m", "FIELD-ALPHA", priority=5, classification="UNCLASSIFIED")
        assert result == [DLQ_RECIPIENT]

    def test_empty_rules_sends_to_dlq(self):
        engine = RoutingEngine(rules=[])
        assert engine.route("m", "S", 5, "U") == [DLQ_RECIPIENT]
