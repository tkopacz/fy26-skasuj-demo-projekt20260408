"""
Routing engine for the tactical relay service.

Loads routing rules from a YAML file and maps each incoming message to one or
more recipient queues based on priority, classification, and originator pattern.
"""

from __future__ import annotations

import fnmatch
import logging
from pathlib import Path
from typing import Optional

import yaml

from tactical_relay.queues import DLQ_RECIPIENT

logger = logging.getLogger(__name__)

# Action type constants
ACTION_DIRECT = "direct"
ACTION_MULTICAST = "multicast"
ACTION_STORE_AND_FORWARD = "store_and_forward"


class RoutingEngine:
    """
    Rule-based message router.

    Rules are loaded from a YAML file. Each rule specifies match criteria
    and an action. Rules are evaluated in order; the first match wins for
    ``direct`` and ``store_and_forward`` actions. ``multicast`` actions
    always send to all listed recipients.

    If no rule matches, the message is sent to the dead-letter queue.
    """

    def __init__(self, rules: Optional[list[dict]] = None) -> None:
        """
        Initialise the RoutingEngine with an optional list of rule dicts.

        Args:
            rules: Pre-parsed list of rule dicts. Pass None to start with an
                   empty rule set (load from file separately via load_rules).
        """
        self._rules: list[dict] = rules or []

    # ------------------------------------------------------------------
    # Rule loading
    # ------------------------------------------------------------------

    @classmethod
    def from_file(cls, rules_file: str) -> "RoutingEngine":
        """
        Create a RoutingEngine by loading rules from a YAML file.

        Args:
            rules_file: Path to the YAML routing rules file.

        Returns:
            A new RoutingEngine instance.

        Raises:
            FileNotFoundError: If the rules file does not exist.
            ValueError: If the rules file has invalid structure.
        """
        path = Path(rules_file)
        if not path.exists():
            raise FileNotFoundError(f"Routing rules file not found: {rules_file}")

        with open(rules_file, "r", encoding="utf-8") as fh:
            raw = yaml.safe_load(fh) or {}

        rules = raw.get("rules", [])
        if not isinstance(rules, list):
            raise ValueError("Routing rules file must have a top-level 'rules' list")

        for i, rule in enumerate(rules):
            cls._validate_rule(rule, index=i)

        engine = cls(rules=rules)
        logger.info("Loaded %d routing rules from %s", len(rules), rules_file)
        return engine

    @staticmethod
    def _validate_rule(rule: dict, index: int) -> None:
        """Raise ValueError if a rule dict is structurally invalid."""
        if not isinstance(rule, dict):
            raise ValueError(f"Rule[{index}] must be a dict, got {type(rule)}")
        action = rule.get("action", {})
        if not isinstance(action, dict):
            raise ValueError(f"Rule[{index}].action must be a dict")
        action_type = action.get("type")
        if action_type not in (ACTION_DIRECT, ACTION_MULTICAST, ACTION_STORE_AND_FORWARD):
            raise ValueError(
                f"Rule[{index}].action.type must be one of "
                f"{ACTION_DIRECT!r}, {ACTION_MULTICAST!r}, {ACTION_STORE_AND_FORWARD!r}; "
                f"got {action_type!r}"
            )
        recipients = action.get("recipients", [])
        if not isinstance(recipients, list) or not recipients:
            raise ValueError(f"Rule[{index}].action.recipients must be a non-empty list")

    # ------------------------------------------------------------------
    # Routing
    # ------------------------------------------------------------------

    def route(
        self,
        message_id: str,
        sender: str,
        priority: int,
        classification: str,
        destination: Optional[str] = None,
    ) -> list[str]:
        """
        Determine the recipient queue(s) for a message.

        Rules are evaluated in declaration order. The first matching rule's
        action determines the outcome.  If no rule matches, the message is
        routed to the dead-letter queue.

        Args:
            message_id: Unique message identifier (for logging only).
            sender: CN of the originating terminal.
            priority: Message priority (1-9).
            classification: Security classification label.
            destination: Optional explicit destination CN from the message.

        Returns:
            A list of recipient queue names. Never empty (falls back to DLQ).
        """
        for rule in self._rules:
            if self._matches(rule.get("match", {}), priority, classification, sender, destination):
                action = rule["action"]
                recipients = list(action["recipients"])
                action_type = action["type"]
                logger.debug(
                    "route: message_id=%r matched rule=%r action=%r recipients=%r",
                    message_id, rule.get("name", "unnamed"), action_type, recipients,
                )
                return recipients

        logger.warning(
            "route: message_id=%r sender=%r — no rule matched, sending to DLQ",
            message_id, sender,
        )
        return [DLQ_RECIPIENT]

    @staticmethod
    def _matches(
        criteria: dict,
        priority: int,
        classification: str,
        sender: str,
        destination: Optional[str],
    ) -> bool:
        """
        Return True if the message attributes satisfy all match criteria.

        An empty criteria dict matches everything (wildcard / default rule).

        Match fields:
        - priority_max: message priority must be <= this value
        - priority_min: message priority must be >= this value
        - classification: exact match (case-sensitive)
        - originator_pattern: fnmatch glob applied to sender CN
        - destination_pattern: fnmatch glob applied to destination CN
        """
        if not criteria:
            return True

        if "priority_max" in criteria:
            if priority > int(criteria["priority_max"]):
                return False

        if "priority_min" in criteria:
            if priority < int(criteria["priority_min"]):
                return False

        if "classification" in criteria:
            if classification != criteria["classification"]:
                return False

        if "originator_pattern" in criteria:
            if not fnmatch.fnmatch(sender, criteria["originator_pattern"]):
                return False

        if "destination_pattern" in criteria and destination is not None:
            if not fnmatch.fnmatch(destination, criteria["destination_pattern"]):
                return False

        return True

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------

    def get_rules(self) -> list[dict]:
        """Return a copy of the loaded routing rules."""
        return list(self._rules)
