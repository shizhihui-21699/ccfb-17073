#!/usr/bin/env python3
"""适配器解析与基线存储测试。"""

from __future__ import annotations

import os
import tempfile
import unittest

from mailbox_audit.adapters.exo import ExchangeParser
from mailbox_audit.adapters.gmail import GmailParser
from mailbox_audit.models import MailboxSnapshot
from mailbox_audit.store import BaselineStore


class ExchangeParserTests(unittest.TestCase):
    def setUp(self):
        self.parser = ExchangeParser()

    def test_rule_forward_and_move(self):
        raw = {
            "Identity": "mbx\\rule1", "Mailbox": "mbx@contoso.com",
            "Name": "发票", "Enabled": True,
            "SubjectOrBodyContains": ["发票", "invoice"],
            "ForwardTo": ["evil@gmail.com"],
            "MoveToFolder": "mbx@contoso.com\\RSS",
        }
        rule = self.parser.parse_rule(raw, hidden=False)
        self.assertEqual(rule.mailbox, "mbx@contoso.com")
        action_types = {a.type for a in rule.actions}
        self.assertIn("forward", action_types)
        self.assertIn("move", action_types)
        self.assertTrue(any(c.values == ["发票", "invoice"] for c in rule.conditions))

    def test_hidden_flag(self):
        raw = {"Identity": "x\\h1", "Mailbox": "x@contoso.com", "Name": "",
               "IsHidden": True, "DeleteMessage": True}
        rule = self.parser.parse_rule(raw, hidden=False)
        self.assertTrue(rule.hidden)
        self.assertIn("delete", {a.type for a in rule.actions})

    def test_header_condition_split(self):
        raw = {"Identity": "x\\h2", "Mailbox": "x@contoso.com", "Name": "hdr",
               "HeaderContains": {"HeaderName": "X-Sender-Id", "Words": ["spam"]}}
        rule = self.parser.parse_rule(raw, hidden=False)
        self.assertEqual(rule.conditions[0].field, "header:x-sender-id")
        self.assertEqual(rule.conditions[0].values, ["spam"])

    def test_permission_list_not_double_stringified(self):
        rows = [{"Identity": "boss@contoso.com", "Trustee": "ea@contoso.com",
                 "AccessRights": ["FullAccess"]}]
        delegates = self.parser.parse_delegates(rows)
        self.assertEqual(delegates[0].permissions, ["FullAccess"])
        self.assertEqual(delegates[0].access_type, "full_access")

    def test_service_principal_detection(self):
        rows = [{"Identity": "a@contoso.com",
                 "Trustee": "app:8f9c2d4e-aaaa-bbbb-cccc-1234567890ab",
                 "AccessRights": ["FullAccess"]}]
        delegates = self.parser.parse_delegates(rows)
        self.assertTrue(delegates[0].service_principal)

    def test_smtp_prefix_stripped_in_forwarding(self):
        mbx = {"Identity": "ceo@contoso.com",
               "ForwardingSmtpAddress": "smtp:ceo@evil.com",
               "DeliverToMailboxAndForward": False}
        forwards = self.parser.parse_forwarding(mbx, None)
        self.assertEqual(forwards[0].destination, "ceo@evil.com")
        self.assertFalse(forwards[0].deliver_to_mailbox_and_forward)

    def test_hidden_dedup_across_files(self):
        visible = [{"Identity": "m\\r1", "Mailbox": "m@contoso.com",
                    "Name": "v", "MarkAsRead": True}]
        hidden = visible + [
            {"Identity": "m\\r1", "Mailbox": "m@contoso.com", "Name": "v",
             "IsHidden": False, "MarkAsRead": True},
            {"Identity": "m\\r2", "Mailbox": "m@contoso.com", "Name": "secret",
             "IsHidden": True, "DeleteMessage": True},
        ]
        snapshots = self.parser.parse_export(
            rules=visible, hidden_rules=hidden, forwarding=[],
            auto_config=[], permissions=[])
        rules = snapshots[0].rules
        identities = {r.rule_id for r in rules}
        self.assertEqual(identities, {"m\\r1", "m\\r2"})
        secret = next(r for r in rules if r.rule_id == "m\\r2")
        self.assertTrue(secret.hidden)

    def test_no_false_coverage_warning_when_hidden_present(self):
        snapshots = self.parser.parse_export(
            rules=[{"Identity": "m\\r1", "Mailbox": "m@contoso.com", "Name": "v"}],
            hidden_rules=[{"Identity": "m\\r1", "Mailbox": "m@contoso.com",
                           "Name": "v", "IsHidden": False}],
            forwarding=[], auto_config=[], permissions=[])
        self.assertEqual(snapshots[0].warnings, [])

    def test_coverage_warning_when_hidden_missing(self):
        snapshots = self.parser.parse_export(
            rules=[{"Identity": "m\\r1", "Mailbox": "m@contoso.com", "Name": "v"}],
            hidden_rules=[], forwarding=[], auto_config=[], permissions=[])
        self.assertTrue(any("IncludeHidden" in w for w in snapshots[0].warnings))


class GmailParserTests(unittest.TestCase):
    def setUp(self):
        self.parser = GmailParser()

    def test_filter_forward_and_archive(self):
        raw = {
            "id": "f1",
            "criteria": {"subject": "invoice", "query": "has:attachment"},
            "action": {"addForwardingEmailAddress": "x@gmail.com",
                       "archive": True, "removeLabelIds": ["INBOX"]},
        }
        rule = self.parser.parse_filter("user@corp.com", raw)
        self.assertIn("forward", {a.type for a in rule.actions})
        self.assertTrue(any(c.field == "query" for c in rule.conditions))

    def test_delete_filter(self):
        raw = {"id": "f2", "criteria": {"subject": "security alert"},
               "action": {"delete": True}}
        rule = self.parser.parse_filter("user@corp.com", raw)
        self.assertIn("delete", {a.type for a in rule.actions})

    def test_auto_forwarding_disabled(self):
        self.assertIsNone(
            self.parser.parse_auto_forwarding("a@corp.com", {"enabled": False}))

    def test_export_end_to_end(self):
        snapshots = self.parser.parse_export(
            gmail_filters=[{"mailbox": "a@corp.com", "id": "f1",
                            "criteria": {"from": "boss"},
                            "action": {"addForwardingEmailAddress": "out@evil.net"}}],
            gmail_forwarding=[{"mailbox": "a@corp.com",
                               "autoForwarding": {"enabled": True,
                                                  "emailAddress": "out@evil.net"}}],
            gmail_delegates=[{"mailbox": "a@corp.com",
                              "delegates": [{"delegateEmail": "pa@corp.com",
                                             "verificationStatus": "accepted"}]}],
        )
        snap = snapshots[0]
        self.assertEqual(len(snap.rules), 1)
        self.assertEqual(snap.forwarding[0].destination, "out@evil.net")
        self.assertEqual(snap.delegates[0].delegate, "pa@corp.com")


class BaselineStoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        self.store = BaselineStore(self.tmp.name)

    def tearDown(self):
        self.store.close()
        os.unlink(self.tmp.name)

    def _snapshot(self, mailbox="a@contoso.com", rule_id="r1", forward_to=None):
        from mailbox_audit.models import Rule, RuleAction
        actions = [RuleAction(type="forward", targets=[forward_to])] if forward_to else []
        return MailboxSnapshot(
            mailbox=mailbox, source_system="test",
            rules=[Rule(rule_id=rule_id, mailbox=mailbox, name="n", actions=actions)],
        )

    def test_new_changed_removed_lifecycle(self):
        first = self.store.diff_and_update([self._snapshot()])
        self.assertEqual(first[("a@contoso.com", "rule", "r1")], "new")

        second = self.store.diff_and_update([self._snapshot()])
        self.assertEqual(second[("a@contoso.com", "rule", "r1")], "unchanged")

        # 修改动作 → changed
        changed = self.store.diff_and_update(
            [self._snapshot(forward_to="new@evil.com")])
        self.assertEqual(changed[("a@contoso.com", "rule", "r1")], "changed")

        # 规则消失 → removed
        removed = self.store.diff_and_update([
            MailboxSnapshot(mailbox="a@contoso.com", source_system="test")])
        self.assertEqual(removed[("a@contoso.com", "rule", "r1")], "removed")


if __name__ == "__main__":
    unittest.main(verbosity=2)
