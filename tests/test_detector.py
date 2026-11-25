#!/usr/bin/env python3
"""核心检测逻辑单元测试（纯标准库 unittest，无需 pytest）。

运行：python3 -m unittest tests.test_detector -v
"""

from __future__ import annotations

import unittest

from mailbox_audit.config import AuditConfig
from mailbox_audit.detector import (
    evaluate_delegate,
    evaluate_forwarding,
    evaluate_rule,
)
from mailbox_audit.domains import (
    external_targets,
    is_internal_address,
    lookalike_of_internal,
)
from mailbox_audit.keywords import scan_text
from mailbox_audit.models import (
    DelegateEntry,
    ForwardingConfig,
    Rule,
    RuleAction,
    RuleCondition,
)


def make_config(**overrides) -> AuditConfig:
    base = AuditConfig(
        internal_domains={"contoso.com"},
        trusted_forward_domains={"contoso-archive.example"},
        trusted_service_principals={"app:trusted-sp-id"},
    )
    for key, value in overrides.items():
        setattr(base, key, value)
    return base


class DomainTests(unittest.TestCase):
    def test_internal_detection(self):
        self.assertTrue(is_internal_address("user@contoso.com", {"contoso.com"}))
        self.assertTrue(is_internal_address("user@mail.contoso.com", {"contoso.com"}))
        self.assertFalse(is_internal_address("user@evil.com", {"contoso.com"}))

    def test_external_targets(self):
        addresses = ["a@contoso.com", "b@evil.net", "c@contoso-archive.example"]
        result = external_targets(addresses, {"contoso.com"})
        self.assertEqual(set(result), {"b@evil.net", "c@contoso-archive.example"})

    def test_homoglyph_lookalike(self):
        # contosο 中的 ο 是希腊字母
        hit = lookalike_of_internal("ceo@contosο.com", {"contoso.com"})
        self.assertIsNotNone(hit)
        self.assertTrue(any("同形" in reason or "相似" in reason for reason in hit["reasons"]))

    def test_legit_domain_not_lookalike(self):
        self.assertIsNone(lookalike_of_internal("vendor@fabrikam.com", {"contoso.com"}))

    def test_hyphen_lookalike(self):
        hit = lookalike_of_internal("pay@con-toso.com", {"contoso.com"})
        self.assertIsNotNone(hit)

    def test_subdomain_wrapping(self):
        hit = lookalike_of_internal("x@contoso.com.evil.net", {"contoso.com"})
        self.assertIsNotNone(hit)


class KeywordTests(unittest.TestCase):
    def test_chinese_and_english(self):
        hits = scan_text("关于发票付款 invoice payment 的邮件")
        groups = {hit["group"] for hit in hits}
        self.assertIn("finance_payment", groups)

    def test_security_words(self):
        hits = scan_text("security alert: unusual sign-in")
        self.assertTrue(any(hit["group"] == "security" for hit in hits))

    def test_benign_text(self):
        self.assertEqual(scan_text("周末团建通知"), [])


class RuleDetectionTests(unittest.TestCase):
    def test_full_attack_chain_is_critical(self):
        rule = Rule(
            rule_id="r1", mailbox="finance@contoso.com", name="发票处理",
            conditions=[RuleCondition(field="subject", operator="contains",
                                     values=["发票", "payment"])],
            actions=[
                RuleAction(type="forward", targets=["evil@gmail.com"]),
                RuleAction(type="move", folder="RSS 订阅"),
            ],
        )
        finding = evaluate_rule(rule, make_config())
        self.assertIsNotNone(finding)
        self.assertIn(finding.severity, {"critical", "high"})
        codes = {s["code"] for s in finding.signals}
        self.assertIn("EXTERNAL_EGRESS", codes)
        self.assertIn("SENSITIVE_KEYWORD", codes)
        self.assertIn("HIDE_MOVE_FOLDER", codes)
        self.assertIn("FREE_MAIL_DEST", codes)

    def test_benign_internal_rule_no_finding(self):
        rule = Rule(
            rule_id="r2", mailbox="hr@contoso.com", name="简历归档",
            conditions=[RuleCondition(field="subject", operator="contains", values=["简历"])],
            actions=[RuleAction(type="move", folder="招聘\\简历库")],
        )
        self.assertIsNone(evaluate_rule(rule, make_config()))

    def test_external_forward_without_keywords_is_high_not_critical(self):
        rule = Rule(
            rule_id="r3", mailbox="user@contoso.com", name="同步",
            actions=[RuleAction(type="forward", targets=["personal@outlook.com"])],
        )
        finding = evaluate_rule(rule, make_config())
        self.assertIsNotNone(finding)
        self.assertLess(finding.score, 80)  # 单信号不足以 critical

    def test_trusted_partner_low_score(self):
        rule = Rule(
            rule_id="r4", mailbox="it@contoso.com", name="归档",
            actions=[RuleAction(type="forward",
                                targets=["vault@contoso-archive.example"])],
        )
        finding = evaluate_rule(rule, make_config())
        if finding:  # 可信合作方仅产生低权重信号
            self.assertEqual(finding.severity, "low")

    def test_hidden_rule_capped_without_egress(self):
        rule = Rule(
            rule_id="r5", mailbox="user@contoso.com", name="",
            hidden=True,
            actions=[RuleAction(type="mark_read")],
        )
        finding = evaluate_rule(rule, make_config())
        self.assertIsNotNone(finding)
        self.assertLessEqual(finding.score, 45)  # 不出组织封顶

    def test_obscure_header_and_guid_name(self):
        rule = Rule(
            rule_id="r6", mailbox="it@contoso.com",
            name="a7f3c2e1-9b4d-4f8a-b2c1-6e5d4c3b2a10",
            conditions=[RuleCondition(
                field="header:x-forefront-antispam-report",
                operator="header_contains", values=["SFV:SPM"])],
            actions=[RuleAction(type="redirect", targets=["x@proton.me"])],
        )
        finding = evaluate_rule(rule, make_config())
        codes = {s["code"] for s in finding.signals}
        self.assertIn("OBSCURE_HEADER_CONDITION", codes)
        self.assertIn("BLANK_OR_GUID_NAME", codes)

    def test_broad_scope_wildcard(self):
        rule = Rule(
            rule_id="r7", mailbox="user@contoso.com", name="all",
            conditions=[RuleCondition(field="subject", operator="contains", values=["*"])],
            actions=[RuleAction(type="forward", targets=["x@evil.com"])],
        )
        finding = evaluate_rule(rule, make_config())
        self.assertIn("BROAD_SCOPE", {s["code"] for s in finding.signals})

    def test_regex_obfuscation(self):
        rule = Rule(
            rule_id="r8", mailbox="user@contoso.com", name="r",
            conditions=[RuleCondition(field="body", operator="matches",
                                      values=[r"inv.*\d{3}"])],
            actions=[RuleAction(type="forward", targets=["x@evil.com"])],
        )
        finding = evaluate_rule(rule, make_config())
        self.assertIn("OBFUSCATED_CONDITION", {s["code"] for s in finding.signals})


class ForwardingDetectionTests(unittest.TestCase):
    def test_external_forward_no_copy_is_critical(self):
        forward = ForwardingConfig(
            mailbox="ceo@contoso.com", kind="smtp_forwarding", enabled=True,
            destination="ceo@contosο.com", deliver_to_mailbox_and_forward=False,
        )
        finding = evaluate_forwarding(forward, make_config())
        self.assertIsNotNone(finding)
        codes = {s["code"] for s in finding.signals}
        self.assertIn("NO_LOCAL_COPY", codes)
        self.assertIn("LOOKALIKE_DOMAIN", codes)
        self.assertEqual(finding.severity, "critical")

    def test_disabled_forwarding_no_finding(self):
        forward = ForwardingConfig(
            mailbox="a@contoso.com", kind="smtp_forwarding", enabled=False,
            destination="x@evil.com")
        self.assertIsNone(evaluate_forwarding(forward, make_config()))


class DelegateDetectionTests(unittest.TestCase):
    def test_external_full_access(self):
        delegate = DelegateEntry(
            mailbox="boss@contoso.com", delegate="consultant@external.net",
            permissions=["FullAccess"], access_type="full_access")
        finding = evaluate_delegate(delegate, make_config())
        codes = {s["code"] for s in finding.signals}
        self.assertIn("EXTERNAL_DELEGATE", codes)
        self.assertIn("FULL_ACCESS_DELEGATE", codes)

    def test_trusted_service_principal_downweighted(self):
        delegate = DelegateEntry(
            mailbox="a@contoso.com", delegate="app:trusted-sp-id",
            permissions=["FullAccess"], access_type="full_access",
            service_principal=True)
        finding = evaluate_delegate(delegate, make_config())
        sp_signal = next(s for s in finding.signals if s["code"] == "SERVICE_PRINCIPAL_DELEGATE")
        self.assertEqual(sp_signal["weight"], 5)

    def test_internal_delegate_low_risk(self):
        delegate = DelegateEntry(
            mailbox="ceo@contoso.com", delegate="ea@contoso.com",
            permissions=["FullAccess"], access_type="full_access")
        finding = evaluate_delegate(delegate, make_config())
        self.assertNotIn("EXTERNAL_DELEGATE", {s["code"] for s in finding.signals})


if __name__ == "__main__":
    unittest.main(verbosity=2)
