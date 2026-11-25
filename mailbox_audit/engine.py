"""审计编排：采集 → 检测 → 基线对比 → 报告 → 告警。"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from .alerts import Alerter
from .config import AuditConfig
from .detector import _finding_id, evaluate_snapshot
from .models import Finding, MailboxSnapshot
from .reporting import write_all
from .store import BaselineStore

logger = logging.getLogger("mailbox_audit")


def _removed_finding_id(mailbox: str, object_type: str, object_id: str) -> str:
    # 与 detector._finding_id 保持同一算法，保证基线 key 能映射回结论
    return _finding_id(mailbox, object_type, object_id)


@dataclass
class AuditRunResult:
    findings: list
    snapshots: list
    report_paths: dict
    alerted: int
    baseline_states: dict


def run_audit(snapshots: list[MailboxSnapshot], config: AuditConfig,
              *, update_baseline: bool = True, send_alerts: bool = True) -> AuditRunResult:
    logger.info("开始检测：%d 个邮箱快照", len(snapshots))
    findings: list[Finding] = []
    for snapshot in snapshots:
        findings.extend(evaluate_snapshot(snapshot, config))

    # 基线对比，先拿到全部对象的 new / changed / unchanged / removed 状态
    with BaselineStore(config.baseline_db) as store:
        states = store.diff_and_update(snapshots)
        known_finding_ids = store.previously_open_finding_ids()

        # 把 removed 对象补成结论：攻击者删掉规则/委托清理痕迹时必须可见。
        # 若上一轮已报过该对象消失（finding 已在历史表），本轮状态收敛为
        # unchanged，避免对象持续缺席时每轮重复告警。
        for mailbox, object_type, object_id in (
            key for key, state in states.items() if state == "removed"
        ):
            removed_id = _removed_finding_id(mailbox, object_type, object_id)
            if removed_id in known_finding_ids:
                states[(mailbox, object_type, object_id)] = "unchanged"
                continue
            findings.append(Finding(
                finding_id=removed_id,
                mailbox=mailbox,
                object_type=object_type,
                object_id=object_id,
                object_name=f"已被删除的{object_type}：{object_id}",
                severity="medium",
                score=30,
                signals=[{"code": "OBJECT_REMOVED", "weight": 30,
                          "detail": f"基线中存在的 {object_type} 在本次采集中消失，可能是攻击者清理痕迹",
                          "evidence": {}}],
                evidence={"baseline_key": [mailbox, object_type, object_id]},
            ))

        # 统一回填基线状态（removed 项同样按真实 key 命中）
        for finding in findings:
            key = (finding.mailbox, finding.object_type, finding.object_id)
            finding.baseline_state = states.get(key, "unchanged")

        # 所有结论（含 removed）成型后再持久化，保证下一轮能识别已报告的消失
        if update_baseline:
            store.record_findings(findings)

    findings.sort(key=lambda item: (-item.score, item.mailbox, item.object_type))
    report_paths = write_all(findings, snapshots, config.output_dir)
    alerted = 0
    if send_alerts:
        alerted = Alerter(config.alert).dispatch(findings)

    changed_count = sum(1 for state in states.values() if state != "unchanged")
    logger.info(
        "检测完成：%d 条结论（new=%d changed=%d removed=%d），报告目录 %s",
        len(findings),
        sum(1 for f in findings if f.baseline_state == "new"),
        sum(1 for f in findings if f.baseline_state == "changed"),
        sum(1 for f in findings if f.baseline_state == "removed"),
        config.output_dir,
    )
    return AuditRunResult(findings, snapshots, report_paths, alerted, states)
