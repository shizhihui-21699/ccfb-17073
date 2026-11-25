"""SQLite 基线库：支撑持续监控。

每次审计把每个对象（规则/转发/委托）的指纹与完整 JSON 存入 SQLite；
下一次运行对比得到 new / changed / unchanged / removed 四种状态，
并保留首次/最近出现时间。纯标准库 sqlite3 实现。
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from .models import Finding, MailboxSnapshot, to_plain

_SCHEMA = """
CREATE TABLE IF NOT EXISTS objects (
    mailbox      TEXT NOT NULL,
    object_type  TEXT NOT NULL,
    object_id    TEXT NOT NULL,
    fingerprint  TEXT NOT NULL,
    payload      TEXT NOT NULL,
    first_seen   TEXT NOT NULL,
    last_seen    TEXT NOT NULL,
    PRIMARY KEY (mailbox, object_type, object_id)
);
CREATE TABLE IF NOT EXISTS findings (
    finding_id   TEXT PRIMARY KEY,
    mailbox      TEXT NOT NULL,
    object_type  TEXT NOT NULL,
    object_id    TEXT NOT NULL,
    severity     TEXT NOT NULL,
    score        INTEGER NOT NULL,
    payload      TEXT NOT NULL,
    first_seen   TEXT NOT NULL,
    last_seen    TEXT NOT NULL,
    status       TEXT NOT NULL
);
"""


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _fingerprint(payload: dict) -> str:
    canonical = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class BaselineStore:
    def __init__(self, db_path: str | Path):
        self.db_path = str(db_path)
        parent = Path(self.db_path).parent
        if parent and str(parent) != ".":
            parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(_SCHEMA)
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> "BaselineStore":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # ------------------------------------------------------------------
    # 对象基线
    # ------------------------------------------------------------------
    def _iter_objects(self, snapshot: MailboxSnapshot):
        for rule in snapshot.rules:
            yield "rule", rule.rule_id, to_plain(rule)
        # 转发配置的稳定身份是 kind（smtp_forwarding 等），不能把目标地址
        # 拼进 object_id：否则攻击者篡改转发落点会被误判成 remove+new 而非 changed
        for forward in snapshot.forwarding:
            yield "forwarding", forward.kind, to_plain(forward)
        for delegate in snapshot.delegates:
            yield "delegate", f"{delegate.access_type}:{delegate.delegate}", to_plain(delegate)

    def diff_and_update(self, snapshots: list[MailboxSnapshot]) -> dict[tuple, str]:
        """对比当前快照与基线，返回 {(mailbox, object_type, object_id): 状态}，并更新基线。"""
        now = _utcnow()
        states: dict[tuple, str] = {}
        current_keys: set[tuple] = set()

        for snapshot in snapshots:
            for object_type, object_id, payload in self._iter_objects(snapshot):
                key = (snapshot.mailbox, object_type, object_id)
                current_keys.add(key)
                fingerprint = _fingerprint(payload)
                row = self.conn.execute(
                    "SELECT fingerprint, first_seen FROM objects "
                    "WHERE mailbox=? AND object_type=? AND object_id=?", key,
                ).fetchone()
                if row is None:
                    states[key] = "new"
                    self.conn.execute(
                        "INSERT INTO objects (mailbox, object_type, object_id, fingerprint, "
                        "payload, first_seen, last_seen) VALUES (?,?,?,?,?,?,?)",
                        (*key, fingerprint, json.dumps(payload, ensure_ascii=False), now, now),
                    )
                elif row["fingerprint"] != fingerprint:
                    states[key] = "changed"
                    self.conn.execute(
                        "UPDATE objects SET fingerprint=?, payload=?, last_seen=? "
                        "WHERE mailbox=? AND object_type=? AND object_id=?",
                        (fingerprint, json.dumps(payload, ensure_ascii=False), now, *key),
                    )
                else:
                    states[key] = "unchanged"
                    self.conn.execute(
                        "UPDATE objects SET last_seen=? "
                        "WHERE mailbox=? AND object_type=? AND object_id=?",
                        (now, *key),
                    )

        # 本次未出现的历史对象 → removed（保留记录，只更新时间戳）
        existing = {
            (row["mailbox"], row["object_type"], row["object_id"])
            for row in self.conn.execute(
                "SELECT mailbox, object_type, object_id FROM objects"
            ).fetchall()
        }
        for key in existing - current_keys:
            states[key] = "removed"

        self.conn.commit()
        return states

    def get_object_payload(self, key: tuple) -> dict | None:
        row = self.conn.execute(
            "SELECT payload, first_seen, last_seen FROM objects "
            "WHERE mailbox=? AND object_type=? AND object_id=?", key,
        ).fetchone()
        if row is None:
            return None
        payload = json.loads(row["payload"])
        payload["_first_seen"] = row["first_seen"]
        payload["_last_seen"] = row["last_seen"]
        return payload

    # ------------------------------------------------------------------
    # 检测结论历史（用于告警去重、持续追踪）
    # ------------------------------------------------------------------
    def record_findings(self, findings: list[Finding]) -> None:
        now = _utcnow()
        for finding in findings:
            payload = finding.to_dict()
            row = self.conn.execute(
                "SELECT first_seen FROM findings WHERE finding_id=?", (finding.finding_id,),
            ).fetchone()
            first_seen = row["first_seen"] if row else now
            finding.first_seen = first_seen
            finding.last_seen = now
            self.conn.execute(
                "INSERT INTO findings (finding_id, mailbox, object_type, object_id, severity, "
                "score, payload, first_seen, last_seen, status) VALUES (?,?,?,?,?,?,?,?,?,?) "
                "ON CONFLICT(finding_id) DO UPDATE SET severity=excluded.severity, "
                "score=excluded.score, payload=excluded.payload, last_seen=excluded.last_seen, "
                "status=excluded.status",
                (finding.finding_id, finding.mailbox, finding.object_type, finding.object_id,
                 finding.severity, finding.score,
                 json.dumps(finding.to_dict(), ensure_ascii=False),
                 first_seen, now, finding.status),
            )
        self.conn.commit()

    def previously_open_finding_ids(self) -> set[str]:
        rows = self.conn.execute(
            "SELECT finding_id FROM findings WHERE status != 'resolved'"
        ).fetchall()
        return {row["finding_id"] for row in rows}
