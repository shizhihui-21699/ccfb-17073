"""采集适配器基类与离线导出加载器。

每个适配器负责一种邮件系统的原生数据采集，并把原生结构规范化为
models.MailboxSnapshot。生产环境用在线采集，测试/演练/应急排查用
offline 加载 JSON 导出，两条路径输出结构完全一致。
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from pathlib import Path

from ..models import MailboxSnapshot


class BaseCollector(ABC):
    system_name: str = "base"

    @abstractmethod
    def collect(self) -> list[MailboxSnapshot]:
        """返回租户内所有目标邮箱的规范化快照。"""
        raise NotImplementedError

    @staticmethod
    def _read_json(path: str | Path) -> object:
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)

    @staticmethod
    def _as_list(data: object) -> list:
        """PowerShell ConvertTo-Json 单对象时返回 dict 而非 list，这里统一成列表。"""
        if data is None:
            return []
        if isinstance(data, list):
            return data
        return [data]


class OfflineExportCollector(BaseCollector):
    """从目录加载已采集的原生 JSON 导出，再交给具体适配器解析。

    目录结构（scripts/ 下的采集脚本按此约定输出）：
        export_dir/
          inbox_rules.json
          inbox_rules_hidden.json
          mailbox_forwarding.json
          mailbox_auto_config.json
          recipients_permission.json
          gmail_filters.json / gmail_forwarding.json / gmail_delegates.json
    """

    system_name = "offline"

    def __init__(self, export_dir: str | Path, parser):
        self.export_dir = Path(export_dir)
        self.parser = parser  # 具体适配器的解析器实例

    def load(self, filename: str) -> list:
        path = self.export_dir / filename
        if not path.exists():
            return []
        return self._as_list(self._read_json(path))

    def collect(self) -> list[MailboxSnapshot]:
        return self.parser.parse_export(
            rules=self.load("inbox_rules.json"),
            hidden_rules=self.load("inbox_rules_hidden.json"),
            forwarding=self.load("mailbox_forwarding.json"),
            auto_config=self.load("mailbox_auto_config.json"),
            permissions=self.load("recipients_permission.json"),
            gmail_filters=self.load("gmail_filters.json"),
            gmail_forwarding=self.load("gmail_forwarding.json"),
            gmail_delegates=self.load("gmail_delegates.json"),
        )
