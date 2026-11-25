#!/usr/bin/env python3
"""审计机启动包装器。

用绝对路径定位包目录后再切换到隔离模式（-I 语义），避免审计机当前工作目录
中存在同名恶意模块（如 json.py）被 import 劫持。用法：

    python3 scripts/run_audit.py -c /etc/mailbox-audit/config.json monitor \
        --export-dir /var/lib/mailbox-audit/export --fail-on high
"""

from __future__ import annotations

import os
import sys

# 包目录 = 本脚本的上一级
PACKAGE_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PACKAGE_ROOT not in sys.path:
    sys.path.insert(0, PACKAGE_ROOT)

from mailbox_audit.__main__ import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
