# 企业邮箱收件规则 / 转发 / 委托审计与持续监控

针对钓鱼攻陷后攻击者植入收件规则（自动转发发票/付款邮件、移动或删除原件、
隐藏规则）的问题，对企业邮箱全量用户做**收件规则、邮箱级转发、委托访问**
三类配置的审计与持续监控。

## 为什么需要专门工具

Microsoft Graph / Gmail Admin SDK 的常规接口读不到关键攻击面：

| 攻击手法 | 常规管理界面 | 本工具采集方式 |
| --- | --- | --- |
| MAPI 隐藏规则（不在 Outlook 显示） | 看不到 | `Get-InboxRule -IncludeHidden` |
| 邮箱级 SMTP 自动转发 | 分散 | `Get-Mailbox` 转发字段 |
| Full Access / SendAs 委托（含服务主体） | 部分可见 | `Get-EXORecipientPermission` |
| 转发后不留副本 | 易忽略 | `DeliverToMailboxAndForward=False` 检测 |
| 仿冒内部域名（同形异义字） | 人工难辨 | homoglyph + 编辑距离检测 |

## 架构

```
采集层（在能连邮件系统的机器上跑）         审计层（离线、零依赖、可断网）
┌─────────────────────────────┐          ┌──────────────────────────┐
│ collect_exo.ps1             │  JSON    │ mailbox_audit（纯标准库） │
│ collect_exchange_onprem.ps1 │ ───────▶ │  解析 → 检测 → 基线对比   │
│ collect_gmail.py            │  导出     │  → JSON/CSV/HTML 报告     │
│ GraphCollector（在线可选）   │          │  → Webhook/邮件/Syslog    │
└─────────────────────────────┘          └──────────────────────────┘
```

- **纯 Python 标准库**，审计机不需要 pip install 任何东西，Python 3.10+ 即可。
- 采集与审计分离：凭据只留在采集侧，审计机可放在隔离网段离线运行。
- 不同邮件系统通过适配器统一成同一套规范数据模型（`mailbox_audit/models.py`），
  检测引擎与系统无关。

## 目录结构

```
mailbox_audit/
  models.py        规范数据模型（规则/转发/委托/快照/结论）
  domains.py       内外部地址判定、免费邮箱、homoglyph 仿冒检测
  keywords.py      中英双语敏感词库（财务/凭据/机密，可在配置扩展）
  detector.py      信号体系 + 加权评分 + 白名单豁免（检测引擎核心）
  store.py         SQLite 基线库（new/changed/unchanged/removed）
  reporting.py     JSON / CSV / 自包含 HTML 报告
  alerts.py        Webhook / SMTP / Syslog 告警通道
  engine.py        编排：采集→检测→基线→报告→告警
  adapters/        exo.py / msgraph.py / gmail.py 三套适配器
scripts/           各系统采集脚本 + 启动包装器 + 演示数据生成器
tests/             36 个单元测试（python3 -m unittest discover -s tests）
config.example.json
```

## 快速开始（用内置演示数据验证）

```bash
# 1. 生成一份模拟被攻陷租户的 PowerShell 导出
python3 scripts/make_demo_data.py

# 2. 全量审计（离线）
python3 scripts/run_audit.py -c config.example.json offline \
    --export-dir samples/exo_export --no-alert

# 3. 看报告
open output/audit_report.html
```

演示数据内置 6 个典型场景，包括完整 BEC 攻击链（发票关键词+外部转发+
RSS 文件夹隐藏+MAPI 隐藏规则）、希腊字母 homoglyph 仿冒域名、外部 Full
Access 委托，以及用于验证误报控制的合法内部分类规则。

## 生产部署：Exchange Online

### 第一步：采集（在管理机上）

前置：安装 `ExchangeOnlineManagement` 模块，使用具备 **View-Only Recipients
+ View-Only Configuration** 只读角色的审计账号（不要授予写权限）。

```powershell
Connect-ExchangeOnline
.\scripts\collect_exo.ps1 -OutputDir .\export-20261126
```

输出 5 个 JSON：可见规则、`-IncludeHidden` 隐藏规则、邮箱转发、自动回复
配置、委托权限。把整个目录安全传回审计机。

### 第二步：审计（在审计机上）

```bash
cp config.example.json /etc/mailbox-audit/config.json
# 编辑 internal_domains、白名单、告警通道
python3 scripts/run_audit.py -c /etc/mailbox-audit/config.json offline \
    --export-dir /var/lib/mailbox-audit/export-20261126
```

本地 Exchange（2013/2016/2019）用 `collect_exchange_onprem.ps1`，审计时
加 `--system exchange_onprem`。

### 第三步：持续监控（cron / 任务计划）

```cron
# 每 6 小时采集一次后审计；出现 high 及以上的新增/变更/移除时退出码非零
0 */6 * * * /usr/bin/python3 /opt/mailbox-audit/scripts/run_audit.py \
    -c /etc/mailbox-audit/config.json monitor \
    --export-dir /var/lib/mailbox-audit/export --fail-on high
```

监控语义（已通过五轮回归验证）：

- **首跑**：全部对象标记 `new`，建立基线，高危项退出码 1。
- **无变化运行**：全部 `unchanged`，退出码 0，不发告警。
- **规则被篡改**（如转发落点改变）：同一对象标记 `changed`。
- **规则/委托被删除**（攻击者清理痕迹）：标记 `removed` 并产生专门结论，
  且只在首次发现时告警，后续运行自动收敛、不重复打扰。
- 告警只针对 `new/changed/removed` 且达到严重级别的非白名单结论。

## Google Workspace

```bash
# 采集侧（需要服务账号 + 域级委派，scope 见脚本头注释）
pip install google-api-python-client google-auth
python3 scripts/collect_gmail.py --sa-json sa.json --subject admin@corp.com \
    --domain corp.com --users-file users.txt --export-dir ./gmail-export

# 审计侧（仍然零依赖）
python3 scripts/run_audit.py -c config.json offline --system gmail \
    --export-dir ./gmail-export
```

## 检测信号与评分模型

引擎不靠单条规则定性，而是把可疑特征拆成带权重的信号累加，分数映射
严重级别，且**不出组织的规则风险封顶在 medium 以下**，从机制上压制
合法分类规则的误报。主要信号：

| 信号 | 权重 | 含义 |
| --- | --- | --- |
| EXTERNAL_EGRESS | 40 | 邮件转发/重定向到组织外 |
| LOOKALIKE_DOMAIN | 55 | 落点域名 homoglyph/编辑距离仿冒内部域 |
| HIDDEN_RULE | 45 | MAPI 隐藏规则，常规接口不可见 |
| FORWARD_ALL | 35 | 邮箱级自动转发 |
| EXTERNAL_DELEGATE | 35 | 委托给组织外身份 |
| NO_LOCAL_COPY | 25 | 转发后不留副本，收件箱无痕迹 |
| DELETE_ACTION | 25 | 硬删除邮件 |
| SENSITIVE_KEYWORD | 20 | 条件命中发票/付款/密码等敏感词 |
| HIDE_MOVE_FOLDER | 20 | 移动到 RSS/已删除/同步问题等不起眼文件夹 |
| OBSCURE_HEADER_CONDITION | 18 | 基于冷僻邮件头匹配，规避人工查看 |
| OBFUSCATED_CONDITION | 15 | 正则/通配/编码形式的混淆条件 |
| FREE_MAIL_DEST | 15 | 落点为个人免费邮箱 |
| BROAD_SCOPE | 15 | 无条件或通配，捕获所有邮件 |

## 降低误报：白名单机制

合法转发和分类规则非常普遍，通过配置 `allowlist` 豁免，每条白名单要求
填写**原因和工单号**、可设过期时间，过期自动失效：

```json
{
  "mailbox": "it@contoso.com",
  "object_type": "rule",
  "object_id_or_name": "合规归档",
  "destination": "contoso-archive.example",
  "reason": "合规团队邮件归档流程",
  "ticket": "ITSM-20260301",
  "expires": "2027-01-01"
}
```

- 字段为空 = 通配；多字段同时填 = AND 关系。
- `trusted_forward_domains` 备案合作方域名，命中只给 8 分低权重信号。
- `trusted_service_principals` 备案服务主体，授权信号降权到 5 分。
- 白名单结论降为 `info` 并保留在报告中（可审计，不是静默删除）。

## 告警通道

在配置 `alert.channels` 中启用，全部标准库实现：

- **Webhook**：JSON POST，可对接飞书/企业微信/Slack/SOAR。
- **邮件**：SMTP STARTTLS。
- **Syslog**：UDP RFC3164，直接送 SIEM。

## 安全注意事项

1. 采集账号只用**只读**角色；服务账号密钥放在采集侧，不进审计机。
2. `scripts/run_audit.py` 用绝对路径导入包，避免工作目录同名模块劫持；
   处理外部 JSON 时建议配合 `python3 -I`。
3. 基线库 `audit_baseline.db`、导出目录、报告都含敏感配置，按机密数据
   管控（仓库 `.gitignore` 已默认排除凭据与密钥文件）。
4. Graph 在线采集读不到隐藏规则和委托，**不能替代 PowerShell 适配器**，
   引擎会在报告中显式给出采集覆盖盲区告警。

## 测试

```bash
python3 -m unittest discover -s tests -v   # 36 个用例，覆盖检测/解析/基线
```

## 应急响应联动建议

发现 critical/high 结论后的处置顺序：

1. 立即禁用涉事规则与转发（`Disable-InboxRule`、清空 `ForwardingSmtpAddress`）。
2. 核查 `removed` 结论——攻击者可能已在清理其他后门规则。
3. 重置该邮箱凭据、吊销令牌、核查登录日志与邮件流追踪。
4. 用 `-IncludeHidden` 重新采集确认无残留隐藏规则。
5. 在配置中补白名单只用于确认合法的项，禁止对未定性结论直接加白。
