<#
.SYNOPSIS
    Exchange Online 全量采集脚本：收件规则（含隐藏）、邮箱转发、自动回复配置、委托权限。

.DESCRIPTION
    输出 5 个 JSON 文件，供 mailbox_audit 离线解析：
      inbox_rules.json          Get-InboxRule（可见规则）
      inbox_rules_hidden.json   Get-InboxRule -IncludeHidden（含 MAPI 隐藏规则）
      mailbox_forwarding.json   Get-Mailbox 转发相关字段
      mailbox_auto_config.json  Get-MailboxAutoReplyConfiguration
      recipients_permission.json Get-EXORecipientPermission（SendAs/FullAccess 委托）

    必须使用 Exchange Online PowerShell v3 模块（ExchangeOnlineManagement）。
    最小权限角色：View-Only Recipients + View-Only Configuration（审计只读，
    不要给写权限）。

.PARAMETER OutputDir
    JSON 导出目录。

.PARAMETER RecipientFilter
    可选，限定邮箱范围（默认全部 UserMailbox）。

.EXAMPLE
    Connect-ExchangeOnline
    .\collect_exo.ps1 -OutputDir .\export
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$OutputDir,
    [string]$RecipientFilter = "RecipientTypeDetails -eq 'UserMailbox'"
)

$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

function Write-Json {
    param([string]$Name, [object]$Data)
    $path = Join-Path $OutputDir $Name
    $Data | ConvertTo-Json -Depth 8 | Out-File -FilePath $path -Encoding utf8
    Write-Host "[+] $Name : $((@($Data)).Count) 条记录"
}

Write-Host "[*] 枚举邮箱清单..."
$mailboxes = Get-EXOMailbox -ResultSize Unlimited -Filter $RecipientFilter `
    -Properties PrimarySmtpAddress, ForwardingSmtpAddress,
                DeliverToMailboxAndForward, ForwardingAddress, HiddenFromAddressListsEnabled
Write-Host "[+] 共 $($mailboxes.Count) 个邮箱"

# 1) 收件规则：先常规、再 IncludeHidden（后者结果包含前者，Python 侧按 Identity 去重）
Write-Host "[*] 采集可见收件规则..."
$visibleRules = foreach ($mbx in $mailboxes) {
    try { Get-InboxRule -Mailbox $mbx.Identity -ErrorAction Stop }
    catch { Write-Warning "Get-InboxRule 失败 $($mbx.PrimarySmtpAddress): $_" }
}
Write-Json -Name "inbox_rules.json" -Data $visibleRules

Write-Host "[*] 采集隐藏收件规则（-IncludeHidden，MAPI 植入规则的关键检测点）..."
$hiddenRules = foreach ($mbx in $mailboxes) {
    try { Get-InboxRule -Mailbox $mbx.Identity -IncludeHidden -ErrorAction Stop }
    catch { Write-Warning "Get-InboxRule -IncludeHidden 失败 $($mbx.PrimarySmtpAddress): $_" }
}
Write-Json -Name "inbox_rules_hidden.json" -Data $hiddenRules

# 2) 邮箱级转发配置
Write-Host "[*] 采集邮箱转发配置..."
$forwarding = $mailboxes | Select-Object Identity, PrimarySmtpAddress,
    ForwardingSmtpAddress, ForwardingAddress,
    DeliverToMailboxAndForward, HiddenFromAddressListsEnabled
Write-Json -Name "mailbox_forwarding.json" -Data $forwarding

# 3) 自动回复 / 自动转发策略
Write-Host "[*] 采集自动回复配置..."
$autoConfig = foreach ($mbx in $mailboxes) {
    try { Get-MailboxAutoReplyConfiguration -Identity $mbx.Identity -ErrorAction Stop }
    catch { Write-Warning "AutoReply 配置读取失败 $($mbx.PrimarySmtpAddress): $_" }
}
Write-Json -Name "mailbox_auto_config.json" -Data $autoConfig

# 4) 委托权限（SendAs / FullAccess；服务主体授权会显示为 app:<clientId>）
Write-Host "[*] 采集委托权限..."
$permissions = foreach ($mbx in $mailboxes) {
    try {
        Get-EXORecipientPermission -Identity $mbx.Identity -ResultSize Unlimited `
            -ErrorAction Stop | Where-Object { $_.AccessRights -contains "SendAs" }
    }
    catch { Write-Warning "RecipientPermission 失败 $($mbx.PrimarySmtpAddress): $_" }
    try {
        Get-EXOMailboxPermission -Identity $mbx.Identity -ResultSize Unlimited `
            -ErrorAction Stop |
            Where-Object { $_.AccessRights -contains "FullAccess" -and
                           $_.User -notmatch "^(NT AUTHORITY|S-1-)" }
    }
    catch { Write-Warning "MailboxPermission 失败 $($mbx.PrimarySmtpAddress): $_" }
}
Write-Json -Name "recipients_permission.json" -Data $permissions

# 5) 远程域自动转发策略（租户层面是否允许 AutoForward，作为环境上下文）
try {
    Get-RemoteDomain | Select-Object DomainName, AutoForwardEnabled,
        AutoReplyEnabled | ConvertTo-Json -Depth 4 |
        Out-File (Join-Path $OutputDir "remote_domains.json") -Encoding utf8
    Write-Host "[+] remote_domains.json 已写入"
}
catch { Write-Warning "RemoteDomain 读取失败：$_" }

Write-Host "[*] 采集完成。请把整个目录传回审计机，执行："
Write-Host "    python -m mailbox_audit -c config.json offline --export-dir $OutputDir"
