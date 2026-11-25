<#
.SYNOPSIS
    本地 Exchange（2013/2016/2019）全量采集脚本。

.DESCRIPTION
    与 collect_exo.ps1 输出结构一致，区别仅在于使用本地 Exchange Management Shell
    的 cmdlet（无 EXO 前缀）。需要在装有 Exchange 管理工具的机器上、以具备
    View-Only 审核权限的账号运行。
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
    $Data | ConvertTo-Json -Depth 8 |
        Out-File -FilePath (Join-Path $OutputDir $Name) -Encoding utf8
    Write-Host "[+] $Name : $((@($Data)).Count) 条记录"
}

$mailboxes = Get-Mailbox -ResultSize Unlimited -Filter $RecipientFilter
Write-Host "[+] 共 $($mailboxes.Count) 个邮箱"

$visibleRules = foreach ($mbx in $mailboxes) {
    try { Get-InboxRule -Mailbox $mbx.Identity -ErrorAction Stop }
    catch { Write-Warning "InboxRule 失败 $($mbx.Identity): $_" }
}
Write-Json -Name "inbox_rules.json" -Data $visibleRules

# 本地 Exchange 同样支持 -IncludeHidden
$hiddenRules = foreach ($mbx in $mailboxes) {
    try { Get-InboxRule -Mailbox $mbx.Identity -IncludeHidden -ErrorAction Stop }
    catch { Write-Warning "隐藏 InboxRule 失败 $($mbx.Identity): $_" }
}
Write-Json -Name "inbox_rules_hidden.json" -Data $hiddenRules

$forwarding = $mailboxes | Select-Object Identity, PrimarySmtpAddress,
    ForwardingSmtpAddress, ForwardingAddress,
    DeliverToMailboxAndForward, HiddenFromAddressListsEnabled
Write-Json -Name "mailbox_forwarding.json" -Data $forwarding

$autoConfig = foreach ($mbx in $mailboxes) {
    try { Get-MailboxAutoReplyConfiguration -Identity $mbx.Identity -ErrorAction Stop }
    catch { Write-Warning "AutoReply 失败 $($mbx.Identity): $_" }
}
Write-Json -Name "mailbox_auto_config.json" -Data $autoConfig

$permissions = foreach ($mbx in $mailboxes) {
    try {
        Get-RecipientPermission -Identity $mbx.Identity -ErrorAction Stop |
            Where-Object { $_.AccessRights -contains "SendAs" }
    }
    catch { Write-Warning "RecipientPermission 失败 $($mbx.Identity): $_" }
    try {
        Get-MailboxPermission -Identity $mbx.Identity -ErrorAction Stop |
            Where-Object { $_.AccessRights -contains "FullAccess" -and
                           $_.IsInherited -eq $false }
    }
    catch { Write-Warning "MailboxPermission 失败 $($mbx.Identity): $_" }
}
Write-Json -Name "recipients_permission.json" -Data $permissions

try {
    Get-RemoteDomain | Select-Object DomainName, AutoForwardEnabled, AutoReplyEnabled |
        ConvertTo-Json -Depth 4 |
        Out-File (Join-Path $OutputDir "remote_domains.json") -Encoding utf8
}
catch { Write-Warning "RemoteDomain 读取失败：$_" }

Write-Host "[*] 完成。审计机执行："
Write-Host "    python -m mailbox_audit -c config.json offline --system exchange_onprem --export-dir $OutputDir"
