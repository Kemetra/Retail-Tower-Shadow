<#
.SYNOPSIS
  Start a session that acts as kemetra-agent[bot] on Kemetra/Retail-Tower-Shadow (RT-721 B6).

.DESCRIPTION
  Run this YOURSELF. broker.py reads the kemetra-agent private key from 1Password
  (you approve the unlock), mints a 1-hour token limited to the Shadow, starts the
  command with only that token, and revokes it when the command exits.
  The key never touches disk or the session; the token is never printed.
  Design: tools/ci-gate/AGENT-BROKER.md

.EXAMPLE
  .\tools\agent-broker\Start-KemetraAgentSession.ps1 -Check
  # mint, verify scope/permissions, revoke; prints only expiry, repo and permissions

.EXAMPLE
  .\tools\agent-broker\Start-KemetraAgentSession.ps1
  # starts `claude` in the Shadow checkout as kemetra-agent[bot]
#>
[CmdletBinding()]
param(
    [string]$OpRef = 'op://tower/kemetra agent bot/private key',
    # 1Password account holding the vault, when more than one is configured (sign-in address or ID).
    [string]$OpAccount = '',
    [switch]$Check,
    [string[]]$Command = @('claude')
)
$ErrorActionPreference = 'Stop'
$repo = Resolve-Path (Join-Path $PSScriptRoot '..\..')
Set-Location $repo
$broker = Join-Path $PSScriptRoot 'broker.py'
$accountArgs = @()
if ($OpAccount) { $accountArgs = @('--op-account', $OpAccount) }
if ($Check) {
    & python $broker --op-ref $OpRef @accountArgs --check
} else {
    & python $broker --op-ref $OpRef @accountArgs -- @Command
}
exit $LASTEXITCODE
