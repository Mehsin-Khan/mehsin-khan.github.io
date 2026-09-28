<#
.SYNOPSIS
  Master endpoint agent check: one pass over every security agent on a
  Windows device, with deeper checks for Defender, SentinelOne and Zscaler.

.NOTES
  Portfolio reconstruction. Rebuilt with AI assistance from memory of the
  scripts I used at a bank; the originals stayed with the employer.
  Service patterns are generic. Confirm them against your own agent versions.
  No employer data, hostnames or tokens.

  Run locally as administrator for full detail, or push it through an EDR or
  management console's remote-script feature.

.EXAMPLE
  .\master-agent-check.ps1 -Retired 'SentinelOne','Trend Micro'
  Agents listed in -Retired are expected to be absent after a migration.
  If one is still installed, it is flagged for removal.

.EXAMPLE
  .\master-agent-check.ps1 -SkipNetwork
  Skips the Zscaler cloud test (for devices with no internet path).
#>
param(
  [string[]]$Retired = @(),
  [string]$LogFolder = "$env:ProgramData\AgentHealth",
  [switch]$SkipNetwork
)

# Agent -> service patterns, matched against service name or display name.
$Agents = [ordered]@{
  'SentinelOne'        = 'SentinelAgent','SentinelHelperService','SentinelStaticEngine','LogProcessorService'
  'Microsoft Defender' = 'WinDefend','Sense'
  'Trend Micro'        = '*Apex One*','*Trend Micro*'
  'ManageEngine'       = '*ManageEngine*Agent*'
  'Forescout'          = '*SecureConnector*'
  'Lansweeper'         = '*Lansweeper*'
  'Zscaler'            = 'ZSA*','*Zscaler*'
  'DLP agent'          = '*DLP*'    # broad pattern: narrow it to your DLP product
}

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
             [Security.Principal.WindowsBuiltInRole]::Administrator)
$runBy = "$env:USERDOMAIN\$env:USERNAME"
$stamp = Get-Date -Format 'yyyy-MM-dd HH:mm'
$allServices = Get-Service -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Path $LogFolder -Force | Out-Null

function Get-AgentServices([string[]]$Patterns) {
  $allServices | Where-Object {
    $svc = $_
    $Patterns | Where-Object { $svc.Name -like $_ -or $svc.DisplayName -like $_ }
  } | Sort-Object Name -Unique
}

function Get-InstalledVersion([string]$NamePattern) {
  $keys = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
          'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
  (Get-ItemProperty $keys -ErrorAction SilentlyContinue |
    Where-Object DisplayName -like $NamePattern | Select-Object -First 1).DisplayVersion
}

$results = foreach ($agent in $Agents.Keys) {
  $svc = @(Get-AgentServices $Agents[$agent])

  # 1. Service layer: installed? running?
  if ($svc.Count -eq 0) {
    if ($Retired -contains $agent) { $state = 'Retired'; $detail = 'Not installed, as expected' }
    else                           { $state = 'MISSING'; $detail = 'No matching service found' }
  }
  else {
    $running = @($svc | Where-Object Status -eq 'Running').Count
    if ($running -eq $svc.Count) { $state = 'PASS'; $detail = "$running/$($svc.Count) services running" }
    else                         { $state = 'WARN'; $detail = "Installed, $running/$($svc.Count) services running" }
    if ($Retired -contains $agent) { $state = 'WARN'; $detail = "Should be removed: $detail" }
  }

  # 2. Deeper checks where running services are not proof of protection
  if ($svc.Count -gt 0 -and $Retired -notcontains $agent) {
    switch ($agent) {

      'Microsoft Defender' {
        # Services run even on devices never onboarded, and in passive mode beside another EDR.
        try {
          $mp  = Get-MpComputerStatus -ErrorAction Stop
          $onb = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status' `
                    -ErrorAction SilentlyContinue).OnboardingState
          $rtp = if ($mp.RealTimeProtectionEnabled) { 'on' } else { 'off' }
          $mde = if ($onb -eq 1) { 'onboarded' } else { 'not onboarded' }
          $detail = "Mode: $($mp.AMRunningMode) | RTP $rtp | Signatures $($mp.AntivirusSignatureAge) days | MDE $mde"
          if (-not $mp.RealTimeProtectionEnabled -or $mp.AntivirusSignatureAge -gt 3 -or $onb -ne 1) { $state = 'WARN' }
        }
        catch { $detail += ' | Defender status unavailable: run as administrator' }
      }

      'SentinelOne' {
        # Save the agent's own status report as evidence for the console team.
        $ctl = Get-ChildItem 'C:\Program Files\SentinelOne\Sentinel Agent*\SentinelCtl.exe' -ErrorAction SilentlyContinue |
               Select-Object -First 1
        if ($ctl) {
          $out = Join-Path $LogFolder "sentinelctl-status-$env:COMPUTERNAME.txt"
          & $ctl.FullName status 2>&1 | Out-File $out
          $detail += " | sentinelctl status saved"
        }
      }

      'Zscaler' {
        # Services running is not the same as traffic going through the cloud.
        $ver = Get-InstalledVersion '*Zscaler*'
        if ($ver) { $detail = "v$ver | $detail" }
        if (-not $SkipNetwork) {
          try {
            $page = (Invoke-WebRequest 'https://ip.zscaler.com' -UseBasicParsing -TimeoutSec 10).Content
            if ($page -match 'via Zscaler') {
              $cloud = if ($page -match '(zscaler[a-z0-9]*\.net)') { $Matches[1] } else { 'cloud not shown' }
              $detail += " | traffic via Zscaler | $cloud"
            }
            else { $state = 'WARN'; $detail += ' | traffic NOT via Zscaler (tunnel down or client suspended?)' }
          }
          catch { $state = 'WARN'; $detail += ' | ip.zscaler.com unreachable' }
        }
      }
    }
  }

  [pscustomobject]@{
    Timestamp = $stamp; Computer = $env:COMPUTERNAME; RunBy = $runBy; Admin = $isAdmin
    Agent = $agent; State = $state; Detail = $detail
  }
}

# Console report
$colour = @{ PASS = 'Green'; WARN = 'Yellow'; MISSING = 'Red'; Retired = 'DarkGray' }
$adminText = if ($isAdmin) { 'Yes' } else { 'No' }
Write-Host ""
Write-Host "Master agent check | $env:COMPUTERNAME | run by $runBy | admin: $adminText | $stamp"
Write-Host ""
Write-Host ("{0,-20}{1,-10}{2}" -f 'Agent', 'State', 'Detail')
Write-Host ("{0,-20}{1,-10}{2}" -f '-----', '-----', '------')
foreach ($r in $results) {
  Write-Host ("{0,-20}" -f $r.Agent) -NoNewline
  Write-Host ("{0,-10}" -f $r.State) -NoNewline -ForegroundColor $colour[$r.State]
  Write-Host $r.Detail
}
$count = { param($s) @($results | Where-Object State -eq $s).Count }
Write-Host ""
Write-Host ("Summary: {0} pass, {1} warning, {2} missing, {3} retired" -f `
  (& $count 'PASS'), (& $count 'WARN'), (& $count 'MISSING'), (& $count 'Retired'))

# Evidence log: one row per agent per run
$log = Join-Path $LogFolder 'agent-health.csv'
$results | Export-Csv -Path $log -Append -NoTypeInformation
Write-Host "Log written: $log"
