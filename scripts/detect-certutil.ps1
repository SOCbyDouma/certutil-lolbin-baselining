# detect-certutil.ps1
# Replays the R1/R2/R3 detection logic against the local Sysmon log,
# so the rules can be validated in the lab without a SIEM.
# Run from an elevated PowerShell:
#   powershell -ExecutionPolicy Bypass -File C:\Tools\detect-certutil.ps1

$log = "Microsoft-Windows-Sysmon/Operational"
$events = Get-WinEvent -LogName $log -ErrorAction SilentlyContinue

$procs  = @()
$alerts = @()

foreach ($e in $events) {
    # Parse the event's fields by name instead of scraping message text
    $x = [xml]$e.ToXml()
    $d = @{}
    foreach ($n in $x.Event.EventData.Data) { $d[$n.Name] = $n.'#text' }

    if ([string]$d['Image'] -notmatch '\\certutil\.exe$') { continue }

    # EID 1: process creation -> R1 and R2 (command-line rules)
    if ($e.Id -eq 1) {
        $cmd = [string]$d['CommandLine']
        $procs += [pscustomobject]@{ UtcTime = $d['UtcTime']; Guid = $d['ProcessGuid']; CommandLine = $cmd }

        if ($cmd -match 'urlcache|verifyctl' -and $cmd -match 'https?://') {
            $alerts += [pscustomobject]@{ UtcTime = $d['UtcTime']; Guid = $d['ProcessGuid']; Rule = 'R1 download'; Evidence = $cmd }
        }
        if ($cmd -match '[-/]decode') {
            $alerts += [pscustomobject]@{ UtcTime = $d['UtcTime']; Guid = $d['ProcessGuid']; Rule = 'R2 decode'; Evidence = $cmd }
        }
    }

    # EID 11: file creation -> R3 (certutil wrote an executable or script)
    if ($e.Id -eq 11) {
        $f = [string]$d['TargetFilename']
        if ($f -match '\.(exe|dll|ps1|bat|cmd|vbs|js|hta|scr)$') {
            $alerts += [pscustomobject]@{ UtcTime = $d['UtcTime']; Guid = $d['ProcessGuid']; Rule = 'R3 wrote executable'; Evidence = $f }
        }
    }
}

Write-Host ""
Write-Host "=== Every certutil execution and its verdict ===" -ForegroundColor Cyan
$procs | Sort-Object UtcTime | ForEach-Object {
    $g = $_.Guid
    $hits = ($alerts | Where-Object Guid -eq $g | Select-Object -ExpandProperty Rule -Unique) -join ', '
    if (-not $hits) { $hits = 'no alert' }
    [pscustomobject]@{ UtcTime = $_.UtcTime; Verdict = $hits; CommandLine = $_.CommandLine }
} | Format-Table -Wrap -AutoSize

Write-Host "=== Alerts ===" -ForegroundColor Yellow
$alerts | Sort-Object UtcTime | Format-Table UtcTime, Rule, Evidence -Wrap -AutoSize
