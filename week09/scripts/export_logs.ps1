# Week 9 - export the Windows logs after running the atomic tests, so the team
# can load them into Kibana (screenshots) and into atomic_analytic.py (the table).
#
# Run this in an ELEVATED PowerShell on the LAB VM, AFTER you run the atomic tests.
# It writes one JSON object per line (same field names as the OTRF datasets we used
# in Weeks 5-7), into .\atomic_logs\*.jsonl, then zips them to atomic_logs.zip.
#
#   powershell -ExecutionPolicy Bypass -File .\export_logs.ps1
#
# Then send atomic_logs.zip back (put it in week09/data/ in the repo).

$ErrorActionPreference = "Stop"
$out = Join-Path (Get-Location) "atomic_logs"
New-Item -ItemType Directory -Force -Path $out | Out-Null

# Only keep events from the test window (edit if your run was longer than 2 hours)
$since = (Get-Date).AddHours(-2)

# Which logs to pull, and which EventIDs matter for our detections
$sources = @(
    @{ Name = "sysmon";     Log = "Microsoft-Windows-Sysmon/Operational";              Ids = @(1,3,10,11,12,13) },
    @{ Name = "security";   Log = "Security";                                          Ids = @(4688,4697,4657,4663,7045) },
    @{ Name = "powershell"; Log = "Microsoft-Windows-PowerShell/Operational";          Ids = @(4103,4104) },
    @{ Name = "system";     Log = "System";                                            Ids = @(7045) }
)

function Convert-Event($e) {
    # Flatten the event's XML <EventData> Name=Value pairs into a flat object,
    # matching the field names used in Weeks 5-7 (Image, CommandLine, CallTrace, ...).
    $x = [xml]$e.ToXml()
    $o = [ordered]@{}
    $o["Channel"]     = $e.LogName
    $o["EventID"]     = [int]$e.Id
    $o["TimeCreated"] = $e.TimeCreated.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss.fff")
    $o["UtcTime"]     = $o["TimeCreated"]
    $o["Hostname"]    = $e.MachineName
    $o["Message"]     = $e.Message
    foreach ($d in $x.Event.EventData.Data) {
        if ($d.Name) { $o[$d.Name] = $d.'#text' }
    }
    # Security 4688 uses NewProcessName/CommandLine; copy to the Sysmon-style names too
    if (-not $o.Contains("Image") -and $o.Contains("NewProcessName")) { $o["Image"] = $o["NewProcessName"] }
    if (-not $o.Contains("ParentImage") -and $o.Contains("ParentProcessName")) { $o["ParentImage"] = $o["ParentProcessName"] }
    return $o
}

$total = 0
foreach ($s in $sources) {
    $file = Join-Path $out ("{0}.jsonl" -f $s.Name)
    if (Test-Path $file) { Remove-Item $file }
    try {
        $events = Get-WinEvent -FilterHashtable @{ LogName = $s.Log; Id = $s.Ids; StartTime = $since } -ErrorAction Stop
    } catch {
        Write-Host ("[skip] {0}: {1}" -f $s.Log, $_.Exception.Message)
        continue
    }
    $n = 0
    foreach ($e in $events) {
        (Convert-Event $e | ConvertTo-Json -Compress -Depth 4) | Out-File -FilePath $file -Append -Encoding utf8
        $n++
    }
    Write-Host ("{0,-11} {1,6} events -> {2}" -f $s.Name, $n, $file)
    $total += $n
}

# Also copy the Invoke-AtomicTest execution log (proof of what ran, and when)
$execLog = Join-Path $env:TEMP "Invoke-AtomicTest-ExecutionLog.csv"
if (Test-Path $execLog) { Copy-Item $execLog (Join-Path $out "Invoke-AtomicTest-ExecutionLog.csv") }

$zip = Join-Path (Get-Location) "atomic_logs.zip"
if (Test-Path $zip) { Remove-Item $zip }
Compress-Archive -Path (Join-Path $out "*") -DestinationPath $zip
Write-Host ""
Write-Host ("Done. {0} events total. Send this file: {1}" -f $total, $zip)
