# Downloads public threat-intelligence feeds and compiles them into data/threat-intel.json,
# the offline reference list bundled with the Tripwire extension.
#
# Usage (from the extension folder):   powershell -ExecutionPolicy Bypass -File tools\build-threat-intel.ps1
#
# Sources and parsing rules mirror src/intel.js (the extension's live updater). Filtering of shared
# platforms (GitHub, Google Drive, ...) happens inside the extension, so this file keeps raw entries.

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$outFile = Join-Path $root 'data\threat-intel.json'
New-Item -ItemType Directory -Force (Split-Path $outFile) | Out-Null
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$sources = @(
  @{ id='openphish'; name='OpenPhish'; category='phishing'; format='url-lines'; license='OpenPhish Community Feed (free)'; homepage='https://openphish.com/'
     urls=@('https://openphish.com/feed.txt','https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt') },
  @{ id='phishing-filter'; name='Phishing Filter (PhishTank, OpenPhish, PhishStats)'; category='phishing'; format='host-lines'; license='CC0 / source terms'; homepage='https://gitlab.com/malware-filter/phishing-filter'
     urls=@('https://malware-filter.gitlab.io/phishing-filter/phishing-filter-domains.txt','https://curbengh.github.io/phishing-filter/phishing-filter-domains.txt') },
  @{ id='cert-pl'; name='CERT Polska warning list'; category='phishing'; format='host-lines'; license='CERT Polska open data'; homepage='https://cert.pl/en/warning-list/'
     urls=@('https://hole.cert.pl/domains/v2/domains.txt') },
  @{ id='urlhaus'; name='URLhaus (abuse.ch) online malware sites'; category='malware'; format='host-lines'; license='CC0'; homepage='https://urlhaus.abuse.ch/'
     urls=@('https://malware-filter.gitlab.io/urlhaus-filter/urlhaus-filter-domains-online.txt','https://curbengh.github.io/urlhaus-filter/urlhaus-filter-domains-online.txt') },
  @{ id='feodo'; name='Feodo Tracker (abuse.ch) botnet C2 servers'; category='c2'; format='host-lines'; license='CC0'; homepage='https://feodotracker.abuse.ch/'
     urls=@('https://feodotracker.abuse.ch/downloads/ipblocklist.txt') },
  @{ id='botnet-filter'; name='Botnet Filter (abuse.ch based) malicious server IPs'; category='c2'; format='host-lines'; license='CC0'; homepage='https://gitlab.com/malware-filter/botnet-filter'
     urls=@('https://malware-filter.gitlab.io/botnet-filter/botnet-filter-dnscrypt-blocked-ips.txt','https://curbengh.github.io/botnet-filter/botnet-filter-dnscrypt-blocked-ips.txt') },
  @{ id='c2intel-ip'; name='C2IntelFeeds (C2 server IPs, last 30 days)'; category='c2'; format='csv-label'; license='C2IntelFeeds (GitHub, drb-ra)'; homepage='https://github.com/drb-ra/C2IntelFeeds'
     urls=@('https://raw.githubusercontent.com/drb-ra/C2IntelFeeds/master/feeds/IPC2s-30day.csv') },
  @{ id='c2intel-domain'; name='C2IntelFeeds (C2 server domains, last 30 days)'; category='c2'; format='csv-label'; license='C2IntelFeeds (GitHub, drb-ra)'; homepage='https://github.com/drb-ra/C2IntelFeeds'
     urls=@('https://raw.githubusercontent.com/drb-ra/C2IntelFeeds/master/feeds/domainC2s-30day-filter-abused.csv') }
)

function Get-Host([string]$line) {
  $l = $line.Trim()
  if (-not $l -or '#!;'.Contains($l[0])) { return '' }
  $l = ($l -split '[\s,]')[0]
  if ($l.StartsWith('||')) { $l = $l.Substring(2) -replace '\^.*$', '' }
  if ($l -match '^(0\.0\.0\.0|127\.0\.0\.1)$') { return '' }
  if ($l -notmatch '://') { $l = 'http://' + $l }
  try { $h = ([Uri]$l).IdnHost.ToLowerInvariant().TrimEnd('.') } catch { return '' }
  if ($h -notmatch '[.:]' -or $h -notmatch '^[a-z0-9.\-_:\[\]]+$') { return '' }
  return $h.Trim('[', ']')
}
function Get-UrlKeys([string]$line) {
  try { $u = [Uri]$line.Trim() } catch { return @() }
  if ($u.Scheme -notin 'http','https') { return @() }
  $h = ($u.IdnHost.ToLowerInvariant()) -replace '^www\.', ''
  $p = $u.AbsolutePath.TrimEnd('/')
  $keys = @($h + $p + $u.Query)
  if ($u.Query) { $keys += ($h + $p) }
  return $keys
}
function Esc([string]$s) { ($s -replace '\\', '\\' -replace '"', '\"' -replace '[\x00-\x1f]', '') }

$sb = New-Object System.Text.StringBuilder
$generated = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
[void]$sb.Append("{`"generated`":`"$generated`",`"sources`":[")
$first = $true; $summary = @()
foreach ($s in $sources) {
  $text = $null; $usedUrl = $null
  foreach ($u in $s.urls) {
    try { $r = Invoke-WebRequest -UseBasicParsing -Uri $u -TimeoutSec 60 -Headers @{ 'User-Agent' = 'Tripwire-threat-intel-builder' }; $text = $r.Content; $usedUrl = $u; break } catch { Write-Warning "$($s.id): $u failed ($($_.Exception.Message))" }
  }
  if ($null -eq $text) { Write-Warning "$($s.id): all mirrors failed, skipping"; continue }
  if ($text -is [byte[]]) { $text = [Text.Encoding]::UTF8.GetString($text) }
  $hosts = New-Object 'System.Collections.Generic.HashSet[string]'
  $urls = New-Object 'System.Collections.Generic.HashSet[string]'
  $labels = @{}
  foreach ($line in ($text -split "`r?`n")) {
    $t = $line.Trim()
    if (-not $t -or $t[0] -eq '#' -or $t[0] -eq '!') { continue }
    if ($s.format -eq 'csv-label') {
      $parts = $t -split ',', 2
      if ($parts[0] -match '^(domain|ip|host)$') { continue }
      $h = Get-Host $parts[0]; if (-not $h) { continue }
      [void]$hosts.Add($h)
      if ($parts.Count -gt 1 -and $parts[1].Trim()) { $lab = $parts[1].Trim(); $labels[$h] = $lab.Substring(0, [Math]::Min(80, $lab.Length)) }
    } else {
      $h = Get-Host $t; if (-not $h) { continue }
      [void]$hosts.Add($h)
      if ($s.format -eq 'url-lines') { foreach ($k in (Get-UrlKeys $t)) { [void]$urls.Add($k) } }
    }
  }
  if (-not $first) { [void]$sb.Append(',') }; $first = $false
  [void]$sb.Append("{`"id`":`"$($s.id)`",`"name`":`"$(Esc $s.name)`",`"category`":`"$($s.category)`",`"license`":`"$(Esc $s.license)`",`"homepage`":`"$($s.homepage)`",`"fetchedFrom`":`"$(Esc $usedUrl)`",`"fetched`":`"$generated`",")
  [void]$sb.Append('"hosts":[' + (($hosts | ForEach-Object { '"' + (Esc $_) + '"' }) -join ',') + '],')
  [void]$sb.Append('"urls":[' + (($urls | ForEach-Object { '"' + (Esc $_) + '"' }) -join ',') + '],')
  [void]$sb.Append('"labels":{' + (($labels.GetEnumerator() | ForEach-Object { '"' + (Esc $_.Key) + '":"' + (Esc $_.Value) + '"' }) -join ',') + '}}')
  $summary += [pscustomobject]@{ Source = $s.id; Category = $s.category; Hosts = $hosts.Count; Urls = $urls.Count }
}
[void]$sb.Append(']}')
[IO.File]::WriteAllText($outFile, $sb.ToString(), (New-Object System.Text.UTF8Encoding $false))
$summary | Format-Table -AutoSize
"Wrote $outFile ($([int]((Get-Item $outFile).Length / 1KB)) KB)"
