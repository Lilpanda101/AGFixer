#Requires -Version 5.1
param([Parameter(Mandatory=$true)][ValidateSet('Zapret','VpnTun','OwnProxy','Relay')][string]$Mode,[string]$ProxyUrl='',[ValidateRange(100,60000)][int]$TimeoutMs=5000)
$ErrorActionPreference='Stop'
. "$PSScriptRoot/connection-path.ps1"
$profile=New-AGConnectionProfile -Mode $Mode -ProxyUrl $ProxyUrl
Invoke-AGConnectionProbe -Profile $profile -TimeoutMs $TimeoutMs|ConvertTo-Json -Depth 6 -Compress
