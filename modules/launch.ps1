#Requires -Version 5.1
param([switch]$ControlCenter,[switch]$ElevationAttempted,[string]$ExpectedUserSid)
$ErrorActionPreference='Stop'
try {
    Set-Location -LiteralPath $PSScriptRoot
    . "$PSScriptRoot/common.ps1"
    . "$PSScriptRoot/startup.ps1"
    Invoke-AGAdminStartup -ControlCenter:$ControlCenter -ElevationAttempted:$ElevationAttempted -ExpectedUserSid $ExpectedUserSid
} catch { Write-Warning $_.Exception.Message; exit 1 }
