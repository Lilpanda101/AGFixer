#Requires -Version 5.1
[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$Path, [switch]$Json)
$ErrorActionPreference='Stop'
. "$PSScriptRoot/report-analysis.ps1"
if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw 'Файл не найден.' }
if ((Get-Item -LiteralPath $Path).Length -gt 10MB) { throw 'Максимум 10 МБ.' }
$analysis=Get-AGReportAnalysis -Text (Get-Content -LiteralPath $Path -Raw -Encoding UTF8 -ErrorAction Stop)
if ($Json) { $analysis | ConvertTo-Json -Depth 20 } else { Show-AGReportAnalysis $analysis }
