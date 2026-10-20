#Requires -Version 5.1
#Requires -RunAsAdministrator
[Console]::OutputEncoding=New-Object Text.UTF8Encoding($false)
$OutputEncoding=[Console]::OutputEncoding
$ErrorActionPreference='Stop'
. "$PSScriptRoot/common.ps1"
try { Assert-WindowsAdmin } catch { Write-Warning $_.Exception.Message; exit 1 }
. "$PSScriptRoot/ui.ps1"
$script:AGInteractiveUi=$true
. "$PSScriptRoot/menus.ps1"
. "$PSScriptRoot/builds.ps1"
. "$PSScriptRoot/report-analysis.ps1"
. "$PSScriptRoot/local-audit.ps1"
. "$PSScriptRoot/support-bundle.ps1"
$lastReport=''; $lastAudit=$null
function Read-AGReportFile {
    $path=(Read-AGInput 'Полный путь к TXT-файлу (Enter — отмена)').Trim().Trim('"')
    if (-not $path) { return '' }
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw 'Файл не найден.' }
    if ((Get-Item -LiteralPath $path).Length -gt 10MB) { throw 'Максимум 10 МБ.' }
    return (Get-Content -LiteralPath $path -Raw -Encoding UTF8 -ErrorAction Stop)
}
while ($true) {
    Show-AGMenuScreen -Title 'AGFixer — дополнительные инструменты — Главное меню'
    $pause=$false
    try {
        switch (Read-AGCategoryAction -Menu Doctor) {
            '1' { $lastReport=Get-Clipboard -Raw -ErrorAction Stop; Show-AGReportHelp -Text $lastReport -Paged }
            '2' { $text=Read-AGReportFile; if ($text) { $lastReport=$text; Show-AGReportHelp -Text $lastReport -Paged } }
            '3' { $lastAudit=Get-AGLocalAudit; Show-AGLocalAudit $lastAudit }
            '4' { & "$PSScriptRoot/launch.ps1" -ControlCenter }
            '5' {
                Write-Host 'Проверим, устанавливается ли защищённое соединение с Google.'
                Write-Host 'Без прокси: нажмите Enter. Со своим прокси: укажите его адрес и порт.'
                $url=Read-AGInput 'HTTP/SOCKS5 URL без пароля (Enter — прямой системный путь)'
                $proxy=$null
                if ($url) { $proxy=[uri]$url }
                Write-Host 'Тест создаст сетевое соединение; запрос к модели не отправляется.'
                if (Confirm-Change 'Запустить TLS-проверку?') { $pause=$true; Test-AGConnection -ProxyUri $proxy }
            }
            '16' { . "$PSScriptRoot/connection-path.ps1"; Invoke-AGConnectionCheckMenu }
            '17' { . "$PSScriptRoot/repair-safe.ps1"; Invoke-AGQuickRepair -Snapshot (Get-AGRepairSnapshot) -Analysis $null }
            '6' {
                $answers=Read-AGSupportAnswers
                if (-not $lastReport -and (Confirm-Change 'Добавить TXT-отчёт?')) { $lastReport=Read-AGReportFile }
                if (Confirm-Change 'Добавить локальный снимок процессов/портов/hosts/NRPT?') { $lastAudit=Get-AGLocalAudit } else { $lastAudit=$null }
                $tail=Confirm-Change 'Добавить последние 200 строк forwarder.log после эвристического скрытия реквизитов?'
                $out=Read-AGInput "Папка для ZIP (Enter — $PSScriptRoot)"
                if (-not $out) { $out=$PSScriptRoot }
                $pause=$true
                Export-AGSupportBundle -ReportText $lastReport -Answers $answers -LocalAudit $lastAudit -IncludeLogTail:$tail -OutputDirectory $out
            }
            '7' {
                . "$PSScriptRoot/guide-menu.ps1"
                Show-AGCommunityGuides
            }
            '8' {
                . "$PSScriptRoot/repair-safe.ps1"
                $app=Read-AGInput 'Приложение: 1 Antigravity, 2 Antigravity IDE, 3 Antigravity Manager (Enter — отмена)'
                $name=switch ($app) { '1' { 'Antigravity' } '2' { 'Antigravity IDE' } '3' { 'Antigravity Manager' } default { $null } }
                if ($name) { $result=Move-AGGpuCache -Application $name; $pause=[bool]$result; if($result -is [string]){Write-Host "Резервная папка: $result"} }
                elseif($app){throw 'Неверный номер приложения.'}
            }
            '10' {
                . "$PSScriptRoot/repair-safe.ps1"
                $app=Read-AGInput 'Приложение: 1 Antigravity, 2 Antigravity IDE, 3 Antigravity Manager (Enter — отмена)'
                $name=switch($app){'1'{'Antigravity'}'2'{'Antigravity IDE'}'3'{'Antigravity Manager'}default{$null}}
                if($name){
                    $parent=Join-Path $env:APPDATA $name
                    $files=@(Get-ChildItem -LiteralPath $parent -Directory -Filter 'GPUCache.backup-*' -ErrorAction Stop)
                    $backup=Read-AGBackupChoice -Title 'Какую копию графического кэша вернуть?' -Files $files
                    if($backup){$pause=[bool](Restore-AGGpuCache -Application $name -BackupPath $backup.Trim().Trim('"'))}
                } elseif($app){throw 'Неверный номер приложения.'}
            }
            '14' {
                $backup=Read-AGBackupChoice -Title 'Какую копию настроек Unlocker вернуть?' -Files @(Get-AGSettingsBackups)
                if($backup){$pause=[bool](Restore-AGSettings -BackupPath $backup.Trim().Trim('"'))}
            }
            '15' {
                $files=@(Get-ChildItem -LiteralPath (Split-Path (Get-AGPath 'settings.json') -Parent) -Filter 'dns.backup-*.json' -File)
                $backup=Read-AGBackupChoice -Title 'Какие DNS-настройки вернуть?' -Files $files
                if($backup){$pause=[bool](Restore-AGDns -BackupPath $backup.Trim().Trim('"'))}
            }
            '11' { $pause=Invoke-AGBuildMenuAction -Action Export }
            '12' { $pause=Invoke-AGBuildMenuAction -Action Import }
            '13' { $pause=Invoke-AGBuildMenuAction -Action Preview }
            '0' { return }
            '' { }
            default { $pause=$true; Write-Warning 'Неизвестное действие.' }
        }
    } catch { $pause=$true; Write-Warning $_.Exception.Message }
    if($pause){Wait-AGMenuReturn}
}
