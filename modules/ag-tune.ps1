#Requires -Version 5.1
#Requires -RunAsAdministrator
[Console]::OutputEncoding = New-Object Text.UTF8Encoding($false)
$OutputEncoding = [Console]::OutputEncoding
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\common.ps1"
try { Assert-WindowsAdmin } catch { Write-Warning $_.Exception.Message; exit 1 }
. "$PSScriptRoot/ui.ps1"
$script:AGInteractiveUi=$true
. "$PSScriptRoot/menus.ps1"
. "$PSScriptRoot/builds.ps1"
while ($true) {
    Show-AGMenuScreen -Title 'AGFixer — Ручные настройки'
    $pause=$false
    try {
        switch (Read-AGCategoryAction -Menu Control) {
            '1' {
                if(Test-AGInteractiveUi){
                    $choice=Read-AGListChoice -Title 'Как Unlocker будет подключаться?' -Options @(
                        'VPN через локальный прокси Unlocker (старый профиль)',
                        'Zapret — он уже должен быть установлен',
                        'Мой прокси — нужен адрес и порт из VPN-клиента',
                        'Прокси из группы Unlocker'
                    ) -Intro @('Для VPN/TUN без локального прокси используйте «Настроить свой VPN» в главном меню. Здесь — отдельный старый профиль.')
                    $p=if($choice){[string]$choice}else{''}
                }else{
                Write-Host '1. VPN через локальный прокси Unlocker — старый профиль, не прямой VPN/TUN.'
                Write-Host '2. Zapret — нужен отдельно установленный и настроенный Zapret.'
                Write-Host '3. Свой прокси — нужен HTTP/HTTPS/SOCKS5 адрес; VLESS не вставляется напрямую.'
                Write-Host '4. Групповой прокси — использует маршрут группового прокси Unlocker.'
                $p = Read-AGInput 'Номер режима 1–4 (Enter — отмена)'
                }
                if([string]::IsNullOrWhiteSpace($p)){break}
                $profile = switch ($p) { '1' { 'VPN' } '2' { 'Zapret' } '3' { 'OwnProxy' } '4' { 'GroupProxy' } default { throw 'Неверный номер профиля.' } }
                $url = ''
                if ($profile -eq 'OwnProxy') {
                    Write-Warning 'Адрес с логином/паролем будет виден при вводе и сохранён в settings.json и будущих копиях. Предпочтителен локальный прокси без пароля.'
                    $url = Read-AGInput 'URL прокси (VLESS-ссылки не поддерживаются; Enter — отмена)'
                    if([string]::IsNullOrWhiteSpace($url)){break}
                }
                Write-Warning 'Изменится только способ подключения Unlocker. VPN не установится, DNS Windows и настройки проверки сертификатов останутся прежними.'
                if (Confirm-Change "Сохранить выбранный способ подключения ($profile)?") {
                    $pause=$true
                    Set-AGProfile -Profile $profile -ProxyUrl $url
                    if (Confirm-Change 'Перезапустить задачи Unlocker и сбросить таблицу маршрутов в памяти?') { Reset-AGService }
                }
            }
            '2' { Invoke-Diagnostics }
            '3' {
                . "$PSScriptRoot/config-wizard.ps1"
                $strategy=Read-AGStrategyChoice
                if($strategy){$pause=[bool](Install-ZapretService $strategy)}
            }
            '4' { $pause=[bool](Remove-AGZapretService) }
            '5' {
                $login=Confirm-Change 'Дополнительно включить 3 домена входа из гайда (www.googleapis.com, play.googleapis.com, lh3.googleusercontent.com)?'
                if (Confirm-Change 'Обновить списки доменов и перезапустить работающую службу Zapret?') { $pause=$true; Add-AGDomains -IncludeLogin:$login }
            }
            '6' { if (Confirm-Change 'Перезапустить задачи Unlocker и очистить таблицу маршрутов в памяти (копия gate.json будет сохранена)?') { $pause=$true; Reset-AGService } }
            '7' { $pause=[bool](Set-VpnDns) }
            '8' { if (Confirm-Change 'Очистить DNS-кэш Windows?') { $pause=$true; Clear-DnsClientCache -ErrorAction Stop; Write-Host 'DNS-кэш очищен.' } }
            '9' {
                $backup=Read-AGBackupChoice -Title 'Какую копию настроек Unlocker вернуть?' -Files @(Get-AGSettingsBackups)
                if($backup){$pause=[bool](Restore-AGSettings -BackupPath $backup.Trim().Trim('"'))}
            }
            '10' {
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
