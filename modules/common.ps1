# Shared helpers. Windows PowerShell 5.1 / PowerShell 7 on Windows.
. "$PSScriptRoot/console-input.ps1"
. "$PSScriptRoot/installation-paths.ps1"
function Assert-WindowsAdmin {
    if ($env:OS -ne 'Windows_NT') { throw 'Для работы требуется Windows.' }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Нужны права администратора. Запустите run.bat.'
    }
}
function Confirm-Change {
    param([string]$Message)
    $answer=([string](Read-AGInput "$Message [Y/N, по умолчанию N]")).Trim()
    if($answer -match '^(?i:yes|д|да)$'){return $true}
    return ((ConvertTo-AGCommandKey $answer) -eq 'Y')
}
function Get-AGPath {
    param([string]$Name)
    if (-not $env:LOCALAPPDATA) { throw 'LOCALAPPDATA не определён.' }
    return (Join-Path (Get-AGUnlockerDataRoot) $Name)
}
function Backup-LocalFile {
    param([Parameter(Mandatory=$true)][string]$Path)
    if (Test-Path -LiteralPath $Path -PathType Leaf) {
        $backup = '{0}.backup-{1}-{2}' -f $Path, (Get-Date -Format 'yyyyMMdd-HHmmss'), ([guid]::NewGuid().ToString('N').Substring(0,8))
        Copy-Item -LiteralPath $Path -Destination $backup -ErrorAction Stop
        Write-Host "Резервная копия: $backup" -ForegroundColor DarkGray
        return $backup
    }
}
function Read-AGSettings {
    $path = Get-AGPath 'settings.json'
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Нет $path. Установите и настройте Unlocker отдельно." }
    $raw = Get-Content -LiteralPath $path -Raw -Encoding UTF8 -ErrorAction Stop
    if ($raw.TrimStart() -notmatch '^\{') { throw 'settings.json должен содержать JSON-объект.' }
    $cfg = $raw | ConvertFrom-Json -ErrorAction Stop
    if ($null -eq $cfg -or $cfg -is [array]) { throw 'Некорректный settings.json.' }
    return $cfg
}
function Set-AGProfile {
    param([ValidateSet('VPN','VpnDirect','Zapret','OwnProxy','GroupProxy')][string]$Profile, [string]$ProxyUrl)
    $path = Get-AGPath 'settings.json'
    $originalHash = Get-AGFileHash $path
    $cfg = Read-AGSettings
    $values = @{ dns = $false; local_proxy = $true; builtin_exits = $false; group_proxy = $false; own_proxy_enabled = $false }
    switch ($Profile) {
        'VpnDirect' { $values.local_proxy = $false }
        'Zapret' { $values.dns = $true }
        'GroupProxy' { $values.group_proxy = $true }
        'OwnProxy' {
            $uri = $null
            if ($ProxyUrl -match '[\x00-\x20]' -or -not [uri]::TryCreate($ProxyUrl, [UriKind]::Absolute, [ref]$uri) -or
                $uri.Scheme -notin @('http','https','socks5') -or -not $uri.Host -or $uri.Port -lt 1 -or $uri.Query -or $uri.Fragment -or $uri.AbsolutePath -notin @('','/')) {
                throw 'Нужен HTTP/HTTPS/SOCKS5 URL с адресом и портом, без пути/query/fragment. VLESS-ссылки напрямую не поддерживаются.'
            }
            $values.own_proxy = $ProxyUrl
            $values.own_proxy_enabled = $true
        }
    }
    # Add-Member works both for existing and missing JSON fields.
    foreach ($key in $values.Keys) { $cfg | Add-Member -NotePropertyName $key -NotePropertyValue $values[$key] -Force }
    $json = $cfg | ConvertTo-Json -Depth 100 -ErrorAction Stop
    $null = $json | ConvertFrom-Json -ErrorAction Stop
    $null = Write-AGAtomicText -Path $path -Text $json -ExpectedHash $originalHash
    Write-Host "Профиль $Profile сохранён. Параметры патчера и TLS не изменены." -ForegroundColor Green
}
function Get-ZapretPath {
    $prefs=Get-AGPathPreferences
    if(Test-AGInstallationPath Zapret $prefs.Zapret){return $prefs.Zapret}
    $candidates = New-Object 'System.Collections.Generic.List[string]'
    if ($env:ZAPRET_PATH) { $candidates.Add($env:ZAPRET_PATH) }
    $proc = Get-Process -Name winws -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($proc -and $proc.Path) { $candidates.Add((Split-Path $proc.Path -Parent)) }
    $svc = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\zapret' -ErrorAction SilentlyContinue
    if ($svc -and $svc.ImagePath) {
        # Preserve paths with spaces; never split an executable path on spaces.
        $m = [regex]::Match([string]$svc.ImagePath, '^\s*(?:"(?<exe>[^"]+\.exe)"|(?<exe>.+?\.exe))(?:\s|$)', 'IgnoreCase')
        if ($m.Success) { $candidates.Add((Split-Path $m.Groups['exe'].Value -Parent)) }
    }
    foreach ($root in @((Join-Path $env:USERPROFILE 'Desktop'), (Join-Path $env:USERPROFILE 'Downloads'), 'C:\', 'D:\', $env:ProgramFiles)) {
        if ($root -and (Test-Path -LiteralPath $root)) {
            foreach ($dir in @(Get-ChildItem -LiteralPath $root -Directory -Filter '*zapret*' -ErrorAction SilentlyContinue)) { $candidates.Add($dir.FullName) }
        }
    }
    foreach ($candidate in $candidates) {
        foreach ($dir in @($candidate, (Split-Path $candidate -Parent))) {
            if ($dir -and (Test-Path -LiteralPath (Join-Path $dir 'service.bat') -PathType Leaf)) { return (Resolve-Path -LiteralPath $dir).Path }
        }
    }
    throw 'Zapret не найден. Откройте Инструменты → Папки программ и выберите папку с service.bat.'
}
function Add-AGDomains {
    param([switch]$IncludeLogin)
    . "$PSScriptRoot/local-audit.ps1"
    . "$PSScriptRoot/zapret-lists.ps1"
    $root = Get-ZapretPath
    $plans = @(New-AGZapretListWritePlans -Root $root -IncludeLogin:$IncludeLogin)
    $svc = Get-Service -Name zapret -ErrorAction SilentlyContinue
    if ($svc -and [string]$svc.Status -notin @('Running','Stopped')) { throw 'Служба в переходном состоянии. Списки не изменены.' }
    $wasRunning = $svc -and [string]$svc.Status -eq 'Running'
    try {
        foreach ($plan in $plans) {
            $plan.AppliedHash = Get-AGTextHash $plan.Text
            $plan.Backup = Write-AGAtomicText -Path $plan.Path -Text $plan.Text -ExpectedHash $plan.Hash
            if ((Get-AGFileHash $plan.Path) -ne $plan.AppliedHash) { throw 'Файл списка изменён после записи; проверьте внешние редакторы.' }
        }
        if ($plans.Count -and $wasRunning) {
            Restart-Service -Name zapret -ErrorAction Stop
            (Get-Service zapret).WaitForStatus('Running',[TimeSpan]::FromSeconds(15))
        }
    } catch {
        $failure = $_.Exception.Message; $rollbackErrors = @()
        foreach ($plan in @($plans | Sort-Object Path -Descending)) {
            if ($plan.Backup) {
                try { Restore-AGFileBytes -Path $plan.Path -Backup $plan.Backup -ExpectedHash $plan.AppliedHash -BackupHash $plan.Hash }
                catch { $rollbackErrors += $_.Exception.Message }
            }
        }
        if ($wasRunning) { try { Restart-Service zapret -ErrorAction Stop; (Get-Service zapret).WaitForStatus('Running',[TimeSpan]::FromSeconds(15)) } catch { $rollbackErrors += $_.Exception.Message } }
        if ($rollbackErrors.Count) { throw ($failure + '; Откат неполный: ' + ($rollbackErrors -join '; ')) }
        throw ($failure + '; применённые изменения списков отменены.')
    }
    Write-Host "Списки обработаны. Изменено файлов: $($plans.Count)."
}
function Get-StrategyCommand {
    param([string]$Root, [string]$StrategyBatName)
    if ([IO.Path]::GetFileName($StrategyBatName) -ne $StrategyBatName) { throw 'Укажите только имя BAT-файла.' }
    $path = Join-Path $Root $StrategyBatName
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Нет стратегии $StrategyBatName. Автоподмена другой стратегией запрещена." }
    $exe = Join-Path $Root 'bin\winws.exe'
    if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) { throw 'bin\winws.exe не найден.' }
    $text = Get-Content -LiteralPath $path -Raw -Encoding UTF8 -ErrorAction Stop
    # Join ONLY BAT continuation lines, not every remaining command in the file.
    $text = $text -replace '\^\s*\r?\n', ' '
    $commands = @($text -split '\r?\n' | Where-Object { $_ -notmatch '^\s*(?:rem\b|::)' -and $_ -match '(?i)winws\.exe"?\s+--' })
    if ($commands.Count -ne 1) { throw 'Нужна ровно одна команда winws.exe. Для сложного BAT используйте штатный service.bat.' }
    $m = [regex]::Match($commands[0], '(?i)winws\.exe"?\s+(?<args>--.+)$')
    if (-not $m.Success) { throw 'Не удалось извлечь аргументы winws.' }
    $argsText = $m.Groups['args'].Value.Trim()
    # Literal replacement, not regex replacement (paths may contain $).
    $argsText = $argsText.Replace('%BIN%', ((Join-Path $Root 'bin') + '\')).Replace('%LISTS%', ((Join-Path $Root 'lists') + '\'))
    if ($argsText -match '(?i)%GameFilter(?:TCP|UDP)?%') {
        . "$PSScriptRoot\local-audit.ps1"
        $game=Get-AGGameFilterState -Root $Root
        $variables=@{GameFilterTCP=$game.TCP;GameFilterUDP=$game.UDP;GameFilter=$game.Legacy}
        foreach ($key in $variables.Keys) {
            $replacementValue=[string]$variables[$key]
            $argsText=[regex]::Replace($argsText, ('(?i)%'+$key+'%'), [Text.RegularExpressions.MatchEvaluator]{param($match) $replacementValue})
        }
    }
    if ($argsText -match '%[^%]+%|[!&|<>^`\r\n]') {
        throw 'Неизвестные переменные/команды BAT. Поддерживается только проверенный формат Game Filter Flowseal; для других версий используйте штатный service.bat.'
    }
    if (([regex]::Matches($argsText, '"').Count % 2) -ne 0) { throw 'Несбалансированные кавычки в стратегии.' }
    return ('"{0}" {1}' -f $exe, $argsText)
}
function ConvertTo-WindowsArgument {
    param([AllowEmptyString()][string]$Value)
    # Windows CommandLineToArgvW escaping, including embedded quotes and trailing backslashes.
    $valueEscaped = [regex]::Replace($Value, '(\\*)"', '$1$1\"')
    $valueEscaped = [regex]::Replace($valueEscaped, '(\\+)$', '$1$1')
    return ('"' + $valueEscaped + '"')
}
function Invoke-ServiceControl {
    param([string[]]$Arguments)
    $info = New-Object Diagnostics.ProcessStartInfo
    $info.FileName = "$env:SystemRoot\System32\sc.exe"
    $info.Arguments = (($Arguments | ForEach-Object { ConvertTo-WindowsArgument $_ }) -join ' ')
    $info.UseShellExecute = $false
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $process = New-Object Diagnostics.Process
    $process.StartInfo = $info
    try {
        $null = $process.Start()
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit(30000)) {
            $process.Kill()
            throw 'sc.exe не завершился за 30 секунд; состояние службы нужно проверить вручную.'
        }
        $outputText = $stdout.GetAwaiter().GetResult() + $stderr.GetAwaiter().GetResult()
        if ($process.ExitCode -ne 0) { throw "sc.exe: $outputText (код $($process.ExitCode))" }
    } finally { $process.Dispose() }
}
function Install-ZapretService {
    param([Parameter(Mandatory=$true)][string]$StrategyBatName, [ValidatePattern('^(zapret|AGOptimizerTest-[a-f0-9]{12})$')][string]$ServiceName = 'zapret',[switch]$Confirmed)
    $root = Get-ZapretPath
    $command = Get-StrategyCommand $root $StrategyBatName # Validate BEFORE stopping anything.
    Assert-AGStrategyFiles -Command $command
    if(Test-AGInteractiveUi -and -not $Confirmed){
        Show-AGTextPages -Title 'Выбран способ работы Zapret' -Lines @(
            "Стратегия: $StrategyBatName", "Программа: $(Join-Path $root 'bin\winws.exe')",
            'Изменится автоматически запускаемая служба Zapret. Соединение может кратковременно прерваться.',
            'Продолжайте только если доверяете установленному Zapret и выбранному файлу.',
            'Дальше — отдельное подтверждение. Пока ничего не изменено.'
        )
    }else{
        Write-Host "Исполняемый файл: $(Join-Path $root 'bin\winws.exe')"
        Write-Warning 'Будет изменена автозапускаемая служба Zapret. Доверяйте источнику winws.exe и выбранного BAT.'
    }
    if (-not $Confirmed -and -not (Confirm-Change "Применить стратегию $StrategyBatName?")) { return $false }
    $regPath = ('HKLM:\SYSTEM\CurrentControlSet\Services\' + $ServiceName)
    $old = Get-ItemProperty $regPath -ErrorAction SilentlyContinue
    $svc = Get-Service $ServiceName -ErrorAction SilentlyContinue
    if ($svc -and (-not $old -or -not $old.ImagePath -or $null -eq $old.Start)) { throw 'Не удалось прочитать исходную конфигурацию службы; изменения отменены.' }
    if ($svc -and [string]$svc.Status -notin @('Running','Stopped')) { throw 'Служба в переходном/приостановленном состоянии; изменения отменены.' }
    $wasRunning = $svc -and $svc.Status -eq 'Running'
    $created = $false
    $createAttempted = $false
    if ($old -and -not $svc) { throw 'Реестр службы существует, но SCM её не показывает; проверьте состояние вручную до изменений.' }
    if ($svc) {
        $backup = Join-Path $root ('zapret-service.backup-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '-' + [guid]::NewGuid().ToString('N') + '.json')
        $old | Select-Object ImagePath, Start, DelayedAutoStart, 'zapret-discord-youtube' | ConvertTo-Json | Set-Content -LiteralPath $backup -Encoding UTF8 -ErrorAction Stop
        Write-Host "Резервная копия конфигурации службы: $backup"
    } elseif (Get-Process winws -ErrorAction SilentlyContinue) {
        throw 'winws уже работает вне службы. Остановите его вручную перед установкой службы.'
    }
    try {
        if ($svc) {
            Stop-Service $ServiceName -ErrorAction Stop
            $svc.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(15))
            Invoke-ServiceControl -Arguments @('config',$ServiceName,'binPath=', $command,'start=','auto')
        } else {
            $createAttempted = $true
            Invoke-ServiceControl -Arguments @('create',$ServiceName,'binPath=', $command,'DisplayName=','zapret','start=','auto')
            $created = $true
        }
        Start-Service $ServiceName -ErrorAction Stop
        (Get-Service $ServiceName).WaitForStatus('Running', [TimeSpan]::FromSeconds(15))
        $null = New-ItemProperty -Path $regPath -Name 'zapret-discord-youtube' -Value ([IO.Path]::GetFileNameWithoutExtension($StrategyBatName)) -PropertyType String -Force -ErrorAction Stop
        Write-Host 'Служба запущена.' -ForegroundColor Green
        return $true
    } catch {
        $failure = $_
        try {
            if ($createAttempted -and -not $created) {
                $observed=Get-ItemProperty $regPath -ErrorAction SilentlyContinue
                $live=Get-Service $ServiceName -ErrorAction SilentlyContinue
                if ($live -and $observed -and [string]$observed.ImagePath -eq $command) { $created=$true }
                elseif ($live -or $observed) { throw 'Создание завершилось неоднозначно; найденную конфигурацию нельзя безопасно считать своей. Проверьте службу вручную.' }
                else { throw 'Создание не подтверждено после ошибки/таймаута sc.exe. Проверьте SCM вручную; отсутствие изменений не гарантируется.' }
            }
            if ($created) {
                $live = Get-Service $ServiceName -ErrorAction SilentlyContinue
                if ($live) { Stop-Service $ServiceName -ErrorAction Stop; $live.WaitForStatus('Stopped',[TimeSpan]::FromSeconds(15)) }
                Invoke-ServiceControl -Arguments @('delete',$ServiceName)
            } elseif ($old) {
                Stop-Service $ServiceName -ErrorAction Stop
                (Get-Service $ServiceName).WaitForStatus('Stopped',[TimeSpan]::FromSeconds(15))
                $startMode = switch ([int]$old.Start) { 2 { if ($old.DelayedAutoStart -eq 1) { 'delayed-auto' } else { 'auto' } } 3 { 'demand' } 4 { 'disabled' } default { throw 'Неизвестный режим запуска службы.' } }
                Invoke-ServiceControl -Arguments @('config',$ServiceName,'binPath=',[string]$old.ImagePath,'start=',$startMode)
                if ($null -ne $old.'zapret-discord-youtube') {
                    $null = New-ItemProperty -Path $regPath -Name 'zapret-discord-youtube' -Value $old.'zapret-discord-youtube' -PropertyType String -Force -ErrorAction Stop
                } else { Remove-ItemProperty -Path $regPath -Name 'zapret-discord-youtube' -ErrorAction SilentlyContinue }
                if ($wasRunning) { Start-Service $ServiceName -ErrorAction Stop; (Get-Service $ServiceName).WaitForStatus('Running',[TimeSpan]::FromSeconds(15)) }
            }
        } catch { throw ("Ошибка: " + $failure.Exception.Message + "; Автооткат службы не выполнен: " + $_.Exception.Message + ". Используйте резервную копию.") }
        throw $failure
    }
}
function Reset-AGService {
    param([switch]$RemoveGateReport)
    $names = @('AG Unlocker DNS','AG Unlocker Watchdog')
    foreach ($name in $names) {
        $task = Get-ScheduledTask -TaskName $name -TaskPath '\' -ErrorAction SilentlyContinue
        if (-not $task) { throw "Не найдена задача $name. Сброс отменён." }
        if ([string]$task.State -eq 'Disabled') { throw "Задача $name отключена. Сброс отменён до остановки задач." }
    }
    $gate = Get-AGPath 'gate.json'
    # Penalties in current upstream routes.rs are process-local. Restart resets them.
    # gate.json is a published report; removal is optional, for legacy workflows.
    $null = Backup-LocalFile $gate
    $expectedExe = Assert-AGUnlockerRuntime
    foreach ($proc in @(Get-Process ag_dns -ErrorAction SilentlyContinue)) {
        if (-not $proc.Path -or [IO.Path]::GetFullPath($proc.Path) -ine $expectedExe) {
            throw 'Найден ag_dns вне папки AGUnlocker; сброс отменён до остановки задач.'
        }
    }
    $primaryFailure=$null
    try {
        foreach ($name in $names) { Stop-ScheduledTask -TaskName $name -TaskPath '\' -ErrorAction Stop }
        $deadline = (Get-Date).AddSeconds(10)
        do {
            $running = @($names | ForEach-Object { Get-ScheduledTask -TaskName $_ -TaskPath '\' -ErrorAction Stop } | Where-Object { $_.State -eq 'Running' })
            if (-not $running.Count) { break }
            Start-Sleep -Milliseconds 100
        } while ((Get-Date) -lt $deadline)
        if ($running.Count) { throw 'Задачи не остановились за 10 секунд; сброс отменён.' }
        foreach ($proc in @(Get-Process ag_dns -ErrorAction SilentlyContinue)) {
            if (-not $proc.Path -or [IO.Path]::GetFullPath($proc.Path) -ine $expectedExe) {
                throw 'Найден ag_dns вне папки AGUnlocker; принудительное завершение отменено.'
            }
            Stop-Process -Id $proc.Id -Force -ErrorAction Stop
            if (-not $proc.WaitForExit(5000)) { throw 'ag_dns не завершился за 5 секунд; операция прервана.' }
        }
        if ($RemoveGateReport -and (Test-Path -LiteralPath $gate)) { Remove-Item -LiteralPath $gate -Force -ErrorAction Stop }
        Clear-DnsClientCache -ErrorAction Stop
    } catch { $primaryFailure=$_.Exception.Message } finally {
        # Always attempt both restarts, even if stopping/deleting failed.
        $errors = @()
        foreach ($name in $names) {
            try { Start-ScheduledTask -TaskName $name -TaskPath '\' -ErrorAction Stop }
            catch { $errors += $_.Exception.Message }
        }
        if ($errors.Count) { $primaryFailure = (@($primaryFailure,'Не все задачи запущены: '+($errors -join '; ')) | Where-Object { $_ }) -join '; ' }
    }
    if ($primaryFailure) { throw $primaryFailure }
    if($RemoveGateReport){Write-Host 'Unlocker перезапущен. Старый gate.json сохранён в резервной копии.'}else{Write-Host 'Unlocker перезапущен. gate.json сохранён на месте.'}
}
function Set-VpnDns {
    $adapters = @(Get-NetAdapter -ErrorAction Stop | Where-Object {
        $_.Status -eq 'Up' -and ($_.InterfaceDescription -match 'wireguard|wintun|sing-box|xray|v2ray|openvpn|tap' -or $_.Name -match 'wg|vpn|tun|vless|incy') -and
        $_.InterfaceDescription -notmatch 'radmin|hamachi|virtualbox|hyper-v'
    })
    if (-not $adapters.Count) { throw 'VPN-адаптер не найден. DNS не изменён.' }
    if(Test-AGInteractiveUi){
        $choice=Read-AGListChoice -Title 'У какого VPN поменять DNS?' -Options @($adapters|ForEach-Object{"$($_.Name) — $($_.InterfaceDescription)"}) -Intro @('DNS помогает программе находить адреса сайтов.','Выберите только свой VPN. Enter — ничего не менять.')
        if(-not $choice){return $false};$index=[int]$adapters[$choice-1].InterfaceIndex
    }else{
        foreach ($a in $adapters) { Write-Host "$($a.InterfaceIndex): $($a.Name) — $($a.InterfaceDescription)" }
        $selection = Read-AGInput 'Введите InterfaceIndex нужного VPN-адаптера (Enter — отмена)'
        $index = 0
        if ([string]::IsNullOrWhiteSpace($selection)) { return $false }
        if (-not [int]::TryParse($selection, [ref]$index) -or $index -notin @($adapters.InterfaceIndex)) { throw 'Неверный индекс.' }
    }
    Write-Warning 'Смена DNS не доказывает отсутствие утечек и может нарушить DNS VPN/локальной сети.'
    if (-not (Confirm-Change 'Назначить только IPv4 DNS 1.1.1.1 / 8.8.8.8?')) { return $false }
    $backup = Set-AGAdapterDns -InterfaceIndex $index -ServerAddresses @('1.1.1.1','8.8.8.8')
    Write-Host "DNS назначены и проверены. Копия с режимом/идентификатором адаптера: $backup"
    return $true

}
function Test-AGConnection {
    param([int]$TimeoutMs = 5000, [uri]$ProxyUri,[switch]$RequireTls13)
    . "$PSScriptRoot\TLS-Probe.ps1"
    try {
        $result = Test-AGTls13 -TimeoutMs $TimeoutMs -ProxyUri $ProxyUri -AllowTls12:(-not $RequireTls13)
        if(Test-AGInteractiveUi){
            $lines=@('Соединение установлено. Сертификат Google проверен. Фактический протокол: '+$result.Protocol)
            foreach($prop in $result.PSObject.Properties){$lines+="$($prop.Name): $($prop.Value)"}
            if(-not $result.IsTls13){$lines+=('TLS 1.3 не заявлен: согласован '+$result.Protocol+'. На Windows 10 это ожидаемо для системного Schannel.')}
            $lines+='Это проверка соединения, а не доступа к модели. Аккаунт, квота и региональный доступ проверяются отдельно.'
            Show-AGTextPages -Title 'Результат проверки соединения' -Lines $lines
            return
        }
        $result | Format-List
        if($result.IsTls13){Write-Host 'TLS 1.3 подтверждён с проверкой имени/сертификата.' -ForegroundColor Green}
        else{Write-Host ('Согласован '+$result.Protocol+'. Это не подтверждение TLS 1.3; метрики handshake сохранены.') -ForegroundColor Yellow}
        Write-Host 'TlsHandshakeMs — длительность AuthenticateAsClientAsync, не чистый RTT; проверка сертификата и локальная обработка включены. Resumption не исключён.'
        Write-Host 'Path указывает прямой путь или явно выбранный HTTP/SOCKS5-туннель. Успех не доказывает работу модели, квоты, региональный доступ или вклад именно Zapret.'
    } catch {
        $exception=$_.Exception
        while($exception -and -not ($exception.PSObject.Properties['Result'] -and $exception.Result)){$exception=$exception.InnerException}
        if($exception -and $exception.Result.Status -eq 'Unsupported'){Write-Warning 'TLS 1.3 не поддерживается ОС/runtime. Это не блокировка сервера; совместимый TLS 1.2/1.3 доступен без -RequireTls13.'}
        else{Write-Warning $_.Exception.Message}
    }
}
function Invoke-Diagnostics {
    . "$PSScriptRoot/local-audit.ps1"
    $audit=Get-AGLocalAudit
    Show-AGLocalAudit $audit
}

# Public operations use one per-user exclusive lock. This coordinates this utility,
# not unrelated applications. Hash checks additionally detect most external edits.
. "$PSScriptRoot/state-tools.ps1"
foreach ($operation in @('Set-AGProfile','Add-AGDomains','Install-ZapretService','Reset-AGService')) {
    Set-Item -Path ('Function:Invoke-Unlocked'+$operation) -Value (Get-Item ('Function:'+$operation)).ScriptBlock
}
function Set-AGProfile {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param([ValidateSet('VPN','VpnDirect','Zapret','OwnProxy','GroupProxy')][string]$Profile,[string]$ProxyUrl)
    if(-not $PSCmdlet.ShouldProcess($Profile,'Сохранить профиль Unlocker')){return}
    Invoke-AGExclusiveOperation { Invoke-UnlockedSet-AGProfile -Profile $Profile -ProxyUrl $ProxyUrl }
}
function Add-AGDomains { [CmdletBinding(SupportsShouldProcess=$true)]param([switch]$IncludeLogin) if(-not $PSCmdlet.ShouldProcess('Списки Zapret','Добавить домены и перезапустить работающую службу')){return};Invoke-AGExclusiveOperation { Invoke-UnlockedAdd-AGDomains -IncludeLogin:$IncludeLogin } }
function Install-ZapretService {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param([Parameter(Mandatory=$true)][string]$StrategyBatName,[ValidatePattern('^(zapret|AGOptimizerTest-[a-f0-9]{12})$')][string]$ServiceName='zapret')
    if(-not $PSCmdlet.ShouldProcess($ServiceName,'Применить стратегию '+$StrategyBatName)){return}
    Invoke-AGExclusiveOperation { Invoke-UnlockedInstall-ZapretService -StrategyBatName $StrategyBatName -ServiceName $ServiceName }
}
function Reset-AGService { [CmdletBinding(SupportsShouldProcess=$true)]param([switch]$RemoveGateReport) if(-not $PSCmdlet.ShouldProcess('Задачи Unlocker','Перезапустить маршрутизацию')){return};Invoke-AGExclusiveOperation { Invoke-UnlockedReset-AGService -RemoveGateReport:$RemoveGateReport } }
