#Requires -Version 5.1
# File/DNS recovery helpers. No operations run merely by loading this file.
function Get-AGFileHash {
    param([Parameter(Mandatory=$true)][string]$Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash
}
function Invoke-AGExclusiveOperation {
    param([Parameter(Mandatory=$true)][scriptblock]$Action)
    if (-not $env:LOCALAPPDATA) { throw 'LOCALAPPDATA не определён.' }
    $folder=Join-Path $env:LOCALAPPDATA 'AGOptimizer'
    $null=New-Item -ItemType Directory -Path $folder -Force -ErrorAction Stop
    $handle=$null
    try {
        try { $handle=[IO.File]::Open((Join-Path $folder 'operation.lock'),[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None) }
        catch { throw 'Другая операция AGFixer уже выполняется или нет доступа к operation.lock. Изменения не начаты.' }
        & $Action
    } finally { if ($handle) { $handle.Dispose() } }
}
function Write-AGAtomicText {
    param([Parameter(Mandatory=$true)][string]$Path,[AllowEmptyString()][string]$Text,[Parameter(Mandatory=$true)][string]$ExpectedHash)
    if ((Get-AGFileHash $Path) -ne $ExpectedHash) { throw 'Файл изменён другой программой; перечитайте его. Изменения отменены.' }
    $backup=Backup-LocalFile $Path
    if (-not $backup -or (Get-AGFileHash $backup) -ne $ExpectedHash) { throw 'Не удалось проверить резервную копию; исходник не заменён.' }
    $temp=Join-Path (Split-Path $Path -Parent) ([IO.Path]::GetRandomFileName())
    try {
        [IO.File]::WriteAllText($temp,$Text,(New-Object Text.UTF8Encoding($false)))
        if ((Get-AGFileHash $Path) -ne $ExpectedHash) { throw 'Исходник изменился во время резервирования; запись отменена.' }
        [IO.File]::Replace($temp,$Path,[System.Management.Automation.Language.NullString]::Value)
    } finally { if (Test-Path -LiteralPath $temp) { Remove-Item -LiteralPath $temp -Force -ErrorAction Stop } }
    return $backup
}
function Restore-AGFileBytes {
    param([string]$Path,[string]$Backup,[string]$ExpectedHash,[string]$BackupHash)
    if (-not $ExpectedHash -or (Get-AGFileHash $Path) -ne $ExpectedHash) { throw 'Откат не перезаписывает файл, изменённый после операции. Используйте копию вручную.' }
    if($BackupHash -and (Get-AGFileHash $Backup) -ne $BackupHash){throw 'Резервная копия изменена/повреждена; автоматический откат отменён.'}
    $temp=Join-Path (Split-Path $Path -Parent) ([IO.Path]::GetRandomFileName())
    try {
        [IO.File]::WriteAllBytes($temp,[IO.File]::ReadAllBytes($Backup))
        if ((Get-AGFileHash $Path) -ne $ExpectedHash) { throw 'Файл изменился во время отката; восстановление отменено.' }
        [IO.File]::Replace($temp,$Path,[System.Management.Automation.Language.NullString]::Value)
    } finally { if (Test-Path -LiteralPath $temp) { Remove-Item -LiteralPath $temp -Force -ErrorAction Stop } }
}
function Assert-AGStrategyFiles {
    param([Parameter(Mandatory=$true)][string]$Command)
    foreach ($arg in [regex]::Matches($Command,'--(?<name>[a-z0-9-]+)=(?:"(?<value>[^"]*)"|(?<value>\S+))','IgnoreCase')) {
        $name=$arg.Groups['name'].Value; $value=$arg.Groups['value'].Value
        $isFile=$name -match '^(?:hostlist(?:-exclude|-auto)?|ipset(?:-exclude)?|dpi-desync-fake-(?:tls|http|quic|wireguard|dht|unknown-udp|unknown-tcp))$'
        if ($isFile -and $value -match '^0x[0-9a-fA-F]+$' -and $name -like 'dpi-desync-fake-*') { continue }
        if ($isFile -or [IO.Path]::IsPathRooted($value)) {
            if (-not [IO.Path]::IsPathRooted($value)) { throw "Относительный путь --$name не подходит службе: $value. Укажите абсолютный путь через %BIN%/%LISTS%." }
            if (-not (Test-Path -LiteralPath $value -PathType Leaf)) { throw "Нет файла --${name}: $value" }
        }
    }
}
function Get-AGSettingsBackups {
    $path=Get-AGPath 'settings.json'; $parent=Split-Path $path -Parent
    if (Test-Path -LiteralPath $parent) { Get-ChildItem -LiteralPath $parent -Filter 'settings.json.backup-*' -File | Sort-Object LastWriteTimeUtc -Descending | Select-Object FullName,Length,LastWriteTimeUtc }
}
function Restore-AGSettings {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param([Parameter(Mandatory=$true)][string]$BackupPath)
    if(-not $PSCmdlet.ShouldProcess('Локальная конфигурация','Restore-AGSettings')){return}
    Invoke-AGExclusiveOperation {
        $path=Get-AGPath 'settings.json'
        $resolved=(Resolve-Path -LiteralPath $BackupPath -ErrorAction Stop).Path
        $expectedDir=[IO.Path]::GetFullPath((Split-Path $path -Parent))
        if ([IO.Path]::GetDirectoryName($resolved) -ne $expectedDir -or [IO.Path]::GetFileName($resolved) -notlike 'settings.json.backup-*') { throw 'Разрешены только settings.json.backup-* рядом с текущими настройками.' }
        if ((Get-Item -LiteralPath $resolved).Length -gt 4MB) { throw 'Слишком большая копия настроек.' }
        $text=[IO.File]::ReadAllText($resolved)
        if ($text.TrimStart() -notmatch '^\{') { throw 'Копия не содержит JSON-объект.' }
        $null=$text | ConvertFrom-Json -ErrorAction Stop
        $hash=Get-AGFileHash $path
        Write-Warning 'Сначала закройте окно Unlocker, чтобы оно не перезаписало восстановленные настройки. Служба автоматически не перезапускается.'
        if (-not (Confirm-Change "Восстановить настройки из $resolved?")) { return $false }
        $null=Write-AGAtomicText -Path $path -Text $text -ExpectedHash $hash
        Write-Host 'Настройки восстановлены. Предыдущее состояние сохранено в новой backup-копии.'
        return $true
    }
}
function Test-AGDnsAddresses {
    param([string[]]$Addresses)
    if (-not $Addresses -or $Addresses.Count -gt 8) { throw 'Нужно от 1 до 8 IPv4 DNS-адресов.' }
    foreach ($value in $Addresses) {
        $ip=$null
        if ($value -notmatch '^(?:\d{1,3}\.){3}\d{1,3}$' -or -not [Net.IPAddress]::TryParse($value,[ref]$ip) -or $ip.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork -or $ip.GetAddressBytes()[0] -ge 224 -or $value -in @('0.0.0.0','255.255.255.255')) { throw "Недопустимый IPv4 DNS: $value" }
    }
}
function Get-AGDnsSnapshot {
    param([int]$InterfaceIndex)
    $adapter=Get-NetAdapter -InterfaceIndex $InterfaceIndex -IncludeHidden -ErrorAction Stop
    $guid=[guid]$adapter.InterfaceGuid
    $row=@(Get-DnsClientServerAddress -InterfaceIndex $InterfaceIndex -AddressFamily IPv4 -ErrorAction Stop)
    if ($row.Count -ne 1 -or [int]$row[0].AddressFamily -ne 2) { throw 'Не удалось однозначно получить IPv4 DNS.' }
    $reg='HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\' + $guid.ToString('B')
    $settings=Get-ItemProperty -LiteralPath $reg -ErrorAction Stop
    $static=[string]$settings.NameServer
    $mode=if ([string]::IsNullOrWhiteSpace($static)) { 'DHCP' } else { 'Static' }
    # Refuse unknown/nonstandard registry syntax rather than misclassifying a static setup.
    if ($mode -eq 'Static') {
        $configured=@($static -split '[,;\s]+' | Where-Object { $_ })
        Test-AGDnsAddresses $configured
        if (($configured -join ',') -ne (@($row[0].ServerAddresses) -join ',')) { throw 'DNS реестра и эффективные адреса различаются. Возможна политика/VPN; автоматическая смена отменена.' }
    }
    return [pscustomobject]@{FormatVersion=2;Kind='AGOptimizer.IPv4Dns';ComputerName=$env:COMPUTERNAME;InterfaceGuid=$guid.ToString('D');InterfaceIndex=$InterfaceIndex;Mode=$mode;ServerAddresses=@($row[0].ServerAddresses);CreatedAt=[datetime]::UtcNow.ToString('o')}
}
function Save-AGDnsSnapshot {
    param($Snapshot)
    $path=Get-AGPath ('dns.backup-'+[guid]::NewGuid().ToString('N')+'.json')
    $null=New-Item -ItemType Directory -Path (Split-Path $path -Parent) -Force -ErrorAction Stop
    $Snapshot | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $path -Encoding UTF8 -ErrorAction Stop
    return $path
}
function Set-AGDnsFromSnapshot {
    param($Snapshot)
    if ($Snapshot.Kind -ne 'AGOptimizer.IPv4Dns' -or $Snapshot.FormatVersion -ne 2 -or $Snapshot.Mode -notin @('Static','DHCP')) { throw 'Неизвестный формат копии DNS; автоматическое восстановление запрещено.' }
    if (-not $Snapshot.ComputerName -or $Snapshot.ComputerName -ne $env:COMPUTERNAME) { throw 'Копия DNS от другого/неизвестного компьютера.' }
    $guid=[guid]$Snapshot.InterfaceGuid
    $adapter=@(Get-NetAdapter -IncludeHidden -ErrorAction Stop | Where-Object { [guid]$_.InterfaceGuid -eq $guid })
    if ($adapter.Count -ne 1) { throw 'Исходный адаптер по GUID не найден однозначно. Индекс мог быть переиспользован; откат отменён.' }
    $row=@(Get-DnsClientServerAddress -InterfaceIndex $adapter[0].InterfaceIndex -AddressFamily IPv4 -ErrorAction Stop)
    if ($row.Count -ne 1 -or [int]$row[0].AddressFamily -ne 2) { throw 'Нет однозначного IPv4 DNS-объекта для отката.' }
    if ($Snapshot.Mode -eq 'Static') {
        Test-AGDnsAddresses @($Snapshot.ServerAddresses)
        Set-DnsClientServerAddress -InputObject $row[0] -ServerAddresses @($Snapshot.ServerAddresses) -ErrorAction Stop
    } else { Set-DnsClientServerAddress -InputObject $row[0] -ResetServerAddresses -ErrorAction Stop }
    $after=Get-AGDnsSnapshot -InterfaceIndex $adapter[0].InterfaceIndex
    if ($after.Mode -ne $Snapshot.Mode -or ($Snapshot.Mode -eq 'Static' -and (@($after.ServerAddresses) -join ',') -ne (@($Snapshot.ServerAddresses) -join ','))) { throw 'Проверка восстановленного DNS не пройдена; проверьте политики/VPN вручную.' }
}
function Set-AGAdapterDns {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param([Parameter(Mandatory=$true)][int]$InterfaceIndex,[Parameter(Mandatory=$true)][string[]]$ServerAddresses)
    if(-not $PSCmdlet.ShouldProcess('Локальная конфигурация','Set-AGAdapterDns')){return}
    Invoke-AGExclusiveOperation {
        Test-AGDnsAddresses $ServerAddresses
        $before=Get-AGDnsSnapshot $InterfaceIndex
        if (-not $before.ComputerName) { throw 'COMPUTERNAME не определён.' }
        $backup=Save-AGDnsSnapshot $before
        $row=@(Get-DnsClientServerAddress -InterfaceIndex $InterfaceIndex -AddressFamily IPv4 -ErrorAction Stop)
        if ($row.Count -ne 1 -or [int]$row[0].AddressFamily -ne 2) { throw 'Нет однозначного IPv4 DNS-объекта. Изменения не начаты.' }
        $latest=Get-AGDnsSnapshot $InterfaceIndex
        if ($latest.InterfaceGuid -ne $before.InterfaceGuid -or $latest.Mode -ne $before.Mode -or (@($latest.ServerAddresses) -join ',') -ne (@($before.ServerAddresses) -join ',')) { throw 'DNS/адаптер изменён после создания копии. Изменения отменены.' }
        try {
            Set-DnsClientServerAddress -InputObject $row[0] -ServerAddresses $ServerAddresses -ErrorAction Stop
            $after=Get-AGDnsSnapshot $InterfaceIndex
            if ($after.InterfaceGuid -ne $before.InterfaceGuid -or $after.Mode -ne 'Static' -or (@($after.ServerAddresses) -join ',') -ne ($ServerAddresses -join ',')) { throw 'Назначенные DNS не подтверждены; возможно вмешательство VPN/политики.' }
        } catch {
            $failure=$_.Exception.Message
            try { Set-AGDnsFromSnapshot $before } catch { throw ($failure+'; откат DNS не выполнен: '+$_.Exception.Message+'; копия: '+$backup) }
            throw ($failure+'; прежний режим и IPv4 DNS восстановлены; копия: '+$backup)
        }
        return $backup
    }
}
function Restore-AGDns {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param([Parameter(Mandatory=$true)][string]$BackupPath)
    if(-not $PSCmdlet.ShouldProcess('Локальная конфигурация','Restore-AGDns')){return}
    Invoke-AGExclusiveOperation {
        $resolved=(Resolve-Path -LiteralPath $BackupPath -ErrorAction Stop).Path
        if ((Get-Item -LiteralPath $resolved).Length -gt 1MB) { throw 'Слишком большая копия DNS.' }
        $snapshot=Get-Content -LiteralPath $resolved -Raw -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        if ($snapshot.Kind -ne 'AGOptimizer.IPv4Dns' -or $snapshot.FormatVersion -ne 2 -or $snapshot.ComputerName -ne $env:COMPUTERNAME -or $snapshot.Mode -notin @('Static','DHCP')) { throw 'Копия несовместима или от другого компьютера.' }
        if($snapshot.Mode -eq 'Static'){Test-AGDnsAddresses @($snapshot.ServerAddresses)}
        $guid=[guid]$snapshot.InterfaceGuid
        $adapters=@(Get-NetAdapter -IncludeHidden -ErrorAction Stop | Where-Object { [guid]$_.InterfaceGuid -eq $guid })
        if ($adapters.Count -ne 1) { throw 'Адаптер из копии не найден по GUID.' }
        $before=Get-AGDnsSnapshot $adapters[0].InterfaceIndex
        if (-not (Confirm-Change "Восстановить IPv4 DNS адаптера GUID $guid, режим $($snapshot.Mode)?")) { return $false }
        $undo=Save-AGDnsSnapshot $before
        try { Set-AGDnsFromSnapshot $snapshot }
        catch {
            $failure=$_.Exception.Message
            try { Set-AGDnsFromSnapshot $before } catch { throw ($failure+'; возврат к состоянию до восстановления также не выполнен: '+$_.Exception.Message+'; копия: '+$undo) }
            throw ($failure+'; состояние до восстановления возвращено.')
        }
        Write-Host "IPv4 DNS восстановлены. IPv6 не менялся. Копия состояния до отката: $undo"
        return $true
    }
}
function Remove-AGZapretService {
    [CmdletBinding(SupportsShouldProcess=$true)]param()
    if(-not $PSCmdlet.ShouldProcess('zapret','Удалить службу')){return}
    Invoke-AGExclusiveOperation {
        $svc=Get-Service zapret -ErrorAction SilentlyContinue
        if(-not $svc){throw 'Служба Zapret отсутствует.'}
        if([string]$svc.Status -notin @('Running','Stopped')){throw 'Служба в переходном состоянии; удаление отменено.'}
        $old=Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\zapret' -ErrorAction Stop
        if(-not $old.ImagePath -or $null -eq $old.Start){throw 'Исходные параметры службы недоступны; удаление отменено.'}
        if(Test-AGInteractiveUi){Show-AGTextPages -Title 'Удаление службы Zapret' -Lines @('Zapret перестанет запускаться как служба. Обход через него остановится.','Копия параметров не сохраняет все права и дополнительные настройки службы.','Для установки заново используйте service.bat из установленного Zapret.','Дальше — отдельное подтверждение. Пока ничего не удалено.')}else{
        Write-Warning 'Удаление службы остановит обход. Backup параметров не содержит полный набор прав/триггеров/учётных данных. Для переустановки используйте штатный service.bat.'
        }
        if(-not (Confirm-Change 'Удалить службу Zapret?')){return $false}
        $backup=Get-AGPath ('zapret-service.backup-'+[guid]::NewGuid().ToString('N')+'.json')
        $null=New-Item -ItemType Directory -Path (Split-Path $backup -Parent) -Force -ErrorAction Stop
        $old|Select-Object ImagePath,Start,DelayedAutoStart,'zapret-discord-youtube'|ConvertTo-Json|Set-Content -LiteralPath $backup -Encoding UTF8 -ErrorAction Stop
        $wasRunning=[string]$svc.Status -eq 'Running'
        try {
            Stop-Service zapret -ErrorAction Stop
            $svc.WaitForStatus('Stopped',[timespan]::FromSeconds(15))
            Invoke-ServiceControl -Arguments @('delete','zapret')
        }catch{
            $failure=$_.Exception.Message
            if($wasRunning){
                try{Start-Service zapret -ErrorAction Stop;(Get-Service zapret).WaitForStatus('Running',[timespan]::FromSeconds(15))}
                catch{throw ($failure+'; повторный запуск также не выполнен: '+$_.Exception.Message+'; копия: '+$backup)}
            }
            throw ($failure+'; удаление не подтверждено, проверьте SCM; копия: '+$backup)
        }finally{if($svc -is [IDisposable]){$svc.Dispose()}}
        Write-Host "SCM принял удаление. Служба может быть помечена на удаление до закрытия чужих дескрипторов. Копия: $backup"
        return $true
    }
}

function Get-AGStrictUtf8Text {
    param([Parameter(Mandatory=$true)][string]$Path)
    $bytes=[IO.File]::ReadAllBytes($Path)
    $encoding=New-Object Text.UTF8Encoding($false,$true)
    try{$text=$encoding.GetString($bytes)}catch{throw 'Файл не является корректным UTF-8. Автоперекодирование запрещено; сначала сохраните копию и уточните кодировку.'}
    return $text.TrimStart([char]0xFEFF)
}

function Get-AGTextHash {
    param([AllowEmptyString()][string]$Text)
    $sha=[Security.Cryptography.SHA256]::Create()
    try{return [BitConverter]::ToString($sha.ComputeHash((New-Object Text.UTF8Encoding($false)).GetBytes($Text))).Replace('-','')}finally{$sha.Dispose()}
}
