#Requires -Version 5.1
. "$PSScriptRoot/console-input.ps1"
# AGFixer portable declarative build files. No scripts, executables, credentials or foreign adapter IDs.
function Get-AGBuildComponentLabel {
    param([string]$Component)
    $labels=@{Unlocker='Профиль Unlocker';ZapretStrategy='Стратегия Zapret';ZapretLists='Списки доменов Zapret';VpnDns='IPv4 DNS VPN-адаптера'}
    return $labels[$Component]
}
function Format-AGBuildFlag {param([bool]$Value)if($Value){return 'вкл'}else{return 'выкл'}}
function Assert-AGBuildKeys {
    param($Object,[string[]]$Allowed,[string[]]$Required=@())
    if($null -eq $Object -or $Object -isnot [pscustomobject]){throw 'Ожидался JSON-объект конфига.'}
    foreach($key in @($Object.PSObject.Properties.Name)){if($key -cnotin $Allowed){throw "Неизвестное поле конфига: $key"}}
    foreach($key in $Required){if($key -cnotin @($Object.PSObject.Properties.Name)){throw "Отсутствует поле конфига: $key"}}
}
function Test-AGBuildProxy {
    param([string]$Url)
    $uri=$null
    if($Url.Length -gt 2048 -or $Url -match '[\x00-\x20\x7f]' -or -not [uri]::TryCreate($Url,[UriKind]::Absolute,[ref]$uri) -or $uri.Scheme -notin @('http','https','socks5') -or -not $uri.Host -or $uri.Port -lt 1 -or $uri.UserInfo -or $uri.Query -or $uri.Fragment -or $uri.AbsolutePath -notin @('','/')){throw 'Для конфига нужен HTTP/HTTPS/SOCKS5 URL без пароля, пути, query и fragment.'}
    return $uri
}
function Assert-AGBuildDomain {
    param($Domain)
    if($Domain -isnot [string]){throw 'Запись списка должна быть строкой.'}
    $body=$Domain.TrimStart('^').TrimStart('.')
    if($Domain -notmatch '^\^?\.?[^.^].*$' -or $Domain.Length -gt 255 -or $Domain -match '^\^?\.?.*[\s#;/*:!&|<>]' -or $body -notmatch '^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'){throw 'Список конфига содержит не домен. Допускаются только обычные DNS-имена (IDN — punycode), без команд, URL и wildcard.'}
}
function Assert-AGBuild {
    param($Build)
    Assert-AGBuildKeys $Build @('Kind','FormatVersion','Name','CreatedAt','Components') @('Kind','FormatVersion','Name','CreatedAt','Components')
    if($Build.Kind -cne 'AGFixer.Build' -or ($Build.FormatVersion -isnot [int] -and $Build.FormatVersion -isnot [long]) -or $Build.FormatVersion -ne 1){throw 'Неизвестный формат/версия конфига.'}
    if($Build.Name -isnot [string] -or $Build.Name.Length -lt 1 -or $Build.Name.Length -gt 100 -or $Build.Name -match '[\x00-\x1f\x7f]'){throw 'Неверное имя конфига.'}
    $date=[datetimeoffset]::MinValue
    $dateText=if($Build.CreatedAt -is [datetime]){$Build.CreatedAt.ToUniversalTime().ToString('o')}elseif($Build.CreatedAt -is [datetimeoffset]){$Build.CreatedAt.ToString('o')}elseif($Build.CreatedAt -is [string]){$Build.CreatedAt}else{''}
    if($dateText.Length -gt 64 -or $dateText -match '[\x00-\x1f\x7f]' -or -not [datetimeoffset]::TryParse($dateText,[ref]$date)){throw 'Неверная дата конфига.'}
    Assert-AGBuildKeys $Build.Components @('Unlocker','ZapretStrategy','ZapretLists','VpnDns')
    if(-not @($Build.Components.PSObject.Properties).Count){throw 'В конфиге нет компонентов.'}
    $c=$Build.Components
    if($null -ne $c.Unlocker){
        $fields=@('dns','local_proxy','builtin_exits','group_proxy','own_proxy_enabled')
        Assert-AGBuildKeys $c.Unlocker ($fields+@('ProxyUrl','ProxyNeedsInput')) ($fields+@('ProxyNeedsInput'))
        foreach($field in $fields+@('ProxyNeedsInput')){if($c.Unlocker.$field -isnot [bool]){throw "Переключатель $field должен быть boolean, не строкой/числом."}}
        if($null -ne $c.Unlocker.ProxyUrl){if($c.Unlocker.ProxyUrl -isnot [string]){throw 'ProxyUrl должен быть строкой.'};$null=Test-AGBuildProxy $c.Unlocker.ProxyUrl}
        if($c.Unlocker.own_proxy_enabled -and -not $c.Unlocker.ProxyNeedsInput -and -not $c.Unlocker.ProxyUrl){throw 'Для включённого своего прокси отсутствует URL.'}
    }
    if($null -ne $c.ZapretStrategy){
        Assert-AGBuildKeys $c.ZapretStrategy @('FileName','Sha256') @('FileName','Sha256')
        if($c.ZapretStrategy.FileName -isnot [string] -or $c.ZapretStrategy.FileName -notmatch '^[\p{L}\p{N} _().+-]{1,120}\.bat$' -or $c.ZapretStrategy.FileName -like 'service*' -or $c.ZapretStrategy.Sha256 -isnot [string] -or $c.ZapretStrategy.Sha256 -notmatch '^[a-fA-F0-9]{64}$'){throw 'Неверная ссылка на локальную BAT-стратегию.'}
    }
    if($null -ne $c.ZapretLists){
        Assert-AGBuildKeys $c.ZapretLists @('list-general.txt','list-general-user.txt')
        if(-not @($c.ZapretLists.PSObject.Properties).Count){throw 'Нет поддерживаемых списков Zapret.'}
        foreach($property in $c.ZapretLists.PSObject.Properties){
            if($property.Value -isnot [array] -or $property.Value.Count -gt 10000){throw 'Список доменов должен быть массивом до 10000 элементов.'}
            foreach($domain in $property.Value){Assert-AGBuildDomain $domain}
        }
    }
    if($null -ne $c.VpnDns){
        Assert-AGBuildKeys $c.VpnDns @('Mode','ServerAddresses') @('Mode','ServerAddresses')
        if($c.VpnDns.Mode -cnotin @('DHCP','Static') -or $c.VpnDns.ServerAddresses -isnot [array]){throw 'Неверный режим DNS.'}
        if($c.VpnDns.Mode -eq 'Static'){Test-AGDnsAddresses @($c.VpnDns.ServerAddresses)}elseif($c.VpnDns.ServerAddresses.Count){throw 'DHCP-конфиг не должна переносить полученные адреса DNS.'}
    }
    foreach($property in $c.PSObject.Properties){if($null -eq $property.Value){throw 'Пустой компонент запрещён; исключите его из конфига.'}}
}
function Read-AGBuild {
    param([Parameter(Mandatory=$true)][string]$Path)
    if(-not (Test-Path -LiteralPath $Path -PathType Leaf) -or (Get-Item -LiteralPath $Path).Length -gt 2MB){throw 'Нужен файл конфига размером не более 2 МБ.'}
    $text=Get-AGStrictUtf8Text $Path
    if($text.TrimStart() -notmatch '^\{'){throw 'Конфиг должен содержать JSON-объект.'}
    $build=$text|ConvertFrom-Json -ErrorAction Stop
    Assert-AGBuild $build
    return $build
}
function Write-AGBuild {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param($Build,[Parameter(Mandatory=$true)][string]$Path)
    Assert-AGBuild $Build
    $text=$Build|ConvertTo-Json -Depth 16 -ErrorAction Stop
    if([Text.Encoding]::UTF8.GetByteCount($text) -gt 2MB){throw 'Конфиг превышает 2 МБ.'}
    $full=[IO.Path]::GetFullPath($Path)
    if(Test-Path -LiteralPath $full){throw 'Файл уже существует. Выберите новое имя; перезапись конфигов запрещена.'}
    if(-not $PSCmdlet.ShouldProcess($full,'Сохранение конфига без секретов')){return}
    $temp=Join-Path ([IO.Path]::GetDirectoryName($full)) ([IO.Path]::GetRandomFileName())
    try{
        $stream=[IO.File]::Open($temp,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
        try{$bytes=(New-Object Text.UTF8Encoding($false)).GetBytes($text);$stream.Write($bytes,0,$bytes.Length);$stream.Flush()}finally{$stream.Dispose()}
        [IO.File]::Move($temp,$full) # Fails rather than overwriting a concurrent creator.
    }finally{if(Test-Path -LiteralPath $temp){Remove-Item -LiteralPath $temp -Force -ErrorAction Stop}}
    return $full
}
function Get-AGVpnCandidates {
    return @(Get-NetAdapter -ErrorAction Stop | Where-Object {
        $_.Status -eq 'Up' -and ($_.InterfaceDescription -match 'wireguard|wintun|sing-box|xray|v2ray|openvpn|tap' -or $_.Name -match 'wg|vpn|tun|vless|incy') -and $_.InterfaceDescription -notmatch 'radmin|hamachi|virtualbox|hyper-v'
    })
}
function Read-AGBuildAdapter {
    $adapters=@(Get-AGVpnCandidates)
    if(-not $adapters.Count){throw 'Активный VPN-адаптер не найден. Запустите VPN либо исключите DNS из конфига.'}
    if(Test-AGInteractiveUi){
        $choice=Read-AGListChoice -Title 'Выберите подключение своего VPN' -Options @($adapters|ForEach-Object{"$($_.Name) — $($_.InterfaceDescription)"}) -Intro @('Включите VPN заранее. Выберите его название из списка.','Не уверены? Нажмите Enter: настройки не изменятся.')
        if(-not $choice){return $null};return [int]$adapters[$choice-1].InterfaceIndex
    }
    foreach($a in $adapters){Write-Host "$($a.InterfaceIndex). $($a.Name) — $($a.InterfaceDescription)"}
    $inputText=Read-AGInput 'Индекс ВАШЕГО VPN-адаптера (Enter — отмена)'
    if([string]::IsNullOrWhiteSpace($inputText)){return $null}
    $index=0
    if(-not [int]::TryParse($inputText,[ref]$index) -or $index -notin @($adapters.InterfaceIndex)){throw 'Неверный индекс VPN-адаптера.'}
    return $index
}
function New-AGBuild {
    param([string]$Name,[string[]]$Components,[string]$StrategyFile,[int]$DnsInterfaceIndex=0,[ValidateSet('Current','VPN','Zapret','OwnProxy')][string]$ProfileMode='Current',[string]$ProxyUrl)
    if(-not $Components.Count -or @($Components|Where-Object{$_ -notin @('Unlocker','ZapretStrategy','ZapretLists','VpnDns')}).Count){throw 'Выберите поддерживаемые компоненты.'}
    $c=[ordered]@{}
    if('Unlocker' -in $Components){
        if($ProfileMode -eq 'Current'){$cfg=Read-AGSettings}else{
            $cfg=[pscustomobject]@{dns=($ProfileMode -eq 'Zapret');local_proxy=$true;builtin_exits=$false;group_proxy=$false;own_proxy_enabled=($ProfileMode -eq 'OwnProxy');own_proxy=$ProxyUrl}
            if($ProfileMode -eq 'OwnProxy'){$null=Test-AGBuildProxy $ProxyUrl}
        }
        $u=[ordered]@{}
        foreach($key in @('dns','local_proxy','builtin_exits','group_proxy','own_proxy_enabled')){
            if($cfg.$key -isnot [bool]){throw "В settings.json нет boolean-поля $key. Сохранение не угадывает его значение."};$u[$key]=$cfg.$key
        }
        $u.ProxyNeedsInput=$false
        if($u.own_proxy_enabled){
            # Entire credential-bearing/unsupported URL is withheld, not partially scrubbed.
            try{$null=Test-AGBuildProxy ([string]$cfg.own_proxy);$u.ProxyUrl=[string]$cfg.own_proxy}catch{$u.ProxyNeedsInput=$true}
        }
        $c.Unlocker=[pscustomobject]$u
    }
    if('ZapretStrategy' -in $Components -or 'ZapretLists' -in $Components){$root=Get-ZapretPath}
    if('ZapretStrategy' -in $Components){
        $command=Get-StrategyCommand $root $StrategyFile;Assert-AGStrategyFiles -Command $command
        $c.ZapretStrategy=[pscustomobject]@{FileName=$StrategyFile;Sha256=Get-AGFileHash (Join-Path $root $StrategyFile)}
    }
    if('ZapretLists' -in $Components){
        $lists=[ordered]@{}
        foreach($listName in @('list-general.txt','list-general-user.txt')){
            $path=Join-Path $root ('lists/'+$listName)
            if(-not (Test-Path -LiteralPath $path -PathType Leaf)){continue}
            if((Get-Item -LiteralPath $path).Length -gt 1MB){throw 'Слишком большой список Zapret.'}
            $domains=@(Read-AGBuildDomains -Path $path)
            $lists[$listName]=@($domains|Select-Object -Unique)
        }
        $c.ZapretLists=[pscustomobject]$lists
    }
    if('VpnDns' -in $Components){
        if($DnsInterfaceIndex -notin @((Get-AGVpnCandidates).InterfaceIndex)){throw 'Для сохранения DNS выберите активный VPN-адаптер.'}
        $snap=Get-AGDnsSnapshot $DnsInterfaceIndex
        $addresses=if($snap.Mode -eq 'Static'){@($snap.ServerAddresses)}else{@()}
        $c.VpnDns=[pscustomobject]@{Mode=$snap.Mode;ServerAddresses=@($addresses)}
    }
    $build=[pscustomobject]@{Kind='AGFixer.Build';FormatVersion=1;Name=$Name;CreatedAt=[datetimeoffset]::UtcNow.ToString('o');Components=[pscustomobject]$c}
    Assert-AGBuild $build;return $build
}
function Show-AGBuild {
    param($Build,[switch]$Paged)
    if($Paged){
        Assert-AGBuild $Build
        $lines=@("Название: $($Build.Name)","Создан: $($Build.CreatedAt)")
        $c=$Build.Components
        if($c.Unlocker){
            $labels=@{dns='Обработка DNS через Unlocker';local_proxy='Локальный прокси Unlocker';builtin_exits='Встроенные способы подключения';group_proxy='Прокси из группы';own_proxy_enabled='Свой прокси'}
            foreach($key in @('dns','local_proxy','builtin_exits','group_proxy','own_proxy_enabled')){$lines+="$($labels[$key]): $(Format-AGBuildFlag $c.Unlocker.$key)"}
            if($c.Unlocker.ProxyUrl){$lines+='Адрес своего прокси: '+$c.Unlocker.ProxyUrl}
            if($c.Unlocker.ProxyNeedsInput){$lines+='Адрес прокси не сохранён: при загрузке нужно указать свой.'}
        }
        if($c.ZapretStrategy){$lines+='Zapret: '+$c.ZapretStrategy.FileName;$lines+='На этом ПК нужен такой же файл стратегии. Программа проверит его содержимое. Сам Zapret в конфиг не входит.'}
        if($c.ZapretLists){foreach($item in $c.ZapretLists.PSObject.Properties){$lines+="Список сайтов $($item.Name): $(@($item.Value).Count) записей";foreach($domain in @($item.Value)){$lines+='  '+$domain}}}
        if($c.VpnDns){$lines+='DNS VPN: '+$c.VpnDns.Mode+' '+(@($c.VpnDns.ServerAddresses) -join ', ');$lines+='Подключение VPN нужно выбрать на этом компьютере.'}
        $lines+='Аккаунты, пароли, VPN-приложения и история чатов не переносятся.'
        Show-AGTextPages -Title 'Что находится в конфиге?' -Lines $lines
        return
    }
    Assert-AGBuild $Build
    Write-Host "Конфиг: $($Build.Name) | формат 1 | $($Build.CreatedAt)" -ForegroundColor Cyan
    $c=$Build.Components
    if($c.Unlocker){
        $u=$c.Unlocker
        Write-Host "Unlocker: DNS-перехват=$(Format-AGBuildFlag $u.dns); локальный прокси=$(Format-AGBuildFlag $u.local_proxy); встроенные маршруты=$(Format-AGBuildFlag $u.builtin_exits); групповой=$(Format-AGBuildFlag $u.group_proxy); свой=$(Format-AGBuildFlag $u.own_proxy_enabled)"
        if($u.ProxyUrl){Write-Host "Адрес своего прокси (без пароля): $($u.ProxyUrl)"}
        if($u.ProxyNeedsInput){Write-Warning 'Адрес прокси скрыт: для загрузки нужен свой URL без реквизитов.'}
    }
    if($c.ZapretStrategy){Write-Host "Zapret: $($c.ZapretStrategy.FileName); нужен локальный файл с тем же SHA-256. Сам BAT/EXE не переносится."}
    if($c.ZapretLists){foreach($item in $c.ZapretLists.PSObject.Properties){Write-Host "Список $($item.Name): $(@($item.Value).Count) доменов"; Write-Host ('  Первые 10: '+(@($item.Value|Select-Object -First 10) -join ', '))}}
    if($c.VpnDns){Write-Host "IPv4 DNS VPN: $($c.VpnDns.Mode) $(@($c.VpnDns.ServerAddresses) -join ', '); адаптер выбирается на этом ПК."}
    Write-Host 'Не переносит аккаунты, ключи, драйверы, VPN-конфиги/TUN-маршруты, настройки TLS/патчера и историю IDE.'
}
function Assert-AGBuildTargetFile {
    param([string]$Path)
    if(-not (Test-Path -LiteralPath $Path -PathType Leaf)){throw "Нет целевого файла: $Path. Автосоздание списков/стратегий запрещено."}
    $item=Get-Item -LiteralPath $Path -ErrorAction Stop
    while($null -ne $item){
        if(($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'Reparse point/symlink в пути загрузки запрещён.'}
        $item=if($item -is [IO.FileInfo]){$item.Directory}else{$item.Parent}
    }
}
function Get-AGBuildPlan {
    param($Build,[string[]]$Components,[int]$DnsInterfaceIndex=0,[string]$ProxyUrl,[ValidateSet('Merge','Replace')][string]$ListMode='Merge')
    Assert-AGBuild $Build
    if(-not $Components.Count -or @($Components|Select-Object -Unique).Count -ne $Components.Count){throw 'Нужен непустой выбор без повторов.'}
    foreach($name in $Components){if($name -cnotin @($Build.Components.PSObject.Properties.Name)){throw "Компонент отсутствует в конфиге: $name"}}
    $plan=[pscustomobject]@{Build=$Build;Components=@($Components);SettingsHash=$null;ProxyUrl=$null;Lists=@();ListMode=$ListMode;StrategyHash=$null;StrategyRoot=$null;DnsBefore=$null}
    if('Unlocker' -in $Components){
        $path=Get-AGPath 'settings.json';Assert-AGBuildTargetFile $path;$null=Read-AGSettings;$plan.SettingsHash=Get-AGFileHash $path
        $u=$Build.Components.Unlocker
        if($u.own_proxy_enabled){$url=if($ProxyUrl){$ProxyUrl}elseif(-not $u.ProxyNeedsInput){$u.ProxyUrl}else{''};$null=Test-AGBuildProxy $url;$plan.ProxyUrl=$url}
    }
    if('ZapretStrategy' -in $Components -or 'ZapretLists' -in $Components){$root=Get-ZapretPath;$plan.StrategyRoot=$root}
    if('ZapretStrategy' -in $Components){
        $s=$Build.Components.ZapretStrategy;$path=Join-Path $root $s.FileName;Assert-AGBuildTargetFile $path
        $plan.StrategyHash=Get-AGFileHash $path
        if($plan.StrategyHash -ne $s.Sha256){throw 'Локальная стратегия не совпадает с конфигом по SHA-256. Ничего не применено; установите нужную версию Zapret отдельно.'}
        $command=Get-StrategyCommand $root $s.FileName;Assert-AGStrategyFiles -Command $command
    }
    if('ZapretLists' -in $Components){
        foreach($list in $Build.Components.ZapretLists.PSObject.Properties){
            $path=Join-Path $root ('lists/'+$list.Name);Assert-AGBuildTargetFile $path
            if((Get-Item -LiteralPath $path).Length -gt 2MB){throw 'Слишком большой целевой список.'}
            $hash=Get-AGFileHash $path;$old=Get-AGStrictUtf8Text $path
            if($ListMode -eq 'Replace'){$text=(@($list.Value) -join "`r`n")+"`r`n"}
            else{
                $lines=@($old -split '\r?\n'|ForEach-Object{$_.Trim()});$missing=@($list.Value|Where-Object{$_ -notin $lines})
                $text=$old
                if($missing.Count){if($text -and -not $text.EndsWith("`n")){$text+="`r`n"};$text+=($missing -join "`r`n")+"`r`n"}
            }
            if([Text.Encoding]::UTF8.GetByteCount($text) -gt 3MB){throw 'Итоговый список слишком большой.'}
            $plan.Lists+= [pscustomobject]@{Path=$path;Hash=$hash;Text=$text;AppliedHash=Get-AGTextHash $text;Backup=$null}
        }
        $svc=Get-Service zapret -ErrorAction SilentlyContinue
        if($svc -and [string]$svc.Status -notin @('Running','Stopped')){throw 'Zapret в переходном состоянии.'}
    }
    if('VpnDns' -in $Components){
        if($DnsInterfaceIndex -notin @((Get-AGVpnCandidates).InterfaceIndex)){throw 'Для загрузки DNS выберите активный VPN-адаптер на этом ПК.'}
        $plan.DnsBefore=Get-AGDnsSnapshot $DnsInterfaceIndex
        if(-not $plan.DnsBefore.ComputerName){throw 'COMPUTERNAME не определён.'}
    }
    return $plan
}
function Set-AGBuildUnlocker {
    param($Plan)
    Invoke-AGExclusiveOperation {
        $path=Get-AGPath 'settings.json';Assert-AGBuildTargetFile $path
        if((Get-AGFileHash $path) -ne $Plan.SettingsHash){throw 'Настройки изменились после предварительного просмотра. Загрузка отменена.'}
        $cfg=Read-AGSettings;$u=$Plan.Build.Components.Unlocker
        foreach($key in @('dns','local_proxy','builtin_exits','group_proxy','own_proxy_enabled')){$cfg|Add-Member -NotePropertyName $key -NotePropertyValue $u.$key -Force}
        if($u.own_proxy_enabled){$cfg|Add-Member -NotePropertyName own_proxy -NotePropertyValue $Plan.ProxyUrl -Force}
        return Write-AGAtomicText -Path $path -Text ($cfg|ConvertTo-Json -Depth 100) -ExpectedHash $Plan.SettingsHash
    }
}
function Set-AGBuildLists {
    param($Plan)
    Invoke-AGExclusiveOperation {
        foreach($entry in $Plan.Lists){Assert-AGBuildTargetFile $entry.Path;if((Get-AGFileHash $entry.Path) -ne $entry.Hash){throw 'Списки изменились после просмотра; загрузка отменена.'}}
        $svc=Get-Service zapret -ErrorAction SilentlyContinue
        if($svc -and [string]$svc.Status -notin @('Running','Stopped')){throw 'Служба в переходном состоянии.'}
        $running=$svc -and [string]$svc.Status -eq 'Running'
        try{
            foreach($entry in $Plan.Lists){
                if($entry.Hash -ne $entry.AppliedHash){$entry.Backup=Write-AGAtomicText -Path $entry.Path -Text $entry.Text -ExpectedHash $entry.Hash}
            }
            if($running -and @($Plan.Lists|Where-Object{$_.Backup}).Count){Restart-Service zapret -ErrorAction Stop;(Get-Service zapret).WaitForStatus('Running',[timespan]::FromSeconds(15))}
        }catch{
            $failure=$_.Exception.Message;$errors=@()
            foreach($entry in @($Plan.Lists|Sort-Object Path -Descending)){if($entry.Backup){try{Restore-AGFileBytes -Path $entry.Path -Backup $entry.Backup -ExpectedHash $entry.AppliedHash -BackupHash $entry.Hash}catch{$errors+=$_.Exception.Message}}}
            if($running){try{Restart-Service zapret -ErrorAction Stop;(Get-Service zapret).WaitForStatus('Running',[timespan]::FromSeconds(15))}catch{$errors+=$_.Exception.Message}}
            if($errors.Count){throw ($failure+'; откат списков неполный: '+($errors -join '; '))};throw ($failure+'; изменения списков возвращены.')
        }
        return @($Plan.Lists|Where-Object{$_.Backup}|ForEach-Object{$_.Backup})
    }
}
function Set-AGBuildDns {
    param($Plan)
    Invoke-AGExclusiveOperation {
        $before=$Plan.DnsBefore;$now=Get-AGDnsSnapshot $before.InterfaceIndex
        if($now.InterfaceGuid -ne $before.InterfaceGuid -or $now.Mode -ne $before.Mode -or (@($now.ServerAddresses) -join ',') -ne (@($before.ServerAddresses) -join ',')){throw 'Адаптер/DNS изменился после просмотра; загрузка отменена.'}
        $backup=Save-AGDnsSnapshot $before
        $desired=$before.PSObject.Copy();$desired.Mode=$Plan.Build.Components.VpnDns.Mode;$desired.ServerAddresses=@($Plan.Build.Components.VpnDns.ServerAddresses)
        try{Set-AGDnsFromSnapshot $desired}catch{
            $failure=$_.Exception.Message
            try{Set-AGDnsFromSnapshot $before}catch{throw ($failure+'; откат DNS не выполнен: '+$_.Exception.Message+'; копия: '+$backup)}
            throw ($failure+'; DNS возвращён; копия: '+$backup)
        }
        return $backup
    }
}
function Import-AGBuild {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param($Build,[string[]]$Components,[int]$DnsInterfaceIndex=0,[string]$ProxyUrl,[ValidateSet('Merge','Replace')][string]$ListMode='Merge')
    # Preflight every selected component before the first change. No partial preflight application.
    $plan=Get-AGBuildPlan -Build $Build -Components $Components -DnsInterfaceIndex $DnsInterfaceIndex -ProxyUrl $ProxyUrl -ListMode $ListMode
    if(Test-AGInteractiveUi){
        $review=@('Будут изменены только отмеченные настройки:')
        foreach($component in $Components){$review+='- '+(Get-AGBuildComponentLabel $component)}
        if('ZapretLists' -in $Components){$review+='Списки сайтов: '+$(if($ListMode -eq 'Merge'){'добавить новые записи, сохранить ваши'}else{'заменить целиком; ваши записи уберутся, будет копия'})}
        if($plan.ProxyUrl){$review+='Адрес прокси: '+$plan.ProxyUrl}
        if($plan.DnsBefore){$review+='Подключение VPN: '+$plan.DnsBefore.InterfaceAlias+'; индекс '+$plan.DnsBefore.InterfaceIndex}
        $review+='Сначала закройте окно Unlocker.'
        $review+='Загрузка идёт по шагам. Если один шаг завершится ошибкой, предыдущие успешные шаги не отменятся автоматически.'
        $review+='Сеть или служба могут перезапуститься. Резервные копии содержат прежние личные настройки: не публикуйте их.'
        $review+='На следующем экране будет отдельное подтверждение. Пока ничего не изменено.'
        Show-AGTextPages -Title 'Проверьте изменения перед загрузкой' -Lines $review
    }else{
    Show-AGBuild $Build
    Write-Host ('Будут применены ТОЛЬКО: '+(@($Components|ForEach-Object{Get-AGBuildComponentLabel $_}) -join ', ')) -ForegroundColor Yellow
    if('ZapretLists' -in $Components){Write-Host "Списки: $(if($ListMode -eq 'Merge'){'добавить из конфига, сохранить свои'}else{'заменить целиком'})."}
    if($plan.ProxyUrl){Write-Host "Будет использован адрес прокси: $($plan.ProxyUrl)"}
    if($plan.DnsBefore){Write-Host "Целевой VPN: индекс $($plan.DnsBefore.InterfaceIndex), GUID $($plan.DnsBefore.InterfaceGuid)"}
    Write-Warning 'Закройте окно Unlocker. Загрузка поэтапная, не общая транзакция: при ошибке остановится; уже успешные компоненты сохранятся. Служба/сеть могут перезапуститься. Копии содержат прежние приватные настройки.'
    }
    if(-not $PSCmdlet.ShouldProcess($Build.Name,'Применить выбранные компоненты конфига')){return}
    if(-not (Confirm-Change 'Применить выбранные компоненты?')){return $null}
    $folder=Join-Path $env:LOCALAPPDATA 'AGFixer/imports';$null=New-Item -ItemType Directory -Path $folder -Force -ErrorAction Stop
    $journalPath=Join-Path $folder ('import-'+[guid]::NewGuid().ToString('N')+'.json')
    $journal=[pscustomobject]@{Kind='AGFixer.ImportJournal';CreatedAt=[datetimeoffset]::UtcNow.ToString('o');State='Running';Selected=@($Components);Results=@()}
    # Journal has component names/backup paths only; never URLs, settings, commands or raw errors.
    $save={ $json=$journal|ConvertTo-Json -Depth 8;$tmp=$journalPath+'.tmp';try{[IO.File]::WriteAllText($tmp,$json,(New-Object Text.UTF8Encoding($false)));if(Test-Path -LiteralPath $journalPath){[IO.File]::Replace($tmp,$journalPath,[System.Management.Automation.Language.NullString]::Value)}else{[IO.File]::Move($tmp,$journalPath)}}finally{if(Test-Path -LiteralPath $tmp){Remove-Item -LiteralPath $tmp -Force -ErrorAction Stop}} }
    & $save
    foreach($component in @('Unlocker','ZapretLists','ZapretStrategy','VpnDns')){
        if($component -notin $Components){continue}
        $result=[pscustomobject]@{Component=$component;Status='Started';Backups=@()};$journal.Results+= $result
        & $save # A crash after this point leaves the operation explicitly indeterminate.
        try{
            switch($component){
                'Unlocker' {$result.Backups=@(Set-AGBuildUnlocker $plan)}
                'ZapretLists' {$result.Backups=@(Set-AGBuildLists $plan)}
                'ZapretStrategy' {
                    $applied=Invoke-AGExclusiveOperation {
                        if((Get-ZapretPath) -ne $plan.StrategyRoot){throw 'Папка Zapret изменилась; повторите загрузку.'}
                        $path=Join-Path $plan.StrategyRoot $Build.Components.ZapretStrategy.FileName;Assert-AGBuildTargetFile $path
                        if((Get-AGFileHash $path) -ne $plan.StrategyHash){throw 'Стратегия изменилась после просмотра.'}
                        Invoke-UnlockedInstall-ZapretService -StrategyBatName $Build.Components.ZapretStrategy.FileName
                    }
                    if(-not $applied){$result.Status='Cancelled';$journal.State='Stopped';& $save;Write-Warning 'Применение стратегии отменено. Уже выполненные компоненты не отменялись.';return $journalPath}
                }
                'VpnDns' {$result.Backups=@(Set-AGBuildDns $plan)}
            }
            $result.Status='Applied';& $save;Write-Host "[ГОТОВО] $(Get-AGBuildComponentLabel $component)" -ForegroundColor Green
        }catch{
            $result.Status='FailedOrNeedsReview';$journal.State='Stopped';try{& $save}catch{Write-Warning 'Журнал не обновился; проверьте состояние вручную.'}
            Write-Warning "Загрузка остановлена на $component. Ранее успешные компоненты НЕ отменены. Журнал: $journalPath"
            throw
        }
    }
    $journal.State='Completed';& $save
    Write-Host "Загрузка завершена. Журнал и пути копий: $journalPath"
    if('Unlocker' -in $Components){Write-Host 'Профиль сохранён. Перезапуск Unlocker — отдельный пункт «Исправления → Unlocker → Перезапустить маршрутизацию».'}
    return $journalPath
}

function Read-AGBuildDomains {
    param([string]$Path)
    $number=0
    foreach($raw in @((Get-AGStrictUtf8Text $Path) -split '\r?\n')){
        $number++;$entry=($raw -split '#',2)[0].Trim().TrimStart([char]0xfeff)
        if(-not $entry){continue}
        $prefix='';$body=$entry
        if($body.StartsWith('^')){$prefix='^';$body=$body.Substring(1)}
        if($body.StartsWith('.')){$prefix+='.';$body=$body.Substring(1)}
        try{
            $ascii=(New-Object Globalization.IdnMapping).GetAscii($body.TrimEnd('.')).ToLowerInvariant()
            $normalized=$prefix+$ascii;Assert-AGBuildDomain $normalized
            $normalized
        }catch{
            $sample=[regex]::Replace($entry,'[\p{Cc}\p{Cf}]','?');if($sample.Length -gt 100){$sample=$sample.Substring(0,100)+'...'}
            throw "СПИСОК: $Path, строка ${number}: [$sample]. Неизвестная запись; файл не изменён."
        }
    }
}
