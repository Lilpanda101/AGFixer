#Requires -Version 5.1
# Typed allowlisted operations only. Report text is never passed to Invoke-Expression.
function Get-AGRepairFingerprint {
    param($Value)
    $text=ConvertTo-Json -InputObject $Value -Depth 30 -Compress
    $hash=[Security.Cryptography.SHA256]::Create()
    try{return ([BitConverter]::ToString($hash.ComputeHash([Text.Encoding]::UTF8.GetBytes($text)))).Replace('-','')}finally{$hash.Dispose()}
}
function Get-AGRepairProxyPorts {
    param([string]$Server)
    if(-not $Server -or $Server -match '[\x00-\x20@/?#]'){return @()}
    $ports=@()
    foreach($binding in @($Server -split ';')){
        $value=$binding -replace '^(?i:http|https|socks)=',''
        $m=[regex]::Match($value,'^(?<h>127(?:\.\d{1,3}){3}|localhost|\[::1\]):(?<p>\d{1,5})$','IgnoreCase')
        if(-not $m.Success){return @()}
        if($m.Groups['h'].Value -match '^127\.' -and @($m.Groups['h'].Value.Split('.')|Where-Object{[int]$_ -gt 255}).Count){return @()}
        $number=[int]$m.Groups['p'].Value
        if($number -lt 1 -or $number -gt 65535){return @()}
        $ports+=$number
    }
    return @($ports|Sort-Object -Unique)
}
function Read-AGRepairRegistry {
    param([ValidateSet('HKCU','HKLM')][string]$Scope)
    $path=$Scope+':\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
    $policy=Test-Path -LiteralPath ($Scope+':\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings')
    $entries=@();$server='';$pac='';$enabled=$false
    if(Test-Path -LiteralPath $path){
        $key=Get-Item -LiteralPath $path -ErrorAction Stop
        foreach($name in @('ProxyServer','ProxyEnable','ProxyOverride','AutoConfigURL')){
            $exists=$name -in @($key.GetValueNames());$value=$null;$kind='String'
            if($exists){$value=$key.GetValue($name,$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames);$kind=[string]$key.GetValueKind($name)}
            $entries+=[pscustomobject]@{Name=$name;Exists=$exists;Value=$value;Kind=$kind}
            switch($name){'ProxyServer'{$server=[string]$value}'ProxyEnable'{$enabled=($value -eq 1)}'AutoConfigURL'{$pac=[string]$value}}
        }
    }
    return [pscustomobject]@{Scope=$Scope;Path=$path;Entries=$entries;Server=$server;Enabled=$enabled;PAC=$pac;Managed=[bool]$policy}
}
function Test-AGRepairNrptRule {
    param($Rule)
    $allowed=@('googleapis.com','.googleapis.com','cloudcode-pa.googleapis.com','.cloudcode-pa.googleapis.com','daily-cloudcode-pa.googleapis.com','.daily-cloudcode-pa.googleapis.com','generativelanguage.googleapis.com','.generativelanguage.googleapis.com','antigravity-unleash.goog','.antigravity-unleash.goog')
    $spaces=@($Rule.Namespace)
    if(-not $Rule.Name -or -not $spaces.Count -or @($spaces|Where-Object{$_ -notin $allowed}).Count){return $false}
    $servers=@(foreach($value in @($Rule.NameServers)){([string]$value -split '[,;\s]+'|Where-Object{$_})})
    if('127.0.0.53' -notin $servers){return $false}
    $owned=[string]$Rule.Comment -match '(?i)Antigravity|AG\s*Unlocker|ag_dns'
    if(-not $owned -and @($servers|Where-Object{$_ -ne '127.0.0.53'}).Count){return $false}
    # Advanced security/DirectAccess rules are not a simple Unlocker DNS override.
    foreach($p in $Rule.PSObject.Properties){
        if($p.Name -match '^(DA|DirectAccess|DnsSec|IPsec)' -and $null -ne $p.Value -and [string]$p.Value -notin @('','False','0','None','NoProxy','UseDefault')){return $false}
    }
    return $true
}
function Get-AGRepairNrptShape {
    param($Rule)
    $obj=[ordered]@{}
    foreach($p in @($Rule.PSObject.Properties|Where-Object{$_.Name -notmatch '^(Cim|PS)'}|Sort-Object Name)){$obj[$p.Name]=$p.Value}
    return [pscustomobject]$obj
}
function Get-AGRepairSnapshot {
    param([switch]$IncludeClipboard)
    if($env:OS -ne 'Windows_NT'){throw 'Экспресс-аудит запускается на Windows.'}
    $issues=New-Object 'System.Collections.Generic.List[string]'
    $listeners=$null
    try{$listeners=@(Get-NetTCPConnection -State Listen -ErrorAction Stop)}catch{$issues.Add('Владельцы портов не проверены; системный прокси не удаляем.')}
    $proxies=@();$running=$false
    foreach($scope in @('HKCU','HKLM')){
        try{
            $state=Read-AGRepairRegistry $scope
            $ports=@(Get-AGRepairProxyPorts $state.Server)
            $active=$false
            if($null -ne $listeners){$active=@($listeners|Where-Object{$_.LocalPort -in $ports -and $_.LocalAddress -match '^(127\.|::ffff:127\.|0\.0\.0\.0$|::$|::1$)'}).Count -gt 0}
            if($state.Server -and $active){$running=$true}
            $eligible=$state.Server -and $ports.Count -gt 0 -and $null -ne $listeners -and -not $active -and -not $state.PAC -and -not $state.Managed
            $proxies+=[pscustomobject]@{Scope=$scope;Server=$state.Server;Eligible=[bool]$eligible;Active=$active;State=$state;Fingerprint=(Get-AGRepairFingerprint $state)}
        }catch{$issues.Add("Не прочитан $scope proxy; эту область не меняем.")}
    }
    $nrpt=@();$nrptKnown=$false
    try{$nrpt=@(Get-DnsClientNrptRule -ErrorAction Stop|Where-Object{Test-AGRepairNrptRule $_}|ForEach-Object{Get-AGRepairNrptShape $_});$nrptKnown=$true}catch{$issues.Add('NRPT недоступен; правила DNS не меняем.')}
    $processes=@();try{$processes=@(Get-Process -Name 'Antigravity*','AGUnlocker','language_server*','agy','ag_dns','winws' -ErrorAction SilentlyContinue|Select-Object ProcessName,Id,Path)}catch{$issues.Add('Процессы не проверены.')}
    $settingsHash='';try{$settingsHash=Get-AGFileHash (Get-AGPath 'settings.json')}catch{}
    $report=''
    if($IncludeClipboard){try{$text=Get-Clipboard -Raw -ErrorAction Stop;if($text -is [string] -and $text.Length -le 10MB -and $text -match '(?im)^Antigravity Unlocker\s+v[0-9]'){$report=$text};$text=$null}catch{$issues.Add('Буфер обмена недоступен.')}}
    return [pscustomobject]@{At=[datetime]::UtcNow.ToString('o');Proxies=$proxies;ProxyRunning=$running;Nrpt=$nrpt;NrptKnown=$nrptKnown;Processes=$processes;SettingsHash=$settingsHash;ClipboardReport=$report;Issues=@($issues.ToArray())}
}
function Test-AGRepairRestart {
    foreach($name in @('AG Unlocker DNS','AG Unlocker Watchdog')){
        $task=Get-ScheduledTask -TaskName $name -TaskPath '\' -ErrorAction Stop
        if(-not $task -or [string]$task.State -eq 'Disabled'){throw "Задача $name недоступна или отключена."}
    }
    $null=Assert-AGUnlockerRuntime
}
function Get-AGRepairZapretLists {
    param([string]$Root)
    $rows=@()
    . "$PSScriptRoot/zapret-lists.ps1"
    foreach($file in @(Get-AGZapretListFiles $Root)){
        $null=Get-AGStrictUtf8Text $file.FullName
        $rows+=[pscustomobject]@{Path=$file.FullName;Hash=(Get-AGFileHash $file.FullName)}
    }
    return $rows
}
function Test-AGVpnProfileConfigured {
    param([string]$ExpectedHash)
    # A matching, stable file and five actual booleans are required; unknown is not configured.
    if(-not $ExpectedHash){return $false}
    try{
        $path=Get-AGPath 'settings.json'
        if((Get-AGFileHash $path) -ne $ExpectedHash){return $false}
        $settings=Read-AGSettings
        if((Get-AGFileHash $path) -ne $ExpectedHash){return $false}
        foreach($name in @('dns','local_proxy','builtin_exits','group_proxy','own_proxy_enabled')){
            if($settings.$name -isnot [bool] -or $settings.$name){return $false}
        }
        return $true
    }catch{return $false}
}
function New-AGAutoRepairPlan {
    param($Snapshot,$Analysis,[ValidateSet('Keep','VpnDirect','Zapret')][string]$Mode='Keep',[switch]$Deep,[switch]$IncludeMachineProxy,[string]$StrategyFile)
    $steps=New-Object 'System.Collections.Generic.List[object]';$blocked=New-Object 'System.Collections.Generic.List[string]'
    $actions=@();if($Analysis -and $Analysis.Diagnosis){$actions=@($Analysis.Diagnosis.Actions)}
    foreach($proxy in @($Snapshot.Proxies)){
        if($proxy.Eligible -and ($proxy.Scope -eq 'HKCU' -or $IncludeMachineProxy)){$steps.Add([pscustomobject]@{Id='Proxy';Label="Убрать $($proxy.Scope)-прокси без слушателя: $($proxy.Server)";Target=$proxy.Scope;Fingerprint=$proxy.Fingerprint})}
        elseif($proxy.Server){$blocked.Add("$($proxy.Scope): действующий, управляемый или не выбранный системный прокси.")}
    }
    $dnsOnly=$Mode -eq 'Keep' -and ('Nrpt' -in $actions -or ($Deep -and @($Snapshot.Nrpt).Count))
    if($dnsOnly){
        if(-not $Snapshot.SettingsHash){throw 'Не найдены настройки Unlocker: нельзя отключить DNS-обход перед очисткой NRPT.'}
        Test-AGRepairRestart
        $steps.Add([pscustomobject]@{Id='DnsBypassOff';Label='Выключить DNS-обход в настройках Unlocker';Target='dns';Fingerprint=$Snapshot.SettingsHash})
    }
    if($Mode -eq 'VpnDirect' -or 'Nrpt' -in $actions -or $Deep){
        foreach($rule in @($Snapshot.Nrpt)){$steps.Add([pscustomobject]@{Id='Nrpt';Label=('Убрать NRPT: '+(@($rule.Namespace) -join ', '));Target=[string]$rule.Name;Fingerprint=(Get-AGRepairFingerprint $rule)})}
        if(-not $Snapshot.NrptKnown){$blocked.Add('NRPT не прочитан. Автоудаления правил не будет.')}
    }
    $profileMatches=$Mode -eq 'VpnDirect' -and (Test-AGVpnProfileConfigured -ExpectedHash $Snapshot.SettingsHash)
    $strategyHash='';$root=''
    if($Mode -ne 'Keep'){
        if(-not $Snapshot.SettingsHash){throw 'Настройки Unlocker не найдены/не читаются. Установите Unlocker перед настройкой профиля.'}
        if(-not $profileMatches){Test-AGRepairRestart}
        if($Mode -eq 'Zapret'){
            if([string]::IsNullOrWhiteSpace($StrategyFile)){throw 'Выберите установленную стратегию Zapret перед просмотром плана.'}
            $root=Get-ZapretPath;$command=Get-StrategyCommand $root $StrategyFile;Assert-AGStrategyFiles $command
            if(-not(Test-Path -LiteralPath (Join-Path $root 'lists/list-general.txt') -PathType Leaf)){throw 'Zapret: нет lists/list-general.txt. Стратегия не будет применена.'}
            $listState=@(Get-AGRepairZapretLists $root)
            $steps.Add([pscustomobject]@{Id='ZapretDomains';Label=('Добавить домены Antigravity в списки: '+$root);Target=$root;Fingerprint=(Get-AGRepairFingerprint $listState)})
            $strategyHash=Get-AGRepairFingerprint ([pscustomobject]@{Root=$root;Command=$command;Hash=(Get-AGFileHash (Join-Path $root $StrategyFile))})
            $steps.Add([pscustomobject]@{Id='Zapret';Label=('Применить Zapret '+$StrategyFile+' из '+$root);Target=$root;Fingerprint=$strategyHash})
        }
        if(-not $profileMatches){$steps.Add([pscustomobject]@{Id='Profile';Label=('Сохранить профиль Unlocker: '+$Mode);Target=$Mode;Fingerprint=$Snapshot.SettingsHash})}
    }
    if($Deep){$steps.Add([pscustomobject]@{Id='WinHttp';Label='Сбросить WinHTTP на всей машине (может отключить прокси других программ)';Target='Machine';Fingerprint=''})}
    if(($Mode -ne 'Keep' -and (-not $profileMatches -or $steps.Count -gt 0)) -or $dnsOnly -or 'Restart' -in $actions){
        Test-AGRepairRestart
        $steps.Add([pscustomobject]@{Id='Restart';Label='Перезапустить Unlocker (gate.json — с резервной копией)';Target='KnownUnlockerTasks';Fingerprint=(Get-AGUnlockerRuntime)})
    }
    if($steps.Count -or $Deep){$steps.Add([pscustomobject]@{Id='FlushDns';Label='Очистить кэш DNS Windows';Target='Windows';Fingerprint=''})}
    if($Deep -and $env:APPDATA){
        $cache=Join-Path $env:APPDATA 'Antigravity/GPUCache'
        if(Test-Path -LiteralPath $cache -PathType Container){$steps.Add([pscustomobject]@{Id='GpuCache';Label='Переместить только GPUCache Antigravity в резервную папку';Target=$cache;Fingerprint=''})}
    }
    $label=switch($Mode){'VpnDirect'{'Свой VPN/TUN, без локального прокси Unlocker'}'Zapret'{'Zapret: '+$StrategyFile+' + Unlocker'}default{if($Deep){'Глубокая очистка выбранных сетевых хвостов'}else{'Исправление подтверждённых локальных настроек'}}}
    return [pscustomobject]@{Kind='AGFixer.RepairPlan';Configured=[bool]($profileMatches -and $Snapshot.NrptKnown -and $steps.Count -eq 0 -and $blocked.Count -eq 0);Mode=$Mode;Deep=[bool]$Deep;IncludeMachineProxy=[bool]$IncludeMachineProxy;Label=$label;Steps=@($steps.ToArray());Blocked=@($blocked.ToArray());Snapshot=$Snapshot;Analysis=$Analysis;StrategyRoot=$root;StrategyFile=$StrategyFile}
}
function Invoke-AGRepairNetsh {
    param([ValidateSet('Dump','Reset')][string]$Action)
    $info=New-Object Diagnostics.ProcessStartInfo
    $info.FileName=Join-Path $env:SystemRoot 'System32/netsh.exe'
    $info.Arguments=if($Action -eq 'Dump'){'winhttp dump'}else{'winhttp reset proxy'}
    $info.UseShellExecute=$false;$info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true;$info.CreateNoWindow=$true
    $p=New-Object Diagnostics.Process;$p.StartInfo=$info
    try{
        $null=$p.Start();$out=$p.StandardOutput.ReadToEndAsync();$err=$p.StandardError.ReadToEndAsync()
        if(-not $p.WaitForExit(15000)){$p.Kill();throw 'Тайм-аут netsh. Проверьте WinHTTP вручную.'}
        if($p.ExitCode -ne 0){throw ('netsh завершился с кодом '+$p.ExitCode)}
        return $out.GetAwaiter().GetResult()
    }finally{$p.Dispose()}
}
function Restore-AGRepairRegistryState {
    param($State)
    foreach($entry in @($State.Entries|Where-Object{$_.Name -in @('ProxyServer','ProxyEnable')})){
        if($entry.Exists){$null=New-ItemProperty -LiteralPath $State.Path -Name $entry.Name -Value $entry.Value -PropertyType $entry.Kind -Force -ErrorAction Stop}
        else{if($entry.Name -in @((Get-Item -LiteralPath $State.Path -ErrorAction Stop).GetValueNames())){Remove-ItemProperty -LiteralPath $State.Path -Name $entry.Name -ErrorAction Stop}}
    }
}
function Update-AGRepairWinInet {
    if(-not ('AGFixer.WinInetRefresh' -as [type])){
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
namespace AGFixer {
 public static class WinInetRefresh {
  [DllImport("wininet.dll", SetLastError=true)]
  public static extern bool InternetSetOption(IntPtr handle, int option, IntPtr buffer, int length);
  public static bool Refresh() {
   bool changed=InternetSetOption(IntPtr.Zero,39,IntPtr.Zero,0);
   bool refreshed=InternetSetOption(IntPtr.Zero,37,IntPtr.Zero,0);
   return changed && refreshed;
  }
 }
}
'@ -ErrorAction Stop
    }
    if(-not [AGFixer.WinInetRefresh]::Refresh()){throw 'WinINet не подтвердил перечитывание настроек.'}
}
function Invoke-AGRepairProxyStep {
    param($Proxy)
    $before=Read-AGRepairRegistry $Proxy.Scope
    if((Get-AGRepairFingerprint $before) -ne $Proxy.Fingerprint){throw 'Настройки прокси изменились; обновите план.'}
    $ports=@(Get-AGRepairProxyPorts $before.Server)
    $listeners=@(Get-NetTCPConnection -State Listen -ErrorAction Stop)
    if(-not $ports.Count -or $before.Managed -or $before.PAC -or @($listeners|Where-Object{$_.LocalPort -in $ports -and $_.LocalAddress -match '^(127\.|::ffff:127\.|0\.0\.0\.0$|::$|::1$)'}).Count){throw 'Прокси запущен или защищён настройками: очистка отменена.'}
    try{
        Remove-ItemProperty -LiteralPath $before.Path -Name ProxyServer -ErrorAction Stop
        $null=New-ItemProperty -LiteralPath $before.Path -Name ProxyEnable -Value 0 -PropertyType DWord -Force -ErrorAction Stop
        $after=Read-AGRepairRegistry $Proxy.Scope
        if($after.Server -or $after.Enabled){throw 'Отключение системного прокси не подтверждено.'}
        Update-AGRepairWinInet
    }catch{
        $failure=$_.Exception.Message
        try{Restore-AGRepairRegistryState $before}catch{throw ($failure+'; откат реестра не выполнен: '+$_.Exception.Message)}
        throw ($failure+'; прежние значения реестра возвращены.')
    }
}
function Invoke-AGAutoRepairCore {
    param($Plan)
    Assert-WindowsAdmin
    if($Plan.Kind -cne 'AGFixer.RepairPlan'){throw 'Неизвестный план ремонта.'}
    if(-not @($Plan.Steps).Count){return [pscustomobject]@{Status='NoChanges';Steps=@();Backup='';Message='Применять нечего. Для смены подключения выберите VPN или Zapret.'}}
    # Rebuild from current local state, do not trust stale report state or caller-provided action strings.
    $fresh=Get-AGRepairSnapshot
    $current=New-AGAutoRepairPlan -Snapshot $fresh -Analysis $Plan.Analysis -Mode $Plan.Mode -Deep:$Plan.Deep -IncludeMachineProxy:$Plan.IncludeMachineProxy -StrategyFile $Plan.StrategyFile
    $oldSig=Get-AGRepairFingerprint @($Plan.Steps|Select-Object Id,Target,Fingerprint)
    $newSig=Get-AGRepairFingerprint @($current.Steps|Select-Object Id,Target,Fingerprint)
    if($oldSig -ne $newSig){throw 'Состояние изменилось после просмотра. Обновите план: ничего не применено.'}
    if(@($current.Steps|Where-Object{$_.Id -in @('Profile','DnsBypassOff','Restart','GpuCache')}).Count -and @(Get-Process -Name 'Antigravity*','AGUnlocker','language_server*','agy' -ErrorAction SilentlyContinue).Count){throw 'Сохраните работу, закройте IDE и окно Unlocker, затем повторите ремонт. Процессы не завершаются принудительно.'}
    $folder=Join-Path $env:LOCALAPPDATA ('AGFixer/repairs/'+[datetime]::UtcNow.ToString('yyyyMMdd-HHmmss')+'-'+[guid]::NewGuid().ToString('N'))
    $null=New-Item -ItemType Directory -Path $folder -Force -ErrorAction Stop
    $selectedRules=@($fresh.Nrpt|Where-Object{$_.Name -in @($current.Steps|Where-Object Id -eq 'Nrpt'|ForEach-Object{$_.Target})})
    $backup=[pscustomobject]@{Kind='AGFixer.RepairBackup';Computer=$env:COMPUTERNAME;Proxies=@($fresh.Proxies|Where-Object{$_.Scope -in @($current.Steps|Where-Object Id -eq 'Proxy'|ForEach-Object{$_.Target})}|ForEach-Object{$_.State});Nrpt=$selectedRules;SettingsHash=$fresh.SettingsHash}
    $backup|Export-Clixml -LiteralPath (Join-Path $folder 'before.clixml') -ErrorAction Stop
    if(@($current.Steps|Where-Object Id -eq 'WinHttp').Count){Invoke-AGRepairNetsh Dump|Set-Content -LiteralPath (Join-Path $folder 'winhttp-before.txt') -Encoding UTF8 -ErrorAction Stop}
    $receipts=New-Object 'System.Collections.Generic.List[object]';$status='Applied';$message='Выбранные изменения применены. Перезапустите Antigravity и отправьте запрос.'
    $index=0
    foreach($step in $current.Steps){
        $index++;Write-Host "[$index/$($current.Steps.Count)] $($step.Label)" -ForegroundColor Cyan
        try{
            $detail=''
            switch($step.Id){
                'Proxy'{$proxy=@($fresh.Proxies|Where-Object Scope -eq $step.Target)[0];Invoke-AGRepairProxyStep $proxy}
                'Nrpt'{
                    $live=@(Get-DnsClientNrptRule -ErrorAction Stop|Where-Object Name -eq $step.Target)
                    if($live.Count -ne 1 -or -not(Test-AGRepairNrptRule $live[0]) -or (Get-AGRepairFingerprint (Get-AGRepairNrptShape $live[0])) -ne $step.Fingerprint){throw 'NRPT изменён другой программой; удаление отменено.'}
                    Remove-DnsClientNrptRule -Name $step.Target -Force -Confirm:$false -ErrorAction Stop
                    if(@(Get-DnsClientNrptRule -ErrorAction Stop|Where-Object Name -eq $step.Target).Count){throw 'Удаление NRPT не подтверждено.'}
                }
                'ZapretDomains'{
                    if((Get-ZapretPath) -ne $step.Target -or (Get-AGRepairFingerprint @(Get-AGRepairZapretLists $step.Target)) -ne $step.Fingerprint){throw 'Папка/списки Zapret изменились; перечитайте план.'}
                    Invoke-UnlockedAdd-AGDomains -IncludeLogin
                    . "$PSScriptRoot/local-audit.ps1"
                    . "$PSScriptRoot/zapret-lists.ps1"
                    $health=Get-AGZapretListHealth $step.Target
                    if($health.Status -ne 'Исправно'){throw 'Размещение доменов исправлено, но остались ошибки/широкие исключения. Откройте Инструменты → Проверить списки Zapret.'}
                }
                'Zapret'{
                    $StrategyFile=$current.StrategyFile;$root=Get-ZapretPath;$command=Get-StrategyCommand $root $StrategyFile
                    $now=Get-AGRepairFingerprint ([pscustomobject]@{Root=$root;Command=$command;Hash=(Get-AGFileHash (Join-Path $root $StrategyFile))})
                    if($now -ne $step.Fingerprint){throw 'Стратегия Zapret изменилась: установка отменена.'}
                    if(-not(Invoke-UnlockedInstall-ZapretService -StrategyBatName $StrategyFile -Confirmed)){throw 'Стратегия не применена.'}}
                'DnsBypassOff'{
                    $path=Get-AGPath 'settings.json'
                    if((Get-AGFileHash $path) -ne $step.Fingerprint){throw 'Настройки Unlocker изменились: обновите план.'}
                    $cfg=Read-AGSettings;$cfg|Add-Member -NotePropertyName dns -NotePropertyValue $false -Force
                    $null=Write-AGAtomicText -Path $path -Text ($cfg|ConvertTo-Json -Depth 100) -ExpectedHash $step.Fingerprint
                    if((Read-AGSettings).dns -ne $false){throw 'Выключение DNS-обхода не подтверждено.'}
                }
                'Profile'{Invoke-UnlockedSet-AGProfile -Profile $current.Mode
                    $cfg=Read-AGSettings
                    $wantLocal=$current.Mode -eq 'Zapret';$wantDns=$current.Mode -eq 'Zapret'
                    if($cfg.local_proxy -ne $wantLocal -or $cfg.dns -ne $wantDns -or $cfg.group_proxy -or $cfg.builtin_exits -or $cfg.own_proxy_enabled){throw 'Настройки профиля не подтверждены.'}
                }
                'Restart'{Invoke-UnlockedReset-AGService -RemoveGateReport
                    $deadline=[datetime]::UtcNow.AddSeconds(8)
                    do{
                        $waiting=@(foreach($name in @('AG Unlocker DNS','AG Unlocker Watchdog')){if([string](Get-ScheduledTask -TaskName $name -TaskPath '\' -ErrorAction Stop).State -notin @('Running','Ready')){$name}})
                        $expectedExe=Get-AGUnlockerRuntime
                        $dns=@(Get-Process ag_dns -ErrorAction SilentlyContinue|Where-Object{$_.Path -and [IO.Path]::GetFullPath($_.Path) -ieq $expectedExe})
                        if(-not $dns.Count){$waiting+= 'ag_dns из выбранной папки'}
                        if(-not $waiting.Count){break};Start-Sleep -Milliseconds 100
                    }while([datetime]::UtcNow -lt $deadline)
                    if($waiting.Count){throw ('Запуск Unlocker не подтверждён: '+($waiting -join ', '))}
                }
                'WinHttp'{$null=Invoke-AGRepairNetsh Reset;$dump=Invoke-AGRepairNetsh Dump;if($dump -notmatch '(?im)^\s*reset\s+proxy\s*$' -or $dump -match '(?im)^\s*set\s+(?:proxy|advproxy)\b'){throw 'WinHTTP: состояние Direct после сброса не подтверждено.'}}
                'FlushDns'{Clear-DnsClientCache -ErrorAction Stop}
                'GpuCache'{$detail=[string](Move-AGGpuCache -Application Antigravity -Confirmed);if(-not $detail){throw 'Кэш не перемещён.'}}
                default{throw 'Неизвестная операция: выполнение запрещено.'}
            }
            $receipts.Add([pscustomobject]@{Id=$step.Id;Target=$step.Target;Status='Applied';Detail=$detail})
        }catch{
            $status='Partial';$message='Ремонт остановлен: '+(Protect-AGText $_.Exception.Message)
            $receipts.Add([pscustomobject]@{Id=$step.Id;Target=$step.Target;Status='Failed';Detail=$message});break
        }finally{
            [pscustomobject]@{Status=$status;Results=@($receipts.ToArray());Backup=$folder}|ConvertTo-Json -Depth 10|Set-Content -LiteralPath (Join-Path $folder 'result.json') -Encoding UTF8 -ErrorAction Stop
        }
    }
    return [pscustomobject]@{Status=$status;Steps=@($receipts.ToArray());Backup=$folder;Message=$message}
}
function Invoke-AGAutoRepair {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param([string]$ReportText,$Plan,[ValidateSet('Keep','VpnDirect','Zapret')][string]$Mode='Keep',[switch]$Deep,[switch]$Confirmed,[string]$StrategyFile)
    if(-not(Get-Command Assert-WindowsAdmin -ErrorAction SilentlyContinue)){. "$PSScriptRoot/common.ps1"}
    if(-not(Get-Command Protect-AGText -ErrorAction SilentlyContinue)){. "$PSScriptRoot/report-analysis.ps1"}
    Assert-WindowsAdmin
    if(-not $Plan){$analysis=$null;if($ReportText){$analysis=Get-AGReportAnalysis $ReportText};$Plan=New-AGAutoRepairPlan -Snapshot (Get-AGRepairSnapshot) -Analysis $analysis -Mode $Mode -Deep:$Deep -StrategyFile $StrategyFile}
    if(-not $PSCmdlet.ShouldProcess($Plan.Label,'Применить показанный план ремонта')){return}
    if(-not $Confirmed){return [pscustomobject]@{Status='Preview';Plan=$Plan;Message='Передайте -Confirmed только после просмотра и явного согласия.'}}
    Invoke-AGExclusiveOperation {Invoke-AGAutoRepairCore $Plan}
}
function Show-AGRepairResult {
    param($Result)
    $lines=@($Result.Message)
    $labels=@{Proxy='Системный прокси';DnsBypassOff='DNS-обход Unlocker';Nrpt='Правила DNS';ZapretDomains='Списки сайтов Zapret';Zapret='Стратегия Zapret';Profile='Настройки Unlocker';Restart='Перезапуск Unlocker';WinHttp='Системный WinHTTP';FlushDns='Кэш DNS';GpuCache='Графический кэш'}
    foreach($step in @($Result.Steps)){
        $name=if($labels.ContainsKey([string]$step.Id)){$labels[[string]$step.Id]}else{[string]$step.Id}
        $status=if($step.Status -eq 'Applied'){'готово'}elseif($step.Status -eq 'Failed'){'ошибка'}else{[string]$step.Status}
        $lines+=($name+': '+$status)
    }
    if($Result.Backup){$lines+='Копии и журнал: '+$Result.Backup}
    $title=if($Result.Status -eq 'Applied'){'ГОТОВО: выбранные изменения применены'}elseif($Result.Status -eq 'Partial'){'Ремонт выполнен не полностью'}else{'Без изменений'}
    if(Get-Command Show-AGTextPages -ErrorAction SilentlyContinue){Show-AGTextPages -Title $title -Lines $lines}else{Write-Host $title;foreach($line in $lines){Write-Host $line}}
}
