#Requires -Version 5.1
# Read-only local checks. Missing access/cmdlets are returned explicitly.
function Get-AGDomainList {
    param([switch]$IncludeLogin)
    $config = Get-Content -LiteralPath "$PSScriptRoot/domains.json" -Raw -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    $domains = @($config.Core)
    if ($IncludeLogin) { $domains += @($config.Login) }
    return @($domains | Sort-Object -Unique)
}
function Test-AGHostPattern {
    param([string]$Domain,[string]$Pattern)
    $p = ($Pattern -split '#',2)[0].Trim().ToLowerInvariant()
    $exact = $p.StartsWith('^')
    $p = $p.TrimStart('^').TrimStart('.').TrimEnd('.')
    if ($p -notmatch '^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$') { return $false }
    $d = $Domain.TrimEnd('.').ToLowerInvariant()
    return ($d -eq $p -or (-not $exact -and $d.EndsWith('.' + $p)))
}
function Get-AGZapretAudit {
    param([Parameter(Mandatory=$true)][string]$Root)
    $domains = @(Get-AGDomainList -IncludeLogin)
    $include = New-Object 'System.Collections.Generic.List[string]'
    $exclude = New-Object 'System.Collections.Generic.List[string]'
    $files = New-Object 'System.Collections.Generic.List[object]'
    foreach ($name in @('list-general.txt','list-general-user.txt','list-exclude.txt','list-exclude-user.txt')) {
        $path = Join-Path $Root "lists/$name"
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { $files.Add([pscustomobject]@{Name=$name;Status='missing'}); continue }
        $entries = @(Get-Content -LiteralPath $path -Encoding UTF8 -ErrorAction Stop)
        foreach ($entry in $entries) {
            if ($name -like '*exclude*') { $exclude.Add($entry) } else { $include.Add($entry) }
        }
        $files.Add([pscustomobject]@{ Name=$name; Status='read'; Modified=(Get-Item -LiteralPath $path).LastWriteTimeUtc.ToString('o') })
    }
    $coverage = foreach ($domain in $domains) {
        $inc = @($include | Where-Object { Test-AGHostPattern -Domain $domain -Pattern $_ })
        $exc = @($exclude | Where-Object { Test-AGHostPattern -Domain $domain -Pattern $_ })
        [pscustomobject]@{ Domain=$domain; InKnownIncludeFiles=($inc.Count -gt 0); InKnownExcludeFiles=($exc.Count -gt 0); IncludePatterns=$inc; ExcludePatterns=$exc }
    }
    $ipset = foreach ($name in @('ipset-all.txt','ipset-exclude.txt','ipset-discord.txt')) {
        $path = Join-Path $Root "lists/$name"
        if (Test-Path -LiteralPath $path -PathType Leaf) {
            $file = Get-Item -LiteralPath $path
            [pscustomobject]@{ Name=$name; Bytes=$file.Length; Modified=$file.LastWriteTimeUtc.ToString('o') }
        }
    }
    $gameFilter=$null
    try { $gameFilter=Get-AGGameFilterState -Root $Root } catch { $gameFilter=[pscustomobject]@{Mode='unknown';Reason=$_.Exception.Message} }
    $ipsetMode='unknown'
    $ipsetPath=Join-Path $Root 'lists/ipset-all.txt'
    if (Test-Path -LiteralPath $ipsetPath -PathType Leaf) {
        $entries=@(Get-Content -LiteralPath $ipsetPath -Encoding UTF8 | Where-Object { $_.Trim() -and -not $_.TrimStart().StartsWith('#') })
        $ipsetMode=if (-not $entries.Count) { 'any (empty file)' } elseif ($entries -contains '203.0.113.113/32') { 'none (Flowseal sentinel found)' } else { 'loaded (contents not externally validated)' }
    }
    return [pscustomobject]@{ Files=@($files.ToArray()); DomainCoverage=@($coverage); GameFilter=$gameFilter; IPSetMode=$ipsetMode; IPSetFiles=@($ipset); Limit='Проверяются известные файлы, а не все аргументы активной стратегии. Наличие домена не доказывает перехват трафика; совпадение exclude требует проверки стратегии. Время ipset не доказывает актуальность.' }
}
function Get-AGLocalAudit {
    [CmdletBinding()]
    param([string]$ZapretRoot)
    if ($env:OS -ne 'Windows_NT') { throw 'Локальный аудит требуется выполнять на Windows.' }
    $issues = New-Object 'System.Collections.Generic.List[string]'
    $processes = @(); $tasks = @(); $tcp = @(); $udp = @(); $adapters = @(); $dns = @(); $nrpt = @(); $hosts = @(); $zapret = $null
    $domains = @(Get-AGDomainList -IncludeLogin)
    try {
        $processes = @(Get-Process -Name ag_dns,dns_ai,winws,Antigravity*,language_server* -ErrorAction SilentlyContinue | ForEach-Object {
            $version=$null; $path=$null; $started=$null
            try { $path=$_.Path; if ($path) { $version=[Diagnostics.FileVersionInfo]::GetVersionInfo($path).FileVersion }; $started=$_.StartTime.ToUniversalTime().ToString('o') } catch { $issues.Add('Не все пути/версии процессов доступны; может требоваться повышение прав.') }
            [pscustomobject]@{ Name=$_.ProcessName; PID=$_.Id; Path=$path; FileVersion=$version; Started=$started }
        })
    } catch { $issues.Add("Процессы: $($_.Exception.Message)") }
    try {
        $tasks = @(Get-ScheduledTask -TaskName 'AG Unlocker*' -ErrorAction Stop | ForEach-Object {
            $task=$_; $last=$null
            try { $last=Get-ScheduledTaskInfo -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction Stop } catch { }
            [pscustomobject]@{ Name=$task.TaskName; State=[string]$task.State; LastRunTime=if($last){$last.LastRunTime}else{$null}; LastResult=if ($last) { $last.LastTaskResult } else { $null }; Execute=@($task.Actions | ForEach-Object { $_.Execute }) }
        })
    } catch { $issues.Add("Задачи Unlocker недоступны/не найдены: $($_.Exception.Message)") }
    $agPids = @($processes | Where-Object { $_.Name -in @('ag_dns','dns_ai') } | ForEach-Object { $_.PID })
    try {
        $tcp = @(Get-NetTCPConnection -State Listen -ErrorAction Stop | Where-Object { $_.LocalPort -in @(53,53128,53129,10808,10809,1080,7890,8080) -or $_.OwningProcess -in $agPids } | ForEach-Object {
            $owner = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
            [pscustomobject]@{ Protocol='TCP'; Address=$_.LocalAddress; Port=$_.LocalPort; PID=$_.OwningProcess; Owner=if($owner){$owner.ProcessName}else{'unknown'}; IsAG=($_.OwningProcess -in $agPids) }
        })
    } catch { $issues.Add("TCP listeners: $($_.Exception.Message)") }
    try {
        $udp = @(Get-NetUDPEndpoint -ErrorAction Stop | Where-Object { $_.LocalPort -eq 53 -or $_.OwningProcess -in $agPids } | ForEach-Object {
            $owner = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
            [pscustomobject]@{ Protocol='UDP'; Address=$_.LocalAddress; Port=$_.LocalPort; PID=$_.OwningProcess; Owner=if($owner){$owner.ProcessName}else{'unknown'}; IsAG=($_.OwningProcess -in $agPids) }
        })
    } catch { $issues.Add("UDP listeners: $($_.Exception.Message)") }
    try { $adapters = @(Get-NetAdapter -ErrorAction Stop | Select-Object InterfaceIndex,Name,Status,InterfaceDescription) } catch { $issues.Add("Адаптеры: $($_.Exception.Message)") }
    try { $dns = @(Get-DnsClientServerAddress -ErrorAction Stop | Where-Object { $_.ServerAddresses.Count } | Select-Object InterfaceIndex,InterfaceAlias,AddressFamily,ServerAddresses) } catch { $issues.Add("DNS: $($_.Exception.Message)") }
    try {
        $nrpt = @(Get-DnsClientNrptPolicy -Effective -ErrorAction Stop | Where-Object {
            $matched=$false
            foreach ($pattern in @($_.Namespace)) { foreach ($domain in $domains) { if ($pattern -eq '.' -or (Test-AGHostPattern $domain $pattern)) { $matched=$true } } }
            $matched
        } | Select-Object Namespace,NameServers,DirectAccessDnsServers,Comment)
    } catch { $issues.Add("NRPT: $($_.Exception.Message)") }
    try {
        $hostsPath = if ($script:AGHostsPathOverride) { $script:AGHostsPathOverride } else { Join-Path $env:SystemRoot 'System32/drivers/etc/hosts' }
        $hosts = @(Get-Content -LiteralPath $hostsPath -Encoding UTF8 -ErrorAction Stop | ForEach-Object {
            $line=($_ -split '#',2)[0].Trim()
            if ($line) {
                $parts=@($line -split '\s+')
                if ($parts.Count -gt 1) { foreach ($domain in $parts[1..($parts.Count-1)]) {
                    if ($domain -in $domains) { [pscustomobject]@{ Domain=$domain; Address=$parts[0]; Note='Может быть штатной записью; не удалять без проверки владельца.' } }
                } }
            }
        })
    } catch { $issues.Add("hosts: $($_.Exception.Message)") }
    try {
        if (-not $ZapretRoot) { $ZapretRoot=Get-ZapretPath }
        $zapret=Get-AGZapretAudit -Root $ZapretRoot
    } catch { $issues.Add("Zapret: $($_.Exception.Message)") }
    $proxyCandidates = @($tcp | Where-Object { $_.IsAG -and $_.Port -ne 53 } | Select-Object Port,Address,PID)
    return [pscustomobject]@{
        CollectedAt=(Get-Date).ToUniversalTime().ToString('o'); OS=[Environment]::OSVersion.VersionString; PowerShell=$PSVersionTable.PSVersion.ToString()
        Processes=$processes; Tasks=$tasks; Listeners=@($tcp)+@($udp); ProxyCandidates=$proxyCandidates; Adapters=$adapters; DNS=$dns; NRPT=$nrpt; Hosts=$hosts; Zapret=$zapret; CollectionIssues=@($issues.ToArray())
        Limits='Только чтение. Наличие VPN/NRPT/hosts/порта само по себе не означает конфликт. Кандидаты портов ag_dns не обязательно являются HTTP/SOCKS-прокси. Антивирус, IPv6 и политики не отключаются.'
    }
}
function Show-AGLocalAuditPlain {
    param($Audit)
    Write-Host '=== Локальный аудит, без изменений ===' -ForegroundColor Cyan
    $Audit.Processes | Format-Table Name,PID,FileVersion,Path -AutoSize
    $Audit.Tasks | Format-Table Name,State,LastResult -AutoSize
    $Audit.Listeners | Format-Table Protocol,Address,Port,PID,Owner -AutoSize
    Write-Host 'Кандидаты локального прокси (проверяйте протокол и порт):'
    $Audit.ProxyCandidates | Format-Table
    $Audit.Hosts | Format-Table Domain,Address -AutoSize
    $Audit.NRPT | Format-List
    if ($Audit.Zapret) { $Audit.Zapret.GameFilter | Format-List; Write-Host "IPSet: $($Audit.Zapret.IPSetMode)"; $Audit.Zapret.DomainCoverage | Format-Table Domain,InKnownIncludeFiles,InKnownExcludeFiles -AutoSize; Write-Host $Audit.Zapret.Limit }
    foreach ($issue in $Audit.CollectionIssues) { Write-Warning $issue }
    Write-Host $Audit.Limits
}
function Test-AGPortRanges {
    param([string]$Value)
    if (-not $Value -or $Value.Length -gt 4096) { return $false }
    foreach ($part in ($Value -split ',')) {
        if ($part -notmatch '^[1-9][0-9]{0,4}(?:-[1-9][0-9]{0,4})?$') { return $false }
        $ends=@($part -split '-')
        $first=[int]$ends[0];$last=$first
        if ($ends.Count -eq 2) { $last=[int]$ends[1] }
        if ($first -gt 65535 -or $last -gt 65535 -or $first -gt $last) { return $false }
    }
    return $true
}
function Get-AGGameFilterState {
    param([Parameter(Mandatory=$true)][string]$Root)
    $service=Join-Path $Root 'service.bat'
    if (-not (Test-Path -LiteralPath $service -PathType Leaf)) { throw 'Нет service.bat для определения формата Game Filter.' }
    $source=Get-Content -LiteralPath $service -Raw -Encoding UTF8 -ErrorAction Stop
    # Only the inspected Flowseal data-file schema is supported. Never evaluate BAT.
    if ($source -notmatch '(?i)gameFlagFile=%~dp0utils\\game_filter\.enabled' -or
        $source -notmatch '(?i)GameFilterMode=disabled' -or $source -notmatch '(?i)GameFilterTCP=12') {
        throw 'Неизвестный формат Game Filter в service.bat. Используйте штатный service.bat; порты не угадываются.'
    }
    $flag=Join-Path $Root 'utils/game_filter.enabled'
    $mode='disabled';$tcp='1024-65535';$udp='1024-65535'
    if (Test-Path -LiteralPath $flag -PathType Leaf) {
        foreach ($line in @(Get-Content -LiteralPath $flag -Encoding UTF8 -ErrorAction Stop)) {
            $line=$line.Trim()
            if (-not $line -or $line.StartsWith('#') -or $line.StartsWith(';')) { continue }
            $pair=$line -split '=',2
            $key=$pair[0].ToLowerInvariant();$value=''
            if ($pair.Count -eq 2) { $value=$pair[1].Trim().ToLowerInvariant() }
            switch ($key) {
                'mode' { if ($value -notin @('all','tcp','udp','disabled')) { throw 'Неизвестный mode в Game Filter.' }; $mode=$value }
                'all' { $mode='all' }
                'tcp' { if ($value) { if (-not (Test-AGPortRanges $value)) { throw 'Недопустимый TCP-диапазон Game Filter.' }; $tcp=$value } else { $mode='tcp' } }
                'udp' { if ($value) { if (-not (Test-AGPortRanges $value)) { throw 'Недопустимый UDP-диапазон Game Filter.' }; $udp=$value } else { $mode='udp' } }
                default { throw 'Неизвестная строка в файле Game Filter; настройте его через service.bat.' }
            }
        }
    }
    $tcpEffective='12';$udpEffective='12';$legacy='12'
    if ($mode -in @('all','tcp')) { $tcpEffective=$tcp;$legacy=$tcp }
    if ($mode -in @('all','udp')) { $udpEffective=$udp; if ($mode -eq 'udp') { $legacy=$udp } }
    return [pscustomobject]@{ Schema='Flowseal modern utils/game_filter.enabled'; Mode=$mode; TCP=$tcpEffective; UDP=$udpEffective; Legacy=$legacy; Source='service.bat signature + local data file; BAT not executed' }
}

function Show-AGLocalAudit {
    param($Audit,[switch]$Plain)
    if($Plain){Show-AGLocalAuditPlain $Audit | Out-Host;return}
    . "$PSScriptRoot/audit-view.ps1"
    Show-AGAuditViewer -Audit $Audit
}
