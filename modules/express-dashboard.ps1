#Requires -Version 5.1
. "$PSScriptRoot/console-input.ps1"
function Get-AGDashboardActions {
    return @('Вставить и разобрать отчёт Unlocker','У меня свой VPN — настроить подключение','Zapret — проверить и применить ALT11','Очистить сетевые хвосты (с выбором объёма)')
}
function Get-AGDashboardLines {
    param($Snapshot,$Analysis)
    $lines=@('AGFixer Express v6.8 by txmui')
    if($Analysis){$lines+='Отчёт в буфере: '+$Analysis.Diagnosis.Title}
    if($Snapshot){
        $candidates=@($Snapshot.Proxies|Where-Object Eligible)
        if($candidates.Count){$lines+='[!] Не запущен локальный системный прокси: '+($candidates.Server -join ', ')}
        if(@($Snapshot.Nrpt).Count){$lines+="Локальные NRPT-правила Unlocker: $(@($Snapshot.Nrpt).Count)"}
        $names=@($Snapshot.Processes|ForEach-Object{$_.ProcessName})
        $zap=if('winws' -in $names){'запущен'}else{'не найден'}
        $unlocker=if('ag_dns' -in $names){'запущен'}else{'не найден'}
        $lines+="Zapret: $zap | ag_dns: $unlocker"
        if($Snapshot.ProxyRunning){$lines+='Работающий системный прокси сохранится.'}
    }else{$lines+='Проверяю систему в фоне...'}
    $lines+='[SPACE] Быстрый ремонт — показать найденный план'
    $actions=@(Get-AGDashboardActions)
    for($i=0;$i -lt $actions.Count;$i++){$lines+="[$($i+1)] $($actions[$i])"}
    $lines+='[0] Выход'
    $lines+='R: обновить | A: инструменты и гайды'
    return $lines
}
function Start-AGDashboardAudit {
    $worker=[powershell]::Create()
    $runspace=[runspacefactory]::CreateRunspace()
    if($env:OS -eq 'Windows_NT'){$runspace.ApartmentState='STA'}
    $runspace.ThreadOptions='ReuseThread';$runspace.Open();$worker.Runspace=$runspace
    $null=$worker.AddScript({param($Root) $ErrorActionPreference='Stop';. (Join-Path $Root 'common.ps1');. (Join-Path $Root 'repair-safe.ps1');Get-AGRepairSnapshot -IncludeClipboard}).AddArgument($PSScriptRoot)
    return [pscustomobject]@{Worker=$worker;Runspace=$runspace;Handle=$worker.BeginInvoke();Started=[datetime]::UtcNow}
}
function Read-AGDashboardAudit {
    param($Job)
    if(-not $Job -or -not $Job.Handle.IsCompleted){return $null}
    try{$result=@($Job.Worker.EndInvoke($Job.Handle));if($result.Count){return $result[$result.Count-1]};return $null}finally{$Job.Worker.Dispose();$Job.Runspace.Dispose()}
}
function Read-AGExpressKey {
    try{return (ConvertFrom-AGConsoleKey ([Console]::ReadKey($true)))}catch{
        $value=ConvertTo-AGCommandKey (Read-AGInput '>')
        if($value -eq ''){return 'ENTER'};return $value
    }
}
