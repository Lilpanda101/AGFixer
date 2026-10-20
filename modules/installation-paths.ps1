#Requires -Version 5.1
# Paths are data only. Discovery never starts a program or executes task arguments.
function Get-AGPathPreferences {
    $values=@{}
    if(-not $env:LOCALAPPDATA){return $values}
    $file=Join-Path $env:LOCALAPPDATA 'AGFixer/paths.json'
    if(Test-Path -LiteralPath $file -PathType Leaf){
        try{
            if((Get-Item -LiteralPath $file).Length -gt 16KB){return $values}
            $data=Get-Content -LiteralPath $file -Raw -Encoding UTF8|ConvertFrom-Json -ErrorAction Stop
            foreach($key in @('UnlockerData','UnlockerRuntime','Zapret')){if($data.$key -is [string] -and $data.$key -notmatch '[\x00-\x1f]'){$values[$key]=$data.$key}}
        }catch{}
    }
    return $values
}
function Test-AGInstallationPath {
    param([ValidateSet('UnlockerData','UnlockerRuntime','Zapret')][string]$Kind,[string]$Path)
    if(-not $Path -or -not(Test-Path -LiteralPath $Path -PathType Container)){return $false}
    switch($Kind){
        'UnlockerData'{return (Test-Path -LiteralPath (Join-Path $Path 'settings.json') -PathType Leaf)}
        'UnlockerRuntime'{return (Test-Path -LiteralPath (Join-Path $Path 'ag_dns.exe') -PathType Leaf)}
        'Zapret'{return ((Test-Path -LiteralPath (Join-Path $Path 'service.bat') -PathType Leaf) -and (Test-Path -LiteralPath (Join-Path $Path 'lists') -PathType Container))}
    }
}
function Get-AGExecutableFromAction {
    param([string]$Value,[string]$Name)
    $path=[Environment]::ExpandEnvironmentVariables($Value.Trim().Trim('"'))
    if($path -and [IO.Path]::GetFileName($path) -ieq $Name -and (Test-Path -LiteralPath $path -PathType Leaf)){return [IO.Path]::GetFullPath($path)}
    return ''
}
function Get-AGInstallationCandidates {
    param([ValidateSet('UnlockerData','UnlockerRuntime','Zapret')][string]$Kind)
    $list=New-Object 'System.Collections.Generic.List[string]'
    $prefs=Get-AGPathPreferences
    if($prefs[$Kind]){$list.Add($prefs[$Kind])}
    if($Kind -eq 'UnlockerData' -and $env:LOCALAPPDATA){$list.Add((Join-Path $env:LOCALAPPDATA 'AGUnlocker'))}
    if($Kind -eq 'Zapret' -and $env:ZAPRET_PATH){$list.Add($env:ZAPRET_PATH)}
    $names=if($Kind -eq 'Zapret'){@('winws','winws2')}else{@('ag_dns')}
    try{foreach($p in @(Get-Process -Name $names -ErrorAction SilentlyContinue)){if($p.Path){$dir=Split-Path $p.Path -Parent;$list.Add($dir);if($Kind -eq 'Zapret'){$list.Add((Split-Path $dir -Parent))}}}}catch{}
    if($Kind -ne 'Zapret'){
        try{foreach($t in @(Get-ScheduledTask -TaskName 'AG Unlocker DNS' -TaskPath '\' -ErrorAction SilentlyContinue)){foreach($a in @($t.Actions)){
            $exe=Get-AGExecutableFromAction ([string]$a.Execute) 'ag_dns.exe'
            if($exe){$list.Add((Split-Path $exe -Parent))}
            if($a.WorkingDirectory){$list.Add([string]$a.WorkingDirectory)}
        }}}catch{}
        if($env:LOCALAPPDATA){$list.Add((Join-Path $env:LOCALAPPDATA 'AGUnlocker'))}
    }
    if($Kind -eq 'Zapret'){
        try{
            $svc=Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\zapret' -ErrorAction SilentlyContinue
            $m=[regex]::Match([string]$svc.ImagePath,'^\s*(?:"(?<exe>[^"]+\.exe)"|(?<exe>.+?\.exe))(?:\s|$)','IgnoreCase')
            if($m.Success){$dir=Split-Path $m.Groups['exe'].Value -Parent;$list.Add($dir);$list.Add((Split-Path $dir -Parent))}
        }catch{}
    }
    # Bounded discovery: no recursive drive scan and no reads of report command lines.
    $roots=@($PSScriptRoot)
    if($env:USERPROFILE){$roots+=@(Join-Path $env:USERPROFILE 'Desktop';Join-Path $env:USERPROFILE 'Downloads')}
    foreach($root in @($roots|Where-Object{$_ -and (Test-Path -LiteralPath $_ -PathType Container)})){
        foreach($dir in @(Get-ChildItem -LiteralPath $root -Directory -ErrorAction SilentlyContinue|Where-Object{$_.Name -match '(?i)zapret|unlocker|antigravity'}|Select-Object -First 60)){
            $list.Add($dir.FullName)
            foreach($child in @('AGUnlocker','bin')){$list.Add((Join-Path $dir.FullName $child))}
        }
    }
    return @($list|Where-Object{Test-AGInstallationPath $Kind $_}|ForEach-Object{(Resolve-Path -LiteralPath $_).Path}|Select-Object -Unique)
}
function Get-AGUnlockerDataRoot {
    if(-not $env:LOCALAPPDATA){throw 'LOCALAPPDATA не определён.'}
    $prefs=Get-AGPathPreferences
    if(Test-AGInstallationPath UnlockerData $prefs.UnlockerData){return $prefs.UnlockerData}
    $default=Join-Path $env:LOCALAPPDATA 'AGUnlocker'
    if(Test-AGInstallationPath UnlockerData $default){return $default}
    # Only enumerate when the usual data directory is absent.
    $found=@(Get-AGInstallationCandidates UnlockerData)
    if($found.Count -eq 1){return $found[0]}
    return $default
}
function Get-AGUnlockerRuntime {
    $prefs=Get-AGPathPreferences
    $root=''
    if(Test-AGInstallationPath UnlockerRuntime $prefs.UnlockerRuntime){$root=$prefs.UnlockerRuntime}
    if(-not $root){
        $running=@();try{$running=@(Get-Process ag_dns -ErrorAction SilentlyContinue|ForEach-Object{Get-AGExecutableFromAction ([string]$_.Path) 'ag_dns.exe'}|Where-Object{$_}|Select-Object -Unique)}catch{}
        if($running.Count -eq 1){$root=Split-Path $running[0] -Parent}
        elseif($running.Count -gt 1){throw 'Найдено несколько ag_dns. Выберите нужную папку: Инструменты → Папки программ.'}
    }
    if(-not $root){$found=@(Get-AGInstallationCandidates UnlockerRuntime);if($found.Count -eq 1){$root=$found[0]}}
    if(-not $root){throw 'Не найдена папка с ag_dns.exe. Откройте Инструменты → Папки программ или укажите её при настройке.'}
    return [IO.Path]::GetFullPath((Join-Path $root 'ag_dns.exe'))
}
function Assert-AGUnlockerRuntime {
    $exe=Get-AGUnlockerRuntime
    foreach($p in @(Get-Process ag_dns -ErrorAction SilentlyContinue)){
        if(-not $p.Path -or [IO.Path]::GetFullPath($p.Path) -ine $exe){throw 'Найден ещё один ag_dns из другой установки. Выберите нужную папку и закройте лишнюю установку Unlocker.'}
    }
    $task=Get-ScheduledTask -TaskName 'AG Unlocker DNS' -TaskPath '\' -ErrorAction Stop
    $actions=@($task.Actions)
    if($actions.Count -ne 1 -or -not $actions[0]){throw 'В задаче AG Unlocker DNS должен быть один проверяемый запуск ag_dns.exe. Автоперезапуск отменён.'}
    foreach($action in $actions){
        $taskExe=Get-AGExecutableFromAction ([string]$action.Execute) 'ag_dns.exe'
        if(-not $taskExe){throw 'Команда задачи AG Unlocker DNS не является доступным ag_dns.exe. Проверьте задачу или перезапустите Unlocker вручную.'}
        if($taskExe -ine $exe){throw 'Папка ag_dns не совпадает с задачей AG Unlocker DNS. Выберите папку из этой задачи.'}
    }
    return $exe
}
function Save-AGInstallationPath {
    param([ValidateSet('UnlockerData','UnlockerRuntime','Zapret')][string]$Kind,[string]$Path)
    if(-not(Test-AGInstallationPath $Kind $Path)){throw 'В выбранной папке нет нужных файлов. Выберите установку, а не архив или папку AGFixer.'}
    $path=(Resolve-Path -LiteralPath $Path).Path
    $prefs=Get-AGPathPreferences;$prefs[$Kind]=$path
    $folder=Join-Path $env:LOCALAPPDATA 'AGFixer';$null=New-Item -ItemType Directory -Path $folder -Force -ErrorAction Stop
    $file=Join-Path $folder 'paths.json';$temp=Join-Path $folder ([IO.Path]::GetRandomFileName())
    try{
        [IO.File]::WriteAllText($temp,($prefs|ConvertTo-Json),(New-Object Text.UTF8Encoding($false)))
        if(Test-Path -LiteralPath $file){[IO.File]::Replace($temp,$file,[Management.Automation.Language.NullString]::Value)}else{[IO.File]::Move($temp,$file)}
    }finally{if(Test-Path -LiteralPath $temp){Remove-Item -LiteralPath $temp -Force}}
    return $path
}
function Select-AGInstallationFolder {
    param([ValidateSet('UnlockerData','UnlockerRuntime','Zapret')][string]$Kind)
    $label=@{UnlockerData='Настройки Unlocker (settings.json)';UnlockerRuntime='Сетевая часть Unlocker (ag_dns.exe)';Zapret='Zapret (service.bat и lists)'}[$Kind]
    $found=@(Get-AGInstallationCandidates $Kind)
    $choice=Read-AGListChoice -Title $label -Options (@($found)+@('Указать другую папку')) -Intro @('Выберите найденную установку или вставьте путь к своей папке.')
    if(-not $choice){return $false}
    $path=if($choice -le $found.Count){$found[$choice-1]}else{(Read-AGInput 'Путь к папке (Enter — отменить выбор)').Trim().Trim('"')}
    if(-not $path){return $false}
    $null=Save-AGInstallationPath $Kind $path
    return $true
}
function Get-AGRepairPathRequirements {
    param($Snapshot,$Analysis,[ValidateSet('Keep','VpnDirect','Zapret')][string]$Mode='Keep',[switch]$Deep)
    $actions=@();if($Analysis -and $Analysis.Diagnosis){$actions=@($Analysis.Diagnosis.Actions)}
    $settings=($Mode -ne 'Keep' -or 'Nrpt' -in $actions -or ($Deep -and @($Snapshot.Nrpt).Count -gt 0))
    return [pscustomobject]@{NeedSettings=[bool]$settings;NeedRestart=[bool]($settings -or 'Restart' -in $actions)}
}
function Initialize-AGRepairPaths {
    param([ValidateSet('Keep','VpnDirect','Zapret')][string]$Mode='Keep',[switch]$NeedRestart,[switch]$NeedSettings,$Snapshot,$Analysis,[switch]$Deep)
    $requirements=Get-AGRepairPathRequirements -Snapshot $Snapshot -Analysis $Analysis -Mode $Mode -Deep:$Deep
    if($requirements.NeedSettings -or $NeedSettings){
        $data=Get-AGUnlockerDataRoot
        if(-not(Test-AGInstallationPath UnlockerData $data)){if(-not(Select-AGInstallationFolder UnlockerData)){return $false}}
    }
    if($requirements.NeedRestart -or $NeedRestart){try{$null=Get-AGUnlockerRuntime}catch{if(-not(Select-AGInstallationFolder UnlockerRuntime)){return $false}}}
    if($Mode -eq 'Zapret'){try{$null=Get-ZapretPath}catch{if(-not(Select-AGInstallationFolder Zapret)){return $false}}}
    return $true
}
function Show-AGInstallationFolders {
    while($true){
        $prefs=Get-AGPathPreferences
        $intro=@('Автопоиск использует процессы, задачу Unlocker и обычные папки.','Папка настроек и папка ag_dns могут быть разными.')
        foreach($key in @('UnlockerData','UnlockerRuntime','Zapret')){if($prefs[$key]){$intro+="$key`: $($prefs[$key])"}}
        $n=Read-AGListChoice -Title 'Папки программ' -Options @('Настройки Unlocker — settings.json','Сетевая часть Unlocker — ag_dns.exe','Папка Zapret') -Intro $intro
        if(-not $n){return}
        $kind=@('UnlockerData','UnlockerRuntime','Zapret')[$n-1]
        try{$null=Select-AGInstallationFolder $kind}catch{Show-AGTextPages -Title 'Папка не выбрана' -Lines @($_.Exception.Message)}
    }
}
