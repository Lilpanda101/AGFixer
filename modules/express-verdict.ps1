#Requires -Version 5.1
if(-not(Get-Command Write-AGTextFrame -CommandType Function -ErrorAction SilentlyContinue)){. "$PSScriptRoot/ui.ps1"}
function Get-AGVerdictLines {
    param($Analysis,$Plan)
    $lines=@()
    if($Analysis){
        $lines+='=== Что обнаружено ==='
        $lines+='Проблема: '+$Analysis.Diagnosis.Title
        foreach($issue in @($Analysis.Diagnosis.Issues|Select-Object -First 2)){$lines+='Причина: '+$issue.Cause}
    }
    if($Plan){
        $lines+='=== Что изменится автоматически ==='
        foreach($step in @($Plan.Steps)){
            if($step.Id -eq 'Profile' -and $Plan.Mode -eq 'VpnDirect'){
                $lines+='Настроим Unlocker для вашего VPN/TUN:'
                $lines+='  Обход через DNS → ВЫКЛ'
                $lines+='  Локальный прокси Unlocker → ВЫКЛ'
                $lines+='  Прокси из группы → ВЫКЛ'
                $lines+='  Встроенные выходы → ВЫКЛ'
                $lines+='  Свой прокси в Unlocker → ВЫКЛ'
                $lines+='Трафик IDE должен идти через VPN, а не через порт Unlocker.'
            }elseif($step.Id -eq 'Restart'){
                $lines+='Перезапустим Unlocker и сбросим таймеры маршрутов.'
                $lines+='Перед сбросом gate.json сохраним резервную копию.'
            }elseif($step.Id -eq 'FlushDns'){$lines+='Очистим кэш DNS Windows.'}
            else{$lines+='• '+$step.Label}
        }
        if(-not @($Plan.Steps).Count){
            if($Plan.PSObject.Properties['Configured'] -and $Plan.Configured){$lines+='Настроено. Для этого профиля изменений не требуется.'}
            else{$lines+='Подтверждённых автоматических изменений нет.'}
        }
        if($Plan.Mode -eq 'VpnDirect'){
            $lines+='=== Что нужно сделать самому ==='
            $lines+='Включите свой VPN в режиме TUN (VPN для всей системы).'
            $lines+='В IDE уберите вручную заданный прокси Unlocker, если он есть.'
            $lines+='После применения откройте Antigravity и отправьте запрос.'
            $lines+='AGFixer не включает VPN и не выбирает в нём страну.'
        }elseif($Plan.Mode -eq 'Zapret'){
            $lines+='=== После применения ==='
            $lines+='Откройте Antigravity и проверьте запрос к модели.'
            $lines+='Для этого профиля: DNS и локальный прокси Unlocker — ВКЛ; остальные выходы — ВЫКЛ.'
        }
        if($Plan.Mode -ne 'Keep'){
            $lines+='=== Что останется без изменений ==='
            $lines+='Разблокировка входа, автопатч и проверка TLS.'
            $lines+='При необходимости включите вход и автопатч в самом Unlocker.'
        }
        foreach($blocked in @($Plan.Blocked)){if($blocked){$lines+='Нужна ручная проверка: '+$blocked}}
        $scope=if($Plan.IncludeMachineProxy){'ВКЛ'}else{'ВЫКЛ'}
        $lines+='=== Дополнительно ==='
        $lines+=('M — прокси всех пользователей (HKLM): '+$scope)
        if($Analysis){$lines+='D — подробности отчёта'}
    }
    return $lines
}
function Get-AGRepairReviewFrame {
    param([string[]]$Lines,[int]$Width=80,[int]$Height=25,[int]$Page=0,[bool]$CanApply=$true,[bool]$Configured=$false,[bool]$AllPagesSeen=$true)
    $frame=Get-AGTextFrame -Title 'Проверьте план' -Lines $Lines -Page $Page -Width $Width -Height $Height
    if(-not $frame.TooSmall){
        if($CanApply){
            $footer=if($AllPagesSeen){'Y: исправить | N: игнорировать'}else{'Y: дальше по плану | N: игнорировать'}
            if($Width -lt 55){$footer=if($AllPagesSeen){'Y:исправить | N:игнорировать'}else{'Y:далее | N:игнорировать'}}
        }elseif($Configured){$footer='(Настроено) | Esc/Enter: назад'}else{$footer='Нет изменений | Esc/Enter: назад'}
        if($Width -ge 60 -and $CanApply){$footer+=' | Esc: отмена';if($frame.PageCount -gt 1){$footer+=' | ←/→: страницы'}}
        $frame.Lines[$frame.Lines.Count-1]=Limit-AGAuditLine $footer ([Math]::Max(1,$Width-1))
    }
    return $frame
}
function Get-AGVerdictFrame {
    param([string[]]$Lines,[int]$Width=80,[int]$Height=24,[int]$Page=0)
    return (Get-AGRepairReviewFrame -Lines $Lines -Width $Width -Height $Height -Page $Page)
}
function Show-AGRepairPlanReview {
    param([string[]]$Lines,$Analysis,$Plan)
    $page=0;$oldSize='';$seen=@{}
    try{
        while($true){
            $size=Get-AGAuditConsoleSize;$sizeKey="$($size.Width)x$($size.Height)"
            if($sizeKey -ne $oldSize){$seen=@{}}
            $canApply=[bool]($Plan -and @($Plan.Steps).Count)
            $configured=[bool]($Plan -and $Plan.PSObject.Properties['Configured'] -and $Plan.Configured)
            $frame=Get-AGRepairReviewFrame -Lines $Lines -Page $page -Width $size.Width -Height $size.Height -CanApply:$canApply -Configured:$configured
            $page=$frame.Page
            if(-not $frame.TooSmall){$seen[$page]=$true}
            $allSeen=$seen.Count -eq $frame.PageCount
            $frame=Get-AGRepairReviewFrame -Lines $Lines -Page $page -Width $size.Width -Height $size.Height -CanApply:$canApply -Configured:$configured -AllPagesSeen:$allSeen
            Write-AGTextFrame $frame -Reset:($sizeKey -ne $oldSize);$oldSize=$sizeKey
            if((Get-Command Test-AGTerminalInput -ErrorAction SilentlyContinue) -and (Test-AGTerminalInput)){
                $key=Read-AGTerminalKeyOrResize -Width $size.Width -Height $size.Height
            }else{$key=Read-AGExpressKeyOrResize -Width $size.Width -Height $size.Height}
            $key=ConvertTo-AGCommandKey $key
            if($key -in @('N','ESC','0','Q')){return $false}
            if($frame.TooSmall){continue}
            switch($key){
                'Y'{
                    if($canApply){
                        if($allSeen){return $true}
                        for($i=0;$i -lt $frame.PageCount;$i++){if(-not $seen.ContainsKey($i)){$page=$i;break}}
                    }
                }
                'ENTER'{if($page -eq $frame.PageCount-1){return $false};$page++}
                {$_ -in @('RIGHT','RIGHTARROW','PAGEDOWN')}{$page=[Math]::Min($frame.PageCount-1,$page+1)}
                {$_ -in @('LEFT','LEFTARROW','PAGEUP','P')}{$page=[Math]::Max(0,$page-1)}
                'HOME'{$page=0} 'END'{$page=$frame.PageCount-1}
                'M'{
                    if($Plan){
                        $replacement=New-AGAutoRepairPlan -Snapshot (Get-AGRepairSnapshot) -Analysis $Analysis -Mode $Plan.Mode -Deep:$Plan.Deep -IncludeMachineProxy:(-not $Plan.IncludeMachineProxy) -StrategyFile $Plan.StrategyFile
                        foreach($p in $replacement.PSObject.Properties){$Plan|Add-Member NoteProperty $p.Name $p.Value -Force}
                        $Lines=@(Get-AGVerdictLines $Analysis $Plan);$page=0;$seen=@{};$oldSize=''
                    }
                }
                'D'{if($Analysis){Show-AGReportDetails -Analysis $Analysis -NextSteps @();$oldSize='';$seen=@{}}}
            }
        }
    }finally{Clear-Host}
}
function Read-AGExpressKeyOrResize {
    param([int]$Width,[int]$Height)
    try{
        while(-not [Console]::KeyAvailable){
            Start-Sleep -Milliseconds 80
            if([Console]::WindowWidth -ne $Width -or [Console]::WindowHeight -ne $Height){return 'REDRAW'}
        }
        return (Read-AGExpressKey)
    }catch{return (Read-AGExpressKey)}
}
function Show-AGExpressVerdict {
    param($Analysis,$Plan)
    return (Show-AGRepairPlanReview -Lines @(Get-AGVerdictLines $Analysis $Plan) -Analysis $Analysis -Plan $Plan)
}
