#Requires -Version 5.1
. "$PSScriptRoot/console-input.ps1"
# Separate export workflows; building a config never applies settings to this PC.
function Show-AGWizardStep {
    param([string]$Title)
    Clear-Host
    Write-Host $Title -ForegroundColor Cyan
}
function Get-AGStrategyFiles {
    param([string]$Root)
    $natural={
        $name=$_.Name
        $prefix=if($name -ieq 'general.bat'){'0'}else{'1'}
        $prefix+[regex]::Replace($name.ToLowerInvariant(),'\d+',[Text.RegularExpressions.MatchEvaluator]{param($m)$m.Value.PadLeft(10,'0')})
    }
    return @(Get-ChildItem -LiteralPath $Root -Filter '*.bat' -File | Where-Object{$_.Name -notlike 'service*'}|Sort-Object $natural)
}
function Read-AGStrategyChoice {
    param([string]$Title='Выбор стратегии Zapret')
    if(-not (Get-Command Get-AGAuditFrame -CommandType Function -ErrorAction SilentlyContinue)){. "$PSScriptRoot/audit-view.ps1"}
    $root=Get-ZapretPath;$bats=@(Get-AGStrategyFiles $root)
    if(-not $bats.Count){throw 'Локальных BAT-стратегий нет. Установите Zapret отдельно.'}
    $rows=@();for($i=0;$i -lt $bats.Count;$i++){$rows+="$($i+1). $($bats[$i].Name)"}
    $sections=@([pscustomobject]@{Title=$Title;Lines=$rows});$page=0;$oldSize=''
    while($true){
        $size=Get-AGAuditConsoleSize;$frame=Get-AGAuditFrame -Sections $sections -Section 0 -Page $page -Width $size.Width -Height $size.Height
        $page=$frame.Page;$sizeKey="$($size.Width)x$($size.Height)"
        if($frame.Lines.Count){$frame.Lines[$frame.Lines.Count-1]=Limit-AGAuditLine 'N/P: лист; номер; Enter: отмена' ([Math]::Max(1,$size.Width-1))}
        Write-AGTextFrame $frame -Reset:($sizeKey -ne $oldSize);$oldSize=$sizeKey
        $text=ConvertTo-AGCommandKey (Read-AGInput '>')
        if($text -in @('','0')){return $null}
        if($text -match '^(?i:n|т)$'){$page=[Math]::Min($frame.PageCount-1,$page+1);continue}
        if($text -match '^(?i:p|з)$'){$page=[Math]::Max(0,$page-1);continue}
        $number=0
        if([int]::TryParse($text,[ref]$number) -and $number -ge 1 -and $number -le $bats.Count){return $bats[$number-1].Name}
        # Invalid input stays on the same page; no history spam or extra pause.
    }
}
function Read-AGConfigStepChoice {
    param([string]$Title,[string[]]$Options)
    if(Test-AGInteractiveUi){return (Read-AGListChoice -Title $Title -Options $Options)}
    Show-AGWizardStep $Title
    for($i=0;$i -lt $Options.Count;$i++){Write-Host "$($i+1). $($Options[$i])"}
    Write-Host 'Enter / 0 — отмена'
    $text=(Read-AGInput '>').Trim()
    if($text -in @('','0')){return 0}
    $number=0
    if(-not [int]::TryParse($text,[ref]$number) -or $number -lt 1 -or $number -gt $Options.Count){throw 'Неверный номер шага. Ничего не сохранено и не применено.'}
    return $number
}
function Invoke-AGConfigExportWizard {
    $type=Read-AGConfigStepChoice 'Новый конфиг — выберите тип' @('Zapret: стратегия, домены, профиль Unlocker','VPN / прокси: профиль Unlocker и DNS')
    if(-not $type){return $false}
    $strategy='';$adapter=0;$profile='Current';$proxy='';$selected=@();$build=$null
    if($type -eq 1){
        $strategy=Read-AGStrategyChoice -Title 'Zapret — шаг 1/5: стратегия'
        if(-not $strategy){return $false};$selected+= 'ZapretStrategy'
        $lists=Read-AGConfigStepChoice 'Zapret — шаг 2/5: домены' @('Включить текущие списки доменов','Только стратегия, без списков')
        if(-not $lists){return $false};if($lists -eq 1){$selected+='ZapretLists'}
        $unlocker=Read-AGConfigStepChoice 'Zapret — шаг 3/5: Unlocker' @('Добавить профиль Zapret (для загрузки вместе со стратегией)','Без профиля Unlocker')
        if(-not $unlocker){return $false};if($unlocker -eq 1){$selected+='Unlocker';$profile='Zapret'}
        $title='Zapret'
    }else{
        $mode=Read-AGConfigStepChoice 'VPN — шаг 1/5: подключение' @('Мой VPN уже установлен и включён','Свой HTTP/HTTPS/SOCKS5 прокси')
        if(-not $mode){return $false};$selected=@('Unlocker');$profile='VPN'
        if($mode -eq 2){
            $profile='OwnProxy';Show-AGWizardStep 'VPN — адрес своего прокси'
            $proxy=(Read-AGInput 'URL без логина/пароля (Enter — отмена)').Trim();if(-not $proxy){return $false};$null=Test-AGBuildProxy $proxy
        }
        $dns=Read-AGConfigStepChoice 'VPN — шаг 2/5: DNS' @('Не менять DNS — рекомендуется, если не знаете, что выбрать','Сохранить DNS моего VPN (адреса серверов поиска сайтов)')
        if(-not $dns){return $false}
        if($dns -eq 2){Show-AGWizardStep 'VPN — шаг 3/5: адаптер';$value=Read-AGBuildAdapter;if($null -eq $value){return $false};$adapter=$value;$selected+='VpnDns'}
        $title='VPN'
    }
    Show-AGWizardStep "$title — шаг 4/5: имя конфига"
    $name=(Read-AGInput 'Название (Enter — отмена)').Trim();if(-not $name){return $false}
    try{$build=New-AGBuild -Name $name -Components $selected -StrategyFile $strategy -DnsInterfaceIndex $adapter -ProfileMode $profile -ProxyUrl $proxy}
    catch{
        if('ZapretLists' -notin $selected -or $_.Exception.Message -notlike 'СПИСОК:*'){throw}
        Show-AGWizardStep 'Список доменов требует внимания'
        Write-Warning $_.Exception.Message
        Write-Host 'Исходные файлы не изменены. Непонятные строки не удаляются молча.'
        $choice=Read-AGInput '1 — сохранить БЕЗ списков; Enter — отмена'
        if($choice -ne '1'){return $false}
        $selected=@($selected|Where-Object{$_ -ne 'ZapretLists'})
        $build=New-AGBuild -Name $name -Components $selected -StrategyFile $strategy -ProfileMode $profile
    }
    Show-AGWizardStep "$title — шаг 5/5: просмотр и сохранение"
    Show-AGBuild $build -Paged:(Test-AGInteractiveUi)
    Write-Warning 'Это конфиг настроек, не установщик VPN/Zapret. Проверьте адреса и домены перед передачей.'
    $path=Read-AGBuildPath 'Куда сохранить .agconfig.json (Enter — отмена)';if(-not $path){return $false}
    if(-not (Confirm-Change 'Сохранить этот конфиг? На этом ПК ничего не применяется.')){return $false}
    $out=Write-AGBuild -Build $build -Path $path;Write-Host "Сохранено: $out";return $true
}
