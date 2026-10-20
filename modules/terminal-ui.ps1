#Requires -Version 5.1
. "$PSScriptRoot/console-input.ps1"
# Native Console/PowerShell 5.1 only. Rendering and navigation are pure and testable.
# No system mutation is performed by this module or by highlighting an item.
function Test-AGTerminalInput {
    try{if(-not(Test-AGInteractiveUi) -or [Console]::IsInputRedirected -or [Console]::IsOutputRedirected){return $false};$null=[Console]::KeyAvailable;return $true}catch{return $false}
}
function Read-AGTerminalKey {
    return (ConvertFrom-AGConsoleKey ([Console]::ReadKey($true)))
}
function Read-AGTerminalKeyOrResize {
    param([int]$Width,[int]$Height)
    while(-not [Console]::KeyAvailable){
        Start-Sleep -Milliseconds 80
        if([Console]::WindowWidth -ne $Width -or [Console]::WindowHeight -ne $Height){return 'REDRAW'}
    }
    return (Read-AGTerminalKey)
}
function Get-AGChoiceDetailLines {
    param([string[]]$Intro=@(),[string]$Label,[object]$Item)
    $lines=@($Intro)+@('','Выбранный пункт:',$Label)
    if($Item){
        foreach($name in @('Hint','Action','Path','Value')){
            $property=$Item.PSObject.Properties[$name]
            if($property -and -not [string]::IsNullOrWhiteSpace([string]$property.Value)){
                $caption=@{Hint='Описание';Action='Действие';Path='Путь';Value='Значение'}[$name]
                $lines+="$caption`: $([string]$property.Value)"
            }
        }
    }
    return $lines
}
function ConvertTo-AGTerminalText {
    param([AllowNull()][string]$Text)
    # Do not permit report/path content to inject terminal control sequences.
    return ($Text -replace '[\p{Cc}\p{Cf}]',' ')
}
function Add-AGUiJournal {
    param([string]$Text)
    if(-not(Get-Variable AGUiJournal -Scope Script -ErrorAction SilentlyContinue)){$script:AGUiJournal=@()}
    $clean=ConvertTo-AGTerminalText $Text
    $script:AGUiJournal=@(@($script:AGUiJournal)+((Get-Date -Format 'HH:mm')+'  '+$clean)|Select-Object -Last 20)
}
function Get-AGTuiFrame {
    param([string]$Title,[object[]]$Items,[int]$Selected=0,[int]$Offset=0,[string[]]$Status=@(),[string[]]$Journal=@(),[string]$Hint='',[int]$Width=80,[int]$Height=25,[switch]$Root,[switch]$AllowAll)
    $safeWidth=[Math]::Max(1,$Width-1);$safeHeight=[Math]::Max(1,$Height-1)
    $rows=New-Object 'System.Collections.Generic.List[object]'
    if($Width -lt 32 -or $Height -lt 12){
        foreach($line in @('AGFixer by txmui','Увеличьте окно: минимум 32 x 12.','Esc — назад')){if($rows.Count -lt $safeHeight){$rows.Add([pscustomobject]@{Text=(Limit-AGAuditLine $line $safeWidth);Role='Hint'})}}
        return [pscustomobject]@{Rows=$rows.ToArray();Selected=0;Offset=0;Capacity=0;TooSmall=$true;Width=$safeWidth;Height=$safeHeight}
    }
    $selected=[Math]::Max(0,[Math]::Min([Math]::Max(0,$Items.Count-1),$Selected))
    $rows.Add([pscustomobject]@{Text='AGFixer by txmui';Role='Brand'})
    $rows.Add([pscustomobject]@{Text=(ConvertTo-AGTerminalText $Title);Role='Title'})
    $compact=$Height -lt 18
    if($Height -ge 25){$rows.Add([pscustomobject]@{Text='';Role='Gap'})}
    $statusLimit=if($compact){1}else{3}
    foreach($line in @($Status|Select-Object -First $statusLimit)){$rows.Add([pscustomobject]@{Text=(ConvertTo-AGTerminalText $line);Role='Status'})}
    $rows.Add([pscustomobject]@{Text=('─'*$safeWidth);Role='Rule'})
    $rows.Add([pscustomobject]@{Text='';Role='Gap'})
    $bottom=New-Object 'Collections.Generic.List[object]'
    $bottom.Add([pscustomobject]@{Text=('─'*$safeWidth);Role='Rule'})
    if(-not $compact){$bottom.Add([pscustomobject]@{Text='';Role='Gap'})}
    $hintLimit=if($compact){1}elseif($Height -lt 28){2}else{3}
    $hintRows=@(Split-AGAuditLine (ConvertTo-AGTerminalText $Hint) $safeWidth)
    if($hintRows.Count -gt $hintLimit){$hintRows=@($hintRows|Select-Object -First $hintLimit);$hintRows[-1]=(Limit-AGAuditLine $hintRows[-1] ($safeWidth-1))+'…'}
    foreach($line in $hintRows){$bottom.Add([pscustomobject]@{Text=$line;Role='Hint'})}
    if($Height -ge 24){
        $bottom.Add([pscustomobject]@{Text='';Role='Gap'})
        $bottom.Add([pscustomobject]@{Text=('Журнал '+('─'*$safeWidth));Role='Rule'})
        $last=if($Journal.Count){[string]$Journal[$Journal.Count-1]}else{'Ожидание действия. Выделение пункта ничего не меняет.'}
        $bottom.Add([pscustomobject]@{Text=(ConvertTo-AGTerminalText $last);Role='Journal'})
        $bottom.Add([pscustomobject]@{Text='';Role='Gap'})
    }
    if(-not $compact){$bottom.Add([pscustomobject]@{Text=('─'*$safeWidth);Role='Rule'})}
    $back=if($Root){'Esc: выход'}else{'Esc: назад'}
    $footer='↑↓ выбор | Enter: открыть | '+$back
    if($Width -lt 55){$footer='↑↓ | Enter | '+$back}
    if($AllowAll){$footer=if($Width -lt 55){'↑↓ | Space:метка | A:все | Esc:назад'}else{'↑↓ выбор | Space: отметить | A: все | Esc: отмена'}}
    if(-not $Root){$footer=if($Width -lt 40){if($AllowAll){'↑↓ | Space | A:все | Esc:назад'}else{'↑↓ | Enter | Esc:назад'}}else{if($AllowAll){'↑↓ | Space | A:все | Esc:назад'}else{'↑↓ | Enter:выбор | Esc:назад'}}}
    if($Width -lt 40){$footer=if($AllowAll){'↑↓ | Space | A | Esc:назад'}else{'↑↓ | Enter | '+$back}}
    $bottom.Add([pscustomobject]@{Text=$footer;Role='Footer'})
    $capacity=[Math]::Max(1,$safeHeight-$rows.Count-$bottom.Count)
    $offset=[Math]::Max(0,[Math]::Min([Math]::Max(0,$Items.Count-$capacity),$Offset))
    if($selected -lt $offset){$offset=$selected};if($selected -ge $offset+$capacity){$offset=$selected-$capacity+1}
    for($i=$offset;$i -lt [Math]::Min($Items.Count,$offset+$capacity);$i++){
        $prefix=if($i -eq $selected){'› '}else{'  '}
        $rows.Add([pscustomobject]@{Text=($prefix+(ConvertTo-AGTerminalText ([string]$Items[$i].Label)));Role=$(if($i -eq $selected){'Selected'}else{'Item'})})
    }
    while($rows.Count -lt $safeHeight-$bottom.Count){$rows.Add([pscustomobject]@{Text='';Role='Item'})}
    foreach($row in $bottom){$rows.Add($row)}
    foreach($row in $rows){
        $cells=@(Get-AGAuditGlyphs $row.Text|Measure-Object Cells -Sum)[0].Sum
        if($row.Role -eq 'Rule'){$row.Text=Limit-AGAuditLine $row.Text $safeWidth;continue}
        if($cells -gt $safeWidth){$row.Text=(Limit-AGAuditLine $row.Text ([Math]::Max(1,$safeWidth-1)))+'…'}
    }
    return [pscustomobject]@{Rows=$rows.ToArray();Selected=$selected;Offset=$offset;Capacity=$capacity;TooSmall=$false;Width=$safeWidth;Height=$safeHeight}
}
function Write-AGTuiFrame {
    param($Frame,[switch]$Reset)
    # Redraw in place, not a growing stream of Write-Host output.
    if($Reset){Clear-Host}
    try{[Console]::SetCursorPosition(0,[Console]::WindowTop)}catch{Clear-Host}
    foreach($row in $Frame.Rows){
        $text=$row.Text+(' '*[Math]::Max(0,$Frame.Width-((@(Get-AGAuditGlyphs $row.Text|Measure-Object -Property Cells -Sum)[0].Sum))))
        switch($row.Role){
            'Brand'{Write-Host $text -ForegroundColor DarkRed}
            'Selected'{Write-Host $text -ForegroundColor Black -BackgroundColor Gray}
            'Title'{Write-Host $text -ForegroundColor Cyan}
            {$_ -in @('Hint','Rule','Footer')}{Write-Host $text -ForegroundColor DarkGray}
            default{Write-Host $text}
        }
    }
}
function Move-AGTuiSelection {
    param([int]$Selected,[int]$Count,[string]$Key,[int]$Capacity=8)
    if($Count -le 0){return 0}
    switch($Key){'UP'{$Selected--} 'DOWN'{$Selected++} 'LEFT'{$Selected-=$Capacity} 'RIGHT'{$Selected+=$Capacity} 'HOME'{$Selected=0} 'END'{$Selected=$Count-1} 'PAGEUP'{$Selected-=$Capacity} 'PAGEDOWN'{$Selected+=$Capacity}}
    return [Math]::Max(0,[Math]::Min($Count-1,$Selected))
}
function Read-AGTerminalChoice {
    param([string]$Title,[string[]]$Options,[string[]]$Intro=@(),[int]$EnterValue=0,[switch]$AllowAll,[string[]]$Status=@())
    $items=@(for($i=0;$i -lt $Options.Count;$i++){[pscustomobject]@{Label=$Options[$i];Value=($i+1)}})
    if($EnterValue -eq -1){$items+=@([pscustomobject]@{Label='Готово — продолжить с отмеченными настройками';Value=-1})}
    if(-not $items.Count){return 0}
    $selected=0;$offset=0;$oldSize='';$cursor=$true
    # Intro is shown in full as a separately scrollable explanation, not silently truncated.
    # Selection dialogs open the list immediately; F1 shows full introductions and item details.
    $hint=($Intro -join ' ')
    # Explanations are available through F1; never put an unsolicited text screen before the choices.
    try{
        try{$cursor=[Console]::CursorVisible;[Console]::CursorVisible=$false}catch{}
        while($true){
            $size=Get-AGAuditConsoleSize;$sizeKey="$($size.Width)x$($size.Height)"
            $frame=Get-AGTuiFrame -Title $Title -Items $items -Selected $selected -Offset $offset -Status $Status -Hint $hint -Width $size.Width -Height $size.Height -AllowAll:$AllowAll -Journal @($script:AGUiJournal)
            Write-AGTuiFrame $frame -Reset:($sizeKey -ne $oldSize);$oldSize=$sizeKey;$offset=$frame.Offset
            # Poll resize without requiring a key first.
            while(-not [Console]::KeyAvailable){Start-Sleep -Milliseconds 80;if([Console]::WindowWidth -ne $size.Width -or [Console]::WindowHeight -ne $size.Height){break}}
            if(-not [Console]::KeyAvailable){continue}
            $key=Read-AGTerminalKey
            if($key -eq 'ESC' -or $key -eq '0'){return 0}
            if($frame.TooSmall){continue}
            if($key -eq 'F1'){Show-AGTextPages -Title ('Карточка: '+$Title) -Lines @(Get-AGChoiceDetailLines -Intro (@($Status)+@($Intro)) -Label $items[$selected].Label -Item $items[$selected]);$oldSize='';continue}
            if($AllowAll -and $key -eq 'A'){return -2}
            if($key -eq 'ENTER' -or ($AllowAll -and $key -eq 'SPACE')){return $items[$selected].Value}
            $selected=Move-AGTuiSelection $selected $items.Count $key $frame.Capacity
        }
    }finally{try{[Console]::CursorVisible=$cursor}catch{};Clear-Host}
}
function Get-AGWorkspaceTree {
    $groups=@(
        @{Id='repair';Label='Исправления';Hint='Выберите ремонт. Перед записью будет показан план.';Items=@(@('17','Проверить настройки и исправить'),@('18','Настроить свой VPN'),@('19','Настроить Zapret'),@('20','Очистить сетевые хвосты'),@('4','Ручные настройки'),@('8','Исправить чёрный экран'))},
        @{Id='reports';Label='Разобрать отчёт Unlocker';Hint='Разбор текста отчёта. Проверка Zapret находится в инструментах.';Items=@(@('1','Отчёт из буфера обмена'),@('2','Открыть TXT-отчёт'))},
        @{Id='tools';Label='Инструменты';Hint='Папки программ, состояния и отдельные сетевые проверки.';Items=@(@('21','Найти или указать папки Unlocker и Zapret'),@('22','Проверить списки Zapret'),@('24','Время запуска Unlocker и Antigravity'),@('3','Состояние сети'),@('5','Проверить TLS-соединение с Google'),@('16','Мой путь подключения'),@('6','Собрать пакет для помощи'))},
        @{Id='configs';Label='Конфиги';Hint='Отдельные настройки Zapret и VPN, выборочный импорт.';Items=@(@('11','Создать конфиг Zapret или VPN'),@('12','Загрузить конфиг из файла'),@('13','Посмотреть конфиг без применения'))},
        @{Id='restore';Label='Резервные копии';Hint='Вернуть сохранённые настройки.';Items=@(@('14','Восстановить настройки Unlocker'),@('15','Восстановить DNS'),@('10','Восстановить графический кэш'))}
    )
    return $groups
}
function Get-AGTreeRows {
    param([string[]]$Expanded=@())
    $rows=@()
    foreach($group in @(Get-AGWorkspaceTree)){
        $mark=if($group.Id -in $Expanded){'[-]'}else{'[+]'}
        $rows+=@([pscustomobject]@{Id=$group.Id;Label="$mark $($group.Label)";Hint=$group.Hint;Kind='Group';Action='';Parent=''})
        if($group.Id -in $Expanded){foreach($item in $group.Items){$rows+=@([pscustomobject]@{Id=('action'+$item[0]);Label=('    '+$item[1]);Hint=$group.Hint;Kind='Action';Action=$item[0];Parent=$group.Id})}}
    }
    $rows+=@([pscustomobject]@{Id='guides';Label='Гайды сообщества';Hint='Мой гайд, моя форма и решения участников с источниками.';Kind='Action';Action='7';Parent=''})
    $rows+=@([pscustomobject]@{Id='refresh';Label='Обновить состояния программ';Hint='Повторно прочитать процессы и сетевые адаптеры.';Kind='Action';Action='25';Parent=''})
    $rows+=@([pscustomobject]@{Id='exit';Label='Выход';Hint='Закрыть AGFixer.';Kind='Action';Action='0';Parent=''})
    return $rows
}
function Read-AGWorkspaceAction {
    param($Status)
    if(-not(Test-AGTerminalInput)){
        # Redirected/unsupported hosts keep an accessible numbered fallback.
        $groups=@(Get-AGWorkspaceTree);$choice=Read-AGListChoice -Title 'AGFixer' -Options (@($groups.Label)+@('Гайды сообщества','Обновить состояния')) -Intro @(Get-AGStatusHeader $Status)
        if(-not $choice){return '0'};if($choice -eq 6){return '7'};if($choice -eq 7){return '25'}
        $group=$groups[$choice-1];$n=Read-AGListChoice -Title $group.Label -Options @($group.Items|ForEach-Object{$_[1]});if($n){return [string]$group.Items[$n-1][0]};return ''
    }
    if(-not(Get-Variable AGTreeExpanded -Scope Script -ErrorAction SilentlyContinue)){$script:AGTreeExpanded=@('repair')}
    if(-not(Get-Variable AGTreeSelected -Scope Script -ErrorAction SilentlyContinue)){$script:AGTreeSelected='action17'}
    $offset=0;$oldSize='';$cursor=$true
    try{
        try{$cursor=[Console]::CursorVisible;[Console]::CursorVisible=$false}catch{}
        while($true){
            $items=@(Get-AGTreeRows $script:AGTreeExpanded);$selected=0
            for($i=0;$i -lt $items.Count;$i++){if($items[$i].Id -eq $script:AGTreeSelected){$selected=$i;break}}
            $size=Get-AGAuditConsoleSize;$sizeKey="$($size.Width)x$($size.Height)"
            $frame=Get-AGTuiFrame -Title 'Исправления и настройки Antigravity' -Items $items -Selected $selected -Offset $offset -Status @(Get-AGStatusHeader -Status $Status -Width $size.Width) -Hint $items[$selected].Hint -Journal @($script:AGUiJournal) -Width $size.Width -Height $size.Height -Root
            Write-AGTuiFrame $frame -Reset:($oldSize -ne $sizeKey);$oldSize=$sizeKey;$offset=$frame.Offset
            while(-not [Console]::KeyAvailable){Start-Sleep -Milliseconds 80;if([Console]::WindowWidth -ne $size.Width -or [Console]::WindowHeight -ne $size.Height){break}}
            if(-not [Console]::KeyAvailable){continue}
            $key=Read-AGTerminalKey
            if($key -in @('ESC','Q','0')){return '0'}
            if($key -eq 'F1'){
                $selectedItem=$items[$selected]
                Show-AGTextPages -Title 'Карточка пункта' -Lines @(Get-AGChoiceDetailLines -Intro @('Главное меню AGFixer.') -Label $selectedItem.Label -Item $selectedItem)
                $oldSize=''
                continue
            }
            if($frame.TooSmall){continue}
            $item=$items[$selected]
            if($key -eq 'LEFT' -and $item.Parent){$script:AGTreeSelected=$item.Parent;$script:AGTreeExpanded=@($script:AGTreeExpanded|Where-Object{$_ -ne $item.Parent});continue}
            if($item.Kind -eq 'Group' -and $key -in @('ENTER','SPACE','LEFT','RIGHT')){
                if($key -eq 'LEFT' -or ($item.Id -in $script:AGTreeExpanded -and $key -ne 'RIGHT')){$script:AGTreeExpanded=@($script:AGTreeExpanded|Where-Object{$_ -ne $item.Id})}
                elseif($item.Id -notin $script:AGTreeExpanded){$script:AGTreeExpanded+=@($item.Id)}
                continue
            }
            if($key -eq 'ENTER' -and $item.Kind -eq 'Action'){return [string]$item.Action}
            $selected=Move-AGTuiSelection $selected $items.Count $key $frame.Capacity;$script:AGTreeSelected=$items[$selected].Id
        }
    }finally{try{[Console]::CursorVisible=$cursor}catch{};Clear-Host}
}
