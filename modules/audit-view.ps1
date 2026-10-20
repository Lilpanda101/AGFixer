#Requires -Version 5.1
. "$PSScriptRoot/console-input.ps1"
# Snapshot viewer only. No network refresh or system changes; explicit S saves a local text report.
function ConvertTo-AGAuditText {
    param([AllowNull()]$Value)
    $text=if($null -eq $Value){'—'}else{[string]$Value}
    # Do not let paths/comments send terminal controls or bidi overrides to the console.
    return [regex]::Replace($text,'[\p{Cc}\p{Cf}]',' ')
}
function Get-AGAuditGlyphs {
    param([string]$Text)
    $enumerator=[Globalization.StringInfo]::GetTextElementEnumerator((ConvertTo-AGAuditText $Text))
    while($enumerator.MoveNext()){
        $glyph=$enumerator.GetTextElement();$code=[char]::ConvertToUtf32($glyph,0)
        $category=[Globalization.CharUnicodeInfo]::GetUnicodeCategory($glyph,0)
        $cells=1
        if($category -in @([Globalization.UnicodeCategory]::NonSpacingMark,[Globalization.UnicodeCategory]::EnclosingMark)){$cells=0}
        elseif(($code -ge 0x1100 -and $code -le 0x115f) -or ($code -ge 0x2329 -and $code -le 0x232a) -or ($code -ge 0x2e80 -and $code -le 0xa4cf) -or ($code -ge 0xac00 -and $code -le 0xd7a3) -or ($code -ge 0xf900 -and $code -le 0xfaff) -or ($code -ge 0xfe10 -and $code -le 0xfe6f) -or ($code -ge 0xff01 -and $code -le 0xff60) -or ($code -ge 0xffe0 -and $code -le 0xffe6) -or ($code -ge 0x2600 -and $code -le 0x27bf) -or $glyph.Contains([string][char]0xfe0f) -or $code -ge 0x1f000){$cells=2}
        [pscustomobject]@{Text=$glyph;Cells=$cells}
    }
}
function Split-AGAuditLine {
    param([AllowEmptyString()][string]$Text,[int]$Width)
    $width=[Math]::Max(1,$Width);$line='';$used=0
    foreach($glyph in @(Get-AGAuditGlyphs $Text)){
        if($used+$glyph.Cells -gt $width -and $line.Length){$line;$line='';$used=0}
        if($glyph.Cells -gt $width){$line+='?';$used++}else{$line+=$glyph.Text;$used+=$glyph.Cells}
    }
    if($line.Length){$line}elseif(-not $Text){''}
}
function Limit-AGAuditLine {
    param([string]$Text,[int]$Width)
    $line='';$used=0
    foreach($glyph in @(Get-AGAuditGlyphs $Text)){if($used+$glyph.Cells -gt $Width){break};$line+=$glyph.Text;$used+=$glyph.Cells}
    return $line
}
function Get-AGAuditConsoleSize {
    $width=0;$height=0
    try{$width=[Console]::WindowWidth;$height=[Console]::WindowHeight}catch{}
    if($width -lt 1 -or $height -lt 1){try{$size=$Host.UI.RawUI.WindowSize;$width=$size.Width;$height=$size.Height}catch{}}
    if($width -lt 1){$width=80};if($height -lt 1){$height=24}
    return [pscustomobject]@{Width=$width;Height=$height}
}
function Get-AGAuditSections {
    param($Audit)
    $sections=New-Object 'System.Collections.Generic.List[object]'
    $contents=@('1. Сводка','2. Время запуска','3. Порты и прокси','4. Адаптеры и DNS','5. Hosts и NRPT','6. Zapret: Game Filter / IPSet','7. Домены Zapret','8. Ошибки и ограничения','N / стрелка вправо: следующая страница','P / стрелка влево: предыдущая','Home / End: первая / последняя','Цифра 0-8: перейти в раздел','S: сохранить весь снимок в TXT','Enter / Esc / Q: назад в меню','Изменили размер окна? Нажмите любую клавишу.','Прокрутка мышью не нужна. Снимок не обновляется автоматически.')
    $sections.Add([pscustomobject]@{Title='Разделы';Lines=$contents})
    $ag=@($Audit.Processes|Where-Object{$_.Name -in @('ag_dns','dns_ai')})
    $summary=@("Снимок: $($Audit.CollectedAt)","Процессы: $(@($Audit.Processes).Count); задачи: $(@($Audit.Tasks).Count)","ag_dns/dns_ai: $($ag.Count)","Порты TCP/UDP: $(@($Audit.Listeners).Count)","Прокси-кандидаты: $(@($Audit.ProxyCandidates).Count)","NRPT: $(@($Audit.NRPT).Count); hosts: $(@($Audit.Hosts).Count)")
    if($Audit.Zapret){
        $coverage=@($Audit.Zapret.DomainCoverage);$inc=@($coverage|Where-Object{$_.InKnownIncludeFiles}).Count;$exc=@($coverage|Where-Object{$_.InKnownExcludeFiles}).Count
        $summary+="Zapret: данные есть; Game Filter: $($Audit.Zapret.GameFilter.Mode)"
        $summary+="Домены: include $inc/$($coverage.Count); exclude $exc/$($coverage.Count)"
    }else{$summary+='Zapret: нет данных (см. раздел 8)'}
    $summary+="Ошибки сбора: $(@($Audit.CollectionIssues).Count) (раздел 8)"
    $summary+='Наличие порта/NRPT не доказывает исправность.'
    $summary+='Ничего не меняем: это только просмотр. 0 — выбрать раздел.'
    $summary+='DNS — поиск адресов сайтов; адаптер — сетевое подключение.'
    $summary+='hosts и NRPT — локальные правила, которые могут менять поиск адресов.'
    $summary+='Список портов показывает программы, но не доказывает работу прокси.'
    $sections.Add([pscustomobject]@{Title='Сводка';Lines=$summary})
    $lines=@('Начало текущего сеанса запущенных программ:')
    foreach($group in @(@{Title='Antigravity';Names=@('Antigravity','Antigravity IDE','agy')},@{Title='Unlocker';Names=@('AntigravityUnlocker','AGUnlocker','Antigravity Unlocker')},@{Title='Сетевая часть ag_dns';Names=@('ag_dns','dns_ai')})){
        $times=@($Audit.Processes|Where-Object{$_.Name -in $group.Names}|ForEach-Object{$_.Started}|Where-Object{$_}|Sort-Object|Select-Object -First 1)
        $value=if($times.Count){[string]$times[0]}else{'нет запущенного процесса / время недоступно'}
        $lines+=($group.Title+': '+$value)
    }
    $lines+='Последний запуск задач Unlocker:'
    foreach($t in @($Audit.Tasks)){$value=if($t.LastRunTime){[string]$t.LastRunTime}else{'нет данных'};$lines+=($t.Name+': '+$value)}
    $sections.Add([pscustomobject]@{Title='Время запуска';Lines=$lines})
    $lines=@('Слушающие порты:')
    foreach($group in @($Audit.Listeners|Group-Object Protocol,Address,Port,PID,Owner)){
        $p=$group.Group[0];$repeats=if($group.Count -gt 1){" (x$($group.Count))"}else{''}
        $lines+="$($p.Protocol) $($p.Address):$($p.Port) | PID $($p.PID) $($p.Owner)$repeats"
    }
    if(-not @($Audit.Listeners).Count){$lines+='Не найдены / нет данных.'}
    $lines+='Кандидаты прокси (протокол не доказан):'
    foreach($group in @($Audit.ProxyCandidates|Group-Object Address,Port,PID)){$p=$group.Group[0];$repeats=if($group.Count -gt 1){" (x$($group.Count))"}else{''};$lines+="$($p.Address):$($p.Port) | PID $($p.PID)$repeats"}
    if(-not @($Audit.ProxyCandidates).Count){$lines+='Нет кандидатов.'}
    $sections.Add([pscustomobject]@{Title='Порты/прокси';Lines=$lines})
    $lines=@('Адаптеры:')
    foreach($a in @($Audit.Adapters)){$lines+="[$($a.InterfaceIndex)] $($a.Name): $($a.Status)";$lines+="  $($a.InterfaceDescription)"}
    if(-not @($Audit.Adapters).Count){$lines+='Нет данных.'}
    $lines+='DNS адаптеров:'
    foreach($d in @($Audit.DNS)){$family=if($d.AddressFamily -eq 2){'IPv4'}elseif($d.AddressFamily -eq 23){'IPv6'}else{[string]$d.AddressFamily};$lines+="[$($d.InterfaceIndex)] $($d.InterfaceAlias) $family";$lines+=(@($d.ServerAddresses) -join ', ')}
    if(-not @($Audit.DNS).Count){$lines+='Нет данных.'}
    $sections.Add([pscustomobject]@{Title='Адаптеры/DNS';Lines=$lines})
    $lines=@('Hosts (только относящиеся к Google):')
    foreach($h in @($Audit.Hosts)){$lines+="$($h.Domain) -> $($h.Address)";$lines+=[string]$h.Note}
    if(-not @($Audit.Hosts).Count){$lines+='Совпадений нет / данные недоступны.'}
    $lines+='NRPT (эффективные правила):'
    foreach($r in @($Audit.NRPT)){
        $lines+=(@($r.Namespace) -join ', ');$lines+=('DNS: '+(@($r.NameServers) -join ', '))
        if($r.DirectAccessDnsServers){$lines+=('DirectAccess: '+(@($r.DirectAccessDnsServers) -join ', '))}
        if($r.Comment){$lines+=('Комментарий: '+$r.Comment)}
    }
    if(-not @($Audit.NRPT).Count){$lines+='Совпадений нет / данные недоступны.'}
    $sections.Add([pscustomobject]@{Title='Hosts/NRPT';Lines=$lines})
    $lines=@()
    if($Audit.Zapret){
        $z=$Audit.Zapret;$g=$z.GameFilter
        $lines+="Game Filter: $($g.Mode)";if($g.Schema){$lines+="Схема: $($g.Schema)"}
        if($g.Reason){$lines+="Причина: $($g.Reason)"}
        if($g.TCP){$lines+="TCP: $($g.TCP)"};if($g.UDP){$lines+="UDP: $($g.UDP)"};if($g.Legacy){$lines+="Legacy: $($g.Legacy)"};if($g.Source){$lines+="Источник: $($g.Source)"}
        $lines+="IPSet: $($z.IPSetMode)"
        foreach($f in @($z.IPSetFiles)){$lines+="$($f.Name): $($f.Bytes) байт; $($f.Modified)"}
        $lines+='Файлы списков:'
        foreach($f in @($z.Files)){$lines+="$($f.Name): $($f.Status) $($f.Modified)"}
    }else{$lines+='Данные Zapret недоступны. См. раздел 8.'}
    $sections.Add([pscustomobject]@{Title='Zapret';Lines=$lines})
    $lines=@('include — найден в известных списках.', 'exclude — совпадение требует проверки стратегии.')
    foreach($d in @($Audit.Zapret.DomainCoverage|Where-Object{$null -ne $_})){
        $inc=if($d.InKnownIncludeFiles){'да'}else{'нет'};$exc=if($d.InKnownExcludeFiles){'да'}else{'нет'}
        $lines+=[string]$d.Domain;$lines+="  include: $inc; exclude: $exc"
        if(@($d.IncludePatterns).Count){$lines+=('  + '+(@($d.IncludePatterns) -join ', '))}
        if(@($d.ExcludePatterns).Count){$lines+=('  - '+(@($d.ExcludePatterns) -join ', '))}
    }
    if(-not @($Audit.Zapret.DomainCoverage|Where-Object{$null -ne $_}).Count){$lines+='Нет данных по доменам.'}
    $sections.Add([pscustomobject]@{Title='Домены Zapret';Lines=$lines})
    $lines=@('Ошибки сбора (не скрываются):')
    if(@($Audit.CollectionIssues).Count){$lines+=@($Audit.CollectionIssues)}else{$lines+='Ошибок сбора не зарегистрировано.'}
    if($Audit.Zapret.Limit){$lines+=[string]$Audit.Zapret.Limit}
    $lines+=[string]$Audit.Limits
    $lines+='Нет автоматического исправления. Пустой раздел при ошибке сбора — не подтверждение отсутствия проблемы.'
    $lines+='S сохраняет локальный TXT со всеми разделами. Файл содержит пути/IP: проверьте перед передачей.'
    $sections.Add([pscustomobject]@{Title='Ошибки/ограничения';Lines=$lines})
    return @($sections.ToArray())
}
function Test-AGReadableHeading {
    param([string]$Text)
    return ($Text -match '^=== .+ ===$' -or $Text -in @('Мой гайд','Моя форма','Материалы сообщества','Перед началом','Что ВЫКЛЮЧИТЬ в Unlocker','Что оставить ВКЛЮЧЁННЫМ','Пошаговая настройка','Как понять, что работает','Если не заработало','Чего не делать','Источники'))
}
function Get-AGReadablePages {
    param([string[]]$Lines,[int]$Width,[int]$Capacity)
    $wrapped=New-Object 'Collections.Generic.List[object]'
    foreach($line in $Lines){
        $heading=Test-AGReadableHeading $line
        if($heading -and $wrapped.Count -and $wrapped[$wrapped.Count-1].Text -ne ''){$wrapped.Add([pscustomobject]@{Text='';Heading=$false})}
        foreach($part in @(Split-AGAuditLine $line $Width)){$wrapped.Add([pscustomobject]@{Text=$part;Heading=$heading})}
        if($heading){$wrapped.Add([pscustomobject]@{Text='';Heading=$false})}
    }
    if(-not $wrapped.Count){$wrapped.Add([pscustomobject]@{Text='Нет данных.';Heading=$false})}
    $pages=New-Object 'Collections.Generic.List[object]';$body=New-Object 'Collections.Generic.List[string]';$colors=New-Object 'Collections.Generic.List[int]'
    for($i=0;$i -lt $wrapped.Count;$i++){
        $row=$wrapped[$i]
        if($row.Heading -and ($i -eq 0 -or -not $wrapped[$i-1].Heading)){
            $end=$i;while($end -lt $wrapped.Count -and $wrapped[$end].Heading){$end++}
            $need=[Math]::Min($Capacity,($end-$i)+2)
            if($body.Count -and $Capacity-$body.Count -lt $need){
                while($body.Count -and $body[$body.Count-1] -eq ''){$body.RemoveAt($body.Count-1)}
                $pages.Add([pscustomobject]@{Body=$body.ToArray();Headings=$colors.ToArray()});$body=New-Object 'Collections.Generic.List[string]';$colors=New-Object 'Collections.Generic.List[int]'
            }
        }
        if(-not $body.Count -and $row.Text -eq ''){continue}
        if($row.Heading){$colors.Add($body.Count)};$body.Add($row.Text)
        if($body.Count -eq $Capacity){$pages.Add([pscustomobject]@{Body=$body.ToArray();Headings=$colors.ToArray()});$body=New-Object 'Collections.Generic.List[string]';$colors=New-Object 'Collections.Generic.List[int]'}
    }
    while($body.Count -and $body[$body.Count-1] -eq ''){$body.RemoveAt($body.Count-1)}
    if($body.Count -or -not $pages.Count){$pages.Add([pscustomobject]@{Body=$body.ToArray();Headings=$colors.ToArray()})}
    return $pages.ToArray()
}
function Get-AGAuditFrame {
    param([object[]]$Sections,[int]$Section=1,[int]$Page=0,[int]$Width=80,[int]$Height=24,[string]$Notice)
    $safeWidth=[Math]::Max(1,$Width-1)
    if($Width -lt 24 -or $Height -lt 8){
        $lines=@((Limit-AGAuditLine 'Нужно окно от 24x8' $safeWidth),(Limit-AGAuditLine 'Enter: назад' $safeWidth))
        return [pscustomobject]@{Lines=@($lines|Select-Object -First ([Math]::Max(1,$Height-1)));Page=0;PageCount=1;TooSmall=$true;ViewportWidth=$Width;ViewportHeight=$Height;HeadingRows=@()}
    }
    $section=[Math]::Max(0,[Math]::Min($Sections.Count-1,$Section))
    $readable=$Height -ge 12
    $capacity=if($readable){$Height-7}else{$Height-4}
    $content=@();if($Notice){$content+=$Notice};$content+=@($Sections[$section].Lines)
    if($readable){$pages=@(Get-AGReadablePages -Lines $content -Width $safeWidth -Capacity $capacity)}else{
        # Tiny legacy view keeps all path characters reachable, sacrificing only decorative spacing.
        $wrapped=@(foreach($line in $content){if(-not [string]::IsNullOrWhiteSpace($line)){Split-AGAuditLine $line $safeWidth}})
        if(-not $wrapped.Count){$wrapped=@('Нет данных.')}
        $pages=@(for($i=0;$i -lt $wrapped.Count;$i+=$capacity){[pscustomobject]@{Body=@($wrapped[$i..([Math]::Min($wrapped.Count-1,$i+$capacity-1))]);Headings=@()}})
    }
    $page=[Math]::Max(0,[Math]::Min($pages.Count-1,$Page));$selected=$pages[$page]
    $caption=if($pages.Count -gt 1){"$($Sections[$section].Title) — стр. $($page+1) из $($pages.Count)"}else{$Sections[$section].Title}
    $lines=@((Limit-AGAuditLine $caption $safeWidth));$headingRows=@(0)
    if($readable){$lines+=@(('-'*$safeWidth),'');$headingRows+=@($selected.Headings|ForEach-Object{$_+3})}
    $lines+=@($selected.Body)
    if($readable){while($lines.Count -lt $Height-4){$lines+=''};$lines+=@('',('-'*$safeWidth))}
    $footer=if($Width -ge 60){'N/P: стр. | 0: разделы | 1-8: выбор | S: TXT | Enter: назад'}elseif($Width -ge 24){'N/P | 0 | S:TXT | Enter:назад'}else{'N/P | 0 | S | Enter'}
    if($Width -lt 34){$footer='N/P | 0 | S | Enter:назад'}
    if($pages.Count -eq 1){$footer=if($Width -lt 40){'Enter/Esc:назад | S:TXT'}else{'Enter/Esc: назад | S: сохранить TXT'}}
    $lines+=(Limit-AGAuditLine $footer $safeWidth)
    return [pscustomobject]@{Lines=$lines;Page=$page;PageCount=$pages.Count;TooSmall=$false;ViewportWidth=$Width;ViewportHeight=$Height;HeadingRows=$headingRows;BodyLines=@($selected.Body);BodyHeadingRows=@($selected.Headings);BodyCapacity=$capacity}
}
function ConvertTo-AGAuditCommand {
    param([string]$Value)
    $key=ConvertTo-AGCommandKey $Value
    switch($key){
        {$_ -in @('RIGHT','PAGEDOWN','DOWN')}{return 'N'}
        {$_ -in @('LEFT','PAGEUP','UP')}{return 'P'}
        {$_ -in @('ENTER','ESC','')}{return 'Q'}
        {$_ -in @('N','P','S','Q','F','D','HOME','END')}{return $key}
        default{if($key -match '^[0-8]$'){return $key};return 'REDRAW'}
    }
}
function Read-AGAuditKey {
    try{
        $viewWidth=[Console]::WindowWidth;$viewHeight=[Console]::WindowHeight
        while(-not [Console]::KeyAvailable){
            Start-Sleep -Milliseconds 80
            if([Console]::WindowWidth -ne $viewWidth -or [Console]::WindowHeight -ne $viewHeight){return 'REDRAW'}
        }
        return (ConvertTo-AGAuditCommand (ConvertFrom-AGConsoleKey ([Console]::ReadKey($true))))
    }catch{
        # ISE/redirected hosts: normalize only the command, never general Read-Host input.
        return (ConvertTo-AGAuditCommand (Read-Host '>'))
    }
}
function Save-AGAuditText {
    param([object[]]$Sections)
    if(-not $env:LOCALAPPDATA){throw 'LOCALAPPDATA не определён.'}
    $folder=Join-Path $env:LOCALAPPDATA 'AGFixer/audit-reports';$null=New-Item -ItemType Directory -Path $folder -Force -ErrorAction Stop
    $path=Join-Path $folder ('audit-'+[datetime]::UtcNow.ToString('yyyyMMdd-HHmmss')+'-'+[guid]::NewGuid().ToString('N').Substring(0,8)+'.txt')
    $lines=@('AGFixer — локальный снимок, только чтение. Содержит приватные пути/IP; проверяйте перед передачей.')
    for($i=1;$i -lt $Sections.Count;$i++){$lines+="=== $i. $($Sections[$i].Title) ===";foreach($line in @($Sections[$i].Lines)){$lines+=ConvertTo-AGAuditText $line}}
    $bytes=(New-Object Text.UTF8Encoding($true)).GetPreamble()+(New-Object Text.UTF8Encoding($false)).GetBytes(($lines -join "`r`n"))
    $stream=[IO.File]::Open($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try{$stream.Write($bytes,0,$bytes.Length);$stream.Flush()}finally{$stream.Dispose()}
    return $path
}
function Show-AGAuditViewer {
    param($Audit)
    $sections=@(Get-AGAuditSections $Audit)
    while($true){
        $items=@($sections|Select-Object -Skip 1|ForEach-Object{$_.Title})+@('Сохранить весь снимок в TXT')
        $choice=Read-AGListChoice -Title 'Состояние сети — разделы' -Options $items
        if(-not $choice){return}
        if($choice -eq $items.Count){
            try{$path=Save-AGAuditText $sections;Show-AGTextPages -Title 'Снимок сохранён' -Lines @($path,'Перед отправкой проверьте приватные пути и IP.')}catch{Show-AGTextPages -Title 'Не удалось сохранить' -Lines @($_.Exception.Message)}
            continue
        }
        Show-AGTextPages -Title $sections[$choice].Title -Lines $sections[$choice].Lines
    }
}
