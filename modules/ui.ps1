#Requires -Version 5.1
. "$PSScriptRoot/console-input.ps1"
. "$PSScriptRoot/audit-view.ps1"
. "$PSScriptRoot/terminal-ui.ps1"
# Display-only helpers. UTF-8 BOM is required for Windows PowerShell 5.1.
function Get-AGBanner {
    return 'AGFixer by txmui'
}
function Show-AGBanner {
    [CmdletBinding()]
    param([ConsoleColor]$Color=[ConsoleColor]::DarkRed)
    Write-Host (Get-AGBanner) -ForegroundColor $Color
}

# Called only after the protected entry point has verified administrator rights.
function Show-AGMenuScreen {
    param([Parameter(Mandatory=$true)][string]$Title)
    Clear-Host
    Show-AGBanner
    Write-Host "=== $Title ===" -ForegroundColor Cyan
    Write-Host ('-'*([Math]::Max(1,(Get-AGMenuViewport).Width-1))) -ForegroundColor DarkGray
    Write-Host ''
}
function Wait-AGMenuReturn {
    $null=Read-AGInput 'Enter — назад в меню'
}

function Get-AGMenuViewport {
    $width=0;$height=0
    try{$width=[Console]::WindowWidth;$height=[Console]::WindowHeight}catch{}
    if($width -le 0){$width=80};if($height -le 0){$height=30}
    return [pscustomobject]@{Width=$width;Height=$height}
}

function Initialize-AGPageTools {
    if(-not(Get-Command Get-AGAuditFrame -ErrorAction SilentlyContinue)){. "$PSScriptRoot/audit-view.ps1"}
}
function Get-AGTextFrame {
    param([string]$Title,[string[]]$Lines,[int]$Page=0,[int]$Width=80,[int]$Height=24,[string]$Footer='')
    $frame=Get-AGAuditFrame -Sections @([pscustomobject]@{Title=$Title;Lines=$Lines}) -Section 0 -Page $Page -Width $Width -Height $Height
    if(-not $frame.TooSmall){
        $caption=if($frame.PageCount -gt 1){"$Title — стр. $($frame.Page+1) из $($frame.PageCount)"}else{$Title}
        $frame.Lines[0]=Limit-AGAuditLine $caption ([Math]::Max(1,$Width-1))
        if(-not $Footer){$Footer=if($frame.PageCount -gt 1){'←/→: страницы | Esc/Enter: назад'}else{'Esc/Enter: назад'}}
        $frame.Lines[$frame.Lines.Count-1]=Limit-AGAuditLine $Footer ([Math]::Max(1,$Width-1))
    }
    return $frame
}
# Guides use section-aware pagination. Other report/plan views keep their existing layout.
function Get-AGGuideHeadings {
    return @('Кому подходит','Перед началом','Что ВЫКЛЮЧИТЬ в Unlocker','Что оставить ВКЛЮЧЁННЫМ','Пошаговая настройка','Как понять, что работает','Если не заработало','Чего не делать','Важно','Источники')
}
function Get-AGGuideFrame {
    param([string]$Title,[string[]]$Lines,[int]$Page=0,[int]$Width=80,[int]$Height=25)
    $safe=[Math]::Max(1,$Width-1)
    if($Width -lt 32 -or $Height -lt 12){
        return [pscustomobject]@{Lines=@((Limit-AGAuditLine 'Нужно окно от 32x12' $safe),(Limit-AGAuditLine 'Esc/Enter: назад' $safe));Page=0;PageCount=1;TooSmall=$true;ViewportWidth=$Width;ViewportHeight=$Height;HeadingRows=@()}
    }
    $titleRows=@(Split-AGAuditLine $Title $safe)
    $titleLimit=if($Height -lt 16){1}else{2}
    if($titleRows.Count -gt $titleLimit){$titleRows=@($titleRows|Select-Object -First $titleLimit);$titleRows[-1]=Limit-AGAuditLine ($titleRows[-1]+'…') $safe}
    # title, rule and blank above; blank, rule and help below; never write last console row.
    $capacity=$Height-1-$titleRows.Count-2-3
    $sections=New-Object 'Collections.Generic.List[object]'
    $current=[pscustomobject]@{Heading='';Body=(New-Object 'Collections.Generic.List[string]')}
    foreach($line in $Lines){
        if($line -in @(Get-AGGuideHeadings)){
            if($current.Heading -or $current.Body.Count){$sections.Add($current)}
            $current=[pscustomobject]@{Heading=$line;Body=(New-Object 'Collections.Generic.List[string]')}
        }else{foreach($part in @(Split-AGAuditLine $line $safe)){$current.Body.Add($part)}}
    }
    if($current.Heading -or $current.Body.Count){$sections.Add($current)}
    if(-not $sections.Count){$current.Body.Add('Нет текста.');$sections.Add($current)}
    $pages=New-Object 'Collections.Generic.List[object]'
    $body=New-Object 'Collections.Generic.List[string]'
    $headings=New-Object 'Collections.Generic.List[int]'
    foreach($section in $sections){
        $rows=@($section.Body.ToArray())
        while($rows.Count -gt 0 -and [string]::IsNullOrWhiteSpace($rows[0])){if($rows.Count -eq 1){$rows=@()}else{$rows=@($rows[1..($rows.Count-1)])}}
        while($rows.Count -gt 0 -and [string]::IsNullOrWhiteSpace($rows[-1])){if($rows.Count -eq 1){$rows=@()}else{$rows=@($rows[0..($rows.Count-2)])}}
        if(-not $rows.Count){continue}
        $offset=0;$continued=$false
        while($offset -lt $rows.Count){
            $heading=if($section.Heading){$section.Heading+$(if($continued){' (продолжение)'}else{''})}else{''}
            $headingLines=if($heading){@(Split-AGAuditLine $heading $safe)}else{@()}
            # Heading plus a gap and at least one body row must stay together, even at 32x12.
            $minimum=$headingLines.Count+$(if($heading){1}else{0})+[Math]::Min(2,$rows.Count-$offset)
            $separator=if($body.Count){1}else{0}
            if($body.Count -and $capacity-$body.Count -lt $minimum+$separator){
                while($body.Count -gt 0 -and $body[$body.Count-1] -eq ''){$body.RemoveAt($body.Count-1)}
                $pages.Add([pscustomobject]@{Body=$body.ToArray();Headings=$headings.ToArray()})
                $body=New-Object 'Collections.Generic.List[string]';$headings=New-Object 'Collections.Generic.List[int]'
            }
            if($body.Count){$body.Add('')}
            foreach($h in $headingLines){$headings.Add($body.Count);$body.Add($h)}
            if($heading){$body.Add('')}
            while($offset -lt $rows.Count -and $body.Count -lt $capacity){$body.Add($rows[$offset]);$offset++}
            if($offset -lt $rows.Count){
                while($body.Count -gt 0 -and $body[$body.Count-1] -eq ''){$body.RemoveAt($body.Count-1)}
                $pages.Add([pscustomobject]@{Body=$body.ToArray();Headings=$headings.ToArray()})
                $body=New-Object 'Collections.Generic.List[string]';$headings=New-Object 'Collections.Generic.List[int]'
                while($offset -lt $rows.Count -and $rows[$offset] -eq ''){$offset++}
                $continued=$true
            }
        }
    }
    if($body.Count -or -not $pages.Count){$pages.Add([pscustomobject]@{Body=$body.ToArray();Headings=$headings.ToArray()})}
    $page=[Math]::Max(0,[Math]::Min($pages.Count-1,$Page));$selected=$pages[$page]
    $output=@($titleRows)+@(('-'*$safe),'')
    $colorRows=@(0..($titleRows.Count-1))+@($selected.Headings|ForEach-Object{$_+$titleRows.Count+2})
    $output+=@($selected.Body)
    while($output.Count -lt $Height-4){$output+=''}
    $output+=@('',('-'*$safe))
    $footer=if($pages.Count -gt 1){if($Width -ge 65){"Стр. $($page+1)/$($pages.Count) | ←/→ PgUp/PgDn | Esc/Enter: назад"}else{"$($page+1)/$($pages.Count) ←/→ | Esc/Enter: назад"}}else{'Esc/Enter: назад'}
    $output+=(Limit-AGAuditLine $footer $safe)
    return [pscustomobject]@{Lines=$output;Page=$page;PageCount=$pages.Count;TooSmall=$false;ViewportWidth=$Width;ViewportHeight=$Height;HeadingRows=$colorRows;BodyLines=@($selected.Body);BodyHeadingRows=@($selected.Headings);GuidePages=$pages.ToArray();BodyCapacity=$capacity}
}
function ConvertTo-AGScreenRow {
    param([string]$Text,[int]$Width)
    $safe=[Math]::Max(1,$Width-1)
    $line=Limit-AGAuditLine $Text $safe
    $cells=(@(Get-AGAuditGlyphs $line|Measure-Object Cells -Sum)[0].Sum)
    return $line+(' '*[Math]::Max(0,$safe-$cells))
}
function Write-AGTextFrame {
    param($Frame,[switch]$Reset)
    $size=Get-AGAuditConsoleSize
    $width=if($Frame.ViewportWidth -gt 0){[int]$Frame.ViewportWidth}else{[int]$size.Width}
    $height=if($Frame.ViewportHeight -gt 0){[int]$Frame.ViewportHeight}else{[int]$size.Height}
    if($Reset){Clear-Host}else{try{[Console]::SetCursorPosition(0,[Console]::WindowTop)}catch{Clear-Host}}
    # Replace every occupied row in full: shorter page lines must erase old tails.
    for($i=0;$i -lt [Math]::Max(1,$height-1);$i++){
        $raw=if($i -lt $Frame.Lines.Count){[string]$Frame.Lines[$i]}else{''}
        $line=ConvertTo-AGScreenRow -Text $raw -Width $width
        if($raw -match 'AGFixer by txmui'){Write-Host $line -ForegroundColor DarkRed}
        elseif(($Frame.PSObject.Properties['HeadingRows'] -and $i -in $Frame.HeadingRows) -or $i -eq 0 -or $raw -in @('Мой гайд','Моя форма','Материалы сообщества','Перед началом','Что ВЫКЛЮЧИТЬ в Unlocker','Что оставить ВКЛЮЧЁННЫМ','Пошаговая настройка','Как понять, что работает','Если не заработало','Чего не делать','Источники')){Write-Host $line -ForegroundColor Cyan}
        elseif($raw -match '^ПРОБЛЕМА:'){Write-Host $line -ForegroundColor Red}
        elseif((Test-AGReadableHeading $raw) -or $raw -match '^ПЛАН:'){Write-Host $line -ForegroundColor Cyan}
        elseif($raw -match '^-{5,}$'){Write-Host $line -ForegroundColor DarkGray}
        else{Write-Host $line}
    }
}
function Show-AGTextPages {
    param([string]$Title,[string[]]$Lines,[switch]$GuideSections,[string]$Footer)
    Initialize-AGPageTools
    $page=0;$oldSize=''
    while($true){
        $size=Get-AGAuditConsoleSize
        $frame=if($GuideSections){Get-AGGuideFrame -Title $Title -Lines $Lines -Page $page -Width $size.Width -Height $size.Height}else{Get-AGTextFrame -Title $Title -Lines $Lines -Page $page -Width $size.Width -Height $size.Height}
        if($Footer -and -not $frame.TooSmall){$hint=$Footer;if($frame.PageCount -gt 1 -and $size.Width -ge 60){$hint+=' | ←/→: страницы'};$frame.Lines[$frame.Lines.Count-1]=Limit-AGAuditLine $hint ([Math]::Max(1,$size.Width-1))}
        $page=$frame.Page;$sizeKey="$($size.Width)x$($size.Height)"
        Write-AGTextFrame $frame -Reset:($sizeKey -ne $oldSize);$oldSize=$sizeKey
        switch(Read-AGAuditKey){'Q'{return} ''{return} 'N'{$page=[Math]::Min($frame.PageCount-1,$page+1)} 'P'{$page=[Math]::Max(0,$page-1)} 'HOME'{$page=0} 'END'{$page=$frame.PageCount-1}}
    }
}
function Read-AGListChoice {
    param([string]$Title,[string[]]$Options,[string[]]$Intro=@(),[int]$EnterValue=0,[switch]$AllowAll,[string[]]$Status=@())
    if(Test-AGTerminalInput){return (Read-AGTerminalChoice -Title $Title -Options $Options -Intro $Intro -EnterValue $EnterValue -AllowAll:$AllowAll -Status $Status)}
    Initialize-AGPageTools
    $rows=@($Status)+@($Intro);for($i=0;$i -lt $Options.Count;$i++){$rows+="$($i+1). $($Options[$i])"}
    $page=0;$oldSize=''
    while($true){
        $size=Get-AGAuditConsoleSize
        $footer=if($EnterValue -eq -1){'Номер: отметить | A: все | Enter: готово | 0: отмена'}else{'Номер: выбрать | N/P: страницы | Enter/0: назад'}
        if($size.Width -lt 55){$footer=if($EnterValue -eq -1){'N/P | A | Enter:готово | 0:назад'}else{'Номер | N/P | Enter/0:назад'}}
        $frame=Get-AGTextFrame -Title $Title -Lines $rows -Page $page -Width $size.Width -Height $size.Height -Footer $footer
        $page=$frame.Page
        if($frame.PageCount -eq 1 -and -not $frame.TooSmall){$hint=if($EnterValue -eq -1){'Номер: отметить | A: все | Enter: готово | 0: отмена'}else{'Номер: выбрать | Enter/0: назад'};$frame.Lines[$frame.Lines.Count-1]=Limit-AGAuditLine $hint ([Math]::Max(1,$size.Width-1))}
        $sizeKey="$($size.Width)x$($size.Height)"
        Write-AGTextFrame $frame -Reset:($sizeKey -ne $oldSize);$oldSize=$sizeKey
        $choice=ConvertTo-AGCommandKey (Read-AGInput 'Выбор')
        if($choice -eq ''){return $EnterValue};if($choice -eq '0'){return 0}
        if($choice -match '^(?i:n|т)$'){$page=[Math]::Min($frame.PageCount-1,$page+1);continue}
        if($choice -match '^(?i:p|з)$'){$page=[Math]::Max(0,$page-1);continue}
        if($AllowAll -and $choice -match '^(?i:a|ф|all|все|всё)$'){return -2}
        $number=0
        if(-not $frame.TooSmall -and [int]::TryParse($choice,[ref]$number) -and $number -ge 1 -and $number -le $Options.Count){Clear-Host;return $number}
        Write-Warning 'Такого пункта нет. Введите номер из списка.';Wait-AGMenuReturn
    }
}
function Read-AGBackupChoice {
    param([string]$Title,[object[]]$Files)
    $files=@($Files|Sort-Object LastWriteTimeUtc -Descending)
    if(-not $files.Count){throw 'Сохранённых копий не найдено. Ничего не изменено.'}
    $options=@($files|ForEach-Object{"$($_.LastWriteTimeUtc.ToString('yyyy-MM-dd HH:mm')) UTC | $($_.FullName)"})
    $choice=Read-AGListChoice -Title $Title -Options $options -Intro @('Выберите копию по дате. Последняя созданная — вверху.','Будет отдельное подтверждение перед восстановлением.')
    if($choice -eq 0){return ''};return $files[$choice-1].FullName
}
