#Requires -Version 5.1
# List syntax/placement only, not a claim about DPI bypass or current traffic.
function Get-AGZapretListFiles {
    param([string]$Root)
    $directory=Join-Path $Root 'lists'
    $files=@(Get-ChildItem -LiteralPath $directory -Filter 'list*.txt' -File -ErrorAction Stop|Where-Object{$_.Name -eq 'list-general.txt' -or $_.Name -match '(?i)user|exclude'}|Sort-Object Name)
    return @($files)
}
function ConvertTo-AGListDomain {
    param([string]$Line)
    $text=($Line -split '#',2)[0].Trim().ToLowerInvariant()
    if(-not $text){return ''}
    $text=$text -replace '^[\^.]',''
    if($text.Length -gt 253 -or $text -notmatch '^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$'){return $null}
    return $text
}
function Get-AGZapretListHealth {
    param([string]$Root)
    if(-not(Get-Command Get-AGDomainList -ErrorAction SilentlyContinue)){. "$PSScriptRoot/local-audit.ps1"}
    $required=@(Get-AGDomainList -IncludeLogin);$records=@();$paths=@(Get-AGZapretListFiles $Root)
    $main=Join-Path $Root 'lists/list-general.txt';$mainDomains=@();$missing=@($required)
    foreach($file in $paths){
        if(($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw ('Список является ссылкой: '+$file.Name)}
        if($file.Length -gt 10MB){throw ('Список больше 10 МБ: '+$file.Name)}
        $hash=Get-AGFileHash $file.FullName;$text=Get-AGStrictUtf8Text $file.FullName
        if((Get-AGFileHash $file.FullName) -ne $hash){throw 'Список изменился во время чтения.'}
        $invalid=@();$duplicates=@();$broad=@();$domains=@();$patterns=@();$i=0
        foreach($line in @($text -split '\r?\n')){
            $i++;$domain=ConvertTo-AGListDomain $line
            if($null -eq $domain){$invalid+=@([pscustomobject]@{Number=$i;Text=$line});continue}
            if(-not $domain){continue};$domains+=@($domain);$pattern=($line -split '#',2)[0].Trim();$patterns+=@($pattern)
            if($file.Name -ne 'list-general.txt'){
                if($domain -in $required){$duplicates+=@([pscustomobject]@{Number=$i;Domain=$domain})}
                elseif(-not $pattern.StartsWith('^') -and @($required|Where-Object{$_ -like ('*.'+$domain)}).Count){$broad+=@([pscustomobject]@{Number=$i;Domain=$domain})}
            }
        }
        $bad=$invalid.Count -or $duplicates.Count -or $broad.Count
        if($file.Name -eq 'list-general.txt'){$mainDomains=$domains;$missing=@($required|Where-Object{$target=$_;-not @($patterns|Where-Object{Test-AGHostPattern -Domain $target -Pattern $_}).Count});$bad=$bad -or $missing.Count}
        $records+=@([pscustomobject]@{Name=$file.Name;Path=$file.FullName;Hash=$hash;Text=$text;Domains=$domains;Patterns=$patterns;Invalid=$invalid;ExactConflicts=$duplicates;BroadConflicts=$broad;Status=$(if($bad){'Неисправно'}else{'Исправно'})})
    }
    $exists=Test-Path -LiteralPath $main -PathType Leaf
    $status=if(-not $exists -or @($records|Where-Object Status -eq 'Неисправно').Count){'Неисправно'}else{'Исправно'}
    return [pscustomobject]@{Root=$Root;Status=$status;MainExists=$exists;Missing=$missing;Required=$required;Files=$records}
}
function New-AGZapretListWritePlans {
    param([string]$Root,[switch]$IncludeLogin)
    $health=Get-AGZapretListHealth $Root
    if(-not $health.MainExists){throw 'Нет lists/list-general.txt. Укажите правильную папку Zapret.'}
    $required=@(Get-AGDomainList -IncludeLogin:$IncludeLogin);$plans=@()
    foreach($file in $health.Files){
        $text=$file.Text
        if($file.Name -eq 'list-general.txt'){
            $missing=@($required|Where-Object{$target=$_;-not @($file.Patterns|Where-Object{Test-AGHostPattern -Domain $target -Pattern $_}).Count})
            if($missing.Count){$separator=if($text -and -not $text.EndsWith("`n")){"`r`n"}else{''};$text+=$separator+($missing -join "`r`n")+"`r`n"}
        }else{
            # Only exact AG entries; broad googleapis.com exclusions require manual choice.
            $lines=@($text -split '\r?\n');$removed=$false
            for($i=0;$i -lt $lines.Count;$i++){
                $domain=ConvertTo-AGListDomain $lines[$i]
                if($domain -and $domain -in $required){
                    $comment='';if($lines[$i].Contains('#')){$comment='#'+($lines[$i] -split '#',2)[1]}
                    $lines[$i]=$comment;$removed=$true
                }
            }
            if($removed){$text=$lines -join "`r`n"}
        }
        if($text -cne $file.Text){$plans+=@([pscustomobject]@{Path=$file.Path;Hash=$file.Hash;Text=$text;Backup=$null;AppliedHash=$null})}
    }
    return $plans
}
function Get-AGZapretHealthLines {
    param($Health)
    $lines=@(('Списки Zapret: '+$Health.Status),('Папка: '+$Health.Root),'Проверяем записи файлов, а не прохождение запросов.')
    $present=@($Health.Required|Where-Object{$_ -notin $Health.Missing})
    $lines+=('В list-general.txt есть '+$present.Count+' из '+@($Health.Required).Count+' проверяемых доменов.')
    if($present.Count){$lines+='Уже есть:';foreach($domain in $present){$lines+='  '+$domain}}
    if($Health.Missing.Count){$lines+='Добавить:';foreach($domain in $Health.Missing){$lines+='  '+$domain}}

    if(-not $Health.MainExists){$lines+='list-general.txt: Неисправно — файл не найден.'}
    foreach($file in $Health.Files){
        $lines+=@('',($file.Name+': '+$file.Status))
        foreach($bad in @($file.Invalid|Select-Object -First 8)){$lines+="  Строка $($bad.Number): не домен — $($bad.Text)"}
        foreach($bad in @($file.ExactConflicts|Select-Object -First 8)){$lines+="  Строка $($bad.Number): $($bad.Domain) — должен быть только в list-general.txt"}
        foreach($bad in @($file.BroadConflicts|Select-Object -First 8)){$lines+="  Строка $($bad.Number): $($bad.Domain) затрагивает AG. Широкую запись меняйте вручную."}
        if($file.Invalid.Count -gt 8 -or $file.ExactConflicts.Count -gt 8 -or $file.BroadConflicts.Count -gt 8){$lines+='  Показаны первые 8 записей каждого типа. Исправьте их и повторите проверку.'}
    }

    return $lines
}
function Get-AGZapretRepairLines {
    param($Health,[object[]]$Plans=@())
    $lines=@('=== Результат проверки ===',('Папка: '+$Health.Root),('В основном списке есть '+(@($Health.Required).Count-@($Health.Missing).Count)+' из '+@($Health.Required).Count+' доменов Antigravity.'))
    if($Health.Status -eq 'Исправно' -and -not $Plans.Count){
        $lines+=@('Настроено. Исправлять списки не требуется.')
    }elseif($Plans.Count){
        $lines+='=== Что исправим по Y ==='
        if($Health.Missing.Count){$lines+='Добавим в list-general.txt:';foreach($domain in $Health.Missing){$lines+='  '+$domain}}
        foreach($file in @($Health.Files|Where-Object Name -ne 'list-general.txt')){
            foreach($entry in @($file.ExactConflicts)){$lines+=('Уберём из '+$file.Name+': '+$entry.Domain)}
        }
        $lines+=('Изменим файлы: '+(@($Plans|ForEach-Object{[IO.Path]::GetFileName($_.Path)}) -join ', '))
        $lines+='Перед записью создадим копии. Работающую службу Zapret перезапустим.'
    }else{
        $lines+=@('=== Нужна ручная проверка ===','Безопасных автоматических изменений нет. Причины — ниже.')
    }
    $lines+='=== Состояние файлов ==='
    if(-not $Health.MainExists){$lines+='list-general.txt: не найден — выберите папку с полным комплектом Zapret.'}
    foreach($file in $Health.Files){
        $lines+=($file.Name+': '+$file.Status)
        foreach($bad in @($file.Invalid|Select-Object -First 8)){$lines+=('  Строка '+$bad.Number+': не домен — '+$bad.Text)}
        foreach($bad in @($file.BroadConflicts|Select-Object -First 8)){$lines+=('  Строка '+$bad.Number+': широкое правило '+$bad.Domain+' — проверьте вручную.')}
        if($file.Invalid.Count -gt 8 -or $file.BroadConflicts.Count -gt 8){$lines+='  Показаны первые 8 проблем каждого типа. Полный файл проверьте в редакторе.'}
    }
    return $lines
}
function Get-AGZapretRepairFrame {
    param($Health,[object[]]$Plans=@(),[int]$Width=80,[int]$Height=25,[int]$Page=0,[bool]$AllPagesSeen=$true)
    $configured=$Health.Status -eq 'Исправно' -and -not $Plans.Count
    $title=if($configured){'Списки Zapret — настроено'}else{'Списки Zapret — проверка и исправление'}
    $frame=Get-AGTextFrame -Title $title -Lines @(Get-AGZapretRepairLines -Health $Health -Plans $Plans) -Width $Width -Height $Height -Page $Page
    if(-not $frame.TooSmall){
        if($Plans.Count){
            $footer=if($AllPagesSeen){'Y: исправить | N: игнорировать'}else{'Y: дальше по плану | N: игнорировать'}
            if($Width -lt 45){$footer=if($AllPagesSeen){'Y:исправить | N:игнорировать'}else{'Y:далее | N:игнорировать'}}
        }elseif($configured){$footer='(Настроено) | Esc/Enter: назад'}
        else{$footer=if($Width -lt 45){'Нужно вручную | Esc:назад'}else{'Автоисправлений нет | Esc/Enter: назад'}}
        if($Width -ge 60){if($frame.PageCount -gt 1){$footer+=' | ←/→: страницы'}else{if($Plans.Count){$footer+=' | Esc: назад'}}}
        $frame.Lines[$frame.Lines.Count-1]=Limit-AGAuditLine $footer ([Math]::Max(1,$Width-1))
    }
    return $frame
}
function Read-AGZapretRepairDecision {
    param($Health,[object[]]$Plans=@())
    $page=0;$oldSize='';$seen=@{}
    try{
        while($true){
            $size=Get-AGAuditConsoleSize;$sizeKey="$($size.Width)x$($size.Height)"
            if($sizeKey -ne $oldSize){$seen=@{}}
            $frame=Get-AGZapretRepairFrame -Health $Health -Plans $Plans -Width $size.Width -Height $size.Height -Page $page -AllPagesSeen:$false
            $page=$frame.Page
            if(-not $frame.TooSmall){$seen[$page]=$true}
            $allSeen=$seen.Count -eq $frame.PageCount
            $frame=Get-AGZapretRepairFrame -Health $Health -Plans $Plans -Width $size.Width -Height $size.Height -Page $page -AllPagesSeen:$allSeen
            Write-AGTextFrame -Frame $frame -Reset:($sizeKey -ne $oldSize);$oldSize=$sizeKey
            if(Test-AGTerminalInput){$key=Read-AGTerminalKeyOrResize -Width $size.Width -Height $size.Height}
            else{$key=ConvertTo-AGCommandKey (Read-AGInput 'Клавиша');if(-not $key){$key='ENTER'}}
            $key=ConvertTo-AGCommandKey $key
            if($key -in @('N','ESC','0','Q')){return $false}
            if($frame.TooSmall){continue}
            switch($key){
                'Y'{
                    if(-not $Plans.Count){continue}
                    if($allSeen){return $true}
                    # Y never confirms changes hidden on unread pages.
                    for($i=0;$i -lt $frame.PageCount;$i++){if(-not $seen.ContainsKey($i)){$page=$i;break}}
                }
                'ENTER'{if($page -lt $frame.PageCount-1){$page++}else{return $false}}
                {$_ -in @('RIGHT','PAGEDOWN','DOWN')}{$page=[Math]::Min($frame.PageCount-1,$page+1)}
                {$_ -in @('LEFT','PAGEUP','UP','P')}{$page=[Math]::Max(0,$page-1)}
                'HOME'{$page=0} 'END'{$page=$frame.PageCount-1}
            }
        }
    }finally{Clear-Host}
}
function Show-AGZapretListHealth {
    try{$root=Get-ZapretPath}catch{if(-not(Select-AGInstallationFolder Zapret)){return};$root=Get-ZapretPath}
    while($true){
        $health=Get-AGZapretListHealth $root
        $plans=@();if($health.MainExists){$plans=@(New-AGZapretListWritePlans -Root $root -IncludeLogin)}
        # Y in the visible review is the only confirmation. Enter never reveals a second prompt.
        if(-not(Read-AGZapretRepairDecision -Health $health -Plans $plans)){return}
        if(-not $plans.Count){return}
        Invoke-AGExclusiveOperation {
            if([IO.Path]::GetFullPath((Get-ZapretPath)) -ine [IO.Path]::GetFullPath($root)){throw 'Выбранная папка Zapret изменилась. Повторите проверку списков.'}
            $now=Get-AGZapretListHealth $root
            if(((@($now.Files|ForEach-Object{$_.Path+'='+$_.Hash})) -join "`n") -cne ((@($health.Files|ForEach-Object{$_.Path+'='+$_.Hash})) -join "`n")){throw 'Списки изменились. Повторите проверку.'}
            Invoke-UnlockedAdd-AGDomains -IncludeLogin
        }
        # Same screen, new facts and footer. No extra plan, menu or confirmation is appended.
        $health=Get-AGZapretListHealth $root
        Add-AGUiJournal ('Списки Zapret: '+$health.Status)
    }
}
