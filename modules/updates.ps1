#Requires -Version 5.1
# Explicit read-only update check. Never download assets, execute content or change files.
function Get-AGInstalledVersion {return '1.10.8'}
function ConvertTo-AGReleaseVersion {
    param([string]$Tag)
    if([string]::IsNullOrEmpty($Tag) -or $Tag.Length -gt 96){return $null}
    if($Tag -notmatch '\A(?:AGFixer[-_ ]?)?[vV]?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:\.(0|[1-9][0-9]*))?\z'){return $null}
    try{
        $revision=0;if($Matches[4]){$revision=[int]$Matches[4]}
        return (New-Object Version([int]$Matches[1],[int]$Matches[2],[int]$Matches[3],$revision))
    }catch{return $null}
}
function Invoke-AGGitHubReleaseRequest {
    param([ValidateSet('Latest','Repository')][string]$Resource='Latest')
    $url='https://api.github.com/repos/txmu1/AGFixer'
    if($Resource -eq 'Latest'){$url+='/releases/latest'}
    $oldProtocol=[Net.ServicePointManager]::SecurityProtocol
    $response=$null;$stream=$null;$memory=$null;$request=$null
    try{
        [Net.ServicePointManager]::SecurityProtocol=$oldProtocol -bor [Net.SecurityProtocolType]::Tls12
        $request=[Net.HttpWebRequest][Net.WebRequest]::Create($url)
        $request.Method='GET';$request.UserAgent=('AGFixer/'+(Get-AGInstalledVersion))
        $request.Accept='application/vnd.github+json';$request.Headers['X-GitHub-Api-Version']='2022-11-28'
        $request.AllowAutoRedirect=$false;$request.Timeout=8000;$request.ReadWriteTimeout=8000
        $request.UseDefaultCredentials=$false
        $watch=[Diagnostics.Stopwatch]::StartNew()
        try{$response=$request.GetResponse()}catch [Net.WebException]{
            if($_.Exception.Response){$response=$_.Exception.Response}else{throw}
        }
        $status=[int]$response.StatusCode
        if($status -ne 200){return [pscustomobject]@{StatusCode=$status;Content=''}}
        if($response.ContentLength -gt 262144){throw 'GitHub response exceeds limit'}
        $stream=$response.GetResponseStream();$memory=New-Object IO.MemoryStream
        $buffer=New-Object byte[] 4096
        while($true){
            $remaining=8000-[int]$watch.ElapsedMilliseconds
            if($remaining -le 0){throw 'GitHub response timeout'}
            if($stream.CanTimeout){$stream.ReadTimeout=$remaining}
            $read=$stream.Read($buffer,0,$buffer.Length)
            if($read -eq 0){break}
            if($memory.Length+$read -gt 262144){throw 'GitHub response exceeds limit'}
            $memory.Write($buffer,0,$read)
        }
        $utf8=New-Object Text.UTF8Encoding($false,$true)
        return [pscustomobject]@{StatusCode=200;Content=$utf8.GetString($memory.ToArray())}
    }finally{
        if($stream){$stream.Dispose()};if($memory){$memory.Dispose()};if($response){$response.Close()}
        if($request){$request.Abort()}
        [Net.ServicePointManager]::SecurityProtocol=$oldProtocol
    }
}
function Get-AGUpdateStatus {
    $current=Get-AGInstalledVersion
    $result=[pscustomobject]@{State='Unavailable';CurrentVersion=$current;LatestVersion=$null;CheckedAtUtc=[DateTime]::UtcNow.ToString('o');Repository='https://github.com/txmu1/AGFixer';ReleaseUrl='https://github.com/txmu1/AGFixer/releases';Message='Не удалось проверить обновления. Установленная версия не изменена.'}
    try{
        $response=Invoke-AGGitHubReleaseRequest -Resource Latest
        $code=[int]$response.StatusCode
        if($code -eq 404){
            $repo=Invoke-AGGitHubReleaseRequest -Resource Repository
            if([int]$repo.StatusCode -eq 200){$result.State='NoRelease';$result.Message='Репозиторий доступен, но опубликованный стабильный релиз не найден.'}
            elseif([int]$repo.StatusCode -eq 404){$result.Message='Репозиторий недоступен: он может быть приватным, ещё не опубликованным или иметь другое имя.'}
            elseif([int]$repo.StatusCode -in @(403,429)){$result.State='RateLimited';$result.Message='GitHub отклонил запрос или исчерпан лимит API. Проверьте позднее.'}
            return $result
        }
        if($code -in @(403,429)){$result.State='RateLimited';$result.Message='GitHub отклонил запрос или исчерпан лимит API. Проверьте позднее.';return $result}
        if($code -ne 200){return $result}
        if(-not($response.Content -is [string]) -or $response.Content.Length -gt 262144){throw 'Invalid release content'}
        $release=$response.Content|ConvertFrom-Json -ErrorAction Stop
        if(-not($release -is [pscustomobject]) -or -not($release.tag_name -is [string]) -or -not($release.draft -is [bool]) -or -not($release.prerelease -is [bool])){throw 'Invalid release shape'}
        $remote=ConvertTo-AGReleaseVersion $release.tag_name;$local=ConvertTo-AGReleaseVersion $current
        if(-not $remote -or -not $local -or $release.draft -or $release.prerelease){throw 'Not a supported stable release'}
        $result.LatestVersion=$remote.ToString(3)
        if($remote.Revision -ne 0){$result.LatestVersion=$remote.ToString(4)}
        # Use our fixed repository and strictly validated tag, never html_url/assets from the response.
        $result.ReleaseUrl='https://github.com/txmu1/AGFixer/releases/tag/'+[Uri]::EscapeDataString($release.tag_name)
        if($remote -gt $local){$result.State='UpdateAvailable';$result.Message='Доступна новая версия AGFixer.'}
        elseif($remote -eq $local){$result.State='Current';$result.Message='Установлена последняя опубликованная стабильная версия.'}
        else{$result.State='Ahead';$result.Message='Установленная версия новее последнего опубликованного стабильного релиза.'}
        return $result
    }catch{
        $result.State='Unavailable';$result.LatestVersion=$null
        $result.Message='Проверка недоступна: ошибка сети, TLS или ответ GitHub не распознан. Попробуйте позднее.'
        return $result
    }
}
function Show-AGUpdateCheck {
    $result=Get-AGUpdateStatus
    $lines=@('Результат проверки',$result.Message,'',('Установлено: '+$result.CurrentVersion))
    if($result.LatestVersion){$lines+=('Последний стабильный релиз: '+$result.LatestVersion)}
    $lines+=@('','Релизы GitHub',$result.ReleaseUrl,'','Что сделать дальше')
    if($result.State -eq 'UpdateAvailable'){
        $lines+=@('Откройте страницу релиза и скачайте официальный архив вручную. Распакуйте новую версию в отдельную папку.',
            'Не переносите старые скрипты поверх новой версии. Личные отчёты и резервные копии сохраните отдельно.')
    }elseif($result.State -eq 'Current'){$lines+='Обновление не требуется.'}
    else{$lines+='Можно проверить страницу Releases вручную. Недоступная проверка не означает, что обновлений нет.'}
    $lines+=@('','Важно','Проверяются только опубликованные стабильные GitHub Releases, не ветка main и не тестовые теги.',
        'Файлы не скачиваются и не запускаются; никакие настройки не меняются. Проверка подписи/подлинности ZIP этим не выполняется.')
    Show-AGTextPages -Title 'Обновления AGFixer' -Lines $lines
}
