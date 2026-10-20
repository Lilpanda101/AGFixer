#Requires -Version 5.1
# Explicit navigation. Links are displayed only when their item is opened.
function Get-AGCommunityGuideItems {
    $raw=@(foreach($item in (Get-Content -LiteralPath "$PSScriptRoot/scenarios.json" -Raw -Encoding UTF8|ConvertFrom-Json -ErrorAction Stop)){$item})
    $items=@([pscustomobject]@{Label='Мой гайд — Zapret и AG Unlocker (txmui)';Id='zapret-direct';Kind='Scenario'},[pscustomobject]@{Label='Моя форма — обратиться за помощью';Id='form';Kind='Info'})
    foreach($s in (@($raw|Where-Object Id -eq 'vpn-tun-direct')+@($raw|Where-Object Id -ne 'vpn-tun-direct'))){if($s.Id -ne 'zapret-direct'){$items+=@([pscustomobject]@{Label=[string]$s.Title;Id=[string]$s.Id;Kind='Scenario'})}}
    $items+=@([pscustomobject]@{Label='VPN и прокси — Throne, Happ и другие (AGFixer)';Id='vpn-clients';Kind='Clients'})
    $items+=@([pscustomobject]@{Label='Источники и материалы сообщества';Id='sources';Kind='Info'})
    return $items
}
function Open-AGCommunityScenario {
    param([string]$Id)
    & "$PSScriptRoot/show-scenarios.ps1" -Id $Id -Paged
}
function Show-AGCommunityGuides {
    while($true){
        $items=@(Get-AGCommunityGuideItems)
        $pick=Read-AGListChoice -Title 'Гайды сообщества' -Options @($items.Label)
        if(-not $pick){return}
        $item=$items[$pick-1]
        if($item.Kind -eq 'Clients'){. "$PSScriptRoot/vpn-clients.ps1";Show-AGVpnClientGuides;continue}
        if($item.Kind -eq 'Scenario'){Open-AGCommunityScenario -Id $item.Id;continue}
        if($item.Id -eq 'form'){Show-AGTextPages -GuideSections -Title 'Моя форма' -Lines @('Опишите проблему и приложите диагностику:','https://t.me/nova_txt/69864/253517');continue}
        Show-AGTextPages -GuideSections -Title 'Материалы сообщества' -Lines @('Мой гайд (txmui): https://t.me/nova_txt/69864/251458','Источники каждого решения указаны в конце инструкции.','Подробности адаптации: COMMUNITY-NOTES.md','NickDevo: https://github.com/NickDevo-o/FixNovaAntigtavity')
    }
}
