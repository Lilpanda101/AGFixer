#Requires -Version 5.1
# No interception of built-in Read-Host; only AGFixer's own prompts use this wrapper.
# Command-only normalization for standard RU ЙЦУКЕН and English QWERTY.
# Never call this for paths, report contents, URLs or arbitrary text fields.
function ConvertTo-AGCommandKey {
    param([AllowNull()][string]$Value)
    if($Value -ceq ' '){return 'SPACE'}
    if($null -eq $Value){return ''}
    $text=$Value.Trim().ToUpperInvariant()
    if($text.Length -eq 1){
        $russian='ЙЦУКЕНГШЩЗФЫВАПРОЛДЯЧСМИТЬ'
        $english='QWERTYUIOPASDFGHJKLZXCVBNM'
        $index=$russian.IndexOf($text,[StringComparison]::Ordinal)
        if($index -ge 0){return [string]$english[$index]}
    }
    return $text
}
function ConvertFrom-AGConsoleKey {
    param([Parameter(Mandatory=$true)][ConsoleKeyInfo]$KeyInfo)
    # Ctrl/Alt combinations are not plain menu commands. Shift/Caps Lock are allowed.
    if(($KeyInfo.Modifiers -band [ConsoleModifiers]::Control) -or ($KeyInfo.Modifiers -band [ConsoleModifiers]::Alt)){return 'IGNORED'}
    $name=[string]$KeyInfo.Key
    switch($name){
        'Enter'{return 'ENTER'} 'Spacebar'{return 'SPACE'} 'Escape'{return 'ESC'}
        'UpArrow'{return 'UP'} 'DownArrow'{return 'DOWN'} 'LeftArrow'{return 'LEFT'} 'RightArrow'{return 'RIGHT'}
        'PageUp'{return 'PAGEUP'} 'PageDown'{return 'PAGEDOWN'} 'Home'{return 'HOME'} 'End'{return 'END'}
        'F1'{return 'F1'} 'F2'{return 'F2'}
    }
    if($name -cmatch '^[A-Z]$'){return $name}
    if($name -match '^(?:D|NumPad)([0-9])$' -and -not($KeyInfo.Modifiers -band [ConsoleModifiers]::Shift)){return $Matches[1]}
    if([char]::IsControl($KeyInfo.KeyChar)){return 'IGNORED'}
    return (ConvertTo-AGCommandKey ([string]$KeyInfo.KeyChar))
}
function Test-AGInteractiveUi {
    return [bool](Get-Variable -Name AGInteractiveUi -ValueOnly -ErrorAction SilentlyContinue)
}
function Read-AGInput {
    param([string]$Prompt)
    if((Test-AGInteractiveUi) -and (Get-Command Split-AGAuditLine -ErrorAction SilentlyContinue)){
        $size=Get-AGAuditConsoleSize
        foreach($line in @(Split-AGAuditLine $Prompt ([Math]::Max(1,$size.Width-1)))){Write-Host $line}
        $value=Read-Host '>'
    }else{$value=Read-Host $Prompt}
    if(Test-AGInteractiveUi){Clear-Host}
    return $value
}
