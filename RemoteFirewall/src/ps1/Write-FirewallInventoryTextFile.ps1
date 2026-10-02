<#PSScriptInfo

.DESCRIPTION Writes text to a file as UTF-8 without a byte order mark

.VERSION 1.3.0

.GUID 21cb9d72-4083-4ef3-b83e-1b571c6f3a7a

.AUTHOR Tom Stryhn

.COMPANYNAME Tom Stryhn

.COPYRIGHT 2026 (c) Tom Stryhn

.LICENSEURI https://github.com/tomstryhn/RemoteFirewall/blob/main/LICENSE

.PROJECTURI https://github.com/tomstryhn/RemoteFirewall

#>

function Write-FirewallInventoryTextFile {

    <#
    .SYNOPSIS
        Writes text to a file as UTF-8 without a byte order mark.

    .DESCRIPTION
        Used for every text file the host writes into a per-computer folder or the run folder
        (run.json, system.json, summary.json, profiles.json, globalsettings.json, rules.json,
        accounts.json), so all of them share one consistent encoding regardless of what the content
        happens to contain.

    .PARAMETER Path
        The file to write.

    .PARAMETER Content
        The text to write. May be an empty string.

    .NOTES
        FUNCTION: Write-FirewallInventoryTextFile
        AUTHOR:   Tom Stryhn
        GITHUB:   https://github.com/tomstryhn/

    .INPUTS
        None. Does not accept pipeline input.

    .OUTPUTS
        None.
    #>

    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Content
    )

    $encoding = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $Content, $encoding)
}
