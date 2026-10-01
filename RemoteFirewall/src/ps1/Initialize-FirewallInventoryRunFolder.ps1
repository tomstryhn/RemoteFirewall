<#PSScriptInfo

.DESCRIPTION Creates the run folder under OutputPath and proves it is writable

.VERSION 1.2.0

.GUID 93129ad1-22a4-4f87-88f0-f1e997de4a44

.AUTHOR Tom Stryhn

.COMPANYNAME Tom Stryhn

.COPYRIGHT 2026 (c) Tom Stryhn

.LICENSEURI https://github.com/tomstryhn/RemoteFirewall/blob/main/LICENSE

.PROJECTURI https://github.com/tomstryhn/RemoteFirewall

#>

function Initialize-FirewallInventoryRunFolder {

    <#
    .SYNOPSIS
        Creates the run folder under OutputPath and proves it is writable.

    .DESCRIPTION
        Creates <OutputPath>\RemoteFirewall-<yyyyMMdd-HHmmss>Z and throws on any failure, before
        any collection starts. OutputPath itself is created first when missing. Writability is
        proved by writing and removing a small probe file inside the new run folder, not by
        inspecting permissions, so the same check works the same way on any file system.

    .PARAMETER OutputPath
        The already-resolved root folder for the run.

    .NOTES
        FUNCTION: Initialize-FirewallInventoryRunFolder
        AUTHOR:   Tom Stryhn
        GITHUB:   https://github.com/tomstryhn/

    .INPUTS
        None. Does not accept pipeline input.

    .OUTPUTS
        System.String
    #>

    param(
        [Parameter(Mandatory = $true)]
        [string]$OutputPath
    )

    if (-not (Test-Path -LiteralPath $OutputPath)) {
        New-Item -Path $OutputPath -ItemType Directory -Force -ErrorAction Stop -WhatIf:$false -Confirm:$false | Out-Null
    }

    $stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMdd-HHmmss', [System.Globalization.CultureInfo]::InvariantCulture)
    $runFolder = Resolve-FirewallInventoryUniqueFolder -Path (Join-Path $OutputPath ('RemoteFirewall-' + $stamp + 'Z'))

    $probePath = Join-Path $runFolder '.write-test'
    try {
        [System.IO.File]::WriteAllText($probePath, 'ok')
        Remove-Item -LiteralPath $probePath -Force -ErrorAction Stop -WhatIf:$false -Confirm:$false
    } catch {
        throw "OutputPath is not writable: $OutputPath. $($_.Exception.Message)"
    }

    return $runFolder
}
