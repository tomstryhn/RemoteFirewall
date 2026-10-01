<#PSScriptInfo

.DESCRIPTION Reads the collecting computer's own ComputerId for run.json

.VERSION 1.2.0

.GUID ac3d24d1-50d1-42af-a430-6adb07a058c6

.AUTHOR Tom Stryhn

.COMPANYNAME Tom Stryhn

.COPYRIGHT 2026 (c) Tom Stryhn

.LICENSEURI https://github.com/tomstryhn/RemoteFirewall/blob/main/LICENSE

.PROJECTURI https://github.com/tomstryhn/RemoteFirewall

#>

function Get-FirewallInventoryHostComputerId {

    <#
    .SYNOPSIS
        Reads the collecting computer's own ComputerId for run.json.

    .DESCRIPTION
        Reads Win32_ComputerSystemProduct.UUID on the collecting computer, the same way the
        worker reads ComputerId for a target: through CIM, upper case, null when the class or the
        property is missing or the read throws. Runs on the host, so unlike the worker it may use
        module helpers.

    .NOTES
        FUNCTION: Get-FirewallInventoryHostComputerId
        AUTHOR:   Tom Stryhn
        GITHUB:   https://github.com/tomstryhn/

    .INPUTS
        None. Does not accept pipeline input.

    .OUTPUTS
        System.String
    #>

    param()

    $computerId = $null
    try {
        $product = $null
        $product = Get-CimInstance -ClassName Win32_ComputerSystemProduct -ErrorAction Stop -Verbose:$false
        if ($null -ne $product -and $null -ne $product.PSObject.Properties['UUID'] -and -not [string]::IsNullOrWhiteSpace([string]$product.UUID)) {
            $computerId = ([string]$product.UUID).Trim().ToUpperInvariant()
        }
    } catch {
        $computerId = $null
    }

    return $computerId
}
