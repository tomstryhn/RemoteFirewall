<#PSScriptInfo

.DESCRIPTION Runs the worker in-process on the local computer

.VERSION 1.3.0

.GUID 8f67e06b-ca75-4052-83d2-d68157f283b2

.AUTHOR Tom Stryhn

.COMPANYNAME Tom Stryhn

.COPYRIGHT 2026 (c) Tom Stryhn

.LICENSEURI https://github.com/tomstryhn/RemoteFirewall/blob/main/LICENSE

.PROJECTURI https://github.com/tomstryhn/RemoteFirewall

#>

function Invoke-FirewallInventoryLocal {

    <#
    .SYNOPSIS
        Runs the worker in-process on the local computer.

    .DESCRIPTION
        Kept as its own function, separate from the worker scriptblock, so tests can mock the
        local call without touching the real NetSecurity cmdlets. Takes one switch,
        SkipSidReference, and has no logic of its own beyond the call, which is deliberate: every
        local alias in the same Get-FirewallInventory call shares this one run instead of each
        alias triggering its own.

    .PARAMETER SkipSidReference
        Passed to the worker as a real [bool], by name. When set, the worker leaves MachineSid,
        DomainSid, ComputerAccountSid and DomainNetbiosName null.

    .NOTES
        FUNCTION: Invoke-FirewallInventoryLocal
        AUTHOR:   Tom Stryhn
        GITHUB:   https://github.com/tomstryhn/

    .INPUTS
        None. Does not accept pipeline input.

    .OUTPUTS
        System.Management.Automation.PSObject
    #>

    param(
        [switch]$SkipSidReference
    )

    $worker = Get-FirewallInventoryWorker
    return & $worker -SkipSidReference ([bool]$SkipSidReference)
}
