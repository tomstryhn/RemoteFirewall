<#PSScriptInfo

.DESCRIPTION Builds one RemoteFirewall.Result row

.VERSION 1.2.0

.GUID 55ec8f60-3c72-4c92-9b8c-417fa7e6c76c

.AUTHOR Tom Stryhn

.COMPANYNAME Tom Stryhn

.COPYRIGHT 2026 (c) Tom Stryhn

.LICENSEURI https://github.com/tomstryhn/RemoteFirewall/blob/main/LICENSE

.PROJECTURI https://github.com/tomstryhn/RemoteFirewall

#>

function ConvertTo-FirewallInventoryResultRow {

    <#
    .SYNOPSIS
        Builds one RemoteFirewall.Result row.

    .DESCRIPTION
        Every optional property defaults to the "not reached" shape, so a caller only needs to
        override what it actually knows. Error is derived from Errors here, as the first entry,
        rather than being supplied separately, so the two can never disagree about which message
        came first. Every entry of Errors is collapsed to one line (trimmed, each run of whitespace
        one space) before either is set.

    .PARAMETER ComputerName
        The name as requested by the caller.

    .PARAMETER ComputerId
        The computer's identity from the worker object (section 5), or $null when the target was
        never reached.

    .PARAMETER Status
        Success, Partial, or Failed.

    .PARAMETER Transport
        Local or WinRM.

    .PARAMETER OutputFolder
        The per-computer folder, or $null when the target was never reached.

    .PARAMETER IsElevated
        Elevation as reported by the target, or $null when unknown.

    .PARAMETER ProfileCount
        Number of firewall profiles returned, or $null.

    .PARAMETER RuleCount
        Number of firewall rules returned, or $null when the rules were never read.

    .PARAMETER FilterFailedCount
        Filter classes (of seven) whose one-pass read failed, or $null when the rules were never
        read.

    .PARAMETER SddlFailedCount
        Rule security descriptor values that did not parse, or $null.

    .PARAMETER AccountCount
        Distinct security principal tokens named by the rules, or $null.

    .PARAMETER AccountUnresolvedCount
        Of those, without a SID after the lookup, or $null.

    .PARAMETER Errors
        Every error message seen for this computer, target and host side. May be empty.
        ErrorCount is derived from this list's Count, so the two can never disagree.

    .NOTES
        FUNCTION: ConvertTo-FirewallInventoryResultRow
        AUTHOR:   Tom Stryhn
        GITHUB:   https://github.com/tomstryhn/

    .INPUTS
        None. Does not accept pipeline input.

    .OUTPUTS
        System.Management.Automation.PSObject, type name RemoteFirewall.Result
    #>

    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName,

        [AllowNull()]
        $ComputerId,

        [Parameter(Mandatory = $true)]
        [string]$Status,

        [Parameter(Mandatory = $true)]
        [string]$Transport,

        [AllowNull()]
        [string]$OutputFolder,

        [AllowNull()]
        $IsElevated,

        [AllowNull()]
        $ProfileCount,

        [AllowNull()]
        $RuleCount,

        [AllowNull()]
        $FilterFailedCount,

        [AllowNull()]
        $SddlFailedCount,

        [AllowNull()]
        $AccountCount,

        [AllowNull()]
        $AccountUnresolvedCount,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [AllowEmptyString()]
        [string[]]$Errors
    )

    # Every entry is collapsed to one line here, not trusted from the caller: a host-side message such as a remote connection error spans several lines, and Error and Errors feed results.csv and the console warning, where a line break splits a row.
    $errorList = @($Errors | ForEach-Object { ([string]$_).Trim() -replace '\s+', ' ' })

    return [pscustomobject]@{
        PSTypeName              = 'RemoteFirewall.Result'
        ComputerName            = $ComputerName
        ComputerId              = $ComputerId
        Status                  = $Status
        Transport               = $Transport
        OutputFolder            = $OutputFolder
        IsElevated              = $IsElevated
        ProfileCount            = $ProfileCount
        RuleCount               = $RuleCount
        FilterFailedCount       = $FilterFailedCount
        SddlFailedCount         = $SddlFailedCount
        AccountCount            = $AccountCount
        AccountUnresolvedCount  = $AccountUnresolvedCount
        Error                   = $(if ($errorList.Count -gt 0) { $errorList[0] } else { '' })
        ErrorCount              = $errorList.Count
        Errors                  = [string[]]$errorList
    }
}
