<#PSScriptInfo

.DESCRIPTION Runs the worker on one or more remote computers with a single Invoke-Command call

.VERSION 1.3.0

.GUID 5bbeeeb6-8b12-4066-afdb-7b15389eac2c

.AUTHOR Tom Stryhn

.COMPANYNAME Tom Stryhn

.COPYRIGHT 2026 (c) Tom Stryhn

.LICENSEURI https://github.com/tomstryhn/RemoteFirewall/blob/main/LICENSE

.PROJECTURI https://github.com/tomstryhn/RemoteFirewall

#>

function Invoke-FirewallInventoryRemote {

    <#
    .SYNOPSIS
        Runs the worker on one or more remote computers with a single Invoke-Command call.

    .DESCRIPTION
        Kept as its own function, rather than calling Invoke-Command directly from the public
        function, so tests can mock this one boundary and control both the streamed worker
        objects and the error records without depending on -ErrorVariable behaviour under a mock.
        Each worker-shaped object carrying a PSComputerName note property is passed to -OnResult
        as it arrives from the pipeline, one at a time, so the caller can finish with one result
        (write its folder, build its row) and drop its reference before the next one is held,
        rather than holding every target's result until the whole pipeline ends. Every error
        record Invoke-Command collects through -ErrorVariable is returned once the pipeline has
        ended.

    .PARAMETER ComputerName
        The remote targets to contact, already resolved and de-duplicated.

    .PARAMETER Credential
        Forwarded to Invoke-Command when supplied. Omitted entirely, not passed as $null, when
        the caller supplies nothing.

    .PARAMETER ThrottleLimit
        Forwarded to Invoke-Command.

    .PARAMETER OnResult
        Invoked once per worker-shaped object as it arrives from Invoke-Command, before the next
        one is read from the pipeline.

    .PARAMETER UseSSL
        Forwarded to Invoke-Command as UseSSL when set. Omitted entirely, not passed as
        $false, when the caller does not supply it.

    .PARAMETER SkipSidReference
        Passed to the worker as its only argument, a real [bool], on every call: $false without
        the switch and $true with it. The worker takes it as its first, positional parameter.

    .NOTES
        FUNCTION: Invoke-FirewallInventoryRemote
        AUTHOR:   Tom Stryhn
        GITHUB:   https://github.com/tomstryhn/

    .INPUTS
        None. Does not accept pipeline input.

    .OUTPUTS
        System.Management.Automation.PSObject
    #>

    param(
        [Parameter(Mandatory = $true)]
        [string[]]$ComputerName,

        [System.Management.Automation.PSCredential]
        $Credential,

        [Parameter(Mandatory = $true)]
        [int]$ThrottleLimit,

        [Parameter(Mandatory = $true)]
        [scriptblock]$OnResult,

        [switch]$UseSSL,

        [switch]$SkipSidReference
    )

    $invokeParams = @{
        ComputerName  = @($ComputerName)
        ScriptBlock   = Get-FirewallInventoryWorker
        ThrottleLimit = $ThrottleLimit
        ErrorAction   = 'SilentlyContinue'
        ErrorVariable = 'remoteErrors'
    }
    # Always passed, with or without the switch: the worker's first parameter is positional and a real bool, never a switch object or a string.
    $invokeParams['ArgumentList'] = @([bool]$SkipSidReference)
    if ($Credential) { $invokeParams['Credential'] = $Credential }
    if ($UseSSL) { $invokeParams['UseSSL'] = $true }

    $remoteErrors = $null
    Invoke-Command @invokeParams | ForEach-Object { & $OnResult $_ }

    return [pscustomobject]@{
        Errors = @($remoteErrors)
    }
}
