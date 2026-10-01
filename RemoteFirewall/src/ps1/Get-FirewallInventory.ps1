<#PSScriptInfo

.DESCRIPTION Collects the Windows Firewall profile settings, global settings and every firewall rule with its filters from local or remote computers

.VERSION 1.2.0

.GUID b71741ea-bd85-4cfb-b334-7e8f3dd60e6c

.AUTHOR Tom Stryhn

.COMPANYNAME Tom Stryhn

.COPYRIGHT 2026 (c) Tom Stryhn

.LICENSEURI https://github.com/tomstryhn/RemoteFirewall/blob/main/LICENSE

.PROJECTURI https://github.com/tomstryhn/RemoteFirewall

#>

function Get-FirewallInventory {

    <#
    .SYNOPSIS
        Collects the Windows Firewall profile settings, global settings and every firewall rule
        with its filters from local or remote computers.

    .DESCRIPTION
        Collects the Windows Firewall (Windows Defender Firewall with Advanced Security) on the
        local computer in-process or on remote computers over WinRM (one Invoke-Command call for
        every remote target): the settings of the three profiles, the global settings, and every
        rule in the active store with its seven filters (address, port, application, service,
        interface, interface type and security), as the firewall reports them. Nothing is
        interpreted. A rule delivered by Group Policy is identified by a traced read: its
        PolicyStoreSourceType is GroupPolicy and PolicyStoreSource names the GPO. Each security
        principal a rule names (the rule owner, the application package, and the users and
        machines of its security descriptors) is resolved once to its SID and name where the
        target can. An application package SID is resolved to its package family name from the
        packages installed on the target (Get-AppxPackage -AllUsers, which needs elevation; an
        unelevated run or a target without the Appx module leaves those SIDs NotFound). The raw
        files are written to a per-computer folder under -OutputPath together with the identity
        of the computer and every error seen on the way. A separate project analyses the files
        and decides which rules need attention.

        Not collected: connection security (IPsec) and main mode rules, Hyper-V firewall rules,
        hashes and signatures of rule programs, the registry rule stores, the persistent and
        Group Policy stores as separate reads, and the AppContainer isolation rules that the rule
        cmdlet does not list.

        Prerequisites, and nothing beyond them: the NetSecurity module on the target (it ships
        with Windows), Windows PowerShell 5.1 on the target. The target is only read, never
        changed. Administrative rights are recommended but not required: without them the address,
        port, interface and interface type filters of every rule are withheld, the row comes back
        Partial with those four filter classes named and a packages: error line, and the rules
        themselves, the profiles and the other three filters are still collected. Remote targets additionally need WinRM
        reachable from the caller. Local targets never use WinRM. Remote targets called without
        -Credential use the caller's own identity, exactly like any other Invoke-Command call.
        Nothing in this module is specific to any domain, server name, or account. It works
        unchanged on a domain-joined computer or on a workgroup computer.

        Writes <OutputPath>\RemoteFirewall-<yyyyMMdd-HHmmss>Z\ containing run.json, results.csv,
        and one folder per computer that was actually reached. Every failure short of a bad
        -OutputPath or an empty -ComputerName list becomes a result row plus one Write-Warning.
        It is never a terminating error.

        Results are completed as they arrive rather than after every target has answered: each
        remote result has its folder written and its row built as soon as it arrives, and the
        reference to it is dropped before the next one is read.

    .PARAMETER ComputerName
        Targets. '.', 'localhost', '127.0.0.1', '::1', the local NetBIOS name and the local FQDN
        (case-insensitive) run in-process without WinRM. Everything else goes through one
        Invoke-Command call. Accepts pipeline input by value and by property name. Duplicates are
        removed case-insensitively. The first-seen order is kept. Defaults to the local computer
        name when nothing is supplied.

    .PARAMETER Credential
        Passed to Invoke-Command for remote targets only. Ignored for local targets (a
        Write-Verbose line records that it was ignored). When omitted, remote targets are
        contacted with the caller's own identity.

    .PARAMETER UseSSL
        Connects to remote targets over WinRM HTTPS (port 5986) instead of HTTP. Each target
        needs an HTTPS listener with a certificate the calling computer trusts, and the name you
        pass must match the certificate's subject or subject alternative name, which is normally
        the computer's fully qualified domain name (FQDN). A short name or an IP address fails
        the certificate name check with WinRM error 12175. Certificate checks are never skipped:
        the module offers no SkipCACheck or SkipCNCheck option, by design. Ignored for local
        targets, which never use WinRM. Recorded as UseSSL in run.json.

    .PARAMETER OutputPath
        Root folder for the run. May be relative. Resolved once, against the current location,
        before any collection starts. Created if missing. Must be writable. This is tested by
        creating the run folder before any collection starts, so a bad -OutputPath fails before
        any target is contacted.

    .PARAMETER ThrottleLimit
        Passed to Invoke-Command for remote targets. From 1 to 256. Defaults to 32.

    .EXAMPLE
        PS C:\> Get-FirewallInventory -OutputPath C:\FirewallRuns | Format-List

        ComputerName           : WS01
        ComputerId             : 11111111-2222-3333-4444-555555555501
        Status                 : Success
        Transport              : Local
        OutputFolder           : C:\FirewallRuns\RemoteFirewall-20260930-195942Z\WS01_26300_20260930-195948Z
        IsElevated             : True
        ProfileCount           : 3
        RuleCount              : 574
        FilterFailedCount      : 0
        SddlFailedCount        : 0
        AccountCount           : 4
        AccountUnresolvedCount : 1
        Error                  :
        ErrorCount             : 0
        Errors                 : {}

        Collects from the local computer only, run elevated on a workgroup Windows 11 host. All
        seven filters were read for the 574 rules. One of the four accounts the rules name does
        not resolve to a name; that is data and does not change Status.

    .EXAMPLE
        PS C:\FirewallTest> '.', 'localhost', 'SRV010', 'DC01', 'dc01.contoso.com', 'SRV099', 'NOSUCHHOST01' |
            Get-FirewallInventory -OutputPath 'out' |
            Format-Table -Property ComputerName, ComputerId, Status, Transport, ProfileCount, RuleCount, FilterFailedCount, SddlFailedCount, AccountCount, AccountUnresolvedCount, ErrorCount

        ComputerName     ComputerId                           Status  Transport ProfileCount RuleCount FilterFailedCount SddlFailedCount AccountCount AccountUnresolvedCount ErrorCount
        ------------     ----------                           ------  --------- ------------ --------- ----------------- --------------- ------------ ---------------------- ----------
        .                11111111-2222-3333-4444-555555555504 Success Local                3       300                 0               0           15                     14          0
        localhost        11111111-2222-3333-4444-555555555504 Success Local                3       300                 0               0           15                     14          0
        SRV010           11111111-2222-3333-4444-555555555504 Success Local                3       300                 0               0           15                     14          0
        DC01             11111111-2222-3333-4444-555555555503 Success WinRM                3       310                 0               0           15                     14          0
        dc01.contoso.com 11111111-2222-3333-4444-555555555503 Success WinRM                3       310                 0               0           15                     14          0
        SRV099           11111111-2222-3333-4444-555555555502 Success WinRM                3       263                 0               0           15                     14          0
        NOSUCHHOST01                                          Failed  WinRM                                                                                                           1
        WARNING: NOSUCHHOST01: Connecting to remote server NOSUCHHOST01 failed with the following error message : WinRM cannot process the request. The following error occurred while using Kerberos authentication: Cannot find the computer NOSUCHHOST01. Verify that the computer exists on the network and that the name provided is spelled correctly. For more information, see the about_Remote_Troubleshooting Help topic.

        Run from SRV010, a Windows Server 2022 domain member, against local aliases, a NetBIOS and
        FQDN pair, another domain member over WinRM, and one name that does not resolve. The three
        local aliases give identical rows, DC01 and dc01.contoso.com are one computer requested
        twice, and the name that does not resolve comes back as a Failed result row, not a
        terminating error.

    .EXAMPLE
        PS C:\FirewallTest> Get-FirewallInventory -ComputerName 'SRV099.contoso.com' -UseSSL -OutputPath 'out' | Format-Table -Property ComputerName, ComputerId, Status, Transport, RuleCount, ErrorCount

        ComputerName       ComputerId                           Status  Transport RuleCount ErrorCount
        ------------       ----------                           ------  --------- --------- ----------
        SRV099.contoso.com 11111111-2222-3333-4444-555555555502 Success WinRM           263          0

        Collects from one domain member over WinRM HTTPS (port 5986). The name is the FQDN, which
        matches the listener certificate, and run.json of that run has UseSSL True and
        SchemaVersion 1.2.

    .NOTES
        FUNCTION: Get-FirewallInventory
        AUTHOR:   Tom Stryhn
        GITHUB:   https://github.com/tomstryhn/

    .INPUTS
        System.String[]. ComputerName is accepted from the pipeline, by value and by property
        name.

    .OUTPUTS
        System.Management.Automation.PSObject, type name RemoteFirewall.Result

    .LINK
        https://github.com/tomstryhn/RemoteFirewall
    #>

    [CmdletBinding()]
    param(
        [Parameter(Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [string[]]$ComputerName = @($env:COMPUTERNAME),

        [System.Management.Automation.PSCredential]
        $Credential,

        [switch]$UseSSL,

        [Parameter(Mandatory = $true)]
        [string]$OutputPath,

        [ValidateRange(1, 256)]
        [int]$ThrottleLimit = 32
    )

    begin {
        Set-StrictMode -Version Latest
        $ErrorActionPreference = 'Stop'

        $collectedNames = @()
    }

    process {
        if ($ComputerName) { $collectedNames += @($ComputerName) }
    }

    end {
        # Resolved once here, against the caller's current location, not $PSScriptRoot or any other implicit base, and used everywhere after.
        $resolvedOutputPath = $PSCmdlet.GetUnresolvedProviderPathFromPSPath($OutputPath)

        $resolvedNames = @(Resolve-FirewallInventoryComputerList -ComputerName $collectedNames)
        if ($resolvedNames.Count -eq 0) {
            throw 'ComputerName is empty after removing blanks and duplicates.'
        }

        $localNames = @()
        $remoteNames = @()
        foreach ($name in $resolvedNames) {
            if (Test-FirewallInventoryLocalName -Name $name) {
                $localNames += $name
            } else {
                $remoteNames += $name
            }
        }

        $runFolder = Initialize-FirewallInventoryRunFolder -OutputPath $resolvedOutputPath

        $startUtc = (Get-Date).ToUniversalTime()

        $rowMap = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([System.StringComparer]::OrdinalIgnoreCase)

        # Names of remote results that matched no requested computer. The callback only records them, and the warnings are the last statements of the function: under a caller's -WarningAction Stop a warning is a terminating error, and written inside the callback or before the files and rows exist it would end the run with nothing delivered. Created here, at run level, so the final loop can read it when no remote name was requested.
        $unattributedNames = New-Object 'System.Collections.Generic.List[string]'
        # Messages of remote errors that matched no requested computer and no unresolved name. Recorded here and warned about at the end of the function, for the same reason as the unattributed results: a warning is a terminating error under a caller's -WarningAction Stop, and it must not end the run before the files exist.
        $unattributedErrorMessages = [System.Collections.Generic.List[string]]::new()

        if ($localNames.Count -gt 0) {
            # Local aliases share one worker run and one OutputFolder. The worker runs exactly once per call no matter how many aliases were requested, and each alias still gets its own row.
            if ($Credential) {
                Write-Verbose "Credential ignored for local targets: $($localNames -join ', ')."
            }
            if ($UseSSL) {
                Write-Verbose "UseSSL ignored for local targets: $($localNames -join ', ')."
            }
            Write-Verbose "Collecting locally: $($localNames -join ', ')"

            $localWorkerObject = $null
            $localExtraErrors = @()
            try {
                $localWorkerObject = Invoke-FirewallInventoryLocal
            } catch {
                $localExtraErrors += $_.Exception.Message
            }

            # The first alias completes the computer and writes the folder. Every later alias copies that row and changes only ComputerName, so no two rows for one folder can ever disagree on Status, a count or Errors.
            $firstLocalRow = $null
            foreach ($name in $localNames) {
                if ($null -eq $firstLocalRow) {
                    $firstLocalRow = Complete-FirewallInventoryComputer -RequestedComputerName $name -Transport 'Local' -RunFolder $runFolder -WorkerObject $localWorkerObject -ExtraErrors $localExtraErrors
                    $rowMap[$name] = $firstLocalRow
                } else {
                    $aliasRow = $firstLocalRow.PSObject.Copy()
                    $aliasRow.ComputerName = $name
                    $rowMap[$name] = $aliasRow
                }
            }
        }

        if ($remoteNames.Count -gt 0) {
            Write-Verbose "Collecting remotely over WinRM: $($remoteNames -join ', ')"

            # Rows are built from the worker results as they stream in, then errors are mapped onto those rows afterward, never the reverse, so an error never overwrites a row a worker result already produced. Results are completed as they arrive rather than after every target has answered: each one is completed and released inside -OnResult, before the next one is read from the pipeline.
            $matchedResultNames = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)

            $onRemoteResult = {
                param($res)

                $pcName = $null
                $requested = $null
                # The whole body sits in one try so that nothing a single result does can throw out of the callback and end the run: the computer is reported Failed instead and the next result is still read.
                try {
                    $pcName = Get-FirewallInventorySafeProperty -InputObject $res -Name 'PSComputerName' -Default $null
                    foreach ($rn in $remoteNames) {
                        if ($rn -ieq $pcName) { $requested = $rn; break }
                    }
                    if (-not $requested) {
                        # A result whose PSComputerName matches no requested name gets no folder and no row: it would never be emitted, because rows are built from the requested names only.
                        [void]$unattributedNames.Add($pcName)
                        return
                    }

                    $row = Complete-FirewallInventoryComputer -RequestedComputerName $requested -Transport 'WinRM' -RunFolder $runFolder -WorkerObject $res -ExtraErrors @()
                    $rowMap[$requested] = $row
                    [void]$matchedResultNames.Add($requested)
                } catch {
                    $hostMessage = "host: $($_.Exception.Message)"
                    if ($requested) {
                        $rowMap[$requested] = ConvertTo-FirewallInventoryResultRow -ComputerName $requested -Status 'Failed' -Transport 'WinRM' -Errors @($hostMessage)
                        [void]$matchedResultNames.Add($requested)
                    } else {
                        # The failure came before the result could be attributed, so there is no requested name to carry a row.
                        [void]$unattributedNames.Add($pcName)
                    }
                }
            }

            $remoteResult = $null
            $remoteCallError = $null
            try {
                $remoteResult = Invoke-FirewallInventoryRemote -ComputerName $remoteNames -Credential $Credential -ThrottleLimit $ThrottleLimit -OnResult $onRemoteResult -UseSSL:$UseSSL
            } catch {
                $remoteCallError = $_.Exception.Message
            }

            $pendingErrors = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([System.StringComparer]::OrdinalIgnoreCase)
            foreach ($rn in $remoteNames) { $pendingErrors[$rn] = New-Object 'System.Collections.Generic.List[string]' }

            if ($null -ne $remoteResult) {
                foreach ($err in @($remoteResult.Errors)) {
                    $message = Get-FirewallInventorySafeProperty -InputObject $err -Name 'Exception' -Default $null
                    $messageText = if ($message) { Get-FirewallInventorySafeProperty -InputObject $message -Name 'Message' -Default "$err" } else { "$err" }

                    $matchedName = Resolve-FirewallInventoryRemoteErrorName -ErrorRecord $err -RemoteNames $remoteNames

                    if ($matchedName) {
                        $pendingErrors[$matchedName].Add($messageText)
                    } else {
                        $unresolvedNames = @($remoteNames | Where-Object { -not $matchedResultNames.Contains($_) })
                        if ($unresolvedNames.Count -gt 0) {
                            foreach ($rn in $unresolvedNames) { $pendingErrors[$rn].Add($messageText) }
                        } else {
                            [void]$unattributedErrorMessages.Add($messageText)
                        }
                    }
                }
            }

            foreach ($rn in $remoteNames) {
                if ($matchedResultNames.Contains($rn)) {
                    $row = $rowMap[$rn]
                    foreach ($msg in $pendingErrors[$rn]) {
                        # Collapsed to one trimmed line like every other message: this entry is added after the row builder ran, so it never went through the collapse there, and a remote connection error spans several lines.
                        $row.Errors += ([string]$msg).Trim() -replace '\s+', ' '
                    }
                    # A late host-side error appended here after the row was already built from the worker object, so ErrorCount and Error are recomputed from Errors rather than left at the counts the worker object alone produced.
                    $row.ErrorCount = @($row.Errors).Count
                    if ([string]::IsNullOrEmpty($row.Error) -and $row.ErrorCount -gt 0) { $row.Error = $row.Errors[0] }
                } else {
                    $extraErrors = @($pendingErrors[$rn])
                    if ($extraErrors.Count -eq 0) {
                        $extraErrors = @( $(if ($remoteCallError) { $remoteCallError } else { 'no result and no error returned' }) )
                    }
                    $row = Complete-FirewallInventoryComputer -RequestedComputerName $rn -Transport 'WinRM' -RunFolder $runFolder -WorkerObject $null -ExtraErrors $extraErrors
                    $rowMap[$rn] = $row
                }
            }
        }

        $rows = @()
        foreach ($name in $resolvedNames) {
            $rows += $rowMap[$name]
        }

        $endUtc = (Get-Date).ToUniversalTime()

        $runInfo = [pscustomobject]@{
            RunId              = Split-Path -Path $runFolder -Leaf
            Collector          = 'RemoteFirewall'
            CollectorVersion   = $MyInvocation.MyCommand.Module.Version.ToString()
            SchemaVersion      = '1.2'
            HostComputer       = $env:COMPUTERNAME
            HostComputerId     = Get-FirewallInventoryHostComputerId
            HostUser           = "$env:USERDOMAIN\$env:USERNAME"
            PSVersion          = $PSVersionTable.PSVersion.ToString()
            StartUtc           = $startUtc.ToString('yyyy-MM-ddTHH:mm:ssZ', [System.Globalization.CultureInfo]::InvariantCulture)
            EndUtc             = $endUtc.ToString('yyyy-MM-ddTHH:mm:ssZ', [System.Globalization.CultureInfo]::InvariantCulture)
            RequestedComputers = @($resolvedNames)
            ThrottleLimit      = $ThrottleLimit
            UseSSL             = [bool]$UseSSL
            Results            = @($rows)
        }

        try {
            $runJson = $runInfo | ConvertTo-Json -Depth 8
            Write-FirewallInventoryTextFile -Path (Join-Path $runFolder 'run.json') -Content $runJson
        } catch {
            Write-Warning "Failed to write run.json: $($_.Exception.Message)"
        }

        try {
            $csvRows = @()
            foreach ($row in $rows) {
                $csvRows += $row | Select-Object -Property * -ExcludeProperty Errors
            }
            $csvPath = Join-Path $runFolder 'results.csv'
            Write-FirewallInventoryCsvFile -Row $csvRows -Path $csvPath
        } catch {
            Write-Warning "Failed to write results.csv: $($_.Exception.Message)"
        }

        foreach ($row in $rows) {
            if ($row.Status -ne 'Success') {
                Write-Warning "$($row.ComputerName): $($row.Error)"
            }
            $row
        }

        # The last statements of the function, after run.json and results.csv are written and every row is out: a caller's -WarningAction Stop turns each warning into a terminating error, and written any earlier it would end the run before its files and rows existed.
        foreach ($unattributedName in $unattributedNames) {
            Write-Warning "Unattributed remote result, matched no requested computer name: $unattributedName"
        }
        foreach ($unattributedMessage in $unattributedErrorMessages) {
            Write-Warning "Unattributed remote error, matched no requested computer name: $unattributedMessage"
        }
    }
}
