<#PSScriptInfo

.DESCRIPTION Returns the self-contained scriptblock that collects the firewall inventory on a target

.VERSION 1.3.0

.GUID dd6fa18d-5095-4296-ae0b-7a76eaa171c1

.AUTHOR Tom Stryhn

.COMPANYNAME Tom Stryhn

.COPYRIGHT 2026 (c) Tom Stryhn

.LICENSEURI https://github.com/tomstryhn/RemoteFirewall/blob/main/LICENSE

.PROJECTURI https://github.com/tomstryhn/RemoteFirewall

#>

function Get-FirewallInventoryWorker {

    <#
    .SYNOPSIS
        Returns the self-contained scriptblock that collects the firewall inventory on a target.

    .DESCRIPTION
        The scriptblock this function returns is what actually runs on the target, local or
        remote, so it uses no module function, no module variable and no using: expression. It
        takes one parameter, SkipSidReference, and depends on nothing else from the caller's
        session. The parameter is a [bool], false by default, and the first one of the
        scriptblock because the remote call passes it by position; when true the four SID
        reference values are not read and are null, with no error. It reads the SID reference (MachineSid, from the local account with RID 500
        read through Win32_UserAccount, and on a domain-joined computer DomainSid,
        ComputerAccountSid and DomainNetbiosName, from the computer's own domain account through
        an account lookup), the three firewall profiles and the global settings as enforced (the active store), every
        firewall rule of the active store, the seven filter classes of those rules (one call per
        class, joined on InstanceID), and the SID of every principal the rules name (the owner,
        the application package and the access control entries of the user and machine
        descriptors), resolves an application package SID to its package family name from the
        packages installed on the target (Get-AppxPackage -AllUsers, hashed the way Windows
        derives the SID, and nothing is resolved when the command is absent or the read is
        refused), and returns one flat object describing the target and all of it, as plain
        data only: strings, numbers, booleans, arrays of strings and ordered property bags.
        It never throws: every step is wrapped in its own try/catch and appends to an Errors
        list instead. It changes nothing on the target and writes nothing to its disk.
        Invoke-FirewallInventoryLocal calls it directly for the local computer.
        Invoke-FirewallInventoryRemote passes it to Invoke-Command for every remote target.

    .NOTES
        FUNCTION: Get-FirewallInventoryWorker
        AUTHOR:   Tom Stryhn
        GITHUB:   https://github.com/tomstryhn/

    .INPUTS
        None. Does not accept pipeline input.

    .OUTPUTS
        System.Management.Automation.ScriptBlock
    #>

    param()

    return {
        # First and positional: Invoke-Command passes its ArgumentList by position, so a parameter added before this one would receive the wrong value.
        param(
            [bool]$SkipSidReference = $false
        )

        # Off here, not only in the public function, so the worker behaves the same in-process as on a remote target, where strict mode is off by default.
        Set-StrictMode -Off

        function Add-FirewallInventoryRowContent {
            <#
            .SYNOPSIS
                Reads the listed properties of source objects and stores them as plain data under their own names in a property bag.
            #>
            param(
                [Parameter(Mandatory)]
                $Row,

                [Parameter(Mandatory)]
                $Sources,

                [Parameter(Mandatory)]
                $Columns
            )

            # One call per object, the loop over its columns inside, because a function call per column costs seconds on a few hundred rules. Each column is the source key, the property name and the kind.
            $propertyBags = @{}
            foreach ($column in $Columns) {
                $sourceKey = $column[0]
                $name = $column[1]
                $kind = $column[2]

                # The property collection of a source is taken once per call, not once per column: on a CIM instance each lookup through PSObject.Properties is slow.
                if (-not $propertyBags.ContainsKey($sourceKey)) {
                    $propertyBags[$sourceKey] = $null
                    if ($null -ne $Sources[$sourceKey]) { $propertyBags[$sourceKey] = $Sources[$sourceKey].PSObject.Properties }
                }
                $sourceProps = $propertyBags[$sourceKey]

                # The result is stored into the bag, never returned, so an empty or one-element array is never unrolled by the pipeline on its way to the caller.
                $present = $false
                $value = $null
                if ($null -ne $sourceProps) {
                    $prop = $sourceProps[$name]
                    if ($null -ne $prop) {
                        $present = $true
                        $value = $prop.Value
                    }
                }

                # A property the source lacks, and a source that was never read (a filter class that failed), give null for every kind, arrays included.
                if (-not $present) {
                    $Row[$name] = $null
                } elseif ($kind -eq 'Array') {
                    $items = [System.Collections.Generic.List[string]]::new()
                    if ($null -ne $value) {
                        foreach ($item in @($value)) {
                            if ($null -ne $item) { [void]$items.Add([string]$item) }
                        }
                    }
                    $Row[$name] = $items.ToArray()
                } elseif ($null -eq $value) {
                    $Row[$name] = $null
                } elseif ($kind -eq 'Bool') {
                    if ($value -is [bool]) {
                        $Row[$name] = [bool]$value
                    } else {
                        $text = ([string]$value).Trim()
                        if ($text -ieq 'True') { $Row[$name] = $true }
                        elseif ($text -ieq 'False') { $Row[$name] = $false }
                        else { $Row[$name] = $null }
                    }
                } elseif ($kind -eq 'Number') {
                    # An integral value of any integer type stays a number: Int64 whenever it fits, UInt64 above that, so the "not configured" marker of LogMaxSizeKilobytes (the largest UInt64) is never lost. A string that parses as an integer becomes a number. Anything else, a boolean and an enumeration included, is null.
                    $number = $null
                    if (($value -is [int64]) -or ($value -is [int32]) -or ($value -is [int16]) -or ($value -is [sbyte]) -or ($value -is [byte]) -or ($value -is [uint16]) -or ($value -is [uint32])) {
                        $number = [int64]$value
                    } elseif ($value -is [uint64]) {
                        if ([uint64]$value -le [uint64][int64]::MaxValue) { $number = [int64]$value } else { $number = [uint64]$value }
                    } elseif ($value -is [string]) {
                        $signed = [int64]0
                        $unsigned = [uint64]0
                        $numberText = $value.Trim()
                        if ([int64]::TryParse($numberText, [System.Globalization.NumberStyles]::Integer, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$signed)) {
                            $number = $signed
                        } elseif ([uint64]::TryParse($numberText, [System.Globalization.NumberStyles]::Integer, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$unsigned)) {
                            $number = $unsigned
                        }
                    }
                    $Row[$name] = $number
                } else {
                    # An enumeration becomes its display string, a string stays as it is: nothing is translated or trimmed.
                    $Row[$name] = [string]$value
                }
            }
        }

        function ConvertTo-FirewallInventoryMessage {
            <#
            .SYNOPSIS
                Returns a message as a single trimmed line.
            #>
            param(
                [AllowNull()]
                [string]$Text
            )

            return ([string]$Text).Trim() -replace '\s+', ' '
        }

        function Join-FirewallInventoryFilter {
            <#
            .SYNOPSIS
                Joins the filter objects of one class to the rules, by position when the InstanceID sequences agree and by InstanceID otherwise.
            #>
            param(
                [Parameter(Mandatory)]
                [AllowEmptyCollection()]
                $RuleIds,

                [Parameter(Mandatory)]
                [AllowEmptyCollection()]
                $FilterObjects,

                [Parameter(Mandatory)]
                [AllowEmptyCollection()]
                $Joined,

                [Parameter(Mandatory)]
                [AllowEmptyCollection()]
                $AmbiguousIds
            )

            # The result goes into $Joined (one slot per rule, $null where no filter object belongs to the rule) and $AmbiguousIds, never to the output stream, so an empty result is never unrolled.
            $filterIds = [System.Collections.Generic.List[object]]::new()
            foreach ($filterObject in $FilterObjects) {
                $filterId = $null
                $instanceProp = $filterObject.PSObject.Properties['InstanceID']
                if ($null -ne $instanceProp -and $null -ne $instanceProp.Value) { $filterId = [string]$instanceProp.Value }
                [void]$filterIds.Add($filterId)
            }

            # The filter reads enumerate in the order of the rule read, so equal InstanceID sequences (ordinal, ignoring case) mean filter object i belongs to rule i, even when several rules share an id.
            $sameSequence = ($filterIds.Count -eq $RuleIds.Count)
            if ($sameSequence) {
                for ($i = 0; $i -lt $RuleIds.Count; $i++) {
                    $ruleId = $RuleIds[$i]
                    $filterId = $filterIds[$i]
                    if (($null -eq $ruleId) -and ($null -eq $filterId)) { continue }
                    if (($null -eq $ruleId) -or ($null -eq $filterId) -or (-not [string]::Equals([string]$ruleId, [string]$filterId, [System.StringComparison]::OrdinalIgnoreCase))) {
                        $sameSequence = $false
                        break
                    }
                }
            }
            if ($sameSequence) {
                # A rule or a filter object without an InstanceID is never joined, in position or otherwise.
                for ($i = 0; $i -lt $RuleIds.Count; $i++) {
                    if ($null -ne $RuleIds[$i]) { $Joined[$i] = $FilterObjects[$i] }
                }
                return
            }

            # The sequences differ: only an id carried by exactly one rule and exactly one filter object is joined; an id carried by more than one of either is ambiguous and stays null on every rule with that id.
            $ruleIdCount = [System.Collections.Generic.Dictionary[string, int]]::new([System.StringComparer]::OrdinalIgnoreCase)
            foreach ($ruleId in $RuleIds) {
                if ($null -eq $ruleId) { continue }
                if ($ruleIdCount.ContainsKey([string]$ruleId)) { $ruleIdCount[[string]$ruleId] = $ruleIdCount[[string]$ruleId] + 1 } else { $ruleIdCount[[string]$ruleId] = 1 }
            }
            $filterIdCount = [System.Collections.Generic.Dictionary[string, int]]::new([System.StringComparer]::OrdinalIgnoreCase)
            $filterById = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::OrdinalIgnoreCase)
            for ($i = 0; $i -lt $filterIds.Count; $i++) {
                $filterId = $filterIds[$i]
                if ($null -eq $filterId) { continue }
                if ($filterIdCount.ContainsKey($filterId)) { $filterIdCount[$filterId] = $filterIdCount[$filterId] + 1 } else { $filterIdCount[$filterId] = 1 }
                $filterById[$filterId] = $FilterObjects[$i]
            }
            $reported = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            for ($i = 0; $i -lt $RuleIds.Count; $i++) {
                $ruleId = $RuleIds[$i]
                if ($null -eq $ruleId) { continue }
                $filtersForId = 0
                if ($filterIdCount.ContainsKey([string]$ruleId)) { $filtersForId = $filterIdCount[[string]$ruleId] }
                if (($ruleIdCount[[string]$ruleId] -gt 1) -or ($filtersForId -gt 1)) {
                    if ($reported.Add([string]$ruleId)) { [void]$AmbiguousIds.Add([string]$ruleId) }
                } elseif ($filtersForId -eq 1) {
                    $Joined[$i] = $filterById[[string]$ruleId]
                }
            }
        }

        $errors = @()

        #region Identity
        $dnsHostName = $null
        $domain = $null
        $partOfDomain = $false
        $domainRole = -1
        $osCaption = $null
        $osVersion = $null
        $currentBuild = $null
        $ubr = $null
        $displayVersion = $null
        $editionId = $null
        $installationType = $null
        $culture = $null
        $timeZoneId = $null
        $isElevated = $false
        $collectedBy = $null

        try {
            $cv = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
            $currentBuild = $cv.CurrentBuild
            if ($null -ne $cv.UBR) { $ubr = $cv.UBR.ToString() }
            $displayVersion = $cv.DisplayVersion
            $editionId = $cv.EditionID
            $installationType = $cv.InstallationType
        } catch {
            $errors += "CurrentVersion key: $($_.Exception.Message)"
        }

        $os = $null
        $cs = $null
        try {
            $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop -Verbose:$false
            $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop -Verbose:$false
        } catch {
            $errors += "Get-CimInstance failed: $($_.Exception.Message)"
        }

        if ($null -ne $os) {
            $osCaption = $os.Caption
            $osVersion = $os.Version
        }
        if ($null -ne $cs) {
            $dnsHostName = $cs.DNSHostName
            $domain = $cs.Domain
            $partOfDomain = [bool]$cs.PartOfDomain
            if ($null -ne $cs.DomainRole) { $domainRole = [int]$cs.DomainRole }
        }

        try {
            $culture = [System.Globalization.CultureInfo]::CurrentCulture.Name
        } catch {
            $errors += "culture: $($_.Exception.Message)"
        }

        try {
            $timeZoneId = [System.TimeZoneInfo]::Local.Id
        } catch {
            $errors += "time zone: $($_.Exception.Message)"
        }

        try {
            $winIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
            $collectedBy = $winIdentity.Name
            $winPrincipal = New-Object System.Security.Principal.WindowsPrincipal($winIdentity)
            $isElevated = $winPrincipal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
        } catch {
            $errors += "elevation check: $($_.Exception.Message)"
            $isElevated = $false
        }
        #endregion

        #region Computer identity
        $computerId = $null
        $machineGuid = $null
        try {
            $product = $null
            $product = Get-CimInstance -ClassName Win32_ComputerSystemProduct -ErrorAction Stop -Verbose:$false
            if ($null -ne $product -and $null -ne $product.PSObject.Properties['UUID'] -and -not [string]::IsNullOrWhiteSpace([string]$product.UUID)) {
                $computerId = ([string]$product.UUID).Trim().ToUpperInvariant()
            }
        }
        catch { $errors += "identity: ComputerId: $($_.Exception.Message)" }
        try {
            $machineGuid = [string](Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Cryptography' -Name MachineGuid -ErrorAction Stop).MachineGuid
        }
        catch { $errors += "identity: MachineGuid: $($_.Exception.Message)" }
        #endregion

        #region SID reference
        # Four reference values that say whose an S-1-5-21 SID is; none is used as identity. MachineSid is the SID of the computer's own account database: the built-in Administrator (RID 500, whatever its name or state) without the RID. The filter names the computer as the domain, so only the local accounts are read; a domain controller has no such row and keeps null with no error. The domain values come from the computer's own account and are read only on a domain-joined computer. -SkipSidReference leaves all four null with no error.
        $machineSid = $null
        $domainSid = $null
        $computerAccountSid = $null
        $domainNetbiosName = $null
        if (-not $SkipSidReference) {
            try {
                $localAccounts = @(Get-CimInstance -ClassName Win32_UserAccount -Filter ('Domain = "{0}"' -f $env:COMPUTERNAME) -ErrorAction Stop -Verbose:$false)
                foreach ($localAccount in $localAccounts) {
                    if ([string]$localAccount.SID -match '^(S-1-5-21-\d+-\d+-\d+)-500$') {
                        $machineSid = $matches[1]
                        break
                    }
                }
            }
            catch { $errors += "identity: MachineSid: $($_.Exception.Message)" }

            if ($partOfDomain) {
                $computerAccountSidObject = $null
                try {
                    $computerAccount = New-Object System.Security.Principal.NTAccount(($domain + '\' + $env:COMPUTERNAME + '$'))
                    $computerAccountSidObject = $computerAccount.Translate([System.Security.Principal.SecurityIdentifier])
                    $computerAccountSid = $computerAccountSidObject.Value
                    $domainSid = $computerAccountSidObject.AccountDomainSid.Value
                }
                catch {
                    $computerAccountSidObject = $null
                    $computerAccountSid = $null
                    $domainSid = $null
                    $errors += "identity: DomainSid: $($_.Exception.GetBaseException().Message)"
                }

                if ($null -ne $computerAccountSidObject) {
                    try {
                        $computerAccountName = $computerAccountSidObject.Translate([System.Security.Principal.NTAccount]).Value
                        $separatorIndex = $computerAccountName.IndexOf('\')
                        if ($separatorIndex -gt 0) { $domainNetbiosName = $computerAccountName.Substring(0, $separatorIndex) }
                    }
                    catch { $errors += "identity: DomainNetbiosName: $($_.Exception.GetBaseException().Message)" }
                }
            }
        }
        #endregion

        #region Profiles
        $profiles = @()
        $profileCount = 0
        $activeProfile = $null
        $settings = $null
        $profilesDurationMs = 0

        # Column lists in the order of the contract, each column being the source key, the property name and the kind. Kind is Text (an enumeration or a string, as a string), Bool, Number or Array (always an array of strings).
        $profileColumns = @(
            @('Item', 'Name', 'Text'), @('Item', 'Enabled', 'Text'), @('Item', 'DefaultInboundAction', 'Text'), @('Item', 'DefaultOutboundAction', 'Text'),
            @('Item', 'AllowInboundRules', 'Text'), @('Item', 'AllowLocalFirewallRules', 'Text'), @('Item', 'AllowLocalIPsecRules', 'Text'),
            @('Item', 'AllowUserApps', 'Text'), @('Item', 'AllowUserPorts', 'Text'), @('Item', 'AllowUnicastResponseToMulticast', 'Text'),
            @('Item', 'NotifyOnListen', 'Text'), @('Item', 'EnableStealthModeForIPsec', 'Text'), @('Item', 'LogFileName', 'Text'),
            @('Item', 'LogMaxSizeKilobytes', 'Number'), @('Item', 'LogAllowed', 'Text'), @('Item', 'LogBlocked', 'Text'), @('Item', 'LogIgnored', 'Text'),
            @('Item', 'DisabledInterfaceAliases', 'Array')
        )
        $settingColumns = @(
            @('Item', 'ActiveProfile', 'Text'), @('Item', 'Exemptions', 'Text'), @('Item', 'EnableStatefulFtp', 'Text'), @('Item', 'EnableStatefulPptp', 'Text'),
            @('Item', 'RequireFullAuthSupport', 'Text'), @('Item', 'CertValidationLevel', 'Text'), @('Item', 'AllowIPsecThroughNAT', 'Text'),
            @('Item', 'MaxSAIdleTimeSeconds', 'Number'), @('Item', 'KeyEncoding', 'Text'), @('Item', 'EnablePacketQueuing', 'Text'),
            @('Item', 'RemoteMachineTransportAuthorizationList', 'Text'), @('Item', 'RemoteMachineTunnelAuthorizationList', 'Text'),
            @('Item', 'RemoteUserTransportAuthorizationList', 'Text'), @('Item', 'RemoteUserTunnelAuthorizationList', 'Text')
        )

        $stopwatchProfiles = [System.Diagnostics.Stopwatch]::StartNew()

        try {
            $profileObjects = @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop)
            $profileList = [System.Collections.Generic.List[object]]::new()
            foreach ($profileObject in $profileObjects) {
                $profileRow = [ordered]@{}
                Add-FirewallInventoryRowContent -Row $profileRow -Sources @{ Item = $profileObject } -Columns $profileColumns
                [void]$profileList.Add([pscustomobject]$profileRow)
            }
            # Domain, Private, Public first in that order, any other name after them, ordinal ignoring case.
            $profileList.Sort( [Comparison[object]] {
                param($a, $b)
                $rankA = [array]::IndexOf(@('domain', 'private', 'public'), ([string]$a.Name).ToLowerInvariant())
                $rankB = [array]::IndexOf(@('domain', 'private', 'public'), ([string]$b.Name).ToLowerInvariant())
                if ($rankA -lt 0) { $rankA = 99 }
                if ($rankB -lt 0) { $rankB = 99 }
                if ($rankA -ne $rankB) { return $rankA.CompareTo($rankB) }
                return [string]::Compare($a.Name, $b.Name, [System.StringComparison]::OrdinalIgnoreCase)
            } )
            $profiles = $profileList.ToArray()
            $profileCount = $profiles.Count
        } catch {
            $errors += "profiles: $(ConvertTo-FirewallInventoryMessage -Text $_.Exception.Message)"
            $profiles = @()
            $profileCount = 0
        }

        try {
            $settingObjects = @(Get-NetFirewallSetting -PolicyStore ActiveStore -ErrorAction Stop)
            if ($settingObjects.Count -eq 0) {
                $errors += 'settings: no object returned'
            } else {
                $settingRow = [ordered]@{}
                Add-FirewallInventoryRowContent -Row $settingRow -Sources @{ Item = $settingObjects[0] } -Columns $settingColumns
                $settings = [pscustomobject]$settingRow
                $activeProfile = $settings.ActiveProfile
            }
        } catch {
            $errors += "settings: $(ConvertTo-FirewallInventoryMessage -Text $_.Exception.Message)"
            $settings = $null
            $activeProfile = $null
        }

        $stopwatchProfiles.Stop()
        $profilesDurationMs = [int]$stopwatchProfiles.ElapsedMilliseconds
        #endregion

        #region Rules
        $ruleObjects = $null
        $rulesRead = $false
        $rulesDurationMs = 0

        $stopwatchRules = [System.Diagnostics.Stopwatch]::StartNew()
        try {
            $ruleObjects = @(Get-NetFirewallRule -PolicyStore ActiveStore -TracePolicyStore -ErrorAction Stop)
            $rulesRead = $true
            # A read that succeeds and returns nothing is read (RuleCount 0) but says why the row will be Failed.
            if ($ruleObjects.Count -eq 0) { $errors += 'rules: no rule returned' }
        } catch {
            $errors += "rules: $(ConvertTo-FirewallInventoryMessage -Text $_.Exception.Message)"
            $ruleObjects = $null
            $rulesRead = $false
        }
        $stopwatchRules.Stop()
        $rulesDurationMs = [int]$stopwatchRules.ElapsedMilliseconds
        #endregion

        #region Filters and rule rows
        $rules = @()
        $ruleCount = $null
        $enabledRuleCount = $null
        $filterFailedCount = $null
        $filterFailedItems = @()
        $filtersDurationMs = 0

        # The rule's own columns first, then the filter columns; the filter columns are in the order of the contract, which differs from the order of the calls.
        $ruleColumns = @(
            @('Rule', 'Name', 'Text'), @('Rule', 'InstanceID', 'Text'), @('Rule', 'DisplayName', 'Text'), @('Rule', 'Description', 'Text'), @('Rule', 'Group', 'Text'),
            @('Rule', 'DisplayGroup', 'Text'), @('Rule', 'Enabled', 'Text'), @('Rule', 'Profile', 'Text'), @('Rule', 'Direction', 'Text'), @('Rule', 'Action', 'Text'),
            @('Rule', 'EdgeTraversalPolicy', 'Text'), @('Rule', 'LooseSourceMapping', 'Bool'), @('Rule', 'LocalOnlyMapping', 'Bool'), @('Rule', 'Owner', 'Text'),
            @('Rule', 'Platform', 'Array'), @('Rule', 'PolicyStoreSource', 'Text'), @('Rule', 'PolicyStoreSourceType', 'Text'), @('Rule', 'PrimaryStatus', 'Text'),
            @('Rule', 'Status', 'Text'), @('Rule', 'StatusCode', 'Number'), @('Rule', 'EnforcementStatus', 'Array'), @('Rule', 'PackageFamilyName', 'Text'),
            @('Rule', 'PolicyAppId', 'Text'), @('Rule', 'RemoteDynamicKeywordAddresses', 'Array')
        )
        $filterClasses = @('Address', 'Port', 'Application', 'Service', 'Interface', 'InterfaceType', 'Security')
        $filterColumns = @(
            @('Port', 'Protocol', 'Text'), @('Port', 'LocalPort', 'Array'), @('Port', 'RemotePort', 'Array'),
            @('Port', 'IcmpType', 'Array'), @('Port', 'DynamicTransport', 'Text'),
            @('Address', 'LocalAddress', 'Array'), @('Address', 'RemoteAddress', 'Array'),
            @('Application', 'Program', 'Text'), @('Application', 'Package', 'Text'),
            @('Service', 'Service', 'Text'),
            @('Interface', 'InterfaceAlias', 'Array'),
            @('InterfaceType', 'InterfaceType', 'Text'),
            @('Security', 'Authentication', 'Text'), @('Security', 'Encryption', 'Text'), @('Security', 'OverrideBlockRules', 'Bool'),
            @('Security', 'LocalUser', 'Text'), @('Security', 'RemoteUser', 'Text'), @('Security', 'RemoteMachine', 'Text')
        )
        $rowColumns = $ruleColumns + $filterColumns

        if ($rulesRead) {
            $stopwatchFilters = [System.Diagnostics.Stopwatch]::StartNew()

            # The InstanceID of every rule, in the order of the rule read, $null for a rule that has none.
            $ruleIds = [System.Collections.Generic.List[object]]::new()
            foreach ($ruleObject in $ruleObjects) {
                $ruleId = $null
                $instanceProp = $null
                if ($null -ne $ruleObject) { $instanceProp = $ruleObject.PSObject.Properties['InstanceID'] }
                if ($null -ne $instanceProp -and $null -ne $instanceProp.Value) { $ruleId = [string]$instanceProp.Value }
                [void]$ruleIds.Add($ruleId)
            }

            # One read per class, joined to the rules at once: $joinedFilters[$class] holds one filter object, or $null, per rule in the order of the rule read. A class that could not be read stays null as a whole and every column of that class is null on every rule. No per-rule fallback.
            $joinedFilters = @{}
            $failedList = [System.Collections.Generic.List[string]]::new()
            foreach ($class in $filterClasses) {
                $joinedFilters[$class] = $null
                try {
                    $filterObjects = @(& "Get-NetFirewall$($class)Filter" -PolicyStore ActiveStore -ErrorAction Stop)
                    $joined = [object[]]::new($ruleIds.Count)
                    $ambiguousIds = [System.Collections.Generic.List[string]]::new()
                    Join-FirewallInventoryFilter -RuleIds $ruleIds -FilterObjects $filterObjects -Joined $joined -AmbiguousIds $ambiguousIds
                    $joinedFilters[$class] = $joined
                    # An id that more than one rule or one filter object carries is never guessed: its columns stay null, and the row is Partial through this error, not through FilterFailedCount.
                    foreach ($ambiguousId in $ambiguousIds) {
                        $errors += "filter ${class}: ambiguous InstanceID $(ConvertTo-FirewallInventoryMessage -Text $ambiguousId)"
                    }
                } catch {
                    $errors += "filter ${class}: $(ConvertTo-FirewallInventoryMessage -Text $_.Exception.Message)"
                    [void]$failedList.Add($class)
                    $joinedFilters[$class] = $null
                }
            }
            $filterFailedCount = [int]$failedList.Count
            $filterFailedItems = $failedList.ToArray()

            $ruleList = [System.Collections.Generic.List[object]]::new()
            for ($ruleIndex = 0; $ruleIndex -lt $ruleObjects.Count; $ruleIndex++) {
                $ruleObject = $ruleObjects[$ruleIndex]
                try {
                    # The filter objects of this rule, taken by its position; a class that failed, or has no object for the rule, stays null.
                    $sources = @{ Rule = $ruleObject }
                    foreach ($class in $filterClasses) {
                        $sources[$class] = $null
                        if ($null -ne $joinedFilters[$class]) { $sources[$class] = $joinedFilters[$class][$ruleIndex] }
                    }

                    $ruleRow = [ordered]@{}
                    Add-FirewallInventoryRowContent -Row $ruleRow -Sources $sources -Columns $rowColumns

                    [void]$ruleList.Add([pscustomobject]$ruleRow)
                } catch {
                    $errors += "rule row: $(ConvertTo-FirewallInventoryMessage -Text $_.Exception.Message)"
                }
            }

            # Name, InstanceID, PolicyStoreSourceType, then PolicyStoreSource, all ordinal ignoring case: two rules that share a name and an id (a Group Policy copy beside the local rule) still come out in a fixed order.
            $ruleList.Sort( [Comparison[object]] {
                param($a, $b)
                $byName = [string]::Compare($a.Name, $b.Name, [System.StringComparison]::OrdinalIgnoreCase)
                if ($byName -ne 0) { return $byName }
                $byId = [string]::Compare($a.InstanceID, $b.InstanceID, [System.StringComparison]::OrdinalIgnoreCase)
                if ($byId -ne 0) { return $byId }
                $bySourceType = [string]::Compare($a.PolicyStoreSourceType, $b.PolicyStoreSourceType, [System.StringComparison]::OrdinalIgnoreCase)
                if ($bySourceType -ne 0) { return $bySourceType }
                return [string]::Compare($a.PolicyStoreSource, $b.PolicyStoreSource, [System.StringComparison]::OrdinalIgnoreCase)
            } )
            # .ToArray(), not @(...): wrapping a generic List[object] with the array subexpression operator hits a PowerShell dynamic-binder mismatch ("Argument types do not match") once enough CIM types have been loaded in the session.
            $rules = $ruleList.ToArray()
            $ruleCount = [int]$rules.Count

            $enabledRuleCount = 0
            foreach ($ruleRow in $rules) {
                if ($ruleRow.Enabled -ieq 'True') { $enabledRuleCount++ }
            }

            $stopwatchFilters.Stop()
            $filtersDurationMs = [int]$stopwatchFilters.ElapsedMilliseconds
        }
        #endregion

        #region Packages
        $packageCount = $null
        $packagesDurationMs = 0
        # Application package SID to package family name, for the accounts step. A package SID is the SHA-256 of the lower-cased family name in UTF-16, its first 28 bytes read as seven unsigned 32-bit sub-authorities, so the name is found by hashing every family name the target has installed. The dictionary stays empty when the target has no Get-AppxPackage or the read fails.
        $packageNameBySid = [System.Collections.Generic.Dictionary[string, string]]::new([System.StringComparer]::OrdinalIgnoreCase)

        $stopwatchPackages = [System.Diagnostics.Stopwatch]::StartNew()
        try {
            # A build without the Appx module has no such command: a fact about the target, not an error, so the count stays null and nothing is added to $errors. When the rules read failed there is no rule and so no package token to name: the step is skipped the same way the filter reads are.
            if ($rulesRead -and (Get-Command Get-AppxPackage -ErrorAction SilentlyContinue)) {
                $appxPackages = @(Get-AppxPackage -AllUsers -ErrorAction Stop)
                $familyNames = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
                $sha256 = New-Object System.Security.Cryptography.SHA256CryptoServiceProvider
                try {
                    foreach ($appxPackage in $appxPackages) {
                        $familyProp = $null
                        if ($null -ne $appxPackage) { $familyProp = $appxPackage.PSObject.Properties['PackageFamilyName'] }
                        if (($null -eq $familyProp) -or [string]::IsNullOrWhiteSpace([string]$familyProp.Value)) { continue }
                        # The family name is kept as the cmdlet gives it, one entry per distinct name ignoring case; only the hash input is lower-cased.
                        $familyName = [string]$familyProp.Value
                        if (-not $familyNames.Add($familyName)) { continue }
                        $hash = $sha256.ComputeHash([System.Text.Encoding]::Unicode.GetBytes($familyName.ToLowerInvariant()))
                        $subAuthorities = [System.Collections.Generic.List[string]]::new()
                        for ($i = 0; $i -lt 7; $i++) { [void]$subAuthorities.Add([BitConverter]::ToUInt32($hash, $i * 4).ToString([System.Globalization.CultureInfo]::InvariantCulture)) }
                        $packageNameBySid['S-1-15-2-' + ($subAuthorities -join '-')] = $familyName
                    }
                } finally {
                    $sha256.Dispose()
                }
                $packageCount = [int]$familyNames.Count
            }
        } catch {
            # An unelevated caller gets Access is denied here. The step leaves no half-filled state behind: no count and no names.
            $errors += "packages: $(ConvertTo-FirewallInventoryMessage -Text $_.Exception.Message)"
            $packageCount = $null
            $packageNameBySid.Clear()
        } finally {
            $stopwatchPackages.Stop()
            $packagesDurationMs = [int]$stopwatchPackages.ElapsedMilliseconds
        }
        #endregion

        #region Accounts
        $accounts = @()
        $accountCount = 0
        $accountUnresolvedCount = 0
        $accountsDurationMs = 0
        $sddlFailedCount = $null
        $sddlFailedItems = @()

        $stopwatchAccounts = [System.Diagnostics.Stopwatch]::StartNew()

        # The rules read is a precondition: without it nothing was examined, so SddlFailedCount stays null and the loops below have no rules to walk.
        if ($rulesRead) { $sddlFailedCount = 0 }

        # The grouping and every lookup sit inside one try/catch, so a failure anywhere in this step never stops the return: the account data for this run is simply empty, with the reason in $errors.
        try {
            $sddlFailedList = [System.Collections.Generic.List[string]]::new()

            # First spelling seen per case-insensitive token is kept as the account's Token, so two rules differing only by SID casing still resolve to one account row.
            $tokenRuleNames = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::OrdinalIgnoreCase)
            $tokenOrder = [System.Collections.Generic.List[string]]::new()
            # A rule name is listed once per token, ignoring case, even when two rules carry the same name (a Group Policy copy beside the local rule); the first spelling seen in the sorted rule order is kept.
            $tokenNamesSeen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

            foreach ($ruleRow in $rules) {
                $ruleName = [string]$ruleRow.Name
                # Every principal a rule names, each token once per rule.
                $ruleTokens = [System.Collections.Generic.List[string]]::new()

                if (-not [string]::IsNullOrWhiteSpace($ruleRow.Owner)) { [void]$ruleTokens.Add([string]$ruleRow.Owner) }
                if (-not [string]::IsNullOrWhiteSpace($ruleRow.Package)) { [void]$ruleTokens.Add([string]$ruleRow.Package) }

                foreach ($field in @('LocalUser', 'RemoteUser', 'RemoteMachine')) {
                    $sddl = $ruleRow.$field
                    if ([string]::IsNullOrWhiteSpace($sddl) -or $sddl -ieq 'Any') { continue }
                    try {
                        $descriptor = New-Object System.Security.AccessControl.RawSecurityDescriptor ($sddl) -ErrorAction Stop
                        foreach ($acl in @($descriptor.DiscretionaryAcl, $descriptor.SystemAcl)) {
                            if ($null -eq $acl) { continue }
                            foreach ($ace in $acl) {
                                $aceSid = $ace.PSObject.Properties['SecurityIdentifier']
                                if ($null -ne $aceSid -and $null -ne $aceSid.Value) { [void]$ruleTokens.Add([string]$aceSid.Value.Value) }
                            }
                        }
                    } catch {
                        $sddlFailedCount++
                        [void]$sddlFailedList.Add("${ruleName}:${field}")
                        $errors += "sddl $ruleName ${field}: $(ConvertTo-FirewallInventoryMessage -Text $_.Exception.GetBaseException().Message)"
                    }
                }

                $seenForRule = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
                foreach ($ruleToken in $ruleTokens) {
                    if (-not $seenForRule.Add($ruleToken)) { continue }
                    if (-not $tokenRuleNames.ContainsKey($ruleToken)) {
                        $tokenRuleNames[$ruleToken] = [System.Collections.Generic.List[string]]::new()
                        [void]$tokenOrder.Add($ruleToken)
                    }
                    if ($tokenNamesSeen.Add("$ruleToken`0$ruleName")) { $tokenRuleNames[$ruleToken].Add($ruleName) }
                }
            }
            $sddlFailedItems = $sddlFailedList.ToArray()

            $tokenOrder.Sort( [Comparison[string]] { param($a, $b) [string]::Compare($a, $b, [System.StringComparison]::Ordinal) } )

            foreach ($token in $tokenOrder) {
                # A leading * (the secedit export form) is ignored for the Kind test only, never for the token itself.
                $sidCandidate = $token
                if ($sidCandidate.StartsWith('*', [System.StringComparison]::Ordinal)) { $sidCandidate = $sidCandidate.Substring(1) }

                $kind = 'Name'
                if ($sidCandidate -match '^S-1-\d+(-\d+)+$') { $kind = 'Sid' }

                $sid = $null
                $accountName = $null
                $status = 'Resolved'
                $acctError = ''

                if ($kind -eq 'Sid') {
                    $sid = $sidCandidate
                    try {
                        $securityId = New-Object System.Security.Principal.SecurityIdentifier($sidCandidate)
                        $translatedAccount = $securityId.Translate([System.Security.Principal.NTAccount])
                        $accountName = $translatedAccount.Value
                    } catch {
                        $status = 'NotFound'
                        $accountName = $null
                        # The innermost exception's own message, not the method-invocation wrapper, trimmed and with every run of whitespace, line breaks included, collapsed to one space, so a NotFound account's Error is always a single line.
                        $rawMessage = $_.Exception.GetBaseException().Message
                        $acctError = ([string]$rawMessage).Trim() -replace '\s+', ' '
                    }
                } else {
                    $lookupName = $token
                    try {
                        if ($token -ieq 'LocalSystem') {
                            # The Service Control Manager's own alias, not a real account, so it never goes through a lookup.
                            $sid = 'S-1-5-18'
                        } else {
                            if ($token.StartsWith('.\', [System.StringComparison]::Ordinal)) {
                                $lookupName = $env:COMPUTERNAME + $token.Substring(1)
                            }
                            $ntAccount = New-Object System.Security.Principal.NTAccount($lookupName)
                            $translated = $ntAccount.Translate([System.Security.Principal.SecurityIdentifier])
                            $sid = $translated.Value
                        }
                    } catch {
                        $status = 'NotFound'
                        $sid = $null
                        $rawMessage = $_.Exception.GetBaseException().Message
                        $acctError = ([string]$rawMessage).Trim() -replace '\s+', ' '
                    }
                    $accountName = $lookupName
                }

                # The token's own list, sorted in place: it is read nowhere else after this loop, so a copy would only cost memory. Sorted with the same comparer the Rules array itself uses, ordinal case-insensitive.
                $ruleNamesForToken = $tokenRuleNames[$token]
                $ruleNamesForToken.Sort( [Comparison[string]] { param($a, $b) [string]::Compare($a, $b, [System.StringComparison]::OrdinalIgnoreCase) } )

                $accountObject = [pscustomobject]@{
                    Token          = $token
                    Kind           = $kind
                    Sid            = $sid
                    Name           = $accountName
                    Status         = $status
                    ReferenceCount = $ruleNamesForToken.Count
                    References     = @($ruleNamesForToken.ToArray())
                    Error          = $acctError
                }

                $accounts += $accountObject

                if ($status -eq 'NotFound') { $accountUnresolvedCount++ }
            }

            $accountCount = $accounts.Count

            # Package names, after the resolver block, which is not changed: no account lookup knows an application package SID, so every package SID that came back NotFound is looked up in the dictionary of the packages step. A package that is not installed on the target stays NotFound with the lookup's own error; a capability SID (S-1-15-3-) is not looked up. String tests and a dictionary lookup only; the accounts step's own catch below covers it.
            if ($packageNameBySid.Count -gt 0) {
                foreach ($packageAccount in $accounts) {
                    if ($packageAccount.Status -ne 'NotFound') { continue }
                    if (-not ([string]$packageAccount.Token).StartsWith('S-1-15-2-', [System.StringComparison]::OrdinalIgnoreCase)) { continue }
                    $packageName = $null
                    if ($packageNameBySid.TryGetValue([string]$packageAccount.Token, [ref]$packageName)) {
                        $packageAccount.Name = $packageName
                        $packageAccount.Status = 'Resolved'
                        $packageAccount.Error = ''
                    }
                }
            }

            # Counted after the pass, so a package that was named is no longer unresolved.
            $accountUnresolvedCount = 0
            foreach ($countedAccount in $accounts) {
                if ($countedAccount.Status -eq 'NotFound') { $accountUnresolvedCount++ }
            }
        } catch {
            $errors += "accounts: $(ConvertTo-FirewallInventoryMessage -Text $_.Exception.Message)"
            $accounts = @()
            $accountCount = 0
            $accountUnresolvedCount = 0
        } finally {
            $stopwatchAccounts.Stop()
            $accountsDurationMs = [int]$stopwatchAccounts.ElapsedMilliseconds
        }
        #endregion

        #region Return
        $collectedUtc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', [System.Globalization.CultureInfo]::InvariantCulture)

        $sddlFailedOut = $null
        if ($null -ne $sddlFailedCount) { $sddlFailedOut = [int]$sddlFailedCount }

        $packageCountOut = $null
        if ($null -ne $packageCount) { $packageCountOut = [int]$packageCount }

        [pscustomobject]@{
            ComputerName           = $env:COMPUTERNAME
            DnsHostName            = $dnsHostName
            Domain                 = $domain
            OSCaption              = $osCaption
            OSVersion              = $osVersion
            CurrentBuild           = $currentBuild
            UBR                    = $ubr
            DisplayVersion         = $displayVersion
            EditionID              = $editionId
            InstallationType       = $installationType
            Culture                = $culture
            TimeZoneId             = $timeZoneId
            PSVersion              = $PSVersionTable.PSVersion.ToString()
            CollectedBy            = $collectedBy
            PartOfDomain           = [bool]$partOfDomain
            IsElevated             = [bool]$isElevated
            DomainRole             = [int]$domainRole
            CollectedUtc           = $collectedUtc
            ComputerId             = $computerId
            MachineGuid            = $machineGuid
            MachineSid             = $machineSid
            DomainSid              = $domainSid
            ComputerAccountSid     = $computerAccountSid
            DomainNetbiosName      = $domainNetbiosName
            ActiveProfile          = $activeProfile
            ProfileCount           = [int]$profileCount
            RuleCount              = $ruleCount
            EnabledRuleCount       = $enabledRuleCount
            FilterFailedCount      = $filterFailedCount
            SddlFailedCount        = $sddlFailedOut
            PackageCount           = $packageCountOut
            AccountCount           = [int]$accountCount
            AccountUnresolvedCount = [int]$accountUnresolvedCount
            ProfilesDurationMs     = [int]$profilesDurationMs
            RulesDurationMs        = [int]$rulesDurationMs
            FiltersDurationMs      = [int]$filtersDurationMs
            PackagesDurationMs     = [int]$packagesDurationMs
            AccountsDurationMs     = [int]$accountsDurationMs
            FilterFailedItems      = @($filterFailedItems)
            SddlFailedItems        = @($sddlFailedItems)
            Profiles               = @($profiles)
            Settings               = $settings
            Rules                  = @($rules)
            Accounts               = @($accounts)
            Errors                 = @($errors | ForEach-Object { ([string]$_).Trim() -replace '\s+', ' ' })
        }
        #endregion
    }
}
