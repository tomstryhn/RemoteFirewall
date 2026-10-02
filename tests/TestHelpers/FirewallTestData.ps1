<#PSScriptInfo

.DESCRIPTION Column lists, key orders and kinds of the RemoteFirewall contract, written out independently of the module source for the tests

.VERSION 1.3.0

.GUID 62fc3c31-1238-436d-9683-c4ee4fc30b52

.AUTHOR Tom Stryhn

.COMPANYNAME Tom Stryhn

.COPYRIGHT 2026 (c) Tom Stryhn

.LICENSEURI https://github.com/tomstryhn/RemoteFirewall/blob/main/LICENSE

.PROJECTURI https://github.com/tomstryhn/RemoteFirewall

#>

<#
The expected shapes of RemoteFirewall, typed out here from DESIGN.md sections 5 and 6 and not read
from the module, so a test that compares the module against these lists can fail. Dot-source this
file and call Get-FirewallTestData. A rule column is written as Name|Source|Kind: the source is
Rule or the filter class the column is read from, the kind is Text, Bool, Number or Array.
#>

function Get-FirewallTestData {
    [CmdletBinding()]
    param()

    $ruleColumnSpec = @(
        'Name|Rule|Text', 'InstanceID|Rule|Text', 'DisplayName|Rule|Text', 'Description|Rule|Text', 'Group|Rule|Text', 'DisplayGroup|Rule|Text',
        'Enabled|Rule|Text', 'Profile|Rule|Text', 'Direction|Rule|Text', 'Action|Rule|Text', 'EdgeTraversalPolicy|Rule|Text',
        'LooseSourceMapping|Rule|Bool', 'LocalOnlyMapping|Rule|Bool', 'Owner|Rule|Text', 'Platform|Rule|Array', 'PolicyStoreSource|Rule|Text',
        'PolicyStoreSourceType|Rule|Text', 'PrimaryStatus|Rule|Text', 'Status|Rule|Text', 'StatusCode|Rule|Number', 'EnforcementStatus|Rule|Array',
        'PackageFamilyName|Rule|Text', 'PolicyAppId|Rule|Text', 'RemoteDynamicKeywordAddresses|Rule|Array',
        'Protocol|Port|Text', 'LocalPort|Port|Array', 'RemotePort|Port|Array', 'IcmpType|Port|Array', 'DynamicTransport|Port|Text',
        'LocalAddress|Address|Array', 'RemoteAddress|Address|Array',
        'Program|Application|Text', 'Package|Application|Text',
        'Service|Service|Text',
        'InterfaceAlias|Interface|Array',
        'InterfaceType|InterfaceType|Text',
        'Authentication|Security|Text', 'Encryption|Security|Text', 'OverrideBlockRules|Security|Bool',
        'LocalUser|Security|Text', 'RemoteUser|Security|Text', 'RemoteMachine|Security|Text'
    )
    $ruleColumns = @()
    foreach ($spec in $ruleColumnSpec) {
        $parts = $spec.Split('|')
        $ruleColumns += [pscustomobject]@{ Name = $parts[0]; Source = $parts[1]; Kind = $parts[2] }
    }

    $identityKeys = @('ComputerName', 'DnsHostName', 'Domain', 'OSCaption', 'OSVersion', 'CurrentBuild', 'UBR',
        'DisplayVersion', 'EditionID', 'InstallationType', 'Culture', 'TimeZoneId', 'PSVersion', 'CollectedBy',
        'PartOfDomain', 'IsElevated', 'DomainRole', 'CollectedUtc', 'ComputerId', 'MachineGuid',
        'MachineSid', 'DomainSid', 'ComputerAccountSid', 'DomainNetbiosName')
    $workerModuleKeys = @('ActiveProfile', 'ProfileCount', 'RuleCount', 'EnabledRuleCount', 'FilterFailedCount', 'SddlFailedCount', 'PackageCount',
        'AccountCount', 'AccountUnresolvedCount', 'ProfilesDurationMs', 'RulesDurationMs', 'FiltersDurationMs', 'PackagesDurationMs', 'AccountsDurationMs',
        'FilterFailedItems', 'SddlFailedItems', 'Profiles', 'Settings', 'Rules', 'Accounts', 'Errors')
    $systemModuleKeys = @('ActiveProfile', 'ProfileCount', 'RuleCount', 'EnabledRuleCount', 'FilterFailedCount', 'SddlFailedCount', 'PackageCount',
        'AccountCount', 'AccountUnresolvedCount', 'ProfilesDurationMs', 'RulesDurationMs', 'FiltersDurationMs', 'PackagesDurationMs', 'AccountsDurationMs')

    # One case per way an array column can arrive from the target. Value is what the fake object holds, Expected what the worker must return.
    $arrayCases = @()
    $caseId = 0
    $arrayColumns = @($ruleColumns | Where-Object { $_.Kind -eq 'Array' })
    foreach ($column in $arrayColumns) {
        $variants = @(
            @{ Label = 'zero elements'; Value = [string[]]@(); Expected = @() },
            @{ Label = 'a null value'; Value = $null; Expected = @() },
            @{ Label = 'one element'; Value = [string[]]@('v1'); Expected = @('v1') },
            @{ Label = 'a bare string'; Value = 'v1'; Expected = @('v1') },
            @{ Label = 'two elements'; Value = [string[]]@('v1', 'v2'); Expected = @('v1', 'v2') }
        )
        foreach ($variant in $variants) {
            $caseId++
            $arrayCases += @{ Id = $caseId; Label = $variant.Label; Column = $column.Name; Source = $column.Source; Value = $variant.Value; Expected = $variant.Expected }
        }
    }
    $caseId++
    $arrayCases += @{ Id = $caseId; Label = 'an array of integers'; Column = 'IcmpType'; Source = 'Port'; Value = @(8, 0); Expected = @('8', '0') }
    $caseId++
    $arrayCases += @{ Id = $caseId; Label = 'a bare enumeration value'; Column = 'EnforcementStatus'; Source = 'Rule'; Value = [RemoteFirewallTests.FwEnforce]::Enforced; Expected = @('Enforced') }
    $caseId++
    $arrayCases += @{ Id = $caseId; Label = 'an array of enumeration values'; Column = 'EnforcementStatus'; Source = 'Rule'
        Value = [RemoteFirewallTests.FwEnforce[]]@([RemoteFirewallTests.FwEnforce]::NotApplicable, [RemoteFirewallTests.FwEnforce]::Enforced); Expected = @('NotApplicable', 'Enforced')
    }
    $caseId++
    $arrayCases += @{ Id = $caseId; Label = 'an array holding a null element'; Column = 'LocalAddress'; Source = 'Address'; Value = @('10.0.0.1', $null, '10.0.0.2'); Expected = @('10.0.0.1', '10.0.0.2') }

    # One case per way a scalar column can arrive. Kind is the column's kind; Expected is $null where the worker must return null.
    $scalarCases = @(
        @{ Label = 'the boolean true'; Column = 'LooseSourceMapping'; Source = 'Rule'; Kind = 'Bool'; Value = $true; Expected = $true },
        @{ Label = 'the boolean false'; Column = 'LocalOnlyMapping'; Source = 'Rule'; Kind = 'Bool'; Value = $false; Expected = $false },
        @{ Label = 'the boolean true on a filter'; Column = 'OverrideBlockRules'; Source = 'Security'; Kind = 'Bool'; Value = $true; Expected = $true },
        @{ Label = 'the string True'; Column = 'LooseSourceMapping'; Source = 'Rule'; Kind = 'Bool'; Value = 'True'; Expected = $true },
        @{ Label = 'the string false'; Column = 'LocalOnlyMapping'; Source = 'Rule'; Kind = 'Bool'; Value = 'false'; Expected = $false },
        @{ Label = 'the enumeration value True'; Column = 'LocalOnlyMapping'; Source = 'Rule'; Kind = 'Bool'; Value = [RemoteFirewallTests.FwBool]::True; Expected = $true },
        @{ Label = 'the enumeration value False on a filter'; Column = 'OverrideBlockRules'; Source = 'Security'; Kind = 'Bool'; Value = [RemoteFirewallTests.FwBool]::False; Expected = $false },
        @{ Label = 'text that is not a boolean'; Column = 'OverrideBlockRules'; Source = 'Security'; Kind = 'Bool'; Value = 'garbage'; Expected = $null },
        @{ Label = 'a null value'; Column = 'LooseSourceMapping'; Source = 'Rule'; Kind = 'Bool'; Value = $null; Expected = $null },
        @{ Label = 'a number in a boolean column'; Column = 'LooseSourceMapping'; Source = 'Rule'; Kind = 'Bool'; Value = 1; Expected = $null },
        @{ Label = 'an unsigned 32-bit number'; Column = 'StatusCode'; Source = 'Rule'; Kind = 'Number'; Value = [uint32]65536; Expected = [int64]65536 },
        @{ Label = 'a numeric string'; Column = 'StatusCode'; Source = 'Rule'; Kind = 'Number'; Value = '65540'; Expected = [int64]65540 },
        @{ Label = 'text that is not a number'; Column = 'StatusCode'; Source = 'Rule'; Kind = 'Number'; Value = 'abc'; Expected = $null },
        @{ Label = 'a null value'; Column = 'StatusCode'; Source = 'Rule'; Kind = 'Number'; Value = $null; Expected = $null },
        @{ Label = 'a negative number'; Column = 'StatusCode'; Source = 'Rule'; Kind = 'Number'; Value = -1; Expected = [int64]-1 },
        @{ Label = 'the largest unsigned 64-bit number'; Column = 'StatusCode'; Source = 'Rule'; Kind = 'Number'; Value = [uint64]::MaxValue; Expected = [uint64]::MaxValue },
        @{ Label = 'an unsigned 64-bit number that fits in a signed one'; Column = 'StatusCode'; Source = 'Rule'; Kind = 'Number'; Value = [uint64]4096; Expected = [int64]4096 },
        @{ Label = 'the largest unsigned 64-bit number as text'; Column = 'StatusCode'; Source = 'Rule'; Kind = 'Number'; Value = '18446744073709551615'; Expected = [uint64]::MaxValue },
        @{ Label = 'a signed 16-bit number'; Column = 'StatusCode'; Source = 'Rule'; Kind = 'Number'; Value = [int16]-7; Expected = [int64]-7 },
        @{ Label = 'a decimal fraction as text'; Column = 'StatusCode'; Source = 'Rule'; Kind = 'Number'; Value = '1.5'; Expected = $null },
        @{ Label = 'a boolean in a number column'; Column = 'StatusCode'; Source = 'Rule'; Kind = 'Number'; Value = $true; Expected = $null },
        @{ Label = 'a null value'; Column = 'Description'; Source = 'Rule'; Kind = 'Text'; Value = $null; Expected = $null },
        @{ Label = 'an empty string'; Column = 'Description'; Source = 'Rule'; Kind = 'Text'; Value = ''; Expected = '' },
        @{ Label = 'untrimmed multi-line text'; Column = 'Description'; Source = 'Rule'; Kind = 'Text'; Value = "  padded`r`n  text `t"; Expected = "  padded`r`n  text `t" },
        @{ Label = 'an enumeration value'; Column = 'Enabled'; Source = 'Rule'; Kind = 'Text'; Value = [RemoteFirewallTests.FwBool]::False; Expected = 'False' },
        @{ Label = 'a flags enumeration with two members'; Column = 'Profile'; Source = 'Rule'; Kind = 'Text'; Value = [RemoteFirewallTests.FwProfile]'Domain, Public'; Expected = 'Domain, Public' },
        @{ Label = 'a flags enumeration with no member set'; Column = 'Profile'; Source = 'Rule'; Kind = 'Text'; Value = [RemoteFirewallTests.FwProfile]::Any; Expected = 'Any' },
        @{ Label = 'a null value on a filter'; Column = 'Program'; Source = 'Application'; Kind = 'Text'; Value = $null; Expected = $null },
        @{ Label = 'the word Any'; Column = 'LocalUser'; Source = 'Security'; Kind = 'Text'; Value = 'Any'; Expected = 'Any' },
        @{ Label = 'a number in a text column'; Column = 'PolicyAppId'; Source = 'Rule'; Kind = 'Text'; Value = 12345; Expected = '12345' }
    )
    $scalarId = 0
    $scalarCaseList = @()
    foreach ($scalarCase in $scalarCases) {
        $scalarId++
        $scalarCase['Id'] = $scalarId
        $scalarCaseList += $scalarCase
    }

    [ordered]@{
        ArrayCases           = $arrayCases
        ScalarCases          = $scalarCaseList
        RuleColumns          = $ruleColumns
        RuleColumnNames      = @($ruleColumns | ForEach-Object { $_.Name })
        FilterClasses        = @('Address', 'Port', 'Application', 'Service', 'Interface', 'InterfaceType', 'Security')
        FilterClassColumns   = [ordered]@{
            Address       = @('LocalAddress', 'RemoteAddress')
            Port          = @('Protocol', 'LocalPort', 'RemotePort', 'IcmpType', 'DynamicTransport')
            Application   = @('Program', 'Package')
            Service       = @('Service')
            Interface     = @('InterfaceAlias')
            InterfaceType = @('InterfaceType')
            Security      = @('Authentication', 'Encryption', 'OverrideBlockRules', 'LocalUser', 'RemoteUser', 'RemoteMachine')
        }
        IdentityKeys         = $identityKeys
        WorkerKeys           = @($identityKeys + $workerModuleKeys)
        ProfileColumns       = @('Name', 'Enabled', 'DefaultInboundAction', 'DefaultOutboundAction', 'AllowInboundRules', 'AllowLocalFirewallRules',
            'AllowLocalIPsecRules', 'AllowUserApps', 'AllowUserPorts', 'AllowUnicastResponseToMulticast', 'NotifyOnListen',
            'EnableStealthModeForIPsec', 'LogFileName', 'LogMaxSizeKilobytes', 'LogAllowed', 'LogBlocked', 'LogIgnored', 'DisabledInterfaceAliases')
        SettingColumns       = @('ActiveProfile', 'Exemptions', 'EnableStatefulFtp', 'EnableStatefulPptp', 'RequireFullAuthSupport', 'CertValidationLevel',
            'AllowIPsecThroughNAT', 'MaxSAIdleTimeSeconds', 'KeyEncoding', 'EnablePacketQueuing', 'RemoteMachineTransportAuthorizationList',
            'RemoteMachineTunnelAuthorizationList', 'RemoteUserTransportAuthorizationList', 'RemoteUserTunnelAuthorizationList')
        AccountColumns       = @('Token', 'Kind', 'Sid', 'Name', 'Status', 'ReferenceCount', 'References', 'Error')
        AccountCsvColumns    = @('Token', 'Kind', 'Sid', 'Name', 'Status', 'ReferenceCount', 'Error')
        SummaryKeys          = @('ActiveProfile', 'ProfileCount', 'RuleCount', 'EnabledRuleCount', 'RuleCountBySourceType', 'FilterFailedCount',
            'FilterFailedItems', 'SddlFailedCount', 'SddlFailedItems', 'PackageCount', 'ProfilesDurationMs', 'RulesDurationMs', 'FiltersDurationMs',
            'PackagesDurationMs', 'AccountsDurationMs', 'AccountCount', 'AccountUnresolvedCount', 'AccountUnresolvedTokens')
        # Package SID and package family name pairs taken from the AppContainer registry mappings of a Windows 11 host (DESIGN.md section 12.4), typed out here and not computed by the module.
        PackagePairs         = @(
            @{ Sid = 'S-1-15-2-1050576210-4101474698-56307613-2706264498-167457550-835605972-784472318'; FamilyName = 'microsoft.windowsnotepad_8wekyb3d8bbwe' },
            @{ Sid = 'S-1-15-2-1075972307-1477995677-3981890472-2965168153-2910496065-638303522-2449858333'; FamilyName = 'microsoftwindows.client.coreai_cw5n1h2txyewy' },
            @{ Sid = 'S-1-15-2-1083666204-94104884-4233206613-1271453470-922726920-1064507403-787610193'; FamilyName = 'microsoft.vclibs.140.00_8wekyb3d8bbwe' }
        )
        SystemKeys           = @($identityKeys + @('Collector', 'CollectorVersion', 'RunId') + $systemModuleKeys + @('Errors', 'Transport', 'RequestedComputerName', 'Status'))
        RunKeys              = @('RunId', 'Collector', 'CollectorVersion', 'SchemaVersion', 'HostComputer', 'HostComputerId',
            'HostUser', 'PSVersion', 'StartUtc', 'EndUtc', 'RequestedComputers', 'ThrottleLimit', 'UseSSL', 'SkipSidReference', 'Results')
        ResultCsvColumns     = @('ComputerName', 'ComputerId', 'Status', 'Transport', 'OutputFolder', 'IsElevated', 'ProfileCount', 'RuleCount',
            'FilterFailedCount', 'SddlFailedCount', 'AccountCount', 'AccountUnresolvedCount', 'Error', 'ErrorCount')
        ResultRowProperties  = @('ComputerName', 'ComputerId', 'Status', 'Transport', 'OutputFolder', 'IsElevated', 'ProfileCount', 'RuleCount',
            'FilterFailedCount', 'SddlFailedCount', 'AccountCount', 'AccountUnresolvedCount', 'Error', 'ErrorCount', 'Errors')
        RuleArrayColumnNames = @('Platform', 'EnforcementStatus', 'RemoteDynamicKeywordAddresses', 'LocalPort', 'RemotePort', 'IcmpType',
            'LocalAddress', 'RemoteAddress', 'InterfaceAlias')
        # Names of the ten NetSecurity cmdlets the worker calls, in the order it calls them.
        CmdletCallOrder      = @('Get-NetFirewallProfile', 'Get-NetFirewallSetting', 'Get-NetFirewallRule', 'Get-NetFirewallAddressFilter',
            'Get-NetFirewallPortFilter', 'Get-NetFirewallApplicationFilter', 'Get-NetFirewallServiceFilter', 'Get-NetFirewallInterfaceFilter',
            'Get-NetFirewallInterfaceTypeFilter', 'Get-NetFirewallSecurityFilter')
    }
}
