<#PSScriptInfo

.DESCRIPTION Builders for fake NetSecurity objects (rules, the seven filter classes, profiles, settings) and the state the fake cmdlets read

.VERSION 1.2.0

.GUID 70782af9-8c5a-4941-bdf3-96c6b1f42a27

.AUTHOR Tom Stryhn

.COMPANYNAME Tom Stryhn

.COPYRIGHT 2026 (c) Tom Stryhn

.LICENSEURI https://github.com/tomstryhn/RemoteFirewall/blob/main/LICENSE

.PROJECTURI https://github.com/tomstryhn/RemoteFirewall

#>

<#
Fake objects shaped like what the NetSecurity cmdlets return, for the tests of the worker
scriptblock. Enumeration properties hold values of the types in FirewallTestTypes.ps1, so the
worker's [string] conversion does real work. Array properties are typed string arrays, the way the
CIM layer delivers them. Every fake also carries an extra property the contract does not name, so a
test can prove that nothing outside the column lists leaks into a row. Dot-source
FirewallTestTypes.ps1 first, then this file.
#>

function Get-FakeFirewallRule {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [hashtable]$Set = @{},

        [string[]]$Omit = @()
    )

    $rule = [ordered]@{
        Name                          = $Name
        InstanceID                    = $Name
        DisplayName                   = "Display $Name"
        Description                   = 'A fake rule'
        Group                         = '@FirewallAPI.dll,-30267'
        DisplayGroup                  = 'Windows Remote Management'
        Enabled                       = [RemoteFirewallTests.FwBool]::True
        Profile                       = [RemoteFirewallTests.FwProfile]'Domain, Private'
        Direction                     = [RemoteFirewallTests.FwDirection]::Inbound
        Action                        = [RemoteFirewallTests.FwAction]::Allow
        EdgeTraversalPolicy           = [RemoteFirewallTests.FwEdge]::Block
        LooseSourceMapping            = $false
        LocalOnlyMapping              = $false
        Owner                         = $null
        Platform                      = [string[]]@('6.0+')
        PolicyStoreSource             = 'PersistentStore'
        PolicyStoreSourceType         = [RemoteFirewallTests.FwSourceType]::Local
        PrimaryStatus                 = [RemoteFirewallTests.FwStatus]::OK
        Status                        = 'The rule was parsed successfully from the store. (65536)'
        StatusCode                    = [uint32]65536
        EnforcementStatus             = [RemoteFirewallTests.FwEnforce[]]@([RemoteFirewallTests.FwEnforce]::NotApplicable)
        PackageFamilyName             = $null
        PolicyAppId                   = $null
        RemoteDynamicKeywordAddresses = [string[]]@()
        CreationClassName             = 'MSFT|FW|FirewallRule|extra'
    }
    foreach ($key in $Set.Keys) { $rule[$key] = $Set[$key] }
    foreach ($key in $Omit) { $rule.Remove($key) }
    return [pscustomobject]$rule
}

function Get-FakeFirewallFilter {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('Address', 'Port', 'Application', 'Service', 'Interface', 'InterfaceType', 'Security')]
        [string]$Class,

        [Parameter(Mandatory = $true)]
        [string]$InstanceID,

        [hashtable]$Set = @{},

        [string[]]$Omit = @()
    )

    $filter = [ordered]@{ InstanceID = $InstanceID }
    switch ($Class) {
        'Address' {
            $filter['LocalAddress'] = [string[]]@('Any')
            $filter['RemoteAddress'] = [string[]]@('Any')
        }
        'Port' {
            $filter['Protocol'] = 'TCP'
            $filter['LocalPort'] = [string[]]@('5985')
            $filter['RemotePort'] = [string[]]@('Any')
            $filter['IcmpType'] = [string[]]@('Any')
            $filter['DynamicTransport'] = 'Any'
        }
        'Application' {
            $filter['Program'] = 'Any'
            $filter['Package'] = $null
        }
        'Service' {
            $filter['Service'] = 'Any'
        }
        'Interface' {
            $filter['InterfaceAlias'] = [string[]]@('Any')
        }
        'InterfaceType' {
            $filter['InterfaceType'] = [RemoteFirewallTests.FwIfType]::Any
        }
        'Security' {
            $filter['Authentication'] = [RemoteFirewallTests.FwAuth]::NotRequired
            $filter['Encryption'] = [RemoteFirewallTests.FwEnc]::NotRequired
            $filter['OverrideBlockRules'] = $false
            $filter['LocalUser'] = 'Any'
            $filter['RemoteUser'] = 'Any'
            $filter['RemoteMachine'] = 'Any'
        }
    }
    $filter['CreationClassName'] = "MSFT|FW|$Class|extra"
    foreach ($key in $Set.Keys) { $filter[$key] = $Set[$key] }
    foreach ($key in $Omit) { $filter.Remove($key) }
    return [pscustomobject]$filter
}

function Get-FakeFirewallProfile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [hashtable]$Set = @{},

        [string[]]$Omit = @()
    )

    $profileObject = [ordered]@{
        Name                            = $Name
        Enabled                         = [RemoteFirewallTests.FwGpoBool]::True
        DefaultInboundAction            = [RemoteFirewallTests.FwAction]::Block
        DefaultOutboundAction           = [RemoteFirewallTests.FwAction]::Allow
        AllowInboundRules               = [RemoteFirewallTests.FwGpoBool]::True
        AllowLocalFirewallRules         = [RemoteFirewallTests.FwGpoBool]::NotConfigured
        AllowLocalIPsecRules            = [RemoteFirewallTests.FwGpoBool]::NotConfigured
        AllowUserApps                   = [RemoteFirewallTests.FwGpoBool]::NotConfigured
        AllowUserPorts                  = [RemoteFirewallTests.FwGpoBool]::NotConfigured
        AllowUnicastResponseToMulticast = [RemoteFirewallTests.FwGpoBool]::NotConfigured
        NotifyOnListen                  = [RemoteFirewallTests.FwGpoBool]::False
        EnableStealthModeForIPsec       = [RemoteFirewallTests.FwGpoBool]::NotConfigured
        LogFileName                     = '%systemroot%\system32\LogFiles\Firewall\pfirewall.log'
        LogMaxSizeKilobytes             = [uint64]4096
        LogAllowed                      = [RemoteFirewallTests.FwGpoBool]::False
        LogBlocked                      = [RemoteFirewallTests.FwGpoBool]::True
        LogIgnored                      = [RemoteFirewallTests.FwGpoBool]::NotConfigured
        DisabledInterfaceAliases        = [string[]]@()
        CreationClassName               = 'MSFT|FW|Profile|extra'
    }
    foreach ($key in $Set.Keys) { $profileObject[$key] = $Set[$key] }
    foreach ($key in $Omit) { $profileObject.Remove($key) }
    return [pscustomobject]$profileObject
}

function Get-FakeFirewallSetting {
    [CmdletBinding()]
    param(
        [hashtable]$Set = @{},

        [string[]]$Omit = @()
    )

    $setting = [ordered]@{
        ActiveProfile                           = [RemoteFirewallTests.FwProfile]'Domain, Private'
        Exemptions                              = [RemoteFirewallTests.FwExemption]::NeighborDiscovery
        EnableStatefulFtp                       = [RemoteFirewallTests.FwGpoBool]::True
        EnableStatefulPptp                      = [RemoteFirewallTests.FwGpoBool]::False
        RequireFullAuthSupport                  = [RemoteFirewallTests.FwGpoBool]::NotConfigured
        CertValidationLevel                     = [RemoteFirewallTests.FwGpoBool]::NotConfigured
        AllowIPsecThroughNAT                    = [RemoteFirewallTests.FwGpoBool]::NotConfigured
        MaxSAIdleTimeSeconds                    = [uint32]300
        KeyEncoding                             = [RemoteFirewallTests.FwKeyEncoding]::UTF8
        EnablePacketQueuing                     = [RemoteFirewallTests.FwExemption]::None
        RemoteMachineTransportAuthorizationList = 'NotConfigured'
        RemoteMachineTunnelAuthorizationList    = 'NotConfigured'
        RemoteUserTransportAuthorizationList    = 'NotConfigured'
        RemoteUserTunnelAuthorizationList       = 'NotConfigured'
        CreationClassName                       = 'MSFT|FW|GlobalConfig|extra'
    }
    foreach ($key in $Set.Keys) { $setting[$key] = $Set[$key] }
    foreach ($key in $Omit) { $setting.Remove($key) }
    return [pscustomobject]$setting
}

function Get-FakeFirewallState {
    <#
    Builds the state the fake NetSecurity cmdlets read: three profiles (in the order Public, Domain,
    Private, on purpose), one settings object, no rules, and an empty filter list per class. Fail is
    a hashtable from a read name (Profile, Setting, Rule, or a filter class) to the error text that
    read writes; SettingNothing makes the settings read return nothing. Calls records every call.
    Appx drives the fake Get-AppxPackage: Mode Present (the default) returns Packages, each an object
    with a PackageFamilyName; Mode Throw throws Message the way the real cmdlet does for an unelevated
    -AllUsers read; Mode Error writes Message as a non-terminating error. A target without the command
    is made by a test that mocks Get-Command for that name. AppxCalls records every call of the fake
    apart from Calls, so the ten NetSecurity calls stay a list of their own.
    #>
    [CmdletBinding()]
    param()

    $filters = @{}
    foreach ($class in @('Address', 'Port', 'Application', 'Service', 'Interface', 'InterfaceType', 'Security')) {
        $filters[$class] = @()
    }
    return @{
        Profiles       = @(
            (Get-FakeFirewallProfile -Name 'Public'),
            (Get-FakeFirewallProfile -Name 'Domain'),
            (Get-FakeFirewallProfile -Name 'Private')
        )
        Setting        = (Get-FakeFirewallSetting)
        SettingNothing = $false
        Rules          = @()
        Filters        = $filters
        Fail           = @{}
        Calls          = [System.Collections.Generic.List[string]]::new()
        Appx           = @{ Mode = 'Present'; Packages = @(); Message = 'Access is denied.' }
        AppxCalls      = [System.Collections.Generic.List[string]]::new()
    }
}

function Add-FakeFirewallRule {
    <#
    Adds one rule to a state, with a default filter object of every class joined on the rule's
    InstanceID. RuleSet and RuleOmit shape the rule; FilterSet maps a class to the properties to
    set on its filter and FilterOmit maps a class to the properties to leave out; NoFilter names the
    classes that get no filter object for this rule; FilterInstanceID gives every filter of this rule
    another InstanceID than the rule's own (a different letter case, or a value that matches nothing).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$State,

        [Parameter(Mandatory = $true)]
        [string]$Name,

        [string]$InstanceID,

        [hashtable]$RuleSet = @{},

        [string[]]$RuleOmit = @(),

        [hashtable]$FilterSet = @{},

        [hashtable]$FilterOmit = @{},

        [string[]]$NoFilter = @(),

        [string]$FilterInstanceID
    )

    if (-not $InstanceID) { $InstanceID = $Name }
    if (-not $FilterInstanceID) { $FilterInstanceID = $InstanceID }

    $effectiveRuleSet = @{}
    foreach ($key in $RuleSet.Keys) { $effectiveRuleSet[$key] = $RuleSet[$key] }
    $effectiveRuleSet['InstanceID'] = $InstanceID
    $State.Rules = @($State.Rules) + @(Get-FakeFirewallRule -Name $Name -Set $effectiveRuleSet -Omit $RuleOmit)

    foreach ($class in @('Address', 'Port', 'Application', 'Service', 'Interface', 'InterfaceType', 'Security')) {
        if ($NoFilter -contains $class) { continue }
        $set = @{}
        if ($FilterSet.ContainsKey($class)) { $set = $FilterSet[$class] }
        $omit = @()
        if ($FilterOmit.ContainsKey($class)) { $omit = @($FilterOmit[$class]) }
        $State.Filters[$class] = @($State.Filters[$class]) + @(Get-FakeFirewallFilter -Class $class -InstanceID $FilterInstanceID -Set $set -Omit $omit)
    }
}
