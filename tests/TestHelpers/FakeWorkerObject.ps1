<#PSScriptInfo

.DESCRIPTION Builds a complete hand-made worker object for the host-side tests of RemoteFirewall

.VERSION 1.3.0

.GUID 36259576-e978-48ba-b2a4-9e9c23ce43d7

.AUTHOR Tom Stryhn

.COMPANYNAME Tom Stryhn

.COPYRIGHT 2026 (c) Tom Stryhn

.LICENSEURI https://github.com/tomstryhn/RemoteFirewall/blob/main/LICENSE

.PROJECTURI https://github.com/tomstryhn/RemoteFirewall

#>

<#
Get-FakeWorkerObject returns what Get-FirewallInventoryWorker's scriptblock returns, as plain data
(strings, numbers, booleans, string arrays), with every key of DESIGN.md section 5 in that order. It is
what the host functions receive, live for a local run and deserialised for a remote one. Scenarios:

  Success       three profiles (in the order Public, Domain, Private, on purpose), settings, seven rules
                sorted by Name, five accounts, no errors.
  FilterFailed  the Address, Port, Interface and InterfaceType classes failed, the way an unelevated read
                fails: their columns are null on every rule, FilterFailedCount 4, four errors.
  RulesFailed   the rules read failed: Rules and Accounts empty, RuleCount, EnabledRuleCount, FilterFailedCount
                and SddlFailedCount null, one error.

The rules cover arrays of 0, 1 and 2 elements, a Group Policy rule, a rule with Owner, one with Package, one
with SDDL LocalUser and RemoteUser, null newer properties, a multi-line Description and a DisplayName with a
comma and a double quote. Dot-source this file, then call Get-FakeWorkerObject.
#>

function Get-FakeHostRule {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [hashtable]$Set = @{}
    )

    $rule = [ordered]@{
        Name                          = $Name
        InstanceID                    = $Name
        DisplayName                   = $Name
        Description                   = ''
        Group                         = '@FirewallAPI.dll,-30267'
        DisplayGroup                  = 'Windows Remote Management'
        Enabled                       = 'True'
        Profile                       = 'Domain, Private'
        Direction                     = 'Inbound'
        Action                        = 'Allow'
        EdgeTraversalPolicy           = 'Block'
        LooseSourceMapping            = $false
        LocalOnlyMapping              = $false
        Owner                         = $null
        Platform                      = @('6.0+')
        PolicyStoreSource             = 'PersistentStore'
        PolicyStoreSourceType         = 'Local'
        PrimaryStatus                 = 'OK'
        Status                        = 'The rule was parsed successfully from the store. (65536)'
        StatusCode                    = 65536
        EnforcementStatus             = @('NotApplicable')
        PackageFamilyName             = $null
        PolicyAppId                   = $null
        RemoteDynamicKeywordAddresses = @()
        Protocol                      = 'TCP'
        LocalPort                     = @('5985')
        RemotePort                    = @('Any')
        IcmpType                      = @('Any')
        DynamicTransport              = 'Any'
        LocalAddress                  = @('Any')
        RemoteAddress                 = @('Any')
        Program                       = 'System'
        Package                       = $null
        Service                       = 'Any'
        InterfaceAlias                = @('Any')
        InterfaceType                 = 'Any'
        Authentication                = 'NotRequired'
        Encryption                    = 'NotRequired'
        OverrideBlockRules            = $false
        LocalUser                     = 'Any'
        RemoteUser                    = 'Any'
        RemoteMachine                 = 'Any'
    }
    foreach ($key in $Set.Keys) { $rule[$key] = $Set[$key] }
    return [pscustomobject]$rule
}

function Get-FakeWorkerObject {
    [CmdletBinding()]
    param(
        [ValidateSet('Success', 'FilterFailed', 'RulesFailed')]
        [string]$Scenario = 'Success',

        [string]$ComputerName = 'FAKEHOST01',

        [string]$PSComputerNameValue,

        [int]$SddlFailedCount = 0,

        [string[]]$WorkerErrors = @(),

        [AllowNull()]
        [string]$ComputerId = '11111111-2222-3333-4444-555555555555',

        [AllowNull()]
        [string]$MachineGuid = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',

        [AllowNull()]
        [string]$MachineSid = 'S-1-5-21-1111111111-2222222222-3333333333',

        [AllowNull()]
        [string]$DomainSid = 'S-1-5-21-4444444444-5555555555-6666666666',

        [AllowNull()]
        [string]$ComputerAccountSid = 'S-1-5-21-4444444444-5555555555-6666666666-1104',

        [AllowNull()]
        [string]$DomainNetbiosName = 'CORP'
    )

    $packageSid = 'S-1-15-2-1234567890-1234567890-1234567890-1234567890-1234567890-1234567890-1234567890'
    $ownerSid = 'S-1-5-21-1111111111-2222222222-3333333333-1001'
    $groupSid = 'S-1-5-21-1111111111-2222222222-3333333333-513'

    $rules = @(
        # Sorted by Name, ordinal ignoring case, the way the worker returns them.
        (Get-FakeHostRule -Name 'CoreNet-DHCP-In' -Set @{ DisplayName = 'Core Networking - Dynamic Host Configuration Protocol (DHCP-In)'; Description = "Allows DHCP messages`r`n   for stateless auto-configuration.`tSecond line"; Group = '@FirewallAPI.dll,-25000'; DisplayGroup = 'Core Networking'; Profile = 'Any'; Protocol = 'UDP'; LocalPort = @('68', '67'); RemotePort = @('67', '68'); Platform = @(); EnforcementStatus = @(); Program = '%SystemRoot%\system32\svchost.exe'; Service = 'dhcp' }),
        (Get-FakeHostRule -Name 'GP-Allow-RDP-In' -Set @{ DisplayName = 'Allow "RDP", from corp'; PolicyStoreSource = 'Default Domain Policy'; PolicyStoreSourceType = 'GroupPolicy'; LocalPort = @('3389'); Platform = @('6.0+', '10.0+'); Profile = 'Domain' }),
        (Get-FakeHostRule -Name 'Hyp-Owned-Rule' -Set @{ Owner = $ownerSid; Enabled = 'False'; Direction = 'Outbound'; Action = 'Block'; Protocol = 'Any'; LocalPort = @(); RemotePort = @(); IcmpType = @(); LocalAddress = @('LocalSubnet'); RemoteAddress = @('10.0.0.0/8', '192.168.0.0/16') }),
        (Get-FakeHostRule -Name 'Pkg-App-Rule' -Set @{ Package = $packageSid; Program = 'C:\Program Files\WindowsApps\Contoso.App_1.0.0.0_x64__abc\app.exe'; Direction = 'Outbound'; Profile = 'Domain, Private, Public'; PackageFamilyName = 'Contoso.App_abc' }),
        (Get-FakeHostRule -Name 'Sddl-User-Rule' -Set @{ LocalUser = 'O:LSD:(A;;CC;;;S-1-5-84-0-0-0-0-0)'; RemoteUser = "O:LSD:(A;;CC;;;S-1-5-32-544)(A;;CC;;;$groupSid)"; Authentication = 'Required'; Encryption = 'Required'; OverrideBlockRules = $true }),
        (Get-FakeHostRule -Name 'WINRM-HTTP-In-TCP' -Set @{ DisplayName = 'Windows Remote Management (HTTP-In)'; Description = 'Inbound rule for Windows Remote Management via WS-Management. [TCP 5985]'; LooseSourceMapping = $true; PolicyAppId = 'app1' }),
        (Get-FakeHostRule -Name 'zz-Disabled-Rule' -Set @{ Enabled = 'False'; Profile = 'Public'; Action = 'Block'; LocalPort = @('445'); Platform = @('6.1+') })
    )

    $accounts = @(
        [pscustomobject][ordered]@{ Token = $packageSid; Kind = 'Sid'; Sid = $packageSid; Name = $null; Status = 'NotFound'; ReferenceCount = 1; References = @('Pkg-App-Rule'); Error = 'Some or all identity references could not be translated.' }
        [pscustomobject][ordered]@{ Token = $ownerSid; Kind = 'Sid'; Sid = $ownerSid; Name = $null; Status = 'NotFound'; ReferenceCount = 1; References = @('Hyp-Owned-Rule'); Error = 'Some or all identity references could not be translated.' }
        [pscustomobject][ordered]@{ Token = $groupSid; Kind = 'Sid'; Sid = $groupSid; Name = $null; Status = 'NotFound'; ReferenceCount = 1; References = @('Sddl-User-Rule'); Error = 'Some or all identity references could not be translated.' }
        [pscustomobject][ordered]@{ Token = 'S-1-5-32-544'; Kind = 'Sid'; Sid = 'S-1-5-32-544'; Name = 'BUILTIN\Administrators'; Status = 'Resolved'; ReferenceCount = 1; References = @('Sddl-User-Rule'); Error = '' }
        [pscustomobject][ordered]@{ Token = 'S-1-5-84-0-0-0-0-0'; Kind = 'Sid'; Sid = 'S-1-5-84-0-0-0-0-0'; Name = $null; Status = 'NotFound'; ReferenceCount = 1; References = @('Sddl-User-Rule'); Error = 'Some or all identity references could not be translated.' }
    )

    $profiles = @(
        [pscustomobject][ordered]@{ Name = 'Public'; Enabled = 'True'; DefaultInboundAction = 'Block'; DefaultOutboundAction = 'Allow'; AllowInboundRules = 'True'; AllowLocalFirewallRules = 'True'; AllowLocalIPsecRules = 'True'; AllowUserApps = 'True'; AllowUserPorts = 'True'; AllowUnicastResponseToMulticast = 'True'; NotifyOnListen = 'False'; EnableStealthModeForIPsec = 'True'; LogFileName = '%systemroot%\system32\LogFiles\Firewall\pfirewall.log'; LogMaxSizeKilobytes = 4096; LogAllowed = 'False'; LogBlocked = 'False'; LogIgnored = 'NotConfigured'; DisabledInterfaceAliases = @('Wi-Fi', 'Ethernet 3') }
        [pscustomobject][ordered]@{ Name = 'Domain'; Enabled = 'True'; DefaultInboundAction = 'Block'; DefaultOutboundAction = 'Allow'; AllowInboundRules = 'True'; AllowLocalFirewallRules = 'True'; AllowLocalIPsecRules = 'True'; AllowUserApps = 'True'; AllowUserPorts = 'True'; AllowUnicastResponseToMulticast = 'True'; NotifyOnListen = 'False'; EnableStealthModeForIPsec = 'True'; LogFileName = '%systemroot%\system32\LogFiles\Firewall\pfirewall.log'; LogMaxSizeKilobytes = 4096; LogAllowed = 'False'; LogBlocked = 'False'; LogIgnored = 'NotConfigured'; DisabledInterfaceAliases = @() }
        [pscustomobject][ordered]@{ Name = 'Private'; Enabled = 'True'; DefaultInboundAction = 'Block'; DefaultOutboundAction = 'Allow'; AllowInboundRules = 'True'; AllowLocalFirewallRules = 'True'; AllowLocalIPsecRules = 'True'; AllowUserApps = 'True'; AllowUserPorts = 'True'; AllowUnicastResponseToMulticast = 'True'; NotifyOnListen = 'False'; EnableStealthModeForIPsec = 'True'; LogFileName = '%systemroot%\system32\LogFiles\Firewall\pfirewall.log'; LogMaxSizeKilobytes = 4096; LogAllowed = 'False'; LogBlocked = 'False'; LogIgnored = 'NotConfigured'; DisabledInterfaceAliases = @('Ethernet 2') }
    )

    $settings = [pscustomobject][ordered]@{
        ActiveProfile                           = 'Domain'
        Exemptions                              = 'None'
        EnableStatefulFtp                       = 'True'
        EnableStatefulPptp                      = 'False'
        RequireFullAuthSupport                  = 'NotConfigured'
        CertValidationLevel                     = 'NotConfigured'
        AllowIPsecThroughNAT                    = 'NotConfigured'
        MaxSAIdleTimeSeconds                    = 300
        KeyEncoding                             = 'UTF8'
        EnablePacketQueuing                     = 'None'
        RemoteMachineTransportAuthorizationList = 'NotConfigured'
        RemoteMachineTunnelAuthorizationList    = 'NotConfigured'
        RemoteUserTransportAuthorizationList    = 'NotConfigured'
        RemoteUserTunnelAuthorizationList       = 'NotConfigured'
    }

    $errors = @($WorkerErrors)
    $filterFailedCount = 0
    $filterFailedItems = @()
    $ruleCount = $rules.Count
    $enabledRuleCount = @($rules | Where-Object { $_.Enabled -eq 'True' }).Count
    $sddlFailedOut = $SddlFailedCount

    if ($Scenario -eq 'FilterFailed') {
        $nullColumns = @('LocalAddress', 'RemoteAddress', 'Protocol', 'LocalPort', 'RemotePort', 'IcmpType', 'DynamicTransport', 'InterfaceAlias', 'InterfaceType')
        foreach ($class in @('Address', 'Port', 'Interface', 'InterfaceType')) {
            $errors += "filter ${class}: Access is denied."
            $filterFailedItems += $class
        }
        $filterFailedCount = 4
        $rules = @($rules | ForEach-Object {
                $copy = [ordered]@{}
                foreach ($property in $_.PSObject.Properties) { $copy[$property.Name] = $property.Value }
                foreach ($column in $nullColumns) { $copy[$column] = $null }
                [pscustomobject]$copy
            })
    }

    if ($Scenario -eq 'RulesFailed') {
        $errors += 'rules: The CIM provider failed.'
        $rules = @()
        $accounts = @()
        $ruleCount = $null
        $enabledRuleCount = $null
        $filterFailedCount = $null
        $sddlFailedOut = $null
    }

    $accountUnresolved = @($accounts | Where-Object { $_.Status -eq 'NotFound' }).Count

    $worker = [pscustomobject][ordered]@{
        ComputerName           = $ComputerName
        DnsHostName            = "$ComputerName.corp.example"
        Domain                 = 'corp.example'
        OSCaption              = 'Microsoft Windows Server 2022 Standard'
        OSVersion              = '10.0.20348'
        CurrentBuild           = '20348'
        UBR                    = '2762'
        DisplayVersion         = '21H2'
        EditionID              = 'ServerStandard'
        InstallationType       = 'Server'
        Culture                = 'en-US'
        TimeZoneId             = 'UTC'
        PSVersion              = '5.1.20348.2760'
        CollectedBy            = 'CORP\svc-collector'
        PartOfDomain           = $true
        IsElevated             = $true
        DomainRole             = 3
        CollectedUtc           = '2026-09-30T10:00:00Z'
        ComputerId             = $ComputerId
        MachineGuid            = $MachineGuid
        MachineSid             = $MachineSid
        DomainSid              = $DomainSid
        ComputerAccountSid     = $ComputerAccountSid
        DomainNetbiosName      = $DomainNetbiosName
        ActiveProfile          = 'Domain'
        ProfileCount           = 3
        RuleCount              = $ruleCount
        EnabledRuleCount       = $enabledRuleCount
        FilterFailedCount      = $filterFailedCount
        SddlFailedCount        = $sddlFailedOut
        PackageCount           = 14
        AccountCount           = @($accounts).Count
        AccountUnresolvedCount = $accountUnresolved
        ProfilesDurationMs     = 12
        RulesDurationMs        = 340
        FiltersDurationMs      = 410
        PackagesDurationMs     = 75
        AccountsDurationMs     = 25
        FilterFailedItems      = @($filterFailedItems)
        SddlFailedItems        = @()
        Profiles               = @($profiles)
        Settings               = $settings
        Rules                  = @($rules)
        Accounts               = @($accounts)
        Errors                 = @($errors)
    }
    if ($PSComputerNameValue) {
        $worker | Add-Member -MemberType NoteProperty -Name 'PSComputerName' -Value $PSComputerNameValue
        $worker | Add-Member -MemberType NoteProperty -Name 'RunspaceId' -Value ([guid]::NewGuid())
        $worker | Add-Member -MemberType NoteProperty -Name 'PSShowComputerName' -Value $true
    }
    return $worker
}
