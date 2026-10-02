<#PSScriptInfo

.DESCRIPTION Defines small real enumeration types that stand in for the NetSecurity CIM enumerations in the RemoteFirewall tests

.VERSION 1.3.0

.GUID f4af96d4-76b8-4f68-9566-3e59b256e411

.AUTHOR Tom Stryhn

.COMPANYNAME Tom Stryhn

.COPYRIGHT 2026 (c) Tom Stryhn

.LICENSEURI https://github.com/tomstryhn/RemoteFirewall/blob/main/LICENSE

.PROJECTURI https://github.com/tomstryhn/RemoteFirewall

#>

<#
The NetSecurity cmdlets return CIM instances whose enumerations display as names but are real
enumeration values, not strings. A fake that holds a plain string would let a test pass even when
the worker never converts anything, so the fakes in this folder hold values of these types instead.
[string]$value on one of them gives the member name, and on a [Flags] member combination gives the
comma separated list, exactly as the real enumerations do. Dot-source this file; a second dot-source
in the same session leaves the types as they are.
#>

if (-not ('RemoteFirewallTests.FwBool' -as [type])) {
    Add-Type -TypeDefinition @'
namespace RemoteFirewallTests
{
    public enum FwBool { True = 1, False = 2 }
    public enum FwGpoBool { False = 0, True = 1, NotConfigured = 2 }
    [System.Flags]
    public enum FwProfile { Any = 0, Domain = 1, Private = 2, Public = 4, NotApplicable = 32768 }
    public enum FwDirection { Inbound = 1, Outbound = 2 }
    public enum FwAction { NotConfigured = 0, Allow = 2, Block = 4 }
    public enum FwEdge { Block = 0, Allow = 1, DeferToUser = 2, DeferToApp = 3 }
    public enum FwStatus { Unknown = 0, OK = 1, Degraded = 2, Error = 3 }
    public enum FwSourceType { None = 0, Local = 1, GroupPolicy = 2, Dynamic = 3, Generated = 4, Hardcoded = 5 }
    public enum FwAuth { NotRequired = 0, Required = 1, NoEncap = 2 }
    public enum FwEnc { NotRequired = 0, Required = 1, Dynamic = 2 }
    [System.Flags]
    public enum FwIfType { Any = 0, Wired = 1, Wireless = 2, RemoteAccess = 4 }
    public enum FwEnforce { NotApplicable = 1, Enforced = 2, Unenforced = 3 }
    public enum FwExemption { None = 0, NeighborDiscovery = 1, Icmp = 2, Dhcp = 3 }
    public enum FwKeyEncoding { None = 0, UTF8 = 1, UTF16 = 2 }
}
'@
}
