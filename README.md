# RemoteFirewall PowerShell Module

Collects the Windows Firewall profile settings, the global settings, every firewall rule with its seven filters, and the security principals the rules name, from the local computer in-process and from remote computers over WinRM, without interpreting anything.

## Table of Content

- [Version Changes](#version-changes)
- [Background](#background)
  - [Risk(s)](#risks)
  - [Mitigation](#mitigation)
- [Requirements](#requirements)
- [Output Data Handling](#output-data-handling)
- [Importing the Module](#importing-the-module)
- [Examples](#examples)
- [Functions](#functions)
  - [Get-FirewallInventory](#get-firewallinventory)
- [How it works](#how-it-works)
- [Testing](#testing)
- [Support and versioning](#support-and-versioning)
- [References](#references)
- [License](#license)

## Version Changes

##### 1.3.0

- Reads the SID reference of each computer and writes it to `system.json`: `MachineSid` (the SID of the computer's own account database, no RID), `DomainSid`, `ComputerAccountSid` (the full SID of the computer's own account in the domain) and `DomainNetbiosName`, in that order directly after `MachineGuid`. None is used as identity; they say whose an `S-1-5-21` SID is. `MachineSid` is the local account with RID 500 read through `Win32_UserAccount` with the computer name as `Domain`; the three domain values come from the computer's own domain account through the same account lookup the module uses for the principals of the rules, and are read only on a domain-joined computer. No Active Directory module and no LDAP is used.
- `Win32_UserAccount` lists no local account on a domain controller, so `MachineSid` is null there. The three domain values are null on a workgroup computer. A domain-joined computer that cannot resolve its own account gets the error `identity: DomainSid: <message>` and a `Partial` row.
- New switch `-SkipSidReference` leaves the four values unread (null in `system.json`, no error) and `run.json` records `SkipSidReference` true. It is meant for a caller that runs several collectors against the same computers and needs the reference from one of them only, as RemoteBaseline does. Without the switch every run reads it.
- The worker scriptblock takes one parameter, `SkipSidReference`, as its first and positional one: the remote call hands it over as the only element of `-ArgumentList`.
- Follows output convention 1.3: `run.json` carries `SchemaVersion` `1.3` and the key `SkipSidReference` directly after `UseSSL`.

##### 1.2.0

- Every error message and every csv cell is one line. The result row collapses each entry of `Errors` (and so `Error`) to one line, which covers a multi-line remote connection error (also one attributed after the row was built), and the csv writer trims every text cell and collapses its whitespace to one space, so a row never spans lines in a spreadsheet. The json files keep the source form.
- The per-computer folder name is built from the reported computer name and the build number with every character outside letters, digits, underscore and hyphen replaced by an underscore, so a name that carries path separators or dots cannot steer the folder outside the run folder. A real NetBIOS name is unchanged, and the name in the json and csv files stays as the target gave it.
- The result callback never ends the run: if completing one computer's result throws, that computer is reported `Failed` with an error line starting `host: ` and the run goes on. The warning for a result that matches no requested name is written as the last statement of the function, after `run.json`, `results.csv` and the rows, so a caller's `-WarningAction Stop` stops a finished run and no file or row is lost.
- The module loader reads `src\ps1` with `-LiteralPath` and `-Filter`, so an install path with brackets or other wildcard characters no longer imports nothing.
- A write-only dictionary in the worker's account step is removed and the rule name list of each account is sorted in place; the output is unchanged.
- README: Known limits and Automation paragraphs, a File formats paragraph, workgroup prerequisites, the Testing prerequisites, a Support and versioning section and a `SECURITY.md`. The examples are real captures with names and identifiers replaced by sample values.
- Follows output convention 1.2: `run.json` carries `SchemaVersion` `1.2`.

##### 1.1.0

- Application package SIDs (`S-1-15-2-...`, named by the application filter of a rule) are resolved to their package family name on the target: the worker reads the installed packages with `Get-AppxPackage -AllUsers`, derives the SID of every package family name the way Windows does (SHA-256 of the lower-cased name) and matches it against the package SIDs in the account table. A resolved package SID is `Resolved` in `accounts.csv` and `accounts.json` with the family name in `Name`, and `AccountUnresolvedCount` and `AccountUnresolvedTokens` no longer count it.
- `summary.json` and `system.json` gain two keys: `PackageCount` (the number of distinct package family names read, null when the packages were not read) and `PackagesDurationMs`. `PackageCount` follows `SddlFailedItems` in `summary.json` and `SddlFailedCount` in `system.json`; `PackagesDurationMs` follows `FiltersDurationMs` in both.
- A target that cannot give the packages leaves its package SIDs `NotFound`: an unelevated run gets `Access is denied` from `Get-AppxPackage -AllUsers`, which adds one `packages:` error line and makes the row `Partial`, and a target without the `Appx` module adds no error and no package names. A package SID whose package is not installed stays `NotFound` too.
- Nothing else changes shape: `rules.csv`, `rules.json` (`PackageFamilyName` is still what the rule reports), `profiles`, `globalsettings.json`, `results.csv` and `run.json` have the same columns and keys as in 1.0.0. Two values in a result row move with the feature: `AccountUnresolvedCount` and `AccountUnresolvedTokens` no longer count a package SID that was named, and a target whose packages could not be read has `ErrorCount` one higher with the `packages:` line in `Errors`.

##### 1.0.0

- First release.
- Collects from every requested computer the settings of the three firewall profiles (Domain, Private, Public), the global firewall settings, and every firewall rule in the active store with its seven filters (address, port, application, service, interface, interface type and security), as the firewall reports them.
- Identifies a rule delivered by Group Policy through a traced read of the rules, so its `PolicyStoreSourceType` is `GroupPolicy` and its `PolicyStoreSource` names the GPO.
- Resolves each security principal a rule names (the rule owner, the application package, and the users and machines of its security descriptors) once to its SID and name where the target can, so `accounts.csv` lists every distinct principal with how many rules name it.
- Works against the local computer in-process and against any number of remote computers over WinRM in the same call, exactly like the other collectors of the family: `.`, `localhost`, and the local computer's own names never leave the process, everything else goes through one `Invoke-Command`. Remote targets can be reached over WinRM HTTPS with `-UseSSL`.
- Leaves out: connection security (IPsec) and main mode rules, Hyper-V firewall rules, hashes and signatures of rule programs, the registry rule stores, the persistent and Group Policy stores as separate reads, and the AppContainer isolation rules that the rule cmdlet does not list.
- Follows the shared output convention (`SchemaVersion` `1.2`) of RemoteRSOP, RemoteScheduledTask, RemoteSecEdit and RemoteService.
- Runs on Windows PowerShell 5.1 and PowerShell 7, with a Pester test suite covering both engines. Every csv file it writes carries a UTF-8 byte order mark on both engines.

## Background

The Windows Firewall on a computer is three profile settings (Domain, Private, Public), a set of global settings, and a list of rules. The rules come from more than one source: rules installed with Windows or with a product, rules an administrator created, and rules Group Policy delivers. Each rule has a direction, an action, the profiles it applies to and seven filter classes (address, port, application, service, interface, interface type and security), and some rules are owned by a user's SID or name an application package.

### Risk(s)

A hardening baseline, a Group Policy change or an application installation changes which traffic a computer accepts, and a rule that nobody inventories either blocks what a role relies on or leaves a port, a program or an address open that nobody reviewed.

### Mitigation

Collect the full firewall inventory from every computer before the change, so the analysis can list every enabled rule, the rules each Group Policy object delivers, the profile settings that decide what happens to traffic no rule matches, and every principal that a rule names, and decide what needs attention.

## Requirements

- The `NetSecurity` module present on the target (it ships with Windows 8 and Server 2012 and later, so this is normally already true. A target without it gives a `Failed` row, because the rules read fails).
- Windows PowerShell 5.1 or PowerShell 7 on the collecting computer; the targets run Windows PowerShell 5.1.

Run elevated for a complete collection. Running without administrative rights has two consequences, captured in the row rather than hidden: the address, port, interface and interface type filters cannot be read without elevation, so every column of those four filter classes is null on every rule, `FilterFailedCount` is 4, the four class names are in `FilterFailedItems` and in `Errors`, and that computer's row comes back `Partial`; and the installed packages cannot be read for all users, so `Get-AppxPackage -AllUsers` adds the error line `packages: Access is denied. Access is denied.` (the cmdlet's own message, which names the failure twice), `PackageCount` is null, and the application package SIDs in the account table stay `NotFound` instead of getting their package family name. The rules themselves, the profiles, the global settings and the application, service and security filters are still collected. `IsElevated` in `results.csv` is the check for which case a row is in.

The collector reads the active store, the rules and settings as the firewall enforces them on the target. A rule delivered by Group Policy is identified by a traced read of the rules. Nothing is written on the target. Nothing else is required. Apart from the `NetSecurity` module there is no dependency on any other PowerShell module, no domain requirement, and nothing in the module refers to any specific domain, server, or account name. It runs the same way on a domain-joined computer and on a workgroup computer, and against a mix of both in the same run. Local collection never uses WinRM. Remote collection needs WinRM reachable from the computer you run this from. If you do not pass `-Credential`, it uses your own logged-on identity, exactly as any other remote PowerShell command would.

Hardening baselines can switch remote collection off. The CIS Level 2 benchmarks, for example,
set "Allow remote server management through WinRM" to Disabled, which removes the WinRM
listener on member servers and domain controllers. A remote call to such a computer returns a
`Failed` row with the connection error, and the other computers in the same call are not
affected. Run the command locally on those computers instead, for example through your software
distribution tool or a scheduled task, and collect the output folders afterwards. A local run
never uses WinRM and gives the same output.

Use the fully qualified domain name (FQDN) for remote targets, for example
`SRV010.contoso.com` rather than `SRV010` or an IP address. Kerberos, which WinRM uses by
default in a domain, needs a name it can match to the computer's account, and an IP
address falls back to rules that need TrustedHosts and explicit credentials. With
`-UseSSL` the FQDN is normally required: the collection then connects over WinRM HTTPS
(port 5986), and the name you pass must match the subject or subject alternative name of
the target's listener certificate, which normally carries only the FQDN. A short name or
an IP address then fails with WinRM error 12175, a certificate name mismatch. The target
needs an HTTPS listener and an inbound firewall rule for port 5986, and the collecting
computer must trust the certificate's issuing CA. Certificate checks are never skipped:
the module offers no SkipCACheck or SkipCNCheck option, by design. A target in a workgroup, or addressed by IP, needs the collecting computer to list it in TrustedHosts and, for a local administrator account that is not the built-in Administrator, `LocalAccountTokenFilterPolicy` set to 1 on the target; the module changes neither setting.

How local rules look when a policy sets `AllowLocalFirewallRules` to False is not proven: `EnforcementStatus` is copied as the target reports it. The rule count of a session host can be very large; writing a csv file of 20,000 rows of 42 columns takes the csv writer about 6 s on Windows PowerShell 5.1 and about 5 s on PowerShell 7, measured on a lab machine, and that is only one part of the collection.

Known limits. The module was verified on Windows Server 2016, 2019, 2022 and 2025 (each as a local run and as a WinRM target over HTTP and over HTTPS) and on Windows 11. A profile that is switched off comes out as `Enabled` `False` in profiles.csv with its rules carrying `DisabledInProfile` in `EnforcementStatus` (verified on a Windows Server 2022 target). A target whose firewall service (MpsSvc) is stopped and disabled gives a `Failed` row with three errors, `profiles:`, `settings:` and `rules:`, each ending in `There are no more endpoints available from the endpoint mapper.`; its computer folder holds system.json with the identity, empty profiles, rules and accounts files and a summary with null counts, and no globalsettings.json; the other targets of the same call are not affected (verified on a Windows Server 2019 target). Windows client editions and non-English Windows installations are untested: the code matches no English console text and reads SIDs and numeric codes, so locale risk is low, but it is not proven. The module runs in FullLanguage mode only: under ConstrainedLanguage mode, which an enforced WDAC or AppLocker policy produces, the worker fails at its first .NET call and the computer's row comes back `Failed` with that error; no file is left behind. The module files are not signed, so an AllSigned execution policy or a publisher rule refuses the import (see Importing the Module). A JEA endpoint does not run the worker: the module has no -ConfigurationName.

Automation. The functions never throw and the process exit code is 0 even when every row is `Failed`: a wrapper decides on the `Status` column of `results.csv` or the row objects, not on the exit code. No timeout parameter exists; a remote call uses the WinRM defaults (operation timeout 3 minutes). Running twice into the same `-OutputPath` never overwrites: every run gets its own UTC-stamped run folder. A caller's -WarningAction Stop turns a warning into a terminating error; the collectors emit their warnings after the run files are written, so the output on disk is complete in that case too.

## Output Data Handling

The output is a configuration inventory of every computer you collect from. It holds no
password, key or password hash that the module reads on purpose, but it names hosts, programs,
ports, addresses and SIDs: which program may accept connections on which port from which
address, which rules belong to which user SID, and which Group Policy objects deliver rules. It
describes how each computer is exposed in a detail that is useful to an attacker. Treat every
output folder as confidential.

What the output contains, per computer folder:

- `profiles.csv` and `profiles.json`: one row per profile (Domain, Private, Public) with whether it is enabled, its default inbound and outbound action, the switches for local firewall rules, local IPsec rules, user applications and user ports, and its log file name, size and settings.
- `globalsettings.json`: the global firewall settings as one object, among them the active profile, the stateful FTP and PPTP switches and the remote machine and remote user authorization lists. It is not written when the settings could not be read.
- `rules.csv` and `rules.json`: every rule in the active store, with its name, display name, description, group, profile, direction, action, owner SID, source (`PolicyStoreSource` and `PolicyStoreSourceType`), status, and the values of its seven filters: protocol, ports, addresses, program, package, service, interface aliases and type, authentication, encryption, and the users and machines of its security descriptors as SDDL text.
- `accounts.csv` and `accounts.json`: every principal the rules name (owner, application package, and the SIDs in the security descriptors), with its SID, its resolved name where the target could resolve it (for an application package SID, its package family name), and how many rules name it. The rule names are in `accounts.json` only.
- `summary.json`: the counts of the computer, the rule count by source type, the filter classes that could not be read, the number of installed package family names read, the durations of the steps and the unresolved account tokens.
- `system.json`: the computer's name, domain, OS build, hardware UUID (`ComputerId`) and `MachineGuid`, the SID reference (`MachineSid`, `DomainSid`, `ComputerAccountSid` and `DomainNetbiosName`, which are null as described under How it works), the counts, and the result and errors of the computer.

In the run folder, `results.csv` and `run.json` list the computers collected and the result and errors of each.

Nothing is redacted. Rule names, descriptions, program paths, service names, addresses, port lists and SDDL text are written exactly as the firewall reports them, so a rule whose name or description carries internal information exposes it here.

Recommended handling:

- Write the output to a folder that only administrators can read. The module creates its run
  folder under `-OutputPath` and sets no permissions of its own, so the run folder inherits the
  permissions of its parent.
- Move the output only as an encrypted archive or over an encrypted channel, never by
  unencrypted email or an open file share.
- Keep each run folder intact. Its files refer to each other by `RunId` and `ComputerId`, and an
  edited file cannot be told apart from an original one.
- Delete the output when the analysis is finished, following your own retention rules.

The collection writes nothing to the computers it reads. A remote run returns its data over
WinRM, which encrypts the traffic of a Kerberos or NTLM authenticated session even over HTTP,
unless unencrypted traffic has been allowed on the endpoint.

File formats. The csv files are UTF-8 with a byte order mark, every cell quoted, one row per line (whitespace inside a cell is collapsed to one space); the json files are UTF-8 without a byte order mark, and a top-level array is an array at zero and one element too. The csv is for spreadsheets; a loader that needs the source form of a value, or the null against empty-string distinction, reads the json.

## Importing the Module

From a Windows PowerShell 5.1 prompt, on the computer you want to collect from or run the
collection from. The module is not signed, so a copy downloaded or copied from elsewhere needs
unblocking and a process-scoped execution policy relaxed before it will import. This does not
bypass a Group Policy-enforced `AllSigned` execution policy, which overrides the process scope
and still blocks the import:

```powershell
Get-ChildItem C:\Path\To\RemoteFirewall -Recurse | Unblock-File
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
Import-Module C:\Path\To\RemoteFirewall\RemoteFirewall\RemoteFirewall.psd1
```

## Examples

Collecting from the local computer only, run elevated on a workgroup Windows 11 host:

```powershell
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
```

That run took 8 s. The files written to the computer folder, with their size in bytes: `accounts.csv` 565, `accounts.json` 14938, `globalsettings.json` 623, `profiles.csv` 893, `profiles.json` 2402, `rules.csv` 364436, `rules.json` 1305210, `summary.json` 814 and `system.json` 1332. The run folder also holds `results.csv` (390) and `run.json` (1478).

`profiles.csv` of that run:

```
"Name","Enabled","DefaultInboundAction","DefaultOutboundAction","AllowInboundRules","AllowLocalFirewallRules","AllowLocalIPsecRules","AllowUserApps","AllowUserPorts","AllowUnicastResponseToMulticast","NotifyOnListen","EnableStealthModeForIPsec","LogFileName","LogMaxSizeKilobytes","LogAllowed","LogBlocked","LogIgnored","DisabledInterfaceAliases"
"Domain","True","Block","Allow","True","True","True","True","True","True","True","False","%systemroot%\system32\LogFiles\Firewall\domfirewall.log","32767","True","True","True",""
"Private","True","Block","Allow","True","True","True","True","True","True","True","False","%systemroot%\system32\LogFiles\Firewall\privfirewall.log","32767","True","True","True",""
"Public","True","Block","Allow","True","True","True","True","True","True","True","False","%systemroot%\system32\LogFiles\Firewall\pubfirewall.log","32767","True","True","True",""
```

The header and data rows 2 to 4 of `rules.csv` of that run (the first data row is left out). A null is a bare empty cell, an empty array is `""`, and an array with more than one element is joined with `|` (none of the three rows has one):

```
"Name","InstanceID","DisplayName","Description","Group","DisplayGroup","Enabled","Profile","Direction","Action","EdgeTraversalPolicy","LooseSourceMapping","LocalOnlyMapping","Owner","Platform","PolicyStoreSource","PolicyStoreSourceType","PrimaryStatus","Status","StatusCode","EnforcementStatus","PackageFamilyName","PolicyAppId","RemoteDynamicKeywordAddresses","Protocol","LocalPort","RemotePort","IcmpType","DynamicTransport","LocalAddress","RemoteAddress","Program","Package","Service","InterfaceAlias","InterfaceType","Authentication","Encryption","OverrideBlockRules","LocalUser","RemoteUser","RemoteMachine"
"AllJoyn-Router-In-TCP","AllJoyn-Router-In-TCP","AllJoyn Router (TCP-In)","Inbound rule for AllJoyn Router traffic [TCP]","@FirewallAPI.dll,-37002","AllJoyn Router","True","Domain, Private","Inbound","Allow","Block","False","False",,"","PersistentStore","Local","Inactive","The rule was parsed successfully from the store. (65536)","65536","ProfileInactive",,,"","TCP","9955","Any","Any","Any","Any","Any","C:\Windows\system32\svchost.exe",,"AJRouter","Any","Any","NotRequired","NotRequired","False","Any","Any","Any"
"AllJoyn-Router-In-UDP","AllJoyn-Router-In-UDP","AllJoyn Router (UDP-In)","Inbound rule for AllJoyn Router traffic [UDP]","@FirewallAPI.dll,-37002","AllJoyn Router","True","Domain, Private","Inbound","Allow","Block","False","False",,"","PersistentStore","Local","Inactive","The rule was parsed successfully from the store. (65536)","65536","ProfileInactive",,,"","UDP","Any","Any","Any","Any","Any","Any","C:\Windows\system32\svchost.exe",,"AJRouter","Any","Any","NotRequired","NotRequired","False","Any","Any","Any"
"AllJoyn-Router-Out-TCP","AllJoyn-Router-Out-TCP","AllJoyn Router (TCP-Out)","Outbound rule for AllJoyn Router traffic [TCP]","@FirewallAPI.dll,-37002","AllJoyn Router","True","Domain, Private","Outbound","Allow","Block","False","False",,"","PersistentStore","Local","Inactive","The rule was parsed successfully from the store. (65536)","65536","OptimizedOut",,,"","TCP","Any","Any","Any","Any","Any","Any","C:\Windows\system32\svchost.exe",,"AJRouter","Any","Any","NotRequired","NotRequired","False","Any","Any","Any"
```

`summary.json` of that run:

```json
{
    "ActiveProfile":  "Public",
    "ProfileCount":  3,
    "RuleCount":  574,
    "EnabledRuleCount":  318,
    "RuleCountBySourceType":  {
                                  "Dynamic":  3,
                                  "Local":  571
                              },
    "FilterFailedCount":  0,
    "FilterFailedItems":  [

                          ],
    "SddlFailedCount":  0,
    "SddlFailedItems":  [

                        ],
    "ProfilesDurationMs":  1291,
    "RulesDurationMs":  1333,
    "FiltersDurationMs":  3339,
    "AccountsDurationMs":  140,
    "AccountCount":  4,
    "AccountUnresolvedCount":  1,
    "AccountUnresolvedTokens":  [
                                    "S-1-5-92-3339056971-1291069075-3798698925-2882100687-0"
                                ]
}
```

`accounts.csv` of that run. The last token did not resolve to a name; that is data, and the row is still `Success`:

```
"Token","Kind","Sid","Name","Status","ReferenceCount","Error"
"S-1-5-18","Sid","S-1-5-18","NT AUTHORITY\SYSTEM","Resolved","46",""
"S-1-5-21-1111111111-2222222222-3333333333-1001","Sid","S-1-5-21-1111111111-2222222222-3333333333-1001","WS01\admin","Resolved","59",""
"S-1-5-84-0-0-0-0-0","Sid","S-1-5-84-0-0-0-0-0","NT AUTHORITY\USER MODE DRIVERS","Resolved","3",""
"S-1-5-92-3339056971-1291069075-3798698925-2882100687-0","Sid","S-1-5-92-3339056971-1291069075-3798698925-2882100687-0",,"NotFound","2","Some or all identity references could not be translated."
```

Run from a Windows Server 2022 domain member against local aliases, a NetBIOS and FQDN pair, another domain member over WinRM, and one name that does not resolve. That row comes back as a `Failed` result row, not a terminating error. On these servers 14 of the 15 accounts did not resolve to a name, and every reached row is still `Success`:

```powershell
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
```

Computer names can also be passed with `-ComputerName` instead of the pipeline, and a credential
supplied for remote targets that the caller's own account does not have rights on:

```powershell
'SRV01', 'SRV02', 'SRV03' | Get-FirewallInventory -Credential (Get-Credential) -OutputPath C:\FirewallRuns
```

`.`, `localhost`, your own computer name, and your own DNS name (any case) are all treated as
local and never go over WinRM. Anything else goes over WinRM through a single `Invoke-Command`
call.

Over WinRM HTTPS with `-UseSSL`, using the FQDN that the target's listener certificate
carries. `run.json` of that run has `UseSSL` True and `SchemaVersion` 1.3:

```powershell
PS C:\FirewallTest> Get-FirewallInventory -ComputerName 'SRV099.contoso.com' -UseSSL -OutputPath 'out' | Format-Table -Property ComputerName, ComputerId, Status, Transport, RuleCount, ErrorCount

ComputerName       ComputerId                           Status  Transport RuleCount ErrorCount
------------       ----------                           ------  --------- --------- ----------
SRV099.contoso.com 11111111-2222-3333-4444-555555555502 Success WinRM           263          0
```

A Group Policy rule beside a local rule in `rules.csv` on SRV010, selected columns. The two GUID-named rules come from the domain GPOs: their `PolicyStoreSourceType` is `GroupPolicy` and `PolicyStoreSource` names the GPO. `EnforcementStatus` is an array, so the local rule's two values are joined with `|` in the csv:

```
Name                                   DisplayName                          Enabled Profile         Direction Action PolicyStoreSourceType PolicyStoreSource            EnforcementStatus        Protocol
----                                   -----------                          ------- -------         --------- ------ --------------------- -----------------            -----------------        --------
WINRM-HTTP-In-TCP                      Windows Remote Management (HTTP-In)  True    Domain, Private Inbound   Allow  Local                 PersistentStore              ProfileInactive|Enforced TCP
{895081BF-26D8-4115-98E7-CDD0D915B0A3} Windows Remote Management (HTTP-In)  True    Domain          Inbound   Allow  GroupPolicy           C.SEC.Domain.All.WinRM       Enforced                 TCP
{D4D11B53-2407-441C-883A-4F61AF9EE4B3} Windows Remote Management (HTTPS-In) True    Domain          Inbound   Allow  GroupPolicy           C.SEC.Domain.All.WinRM-HTTPS Enforced                 TCP
```

## Functions

The list of the functions contained in this module.

### Get-FirewallInventory

```PowerShell
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

    The SID reference is four values that say whose an S-1-5-21 SID is: MachineSid (the SID
    of the computer's own account database), DomainSid, ComputerAccountSid and
    DomainNetbiosName. MachineSid is read from the local account with RID 500 through CIM
    (Win32_UserAccount). The three domain values are read from the computer's own domain
    account through the same account lookup the module uses for the principals of the rules,
    and only on a domain-joined computer. No Active Directory module and no LDAP is used. A
    domain controller has no MachineSid, and a workgroup computer has no domain values; both
    stay null with no error.

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

.PARAMETER SkipSidReference
    Leaves the SID reference unread: MachineSid, DomainSid, ComputerAccountSid and
    DomainNetbiosName are null in system.json, and run.json records SkipSidReference true.
    Meant for a caller that runs several collectors against the same computers and needs the
    reference from one of them only, as RemoteBaseline does. Without the switch every run
    reads it.

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
    SchemaVersion 1.3.

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
```

## How it works

Three sources are collected per computer: the settings of the three firewall profiles together with the global firewall settings, every firewall rule in the active store, and the seven filters of those rules. A last step reads the installed application packages and resolves the security principals the rules name. The active store is the firewall's own view of what it enforces, so the rules in it come with a `PolicyStoreSourceType` such as `Local`, `GroupPolicy` or `Dynamic`.

All steps run through one self-contained worker: in-process for local targets, or once per call through `Invoke-Command` for remote targets, regardless of how many local aliases or remote names were requested. The worker runs on Windows PowerShell 5.1 on the target. It never throws: every step records its own error and moves on. It changes nothing on the target and writes nothing to its disk. In order, the worker:

1. Reads the identity of the computer: names, domain, OS version and build, edition, culture, time zone, PowerShell version, whether the session is elevated, `ComputerId` and `MachineGuid`, then the SID reference (see below) unless `-SkipSidReference` was given.
2. Reads the profiles with `Get-NetFirewallProfile -PolicyStore ActiveStore`. A failure adds the error `profiles: <message>` and leaves `ProfileCount` at 0. The profiles are written Domain, Private, Public.
3. Reads the global settings with `Get-NetFirewallSetting -PolicyStore ActiveStore`. A failure adds the error `settings: <message>`, an empty result adds `settings: no object returned`, and in both cases `globalsettings.json` is not written.
4. Reads every rule with `Get-NetFirewallRule -PolicyStore ActiveStore -TracePolicyStore`. The traced read is what shows a Group Policy rule as `GroupPolicy` with the GPO name in `PolicyStoreSource`. A failure adds the error `rules: <message>`, leaves `RuleCount` null (not 0, because nothing was read), skips steps 5 and 6, and the row is `Failed`. A read that succeeds and returns no rule gives `RuleCount` 0 and the error `rules: no rule returned`, so the `Failed` row says why.
5. Reads the filters: for each of Address, Port, Application, Service, Interface, InterfaceType and Security, one call of `Get-NetFirewall<Class>Filter -PolicyStore ActiveStore` that returns the filter objects of all rules at once.
6. Builds one row per rule, the rule's own properties first and then the filter properties, and sorts the rows by `Name` (ordinal, ignoring case), then `InstanceID`, `PolicyStoreSourceType` and `PolicyStoreSource`, so the order is the same on every run.
7. Reads the installed application packages with `Get-AppxPackage -AllUsers` (when the command exists on the target, and only when step 3 read the rules; with no rule there is no token to name) and turns every distinct package family name into its package SID, for step 8. A target without the command adds no error and `PackageCount` stays null. A command that throws, as it does for an unelevated caller, adds the error `packages: <message>` and leaves `PackageCount` null.
8. Resolves the security principals the rules name (see below) and returns everything as one object.

Each filter class is read with one call, never by piping each rule to a filter cmdlet, which costs about 30 ms per rule per filter (about 120 s for 574 rules). A class whose call throws adds the error `filter <Class>: <message>`, counts in `FilterFailedCount`, and its name goes to `FilterFailedItems`; every column of that class is then null on every rule. There is no per-rule fallback. An unelevated run is this case for four classes.

The filter reads are joined to the rules by position. The active store can hold two rules with one `InstanceID`, a Group Policy copy of a built-in rule beside the local rule, and neither the id nor a per-rule association read can tell such copies apart, but every filter read enumerates in exactly the order of the rule read (seen on three reads, for all seven classes, with the plain and the traced rule read), so when a class's sequence of `InstanceID` values equals the rule read's sequence, filter object i belongs to rule i. When the sequences differ (never seen), the class is joined through a dictionary on `InstanceID` for every id carried by one rule and one filter object; for an id carried by more than one rule or more than one filter object, the columns of that class are null on every rule with that id and one error `filter <Class>: ambiguous InstanceID <id>` is added. That class does not count in `FilterFailedCount`, but the error makes the row `Partial`. A value that might belong to another rule is never written.

Values are copied as the firewall reports them and nothing is translated or trimmed, so `Any` stays `Any`. An enumeration is written as its display string (`True`, `Allow`, `Domain, Private`, `NotConfigured`), a boolean stays a boolean and a number stays a number. `LogMaxSizeKilobytes` is a number, and its "not configured" marker, the largest unsigned 64-bit integer, is written as that number and not as null. A field that can hold several values (`Platform`, `EnforcementStatus`, `RemoteDynamicKeywordAddresses`, `LocalPort`, `RemotePort`, `IcmpType`, `LocalAddress`, `RemoteAddress` and `InterfaceAlias` of a rule, `DisabledInterfaceAliases` of a profile) is always an array of strings once it was read: no value gives an empty array and one value gives a one-element array. Two cases give null instead: every column of a filter class whose read failed, so "could not be read" never looks like "no values", and a property the target does not have at all. `PackageFamilyName` is such a property: Windows 11 has it and Windows Server 2022 does not, and newer builds can add properties that an older build lacks. `StatusCode` is the rule status number of the firewall (65536 for a rule parsed successfully), not a Windows result code, so it has no hex column.

In the csv files an array cell is its elements joined with `|`, and whitespace runs in text cells collapse to one space so a row stays on one line. An element that itself contains `|` cannot be told apart in the csv; the json is exact. A null is a bare empty cell and an empty string is `""`, so a loader that needs the distinction reads the json.

Every principal a rule names becomes one token in the account table, the SID as text with `Kind` `Sid`: the rule's `Owner` when it is not empty, its application filter's `Package` when it is not empty, and, for each of `LocalUser`, `RemoteUser` and `RemoteMachine` whose value is not empty and not `Any`, the SID of every access control entry in the security descriptor text (its discretionary and system lists, not its owner or group). A value that does not parse adds the error `sddl <rule Name> <field>: <message>`, counts in `SddlFailedCount`, and adds `<rule Name>:<field>` to `SddlFailedItems`; the rule row keeps the text as the target gave it either way. Each distinct token is looked up once on the target and resolved to a name: `Status` is `Resolved`, or `NotFound` with the lookup's own message. No account lookup knows an application package SID, so a package SID that comes back `NotFound` is then looked up among the package SIDs of step 7: a hit sets `Name` to the package family name, `Status` to `Resolved` and `Error` to an empty string. A package SID is the SHA-256 of the lower-cased family name in UTF-16, its first 28 bytes read as seven unsigned 32-bit sub-authorities after `S-1-15-2-`, which is why the name can only be found by hashing the family names the target has installed. A package that is not installed on the target stays `NotFound` with the lookup's message, and a capability SID (`S-1-15-3-`) is not looked up. `accounts.csv` lists one row per token (`Token`, `Kind`, `Sid`, `Name`, `Status`, `ReferenceCount`, `Error`). The rule names each token references, sorted and each name once, are in `accounts.json`'s `References` only, and `ReferenceCount` is their number. Tokens are sorted ordinal.

Two facts about these principals. A rule can be owned by a user's SID (the `Owner` column of `rules.csv` then holds it, as the `accounts.csv` sample above shows for `S-1-5-21-1111111111-2222222222-3333333333-1001`, which 59 rules name and which resolves to `WS01\admin`), and the lookup runs on the target, so a SID resolves only where the target can translate it. A token such as an application package SID whose package is not installed or was not read (see step 7), a capability SID or a user from another machine that does not resolve is recorded as `NotFound`, which is data for the analysis, not an error: it never enters `Errors` and never changes `Status`.

Every computer's identity includes `ComputerId` (`Win32_ComputerSystemProduct.UUID`, upper case, bound to the hardware or the virtual machine and unaffected by a rename or a domain move) and `MachineGuid` (bound to the Windows installation), both null when the read fails. `ComputerId` is in the result row and `system.json`. `MachineGuid` is in `system.json` only. `run.json` carries the collecting computer's own `ComputerId` as `HostComputerId`, read the same way, plus `Collector` and `SchemaVersion`, so a shared loader can tell which collector and which version of the output convention produced a run folder.

The SID reference is read in the identity step, with two reads and no Active Directory module and no LDAP. `MachineSid` is the SID of the computer's own account database, taken from the built-in Administrator (RID 500, whatever its name or state) among the local accounts that `Win32_UserAccount` returns when the computer name is given as the domain, without the RID. `Win32_UserAccount` lists no local account on a domain controller, so `MachineSid` is null there, with no error. The domain values come from the computer's own account in the domain (`<domain>\<computer>$`, translated to a SID and back to a name through the same lookup the module uses for the principals of the rules): `ComputerAccountSid` is that SID with its RID, `DomainSid` is the SID without it and `DomainNetbiosName` is the domain part of the name it translates back to. They are read only on a domain-joined computer, so all three are null on a workgroup computer. A domain-joined computer that cannot resolve its own account gets the error `identity: DomainSid: <message>`, a `Partial` row and null domain values. `-SkipSidReference` leaves all four null with no error.

Results are completed as they arrive rather than after every target has answered: each remote result has its folder written and its row built as soon as it arrives from `Invoke-Command`, and the reference to it is dropped before the next one is read.

Each run creates one new, timestamped folder under `-OutputPath`:

```
C:\FirewallRuns\RemoteFirewall-<run timestamp>Z\
    run.json                       summary of the whole run
    results.csv                    one row per computer, opens in Excel
    <COMPUTER>_<build>_<timestamp>Z\   one folder per computer actually reached
        system.json
        profiles.json / profiles.csv
        globalsettings.json
        rules.json / rules.csv
        accounts.json / accounts.csv
        summary.json
```

A computer that could not be reached at all (WinRM failure, wrong name, and so on) still gets a row in `results.csv` and `run.json`, but no folder of its own, since nothing was collected from it. Nothing in a per-computer folder is modified after the run.

Each computer's row has a `Status`, computed from the worker's own counts and its own errors alone, never from anything the host has trouble with while writing files:

- **Success**: at least one rule was found, every filter class was read, every security descriptor text parsed, and the worker reported no errors of its own.
- **Partial**: everything else short of a total failure. An unelevated run comes back `Partial` with the four filter classes that need elevation named in `FilterFailedItems`. An ambiguous `InstanceID` also makes a row `Partial`.
- **Failed**: the computer could not be reached at all, or the worker's `RuleCount` is null or 0.

Every row also carries `Error` (the first problem seen, blank when there was none), `ErrorCount` (how many messages are in `Errors`), and `Errors` (every problem seen, in `run.json` and `system.json`, not in the csv). For anything other than `Success`, the same message is also written as a `Write-Warning` while the command runs, so you will see it scroll past in the console as well as find it in the output files afterwards.

No firewall setting is changed on any target. This module only reads, and it writes nothing to the target's disk.

### What to send back

Send the whole `RemoteFirewall-<timestamp>Z` folder (zipped is fine). It contains everything the analysis side needs: `run.json`, `results.csv`, and every reached computer's folder with its raw profile, global setting, rule and account files. Do not edit any file inside it before sending. Nothing in a per-computer folder is touched again after the run, and the analysis relies on that.

## Testing

`tests\Invoke-Tests.ps1` runs `PSScriptAnalyzer` (pinned to 1.25.0) over the module and tests
folder using `PSScriptAnalyzerSettings.psd1`, then runs the Pester suite (pinned to 6.1.0). It exits 1 on any analyzer Error or Warning
result, on any failed test, or when zero tests ran.

The gate needs Pester 6.1.0 and PSScriptAnalyzer 1.25.0 exactly; Windows PowerShell 5.1 ships Pester 3.4, so install both once per engine with `Install-Module Pester -RequiredVersion 6.1.0 -Scope CurrentUser -Force` and `Install-Module PSScriptAnalyzer -RequiredVersion 1.25.0 -Scope CurrentUser`. Without them the gate exits 1 before any test runs. A few tests that need administrative rights report Inconclusive in an unelevated session, which does not fail the gate; run the gate once elevated per release to cover them.

Run it under both engines from the repository root:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File tests\Invoke-Tests.ps1
pwsh -NoProfile -File tests\Invoke-Tests.ps1
```

Every path inside the test suite is derived from `$PSScriptRoot`, so it also passes from a
relocated copy of the repository.

## Support and versioning

Versions follow semantic versioning: a patch release changes no output file, column or value; a minor release may add columns, keys or files and may change a value's rule, and the five Remote collectors release such a change together under one output convention version; a major release would change an existing column or key. Every release is a tagged commit (`v<version>`) and the Version Changes list above is the change log. Report a defect or a question as an issue on the project repository (ProjectUri in the manifest); report a security concern as described in SECURITY.md. The module is provided under the MIT licence without a support contract; fixes land in the next release.

## References

- [Get-NetFirewallRule - Microsoft Learn](https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallrule)
- [Get-NetFirewallProfile - Microsoft Learn](https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallprofile)
- [Get-NetFirewallSetting - Microsoft Learn](https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallsetting)
- [Get-NetFirewallAddressFilter - Microsoft Learn](https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewalladdressfilter)
- [Get-NetFirewallPortFilter - Microsoft Learn](https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallportfilter)
- [Get-NetFirewallApplicationFilter - Microsoft Learn](https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallapplicationfilter)
- [Get-NetFirewallServiceFilter - Microsoft Learn](https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallservicefilter)
- [Get-NetFirewallInterfaceFilter - Microsoft Learn](https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallinterfacefilter)
- [Get-NetFirewallInterfaceTypeFilter - Microsoft Learn](https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallinterfacetypefilter)
- [Get-NetFirewallSecurityFilter - Microsoft Learn](https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallsecurityfilter)

## License

Tom Stryhn, https://github.com/tomstryhn

Project: https://github.com/tomstryhn/RemoteFirewall

MIT License, see [LICENSE](LICENSE)
