@{
    RootModule           = 'RemoteFirewall.psm1'
    ModuleVersion        = '1.2.0'
    GUID                 = '4d0cf6bd-bc17-45ea-9056-9159d2a60290'
    Author               = 'Tom Stryhn'
    CompanyName          = 'Tom Stryhn'
    Copyright            = 'Copyright (c) 2026 Tom Stryhn'
    Description          = 'PowerShell Module to collect the Windows Firewall profile settings, global settings and every firewall rule with its filters and the security principals it names from local and remote computers'
    PowerShellVersion    = '5.1'
    CompatiblePSEditions = @('Desktop', 'Core')

    FunctionsToExport = @('Get-FirewallInventory')
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()

    FileList = @(
        'RemoteFirewall.psd1',
        'RemoteFirewall.psm1',
        'LICENSE',
        'src\ps1\Complete-FirewallInventoryComputer.ps1',
        'src\ps1\ConvertTo-FirewallInventoryResultRow.ps1',
        'src\ps1\ConvertTo-FirewallInventoryRuleCsvRow.ps1',
        'src\ps1\Get-FirewallInventory.ps1',
        'src\ps1\Get-FirewallInventoryHostComputerId.ps1',
        'src\ps1\Get-FirewallInventorySafeProperty.ps1',
        'src\ps1\Get-FirewallInventoryWorker.ps1',
        'src\ps1\Initialize-FirewallInventoryRunFolder.ps1',
        'src\ps1\Invoke-FirewallInventoryLocal.ps1',
        'src\ps1\Invoke-FirewallInventoryRemote.ps1',
        'src\ps1\Resolve-FirewallInventoryComputerList.ps1',
        'src\ps1\Resolve-FirewallInventoryRemoteErrorName.ps1',
        'src\ps1\Resolve-FirewallInventoryUniqueFolder.ps1',
        'src\ps1\Test-FirewallInventoryLocalName.ps1',
        'src\ps1\Write-FirewallInventoryCsvFile.ps1',
        'src\ps1\Write-FirewallInventoryTextFile.ps1'
    )

    PrivateData = @{
        PSData = @{
            Tags         = @('PSEdition_Desktop', 'PSEdition_Core', 'Windows', 'Security', 'Firewall', 'WindowsFirewall', 'FirewallRules', 'WinRM')
            LicenseUri   = 'https://opensource.org/licenses/MIT'
            ProjectUri   = 'https://github.com/tomstryhn/RemoteFirewall'
            ReleaseNotes = '1.2.0: unelevated runs report the shortfall and come back Partial (RemoteScheduledTask, RemoteService); every error message and csv cell is one line; the per-computer folder name is sanitised; the result callback never ends the run; loader hardened against wildcard paths; unused account lookup dictionary removed and account reference lists sorted in place; README Known limits, Automation, File formats, Support and versioning, workgroup prerequisites; SECURITY.md; examples anonymised; output convention 1.2. RemoteFirewall 1.1.0. Application package SIDs are resolved to package family names on the target (Get-AppxPackage -AllUsers, hashed the way Windows derives the SID), and summary.json and system.json gain PackageCount and PackagesDurationMs. RemoteFirewall 1.0.0. First release: collects the three firewall profiles, the global settings and every firewall rule with its seven filters, and the security principals the rules name, from local and remote computers in the output convention of the Remote collectors.'
        }
    }
}
