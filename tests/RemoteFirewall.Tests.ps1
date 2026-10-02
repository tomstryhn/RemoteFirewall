<#PSScriptInfo

.DESCRIPTION Pester tests for the RemoteFirewall module

.VERSION 1.3.0

.GUID 243205c7-1aaf-4e8c-af49-6915ebced0db

.AUTHOR Tom Stryhn

.COMPANYNAME Tom Stryhn

.COPYRIGHT 2026 (c) Tom Stryhn

.LICENSEURI https://github.com/tomstryhn/RemoteFirewall/blob/main/LICENSE

.PROJECTURI https://github.com/tomstryhn/RemoteFirewall

#>

<#
Pester tests for the RemoteFirewall module, written in Pester 6 syntax. Two groups. The first is the shared
contract of the Remote collector family, carried over from RemoteService with the noun changed: local name
detection, local alias rows, remote attribution and error mapping, streaming through -OnResult, credential and
UseSSL forwarding, the unattributed result warning, parameter validation, the unique folder, the csv and text
writers, the manifest, the system.json key order, CollectorVersion and the CIM failure identity. The second is
the firewall part (DESIGN.md section 10): the worker scriptblock run against fakes of the ten NetSecurity
cmdlets (defined in the module's own session state by tests\TestHelpers), the host functions run against a
hand-made worker object, the two joined end to end, the Status matrix of section 8, and one real local run
that is skipped when the NetSecurity module is absent. Every path is derived from $PSScriptRoot, so the suite
still passes from a relocated copy of the repository.
#>

# Discovery phase: -ForEach data and skip conditions are bound here, before any BeforeAll runs, so the helpers
# are dot-sourced at file scope too. The same helpers are dot-sourced again in BeforeAll for the run phase.
$discoveryHelperPath = Join-Path -Path $PSScriptRoot -ChildPath 'TestHelpers'
foreach ($helperName in @('FirewallTestTypes.ps1', 'FirewallTestData.ps1', 'FakeFirewall.ps1', 'FakeNetSecurity.ps1', 'FakeWorkerObject.ps1')) {
    . (Join-Path -Path $discoveryHelperPath -ChildPath $helperName)
}
$FwDiscovery = Get-FirewallTestData
$ArrayColumnCases = @(
    foreach ($case in $FwDiscovery.ArrayCases) { @{ Id = $case.Id; Label = $case.Label; Column = $case.Column; Source = $case.Source } }
)
$FilterClassCases = @(foreach ($class in $FwDiscovery.FilterClasses) { @{ Class = $class } })
$RuleColumnCases = @(foreach ($column in $FwDiscovery.RuleColumnNames) { @{ Column = $column } })
$ScalarCases = @(
    foreach ($case in $FwDiscovery.ScalarCases) { @{ Id = $case.Id; Label = $case.Label; Column = $case.Column } }
)
$PackagePairCases = @(foreach ($pair in $FwDiscovery.PackagePairs) { @{ Sid = $pair.Sid; FamilyName = $pair.FamilyName } })

BeforeAll {
    $script:RepoRoot = Split-Path -Path $PSScriptRoot -Parent
    $script:ManifestPath = Join-Path -Path $script:RepoRoot -ChildPath 'RemoteFirewall\RemoteFirewall.psd1'
    $script:ModuleFolder = Split-Path -Path $script:ManifestPath -Parent
    $script:HelperPath = Join-Path -Path $PSScriptRoot -ChildPath 'TestHelpers'
    foreach ($helperName in @('FirewallTestTypes.ps1', 'FirewallTestData.ps1', 'FakeFirewall.ps1', 'FakeNetSecurity.ps1', 'FakeWorkerObject.ps1')) {
        . (Join-Path -Path $script:HelperPath -ChildPath $helperName)
    }
    $script:Fw = Get-FirewallTestData
    $script:NetSecurityPresent = [bool](Get-Module -ListAvailable -Name NetSecurity)

    Import-Module $script:ManifestPath -Force
    $script:Module = Get-Module RemoteFirewall

    # Windows PowerShell 5.1 hands a json array over as one object when it is piped to ConvertFrom-Json, PowerShell 7 hands over its elements; -InputObject and one enumeration here give the elements on both, so a caller wraps the call in @().
    # PowerShell 7 also turns an ISO 8601 looking string into a DateTime, so no test compares a timestamp field through this.
    function ConvertFrom-JsonArray {
        param([string]$Text)
        $parsed = ConvertFrom-Json -InputObject $Text
        foreach ($element in $parsed) { $element }
    }

    # A fresh, empty run folder under TestDrive, the shape Complete-FirewallInventoryComputer expects.
    function Get-TestRunFolder {
        $runFolder = Join-Path -Path $TestDrive -ChildPath ([guid]::NewGuid().ToString('N'))
        New-Item -Path $runFolder -ItemType Directory -Force | Out-Null
        return $runFolder
    }

    # Complete-FirewallInventoryComputer is private, reached inside the module by name, so the host side can be run
    # on a hand-made or a real worker object without the public function or any mock.
    function Invoke-CompleteInModule {
        param(
            [AllowNull()]
            $WorkerObject,
            [string]$RequestedName = 'fakehost',
            [string]$Transport = 'WinRM',
            [string]$RunFolder,
            [string[]]$ExtraErrors = @()
        )
        if (-not $RunFolder) { $RunFolder = Get-TestRunFolder }
        $completeScript = {
            param($RequestedComputerName, $TransportName, $Folder, $Worker, $Extra)
            Complete-FirewallInventoryComputer -RequestedComputerName $RequestedComputerName -Transport $TransportName -RunFolder $Folder -WorkerObject $Worker -ExtraErrors $Extra
        }
        & $script:Module $completeScript $RequestedName $Transport $RunFolder $WorkerObject $ExtraErrors
    }

    # Runs the worker scriptblock at the given error action preference, set inside the module's session state where the scriptblock resolves it.
    function Invoke-WorkerInModule {
        param(
            [string]$Preference = 'Stop',
            [switch]$Full,
            [switch]$ReadSidReference
        )
        # The SID reference is skipped unless a test asks for it: the identity mocks of most tests name a domain the test host is not in, and a read would send a real account lookup to it. The tests of the SID reference itself pass -ReadSidReference.
        $skipSidReference = -not $ReadSidReference
        $worker = & $script:Module { Get-FirewallInventoryWorker }
        $output = @(& $script:Module { param($w, $preference, $skip) $ErrorActionPreference = $preference; & $w -SkipSidReference $skip } $worker $Preference $skipSidReference 2>&1)
        $errorRecords = @($output | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] })
        $results = @($output | Where-Object { $_ -isnot [System.Management.Automation.ErrorRecord] })
        if ($Full) { return [pscustomobject]@{ Result = $results[0]; ResultCount = $results.Count; ErrorRecords = $errorRecords } }
        return $results[0]
    }

    # Points the fake NetSecurity cmdlets at a state and runs the worker once. The fakes must already be installed in the module.
    function Get-WorkerResult {
        param(
            [Parameter(Mandatory = $true)]
            [hashtable]$State,
            [string]$Preference = 'Stop',
            [switch]$Full,
            [switch]$ReadSidReference
        )
        Use-FakeFirewallState -Module $script:Module -State $State
        Invoke-WorkerInModule -Preference $Preference -Full:$Full -ReadSidReference:$ReadSidReference
    }

    # The rules of the shared InstanceID tests: every one has the id Shared-Id, and its own value in every filter class, told from its number. Number 1 is the local rule, 2 and 3 are Group Policy copies, sorted after each other by PolicyStoreSource: 'alpha GPO' (3) before 'Lab GPO' (2).
    function Get-SharedIdSpec {
        param([int]$Number)
        switch ($Number) {
            1 { return @{ Tag = 'Local'; Type = [RemoteFirewallTests.FwSourceType]::Local; TypeText = 'Local'; Source = 'PersistentStore' } }
            2 { return @{ Tag = 'Gpo'; Type = [RemoteFirewallTests.FwSourceType]::GroupPolicy; TypeText = 'GroupPolicy'; Source = 'Lab GPO' } }
            default { return @{ Tag = 'GpoThree'; Type = [RemoteFirewallTests.FwSourceType]::GroupPolicy; TypeText = 'GroupPolicy'; Source = 'alpha GPO' } }
        }
    }

    function Get-SharedIdFilterSet {
        param([int]$Number)
        $spec = Get-SharedIdSpec -Number $Number
        return @{
            Address       = @{ LocalAddress = [string[]]@("10.0.$Number.1"); RemoteAddress = [string[]]@("10.9.$Number.0/24") }
            Port          = @{ LocalPort = [string[]]@("338$Number") }
            Application   = @{ Program = ('C:\' + $spec.Tag + '.exe') }
            Service       = @{ Service = ('svc' + $spec.Tag) }
            Interface     = @{ InterfaceAlias = [string[]]@(('Eth' + $spec.Tag)) }
            InterfaceType = @{ InterfaceType = [RemoteFirewallTests.FwIfType]$Number }
            Security      = @{ Authentication = [RemoteFirewallTests.FwAuth]($Number % 3); Encryption = [RemoteFirewallTests.FwEnc]($Number % 3) }
        }
    }

    # Adds the rule of that number with the id Shared-Id, unless another id is given. The filter objects of every class follow in the order the rules were added, the way the lab read returns them.
    function Add-SharedIdRule {
        param([hashtable]$State, [int]$Number, [string]$Id = 'Shared-Id', [string]$Name, [string]$FilterInstanceID)
        $spec = Get-SharedIdSpec -Number $Number
        if (-not $Name) { $Name = $Id }
        $parameters = @{
            State      = $State
            Name       = $Name
            InstanceID = $Id
            RuleSet    = @{ PolicyStoreSourceType = $spec.Type; PolicyStoreSource = $spec.Source }
            FilterSet  = (Get-SharedIdFilterSet -Number $Number)
        }
        if ($FilterInstanceID) { $parameters['FilterInstanceID'] = $FilterInstanceID }
        Add-FakeFirewallRule @parameters
    }

    # Every column of the seven classes of one shared-id rule row, against what Get-SharedIdFilterSet handed over for that number.
    function Assert-SharedIdRow {
        param($Row, [int]$Number)
        $spec = Get-SharedIdSpec -Number $Number
        $Row.PolicyStoreSourceType | Should -BeExactly $spec.TypeText
        $Row.PolicyStoreSource | Should -BeExactly $spec.Source
        @($Row.LocalAddress) | Should -Be @("10.0.$Number.1")
        @($Row.RemoteAddress) | Should -Be @("10.9.$Number.0/24")
        @($Row.LocalPort) | Should -Be @("338$Number")
        $Row.Program | Should -BeExactly ('C:\' + $spec.Tag + '.exe')
        $Row.Service | Should -BeExactly ('svc' + $spec.Tag)
        @($Row.InterfaceAlias) | Should -Be @(('Eth' + $spec.Tag))
        $Row.InterfaceType | Should -BeExactly ([string][RemoteFirewallTests.FwIfType]$Number)
        $Row.Authentication | Should -BeExactly ([string][RemoteFirewallTests.FwAuth]($Number % 3))
        $Row.Encryption | Should -BeExactly ([string][RemoteFirewallTests.FwEnc]($Number % 3))
    }

    # One value of a rule column or a filter column, compared by its kind: an array is an array of strings, a bool a bool, a number an int64 (a uint64 above the int64 range), text a string.
    function Assert-ColumnValue {
        param($Actual, $Expected, [string]$Kind, [string]$Column)
        if ($null -eq $Expected) {
            ($null -eq $Actual) | Should -BeTrue -Because "$Column is null"
            return
        }
        switch ($Kind) {
            'Array' {
                ($Actual -is [System.Array]) | Should -BeTrue -Because "$Column is an array"
                @($Actual).Count | Should -Be @($Expected).Count -Because "$Column has that many elements"
                for ($i = 0; $i -lt @($Expected).Count; $i++) {
                    $Actual[$i] | Should -BeOfType [string]
                    $Actual[$i] | Should -BeExactly $Expected[$i]
                }
            }
            'Bool' {
                $Actual | Should -BeOfType [bool]
                $Actual | Should -Be $Expected
            }
            'Number' {
                $Actual | Should -Not -BeOfType [string]
                # Int64 for every value that fits, UInt64 only above the Int64 range.
                $Actual | Should -BeOfType $Expected.GetType()
                $Actual | Should -Be $Expected
            }
            default {
                $Actual | Should -BeOfType [string]
                $Actual | Should -BeExactly $Expected
            }
        }
    }
}

AfterAll {
    if ($null -ne $script:Module) { Uninstall-FakeNetSecurity -Module $script:Module }
}

Describe 'Get-FirewallInventory - local name detection' {
    BeforeAll {
        Mock -ModuleName RemoteFirewall -CommandName Invoke-FirewallInventoryLocal -MockWith {
            Get-FakeWorkerObject -ComputerName $env:COMPUTERNAME
        }
        Mock -ModuleName RemoteFirewall -CommandName Invoke-FirewallInventoryRemote
    }

    It 'treats <_> as a local target' -ForEach @('.', 'localhost', $env:COMPUTERNAME, $env:COMPUTERNAME.ToLowerInvariant()) {
        $outPath = Join-Path -Path $TestDrive -ChildPath ([guid]::NewGuid().ToString('N'))
        $rows = @(Get-FirewallInventory -ComputerName $_ -OutputPath $outPath)
        $rows.Count | Should -Be 1
        $rows[0].Transport | Should -Be 'Local'
    }

    It 'never calls Invoke-FirewallInventoryRemote for local-only requests' {
        # -Scope Describe aggregates over every It in this Describe, including the -ForEach cases above. -Scope It would miss calls made in earlier It blocks and always pass regardless of what happened.
        Should -Invoke -ModuleName RemoteFirewall -CommandName Invoke-FirewallInventoryRemote -Exactly -Times 0 -Scope Describe
    }

    It 'writes a Verbose message when -UseSSL is given for a local target' {
        $outPath = Join-Path -Path $TestDrive -ChildPath ([guid]::NewGuid().ToString('N'))
        $verboseOutput = Get-FirewallInventory -ComputerName $env:COMPUTERNAME -OutputPath $outPath -UseSSL -Verbose 4>&1
        $verboseOutput | Where-Object { $_ -match 'UseSSL ignored for local targets' } | Should -Not -BeNullOrEmpty
    }
}

Describe 'Get-FirewallInventory - local alias folder sharing' {
    It 'runs the worker exactly once for multiple local aliases and points every alias row at the same OutputFolder' {
        Mock -ModuleName RemoteFirewall -CommandName Invoke-FirewallInventoryLocal -MockWith {
            Get-FakeWorkerObject -ComputerName $env:COMPUTERNAME
        }

        $outPath = Join-Path -Path $TestDrive -ChildPath ([guid]::NewGuid().ToString('N'))
        $rows = @(Get-FirewallInventory -ComputerName @('.', 'localhost', $env:COMPUTERNAME) -OutputPath $outPath)

        $rows.Count | Should -Be 3
        (@($rows | Select-Object -ExpandProperty OutputFolder -Unique)).Count | Should -Be 1
        foreach ($row in $rows) {
            $row.Transport | Should -Be 'Local'
            $row.OutputFolder | Should -Not -BeNullOrEmpty
        }

        Should -Invoke -ModuleName RemoteFirewall -CommandName Invoke-FirewallInventoryLocal -Exactly -Times 1 -Scope It
    }

    It 'collapses the message of a failed write, a line break and repeated spaces included, to one line in system.json and in the row' {
        Mock -ModuleName RemoteFirewall -CommandName Invoke-FirewallInventoryLocal -MockWith {
            Get-FakeWorkerObject -ComputerName $env:COMPUTERNAME
        }
        # Fails only the summary.json write, with a message that carries a line break, which the target or the disk can produce.
        Mock -ModuleName RemoteFirewall -CommandName Write-FirewallInventoryTextFile -MockWith {
            if ($Path -like '*summary.json') { throw "disk full`r`n  while   writing`n" }
            [System.IO.File]::WriteAllText($Path, $Content)
        }

        $outPath = Join-Path -Path $TestDrive -ChildPath ([guid]::NewGuid().ToString('N'))
        $rows = @(Get-FirewallInventory -ComputerName $env:COMPUTERNAME -OutputPath $outPath)

        $rows.Count | Should -Be 1
        $expected = "write summary.json on $($rows[0].ComputerName): disk full while writing"
        @($rows[0].Errors | Where-Object { $_ -like 'write summary.json*' }) | Should -Be @($expected)
        $system = Get-Content -LiteralPath (Join-Path -Path $rows[0].OutputFolder -ChildPath 'system.json') -Raw | ConvertFrom-Json
        @($system.Errors | Where-Object { $_ -like 'write summary.json*' }) | Should -Be @($expected)
    }
    It 'gives every local alias row identical properties, changing only ComputerName, when writing summary.json fails' {
        Mock -ModuleName RemoteFirewall -CommandName Invoke-FirewallInventoryLocal -MockWith {
            Get-FakeWorkerObject -ComputerName $env:COMPUTERNAME
        }
        # Fails only the summary.json write, so the first alias completes with a host-side error that a later alias must carry too.
        Mock -ModuleName RemoteFirewall -CommandName Write-FirewallInventoryTextFile -MockWith {
            if ($Path -like '*summary.json') { throw 'simulated disk failure' }
            [System.IO.File]::WriteAllText($Path, $Content)
        }

        $outPath = Join-Path -Path $TestDrive -ChildPath ([guid]::NewGuid().ToString('N'))
        $rows = @(Get-FirewallInventory -ComputerName @('.', 'localhost', $env:COMPUTERNAME) -OutputPath $outPath)

        $rows.Count | Should -Be 3
        $firstRow = $rows[0]
        $firstRow.ErrorCount | Should -Be 1
        $firstRow.Errors[0] | Should -Match 'write summary.json'

        $propertyNames = @($firstRow.PSObject.Properties.Name)
        for ($i = 1; $i -lt $rows.Count; $i++) {
            @($rows[$i].PSObject.Properties.Name) | Should -Be $propertyNames
            $rows[$i].ComputerName | Should -Not -Be $firstRow.ComputerName
            foreach ($propertyName in $propertyNames) {
                if ($propertyName -eq 'ComputerName') { continue }
                (@($rows[$i].$propertyName) -join '|') | Should -Be (@($firstRow.$propertyName) -join '|')
            }
        }

        Should -Invoke -ModuleName RemoteFirewall -CommandName Invoke-FirewallInventoryLocal -Exactly -Times 1 -Scope It
    }

    It 'gives every local alias row the same values as the first row, apart from ComputerName, on a run with a worker error' {
        Mock -ModuleName RemoteFirewall -CommandName Invoke-FirewallInventoryLocal -MockWith {
            Get-FakeWorkerObject -Scenario FilterFailed -ComputerName $env:COMPUTERNAME
        }

        $outPath = Join-Path -Path $TestDrive -ChildPath ([guid]::NewGuid().ToString('N'))
        $rows = @(Get-FirewallInventory -ComputerName @('.', 'localhost') -OutputPath $outPath -WarningAction SilentlyContinue)

        $rows.Count | Should -Be 2
        $rows[0].Status | Should -Be 'Partial'
        $rows[1].Status | Should -Be 'Partial'
        $rows[1].FilterFailedCount | Should -Be 4
        $rows[1].ErrorCount | Should -Be 4
        @($rows[1].Errors) | Should -Be @($rows[0].Errors)
        $rows[1].ComputerName | Should -Be 'localhost'
        $rows[0].ComputerName | Should -Be '.'
        # Two separate objects: a change to one alias row must never show in the other.
        [object]::ReferenceEquals($rows[0], $rows[1]) | Should -BeFalse
    }
}

Describe 'Resolve-FirewallInventoryUniqueFolder - folder collisions' {
    It 'creates a folder without -Force and appends _2, _3 on collision' {
        InModuleScope RemoteFirewall {
            $base = Join-Path -Path $TestDrive -ChildPath ([guid]::NewGuid().ToString('N'))

            $first = Resolve-FirewallInventoryUniqueFolder -Path $base
            $second = Resolve-FirewallInventoryUniqueFolder -Path $base
            $third = Resolve-FirewallInventoryUniqueFolder -Path $base

            $first | Should -Be $base
            $second | Should -Be ($base + '_2')
            $third | Should -Be ($base + '_3')
            (Test-Path -LiteralPath $first) | Should -BeTrue
            (Test-Path -LiteralPath $second) | Should -BeTrue
            (Test-Path -LiteralPath $third) | Should -BeTrue
        }
    }
}

Describe 'Write-FirewallInventoryCsvFile' {
    It 'skips a null row and writes the header and exactly one data row' {
        InModuleScope RemoteFirewall {
            $path = Join-Path -Path $TestDrive -ChildPath 'null-row.csv'
            # -ErrorAction Stop matches the public function, whose callers run at Stop: ConvertTo-Csv reports a null pipeline element as an error, which only ends the call when the error action is Stop.
            Write-FirewallInventoryCsvFile -Row @([pscustomobject]@{ A = 1; B = 'x' }, $null) -Path $path -Column @('A', 'B') -ErrorAction Stop

            $lines = @(Get-Content -LiteralPath $path)
            $lines.Count | Should -Be 2
            $lines[0] | Should -Be '"A","B"'
            $lines[1] | Should -Be '"1","x"'
        }
    }

    It 'writes a UTF-8 byte order mark before the header' {
        InModuleScope RemoteFirewall {
            $path = Join-Path -Path $TestDrive -ChildPath 'bom.csv'
            Write-FirewallInventoryCsvFile -Row @([pscustomobject]@{ A = 1 }) -Path $path -Column @('A')

            $bytes = [System.IO.File]::ReadAllBytes($path)
            $bytes[0] | Should -Be 0xEF
            $bytes[1] | Should -Be 0xBB
            $bytes[2] | Should -Be 0xBF
            # The first character after the mark is the opening quote of the header, not a second mark.
            $bytes[3] | Should -Be 0x22
        }
    }

    It 'writes a header-only file, with the mark, from -Column when there are no rows' {
        InModuleScope RemoteFirewall {
            $path = Join-Path -Path $TestDrive -ChildPath 'header-only.csv'
            Write-FirewallInventoryCsvFile -Row @() -Path $path -Column @('A', 'B', 'C')

            $lines = @(Get-Content -LiteralPath $path)
            $lines.Count | Should -Be 1
            $lines[0] | Should -Be '"A","B","C"'
            $bytes = [System.IO.File]::ReadAllBytes($path)
            $bytes[0] | Should -Be 0xEF
            $bytes[1] | Should -Be 0xBB
            $bytes[2] | Should -Be 0xBF
        }
    }

    It 'writes a header-only file when the only row is null' {
        InModuleScope RemoteFirewall {
            $path = Join-Path -Path $TestDrive -ChildPath 'null-only.csv'
            Write-FirewallInventoryCsvFile -Row @($null) -Path $path -Column @('A', 'B') -ErrorAction Stop

            $lines = @(Get-Content -LiteralPath $path)
            $lines.Count | Should -Be 1
            $lines[0] | Should -Be '"A","B"'
        }
    }

    It 'takes the header from the rows, not from -Column, when there are rows' {
        InModuleScope RemoteFirewall {
            $path = Join-Path -Path $TestDrive -ChildPath 'rows-win.csv'
            Write-FirewallInventoryCsvFile -Row @([pscustomobject]@{ X = 1 }) -Path $path -Column @('A', 'B')

            $lines = @(Get-Content -LiteralPath $path)
            $lines.Count | Should -Be 2
            $lines[0] | Should -Be '"X"'
        }
    }

    It 'collapses whitespace in a string cell to one line, and leaves a null, an empty string and an int as they were' {
        InModuleScope RemoteFirewall {
            $path = Join-Path -Path $TestDrive -ChildPath 'collapse.csv'
            $source = [pscustomobject]@{ Text = "a`r`nb  c"; Padded = '  x  '; Nothing = $null; Empty = ''; Number = 7 }
            Write-FirewallInventoryCsvFile -Row @($source) -Path $path

            $lines = @(Get-Content -LiteralPath $path)
            $lines.Count | Should -Be 2
            $lines[0] | Should -Be '"Text","Padded","Nothing","Empty","Number"'
            # A null is a bare cell and an empty string a quoted empty cell, the rule of convention section 8; the int is quoted like every cell.
            $lines[1] | Should -Be '"a b c","x",,"","7"'
            # The caller's object keeps the source form, which summary.json and the json files rely on.
            $source.Text | Should -BeExactly "a`r`nb  c"
        }
    }

    It 'writes a row that needs no change exactly as it is and leaves the caller''s objects untouched' {
        InModuleScope RemoteFirewall {
            $path = Join-Path -Path $TestDrive -ChildPath 'pass-through.csv'
            $plain = [pscustomobject]@{ Text = 'plain text'; Nothing = $null; Empty = ''; Count = 7; Flag = $true }
            $changed = [pscustomobject]@{ Text = "a`r`nb"; Nothing = $null; Empty = ''; Count = 8; Flag = $false }
            Write-FirewallInventoryCsvFile -Row @($plain, $changed) -Path $path

            $lines = [System.IO.File]::ReadAllLines($path)
            $lines.Count | Should -Be 3
            $lines[0] | Should -BeExactly '"Text","Nothing","Empty","Count","Flag"'
            # The row with nothing to change comes out as its own values: null bare, empty string quoted, the int and the bool as they are.
            $lines[1] | Should -BeExactly '"plain text",,"","7","True"'
            $lines[2] | Should -BeExactly '"a b",,"","8","False"'
            # Neither the passed-through object nor the rebuilt one is modified: property order, values and types stay as the caller made them.
            ($plain.PSObject.Properties.Name -join ',') | Should -BeExactly 'Text,Nothing,Empty,Count,Flag'
            $plain.Text | Should -BeExactly 'plain text'
            $plain.Nothing | Should -BeNull
            $plain.Empty | Should -BeExactly ''
            $plain.Count | Should -BeOfType [int]
            $plain.Flag | Should -BeOfType [bool]
            $changed.Text | Should -BeExactly "a`r`nb"
        }
    }
}

Describe 'Write-FirewallInventoryTextFile' {
    It 'writes UTF-8 without a byte order mark' {
        InModuleScope RemoteFirewall {
            $path = Join-Path -Path $TestDrive -ChildPath 'text.json'
            Write-FirewallInventoryTextFile -Path $path -Content '{"a":1}'

            $bytes = [System.IO.File]::ReadAllBytes($path)
            $bytes.Count | Should -Be 7
            $bytes[0] | Should -Be 0x7B
        }
    }

    It 'encodes a non-ASCII character as UTF-8' {
        InModuleScope RemoteFirewall {
            $path = Join-Path -Path $TestDrive -ChildPath 'utf8.json'
            # Built from a code point, so this file stays ASCII: U+00E6 is C3 A6 in UTF-8.
            Write-FirewallInventoryTextFile -Path $path -Content ([string][char]0x00E6)

            $bytes = [System.IO.File]::ReadAllBytes($path)
            $bytes.Count | Should -Be 2
            $bytes[0] | Should -Be 0xC3
            $bytes[1] | Should -Be 0xA6
        }
    }

    It 'writes an empty file for an empty string' {
        InModuleScope RemoteFirewall {
            $path = Join-Path -Path $TestDrive -ChildPath 'empty.json'
            Write-FirewallInventoryTextFile -Path $path -Content ''

            (Test-Path -LiteralPath $path) | Should -BeTrue
            [System.IO.File]::ReadAllBytes($path).Count | Should -Be 0
        }
    }
}

Describe 'Get-FirewallInventory - relative OutputPath' {
    It 'resolves a relative OutputPath against the current location, not the script root' {
        Mock -ModuleName RemoteFirewall -CommandName Invoke-FirewallInventoryLocal -MockWith {
            Get-FakeWorkerObject -ComputerName $env:COMPUTERNAME
        }

        $workDir = Join-Path -Path $TestDrive -ChildPath ([guid]::NewGuid().ToString('N'))
        New-Item -Path $workDir -ItemType Directory -Force | Out-Null

        Push-Location -Path $workDir
        try {
            $rows = @(Get-FirewallInventory -ComputerName 'localhost' -OutputPath 'relative-out')
        } finally {
            Pop-Location
        }

        $rows[0].OutputFolder | Should -Not -BeNullOrEmpty
        $expectedRoot = Join-Path -Path $workDir -ChildPath 'relative-out'
        (Test-Path -LiteralPath $expectedRoot) | Should -BeTrue
        $rows[0].OutputFolder | Should -Match ([regex]::Escape($workDir))
    }
}

Describe 'Get-FirewallInventory - local worker mocked, per-computer files and csv encoding' {
    It 'writes every csv file (results.csv, profiles.csv, rules.csv, accounts.csv) with a UTF-8 byte order mark' {
        Mock -ModuleName RemoteFirewall -CommandName Invoke-FirewallInventoryLocal -MockWith {
            Get-FakeWorkerObject -ComputerName $env:COMPUTERNAME
        }
        $outPath = Join-Path -Path $TestDrive -ChildPath ([guid]::NewGuid().ToString('N'))
        $rows = @(Get-FirewallInventory -ComputerName 'localhost' -OutputPath $outPath)
        $folder = $rows[0].OutputFolder
        $runFolder = Split-Path -Path $folder -Parent

        $csvPaths = @(
            (Join-Path -Path $runFolder -ChildPath 'results.csv'),
            (Join-Path -Path $folder -ChildPath 'profiles.csv'),
            (Join-Path -Path $folder -ChildPath 'rules.csv'),
            (Join-Path -Path $folder -ChildPath 'accounts.csv')
        )
        foreach ($csvPath in $csvPaths) {
            $bytes = [System.IO.File]::ReadAllBytes($csvPath)
            $bytes.Count | Should -BeGreaterOrEqual 3
            $bytes[0] | Should -Be 0xEF
            $bytes[1] | Should -Be 0xBB
            $bytes[2] | Should -Be 0xBF
        }
    }

    It 'writes all csv files when the last -OutputPath folder name contains brackets' {
        Mock -ModuleName RemoteFirewall -CommandName Invoke-FirewallInventoryLocal -MockWith {
            Get-FakeWorkerObject -ComputerName $env:COMPUTERNAME
        }
        $outPath = Join-Path -Path $TestDrive -ChildPath 'run[1]'
        $rows = @(Get-FirewallInventory -ComputerName 'localhost' -OutputPath $outPath)
        $folder = $rows[0].OutputFolder
        $runFolder = Split-Path -Path $folder -Parent

        (Test-Path -LiteralPath (Join-Path -Path $runFolder -ChildPath 'results.csv')) | Should -BeTrue
        (Test-Path -LiteralPath (Join-Path -Path $folder -ChildPath 'profiles.csv')) | Should -BeTrue
        (Test-Path -LiteralPath (Join-Path -Path $folder -ChildPath 'rules.csv')) | Should -BeTrue
        (Test-Path -LiteralPath (Join-Path -Path $folder -ChildPath 'accounts.csv')) | Should -BeTrue
        (Test-Path -LiteralPath (Join-Path -Path $folder -ChildPath 'rules.json')) | Should -BeTrue
    }

    It 'gives a Failed row and no folder when the local worker call throws' {
        Mock -ModuleName RemoteFirewall -CommandName Invoke-FirewallInventoryLocal -MockWith { throw 'the local worker deliberately failed' }
        $outPath = Join-Path -Path $TestDrive -ChildPath ([guid]::NewGuid().ToString('N'))
        $rows = @(Get-FirewallInventory -ComputerName 'localhost' -OutputPath $outPath -WarningAction SilentlyContinue)

        $rows.Count | Should -Be 1
        $rows[0].Status | Should -Be 'Failed'
        $rows[0].OutputFolder | Should -BeExactly ''
        $rows[0].ComputerId | Should -BeNull
        $rows[0].Error | Should -Match 'the local worker deliberately failed'
        $rows[0].RuleCount | Should -BeNullOrEmpty
    }
}

Describe 'Get-FirewallInventory - remote, Invoke-FirewallInventoryRemote mocked' {
    It 'builds rows for one successful worker result and one error record, writes files, csv, run.json, and strips remoting properties from system.json' {
        $reachedName = 'remote1'
        $unreachedName = 'remote2'
        $reportedName = 'REMOTE1'
        $goodWorker = Get-FakeWorkerObject -ComputerName $reportedName -PSComputerNameValue $reachedName
        $errorRecord = [System.Management.Automation.ErrorRecord]::new(
            [System.Exception]::new('WinRM cannot complete the operation.'),
            'RemotingError',
            [System.Management.Automation.ErrorCategory]::OperationTimeout,
            $unreachedName
        )

        Mock -ModuleName RemoteFirewall -CommandName Invoke-FirewallInventoryRemote -MockWith {
            & $OnResult $goodWorker
            [pscustomobject]@{
                Errors = @($errorRecord)
            }
        }

        $outPath = Join-Path -Path $TestDrive -ChildPath ([guid]::NewGuid().ToString('N'))
        $rows = @($reachedName, $unreachedName) | Get-FirewallInventory -OutputPath $outPath -WarningAction SilentlyContinue

        $rows.Count | Should -Be 2

        $row1 = $rows | Where-Object { $_.ComputerName -eq 'remote1' }
        $row1.Status | Should -Be 'Success'
        $row1.Transport | Should -Be 'WinRM'
        $row1.OutputFolder | Should -Not -BeNullOrEmpty
        $row1.ComputerId | Should -Be '11111111-2222-3333-4444-555555555555'
        $row1.ErrorCount | Should -Be 0
        $row1.PSObject.TypeNames[0] | Should -Be 'RemoteFirewall.Result'
        @($row1.PSObject.Properties.Name) | Should -Be $script:Fw.ResultRowProperties

        $systemJson = Get-Content -LiteralPath (Join-Path $row1.OutputFolder 'system.json') -Raw
        $systemJson | Should -Not -Match 'PSComputerName'
        $systemJson | Should -Not -Match 'RunspaceId'
        $systemJson | Should -Not -Match 'PSShowComputerName'

        $row2 = $rows | Where-Object { $_.ComputerName -eq 'remote2' }
        $row2.Status | Should -Be 'Failed'
        $row2.OutputFolder | Should -BeExactly ''
        $row2.ComputerId | Should -BeNull
        $row2.RuleCount | Should -BeNull
        $row2.Error | Should -Match 'WinRM cannot complete'
        $row2.ErrorCount | Should -Be 1

        $runFolder = @(Get-ChildItem -Path $outPath -Directory -Filter 'RemoteFirewall-*')
        $runFolder.Count | Should -Be 1
        (Test-Path -LiteralPath (Join-Path -Path $runFolder[0].FullName -ChildPath 'run.json')) | Should -BeTrue
        (Test-Path -LiteralPath (Join-Path -Path $runFolder[0].FullName -ChildPath 'results.csv')) | Should -BeTrue

        $runJson = Get-Content -LiteralPath (Join-Path -Path $runFolder[0].FullName -ChildPath 'run.json') -Raw | ConvertFrom-Json
        $runJson.RequestedComputers.Count | Should -Be 2
        $runJson.Results.Count | Should -Be 2
        @($runJson.PSObject.Properties.Name) | Should -Be $script:Fw.RunKeys
        $runJson.Collector | Should -Be 'RemoteFirewall'
        $manifestVersion = (Import-PowerShellDataFile -LiteralPath $script:ManifestPath).ModuleVersion
        $runJson.CollectorVersion | Should -Be $manifestVersion
        # Complete-FirewallInventoryComputer runs here inside the streaming callback, the other place the version is read.
        (Get-Content -LiteralPath (Join-Path $row1.OutputFolder 'system.json') -Raw | ConvertFrom-Json).CollectorVersion | Should -Be $manifestVersion
        $runJson.SchemaVersion | Should -Be '1.3'
        $runJson.UseSSL | Should -Be $false
        $runJson.SkipSidReference | Should -Be $false

        $csv = @(Import-Csv -LiteralPath (Join-Path -Path $runFolder[0].FullName -ChildPath 'results.csv'))
        $csv.Count | Should -Be 2
        @($csv[0].PSObject.Properties.Name) | Should -Not -Contain 'Errors'
        @($csv[0].PSObject.Properties.Name) | Should -Be $script:Fw.ResultCsvColumns
        $csvRow2 = $csv | Where-Object { $_.ComputerName -eq 'remote2' }
        $csvRow2.RuleCount | Should -Be ''
        $csvRow2.Status | Should -Be 'Failed'
        $csvRow1 = $csv | Where-Object { $_.ComputerName -eq 'remote1' }
        $csvRow1.ProfileCount | Should -Be '3'
        $csvRow1.RuleCount | Should -Be '7'
        $csvRow1.FilterFailedCount | Should -Be '0'
        $csvRow1.SddlFailedCount | Should -Be '0'
        $csvRow1.AccountCount | Should -Be '5'
    }

    It 'calls Invoke-FirewallInventoryRemote with UseSSL true and writes run.json with UseSSL true when -UseSSL is given' {
        $reachedName = 'remote8'
        $reportedName = 'REMOTE8'
        $goodWorker = Get-FakeWorkerObject -ComputerName $reportedName -PSComputerNameValue $reachedName
        Mock -ModuleName RemoteFirewall -CommandName Invoke-FirewallInventoryRemote -MockWith {
            & $OnResult $goodWorker
            [pscustomobject]@{ Errors = @() }
        }

        $outPath = Join-Path -Path $TestDrive -ChildPath ([guid]::NewGuid().ToString('N'))
        $null = @($reachedName | Get-FirewallInventory -OutputPath $outPath -UseSSL)

        Should -Invoke -ModuleName RemoteFirewall -CommandName Invoke-FirewallInventoryRemote -Exactly -Times 1 -ParameterFilter {
            $UseSSL -eq $true
        }

        $runFolder = @(Get-ChildItem -Path $outPath -Directory -Filter 'RemoteFirewall-*')[0].FullName
        $runJson = Get-Content -LiteralPath (Join-Path -Path $runFolder -ChildPath 'run.json') -Raw | ConvertFrom-Json
        $runJson.UseSSL | Should -Be $true
    }

    It 'calls Invoke-FirewallInventoryRemote with UseSSL false when -UseSSL is not given' {
        $reachedName = 'remote9'
        $reportedName = 'REMOTE9'
        $goodWorker = Get-FakeWorkerObject -ComputerName $reportedName -PSComputerNameValue $reachedName
        Mock -ModuleName RemoteFirewall -CommandName Invoke-FirewallInventoryRemote -MockWith {
            & $OnResult $goodWorker
            [pscustomobject]@{ Errors = @() }
        }

        $outPath = Join-Path -Path $TestDrive -ChildPath ([guid]::NewGuid().ToString('N'))
        $null = @($reachedName | Get-FirewallInventory -OutputPath $outPath)

        Should -Invoke -ModuleName RemoteFirewall -CommandName Invoke-FirewallInventoryRemote -Exactly -Times 1 -ParameterFilter {
            $UseSSL -eq $false
        }
    }

    It 'passes -Credential and -ThrottleLimit on to Invoke-FirewallInventoryRemote' {
        $reachedName = 'remote7'
        $goodWorker = Get-FakeWorkerObject -ComputerName $reachedName.ToUpperInvariant() -PSComputerNameValue $reachedName
        $securePassword = New-Object System.Security.SecureString
        foreach ($ch in 'x'.ToCharArray()) { $securePassword.AppendChar($ch) }
        $securePassword.MakeReadOnly()
        $credential = New-Object System.Management.Automation.PSCredential('someuser', $securePassword)
        Mock -ModuleName RemoteFirewall -CommandName Invoke-FirewallInventoryRemote -MockWith {
            & $OnResult $goodWorker
            [pscustomobject]@{ Errors = @() }
        }

        $outPath = Join-Path -Path $TestDrive -ChildPath ([guid]::NewGuid().ToString('N'))
        $null = @($reachedName | Get-FirewallInventory -OutputPath $outPath -Credential $credential -ThrottleLimit 5)

        Should -Invoke -ModuleName RemoteFirewall -CommandName Invoke-FirewallInventoryRemote -Exactly -Times 1 -ParameterFilter {
            $PesterBoundParameters.ContainsKey('Credential') -and $PesterBoundParameters['Credential'].UserName -eq 'someuser' -and $PesterBoundParameters['ThrottleLimit'] -eq 5
        }
    }

    It 'recomputes ErrorCount and backfills Error when a late remote-side error is appended to a row a worker result already built for the same host' {
        $reachedName = 'remote1'
        $goodWorker = Get-FakeWorkerObject -ComputerName $reachedName.ToUpperInvariant() -PSComputerNameValue $reachedName
        $lateMessage = 'a late remote-side warning for remote1'
        $errorRecord = [System.Management.Automation.ErrorRecord]::new(
            [System.Exception]::new($lateMessage),
            'LateRemoteError',
            [System.Management.Automation.ErrorCategory]::NotSpecified,
            $reachedName
        )

        # One worker result and one ErrorRecord for the same host, both attributable to $reachedName, so
        # the error is appended onto the row the worker result already built rather than standing in for
        # a target that was never reached.
        Mock -ModuleName RemoteFirewall -CommandName Invoke-FirewallInventoryRemote -MockWith {
            & $OnResult $goodWorker
            [pscustomobject]@{
                Errors = @($errorRecord)
            }
        }

        $outPath = Join-Path -Path $TestDrive -ChildPath ([guid]::NewGuid().ToString('N'))
        $rows = @($reachedName | Get-FirewallInventory -OutputPath $outPath -WarningAction SilentlyContinue)

        $rows.Count | Should -Be 1
        $row = $rows[0]
        $row.ErrorCount | Should -Be @($row.Errors).Count
        $row.ErrorCount | Should -Be 1
        $row.Error | Should -Be $row.Errors[0]
        $row.Error | Should -Match ([regex]::Escape($lateMessage))

        $runFolder = @(Get-ChildItem -Path $outPath -Directory -Filter 'RemoteFirewall-*')
        $runFolder.Count | Should -Be 1

        $runJson = Get-Content -LiteralPath (Join-Path -Path $runFolder[0].FullName -ChildPath 'run.json') -Raw | ConvertFrom-Json
        $jsonRow = $runJson.Results | Where-Object { $_.ComputerName -eq $reachedName }
        $jsonRow.ErrorCount | Should -Be 1
        $jsonRow.Error | Should -Match ([regex]::Escape($lateMessage))

        $csv = @(Import-Csv -LiteralPath (Join-Path -Path $runFolder[0].FullName -ChildPath 'results.csv'))
        $csvRow = $csv | Where-Object { $_.ComputerName -eq $reachedName }
        [int]$csvRow.ErrorCount | Should -Be 1
        $csvRow.Error | Should -Match ([regex]::Escape($lateMessage))
    }

    It 'collapses a late remote-side error with an embedded line break to one line before it is added to the row and before Error is recomputed' {
        $reachedName = 'remote1'
        $goodWorker = Get-FakeWorkerObject -ComputerName $reachedName.ToUpperInvariant() -PSComputerNameValue $reachedName
        $lateMessage = "Connecting to remote server remote1 failed:`r`n   the WinRM client  could not finish`r`n"
        $errorRecord = [System.Management.Automation.ErrorRecord]::new(
            [System.Exception]::new($lateMessage),
            'LateRemoteError',
            [System.Management.Automation.ErrorCategory]::NotSpecified,
            $reachedName
        )
        Mock -ModuleName RemoteFirewall -CommandName Invoke-FirewallInventoryRemote -MockWith {
            & $OnResult $goodWorker
            [pscustomobject]@{ Errors = @($errorRecord) }
        }

        $outPath = Join-Path -Path $TestDrive -ChildPath ([guid]::NewGuid().ToString('N'))
        $rows = @($reachedName | Get-FirewallInventory -OutputPath $outPath -WarningAction SilentlyContinue)

        $rows.Count | Should -Be 1
        $rows[0].ErrorCount | Should -Be 1
        $rows[0].Errors[0] | Should -BeExactly 'Connecting to remote server remote1 failed: the WinRM client could not finish'
        $rows[0].Error | Should -BeExactly $rows[0].Errors[0]
    }

    It 'drops a remote result that matches no requested name with one warning, giving exactly the requested rows and one computer folder' {
        $requestedName = 'remote1'
        $strangerName = 'stranger'
        $goodWorker = Get-FakeWorkerObject -ComputerName $requestedName.ToUpperInvariant() -PSComputerNameValue $requestedName
        $strangerWorker = Get-FakeWorkerObject -ComputerName $strangerName.ToUpperInvariant() -PSComputerNameValue $strangerName

        Mock -ModuleName RemoteFirewall -CommandName Invoke-FirewallInventoryRemote -MockWith {
            & $OnResult $goodWorker
            & $OnResult $strangerWorker
            [pscustomobject]@{ Errors = @() }
        }

        $outPath = Join-Path -Path $TestDrive -ChildPath ([guid]::NewGuid().ToString('N'))
        $output = @($requestedName | Get-FirewallInventory -OutputPath $outPath 3>&1)
        $warnings = @($output | Where-Object { $_ -is [System.Management.Automation.WarningRecord] })
        $rows = @($output | Where-Object { $_ -isnot [System.Management.Automation.WarningRecord] })

        $rows.Count | Should -Be 1
        $rows[0].ComputerName | Should -Be $requestedName
        $rows[0].Status | Should -Be 'Success'

        $warnings.Count | Should -Be 1
        $warnings[0].Message | Should -Be 'Unattributed remote result, matched no requested computer name: stranger'

        $runFolder = @(Get-ChildItem -Path $outPath -Directory -Filter 'RemoteFirewall-*')
        $runFolder.Count | Should -Be 1
        @(Get-ChildItem -LiteralPath $runFolder[0].FullName -Directory).Count | Should -Be 1
    }

    It 'warns about a remote error that matches no requested computer only as the last step, after run.json and results.csv are written' {
        $requestedName = 'remote1'
        $goodWorker = Get-FakeWorkerObject -ComputerName $requestedName.ToUpperInvariant() -PSComputerNameValue $requestedName
        $script:UnattributedErrorEvents = [System.Collections.Generic.List[string]]::new()
        $script:UnattributedErrorOutPath = Join-Path -Path $TestDrive -ChildPath ([guid]::NewGuid().ToString('N'))
        Mock -ModuleName RemoteFirewall -CommandName Invoke-FirewallInventoryRemote -MockWith {
            & $OnResult $goodWorker
            $script:UnattributedErrorEvents.Add('remote call returned')
            # An error record that names no computer, arriving after the requested computer already answered: it cannot be put on a row, so it is reported as a warning, and that warning must not come before the files exist.
            [pscustomobject]@{ Errors = @([System.Management.Automation.ErrorRecord]::new([System.InvalidOperationException]::new('orphan transport error'), 'OrphanError', [System.Management.Automation.ErrorCategory]::NotSpecified, $null)) }
        }
        # Records, at the moment the warning is written, how many of the two run files are on disk: under a caller's -WarningAction Stop the warning ends the call, so both must already be there.
        Mock -ModuleName RemoteFirewall -CommandName Write-Warning -MockWith {
            $filesOnDisk = @(Get-ChildItem -LiteralPath $script:UnattributedErrorOutPath -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -in @('run.json', 'results.csv') })
            $script:UnattributedErrorEvents.Add('warning with ' + $filesOnDisk.Count + ' run files on disk: ' + $Message)
        }

        $rows = @($requestedName | Get-FirewallInventory -OutputPath $script:UnattributedErrorOutPath)

        $rows.Count | Should -Be 1
        $rows[0].ComputerName | Should -Be $requestedName
        $rows[0].Status | Should -BeExactly 'Success'
        @($script:UnattributedErrorEvents) | Should -Be @('remote call returned', 'warning with 2 run files on disk: Unattributed remote error, matched no requested computer name: orphan transport error')
    }
    It 'emits the unattributed result warning last, after run.json and results.csv are written, so -WarningAction Stop stops a finished run and no result after the stranger is lost' {
        $requestedName = 'remote1'
        $goodWorker = Get-FakeWorkerObject -ComputerName $requestedName.ToUpperInvariant() -PSComputerNameValue $requestedName
        $strangerName = 'stranger'
        $strangerWorker = Get-FakeWorkerObject -ComputerName $strangerName.ToUpperInvariant() -PSComputerNameValue $strangerName

        # The stranger comes first: a warning raised inside the callback and turned into an exception by -WarningAction Stop would end the run before the requested computer's result was read.
        Mock -ModuleName RemoteFirewall -CommandName Invoke-FirewallInventoryRemote -MockWith {
            & $OnResult $strangerWorker
            & $OnResult $goodWorker
            [pscustomobject]@{ Errors = @() }
        }

        $outPath = Join-Path -Path $TestDrive -ChildPath ([guid]::NewGuid().ToString('N'))
        $thrown = $null
        try {
            $null = @($requestedName | Get-FirewallInventory -OutputPath $outPath -WarningAction Stop)
        } catch {
            $thrown = $_
        }

        $thrown | Should -Not -BeNullOrEmpty
        $thrown.Exception.Message | Should -Match 'Unattributed remote result, matched no requested computer name: stranger'

        # The requested computer's result was completed before the warning ended the run, and the stranger got no folder.
        $runFolder = @(Get-ChildItem -Path $outPath -Directory -Filter 'RemoteFirewall-*')
        $runFolder.Count | Should -Be 1
        $computerFolders = @(Get-ChildItem -LiteralPath $runFolder[0].FullName -Directory)
        $computerFolders.Count | Should -Be 1
        $computerFolders[0].Name | Should -BeLike 'REMOTE1_*'
        # The warning is the last statement of the function, so the run files were written before it stopped the run.
        (Test-Path -LiteralPath (Join-Path -Path $runFolder[0].FullName -ChildPath 'run.json')) | Should -BeTrue
        $csv = @(Import-Csv -LiteralPath (Join-Path -Path $runFolder[0].FullName -ChildPath 'results.csv'))
        $csv.Count | Should -Be 1
        $csv[0].ComputerName | Should -Be $requestedName
        $csv[0].Status | Should -Be 'Success'
    }

    It 'reports a computer Failed with a host: error when completing its result throws, and goes on with the other computers' {
        $failingName = 'remote2'
        $goodName = 'remote1'
        $failingWorker = Get-FakeWorkerObject -ComputerName $failingName.ToUpperInvariant() -PSComputerNameValue $failingName
        $goodWorker = Get-FakeWorkerObject -ComputerName $goodName.ToUpperInvariant() -PSComputerNameValue $goodName

        # The failing computer's result arrives first, so the second result proves the run went on after the throw.
        Mock -ModuleName RemoteFirewall -CommandName Invoke-FirewallInventoryRemote -MockWith {
            & $OnResult $failingWorker
            & $OnResult $goodWorker
            [pscustomobject]@{ Errors = @() }
        }
        Mock -ModuleName RemoteFirewall -CommandName Complete-FirewallInventoryComputer -ParameterFilter { $RequestedComputerName -eq 'remote2' } -MockWith {
            throw "the complete step deliberately failed`r`nwith a second line"
        }
        Mock -ModuleName RemoteFirewall -CommandName Complete-FirewallInventoryComputer -ParameterFilter { $RequestedComputerName -eq 'remote1' } -MockWith {
            # A plain row of the result shape: a mock body does not resolve the private row builder of the module.
            [pscustomobject]@{ ComputerName = $RequestedComputerName; Status = 'Success'; Transport = $Transport; RuleCount = 7; ErrorCount = 0; Error = ''; Errors = @() }
        }

        $outPath = Join-Path -Path $TestDrive -ChildPath ([guid]::NewGuid().ToString('N'))
        $rows = @(@($failingName, $goodName) | Get-FirewallInventory -OutputPath $outPath -WarningAction SilentlyContinue)

        $rows.Count | Should -Be 2
        $failingRow = $rows | Where-Object { $_.ComputerName -eq $failingName }
        $failingRow.Status | Should -Be 'Failed'
        $failingRow.Transport | Should -Be 'WinRM'
        $failingRow.Error | Should -BeLike 'host: the complete step deliberately failed*'
        $failingRow.ErrorCount | Should -Be 1
        $failingRow.OutputFolder | Should -BeExactly ''
        $failingRow.ComputerId | Should -BeNull

        $goodRow = $rows | Where-Object { $_.ComputerName -eq $goodName }
        $goodRow.Status | Should -Be 'Success'
        $goodRow.RuleCount | Should -Be 7
        $goodRow.ErrorCount | Should -Be 0
    }

    It 'maps an error record that names one target onto that target only, and one that names none onto every target without a result' {
        $reachedName = 'remote1'
        $silentName = 'remote2'
        $namedName = 'remote3'
        $goodWorker = Get-FakeWorkerObject -ComputerName $reachedName.ToUpperInvariant() -PSComputerNameValue $reachedName
        $namedError = [System.Management.Automation.ErrorRecord]::new(
            [System.Exception]::new('Connecting to remote3 failed.'),
            'NamedError',
            [System.Management.Automation.ErrorCategory]::ConnectionError,
            $namedName
        )
        $anonymousError = [System.Management.Automation.ErrorRecord]::new(
            [System.Exception]::new('An error that names nobody.'),
            'AnonymousError',
            [System.Management.Automation.ErrorCategory]::NotSpecified,
            $null
        )

        Mock -ModuleName RemoteFirewall -CommandName Invoke-FirewallInventoryRemote -MockWith {
            & $OnResult $goodWorker
            [pscustomobject]@{ Errors = @($namedError, $anonymousError) }
        }

        $outPath = Join-Path -Path $TestDrive -ChildPath ([guid]::NewGuid().ToString('N'))
        $rows = @(@($reachedName, $silentName, $namedName) | Get-FirewallInventory -OutputPath $outPath -WarningAction SilentlyContinue)

        $rows.Count | Should -Be 3
        $reachedRow = $rows | Where-Object { $_.ComputerName -eq $reachedName }
        $silentRow = $rows | Where-Object { $_.ComputerName -eq $silentName }
        $namedRow = $rows | Where-Object { $_.ComputerName -eq $namedName }
        $reachedRow.Status | Should -Be 'Success'
        $reachedRow.ErrorCount | Should -Be 0
        $silentRow.Status | Should -Be 'Failed'
        @($silentRow.Errors) | Should -Be @('An error that names nobody.')
        $namedRow.Status | Should -Be 'Failed'
        @($namedRow.Errors) | Should -Be @('Connecting to remote3 failed.', 'An error that names nobody.')
    }

    It 'gives a Failed row that says so when no result and no error comes back for a target' {
        $silentName = 'remote4'
        Mock -ModuleName RemoteFirewall -CommandName Invoke-FirewallInventoryRemote -MockWith { [pscustomobject]@{ Errors = @() } }

        $outPath = Join-Path -Path $TestDrive -ChildPath ([guid]::NewGuid().ToString('N'))
        $rows = @($silentName | Get-FirewallInventory -OutputPath $outPath -WarningAction SilentlyContinue)

        $rows.Count | Should -Be 1
        $rows[0].Status | Should -Be 'Failed'
        $rows[0].Error | Should -Be 'no result and no error returned'
    }
}

Describe 'Get-FirewallInventoryHostComputerId - CIM only' {
    It 'returns the UUID upper case from CIM, and null with no call to Get-WmiObject when CIM throws' {
        # Get-WmiObject is not on every PowerShell 7 host; where it resolves it is mocked so a call to it would be counted.
        $wmiExists = [bool](Get-Command -Name Get-WmiObject -ErrorAction SilentlyContinue)
        if ($wmiExists) {
            Mock -ModuleName RemoteFirewall -CommandName Get-WmiObject -MockWith { [pscustomobject]@{ UUID = 'from-wmi' } }
        }

        Mock -ModuleName RemoteFirewall -CommandName Get-CimInstance -MockWith { [pscustomobject]@{ UUID = ' aaaa-bbbb ' } }
        (& (Get-Module RemoteFirewall) { Get-FirewallInventoryHostComputerId }) | Should -BeExactly 'AAAA-BBBB'

        Mock -ModuleName RemoteFirewall -CommandName Get-CimInstance -MockWith { throw 'CIM deliberately unavailable' }
        (& (Get-Module RemoteFirewall) { Get-FirewallInventoryHostComputerId }) | Should -BeNullOrEmpty
        if ($wmiExists) {
            Should -Invoke -ModuleName RemoteFirewall -CommandName Get-WmiObject -Exactly -Times 0 -Scope It
        }
    }
}

Describe 'Complete-FirewallInventoryComputer - catch-all path keeps ComputerId' {
    It 'gives a Failed row that still carries ComputerId when folder creation throws after a worker object was reached' {
        # Resolve-FirewallInventoryUniqueFolder is the one call in Complete-FirewallInventoryComputer not
        # wrapped in its own try/catch, so a throw here is what actually reaches the function's own
        # catch-all, after ComputerId has already been read from the worker object.
        Mock -ModuleName RemoteFirewall -CommandName Resolve-FirewallInventoryUniqueFolder -MockWith {
            throw 'folder creation deliberately fails for this test'
        }

        $requestedName = 'remotefail'
        $workerObject = Get-FakeWorkerObject -ComputerName $requestedName.ToUpperInvariant()
        $row = Invoke-CompleteInModule -WorkerObject $workerObject -RequestedName $requestedName

        $row.Status | Should -Be 'Failed'
        $row.ComputerId | Should -Not -BeNullOrEmpty
        $row.ComputerId | Should -Be $workerObject.ComputerId
        $row.OutputFolder | Should -BeExactly ''

        $joinedErrors = $row.Errors -join ' ; '
        $joinedErrors | Should -Match 'unexpected error processing'
    }
}

Describe 'Complete-FirewallInventoryComputer - the folder name is built from a sanitised reported name' {
    It 'keeps a reported name with path separators and dots inside the run folder, and keeps the name as the target gave it in system.json' {
        # The run folder sits two levels below a container of its own, so a name that climbed out of the run folder would land in the container, where the test can see it, and never outside TestDrive.
        $container = Join-Path -Path $TestDrive -ChildPath ([guid]::NewGuid().ToString('N'))
        $runFolder = Join-Path -Path $container -ChildPath 'inner\run'
        New-Item -Path $runFolder -ItemType Directory -Force | Out-Null

        $reportedName = '..\..\ESCAPED'
        $workerObject = Get-FakeWorkerObject -ComputerName $reportedName
        $row = Invoke-CompleteInModule -WorkerObject $workerObject -RequestedName 'remote1' -RunFolder $runFolder

        $row.Status | Should -Be 'Success'
        # The parent of the created folder is the run folder itself, not a folder above it.
        (Split-Path -Path $row.OutputFolder -Parent) | Should -BeExactly $runFolder
        # Every character outside letters, digits, underscore and hyphen, dots and backslashes included, became an underscore.
        (Split-Path -Path $row.OutputFolder -Leaf) | Should -Match ('^______ESCAPED_' + [regex]::Escape($workerObject.CurrentBuild) + '_\d{8}-\d{6}Z$')
        # Nothing was created beside the run folder or above it.
        @(Get-ChildItem -LiteralPath $container -Force | ForEach-Object { $_.Name }) | Should -Be @('inner')
        @(Get-ChildItem -LiteralPath (Join-Path -Path $container -ChildPath 'inner') -Force | ForEach-Object { $_.Name }) | Should -Be @('run')
        (Test-Path -LiteralPath (Join-Path -Path $row.OutputFolder -ChildPath 'system.json')) | Should -BeTrue

        $system = Get-Content -LiteralPath (Join-Path -Path $row.OutputFolder -ChildPath 'system.json') -Raw | ConvertFrom-Json
        $system.ComputerName | Should -BeExactly $reportedName
    }

    It 'reduces a build number with path separators and dots the same way, and leaves the host-made stamp as it is' {
        $container = Join-Path -Path $TestDrive -ChildPath ([guid]::NewGuid().ToString('N'))
        $runFolder = Join-Path -Path $container -ChildPath 'inner\run'
        New-Item -Path $runFolder -ItemType Directory -Force | Out-Null

        $reportedName = 'BUILDHOST'
        $workerObject = Get-FakeWorkerObject -ComputerName $reportedName
        # The build number is a registry string read on the target, so it is as untrusted as the name.
        $workerObject.CurrentBuild = '20348\..\x'
        $row = Invoke-CompleteInModule -WorkerObject $workerObject -RequestedName 'remote1' -RunFolder $runFolder

        $row.Status | Should -Be 'Success'
        (Split-Path -Path $row.OutputFolder -Parent) | Should -BeExactly $runFolder
        (Split-Path -Path $row.OutputFolder -Leaf) | Should -Match '^BUILDHOST_20348____x_\d{8}-\d{6}Z$'
        @(Get-ChildItem -LiteralPath $container -Force | ForEach-Object { $_.Name }) | Should -Be @('inner')
    }
}

Describe 'Complete-FirewallInventoryComputer - system.json carries every worker scalar property' {
    It 'includes every property of the hand-made worker object except the six list properties in system.json' {
        $workerObject = Get-FakeWorkerObject -ComputerName $env:COMPUTERNAME
        $row = Invoke-CompleteInModule -WorkerObject $workerObject -RequestedName $env:COMPUTERNAME -Transport 'Local'

        $systemContent = Get-Content -LiteralPath (Join-Path $row.OutputFolder 'system.json') -Raw | ConvertFrom-Json
        $systemPropertyNames = @($systemContent.PSObject.Properties.Name)

        $listProperties = @('FilterFailedItems', 'SddlFailedItems', 'Profiles', 'Settings', 'Rules', 'Accounts')
        $workerPropertyNames = @($workerObject.PSObject.Properties.Name | Where-Object { $_ -notin $listProperties })

        foreach ($name in $workerPropertyNames) {
            $systemPropertyNames | Should -Contain $name -Because "a future worker property named '$name' must not silently drop out of the fixed system.json property list"
        }
    }

    It 'includes every property the real worker returns, except the six list properties, in system.json' {
        # The scalar list is taken from a run of the real worker over fake cmdlets, so a property added to the worker and left out of the fixed system.json list is caught here even when the hand-made object was not updated.
        Install-FakeNetSecurity -Module $script:Module
        try {
            $state = Get-FakeFirewallState
            Add-FakeFirewallRule -State $state -Name 'Guard-Rule'
            Use-FakeFirewallState -Module $script:Module -State $state
            $realWorkerObject = Invoke-WorkerInModule
        } finally {
            Uninstall-FakeNetSecurity -Module $script:Module
        }
        $row = Invoke-CompleteInModule -WorkerObject $realWorkerObject -RequestedName $env:COMPUTERNAME -Transport 'Local'

        $systemContent = Get-Content -LiteralPath (Join-Path $row.OutputFolder 'system.json') -Raw | ConvertFrom-Json
        $systemPropertyNames = @($systemContent.PSObject.Properties.Name)

        $listProperties = @('FilterFailedItems', 'SddlFailedItems', 'Profiles', 'Settings', 'Rules', 'Accounts')
        foreach ($name in @($realWorkerObject.PSObject.Properties.Name | Where-Object { $_ -notin $listProperties })) {
            $systemPropertyNames | Should -Contain $name -Because "the real worker returns '$name'"
        }
    }

    It 'has the same property names, in the same order, on the hand-made worker object as on the real worker return' {
        Install-FakeNetSecurity -Module $script:Module
        try {
            $state = Get-FakeFirewallState
            Add-FakeFirewallRule -State $state -Name 'Guard-Rule'
            Use-FakeFirewallState -Module $script:Module -State $state
            $realWorkerObject = Invoke-WorkerInModule
        } finally {
            Uninstall-FakeNetSecurity -Module $script:Module
        }
        $fakeWorkerObject = Get-FakeWorkerObject

        @($realWorkerObject.PSObject.Properties.Name) | Should -Be $script:Fw.WorkerKeys
        @($fakeWorkerObject.PSObject.Properties.Name) | Should -Be @($realWorkerObject.PSObject.Properties.Name)
    }
}

Describe 'Get-FirewallInventory - PSSerializer round trip standing in for WinRM' {
    It 'produces the same row and byte-identical files from the live worker object and its PSSerializer round trip at depth <_>' -ForEach @(1, 4) {
        $depth = $_
        $name = 'roundtrip1'
        $sourceWorker = Get-FakeWorkerObject -ComputerName $name.ToUpperInvariant() -PSComputerNameValue $name
        $serialized = [System.Management.Automation.PSSerializer]::Serialize($sourceWorker, $depth)
        $deserialized = [System.Management.Automation.PSSerializer]::Deserialize($serialized)

        # One run folder for both, so the RunId in system.json is the same and every file, system.json included, can be compared byte for byte.
        $runFolder = Get-TestRunFolder
        $liveRow = Invoke-CompleteInModule -WorkerObject $sourceWorker -RequestedName $name -RunFolder $runFolder
        $deserializedRow = Invoke-CompleteInModule -WorkerObject $deserialized -RequestedName $name -RunFolder $runFolder

        $liveRow.OutputFolder | Should -Not -Be $deserializedRow.OutputFolder
        $liveRow.Status | Should -Be $deserializedRow.Status
        $liveRow.ComputerId | Should -Be $deserializedRow.ComputerId
        $liveRow.IsElevated | Should -Be $deserializedRow.IsElevated
        $liveRow.ProfileCount | Should -Be $deserializedRow.ProfileCount
        $liveRow.RuleCount | Should -Be $deserializedRow.RuleCount
        $liveRow.FilterFailedCount | Should -Be $deserializedRow.FilterFailedCount
        $liveRow.SddlFailedCount | Should -Be $deserializedRow.SddlFailedCount
        $liveRow.AccountCount | Should -Be $deserializedRow.AccountCount
        $liveRow.AccountUnresolvedCount | Should -Be $deserializedRow.AccountUnresolvedCount
        $liveRow.ErrorCount | Should -Be $deserializedRow.ErrorCount
        @($liveRow.Errors) | Should -Be @($deserializedRow.Errors)

        foreach ($fileName in @('profiles.json', 'profiles.csv', 'globalsettings.json', 'rules.json', 'rules.csv', 'accounts.json', 'accounts.csv', 'summary.json', 'system.json')) {
            $liveHash = (Get-FileHash -LiteralPath (Join-Path $liveRow.OutputFolder $fileName) -Algorithm SHA256).Hash
            $deserializedHash = (Get-FileHash -LiteralPath (Join-Path $deserializedRow.OutputFolder $fileName) -Algorithm SHA256).Hash
            $deserializedHash | Should -Be $liveHash -Because "$fileName must not depend on whether the object crossed a remoting hop"
        }
    }

    It 'round-trips the output of the real worker into the same files as the live output' {
        Install-FakeNetSecurity -Module $script:Module
        try {
            $state = Get-FakeFirewallState
            Add-FakeFirewallRule -State $state -Name 'Trip-A' -RuleSet @{ Owner = 'S-1-5-18' } -FilterSet @{ Port = @{ LocalPort = [string[]]@('80') } }
            Add-FakeFirewallRule -State $state -Name 'Trip-B' -RuleSet @{ Platform = [string[]]@() } -FilterSet @{ Address = @{ RemoteAddress = [string[]]@('LocalSubnet', '10.0.0.0/8') } }
            $state.Fail['Interface'] = 'Access is denied.'
            Use-FakeFirewallState -Module $script:Module -State $state
            $liveWorker = Invoke-WorkerInModule
        } finally {
            Uninstall-FakeNetSecurity -Module $script:Module
        }
        $deserialized = [System.Management.Automation.PSSerializer]::Deserialize([System.Management.Automation.PSSerializer]::Serialize($liveWorker, 1))

        $runFolder = Get-TestRunFolder
        $liveRow = Invoke-CompleteInModule -WorkerObject $liveWorker -RequestedName 'trip' -RunFolder $runFolder
        $deserializedRow = Invoke-CompleteInModule -WorkerObject $deserialized -RequestedName 'trip' -RunFolder $runFolder

        $liveRow.Status | Should -Be 'Partial'
        $deserializedRow.Status | Should -Be 'Partial'
        foreach ($fileName in @('profiles.json', 'profiles.csv', 'globalsettings.json', 'rules.json', 'rules.csv', 'accounts.json', 'accounts.csv', 'summary.json')) {
            $liveText = [System.IO.File]::ReadAllText((Join-Path $liveRow.OutputFolder $fileName))
            $deserializedText = [System.IO.File]::ReadAllText((Join-Path $deserializedRow.OutputFolder $fileName))
            $deserializedText | Should -BeExactly $liveText -Because "$fileName must not depend on whether the object crossed a remoting hop"
        }
    }

    It 'round-trips a one-rule one-profile worker object into json arrays with one element' {
        $name = 'roundtrip2'
        $sourceWorker = Get-FakeWorkerObject -ComputerName $name.ToUpperInvariant() -PSComputerNameValue $name
        $sourceWorker.Rules = @($sourceWorker.Rules[0])
        $sourceWorker.RuleCount = 1
        $sourceWorker.Profiles = @($sourceWorker.Profiles[0])
        $sourceWorker.ProfileCount = 1
        $sourceWorker.Accounts = @($sourceWorker.Accounts[0])
        $deserialized = [System.Management.Automation.PSSerializer]::Deserialize([System.Management.Automation.PSSerializer]::Serialize($sourceWorker, 4))

        $row = Invoke-CompleteInModule -WorkerObject $deserialized -RequestedName $name
        $folder = $row.OutputFolder

        # ConvertFrom-Json collapses a one-element json array back into a bare PSCustomObject on both engines, so only the raw text proves the file holds an array: a bare object starts with "{", an array, one element or not, with "[".
        foreach ($fileName in @('rules.json', 'profiles.json', 'accounts.json')) {
            (Get-Content -LiteralPath (Join-Path $folder $fileName) -Raw).TrimStart().StartsWith('[') | Should -BeTrue -Because "$fileName is an array"
        }
    }

    It 'round-trips a worker object with no rules, profiles or accounts into [] json files and header-only csv files' {
        $name = 'roundtrip3'
        $sourceWorker = Get-FakeWorkerObject -Scenario RulesFailed -ComputerName $name.ToUpperInvariant() -PSComputerNameValue $name
        $sourceWorker.Profiles = @()
        $sourceWorker.ProfileCount = 0
        $deserialized = [System.Management.Automation.PSSerializer]::Deserialize([System.Management.Automation.PSSerializer]::Serialize($sourceWorker, 4))

        $row = Invoke-CompleteInModule -WorkerObject $deserialized -RequestedName $name
        $folder = $row.OutputFolder

        foreach ($fileName in @('rules.json', 'profiles.json', 'accounts.json')) {
            (Get-Content -LiteralPath (Join-Path $folder $fileName) -Raw) | Should -Match '^\s*\[\s*\]\s*$'
        }
        $rulesCsvLines = @(Get-Content -LiteralPath (Join-Path $folder 'rules.csv'))
        $rulesCsvLines.Count | Should -Be 1
        $rulesCsvLines[0] | Should -Be (($script:Fw.RuleColumnNames | ForEach-Object { '"' + $_ + '"' }) -join ',')
        $profilesCsvLines = @(Get-Content -LiteralPath (Join-Path $folder 'profiles.csv'))
        $profilesCsvLines.Count | Should -Be 1
        $profilesCsvLines[0] | Should -Be (($script:Fw.ProfileColumns | ForEach-Object { '"' + $_ + '"' }) -join ',')
        $accountsCsvLines = @(Get-Content -LiteralPath (Join-Path $folder 'accounts.csv'))
        $accountsCsvLines.Count | Should -Be 1
        $accountsCsvLines[0] | Should -Be '"Token","Kind","Sid","Name","Status","ReferenceCount","Error"'
        $bytes = [System.IO.File]::ReadAllBytes((Join-Path $folder 'rules.csv'))
        $bytes[0] | Should -Be 0xEF
        $bytes[1] | Should -Be 0xBB
        $bytes[2] | Should -Be 0xBF
    }
}

Describe 'Invoke-FirewallInventoryRemote - credential forwarding and OnResult streaming' {
    It 'does not bind -Credential on Invoke-Command when none is supplied' {
        InModuleScope RemoteFirewall {
            # A -ParameterFilter sees the bound parameters as $PesterBoundParameters ($PSBoundParameters is empty there in Pester 6.1.0), so this checks whether -Credential was bound at all.
            Mock Invoke-Command -MockWith { return @() } -ParameterFilter {
                -not $PesterBoundParameters.ContainsKey('Credential')
            }
            # An unfiltered catch-all, registered after the specific mock above, so any call that does not match the filter fails loudly here instead of silently reaching the real Invoke-Command.
            Mock Invoke-Command -MockWith { throw 'real Invoke-Command must never be reached in a test' }

            $remoteNames = @('remote1')
            $null = Invoke-FirewallInventoryRemote -ComputerName $remoteNames -ThrottleLimit 4 -OnResult {}

            Should -Invoke Invoke-Command -Exactly -Times 1 -ParameterFilter {
                -not $PesterBoundParameters.ContainsKey('Credential')
            }
        }
    }

    It 'passes -Credential through to Invoke-Command when supplied' {
        InModuleScope RemoteFirewall {
            # Built without ConvertTo-SecureString -AsPlainText: a synthetic, throwaway credential used only to prove Invoke-FirewallInventoryRemote forwards -Credential, never to authenticate anything.
            $securePassword = New-Object System.Security.SecureString
            foreach ($ch in 'x'.ToCharArray()) { $securePassword.AppendChar($ch) }
            $securePassword.MakeReadOnly()
            $credential = New-Object System.Management.Automation.PSCredential('someuser', $securePassword)

            Mock Invoke-Command -MockWith { return @() } -ParameterFilter {
                $PesterBoundParameters.ContainsKey('Credential') -and $PesterBoundParameters['Credential'].UserName -eq 'someuser'
            }
            Mock Invoke-Command -MockWith { throw 'real Invoke-Command must never be reached in a test' }

            $remoteNames = @('remote1')
            $null = Invoke-FirewallInventoryRemote -ComputerName $remoteNames -Credential $credential -ThrottleLimit 4 -OnResult {}

            Should -Invoke Invoke-Command -Exactly -Times 1 -ParameterFilter {
                $PesterBoundParameters.ContainsKey('Credential') -and $PesterBoundParameters['Credential'].UserName -eq 'someuser'
            }
        }
    }

    It 'does not bind -UseSSL on Invoke-Command when it is not supplied' {
        InModuleScope RemoteFirewall {
            Mock Invoke-Command -MockWith { return @() } -ParameterFilter {
                -not $PesterBoundParameters.ContainsKey('UseSSL')
            }
            Mock Invoke-Command -MockWith { throw 'real Invoke-Command must never be reached in a test' }

            $remoteNames = @('remote1')
            $null = Invoke-FirewallInventoryRemote -ComputerName $remoteNames -ThrottleLimit 4 -OnResult {}

            Should -Invoke Invoke-Command -Exactly -Times 1 -ParameterFilter {
                -not $PesterBoundParameters.ContainsKey('UseSSL')
            }
        }
    }

    It 'passes -UseSSL through to Invoke-Command when supplied' {
        InModuleScope RemoteFirewall {
            Mock Invoke-Command -MockWith { return @() } -ParameterFilter {
                $UseSSL -eq $true
            }
            Mock Invoke-Command -MockWith { throw 'real Invoke-Command must never be reached in a test' }

            $remoteNames = @('remote1')
            $null = Invoke-FirewallInventoryRemote -ComputerName $remoteNames -ThrottleLimit 4 -OnResult {} -UseSSL

            Should -Invoke Invoke-Command -Exactly -Times 1 -ParameterFilter {
                $UseSSL -eq $true
            }
        }
    }

    It 'hands Invoke-Command the worker scriptblock, the target names and the throttle limit' {
        InModuleScope RemoteFirewall {
            Mock Invoke-Command -MockWith { return @() }

            $remoteNames = @('remoteA', 'remoteB')
            $null = Invoke-FirewallInventoryRemote -ComputerName $remoteNames -ThrottleLimit 7 -OnResult {}

            Should -Invoke Invoke-Command -Exactly -Times 1 -ParameterFilter {
                $ScriptBlock -is [scriptblock] -and $ThrottleLimit -eq 7 -and (@($ComputerName) -join ',') -eq 'remoteA,remoteB' -and $ScriptBlock.ToString().Contains('Get-NetFirewallRule')
            }
        }
    }

    It 'invokes -OnResult once per object the Invoke-Command mock emits' {
        InModuleScope RemoteFirewall {
            $emitted = @(
                [pscustomobject]@{ PSComputerName = 'remoteA' },
                [pscustomobject]@{ PSComputerName = 'remoteB' },
                [pscustomobject]@{ PSComputerName = 'remoteC' }
            )

            Mock Invoke-Command -MockWith { return $emitted }

            $script:onResultCallCount = 0
            $onResult = { $script:onResultCallCount++ }

            $remoteNames = @('remoteA', 'remoteB', 'remoteC')
            $null = Invoke-FirewallInventoryRemote -ComputerName $remoteNames -ThrottleLimit 4 -OnResult $onResult

            $script:onResultCallCount | Should -Be 3
        }
    }

    It 'passes each emitted object to -OnResult as it arrives, and returns the collected errors' {
        InModuleScope RemoteFirewall {
            $emitted = @(
                [pscustomobject]@{ PSComputerName = 'remoteA' },
                [pscustomobject]@{ PSComputerName = 'remoteB' }
            )
            Mock Invoke-Command -MockWith { return $emitted }

            $script:seenNames = [System.Collections.Generic.List[string]]::new()
            $onResult = { param($item) [void]$script:seenNames.Add([string]$item.PSComputerName) }

            $remoteNames = @('remoteA', 'remoteB')
            $result = Invoke-FirewallInventoryRemote -ComputerName $remoteNames -ThrottleLimit 4 -OnResult $onResult

            @($script:seenNames) | Should -Be @('remoteA', 'remoteB')
            @($result.Errors).Count | Should -Be 0
        }
    }
}

Describe 'Get-FirewallInventory - parameter validation' {
    It 'throws when ComputerName is empty after removing blanks and duplicates' {
        $outPath = Join-Path -Path $TestDrive -ChildPath ([guid]::NewGuid().ToString('N'))
        { Get-FirewallInventory -ComputerName @('', '   ') -OutputPath $outPath } | Should -Throw
    }

    It 'throws when OutputPath cannot be created or written' {
        $blockerFile = Join-Path -Path $TestDrive -ChildPath 'blocker.txt'
        Set-Content -LiteralPath $blockerFile -Value 'x'
        $badOutputPath = Join-Path -Path $blockerFile -ChildPath 'child'

        Mock -ModuleName RemoteFirewall -CommandName Invoke-FirewallInventoryLocal

        { Get-FirewallInventory -ComputerName 'localhost' -OutputPath $badOutputPath } | Should -Throw
    }

    It 'throws for a ThrottleLimit of <_>' -ForEach @(0, 257) {
        $outPath = Join-Path -Path $TestDrive -ChildPath ([guid]::NewGuid().ToString('N'))
        { Get-FirewallInventory -ComputerName 'localhost' -OutputPath $outPath -ThrottleLimit $_ } | Should -Throw
    }

    It 'requires -OutputPath' {
        (Get-Command -Name Get-FirewallInventory).Parameters['OutputPath'].Attributes.Where({ $_ -is [System.Management.Automation.ParameterAttribute] }).Mandatory | Should -BeTrue
    }

    It 'takes ComputerName from the pipeline by value and by property name, at position 0' {
        $attribute = (Get-Command -Name Get-FirewallInventory).Parameters['ComputerName'].Attributes.Where({ $_ -is [System.Management.Automation.ParameterAttribute] })[0]
        $attribute.Position | Should -Be 0
        $attribute.ValueFromPipeline | Should -BeTrue
        $attribute.ValueFromPipelineByPropertyName | Should -BeTrue
    }
}


Describe 'Resolve-FirewallInventoryComputerList' {
    It 'trims names, drops blanks and case-insensitive duplicates, and keeps the first-seen order and spelling' {
        $names = & $script:Module { param($list) Resolve-FirewallInventoryComputerList -ComputerName $list } @(' Alpha ', '', 'beta', 'ALPHA', '   ', 'Beta', 'gamma')

        ((@($names)) -join '|') | Should -BeExactly 'Alpha|beta|gamma'
    }

    It 'returns nothing for a list of blanks' {
        $names = & $script:Module { param($list) Resolve-FirewallInventoryComputerList -ComputerName $list } @('', '  ')

        @($names).Count | Should -Be 0
    }
}

Describe 'Initialize-FirewallInventoryRunFolder' {
    It 'creates a missing OutputPath and a RemoteFirewall run folder named with a UTC stamp under it, and leaves nothing in it' {
        $root = Join-Path -Path $TestDrive -ChildPath 'newroot\deeper'
        $runFolder = & $script:Module { param($path) Initialize-FirewallInventoryRunFolder -OutputPath $path } $root

        (Test-Path -LiteralPath $runFolder) | Should -BeTrue
        (Split-Path -Path $runFolder -Parent) | Should -Be $root
        (Split-Path -Path $runFolder -Leaf) | Should -Match '^RemoteFirewall-\d{8}-\d{6}Z(_\d+)?$'
        @(Get-ChildItem -LiteralPath $runFolder -Force).Count | Should -Be 0
    }

    It 'gives two calls in the same second two different folders' {
        $root = Join-Path -Path $TestDrive -ChildPath ([guid]::NewGuid().ToString('N'))
        $first = & $script:Module { param($path) Initialize-FirewallInventoryRunFolder -OutputPath $path } $root
        $second = & $script:Module { param($path) Initialize-FirewallInventoryRunFolder -OutputPath $path } $root

        $second | Should -Not -Be $first
        (Test-Path -LiteralPath $first) | Should -BeTrue
        (Test-Path -LiteralPath $second) | Should -BeTrue
    }

    It 'throws OutputPath is not writable when the run folder cannot be written to' {
        $missing = Join-Path -Path $TestDrive -ChildPath 'never-created\run'
        Mock -ModuleName RemoteFirewall -CommandName Resolve-FirewallInventoryUniqueFolder -MockWith { $missing }
        $root = Join-Path -Path $TestDrive -ChildPath ([guid]::NewGuid().ToString('N'))

        { & $script:Module { param($path) Initialize-FirewallInventoryRunFolder -OutputPath $path } $root } | Should -Throw -ExpectedMessage '*OutputPath is not writable*'
    }
}

Describe 'Get-FirewallInventorySafeProperty' {
    It 'returns the default for a null object and for a property the object does not have, and the value otherwise, under strict mode' {
        $script:Probe = [pscustomobject]@{ Present = 0; Flag = $false; Nothing = $null }
        $results = & $script:Module {
            param($probe)
            Set-StrictMode -Version Latest
            [pscustomobject]@{
                NullObject = Get-FirewallInventorySafeProperty -InputObject $null -Name 'Present' -Default 'fallback'
                Absent     = Get-FirewallInventorySafeProperty -InputObject $probe -Name 'Missing' -Default 'fallback'
                Zero       = Get-FirewallInventorySafeProperty -InputObject $probe -Name 'Present' -Default 'fallback'
                False      = Get-FirewallInventorySafeProperty -InputObject $probe -Name 'Flag' -Default 'fallback'
                Null       = Get-FirewallInventorySafeProperty -InputObject $probe -Name 'Nothing' -Default 'fallback'
                NoDefault  = Get-FirewallInventorySafeProperty -InputObject $probe -Name 'Missing'
            }
        } $script:Probe

        $results.NullObject | Should -BeExactly 'fallback'
        $results.Absent | Should -BeExactly 'fallback'
        $results.Zero | Should -Be 0
        $results.Zero | Should -BeOfType [int]
        $results.False | Should -BeFalse
        ($null -eq $results.Null) | Should -BeTrue -Because 'a property that is present with a null value is not absent'
        ($null -eq $results.NoDefault) | Should -BeTrue
    }
}

Describe 'Resolve-FirewallInventoryRemoteErrorName' {
    BeforeAll {
        function Get-MatchedName {
            param($ErrorRecord, [string[]]$RemoteNames)
            & $script:Module { param($record, $names) Resolve-FirewallInventoryRemoteErrorName -ErrorRecord $record -RemoteNames $names } $ErrorRecord $RemoteNames
        }
    }

    It 'matches the TargetObject to a requested name ignoring letter case' {
        $record = [pscustomobject]@{ TargetObject = 'SRV01' }
        Get-MatchedName -ErrorRecord $record -RemoteNames @('srv02', 'srv01') | Should -BeExactly 'srv01'
    }

    It 'matches the host of a uri TargetObject' {
        $record = [pscustomobject]@{ TargetObject = [uri]'http://srv03.corp.example:5985/wsman' }
        Get-MatchedName -ErrorRecord $record -RemoteNames @('srv03.corp.example', 'srv04') | Should -BeExactly 'srv03.corp.example'
    }

    It 'falls back to the PSComputerName of the origin info when the TargetObject names nobody' {
        $record = [pscustomobject]@{ TargetObject = $null; OriginInfo = [pscustomobject]@{ PSComputerName = 'srv05' } }
        Get-MatchedName -ErrorRecord $record -RemoteNames @('srv05') | Should -BeExactly 'srv05'
    }

    It 'retries once with the domain suffix of the candidate stripped' {
        $record = [pscustomobject]@{ TargetObject = 'srv06.corp.example' }
        Get-MatchedName -ErrorRecord $record -RemoteNames @('srv06') | Should -BeExactly 'srv06'
    }

    It 'returns nothing when no requested name matches' {
        $record = [pscustomobject]@{ TargetObject = 'stranger' }
        Get-MatchedName -ErrorRecord $record -RemoteNames @('srv07') | Should -BeNullOrEmpty
    }
}

Describe 'Manifest' {
    BeforeAll {
        $script:ManifestData = Test-ModuleManifest -Path $script:ManifestPath
    }

    It 'passes Test-ModuleManifest' {
        { Test-ModuleManifest -Path $script:ManifestPath -ErrorAction Stop } | Should -Not -Throw
    }

    It 'exports exactly the public function set' {
        @($script:ManifestData.ExportedFunctions.Keys) | Should -Be @('Get-FirewallInventory')
    }

    It 'declares no RequiredModules' {
        $script:ManifestData.RequiredModules.Count | Should -Be 0
    }

    It 'has Author Tom Stryhn' {
        $script:ManifestData.Author | Should -Be 'Tom Stryhn'
    }

    It 'has a matching .VERSION in every src\ps1 file and every tests file that carries a PSScriptInfo header' {
        $moduleVersion = $script:ManifestData.Version.ToString()
        $srcPath = Join-Path -Path $script:RepoRoot -ChildPath 'RemoteFirewall\src\ps1'
        $candidateFiles = @(Get-ChildItem -Path $srcPath -Filter '*.ps1') + @(Get-ChildItem -Path $PSScriptRoot -Recurse -Filter '*.ps1')

        $scriptInfoFiles = @($candidateFiles | Where-Object {
            (Get-Content -LiteralPath $_.FullName -Raw) -match '<#PSScriptInfo'
        })

        # Every src\ps1 file and every tests file (root plus TestHelpers) carries a PSScriptInfo header, so this count also catches a header silently dropped from a new file.
        $scriptInfoFiles.Count | Should -Be $candidateFiles.Count

        foreach ($file in $scriptInfoFiles) {
            $content = Get-Content -LiteralPath $file.FullName -Raw
            $content | Should -Match ([regex]::Escape(".VERSION $moduleVersion")) -Because $file.Name
        }
    }

    It 'has a different .GUID in every file that carries a PSScriptInfo header' {
        $srcPath = Join-Path -Path $script:RepoRoot -ChildPath 'RemoteFirewall\src\ps1'
        $candidateFiles = @(Get-ChildItem -Path $srcPath -Filter '*.ps1') + @(Get-ChildItem -Path $PSScriptRoot -Recurse -Filter '*.ps1')
        $guids = @($candidateFiles | ForEach-Object {
            if ((Get-Content -LiteralPath $_.FullName -Raw) -match '(?m)^\.GUID\s+([0-9a-fA-F-]{36})') { $Matches[1].ToLowerInvariant() }
        })
        $guids.Count | Should -Be $candidateFiles.Count
        @($guids | Select-Object -Unique).Count | Should -Be $guids.Count
    }

    It 'has a FileList that matches the module folder on disk in both directions' {
        # Test-ModuleManifest resolves FileList to full paths, so both sides are compared as full paths here.
        $moduleFolder = Split-Path -Path $script:ManifestPath -Parent
        $diskFiles = @(Get-ChildItem -Path $moduleFolder -File -Recurse | Select-Object -ExpandProperty FullName)
        $fileListPaths = @($script:ManifestData.FileList)

        foreach ($path in $diskFiles) {
            $fileListPaths | Should -Contain $path
        }
        foreach ($path in $fileListPaths) {
            $diskFiles | Should -Contain $path
        }
    }
}

Describe 'Worker scriptblock - identity, return shape and call shape' {
    BeforeAll {
        Install-FakeNetSecurity -Module $script:Module
        # Fixed answers for the three identity queries, so identity values can be compared exactly. The one test that needs the real host re-registers a forwarding mock.
        Mock -ModuleName RemoteFirewall -CommandName Get-CimInstance -MockWith {
            switch ($ClassName) {
                'Win32_OperatingSystem' { [pscustomobject]@{ Caption = 'Microsoft Windows Server 2022 Standard'; Version = '10.0.20348' } }
                'Win32_ComputerSystem' { [pscustomobject]@{ DNSHostName = 'fakehost'; Domain = 'corp.example'; PartOfDomain = $true; DomainRole = [uint16]3 } }
                'Win32_ComputerSystemProduct' { [pscustomobject]@{ UUID = ' 4c4c4544-0042-3910-8056-b8c04f4b4b32 ' } }
                default { throw "unexpected CIM class $ClassName" }
            }
        }
    }

    AfterAll {
        Uninstall-FakeNetSecurity -Module $script:Module
    }

    Context 'one clean run at Continue, the error preference of a remote session' {
        BeforeAll {
            $script:State = Get-FakeFirewallState
            Add-FakeFirewallRule -State $script:State -Name 'Clean-Rule'
            $script:Run = Get-WorkerResult -State $script:State -Preference 'Continue' -Full
            $script:R = $script:Run.Result
        }

        It 'returns exactly one object and writes no error record' {
            $script:Run.ResultCount | Should -Be 1
            $script:Run.ErrorRecords.Count | Should -Be 0
        }

        It 'returns the identity keys, then the module keys, in the order of DESIGN.md section 5' {
            @($script:R.PSObject.Properties.Name) | Should -Be $script:Fw.WorkerKeys
        }

        It 'reads the identity from CIM and the registry as plain values' {
            $script:R.ComputerName | Should -BeExactly $env:COMPUTERNAME
            $script:R.DnsHostName | Should -BeExactly 'fakehost'
            $script:R.Domain | Should -BeExactly 'corp.example'
            $script:R.OSCaption | Should -BeExactly 'Microsoft Windows Server 2022 Standard'
            $script:R.OSVersion | Should -BeExactly '10.0.20348'
            $script:R.PartOfDomain | Should -BeOfType [bool]
            $script:R.PartOfDomain | Should -BeTrue
            $script:R.DomainRole | Should -BeOfType [int]
            $script:R.DomainRole | Should -Be 3
            $script:R.ComputerId | Should -BeExactly '4C4C4544-0042-3910-8056-B8C04F4B4B32'
            $script:R.IsElevated | Should -BeOfType [bool]
            $script:R.CollectedBy | Should -BeExactly ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)
            $script:R.PSVersion | Should -BeExactly $PSVersionTable.PSVersion.ToString()
            $script:R.CollectedUtc | Should -Match '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$'
        }

        It 'reads CurrentBuild, UBR, EditionID, InstallationType and MachineGuid from the registry of this host' {
            $currentVersion = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
            $script:R.CurrentBuild | Should -BeExactly ([string]$currentVersion.CurrentBuild)
            $script:R.UBR | Should -BeExactly ([string]$currentVersion.UBR)
            $script:R.EditionID | Should -BeExactly ([string]$currentVersion.EditionID)
            $script:R.InstallationType | Should -BeExactly ([string]$currentVersion.InstallationType)
            $script:R.MachineGuid | Should -BeExactly ([string](Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Cryptography').MachineGuid)
        }

        It 'reports no error for a clean run, in an empty array' {
            @($script:R.Errors).Count | Should -Be 0
            ($script:R.Errors -is [System.Array]) | Should -BeTrue
        }

        It 'reports counts as integers and durations as non-negative integers' {
            foreach ($name in @('ProfileCount', 'RuleCount', 'EnabledRuleCount', 'FilterFailedCount', 'SddlFailedCount', 'PackageCount', 'AccountCount', 'AccountUnresolvedCount', 'ProfilesDurationMs', 'RulesDurationMs', 'FiltersDurationMs', 'PackagesDurationMs', 'AccountsDurationMs')) {
                $script:R.$name | Should -BeOfType [int] -Because $name
            }
            foreach ($name in @('ProfilesDurationMs', 'RulesDurationMs', 'FiltersDurationMs', 'PackagesDurationMs', 'AccountsDurationMs')) {
                $script:R.$name | Should -BeGreaterOrEqual 0 -Because $name
            }
            $script:R.FilterFailedCount | Should -Be 0
            $script:R.SddlFailedCount | Should -Be 0
            @($script:R.FilterFailedItems).Count | Should -Be 0
            @($script:R.SddlFailedItems).Count | Should -Be 0
        }

        It 'reads the profiles, the settings, the rules and seven filter classes with one call each, in that order, in the active store, every one with -ErrorAction Stop' {
            $expected = @(
                'Get-NetFirewallProfile -PolicyStore ActiveStore EA=Stop',
                'Get-NetFirewallSetting -PolicyStore ActiveStore EA=Stop',
                'Get-NetFirewallRule -PolicyStore ActiveStore -TracePolicyStore EA=Stop',
                'Get-NetFirewallAddressFilter -PolicyStore ActiveStore EA=Stop',
                'Get-NetFirewallPortFilter -PolicyStore ActiveStore EA=Stop',
                'Get-NetFirewallApplicationFilter -PolicyStore ActiveStore EA=Stop',
                'Get-NetFirewallServiceFilter -PolicyStore ActiveStore EA=Stop',
                'Get-NetFirewallInterfaceFilter -PolicyStore ActiveStore EA=Stop',
                'Get-NetFirewallInterfaceTypeFilter -PolicyStore ActiveStore EA=Stop',
                'Get-NetFirewallSecurityFilter -PolicyStore ActiveStore EA=Stop'
            )
            @($script:State.Calls) | Should -Be $expected
        }

        It 'reads the installed packages once, after the ten reads, with -AllUsers and -ErrorAction Stop, and the fake answers for a target with no packages' {
            @($script:State.AppxCalls) | Should -Be @('Get-AppxPackage -AllUsers EA=Stop')
            $script:R.PackageCount | Should -Be 0
            $script:R.PackageCount | Should -BeOfType [int]
        }
    }

    Context 'the many-rule cost rule' {
        It 'calls each filter cmdlet once however many rules there are, never once per rule' {
            $state = Get-FakeFirewallState
            foreach ($index in 1..40) { Add-FakeFirewallRule -State $state -Name ('Bulk-{0:000}' -f $index) }
            $result = Get-WorkerResult -State $state

            $result.RuleCount | Should -Be 40
            @($state.Calls).Count | Should -Be 10
            @($state.Calls | Where-Object { $_ -like 'Get-NetFirewall*Filter *' }).Count | Should -Be 7
        }
    }

    Context 'the CIM queries fail' {
        It 'reports a CIM failure as Get-CimInstance failed and identity entries, with null identity fields, and no call to Get-WmiObject' {
            # Registered with a filter that matches every call, so it wins over the mock of the Describe.
            Mock -ModuleName RemoteFirewall -CommandName Get-CimInstance -ParameterFilter { $true } -MockWith { throw 'CIM deliberately unavailable' }
            # Get-WmiObject is not on every PowerShell 7 host; where it resolves it is mocked so a call to it would be counted, and where it does not resolve a call would surface as a different Errors entry, which the exact list below also catches.
            $wmiExists = [bool](Get-Command -Name Get-WmiObject -ErrorAction SilentlyContinue)
            if ($wmiExists) {
                Mock -ModuleName RemoteFirewall -CommandName Get-WmiObject -MockWith { throw 'Get-WmiObject must not be called' }
            }

            $state = Get-FakeFirewallState
            Add-FakeFirewallRule -State $state -Name 'Cim-Rule'
            $result = Get-WorkerResult -State $state -ReadSidReference

            # In the order the worker runs its steps: OS and computer system, then computer identity, then the SID reference (the computer system read failed, so the computer is not known to be domain-joined and only MachineSid is read). The firewall reads do not use CIM through Get-CimInstance, so they add nothing.
            @($result.Errors) | Should -Be @(
                'Get-CimInstance failed: CIM deliberately unavailable',
                'identity: ComputerId: CIM deliberately unavailable',
                'identity: MachineSid: CIM deliberately unavailable'
            )
            $result.DnsHostName | Should -BeNullOrEmpty
            $result.Domain | Should -BeNullOrEmpty
            $result.OSCaption | Should -BeNullOrEmpty
            $result.OSVersion | Should -BeNullOrEmpty
            $result.ComputerId | Should -BeNullOrEmpty
            $result.PartOfDomain | Should -BeFalse
            $result.DomainRole | Should -Be -1
            # The firewall data is read all the same.
            $result.RuleCount | Should -Be 1
            $result.ProfileCount | Should -Be 3
            if ($wmiExists) {
                Should -Invoke -ModuleName RemoteFirewall -CommandName Get-WmiObject -Exactly -Times 0 -Scope It
            }
        }

        It 'reads ComputerId upper case and MachineGuid as a GUID string on the test host, from the real CIM provider' {
            Mock -ModuleName RemoteFirewall -CommandName Get-CimInstance -ParameterFilter { $true } -MockWith {
                # The filter is forwarded when it was bound (a mock body has no $PSBoundParameters, so Get-Variable tells): without it a Win32_UserAccount read through this mock would list every account.
                $filterVariable = Get-Variable -Name Filter -ErrorAction SilentlyContinue
                if ($null -ne $filterVariable -and $null -ne $filterVariable.Value) {
                    CimCmdlets\Get-CimInstance -ClassName $ClassName -Filter $filterVariable.Value -Verbose:$false
                } else {
                    CimCmdlets\Get-CimInstance -ClassName $ClassName -Verbose:$false
                }
            }
            $state = Get-FakeFirewallState
            Add-FakeFirewallRule -State $state -Name 'Cim-Rule'
            $result = Get-WorkerResult -State $state

            $result.ComputerId | Should -Not -BeNullOrEmpty
            $result.ComputerId | Should -BeExactly $result.ComputerId.ToUpperInvariant()
            $result.MachineGuid | Should -Match '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
            @($result.Errors).Count | Should -Be 0
        }
    }

    Context 'the worker script text' {
        BeforeAll {
            $script:WorkerBlock = & $script:Module { Get-FirewallInventoryWorker }
        }

        It 'is a scriptblock with the one parameter SkipSidReference, a bool false by default, that switches strict mode off as its first statement' {
            $script:WorkerBlock | Should -BeOfType [scriptblock]
            $script:WorkerBlock.Ast.ParamBlock | Should -Not -BeNullOrEmpty
            @($script:WorkerBlock.Ast.ParamBlock.Parameters).Count | Should -Be 1
            $workerParameter = $script:WorkerBlock.Ast.ParamBlock.Parameters[0]
            $workerParameter.Name.VariablePath.UserPath | Should -Be 'SkipSidReference'
            $workerParameter.StaticType | Should -Be ([bool])
            $workerParameter.DefaultValue.Extent.Text | Should -Be '$false'
            $firstStatement = $script:WorkerBlock.Ast.EndBlock.Statements[0]
            $firstStatement.Extent.Text | Should -Be 'Set-StrictMode -Off'
        }

        It 'calls no module function and uses no using: expression, so it runs on a target that has no module' {
            $definedInside = @($script:WorkerBlock.Ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true) | ForEach-Object { $_.Name })
            $commandNames = @($script:WorkerBlock.Ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.CommandAst] }, $true) | ForEach-Object { $_.GetCommandName() } | Where-Object { $_ })
            $moduleCalls = @($commandNames | Where-Object { $_ -like '*-FirewallInventory*' -and $_ -notin $definedInside })
            $moduleCalls.Count | Should -Be 0 -Because "called but not defined inside the scriptblock: $($moduleCalls -join ', ')"
            @($script:WorkerBlock.Ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.UsingExpressionAst] }, $true)).Count | Should -Be 0
            $definedInside | Should -Contain 'Add-FirewallInventoryRowContent'
            $definedInside | Should -Contain 'ConvertTo-FirewallInventoryMessage'
        }

        It 'never changes anything: it calls no Set-, New-, Remove-, Add- or Clear- cmdlet on the target' {
            $commandNames = @($script:WorkerBlock.Ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.CommandAst] }, $true) | ForEach-Object { $_.GetCommandName() } | Where-Object { $_ })
            $definedInside = @($script:WorkerBlock.Ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true) | ForEach-Object { $_.Name })
            # The two allowed exceptions, named so the test fails on any other command with a changing verb: Set-StrictMode switches a setting of the worker's own scope, and New-Object builds in-memory .NET objects; neither touches the target. Invoke-Expression is refused too.
            $allowed = @('Set-StrictMode', 'New-Object')
            $changing = @($commandNames | Where-Object { ($_ -match '^(Set|New|Remove|Add|Clear|Stop|Start|Restart|Disable|Enable|Update|Write)-' -or $_ -eq 'Invoke-Expression') -and $_ -notin $definedInside -and $_ -notin $allowed })
            $changing.Count | Should -Be 0 -Because "changing cmdlets found: $($changing -join ', ')"
        }
    }
}

Describe 'Worker scriptblock - SID reference' {
    BeforeAll {
        Install-FakeNetSecurity -Module $script:Module
        # Three local accounts of one computer account database, the built-in Administrator last, so the match cannot be a first-row accident. The prefix is what MachineSid must be.
        $script:MachineSidPrefix = 'S-1-5-21-1111111111-2222222222-3333333333'
        $script:LocalAccountRows = @(
            [pscustomobject]@{ Name = 'Guest'; SID = "$($script:MachineSidPrefix)-501" },
            [pscustomobject]@{ Name = 'Local1'; SID = "$($script:MachineSidPrefix)-1001" },
            [pscustomobject]@{ Name = 'Admin'; SID = "$($script:MachineSidPrefix)-500" }
        )
        $script:ReadRuleState = {
            $state = Get-FakeFirewallState
            Add-FakeFirewallRule -State $state -Name 'Sid-Rule'
            return $state
        }
    }

    AfterAll {
        Uninstall-FakeNetSecurity -Module $script:Module
    }

    It 'with -SkipSidReference true gives the four properties as null, no error line for them, and never queries Win32_UserAccount' {
        $rows = $script:LocalAccountRows
        # The computer is reported as domain-joined to a domain that does not exist: a skipped run must not look it up either.
        Mock -ModuleName RemoteFirewall -CommandName Get-CimInstance -MockWith {
            switch ($ClassName) {
                'Win32_UserAccount' { $rows }
                'Win32_ComputerSystem' { [pscustomobject]@{ DNSHostName = 'fakehost'; Domain = 'nosuchdomain.invalid'; PartOfDomain = $true; DomainRole = [uint16]3 } }
                default { $filterVariable = Get-Variable -Name Filter -ErrorAction SilentlyContinue; if ($null -ne $filterVariable -and $null -ne $filterVariable.Value) { CimCmdlets\Get-CimInstance -ClassName $ClassName -Filter $filterVariable.Value -Verbose:$false } else { CimCmdlets\Get-CimInstance -ClassName $ClassName -Verbose:$false } }
            }
        }
        $result = Get-WorkerResult -State (& $script:ReadRuleState)

        foreach ($name in @('MachineSid', 'DomainSid', 'ComputerAccountSid', 'DomainNetbiosName')) {
            $result.PSObject.Properties[$name] | Should -Not -BeNullOrEmpty -Because "the worker object has $name"
            $result.$name | Should -BeNullOrEmpty -Because $name
        }
        @($result.Errors | Where-Object { $_ -like 'identity: MachineSid*' -or $_ -like 'identity: DomainSid*' -or $_ -like 'identity: DomainNetbiosName*' }).Count | Should -Be 0
        @($result.Errors | Where-Object { $_ -like '*No mock for command*' -or $_ -like 'Get-CimInstance failed*' }).Count | Should -Be 0 -Because 'no read may hide behind the identity assertions: an unmocked or failed Get-CimInstance call shows as an error line'
        Should -Invoke -ModuleName RemoteFirewall -CommandName Get-CimInstance -Exactly -Times 0 -Scope It -ParameterFilter { $ClassName -eq 'Win32_UserAccount' }
    }

    It 'takes MachineSid from the RID 500 row among rows ending in -501, -1001 and -500, with the computer name as the filter' {
        $rows = $script:LocalAccountRows
        Mock -ModuleName RemoteFirewall -CommandName Get-CimInstance -MockWith {
            switch ($ClassName) {
                'Win32_UserAccount' { $rows }
                'Win32_ComputerSystem' { [pscustomobject]@{ DNSHostName = 'fakehost'; Domain = 'WORKGROUP'; PartOfDomain = $false; DomainRole = [uint16]1 } }
                default { $filterVariable = Get-Variable -Name Filter -ErrorAction SilentlyContinue; if ($null -ne $filterVariable -and $null -ne $filterVariable.Value) { CimCmdlets\Get-CimInstance -ClassName $ClassName -Filter $filterVariable.Value -Verbose:$false } else { CimCmdlets\Get-CimInstance -ClassName $ClassName -Verbose:$false } }
            }
        }
        $result = Get-WorkerResult -State (& $script:ReadRuleState) -ReadSidReference

        $result.MachineSid | Should -BeExactly $script:MachineSidPrefix
        @($result.Errors | Where-Object { $_ -like 'identity: MachineSid*' }).Count | Should -Be 0
        @($result.Errors | Where-Object { $_ -like '*No mock for command*' -or $_ -like 'Get-CimInstance failed*' }).Count | Should -Be 0 -Because 'no read may hide behind the identity assertions: an unmocked or failed Get-CimInstance call shows as an error line'
        $expectedFilter = 'Domain = "{0}"' -f $env:COMPUTERNAME
        Should -Invoke -ModuleName RemoteFirewall -CommandName Get-CimInstance -Exactly -Times 1 -Scope It -ParameterFilter { $ClassName -eq 'Win32_UserAccount' -and $Filter -ceq $expectedFilter }
    }

    It 'gives a null MachineSid and no error line when Win32_UserAccount returns nothing, as on a domain controller' {
        Mock -ModuleName RemoteFirewall -CommandName Get-CimInstance -MockWith {
            switch ($ClassName) {
                'Win32_UserAccount' { }
                'Win32_ComputerSystem' { [pscustomobject]@{ DNSHostName = 'fakehost'; Domain = 'WORKGROUP'; PartOfDomain = $false; DomainRole = [uint16]1 } }
                default { $filterVariable = Get-Variable -Name Filter -ErrorAction SilentlyContinue; if ($null -ne $filterVariable -and $null -ne $filterVariable.Value) { CimCmdlets\Get-CimInstance -ClassName $ClassName -Filter $filterVariable.Value -Verbose:$false } else { CimCmdlets\Get-CimInstance -ClassName $ClassName -Verbose:$false } }
            }
        }
        $result = Get-WorkerResult -State (& $script:ReadRuleState) -ReadSidReference

        $result.MachineSid | Should -BeNullOrEmpty
        @($result.Errors | Where-Object { $_ -like 'identity: MachineSid*' }).Count | Should -Be 0
        @($result.Errors | Where-Object { $_ -like '*No mock for command*' -or $_ -like 'Get-CimInstance failed*' }).Count | Should -Be 0 -Because 'no read may hide behind the identity assertions: an unmocked or failed Get-CimInstance call shows as an error line'
    }

    It 'gives a null MachineSid and exactly one identity: MachineSid line when Win32_UserAccount throws' {
        Mock -ModuleName RemoteFirewall -CommandName Get-CimInstance -MockWith {
            switch ($ClassName) {
                'Win32_UserAccount' { throw 'accounts deliberately unavailable' }
                'Win32_ComputerSystem' { [pscustomobject]@{ DNSHostName = 'fakehost'; Domain = 'WORKGROUP'; PartOfDomain = $false; DomainRole = [uint16]1 } }
                default { $filterVariable = Get-Variable -Name Filter -ErrorAction SilentlyContinue; if ($null -ne $filterVariable -and $null -ne $filterVariable.Value) { CimCmdlets\Get-CimInstance -ClassName $ClassName -Filter $filterVariable.Value -Verbose:$false } else { CimCmdlets\Get-CimInstance -ClassName $ClassName -Verbose:$false } }
            }
        }
        $result = Get-WorkerResult -State (& $script:ReadRuleState) -ReadSidReference

        $result.MachineSid | Should -BeNullOrEmpty
        $sidErrors = @($result.Errors | Where-Object { $_ -like 'identity: MachineSid: *' })
        $sidErrors.Count | Should -Be 1
        $sidErrors[0] | Should -Be 'identity: MachineSid: accounts deliberately unavailable'
    }

    It 'leaves the three domain values null and adds no identity: DomainSid line on a computer that is not part of a domain' {
        $rows = $script:LocalAccountRows
        Mock -ModuleName RemoteFirewall -CommandName Get-CimInstance -MockWith {
            switch ($ClassName) {
                'Win32_UserAccount' { $rows }
                'Win32_ComputerSystem' { [pscustomobject]@{ DNSHostName = 'fakehost'; Domain = 'WORKGROUP'; PartOfDomain = $false; DomainRole = [uint16]1 } }
                default { $filterVariable = Get-Variable -Name Filter -ErrorAction SilentlyContinue; if ($null -ne $filterVariable -and $null -ne $filterVariable.Value) { CimCmdlets\Get-CimInstance -ClassName $ClassName -Filter $filterVariable.Value -Verbose:$false } else { CimCmdlets\Get-CimInstance -ClassName $ClassName -Verbose:$false } }
            }
        }
        $result = Get-WorkerResult -State (& $script:ReadRuleState) -ReadSidReference

        $result.DomainSid | Should -BeNullOrEmpty
        $result.ComputerAccountSid | Should -BeNullOrEmpty
        $result.DomainNetbiosName | Should -BeNullOrEmpty
        @($result.Errors | Where-Object { $_ -like 'identity: DomainSid*' }).Count | Should -Be 0
        @($result.Errors | Where-Object { $_ -like '*No mock for command*' -or $_ -like 'Get-CimInstance failed*' }).Count | Should -Be 0 -Because 'no read may hide behind the identity assertions: an unmocked or failed Get-CimInstance call shows as an error line'
        $result.MachineSid | Should -BeExactly $script:MachineSidPrefix
    }

    It 'leaves the three domain values null with exactly one identity: DomainSid line, no DomainNetbiosName line and MachineSid still set when the domain account cannot be looked up' {
        $rows = $script:LocalAccountRows
        Mock -ModuleName RemoteFirewall -CommandName Get-CimInstance -MockWith {
            switch ($ClassName) {
                'Win32_UserAccount' { $rows }
                'Win32_ComputerSystem' { [pscustomobject]@{ DNSHostName = 'fakehost'; Domain = 'nosuchdomain.invalid'; PartOfDomain = $true; DomainRole = [uint16]3 } }
                default { $filterVariable = Get-Variable -Name Filter -ErrorAction SilentlyContinue; if ($null -ne $filterVariable -and $null -ne $filterVariable.Value) { CimCmdlets\Get-CimInstance -ClassName $ClassName -Filter $filterVariable.Value -Verbose:$false } else { CimCmdlets\Get-CimInstance -ClassName $ClassName -Verbose:$false } }
            }
        }
        $result = Get-WorkerResult -State (& $script:ReadRuleState) -ReadSidReference

        $result.DomainSid | Should -BeNullOrEmpty
        $result.ComputerAccountSid | Should -BeNullOrEmpty
        $result.DomainNetbiosName | Should -BeNullOrEmpty
        @($result.Errors | Where-Object { $_ -like 'identity: DomainSid: *' }).Count | Should -Be 1
        @($result.Errors | Where-Object { $_ -like 'identity: DomainNetbiosName*' }).Count | Should -Be 0
        $result.MachineSid | Should -BeExactly $script:MachineSidPrefix
    }

    It 'returns the four properties directly after MachineGuid, in the order MachineSid, DomainSid, ComputerAccountSid, DomainNetbiosName' {
        $result = Get-WorkerResult -State (& $script:ReadRuleState)
        $names = @($result.PSObject.Properties.Name)
        $at = [array]::IndexOf($names, 'MachineGuid')
        $at | Should -BeGreaterOrEqual 0
        @($names[($at + 1)..($at + 4)]) | Should -Be @('MachineSid', 'DomainSid', 'ComputerAccountSid', 'DomainNetbiosName')
    }

    It 'passes the value from Invoke-FirewallInventoryLocal to the worker: null MachineSid and no Win32_UserAccount query with the switch, a MachineSid and one query without' {
        $rows = $script:LocalAccountRows
        Mock -ModuleName RemoteFirewall -CommandName Get-CimInstance -MockWith {
            switch ($ClassName) {
                'Win32_UserAccount' { $rows }
                'Win32_ComputerSystem' { [pscustomobject]@{ DNSHostName = 'fakehost'; Domain = 'WORKGROUP'; PartOfDomain = $false; DomainRole = [uint16]1 } }
                default { $filterVariable = Get-Variable -Name Filter -ErrorAction SilentlyContinue; if ($null -ne $filterVariable -and $null -ne $filterVariable.Value) { CimCmdlets\Get-CimInstance -ClassName $ClassName -Filter $filterVariable.Value -Verbose:$false } else { CimCmdlets\Get-CimInstance -ClassName $ClassName -Verbose:$false } }
            }
        }
        Use-FakeFirewallState -Module $script:Module -State (& $script:ReadRuleState)

        $skipped = & $script:Module { Invoke-FirewallInventoryLocal -SkipSidReference }
        $skipped.MachineSid | Should -BeNullOrEmpty
        Should -Invoke -ModuleName RemoteFirewall -CommandName Get-CimInstance -Exactly -Times 0 -Scope It -ParameterFilter { $ClassName -eq 'Win32_UserAccount' }

        $read = & $script:Module { Invoke-FirewallInventoryLocal }
        $read.MachineSid | Should -BeExactly $script:MachineSidPrefix
        Should -Invoke -ModuleName RemoteFirewall -CommandName Get-CimInstance -Exactly -Times 1 -Scope It -ParameterFilter { $ClassName -eq 'Win32_UserAccount' }
    }

    It 'reads a MachineSid of this host from the real CIM provider, or null on a domain controller, with the domain values null on a workgroup host' {
        $result = Get-WorkerResult -State (& $script:ReadRuleState) -ReadSidReference

        if ($result.DomainRole -ge 4) {
            $result.MachineSid | Should -BeNullOrEmpty
        } else {
            $result.MachineSid | Should -Match '^S-1-5-21-\d+-\d+-\d+$'
        }
        if (-not $result.PartOfDomain) {
            $result.DomainSid | Should -BeNullOrEmpty
            $result.ComputerAccountSid | Should -BeNullOrEmpty
            $result.DomainNetbiosName | Should -BeNullOrEmpty
            @($result.Errors | Where-Object { $_ -like 'identity: *Sid*' -or $_ -like 'identity: DomainNetbiosName*' }).Count | Should -Be 0
        }
    }
}

Describe 'Invoke-FirewallInventoryRemote - the SkipSidReference argument' {
    It 'hands Invoke-Command an ArgumentList of exactly one element, the bool false, when the switch is not given' {
        InModuleScope RemoteFirewall {
            Mock Invoke-Command -MockWith { return @() }

            $null = Invoke-FirewallInventoryRemote -ComputerName @('remote1') -ThrottleLimit 4 -OnResult {}

            Should -Invoke Invoke-Command -Exactly -Times 1 -ParameterFilter {
                @($ArgumentList).Count -eq 1 -and $ArgumentList[0] -is [bool] -and $ArgumentList[0] -eq $false
            }
        }
    }

    It 'hands Invoke-Command an ArgumentList of exactly one element, the bool true, with the switch' {
        InModuleScope RemoteFirewall {
            Mock Invoke-Command -MockWith { return @() }

            $null = Invoke-FirewallInventoryRemote -ComputerName @('remote1') -ThrottleLimit 4 -OnResult {} -SkipSidReference

            Should -Invoke Invoke-Command -Exactly -Times 1 -ParameterFilter {
                @($ArgumentList).Count -eq 1 -and $ArgumentList[0] -is [bool] -and $ArgumentList[0] -eq $true
            }
        }
    }
}

Describe 'Get-FirewallInventory - SkipSidReference forwarding, run.json and system.json' {
    It 'forwards the switch to the local path in both states and records SkipSidReference right after UseSSL in run.json' -ForEach @(
        @{ Skip = $false },
        @{ Skip = $true }
    ) {
        Mock -ModuleName RemoteFirewall -CommandName Invoke-FirewallInventoryLocal -MockWith { Get-FakeWorkerObject -ComputerName $env:COMPUTERNAME }
        $outPath = Join-Path -Path $TestDrive -ChildPath ([guid]::NewGuid().ToString('N'))
        $null = @(Get-FirewallInventory -ComputerName 'localhost' -OutputPath $outPath -SkipSidReference:$Skip)

        $expected = $Skip
        Should -Invoke -ModuleName RemoteFirewall -CommandName Invoke-FirewallInventoryLocal -Exactly -Times 1 -Scope It -ParameterFilter { [bool]$SkipSidReference -eq $expected }
        $runFolder = @(Get-ChildItem -LiteralPath $outPath -Directory -Filter 'RemoteFirewall-*')[0].FullName
        $runJson = Get-Content -LiteralPath (Join-Path -Path $runFolder -ChildPath 'run.json') -Raw | ConvertFrom-Json
        $names = @($runJson.PSObject.Properties.Name)
        $names[[array]::IndexOf($names, 'UseSSL') + 1] | Should -Be 'SkipSidReference'
        $runJson.SkipSidReference | Should -Be $Skip
        $runJson.SchemaVersion | Should -Be '1.3'
    }

    It 'forwards the switch to the remote path in both states and records SkipSidReference right after UseSSL in run.json' -ForEach @(
        @{ Skip = $false },
        @{ Skip = $true }
    ) {
        $reachedName = 'remote5'
        $goodWorker = Get-FakeWorkerObject -ComputerName $reachedName.ToUpperInvariant() -PSComputerNameValue $reachedName
        Mock -ModuleName RemoteFirewall -CommandName Invoke-FirewallInventoryRemote -MockWith {
            & $OnResult $goodWorker
            [pscustomobject]@{ Errors = @() }
        }
        $outPath = Join-Path -Path $TestDrive -ChildPath ([guid]::NewGuid().ToString('N'))
        $null = @($reachedName | Get-FirewallInventory -OutputPath $outPath -SkipSidReference:$Skip)

        $expected = $Skip
        Should -Invoke -ModuleName RemoteFirewall -CommandName Invoke-FirewallInventoryRemote -Exactly -Times 1 -Scope It -ParameterFilter { [bool]$SkipSidReference -eq $expected }
        $runFolder = @(Get-ChildItem -LiteralPath $outPath -Directory -Filter 'RemoteFirewall-*')[0].FullName
        $runJson = Get-Content -LiteralPath (Join-Path -Path $runFolder -ChildPath 'run.json') -Raw | ConvertFrom-Json
        $names = @($runJson.PSObject.Properties.Name)
        $names[[array]::IndexOf($names, 'UseSSL') + 1] | Should -Be 'SkipSidReference'
        $runJson.SkipSidReference | Should -Be $Skip
        $runJson.SchemaVersion | Should -Be '1.3'
    }

    It 'writes the four keys right after MachineGuid in system.json with the values of the worker object' {
        $row = Invoke-CompleteInModule -WorkerObject (Get-FakeWorkerObject)
        $system = Get-Content -LiteralPath (Join-Path $row.OutputFolder 'system.json') -Raw | ConvertFrom-Json
        $names = @($system.PSObject.Properties.Name)
        $at = [array]::IndexOf($names, 'MachineGuid')
        @($names[($at + 1)..($at + 4)]) | Should -Be @('MachineSid', 'DomainSid', 'ComputerAccountSid', 'DomainNetbiosName')
        $system.MachineSid | Should -Be 'S-1-5-21-1111111111-2222222222-3333333333'
        $system.DomainSid | Should -Be 'S-1-5-21-4444444444-5555555555-6666666666'
        $system.ComputerAccountSid | Should -Be 'S-1-5-21-4444444444-5555555555-6666666666-1104'
        $system.DomainNetbiosName | Should -Be 'CORP'
    }

    It 'writes the four keys as null in system.json for a worker object that lacks the properties, and the row is still Success' {
        $worker = Get-FakeWorkerObject
        foreach ($name in @('MachineSid', 'DomainSid', 'ComputerAccountSid', 'DomainNetbiosName')) { $worker.PSObject.Properties.Remove($name) }
        $row = Invoke-CompleteInModule -WorkerObject $worker
        $system = Get-Content -LiteralPath (Join-Path $row.OutputFolder 'system.json') -Raw | ConvertFrom-Json
        $names = @($system.PSObject.Properties.Name)
        $at = [array]::IndexOf($names, 'MachineGuid')
        @($names[($at + 1)..($at + 4)]) | Should -Be @('MachineSid', 'DomainSid', 'ComputerAccountSid', 'DomainNetbiosName')
        foreach ($name in @('MachineSid', 'DomainSid', 'ComputerAccountSid', 'DomainNetbiosName')) {
            $system.$name | Should -BeNullOrEmpty -Because $name
        }
        $row.Status | Should -Be 'Success'
    }
}

Describe 'Worker scriptblock - a rule with every filter present' {
    BeforeAll {
        Install-FakeNetSecurity -Module $script:Module
        Mock -ModuleName RemoteFirewall -CommandName Get-CimInstance -MockWith {
            switch ($ClassName) {
                'Win32_OperatingSystem' { [pscustomobject]@{ Caption = 'Fake OS'; Version = '10.0.1' } }
                'Win32_ComputerSystem' { [pscustomobject]@{ DNSHostName = 'fakehost'; Domain = 'corp.example'; PartOfDomain = $true; DomainRole = [uint16]3 } }
                'Win32_ComputerSystemProduct' { [pscustomobject]@{ UUID = 'AAAA' } }
                default { throw "unexpected CIM class $ClassName" }
            }
        }

        $state = Get-FakeFirewallState
        $packageSid = 'S-1-15-2-1-2-3-4-5-6-7'
        Add-FakeFirewallRule -State $state -Name 'Second-Rule'
        Add-FakeFirewallRule -State $state -Name 'Full-Rule' -RuleSet @{
            DisplayName                   = 'Full, "quoted" name'
            Description                   = "Line one`r`n  line two`ttabbed  "
            Group                         = '@FirewallAPI.dll,-30300'
            DisplayGroup                  = 'Full display group'
            Enabled                       = [RemoteFirewallTests.FwBool]::False
            Profile                       = [RemoteFirewallTests.FwProfile]'Domain, Public'
            Direction                     = [RemoteFirewallTests.FwDirection]::Outbound
            Action                        = [RemoteFirewallTests.FwAction]::Block
            EdgeTraversalPolicy           = [RemoteFirewallTests.FwEdge]::DeferToApp
            LooseSourceMapping            = $true
            LocalOnlyMapping              = $true
            Owner                         = 'S-1-5-18'
            Platform                      = [string[]]@('6.0+', '10.0+')
            PolicyStoreSource             = 'Contoso Server Policy'
            PolicyStoreSourceType         = [RemoteFirewallTests.FwSourceType]::GroupPolicy
            PrimaryStatus                 = [RemoteFirewallTests.FwStatus]::Degraded
            Status                        = 'Full status text (65540)'
            StatusCode                    = [uint32]65540
            EnforcementStatus             = [RemoteFirewallTests.FwEnforce[]]@([RemoteFirewallTests.FwEnforce]::NotApplicable, [RemoteFirewallTests.FwEnforce]::Enforced)
            PackageFamilyName             = 'Contoso.App_abc'
            PolicyAppId                   = 'app-id-1'
            RemoteDynamicKeywordAddresses = [string[]]@('{11111111-2222-3333-4444-555555555555}')
        } -FilterSet @{
            Port          = @{ Protocol = 'UDP'; LocalPort = [string[]]@('5353', '5355'); RemotePort = [string[]]@('1024-65535'); IcmpType = [string[]]@('8'); DynamicTransport = 'ProximitySharing' }
            Address       = @{ LocalAddress = [string[]]@('10.0.0.1'); RemoteAddress = [string[]]@('LocalSubnet', '10.0.0.0/8') }
            Application   = @{ Program = 'C:\Program Files\App\app.exe'; Package = $packageSid }
            Service       = @{ Service = 'winrm' }
            Interface     = @{ InterfaceAlias = [string[]]@('Ethernet', 'Wi-Fi') }
            InterfaceType = @{ InterfaceType = [RemoteFirewallTests.FwIfType]'Wired, Wireless' }
            Security      = @{
                Authentication     = [RemoteFirewallTests.FwAuth]::Required
                Encryption         = [RemoteFirewallTests.FwEnc]::Dynamic
                OverrideBlockRules = $true
                LocalUser          = 'O:LSD:(A;;CC;;;S-1-5-18)'
                RemoteUser         = 'O:LSD:(A;;CC;;;S-1-5-32-544)'
                RemoteMachine      = 'O:LSD:(A;;CC;;;S-1-1-0)'
            }
        }
        $script:Result = Get-WorkerResult -State $state
        $script:FullRule = @($script:Result.Rules | Where-Object { $_.Name -ceq 'Full-Rule' })[0]
        $script:SecondRule = @($script:Result.Rules | Where-Object { $_.Name -ceq 'Second-Rule' })[0]

        $script:ExpectedFull = @{
            Name                          = 'Full-Rule'
            InstanceID                    = 'Full-Rule'
            DisplayName                   = 'Full, "quoted" name'
            Description                   = "Line one`r`n  line two`ttabbed  "
            Group                         = '@FirewallAPI.dll,-30300'
            DisplayGroup                  = 'Full display group'
            Enabled                       = 'False'
            Profile                       = 'Domain, Public'
            Direction                     = 'Outbound'
            Action                        = 'Block'
            EdgeTraversalPolicy           = 'DeferToApp'
            LooseSourceMapping            = $true
            LocalOnlyMapping              = $true
            Owner                         = 'S-1-5-18'
            Platform                      = @('6.0+', '10.0+')
            PolicyStoreSource             = 'Contoso Server Policy'
            PolicyStoreSourceType         = 'GroupPolicy'
            PrimaryStatus                 = 'Degraded'
            Status                        = 'Full status text (65540)'
            StatusCode                    = [int64]65540
            EnforcementStatus             = @('NotApplicable', 'Enforced')
            PackageFamilyName             = 'Contoso.App_abc'
            PolicyAppId                   = 'app-id-1'
            RemoteDynamicKeywordAddresses = @('{11111111-2222-3333-4444-555555555555}')
            Protocol                      = 'UDP'
            LocalPort                     = @('5353', '5355')
            RemotePort                    = @('1024-65535')
            IcmpType                      = @('8')
            DynamicTransport              = 'ProximitySharing'
            LocalAddress                  = @('10.0.0.1')
            RemoteAddress                 = @('LocalSubnet', '10.0.0.0/8')
            Program                       = 'C:\Program Files\App\app.exe'
            Package                       = $packageSid
            Service                       = 'winrm'
            InterfaceAlias                = @('Ethernet', 'Wi-Fi')
            InterfaceType                 = 'Wired, Wireless'
            Authentication                = 'Required'
            Encryption                    = 'Dynamic'
            OverrideBlockRules            = $true
            LocalUser                     = 'O:LSD:(A;;CC;;;S-1-5-18)'
            RemoteUser                    = 'O:LSD:(A;;CC;;;S-1-5-32-544)'
            RemoteMachine                 = 'O:LSD:(A;;CC;;;S-1-1-0)'
        }
    }

    AfterAll {
        Uninstall-FakeNetSecurity -Module $script:Module
    }

    It 'counts both rules and the enabled one' {
        $script:Result.RuleCount | Should -Be 2
        $script:Result.EnabledRuleCount | Should -Be 1
        $script:Result.FilterFailedCount | Should -Be 0
        @($script:Result.Errors).Count | Should -Be 0
    }

    It 'returns a plain object per rule, with the 42 columns of DESIGN.md section 6.3 in that order and nothing else' {
        $script:FullRule | Should -BeOfType [pscustomobject]
        @($script:FullRule.PSObject.Properties.Name) | Should -Be $script:Fw.RuleColumnNames
        $script:Fw.RuleColumnNames.Count | Should -Be 42
    }

    It 'gives the exact value of the <Column> column, read from the right source' -ForEach $RuleColumnCases {
        $spec = $script:Fw.RuleColumns | Where-Object { $_.Name -eq $Column }
        Assert-ColumnValue -Actual $script:FullRule.$Column -Expected $script:ExpectedFull[$Column] -Kind $spec.Kind -Column $Column
    }

    It 'leaves the same rule with the default values of a second rule untouched by the first one' {
        $script:SecondRule.Name | Should -BeExactly 'Second-Rule'
        $script:SecondRule.Enabled | Should -BeExactly 'True'
        $script:SecondRule.LocalPort | Should -Be @('5985')
        $script:SecondRule.Program | Should -BeExactly 'Any'
        $script:SecondRule.Package | Should -BeNullOrEmpty
        $script:SecondRule.OverrideBlockRules | Should -BeFalse
    }
}

Describe 'Worker scriptblock - array columns' {
    BeforeAll {
        Install-FakeNetSecurity -Module $script:Module
        Mock -ModuleName RemoteFirewall -CommandName Get-CimInstance -MockWith {
            switch ($ClassName) {
                'Win32_OperatingSystem' { [pscustomobject]@{ Caption = 'Fake OS'; Version = '10.0.1' } }
                'Win32_ComputerSystem' { [pscustomobject]@{ DNSHostName = 'fakehost'; Domain = 'corp.example'; PartOfDomain = $true; DomainRole = [uint16]3 } }
                'Win32_ComputerSystemProduct' { [pscustomobject]@{ UUID = 'AAAA' } }
                default { throw "unexpected CIM class $ClassName" }
            }
        }

        # One rule per case, all other columns at their defaults, the one column under test set to the value the case feeds.
        $state = Get-FakeFirewallState
        foreach ($case in $script:Fw.ArrayCases) {
            $ruleSet = @{}
            $filterSet = @{}
            if ($case.Source -eq 'Rule') {
                $ruleSet[$case.Column] = $case.Value
            } else {
                $filterSet[$case.Source] = @{ $case.Column = $case.Value }
            }
            Add-FakeFirewallRule -State $state -Name ('Arr-{0:000}' -f $case.Id) -RuleSet $ruleSet -FilterSet $filterSet
        }
        $script:Result = Get-WorkerResult -State $state
        $script:RowByName = @{}
        foreach ($row in $script:Result.Rules) { $script:RowByName[$row.Name] = $row }
    }

    AfterAll {
        Uninstall-FakeNetSecurity -Module $script:Module
    }

    It 'reads every case rule and reports no error' {
        $script:Result.RuleCount | Should -Be $script:Fw.ArrayCases.Count
        @($script:Result.Errors).Count | Should -Be 0
    }

    It 'gives <Column> as an array of strings when the target hands over <Label> (case <Id>)' -ForEach $ArrayColumnCases {
        $case = $script:Fw.ArrayCases | Where-Object { $_.Id -eq $Id }
        $row = $script:RowByName[('Arr-{0:000}' -f $Id)]
        Assert-ColumnValue -Actual $row.$Column -Expected $case.Expected -Kind 'Array' -Column $Column
    }

    It 'keeps every other array column of a case rule at its default' {
        $row = $script:RowByName['Arr-003']
        @($row.PSObject.Properties.Name) | Should -Be $script:Fw.RuleColumnNames
        @($row.LocalAddress) | Should -Be @('Any')
        @($row.InterfaceAlias) | Should -Be @('Any')
    }
}

Describe 'Worker scriptblock - scalar columns' {
    BeforeAll {
        Install-FakeNetSecurity -Module $script:Module
        Mock -ModuleName RemoteFirewall -CommandName Get-CimInstance -MockWith {
            switch ($ClassName) {
                'Win32_OperatingSystem' { [pscustomobject]@{ Caption = 'Fake OS'; Version = '10.0.1' } }
                'Win32_ComputerSystem' { [pscustomobject]@{ DNSHostName = 'fakehost'; Domain = 'corp.example'; PartOfDomain = $true; DomainRole = [uint16]3 } }
                'Win32_ComputerSystemProduct' { [pscustomobject]@{ UUID = 'AAAA' } }
                default { throw "unexpected CIM class $ClassName" }
            }
        }

        $state = Get-FakeFirewallState
        foreach ($case in $script:Fw.ScalarCases) {
            $ruleSet = @{}
            $filterSet = @{}
            if ($case.Source -eq 'Rule') {
                $ruleSet[$case.Column] = $case.Value
            } else {
                $filterSet[$case.Source] = @{ $case.Column = $case.Value }
            }
            Add-FakeFirewallRule -State $state -Name ('Sca-{0:000}' -f $case.Id) -RuleSet $ruleSet -FilterSet $filterSet
        }
        $script:Result = Get-WorkerResult -State $state
        $script:RowByName = @{}
        foreach ($row in $script:Result.Rules) { $script:RowByName[$row.Name] = $row }
    }

    AfterAll {
        Uninstall-FakeNetSecurity -Module $script:Module
    }

    It 'reads every case rule and reports no error' {
        $script:Result.RuleCount | Should -Be $script:Fw.ScalarCases.Count
        @($script:Result.Errors).Count | Should -Be 0
    }

    It 'gives <Column> as its kind of value when the target hands over <Label> (case <Id>)' -ForEach $ScalarCases {
        $case = $script:Fw.ScalarCases | Where-Object { $_.Id -eq $Id }
        $row = $script:RowByName[('Sca-{0:000}' -f $Id)]
        Assert-ColumnValue -Actual $row.$Column -Expected $case.Expected -Kind $case.Kind -Column $Column
    }

    It 'counts a rule as enabled for an enumeration value True and not for False, however it is spelled' {
        # Enabled is an enumeration on the fakes; the enabled count reads its display string.
        $state = Get-FakeFirewallState
        Add-FakeFirewallRule -State $state -Name 'En-1' -RuleSet @{ Enabled = [RemoteFirewallTests.FwBool]::True }
        Add-FakeFirewallRule -State $state -Name 'En-2' -RuleSet @{ Enabled = [RemoteFirewallTests.FwBool]::False }
        Add-FakeFirewallRule -State $state -Name 'En-3' -RuleSet @{ Enabled = 'true' }
        Add-FakeFirewallRule -State $state -Name 'En-4' -RuleSet @{ Enabled = $null }
        Add-FakeFirewallRule -State $state -Name 'En-5' -RuleSet @{ Enabled = [RemoteFirewallTests.FwBool]::True }
        $result = Get-WorkerResult -State $state

        $result.RuleCount | Should -Be 5
        $result.EnabledRuleCount | Should -Be 3
    }
}

Describe 'Worker scriptblock - properties the target does not have' {
    BeforeAll {
        Install-FakeNetSecurity -Module $script:Module
        Mock -ModuleName RemoteFirewall -CommandName Get-CimInstance -MockWith {
            switch ($ClassName) {
                'Win32_OperatingSystem' { [pscustomobject]@{ Caption = 'Fake OS'; Version = '10.0.1' } }
                'Win32_ComputerSystem' { [pscustomobject]@{ DNSHostName = 'fakehost'; Domain = 'corp.example'; PartOfDomain = $true; DomainRole = [uint16]3 } }
                'Win32_ComputerSystemProduct' { [pscustomobject]@{ UUID = 'AAAA' } }
                default { throw "unexpected CIM class $ClassName" }
            }
        }

        $state = Get-FakeFirewallState
        # A rule and filters that lack properties, the way an older build returns them. DynamicTarget is the old name of DynamicTransport and is not read.
        Add-FakeFirewallRule -State $state -Name 'Abs-Rule' `
            -RuleOmit @('PackageFamilyName', 'PolicyAppId', 'Platform', 'EnforcementStatus', 'Owner', 'Description') `
            -FilterSet @{ Port = @{ DynamicTarget = 'Any' } } `
            -FilterOmit @{ Port = @('DynamicTransport', 'LocalPort', 'Protocol'); Security = @('OverrideBlockRules', 'LocalUser'); Address = @('RemoteAddress') }
        Add-FakeFirewallRule -State $state -Name 'NoFilter-Rule' -NoFilter @('Address', 'Port', 'Application', 'Service', 'Interface', 'InterfaceType', 'Security')
        Add-FakeFirewallRule -State $state -Name 'case-rule' -FilterInstanceID 'CASE-RULE' -FilterSet @{ Application = @{ Program = 'C:\case.exe' } }
        Add-FakeFirewallRule -State $state -Name 'Mismatch-Rule' -FilterInstanceID 'other-id'
        Add-FakeFirewallRule -State $state -Name 'NoId-Rule' -RuleOmit @('InstanceID')
        # A filter object whose rule does not exist, and one without an InstanceID: neither joins to anything nor breaks the run.
        # The null-id filter carries a value that would show on a rule whose InstanceID is an empty string, if it were indexed under the empty string.
        Add-FakeFirewallRule -State $state -Name 'EmptyId-Rule' -NoFilter @('Address', 'Port', 'Application', 'Service', 'Interface', 'InterfaceType', 'Security')
        @($state.Rules | Where-Object { $_.Name -eq 'EmptyId-Rule' })[0].InstanceID = ''
        $state.Filters['Port'] = @($state.Filters['Port']) + @(
            (Get-FakeFirewallFilter -Class Port -InstanceID 'orphan'),
            (Get-FakeFirewallFilter -Class Port -InstanceID 'x' -Set @{ InstanceID = $null; LocalPort = [string[]]@('999') })
        )
        $script:Result = Get-WorkerResult -State $state
        $script:RowByName = @{}
        foreach ($row in $script:Result.Rules) { $script:RowByName[$row.Name] = $row }
    }

    AfterAll {
        Uninstall-FakeNetSecurity -Module $script:Module
    }

    It 'reads the six rules with no error and no failed class' {
        $script:Result.RuleCount | Should -Be 6
        @($script:Result.Errors).Count | Should -Be 0
        $script:Result.FilterFailedCount | Should -Be 0
    }

    It 'does not join a filter object without an InstanceID to a rule whose InstanceID is empty' {
        ($null -eq $script:RowByName['EmptyId-Rule'].LocalPort) | Should -BeTrue
    }

    It 'gives a row with all 42 columns, in order, for a rule that lacks properties' {
        foreach ($row in $script:Result.Rules) {
            @($row.PSObject.Properties.Name) | Should -Be $script:Fw.RuleColumnNames -Because $row.Name
        }
    }

    It 'gives null for a scalar property the rule does not have, and never an empty string' {
        $row = $script:RowByName['Abs-Rule']
        foreach ($column in @('PackageFamilyName', 'PolicyAppId', 'Owner', 'Description')) {
            ($null -eq $row.$column) | Should -BeTrue -Because $column
        }
    }

    It 'gives null, not an empty array, for an array property the rule does not have' {
        $row = $script:RowByName['Abs-Rule']
        foreach ($column in @('Platform', 'EnforcementStatus')) {
            ($null -eq $row.$column) | Should -BeTrue -Because $column
        }
    }

    It 'gives null for a filter property the filter object does not have, arrays and booleans included' {
        $row = $script:RowByName['Abs-Rule']
        foreach ($column in @('LocalPort', 'RemoteAddress', 'Protocol', 'OverrideBlockRules', 'LocalUser')) {
            ($null -eq $row.$column) | Should -BeTrue -Because $column
        }
    }

    It 'reads DynamicTransport from the Port filter property of that name only' {
        ($null -eq $script:RowByName['Abs-Rule'].DynamicTransport) | Should -BeTrue
    }

    It 'still reads the properties beside the absent ones' {
        $row = $script:RowByName['Abs-Rule']
        @($row.RemotePort) | Should -Be @('Any')
        @($row.LocalAddress) | Should -Be @('Any')
        $row.Authentication | Should -BeExactly 'NotRequired'
        $row.RemoteUser | Should -BeExactly 'Any'
        $row.Enabled | Should -BeExactly 'True'
    }

    It 'gives null for all 18 filter columns of a rule that has no filter object of any class, and keeps its own columns' {
        $row = $script:RowByName['NoFilter-Rule']
        foreach ($spec in @($script:Fw.RuleColumns | Where-Object { $_.Source -ne 'Rule' })) {
            ($null -eq $row.($spec.Name)) | Should -BeTrue -Because $spec.Name
        }
        $row.Name | Should -BeExactly 'NoFilter-Rule'
        $row.Enabled | Should -BeExactly 'True'
        @($row.Platform) | Should -Be @('6.0+')
    }

    It 'joins a filter to its rule on InstanceID ignoring letter case' {
        $script:RowByName['case-rule'].Program | Should -BeExactly 'C:\case.exe'
    }

    It 'gives null filter columns for a rule whose filters carry another InstanceID' {
        $row = $script:RowByName['Mismatch-Rule']
        ($null -eq $row.Program) | Should -BeTrue
        ($null -eq $row.LocalPort) | Should -BeTrue
    }

    It 'gives a null InstanceID and null filter columns for a rule that has no InstanceID property, and keeps the run going' {
        $row = $script:RowByName['NoId-Rule']
        ($null -eq $row.InstanceID) | Should -BeTrue
        ($null -eq $row.LocalPort) | Should -BeTrue
        $row.Name | Should -BeExactly 'NoId-Rule'
    }
}

Describe 'Worker scriptblock - rule order' {
    BeforeAll {
        Install-FakeNetSecurity -Module $script:Module
        Mock -ModuleName RemoteFirewall -CommandName Get-CimInstance -MockWith {
            switch ($ClassName) {
                'Win32_OperatingSystem' { [pscustomobject]@{ Caption = 'Fake OS'; Version = '10.0.1' } }
                'Win32_ComputerSystem' { [pscustomobject]@{ DNSHostName = 'fakehost'; Domain = 'corp.example'; PartOfDomain = $true; DomainRole = [uint16]3 } }
                'Win32_ComputerSystemProduct' { [pscustomobject]@{ UUID = 'AAAA' } }
                default { throw "unexpected CIM class $ClassName" }
            }
        }
    }

    AfterAll {
        Uninstall-FakeNetSecurity -Module $script:Module
    }

    It 'sorts the rules by Name, ordinal ignoring case, then by InstanceID, whatever order the target returns them in' {
        $state = Get-FakeFirewallState
        # Input deliberately unsorted. Ordinal ignoring case compares upper case letters: '-' (2D) before letters, and '_' (5F) after every letter. A culture aware sort would put a-b after aa, and an ordinal sort of lower case would put A_c before aa.
        foreach ($entry in @(
                @('zeta', 'zeta'), @('Alpha', 'Alpha'), @('A_c', 'A_c'), @('beta', 'beta'), @('Dup', 'z-id'), @('aa', 'aa'), @('a-b', 'a-b'), @('dup', 'a-id')
            )) {
            Add-FakeFirewallRule -State $state -Name $entry[0] -InstanceID $entry[1]
        }
        $result = Get-WorkerResult -State $state

        ((@($result.Rules | ForEach-Object { $_.Name })) -join '|') | Should -BeExactly 'a-b|aa|Alpha|A_c|beta|dup|Dup|zeta'
        ((@($result.Rules | ForEach-Object { $_.InstanceID })) -join '|') | Should -BeExactly 'a-b|aa|Alpha|A_c|beta|a-id|z-id|zeta'
    }

    It 'gives the same order for the same rules handed over in the opposite order' {
        $state = Get-FakeFirewallState
        foreach ($name in @('m-2', 'M-1', 'k', 'Z', 'a')) { Add-FakeFirewallRule -State $state -Name $name }
        $forward = Get-WorkerResult -State $state
        $reverseState = Get-FakeFirewallState
        foreach ($name in @('a', 'Z', 'k', 'M-1', 'm-2')) { Add-FakeFirewallRule -State $reverseState -Name $name }
        $backward = Get-WorkerResult -State $reverseState

        ((@($forward.Rules | ForEach-Object { $_.Name })) -join '|') | Should -BeExactly 'a|k|M-1|m-2|Z'
        ((@($backward.Rules | ForEach-Object { $_.Name })) -join '|') | Should -BeExactly 'a|k|M-1|m-2|Z'
    }

    It 'orders rules that tie on Name and InstanceID by PolicyStoreSourceType, then PolicyStoreSource, and keeps every rule with its own filters, for the input order <Label>' -ForEach @(
        @{ Label = '1 2 3'; Numbers = @(1, 2, 3) },
        @{ Label = '1 3 2'; Numbers = @(1, 3, 2) },
        @{ Label = '2 1 3'; Numbers = @(2, 1, 3) },
        @{ Label = '2 3 1'; Numbers = @(2, 3, 1) },
        @{ Label = '3 1 2'; Numbers = @(3, 1, 2) },
        @{ Label = '3 2 1'; Numbers = @(3, 2, 1) }
    ) {
        $state = Get-FakeFirewallState
        foreach ($number in $Numbers) { Add-SharedIdRule -State $state -Number $number }
        $result = Get-WorkerResult -State $state

        # Group Policy before Local; between the two Group Policy copies, 'alpha GPO' before 'Lab GPO', ordinal ignoring case.
        @($result.Rules | ForEach-Object { $_.PolicyStoreSource }) | Should -Be @('alpha GPO', 'Lab GPO', 'PersistentStore')
        $expectedNumbers = @(3, 2, 1)
        for ($i = 0; $i -lt 3; $i++) { Assert-SharedIdRow -Row $result.Rules[$i] -Number $expectedNumbers[$i] }
    }

    It 'gives the same rule order for the Group Policy copy and the local rule handed over in either order' {
        $forwardState = Get-FakeFirewallState
        foreach ($number in @(1, 2)) { Add-SharedIdRule -State $forwardState -Number $number }
        $forward = Get-WorkerResult -State $forwardState
        $backwardState = Get-FakeFirewallState
        foreach ($number in @(2, 1)) { Add-SharedIdRule -State $backwardState -Number $number }
        $backward = Get-WorkerResult -State $backwardState

        @($forward.Rules | ForEach-Object { $_.PolicyStoreSourceType }) | Should -Be @('GroupPolicy', 'Local')
        @($backward.Rules | ForEach-Object { $_.PolicyStoreSourceType }) | Should -Be @('GroupPolicy', 'Local')
    }
}

Describe 'Worker scriptblock - rules that share an InstanceID' {
    BeforeAll {
        Install-FakeNetSecurity -Module $script:Module
        Mock -ModuleName RemoteFirewall -CommandName Get-CimInstance -MockWith {
            switch ($ClassName) {
                'Win32_OperatingSystem' { [pscustomobject]@{ Caption = 'Fake OS'; Version = '10.0.1' } }
                'Win32_ComputerSystem' { [pscustomobject]@{ DNSHostName = 'fakehost'; Domain = 'corp.example'; PartOfDomain = $true; DomainRole = [uint16]3 } }
                'Win32_ComputerSystemProduct' { [pscustomobject]@{ UUID = 'AAAA' } }
                default { throw "unexpected CIM class $ClassName" }
            }
        }
    }

    AfterAll {
        Uninstall-FakeNetSecurity -Module $script:Module
    }

    Context 'two rules with one id and two filter objects per class, in the order of the rule read (the lab case)' {
        It 'gives each rule its own values in all seven classes when the <Order> comes first' -ForEach @(
            @{ Order = 'local rule'; Numbers = @(1, 2) },
            @{ Order = 'Group Policy copy'; Numbers = @(2, 1) }
        ) {
            $state = Get-FakeFirewallState
            foreach ($number in $Numbers) { Add-SharedIdRule -State $state -Number $number }
            $result = Get-WorkerResult -State $state

            $result.RuleCount | Should -Be 2
            $result.FilterFailedCount | Should -Be 0
            @($result.Errors).Count | Should -Be 0
            $rows = @{}
            foreach ($row in $result.Rules) { $rows[[string]$row.PolicyStoreSourceType] = $row }
            Assert-SharedIdRow -Row $rows['Local'] -Number 1
            Assert-SharedIdRow -Row $rows['GroupPolicy'] -Number 2
        }

        It 'treats InstanceIDs that differ only by letter case as one id, in rules and in filter objects alike' {
            $state = Get-FakeFirewallState
            Add-SharedIdRule -State $state -Number 1 -Id 'Shared-Id' -Name 'Case-A' -FilterInstanceID 'SHARED-ID'
            Add-SharedIdRule -State $state -Number 2 -Id 'shared-id' -Name 'Case-B' -FilterInstanceID 'SHARED-ID'
            $result = Get-WorkerResult -State $state

            @($result.Errors).Count | Should -Be 0
            $rows = @{}
            foreach ($row in $result.Rules) { $rows[$row.Name] = $row }
            Assert-SharedIdRow -Row $rows['Case-A'] -Number 1
            Assert-SharedIdRow -Row $rows['Case-B'] -Number 2
        }
    }

    Context 'the sequences differ and the shared id cannot be told apart' {
        BeforeAll {
            $state = Get-FakeFirewallState
            Add-SharedIdRule -State $state -Number 1
            Add-SharedIdRule -State $state -Number 2
            Add-FakeFirewallRule -State $state -Name 'Unique-Id' -FilterSet @{ Port = @{ LocalPort = [string[]]@('7777') } }
            # The Port read hands the filter of the unique rule over first: Unique-Id, Shared-Id, Shared-Id against Shared-Id, Shared-Id, Unique-Id.
            $portFilters = @($state.Filters['Port'])
            $state.Filters['Port'] = @($portFilters[2], $portFilters[0], $portFilters[1])
            $script:R = Get-WorkerResult -State $state
            $script:Rows = @{}
            foreach ($row in $script:R.Rules) { $script:Rows[('{0}|{1}' -f $row.Name, $row.PolicyStoreSourceType)] = $row }
        }

        It 'adds one ambiguous InstanceID error for the Port class and no other error, and counts no failed class' {
            @($script:R.Errors) | Should -Be @('filter Port: ambiguous InstanceID Shared-Id')
            $script:R.FilterFailedCount | Should -Be 0
            @($script:R.FilterFailedItems).Count | Should -Be 0
            $script:R.RuleCount | Should -Be 3
        }

        It 'gives null for every Port column of both rules with that id, and never a value that might belong to the other rule' {
            foreach ($key in @('Shared-Id|Local', 'Shared-Id|GroupPolicy')) {
                foreach ($column in @('Protocol', 'LocalPort', 'RemotePort', 'IcmpType', 'DynamicTransport')) {
                    ($null -eq $script:Rows[$key].$column) | Should -BeTrue -Because "$column of $key"
                }
            }
        }

        It 'keeps the other six classes of both rules, joined by position' {
            foreach ($pair in @(@('Shared-Id|Local', 1), @('Shared-Id|GroupPolicy', 2))) {
                $row = $script:Rows[$pair[0]]
                $number = $pair[1]
                $spec = Get-SharedIdSpec -Number $number
                @($row.LocalAddress) | Should -Be @("10.0.$number.1")
                $row.Program | Should -BeExactly ('C:\' + $spec.Tag + '.exe')
                $row.Service | Should -BeExactly ('svc' + $spec.Tag)
                @($row.InterfaceAlias) | Should -Be @(('Eth' + $spec.Tag))
                $row.InterfaceType | Should -BeExactly ([string][RemoteFirewallTests.FwIfType]$number)
                $row.Authentication | Should -BeExactly ([string][RemoteFirewallTests.FwAuth]($number % 3))
            }
        }

        It 'still joins the rule whose id is unique through the dictionary' {
            @($script:Rows['Unique-Id|Local'].LocalPort) | Should -Be @('7777')
        }
    }

    Context 'the sequences differ and every id is unique' {
        It 'joins each rule to its own filter object through the dictionary, a missing filter object giving null' {
            $state = Get-FakeFirewallState
            Add-FakeFirewallRule -State $state -Name 'Uniq-A' -FilterSet @{ Port = @{ LocalPort = [string[]]@('1') }; Service = @{ Service = 'svcA' } }
            Add-FakeFirewallRule -State $state -Name 'Uniq-B' -FilterSet @{ Port = @{ LocalPort = [string[]]@('2') } } -NoFilter @('Service')
            Add-FakeFirewallRule -State $state -Name 'Uniq-C' -FilterSet @{ Port = @{ LocalPort = [string[]]@('3') }; Service = @{ Service = 'svcC' } }
            # The Port read comes back in another order than the rule read, and the Service read lacks one object: both sequences differ.
            $portFilters = @($state.Filters['Port'])
            $state.Filters['Port'] = @($portFilters[2], $portFilters[0], $portFilters[1])
            $result = Get-WorkerResult -State $state

            @($result.Errors).Count | Should -Be 0
            $result.FilterFailedCount | Should -Be 0
            $rows = @{}
            foreach ($row in $result.Rules) { $rows[$row.Name] = $row }
            @($rows['Uniq-A'].LocalPort) | Should -Be @('1')
            @($rows['Uniq-B'].LocalPort) | Should -Be @('2')
            @($rows['Uniq-C'].LocalPort) | Should -Be @('3')
            $rows['Uniq-A'].Service | Should -BeExactly 'svcA'
            ($null -eq $rows['Uniq-B'].Service) | Should -BeTrue
            $rows['Uniq-C'].Service | Should -BeExactly 'svcC'
        }
    }

    Context 'InstanceIDs that differ only by letter case, with sequences that differ' {
        It 'counts them as one shared id and adds one error for it, with the spelling of the first rule' {
            $state = Get-FakeFirewallState
            Add-FakeFirewallRule -State $state -Name 'Case-A' -InstanceID 'Case-Id' -FilterSet @{ Port = @{ LocalPort = [string[]]@('1') } }
            Add-FakeFirewallRule -State $state -Name 'Case-B' -InstanceID 'CASE-ID' -FilterSet @{ Port = @{ LocalPort = [string[]]@('2') } }
            Add-FakeFirewallRule -State $state -Name 'Case-U' -FilterSet @{ Port = @{ LocalPort = [string[]]@('3') } }
            $portFilters = @($state.Filters['Port'])
            $state.Filters['Port'] = @($portFilters[2], $portFilters[0], $portFilters[1])
            $result = Get-WorkerResult -State $state

            @($result.Errors) | Should -Be @('filter Port: ambiguous InstanceID Case-Id')
            $rows = @{}
            foreach ($row in $result.Rules) { $rows[$row.Name] = $row }
            ($null -eq $rows['Case-A'].LocalPort) | Should -BeTrue
            ($null -eq $rows['Case-B'].LocalPort) | Should -BeTrue
            @($rows['Case-U'].LocalPort) | Should -Be @('3')
        }

        It 'counts one filter class with two filter objects under one id as ambiguous for the one rule that carries it' {
            $state = Get-FakeFirewallState
            Add-FakeFirewallRule -State $state -Name 'Twin' -FilterSet @{ Port = @{ LocalPort = [string[]]@('1') } }
            $state.Filters['Port'] = @($state.Filters['Port']) + @(Get-FakeFirewallFilter -Class Port -InstanceID 'TWIN' -Set @{ LocalPort = [string[]]@('2') })
            $result = Get-WorkerResult -State $state

            @($result.Errors) | Should -Be @('filter Port: ambiguous InstanceID Twin')
            ($null -eq $result.Rules[0].LocalPort) | Should -BeTrue
            $result.Rules[0].Program | Should -BeExactly 'Any'
        }
    }

    Context 'a rule without an InstanceID' {
        It 'is never joined to a filter object, not even by position, and the rules around it still are' {
            $state = Get-FakeFirewallState
            Add-FakeFirewallRule -State $state -Name 'Pos-A' -FilterSet @{ Port = @{ LocalPort = [string[]]@('1') } }
            Add-FakeFirewallRule -State $state -Name 'Pos-NoId' -RuleOmit @('InstanceID') -FilterSet @{ Port = @{ InstanceID = $null; LocalPort = [string[]]@('2') } }
            Add-FakeFirewallRule -State $state -Name 'Pos-C' -FilterSet @{ Port = @{ LocalPort = [string[]]@('3') } }
            $result = Get-WorkerResult -State $state

            # The Port sequence is Pos-A, nothing, Pos-C on both sides, so the class is joined by position.
            @($result.Errors).Count | Should -Be 0
            $rows = @{}
            foreach ($row in $result.Rules) { $rows[$row.Name] = $row }
            @($rows['Pos-A'].LocalPort) | Should -Be @('1')
            ($null -eq $rows['Pos-NoId'].LocalPort) | Should -BeTrue
            @($rows['Pos-C'].LocalPort) | Should -Be @('3')
        }
    }
}

Describe 'Worker scriptblock - the rules read returns nothing' {
    BeforeAll {
        Install-FakeNetSecurity -Module $script:Module
        Mock -ModuleName RemoteFirewall -CommandName Get-CimInstance -MockWith {
            switch ($ClassName) {
                'Win32_OperatingSystem' { [pscustomobject]@{ Caption = 'Fake OS'; Version = '10.0.1' } }
                'Win32_ComputerSystem' { [pscustomobject]@{ DNSHostName = 'fakehost'; Domain = 'corp.example'; PartOfDomain = $true; DomainRole = [uint16]3 } }
                'Win32_ComputerSystemProduct' { [pscustomobject]@{ UUID = 'AAAA' } }
                default { throw "unexpected CIM class $ClassName" }
            }
        }
        $script:State = Get-FakeFirewallState
        $script:R = Get-WorkerResult -State $script:State
    }

    AfterAll {
        Uninstall-FakeNetSecurity -Module $script:Module
    }

    It 'reports a rule count of 0, not null, and the error rules: no rule returned' {
        $script:R.RuleCount | Should -BeOfType [int]
        $script:R.RuleCount | Should -Be 0
        $script:R.EnabledRuleCount | Should -Be 0
        @($script:R.Errors) | Should -Be @('rules: no rule returned')
        @($script:R.Rules).Count | Should -Be 0
    }

    It 'gives Status Failed through Complete-FirewallInventoryComputer, with that error as the row Error, and writes the folder' {
        $row = Invoke-CompleteInModule -WorkerObject $script:R
        $row.Status | Should -Be 'Failed'
        $row.RuleCount | Should -Be 0
        @($row.Errors) | Should -Be @('rules: no rule returned')
        $row.Error | Should -BeExactly 'rules: no rule returned'
        Test-Path -LiteralPath (Join-Path $row.OutputFolder 'rules.json') | Should -BeTrue
    }
}

Describe 'Worker scriptblock - a filter class that cannot be read' {
    BeforeAll {
        Install-FakeNetSecurity -Module $script:Module
        Mock -ModuleName RemoteFirewall -CommandName Get-CimInstance -MockWith {
            switch ($ClassName) {
                'Win32_OperatingSystem' { [pscustomobject]@{ Caption = 'Fake OS'; Version = '10.0.1' } }
                'Win32_ComputerSystem' { [pscustomobject]@{ DNSHostName = 'fakehost'; Domain = 'corp.example'; PartOfDomain = $true; DomainRole = [uint16]3 } }
                'Win32_ComputerSystemProduct' { [pscustomobject]@{ UUID = 'AAAA' } }
                default { throw "unexpected CIM class $ClassName" }
            }
        }
        function Get-FilterFailureState {
            $state = Get-FakeFirewallState
            Add-FakeFirewallRule -State $state -Name 'Fail-A' -RuleSet @{ Owner = 'S-1-5-18' } -FilterSet @{
                Address     = @{ LocalAddress = [string[]]@('10.0.0.1'); RemoteAddress = [string[]]@('LocalSubnet', '10.0.0.0/8') }
                Port        = @{ Protocol = 'UDP'; LocalPort = [string[]]@('5353'); RemotePort = [string[]]@('Any'); IcmpType = [string[]]@('Any'); DynamicTransport = 'ProximitySharing' }
                Application = @{ Program = 'C:\a.exe'; Package = 'S-1-15-2-1-2-3-4-5-6-7' }
                Service     = @{ Service = 'winrm' }
                Interface   = @{ InterfaceAlias = [string[]]@('Ethernet') }
                InterfaceType = @{ InterfaceType = [RemoteFirewallTests.FwIfType]::Wired }
                Security    = @{ Authentication = [RemoteFirewallTests.FwAuth]::Required; Encryption = [RemoteFirewallTests.FwEnc]::Required; OverrideBlockRules = $true; LocalUser = 'O:LSD:(A;;CC;;;S-1-5-32-544)'; RemoteUser = 'Any'; RemoteMachine = 'Any' }
            }
            Add-FakeFirewallRule -State $state -Name 'Fail-B'
            return $state
        }
        function Assert-SameAsBaseline {
            param($Rows, $BaselineRows, [string[]]$Column)
            for ($i = 0; $i -lt @($BaselineRows).Count; $i++) {
                foreach ($name in $Column) {
                    (ConvertTo-Json -InputObject $Rows[$i].$name -Compress) | Should -BeExactly (ConvertTo-Json -InputObject $BaselineRows[$i].$name -Compress) -Because "$name of $($Rows[$i].Name)"
                }
            }
        }
    }

    AfterAll {
        Uninstall-FakeNetSecurity -Module $script:Module
    }

    # One case per filter class: the same two rules read once with every class working (the baseline) and once with the class failing.
    It 'counts one failed class, names it, and adds exactly one error line for it, when <Class> fails' -ForEach $FilterClassCases {
        $failState = Get-FilterFailureState
        $failState.Fail[$Class] = 'Access is denied.'
        $result = Get-WorkerResult -State $failState

        $result.FilterFailedCount | Should -Be 1
        @($result.FilterFailedItems) | Should -Be @($Class)
        ($result.FilterFailedItems -is [System.Array]) | Should -BeTrue
        @($result.Errors) | Should -Be @("filter ${Class}: Access is denied.")
    }

    It 'gives null for every column of the class on every rule, when <Class> fails' -ForEach $FilterClassCases {
        $failState = Get-FilterFailureState
        $failState.Fail[$Class] = 'Access is denied.'
        $result = Get-WorkerResult -State $failState

        $result.RuleCount | Should -Be 2
        foreach ($row in $result.Rules) {
            foreach ($column in $script:Fw.FilterClassColumns[$Class]) {
                ($null -eq $row.$column) | Should -BeTrue -Because "$column of $($row.Name) must be null, not empty, when its class could not be read"
            }
        }
    }

    It 'still reads every column of the other classes and every column of the rule itself, when <Class> fails' -ForEach $FilterClassCases {
        $failState = Get-FilterFailureState
        $baseline = Get-WorkerResult -State $failState
        $failState.Fail[$Class] = 'Access is denied.'
        $result = Get-WorkerResult -State $failState

        $otherColumns = @($script:Fw.RuleColumns | Where-Object { $_.Source -ne $Class } | ForEach-Object { $_.Name })
        $otherColumns.Count | Should -Be (42 - @($script:Fw.FilterClassColumns[$Class]).Count)
        Assert-SameAsBaseline -Rows $result.Rules -BaselineRows $baseline.Rules -Column $otherColumns
    }

    It 'keeps the counts of the rules, the profiles and the SDDL, when <Class> fails' -ForEach $FilterClassCases {
        $failState = Get-FilterFailureState
        $failState.Fail[$Class] = 'Access is denied.'
        $result = Get-WorkerResult -State $failState

        $result.RuleCount | Should -Be 2
        $result.EnabledRuleCount | Should -Be 2
        $result.ProfileCount | Should -Be 3
        $result.SddlFailedCount | Should -Be 0
    }

    Context 'with the four classes an unelevated read cannot get' {
        BeforeAll {
            $state = Get-FilterFailureState
            foreach ($class in @('Interface', 'Address', 'InterfaceType', 'Port')) { $state.Fail[$class] = 'Access is denied.' }
            $script:R = Get-WorkerResult -State $state
        }

        It 'names the four classes in the order they are read' {
            $script:R.FilterFailedCount | Should -Be 4
            @($script:R.FilterFailedItems) | Should -Be @('Address', 'Port', 'Interface', 'InterfaceType')
        }

        It 'adds one error line per class, in the order they are read' {
            @($script:R.Errors) | Should -Be @(
                'filter Address: Access is denied.',
                'filter Port: Access is denied.',
                'filter Interface: Access is denied.',
                'filter InterfaceType: Access is denied.'
            )
        }

        It 'keeps the Application, Service and Security columns and nulls the other four classes on every rule' {
            $script:R.RuleCount | Should -Be 2
            foreach ($row in $script:R.Rules) {
                foreach ($class in @('Address', 'Port', 'Interface', 'InterfaceType')) {
                    foreach ($column in $script:Fw.FilterClassColumns[$class]) { ($null -eq $row.$column) | Should -BeTrue -Because $column }
                }
                $row.Program | Should -BeExactly $(if ($row.Name -eq 'Fail-A') { 'C:\a.exe' } else { 'Any' })
                $row.Service | Should -BeExactly $(if ($row.Name -eq 'Fail-A') { 'winrm' } else { 'Any' })
                $row.Authentication | Should -BeExactly $(if ($row.Name -eq 'Fail-A') { 'Required' } else { 'NotRequired' })
            }
        }
    }

    Context 'with all seven classes failing' {
        BeforeAll {
            $state = Get-FilterFailureState
            foreach ($class in $script:Fw.FilterClasses) { $state.Fail[$class] = 'Access is denied.' }
            $script:R = Get-WorkerResult -State $state
        }

        It 'counts seven and names every class in the order they are read' {
            $script:R.FilterFailedCount | Should -Be 7
            @($script:R.FilterFailedItems) | Should -Be $script:Fw.FilterClasses
            @($script:R.Errors).Count | Should -Be 7
        }

        It 'still returns both rules with every rule column and null in all 18 filter columns' {
            $script:R.RuleCount | Should -Be 2
            foreach ($row in $script:R.Rules) {
                foreach ($spec in $script:Fw.RuleColumns) {
                    if ($spec.Source -eq 'Rule') { continue }
                    ($null -eq $row.($spec.Name)) | Should -BeTrue -Because $spec.Name
                }
                $row.Enabled | Should -BeExactly 'True'
            }
            # Only the owner is left to name a principal: the package and the SDDL fields live in filters that were not read.
            @($script:R.Accounts | ForEach-Object { $_.Token }) | Should -Be @('S-1-5-18')
        }
    }

    Context 'with an error text that spans lines' {
        It 'collapses the text of a failed class to one line' {
            $state = Get-FilterFailureState
            $state.Fail['Port'] = "Access is denied.`r`n   Second   line`ttabbed"
            $result = Get-WorkerResult -State $state

            @($result.Errors) | Should -Be @('filter Port: Access is denied. Second line tabbed')
        }
    }
}

Describe 'Worker scriptblock - the rules read fails' {
    BeforeAll {
        Install-FakeNetSecurity -Module $script:Module
        Mock -ModuleName RemoteFirewall -CommandName Get-CimInstance -MockWith {
            switch ($ClassName) {
                'Win32_OperatingSystem' { [pscustomobject]@{ Caption = 'Fake OS'; Version = '10.0.1' } }
                'Win32_ComputerSystem' { [pscustomobject]@{ DNSHostName = 'fakehost'; Domain = 'corp.example'; PartOfDomain = $true; DomainRole = [uint16]3 } }
                'Win32_ComputerSystemProduct' { [pscustomobject]@{ UUID = 'AAAA' } }
                default { throw "unexpected CIM class $ClassName" }
            }
        }
        $script:State = Get-FakeFirewallState
        Add-FakeFirewallRule -State $script:State -Name 'Never-Read' -RuleSet @{ Owner = 'S-1-5-18' }
        $script:State.Fail['Rule'] = "The CIM provider failed.`r`nSecond line"
        # The package read would throw here; with no rule read there is no token to name, so the step must not run and must add no line.
        $script:State.Appx.Mode = 'Throw'
        $script:R = Get-WorkerResult -State $script:State
    }

    AfterAll {
        Uninstall-FakeNetSecurity -Module $script:Module
    }

    It 'reports one rules error on a single line and nothing else' {
        @($script:R.Errors) | Should -Be @('rules: The CIM provider failed. Second line')
    }

    It 'skips the package read, so PackageCount is null and no packages line is added' {
        ($null -eq $script:R.PackageCount) | Should -BeTrue
        @($script:R.Errors | Where-Object { $_ -like 'packages:*' }).Count | Should -Be 0
    }

    It 'gives null, not 0, for every count that says how much was read' {
        foreach ($name in @('RuleCount', 'EnabledRuleCount', 'FilterFailedCount', 'SddlFailedCount')) {
            ($null -eq $script:R.$name) | Should -BeTrue -Because "$name is null when nothing was read"
        }
    }

    It 'returns empty arrays for the rules, the accounts and the two item lists, never null' {
        foreach ($name in @('Rules', 'Accounts', 'FilterFailedItems', 'SddlFailedItems')) {
            ($script:R.$name -is [System.Array]) | Should -BeTrue -Because $name
            @($script:R.$name).Count | Should -Be 0 -Because $name
        }
        $script:R.AccountCount | Should -Be 0
        $script:R.AccountUnresolvedCount | Should -Be 0
    }

    It 'skips the filter reads and still reads the profiles and the settings' {
        @($script:State.Calls | Where-Object { $_ -like 'Get-NetFirewall*Filter *' }).Count | Should -Be 0
        @($script:State.Calls) | Should -Be @(
            'Get-NetFirewallProfile -PolicyStore ActiveStore EA=Stop',
            'Get-NetFirewallSetting -PolicyStore ActiveStore EA=Stop',
            'Get-NetFirewallRule -PolicyStore ActiveStore -TracePolicyStore EA=Stop'
        )
        $script:R.ProfileCount | Should -Be 3
        $script:R.ActiveProfile | Should -BeExactly 'Domain, Private'
    }
}

Describe 'Worker scriptblock - profiles and global settings' {
    BeforeAll {
        Install-FakeNetSecurity -Module $script:Module
        Mock -ModuleName RemoteFirewall -CommandName Get-CimInstance -MockWith {
            switch ($ClassName) {
                'Win32_OperatingSystem' { [pscustomobject]@{ Caption = 'Fake OS'; Version = '10.0.1' } }
                'Win32_ComputerSystem' { [pscustomobject]@{ DNSHostName = 'fakehost'; Domain = 'corp.example'; PartOfDomain = $true; DomainRole = [uint16]3 } }
                'Win32_ComputerSystemProduct' { [pscustomobject]@{ UUID = 'AAAA' } }
                default { throw "unexpected CIM class $ClassName" }
            }
        }
    }

    AfterAll {
        Uninstall-FakeNetSecurity -Module $script:Module
    }

    Context 'six profiles handed over in a scrambled order' {
        BeforeAll {
            $state = Get-FakeFirewallState
            $state.Profiles = @(
                (Get-FakeFirewallProfile -Name 'gamma' -Omit @('DisabledInterfaceAliases', 'LogFileName')),
                (Get-FakeFirewallProfile -Name 'Public' -Set @{ DisabledInterfaceAliases = [string[]]@('Wi-Fi', 'Ethernet 3') }),
                (Get-FakeFirewallProfile -Name 'Beta' -Set @{ DisabledInterfaceAliases = 'Loopback' }),
                (Get-FakeFirewallProfile -Name 'Domain'),
                (Get-FakeFirewallProfile -Name 'alpha' -Set @{ DisabledInterfaceAliases = $null }),
                (Get-FakeFirewallProfile -Name 'Private' -Set @{ DisabledInterfaceAliases = [string[]]@('Ethernet 2') })
            )
            $script:R = Get-WorkerResult -State $state
            $script:ByName = @{}
            foreach ($profileRow in $script:R.Profiles) { $script:ByName[$profileRow.Name] = $profileRow }
        }

        It 'sorts Domain, Private, Public first, then any other profile by name ignoring case' {
            ((@($script:R.Profiles | ForEach-Object { $_.Name })) -join '|') | Should -BeExactly 'Domain|Private|Public|alpha|Beta|gamma'
            $script:R.ProfileCount | Should -Be 6
        }

        It 'gives a profile row with the 18 columns of DESIGN.md section 6.1 in that order and nothing else, except where the profile lacks a property' {
            @($script:ByName['Domain'].PSObject.Properties.Name) | Should -Be $script:Fw.ProfileColumns
            @($script:ByName['gamma'].PSObject.Properties.Name) | Should -Be $script:Fw.ProfileColumns
        }

        It 'gives the enumeration values of a profile as display strings and the log size as an integer' {
            $domain = $script:ByName['Domain']
            $domain.Name | Should -BeExactly 'Domain'
            $domain.Enabled | Should -BeExactly 'True'
            $domain.DefaultInboundAction | Should -BeExactly 'Block'
            $domain.DefaultOutboundAction | Should -BeExactly 'Allow'
            $domain.AllowInboundRules | Should -BeExactly 'True'
            foreach ($name in @('AllowLocalFirewallRules', 'AllowLocalIPsecRules', 'AllowUserApps', 'AllowUserPorts', 'AllowUnicastResponseToMulticast', 'EnableStealthModeForIPsec', 'LogIgnored')) {
                $domain.$name | Should -BeExactly 'NotConfigured' -Because $name
            }
            $domain.NotifyOnListen | Should -BeExactly 'False'
            $domain.LogAllowed | Should -BeExactly 'False'
            $domain.LogBlocked | Should -BeExactly 'True'
            $domain.LogFileName | Should -BeExactly '%systemroot%\system32\LogFiles\Firewall\pfirewall.log'
            $domain.LogMaxSizeKilobytes | Should -Not -BeOfType [string]
            $domain.LogMaxSizeKilobytes | Should -Be 4096
        }

        It 'gives DisabledInterfaceAliases as an array of strings for zero, one and two elements, a null value and a bare string' {
            Assert-ColumnValue -Actual $script:ByName['Domain'].DisabledInterfaceAliases -Expected @() -Kind 'Array' -Column 'Domain'
            Assert-ColumnValue -Actual $script:ByName['Private'].DisabledInterfaceAliases -Expected @('Ethernet 2') -Kind 'Array' -Column 'Private'
            Assert-ColumnValue -Actual $script:ByName['Public'].DisabledInterfaceAliases -Expected @('Wi-Fi', 'Ethernet 3') -Kind 'Array' -Column 'Public'
            Assert-ColumnValue -Actual $script:ByName['alpha'].DisabledInterfaceAliases -Expected @() -Kind 'Array' -Column 'alpha'
            Assert-ColumnValue -Actual $script:ByName['Beta'].DisabledInterfaceAliases -Expected @('Loopback') -Kind 'Array' -Column 'Beta'
        }

        It 'gives null for the properties a profile does not have, an array column included' {
            ($null -eq $script:ByName['gamma'].DisabledInterfaceAliases) | Should -BeTrue
            ($null -eq $script:ByName['gamma'].LogFileName) | Should -BeTrue
            $script:ByName['gamma'].Enabled | Should -BeExactly 'True'
        }
    }

    Context 'the settings read' {
        BeforeAll {
            $state = Get-FakeFirewallState
            $script:R = Get-WorkerResult -State $state
        }

        It 'gives the 14 columns of DESIGN.md section 6.2 in that order and nothing else' {
            @($script:R.Settings.PSObject.Properties.Name) | Should -Be $script:Fw.SettingColumns
        }

        It 'gives the enumeration values as display strings and the idle time as an integer' {
            $settings = $script:R.Settings
            $settings.ActiveProfile | Should -BeExactly 'Domain, Private'
            $settings.Exemptions | Should -BeExactly 'NeighborDiscovery'
            $settings.EnableStatefulFtp | Should -BeExactly 'True'
            $settings.EnableStatefulPptp | Should -BeExactly 'False'
            foreach ($name in @('RequireFullAuthSupport', 'CertValidationLevel', 'AllowIPsecThroughNAT')) {
                $settings.$name | Should -BeExactly 'NotConfigured' -Because $name
            }
            $settings.MaxSAIdleTimeSeconds | Should -Not -BeOfType [string]
            $settings.MaxSAIdleTimeSeconds | Should -Be 300
            $settings.KeyEncoding | Should -BeExactly 'UTF8'
            $settings.EnablePacketQueuing | Should -BeExactly 'None'
            foreach ($name in @('RemoteMachineTransportAuthorizationList', 'RemoteMachineTunnelAuthorizationList', 'RemoteUserTransportAuthorizationList', 'RemoteUserTunnelAuthorizationList')) {
                $settings.$name | Should -BeExactly 'NotConfigured' -Because $name
            }
        }

        It 'returns the active profile as the string of the settings object, a flags value included' {
            $script:R.ActiveProfile | Should -BeOfType [string]
            $script:R.ActiveProfile | Should -BeExactly 'Domain, Private'
            $script:R.ActiveProfile | Should -BeExactly $script:R.Settings.ActiveProfile
        }

        It 'gives null for a settings property the target does not have, and a null ActiveProfile when that is the one' {
            $state = Get-FakeFirewallState
            $state.Setting = Get-FakeFirewallSetting -Omit @('ActiveProfile', 'EnablePacketQueuing')
            # One rule, so the read is not the empty one that reports rules: no rule returned.
            Add-FakeFirewallRule -State $state -Name 'Settings-Rule'
            $result = Get-WorkerResult -State $state

            ($null -eq $result.ActiveProfile) | Should -BeTrue
            ($null -eq $result.Settings.ActiveProfile) | Should -BeTrue
            ($null -eq $result.Settings.EnablePacketQueuing) | Should -BeTrue
            $result.Settings.KeyEncoding | Should -BeExactly 'UTF8'
            @($result.Errors).Count | Should -Be 0
        }
    }

    Context 'the profiles read fails' {
        BeforeAll {
            $state = Get-FakeFirewallState
            Add-FakeFirewallRule -State $state -Name 'Keeps-Going'
            $state.Fail['Profile'] = "Profile store unavailable.`r`nSecond   line"
            $script:R = Get-WorkerResult -State $state
        }

        It 'reports one profiles error on a single line, with no profile and a count of 0' {
            @($script:R.Errors) | Should -Be @('profiles: Profile store unavailable. Second line')
            ($script:R.Profiles -is [System.Array]) | Should -BeTrue
            @($script:R.Profiles).Count | Should -Be 0
            $script:R.ProfileCount | Should -Be 0
        }

        It 'goes on to read the settings and the rules' {
            $script:R.ActiveProfile | Should -BeExactly 'Domain, Private'
            $script:R.Settings | Should -Not -BeNullOrEmpty
            $script:R.RuleCount | Should -Be 1
        }
    }

    Context 'the profiles read returns nothing' {
        It 'reports a profile count of 0 and no error' {
            $state = Get-FakeFirewallState
            $state.Profiles = @()
            Add-FakeFirewallRule -State $state -Name 'Keeps-Going'
            $result = Get-WorkerResult -State $state

            $result.ProfileCount | Should -Be 0
            @($result.Profiles).Count | Should -Be 0
            @($result.Errors).Count | Should -Be 0
        }
    }

    Context 'the settings read fails' {
        BeforeAll {
            $state = Get-FakeFirewallState
            Add-FakeFirewallRule -State $state -Name 'Keeps-Going'
            $state.Fail['Setting'] = "Settings store unavailable.`r`nSecond   line"
            $script:R = Get-WorkerResult -State $state
        }

        It 'reports one settings error on a single line, with null Settings and a null ActiveProfile' {
            @($script:R.Errors) | Should -Be @('settings: Settings store unavailable. Second line')
            ($null -eq $script:R.Settings) | Should -BeTrue
            ($null -eq $script:R.ActiveProfile) | Should -BeTrue
        }

        It 'goes on to read the profiles and the rules' {
            $script:R.ProfileCount | Should -Be 3
            $script:R.RuleCount | Should -Be 1
        }
    }

    Context 'the settings read returns nothing' {
        It 'reports settings: no object returned, with null Settings and a null ActiveProfile' {
            $state = Get-FakeFirewallState
            $state.SettingNothing = $true
            Add-FakeFirewallRule -State $state -Name 'Keeps-Going'
            $result = Get-WorkerResult -State $state

            @($result.Errors) | Should -Be @('settings: no object returned')
            ($null -eq $result.Settings) | Should -BeTrue
            ($null -eq $result.ActiveProfile) | Should -BeTrue
        }
    }
}

Describe 'Worker scriptblock - accounts from the principals the rules name' {
    BeforeAll {
        Install-FakeNetSecurity -Module $script:Module
        Mock -ModuleName RemoteFirewall -CommandName Get-CimInstance -MockWith {
            switch ($ClassName) {
                'Win32_OperatingSystem' { [pscustomobject]@{ Caption = 'Fake OS'; Version = '10.0.1' } }
                'Win32_ComputerSystem' { [pscustomobject]@{ DNSHostName = 'fakehost'; Domain = 'corp.example'; PartOfDomain = $true; DomainRole = [uint16]3 } }
                'Win32_ComputerSystemProduct' { [pscustomobject]@{ UUID = 'AAAA' } }
                default { throw "unexpected CIM class $ClassName" }
            }
        }

        $packageSid = 'S-1-15-2-1234567890-1234567890-1234567890-1234567890-1234567890-1234567890-1234567890'
        $domainSid1 = 'S-1-5-21-1111111111-2222222222-3333333333-1001'
        $domainSid2 = 'S-1-5-21-1111111111-2222222222-3333333333-1002'
        $script:PackageSid = $packageSid
        $script:DomainSid1 = $domainSid1
        $script:DomainSid2 = $domainSid2

        $state = Get-FakeFirewallState
        # Every principal field once: the owner, the package, and each of the three SDDL fields. The owner of the descriptor (O:LS) is not an ACE and must not become a token. BA is S-1-5-32-544 again, WD (Everyone, S-1-1-0) sits in the system ACL.
        Add-FakeFirewallRule -State $state -Name 'Acc-A' -RuleSet @{ Owner = 'S-1-5-18' } -FilterSet @{
            Application = @{ Package = $packageSid }
            Security    = @{
                LocalUser     = 'O:LSD:(A;;CC;;;S-1-5-32-544)'
                RemoteUser    = "O:LSD:(A;;CC;;;$domainSid1)(A;;CC;;;$domainSid2)"
                RemoteMachine = 'O:LSD:(A;;CC;;;BA)S:(AU;FA;CC;;;WD)'
            }
        }
        # The same package and the same SID twice in one descriptor: one reference each.
        Add-FakeFirewallRule -State $state -Name 'Acc-B' -FilterSet @{
            Application = @{ Package = $packageSid }
            Security    = @{ LocalUser = 'O:LSD:(A;;CC;;;S-1-5-32-544)(A;;CC;;;S-1-5-32-544)' }
        }
        # A descriptor that does not parse, an empty value and the word Any in another letter case: only the first counts as a failure.
        Add-FakeFirewallRule -State $state -Name 'Acc-C' -FilterSet @{ Security = @{ LocalUser = ''; RemoteUser = 'not an sddl'; RemoteMachine = 'ANY' } }
        # Blank values name nobody.
        Add-FakeFirewallRule -State $state -Name 'Acc-D' -RuleSet @{ Owner = '   ' } -FilterSet @{ Application = @{ Package = '' }; Security = @{ LocalUser = '   '; RemoteUser = 'any'; RemoteMachine = '' } }
        # A token that is not a SID: the Name kind, and LocalSystem is the alias of S-1-5-18 that never goes through a lookup.
        Add-FakeFirewallRule -State $state -Name 'Acc-Name' -RuleSet @{ Owner = 'LocalSystem' }
        # The owner in lower case, sorted after Acc-A: the same account as Acc-A's S-1-5-18, one row, two references.
        Add-FakeFirewallRule -State $state -Name 'Acc-Z-lower' -RuleSet @{ Owner = 's-1-5-18' }
        $script:R = Get-WorkerResult -State $state
        $script:ByToken = @{}
        foreach ($account in $script:R.Accounts) { $script:ByToken[$account.Token] = $account }
    }

    AfterAll {
        Uninstall-FakeNetSecurity -Module $script:Module
    }

    It 'names every principal once, as the SID text or the name, sorted ordinal by token' {
        @($script:R.Accounts | ForEach-Object { $_.Token }) | Should -Be @(
            'LocalSystem',
            'S-1-1-0',
            $script:PackageSid,
            'S-1-5-18',
            $script:DomainSid1,
            $script:DomainSid2,
            'S-1-5-32-544'
        )
        $script:R.AccountCount | Should -Be 7
    }

    It 'gives an account row the eight properties of the account shape, in order' {
        @($script:R.Accounts[0].PSObject.Properties.Name) | Should -Be $script:Fw.AccountColumns
    }

    It 'takes the owner as a token, and joins an owner in another letter case to the same account' {
        $account = $script:ByToken['S-1-5-18']
        $account.Kind | Should -Be 'Sid'
        $account.Sid | Should -Be 'S-1-5-18'
        $account.Status | Should -Be 'Resolved'
        $account.Name | Should -Not -BeNullOrEmpty
        $account.ReferenceCount | Should -Be 2
        ((@($account.References)) -join '|') | Should -BeExactly 'Acc-A|Acc-Z-lower'
    }

    It 'takes the application package as a token, and references it once per rule; no package is installed on the fake target, so it stays unresolved' {
        $account = $script:ByToken[$script:PackageSid]
        $account.Kind | Should -Be 'Sid'
        $account.Sid | Should -Be $script:PackageSid
        $account.Status | Should -Be 'NotFound'
        ($null -eq $account.Name) | Should -BeTrue
        $account.ReferenceCount | Should -Be 2
        ((@($account.References)) -join '|') | Should -BeExactly 'Acc-A|Acc-B'
    }

    It 'takes the SID of every access control entry of LocalUser, RemoteUser and RemoteMachine, and the system ACL as well as the discretionary one' {
        $script:ByToken.ContainsKey('S-1-5-32-544') | Should -BeTrue
        $script:ByToken.ContainsKey('S-1-1-0') | Should -BeTrue
        $script:ByToken.ContainsKey($script:DomainSid1) | Should -BeTrue
        $script:ByToken.ContainsKey($script:DomainSid2) | Should -BeTrue
        ((@($script:ByToken['S-1-1-0'].References)) -join '|') | Should -BeExactly 'Acc-A'
        ((@($script:ByToken[$script:DomainSid1].References)) -join '|') | Should -BeExactly 'Acc-A'
        ((@($script:ByToken[$script:DomainSid2].References)) -join '|') | Should -BeExactly 'Acc-A'
    }

    It 'counts a SID that sits twice in descriptors of one rule as one reference, and never adds the owner of a descriptor' {
        $account = $script:ByToken['S-1-5-32-544']
        $account.ReferenceCount | Should -Be 2
        ((@($account.References)) -join '|') | Should -BeExactly 'Acc-A|Acc-B'
        # O:LS names the local service as owner of each descriptor; that is not an entry.
        $script:ByToken.ContainsKey('S-1-5-19') | Should -BeFalse
    }

    It 'gives a resolved account its name and an empty error, and an unresolved one no name and a one-line error' {
        foreach ($token in @('S-1-1-0', 'S-1-5-18', 'S-1-5-32-544')) {
            $script:ByToken[$token].Status | Should -Be 'Resolved' -Because $token
            $script:ByToken[$token].Name | Should -Not -BeNullOrEmpty -Because $token
            $script:ByToken[$token].Error | Should -BeExactly '' -Because $token
        }
        foreach ($token in @($script:PackageSid, $script:DomainSid1, $script:DomainSid2)) {
            $script:ByToken[$token].Status | Should -Be 'NotFound' -Because $token
            ($null -eq $script:ByToken[$token].Name) | Should -BeTrue -Because $token
            $script:ByToken[$token].Error | Should -Not -BeNullOrEmpty -Because $token
            $script:ByToken[$token].Error | Should -Not -Match "`r|`n" -Because $token
        }
        $script:R.AccountUnresolvedCount | Should -Be 3
    }

    It 'gives a token that is not a SID the Name kind, and resolves LocalSystem to S-1-5-18 without a lookup' {
        $account = $script:ByToken['LocalSystem']
        $account.Kind | Should -Be 'Name'
        $account.Sid | Should -Be 'S-1-5-18'
        $account.Name | Should -Be 'LocalSystem'
        $account.Status | Should -Be 'Resolved'
        ((@($account.References)) -join '|') | Should -BeExactly 'Acc-Name'
    }

    It 'skips a blank value, an empty value and Any in any letter case, without counting a failure for them' {
        # Acc-D and the empty and Any fields of Acc-C name nobody; the only failure is Acc-C's RemoteUser.
        foreach ($account in $script:R.Accounts) {
            @($account.References) | Should -Not -Contain 'Acc-D'
        }
        $script:R.SddlFailedCount | Should -Be 1
    }

    It 'counts an SDDL value that does not parse, names it Rule:Field, and adds one error line with the reason' {
        $script:R.SddlFailedCount | Should -BeOfType [int]
        $script:R.SddlFailedCount | Should -Be 1
        ($script:R.SddlFailedItems -is [System.Array]) | Should -BeTrue
        @($script:R.SddlFailedItems) | Should -Be @('Acc-C:RemoteUser')
        @($script:R.Errors).Count | Should -Be 1
        $script:R.Errors[0] | Should -Match '^sddl Acc-C RemoteUser: \S'
        # The parameter name comes from the .NET exception on both engines and is not localised.
        $script:R.Errors[0] | Should -Match 'sddlForm'
        $script:R.Errors[0] | Should -Not -Match "`r|`n"
    }

    It 'keeps the SDDL text on the rule row exactly as the target gave it, parsed or not' {
        $rules = @{}
        foreach ($rule in $script:R.Rules) { $rules[$rule.Name] = $rule }
        $rules['Acc-C'].RemoteUser | Should -BeExactly 'not an sddl'
        $rules['Acc-C'].LocalUser | Should -BeExactly ''
        $rules['Acc-C'].RemoteMachine | Should -BeExactly 'ANY'
        $rules['Acc-A'].RemoteMachine | Should -BeExactly 'O:LSD:(A;;CC;;;BA)S:(AU;FA;CC;;;WD)'
    }

    It 'counts no SDDL failure and reports SddlFailedCount 0, not null, when every descriptor parses' {
        $state = Get-FakeFirewallState
        Add-FakeFirewallRule -State $state -Name 'Fine' -FilterSet @{ Security = @{ LocalUser = 'O:LSD:(A;;CC;;;S-1-5-32-544)' } }
        $result = Get-WorkerResult -State $state

        $result.SddlFailedCount | Should -Be 0
        @($result.SddlFailedItems).Count | Should -Be 0
        @($result.Errors).Count | Should -Be 0
    }

    It 'reports SddlFailedItems in the order the rules are sorted, one entry per failed field' {
        $state = Get-FakeFirewallState
        Add-FakeFirewallRule -State $state -Name 'Bad-2' -FilterSet @{ Security = @{ LocalUser = 'bad one'; RemoteMachine = 'bad two' } }
        Add-FakeFirewallRule -State $state -Name 'Bad-1' -FilterSet @{ Security = @{ RemoteUser = 'bad three' } }
        $result = Get-WorkerResult -State $state

        $result.SddlFailedCount | Should -Be 3
        @($result.SddlFailedItems) | Should -Be @('Bad-1:RemoteUser', 'Bad-2:LocalUser', 'Bad-2:RemoteMachine')
        @($result.Errors).Count | Should -Be 3
        $result.Errors[1] | Should -Match '^sddl Bad-2 LocalUser: \S'
    }

    It 'lists a rule name once per account even when rules share the name, ignoring case, and keeps the first spelling in the rule order' {
        $state = Get-FakeFirewallState
        # Dup, Dup and dup, sorted by InstanceID within the name: d1, d2, d3. Other is a different name on the same owner.
        Add-FakeFirewallRule -State $state -Name 'Dup' -InstanceID 'd1' -RuleSet @{ Owner = 'S-1-5-18' }
        Add-FakeFirewallRule -State $state -Name 'Dup' -InstanceID 'd2' -RuleSet @{ Owner = 'S-1-5-18' }
        Add-FakeFirewallRule -State $state -Name 'dup' -InstanceID 'd3' -RuleSet @{ Owner = 'S-1-5-18' }
        Add-FakeFirewallRule -State $state -Name 'Other' -RuleSet @{ Owner = 'S-1-5-18' }
        Add-FakeFirewallRule -State $state -Name 'Lone' -RuleSet @{ Owner = 'S-1-5-19' }
        $result = Get-WorkerResult -State $state

        $result.RuleCount | Should -Be 5
        $byToken = @{}
        foreach ($account in $result.Accounts) { $byToken[$account.Token] = $account }
        $byToken['S-1-5-18'].ReferenceCount | Should -Be 2
        @($byToken['S-1-5-18'].References) | Should -Be @('Dup', 'Other')
        $byToken['S-1-5-19'].ReferenceCount | Should -Be 1
        @($byToken['S-1-5-19'].References) | Should -Be @('Lone')

        # Two rules with the name in both spellings where the lower case one sorts first, by InstanceID.
        $lowerState = Get-FakeFirewallState
        Add-FakeFirewallRule -State $lowerState -Name 'Dup' -InstanceID 'd2' -RuleSet @{ Owner = 'S-1-5-18' }
        Add-FakeFirewallRule -State $lowerState -Name 'dup' -InstanceID 'd1' -RuleSet @{ Owner = 'S-1-5-18' }
        $lowerResult = Get-WorkerResult -State $lowerState
        $lowerResult.Accounts[0].ReferenceCount | Should -Be 1
        @($lowerResult.Accounts[0].References) | Should -Be @('dup')
    }

    It 'collapses the lookup message of an account that cannot be translated to one line, and keeps it data, not an error' {
        # The step has no New-Object call left outside the per-account try, so a failing lookup is the one failure of the step a mock can reach: it ends in the account's own Error, which is collapsed like every other message. Every other New-Object call of the worker goes through to the real cmdlet; only the SID lookup object fails.
        Mock -ModuleName RemoteFirewall -CommandName New-Object -MockWith { & 'Microsoft.PowerShell.Utility\New-Object' @PesterBoundParameters }
        Mock -ModuleName RemoteFirewall -CommandName New-Object -ParameterFilter { $TypeName -like '*SecurityIdentifier*' } -MockWith { throw "lookup failed`r`n   second line" }
        $state = Get-FakeFirewallState
        Add-FakeFirewallRule -State $state -Name 'Acc-One' -RuleSet @{ Owner = 'S-1-5-18' }
        $result = Get-WorkerResult -State $state

        @($result.Errors).Count | Should -Be 0
        $result.AccountCount | Should -Be 1
        $result.AccountUnresolvedCount | Should -Be 1
        $result.Accounts[0].Status | Should -BeExactly 'NotFound'
        $result.Accounts[0].Error | Should -BeExactly 'lookup failed second line'
        $result.RuleCount | Should -Be 1
    }
}

Describe 'Worker scriptblock - application package names, DESIGN.md section 12' {
    BeforeAll {
        Install-FakeNetSecurity -Module $script:Module
        Mock -ModuleName RemoteFirewall -CommandName Get-CimInstance -MockWith {
            switch ($ClassName) {
                'Win32_OperatingSystem' { [pscustomobject]@{ Caption = 'Fake OS'; Version = '10.0.1' } }
                'Win32_ComputerSystem' { [pscustomobject]@{ DNSHostName = 'fakehost'; Domain = 'corp.example'; PartOfDomain = $true; DomainRole = [uint16]3 } }
                'Win32_ComputerSystemProduct' { [pscustomobject]@{ UUID = 'AAAA' } }
                default { throw "unexpected CIM class $ClassName" }
            }
        }

        $script:NotepadSid = $script:Fw.PackagePairs[0].Sid
        $script:CoreAiSid = $script:Fw.PackagePairs[1].Sid
        $script:VcLibsSid = $script:Fw.PackagePairs[2].Sid
        $script:UnknownPackageSid = 'S-1-15-2-1-2-3-4-5-6-7'
        # The sub-authorities of the Notepad package under the capability prefix: only the whole SID may match, never its tail.
        $script:CapabilitySid = 'S-1-15-3-1050576210-4101474698-56307613-2706264498-167457550-835605972-784472318'
        $script:DomainSid = 'S-1-5-21-1111111111-2222222222-3333333333-1001'

        # One state with the three known packages, the way Get-AppxPackage -AllUsers lists them: a package once per version or architecture, the family name in the spelling the package has, one family name in another letter case, and two entries without a usable family name.
        function Get-PackageState {
            $state = Get-FakeFirewallState
            $state.Appx.Packages = @(
                [pscustomobject]@{ Name = 'Microsoft.WindowsNotepad'; PackageFamilyName = 'Microsoft.WindowsNotepad_8wekyb3d8bbwe' },
                [pscustomobject]@{ Name = 'Microsoft.WindowsNotepad'; PackageFamilyName = 'Microsoft.WindowsNotepad_8wekyb3d8bbwe' },
                [pscustomobject]@{ Name = 'MicrosoftWindows.Client.CoreAI'; PackageFamilyName = 'MicrosoftWindows.Client.CoreAI_cw5n1h2txyewy' },
                [pscustomobject]@{ Name = 'Microsoft.VCLibs.140.00'; PackageFamilyName = 'Microsoft.VCLibs.140.00_8wekyb3d8bbwe' },
                [pscustomobject]@{ Name = 'Microsoft.VCLibs.140.00'; PackageFamilyName = 'MICROSOFT.VCLIBS.140.00_8WEKYB3D8BBWE' },
                [pscustomobject]@{ Name = 'NoFamilyName'; PackageFamilyName = $null },
                [pscustomobject]@{ Name = 'BlankFamilyName'; PackageFamilyName = '  ' }
            )
            return $state
        }

        # The rules name every kind of SID once. A-Lower spells the VCLibs SID in lower case: the token keeps the first spelling seen, so the lookup has to match ignoring case.
        $state = Get-PackageState
        Add-FakeFirewallRule -State $state -Name 'A-Lower' -FilterSet @{ Application = @{ Package = $script:VcLibsSid.ToLowerInvariant() } }
        Add-FakeFirewallRule -State $state -Name 'Pkg-Capability' -FilterSet @{ Application = @{ Package = $script:CapabilitySid } }
        Add-FakeFirewallRule -State $state -Name 'Pkg-CoreAI' -FilterSet @{ Application = @{ Package = $script:CoreAiSid } }
        Add-FakeFirewallRule -State $state -Name 'Pkg-Domain-Owner' -RuleSet @{ Owner = $script:DomainSid }
        Add-FakeFirewallRule -State $state -Name 'Pkg-Notepad' -RuleSet @{ Owner = 'S-1-5-18' } -FilterSet @{ Application = @{ Package = $script:NotepadSid } }
        Add-FakeFirewallRule -State $state -Name 'Pkg-Notepad-Two' -FilterSet @{ Application = @{ Package = $script:NotepadSid } }
        Add-FakeFirewallRule -State $state -Name 'Pkg-Unknown' -FilterSet @{ Application = @{ Package = $script:UnknownPackageSid } }
        $script:State = $state
        $script:Run = Get-WorkerResult -State $state -Preference 'Continue' -Full
        $script:R = $script:Run.Result
        $script:ByToken = @{}
        foreach ($account in $script:R.Accounts) { $script:ByToken[$account.Token] = $account }
    }

    AfterAll {
        Uninstall-FakeNetSecurity -Module $script:Module
    }

    It 'hashes the package family name <FamilyName> to its package SID, and the account of that SID gets the name' -ForEach $PackagePairCases {
        $state = Get-FakeFirewallState
        $state.Appx.Packages = @([pscustomobject]@{ Name = 'Pair'; PackageFamilyName = $FamilyName })
        Add-FakeFirewallRule -State $state -Name 'Pair-Rule' -FilterSet @{ Application = @{ Package = $Sid } }
        $result = Get-WorkerResult -State $state

        @($result.Accounts).Count | Should -Be 1
        $result.Accounts[0].Token | Should -BeExactly $Sid
        $result.Accounts[0].Sid | Should -BeExactly $Sid
        $result.Accounts[0].Name | Should -BeExactly $FamilyName
        $result.Accounts[0].Status | Should -BeExactly 'Resolved'
        $result.Accounts[0].Error | Should -BeExactly ''
        $result.PackageCount | Should -Be 1
        $result.AccountUnresolvedCount | Should -Be 0
        @($result.Errors).Count | Should -Be 0
    }

    It 'hashes the family name in lower case, so the same family name in any letter case gives the same SID' {
        foreach ($pair in $script:Fw.PackagePairs) {
            foreach ($spelling in @($pair.FamilyName.ToUpperInvariant(), $pair.FamilyName.ToLowerInvariant())) {
                $state = Get-FakeFirewallState
                $state.Appx.Packages = @([pscustomobject]@{ Name = 'Case'; PackageFamilyName = $spelling })
                Add-FakeFirewallRule -State $state -Name 'Case-Rule' -FilterSet @{ Application = @{ Package = $pair.Sid } }
                $result = Get-WorkerResult -State $state
                $result.Accounts[0].Status | Should -BeExactly 'Resolved' -Because $spelling
                $result.Accounts[0].Name | Should -BeExactly $spelling -Because 'the family name is kept as the cmdlet gave it'
            }
        }
    }

    Context 'a target with packages, one run at Continue' {
        It 'reads the packages with Get-AppxPackage -AllUsers once, at -ErrorAction Stop, and leaves no error record and no error line' {
            @($script:State.AppxCalls) | Should -Be @('Get-AppxPackage -AllUsers EA=Stop')
            $script:Run.ErrorRecords.Count | Should -Be 0
            $script:Run.ResultCount | Should -Be 1
            @($script:R.Errors).Count | Should -Be 0
        }

        It 'counts distinct family names, ignoring case, and skips a package without a usable family name' {
            $script:R.PackageCount | Should -BeOfType [int]
            $script:R.PackageCount | Should -Be 3
            $script:R.PackagesDurationMs | Should -BeOfType [int]
            $script:R.PackagesDurationMs | Should -BeGreaterOrEqual 0
        }

        It 'gives the NotFound package SIDs of installed packages their family name as the cmdlet spelled it, Resolved, with an empty error' {
            $notepad = $script:ByToken[$script:NotepadSid]
            $notepad.Name | Should -BeExactly 'Microsoft.WindowsNotepad_8wekyb3d8bbwe'
            $notepad.Status | Should -BeExactly 'Resolved'
            $notepad.Error | Should -BeExactly ''
            $notepad.Kind | Should -Be 'Sid'
            $notepad.Sid | Should -Be $script:NotepadSid
            $script:ByToken[$script:CoreAiSid].Name | Should -BeExactly 'MicrosoftWindows.Client.CoreAI_cw5n1h2txyewy'
            $script:ByToken[$script:CoreAiSid].Status | Should -BeExactly 'Resolved'
            # The first spelling of the family name in the package list, not the upper case one after it.
            $script:ByToken[$script:VcLibsSid].Name | Should -BeExactly 'Microsoft.VCLibs.140.00_8wekyb3d8bbwe'
        }

        It 'matches a package SID token spelled in lower case, and keeps the token as it was first seen' {
            $lowerToken = $script:VcLibsSid.ToLowerInvariant()
            @($script:R.Accounts | Where-Object { $_.Token -ceq $lowerToken }).Count | Should -Be 1
            @($script:R.Accounts | Where-Object { $_.Token -ceq $script:VcLibsSid }).Count | Should -Be 0
            $script:ByToken[$lowerToken].Status | Should -BeExactly 'Resolved'
            $script:ByToken[$lowerToken].Name | Should -BeExactly 'Microsoft.VCLibs.140.00_8wekyb3d8bbwe'
        }

        It 'keeps the references of a resolved package account' {
            $script:ByToken[$script:NotepadSid].ReferenceCount | Should -Be 2
            (@($script:ByToken[$script:NotepadSid].References) -join '|') | Should -BeExactly 'Pkg-Notepad|Pkg-Notepad-Two'
            (@($script:ByToken[$script:CoreAiSid].References) -join '|') | Should -BeExactly 'Pkg-CoreAI'
        }

        It 'leaves a package SID whose package is not installed, a capability SID and a domain SID NotFound, with no name and the lookup error text' {
            foreach ($token in @($script:UnknownPackageSid, $script:CapabilitySid, $script:DomainSid)) {
                $account = $script:ByToken[$token]
                $account.Status | Should -BeExactly 'NotFound' -Because $token
                ($null -eq $account.Name) | Should -BeTrue -Because $token
                $account.Error | Should -Not -BeNullOrEmpty -Because $token
                $account.Error | Should -Not -Match "`r|`n" -Because $token
            }
        }

        It 'leaves an account that resolved through the ordinary lookup alone' {
            $script:ByToken['S-1-5-18'].Status | Should -BeExactly 'Resolved'
            $script:ByToken['S-1-5-18'].Name | Should -Not -BeNullOrEmpty
            $script:ByToken['S-1-5-18'].Name | Should -Not -Match '_'
            $script:ByToken['S-1-5-18'].Error | Should -BeExactly ''
        }

        It 'counts AccountUnresolvedCount after the lookup: only the three accounts that stayed NotFound' {
            $script:R.AccountCount | Should -Be 7
            $script:R.AccountUnresolvedCount | Should -Be 3
            @($script:R.Accounts | Where-Object { $_.Status -eq 'NotFound' }).Count | Should -Be 3
        }

        It 'keeps the eight properties of the account shape, in order, on a resolved account' {
            @($script:ByToken[$script:NotepadSid].PSObject.Properties.Name) | Should -Be $script:Fw.AccountColumns
        }

        It 'changes nothing in the rule rows: PackageFamilyName stays what the rule object reports, and the Package column the SID' {
            $rules = @{}
            foreach ($rule in $script:R.Rules) { $rules[$rule.Name] = $rule }
            $rules['Pkg-Notepad'].Package | Should -BeExactly $script:NotepadSid
            ($null -eq $rules['Pkg-Notepad'].PackageFamilyName) | Should -BeTrue
        }
    }

    Context 'the worker object keys of DESIGN.md section 12.3' {
        It 'puts PackageCount right after SddlFailedCount and PackagesDurationMs right after FiltersDurationMs' {
            $names = @($script:R.PSObject.Properties.Name)
            $names | Should -Be $script:Fw.WorkerKeys
            $names[[array]::IndexOf($names, 'SddlFailedCount') + 1] | Should -Be 'PackageCount'
            $names[[array]::IndexOf($names, 'FiltersDurationMs') + 1] | Should -Be 'PackagesDurationMs'
            $names[-1] | Should -Be 'Errors'
        }
    }

    Context 'the command Get-AppxPackage is absent on the target' {
        BeforeAll {
            # The worker asks Get-Command whether the command exists; the answer is no for that one name and the real one for every other.
            Mock -ModuleName RemoteFirewall -CommandName Get-Command -ParameterFilter { $Name -contains 'Get-AppxPackage' } -MockWith { $null }
            $absentState = Get-PackageState
            Add-FakeFirewallRule -State $absentState -Name 'Absent-Rule' -FilterSet @{ Application = @{ Package = $script:NotepadSid } }
            $script:AbsentState = $absentState
            $script:AbsentRun = Get-WorkerResult -State $absentState -Preference 'Continue' -Full
            $script:Absent = $script:AbsentRun.Result
        }

        It 'never calls Get-AppxPackage, reports PackageCount null and adds no error, at Continue, with no error record' {
            @($script:AbsentState.AppxCalls).Count | Should -Be 0
            ($null -eq $script:Absent.PackageCount) | Should -BeTrue
            @($script:Absent.Errors).Count | Should -Be 0
            $script:AbsentRun.ErrorRecords.Count | Should -Be 0
            $script:AbsentRun.ResultCount | Should -Be 1
            $script:Absent.PackagesDurationMs | Should -BeOfType [int]
        }

        It 'leaves the package SID NotFound, reads everything else, and the row is Success through the host' {
            $script:Absent.Accounts[0].Status | Should -BeExactly 'NotFound'
            ($null -eq $script:Absent.Accounts[0].Name) | Should -BeTrue
            $script:Absent.AccountUnresolvedCount | Should -Be 1
            $script:Absent.RuleCount | Should -Be 1
            $row = Invoke-CompleteInModule -WorkerObject $script:Absent
            $row.Status | Should -Be 'Success'
            (Get-Content -LiteralPath (Join-Path $row.OutputFolder 'summary.json') -Raw) | Should -Match '"PackageCount":\s*null'
        }
    }

    Context 'the command exists and throws, the way an unelevated -AllUsers read does' {
        BeforeAll {
            # The text of the real failure: the message arrives twice with line breaks.
            $throwState = Get-PackageState
            $throwState.Appx.Mode = 'Throw'
            $throwState.Appx.Message = "Access is denied.`r`n`r`nAccess is denied.`r`n"
            Add-FakeFirewallRule -State $throwState -Name 'Throw-Rule' -FilterSet @{ Application = @{ Package = $script:NotepadSid } }
            $script:ThrowState = $throwState
        }

        It 'adds one packages: error line collapsed to one line, PackageCount null, the package SID NotFound, no error record, at <Preference>' -ForEach @(
            @{ Preference = 'Continue' }
            @{ Preference = 'Stop' }
        ) {
            $run = Get-WorkerResult -State $script:ThrowState -Preference $Preference -Full
            $run.ErrorRecords.Count | Should -Be 0 -Because (($run.ErrorRecords | ForEach-Object { $_.ToString() }) -join ' ; ')
            $run.ResultCount | Should -Be 1
            @($run.Result.Errors) | Should -Be @('packages: Access is denied. Access is denied.')
            ($null -eq $run.Result.PackageCount) | Should -BeTrue
            $run.Result.Accounts[0].Status | Should -BeExactly 'NotFound'
            ($null -eq $run.Result.Accounts[0].Name) | Should -BeTrue
            $run.Result.RuleCount | Should -Be 1
            $run.Result.ProfileCount | Should -Be 3
        }

        It 'makes the row Partial through the host, with the line as the row error and in system.json' {
            $worker = Get-WorkerResult -State $script:ThrowState -Preference 'Continue'
            $row = Invoke-CompleteInModule -WorkerObject $worker
            $row.Status | Should -Be 'Partial'
            $row.Error | Should -Be 'packages: Access is denied. Access is denied.'
            $row.ErrorCount | Should -Be 1
            $system = Get-Content -LiteralPath (Join-Path $row.OutputFolder 'system.json') -Raw | ConvertFrom-Json
            @($system.Errors) | Should -Be @('packages: Access is denied. Access is denied.')
            ($null -eq $system.PackageCount) | Should -BeTrue
        }

        It 'leaves no error record when the read fails with a non-terminating error, at Continue, because the call carries -ErrorAction Stop' {
            $errorState = Get-PackageState
            $errorState.Appx.Mode = 'Error'
            Add-FakeFirewallRule -State $errorState -Name 'Error-Rule' -FilterSet @{ Application = @{ Package = $script:NotepadSid } }
            $run = Get-WorkerResult -State $errorState -Preference 'Continue' -Full
            $run.ErrorRecords.Count | Should -Be 0 -Because (($run.ErrorRecords | ForEach-Object { $_.ToString() }) -join ' ; ')
            @($run.Result.Errors) | Should -Be @('packages: Access is denied.')
            ($null -eq $run.Result.PackageCount) | Should -BeTrue
            @($errorState.AppxCalls) | Should -Be @('Get-AppxPackage -AllUsers EA=Stop')
        }

        It 'leaves no package name and no count behind when a package in the middle of the list cannot be read: the names hashed before it are dropped' {
            $partialState = Get-PackageState
            # A family name that cannot be turned into a string, the way a broken value can fail on conversion.
            $unprintable = New-Object psobject
            $unprintable | Add-Member -MemberType ScriptMethod -Name ToString -Value { throw 'family name unreadable' } -Force
            $unreadable = [pscustomobject]@{ Name = 'Unreadable'; PackageFamilyName = $unprintable }
            # The Notepad package is hashed first and would resolve the rule's SID; the second package then throws.
            $partialState.Appx.Packages = @($partialState.Appx.Packages[0], $unreadable, $partialState.Appx.Packages[2])
            Add-FakeFirewallRule -State $partialState -Name 'Partial-Rule' -FilterSet @{ Application = @{ Package = $script:NotepadSid } }
            $run = Get-WorkerResult -State $partialState -Preference 'Continue' -Full

            $run.ErrorRecords.Count | Should -Be 0
            $run.ResultCount | Should -Be 1
            @($run.Result.Errors).Count | Should -Be 1
            $run.Result.Errors[0] | Should -Match '^packages: \S'
            ($null -eq $run.Result.PackageCount) | Should -BeTrue
            $run.Result.Accounts[0].Status | Should -BeExactly 'NotFound'
            ($null -eq $run.Result.Accounts[0].Name) | Should -BeTrue
            $run.Result.AccountUnresolvedCount | Should -Be 1
        }
    }
}

Describe 'Worker scriptblock - the real Get-AppxPackage of this host' {
    It 'leaves no error record at <Preference> and reports the packages step the way the elevation of this session allows' -ForEach @(
        @{ Preference = 'Continue' }
        @{ Preference = 'Stop' }
    ) {
        if (-not $script:NetSecurityPresent) {
            Set-ItResult -Skipped -Because 'the NetSecurity module is not available on this host'
            return
        }
        # No fake may be left in the module, or this would read the fake.
        $fakeLeft = & $script:Module { [bool](Get-Command -Name 'Get-AppxPackage' -CommandType Function -ErrorAction SilentlyContinue) }
        $fakeLeft | Should -BeFalse -Because 'the real Get-AppxPackage must be the one that runs'

        $appxPresent = [bool](Get-Command -Name 'Get-AppxPackage' -ErrorAction SilentlyContinue)
        $run = Invoke-WorkerInModule -Preference $Preference -Full

        $run.ErrorRecords.Count | Should -Be 0 -Because (($run.ErrorRecords | ForEach-Object { $_.ToString() }) -join ' ; ')
        $run.ResultCount | Should -Be 1
        $packageErrors = @($run.Result.Errors | Where-Object { $_ -like 'packages:*' })
        if (-not $appxPresent) {
            ($null -eq $run.Result.PackageCount) | Should -BeTrue
            $packageErrors.Count | Should -Be 0
        } elseif ($run.Result.IsElevated) {
            $packageErrors.Count | Should -Be 0
            $run.Result.PackageCount | Should -BeGreaterThan 0
        } else {
            # Unelevated, Get-AppxPackage -AllUsers throws Access is denied: one line, no count.
            $packageErrors.Count | Should -Be 1
            $packageErrors[0] | Should -Match '^packages: \S'
            $packageErrors[0] | Should -Not -Match "`r|`n"
            ($null -eq $run.Result.PackageCount) | Should -BeTrue
        }
    }
}

Describe 'Worker scriptblock - a rule row that cannot be built' {
    BeforeAll {
        Install-FakeNetSecurity -Module $script:Module
        Mock -ModuleName RemoteFirewall -CommandName Get-CimInstance -MockWith {
            switch ($ClassName) {
                'Win32_OperatingSystem' { [pscustomobject]@{ Caption = 'Fake OS'; Version = '10.0.1' } }
                'Win32_ComputerSystem' { [pscustomobject]@{ DNSHostName = 'fakehost'; Domain = 'corp.example'; PartOfDomain = $true; DomainRole = [uint16]3 } }
                'Win32_ComputerSystemProduct' { [pscustomobject]@{ UUID = 'AAAA' } }
                default { throw "unexpected CIM class $ClassName" }
            }
        }
        $state = Get-FakeFirewallState
        Add-FakeFirewallRule -State $state -Name 'Good-A'
        $unprintable = New-Object psobject
        $unprintable | Add-Member -MemberType ScriptMethod -Name ToString -Value { throw "conversion deliberately fails`r`non two lines" } -Force
        Add-FakeFirewallRule -State $state -Name 'Bad-Row' -RuleSet @{ Description = $unprintable }
        Add-FakeFirewallRule -State $state -Name 'Good-B'
        # A value that cannot be turned into a string, the way a broken CIM value can fail on conversion.
        $script:R = Get-WorkerResult -State $state
    }

    AfterAll {
        Uninstall-FakeNetSecurity -Module $script:Module
    }

    It 'skips the row, reports it as rule row: with the reason on one line, and counts only the rows that were built' {
        @($script:R.Errors).Count | Should -Be 1
        # The wording of the conversion error is the engine's own, so only its presence is asserted.
        $script:R.Errors[0] | Should -Match '^rule row: \S'
        $script:R.Errors[0] | Should -Not -Match "`r|`n"
        $script:R.RuleCount | Should -Be 2
        ((@($script:R.Rules | ForEach-Object { $_.Name })) -join '|') | Should -BeExactly 'Good-A|Good-B'
        $script:R.EnabledRuleCount | Should -Be 2
    }
}

Describe 'Worker scriptblock - error preference and error records' {
    BeforeAll {
        Install-FakeNetSecurity -Module $script:Module
        Mock -ModuleName RemoteFirewall -CommandName Get-CimInstance -MockWith {
            switch ($ClassName) {
                'Win32_OperatingSystem' { [pscustomobject]@{ Caption = 'Fake OS'; Version = '10.0.1' } }
                'Win32_ComputerSystem' { [pscustomobject]@{ DNSHostName = 'fakehost'; Domain = 'corp.example'; PartOfDomain = $true; DomainRole = [uint16]3 } }
                'Win32_ComputerSystemProduct' { [pscustomobject]@{ UUID = 'AAAA' } }
                default { throw "unexpected CIM class $ClassName" }
            }
        }
    }

    AfterAll {
        Uninstall-FakeNetSecurity -Module $script:Module
    }

    # One case per read that can fail: the worker turns a non-terminating failure of any of them into an Errors line and leaves no error record on the stream, whatever the preference of the session it runs in. A remote session runs at Continue.
    It 'leaves no error record and reports one <Prefix> error line when the <Fail> read fails, at Continue' -ForEach @(
        @{ Fail = 'Profile'; Prefix = 'profiles' }
        @{ Fail = 'Setting'; Prefix = 'settings' }
        @{ Fail = 'Rule'; Prefix = 'rules' }
        @{ Fail = 'Address'; Prefix = 'filter Address' }
        @{ Fail = 'Port'; Prefix = 'filter Port' }
        @{ Fail = 'Application'; Prefix = 'filter Application' }
        @{ Fail = 'Service'; Prefix = 'filter Service' }
        @{ Fail = 'Interface'; Prefix = 'filter Interface' }
        @{ Fail = 'InterfaceType'; Prefix = 'filter InterfaceType' }
        @{ Fail = 'Security'; Prefix = 'filter Security' }
    ) {
        $state = Get-FakeFirewallState
        Add-FakeFirewallRule -State $state -Name 'Continue-Rule'
        $state.Fail[$Fail] = 'Access is denied.'
        $run = Get-WorkerResult -State $state -Preference 'Continue' -Full

        $run.ErrorRecords.Count | Should -Be 0 -Because (($run.ErrorRecords | ForEach-Object { $_.ToString() }) -join ' ; ')
        $run.ResultCount | Should -Be 1
        @($run.Result.Errors) | Should -Be @("${Prefix}: Access is denied.")
        foreach ($call in $state.Calls) { $call | Should -Match ' EA=Stop$' }
    }

    It 'leaves no error record and reports no error for a clean run at Continue' {
        $state = Get-FakeFirewallState
        Add-FakeFirewallRule -State $state -Name 'Continue-Rule' -RuleSet @{ Owner = 'S-1-5-18' } -FilterSet @{ Security = @{ LocalUser = 'O:LSD:(A;;CC;;;S-1-5-32-544)' } }
        $run = Get-WorkerResult -State $state -Preference 'Continue' -Full

        $run.ErrorRecords.Count | Should -Be 0
        $run.ResultCount | Should -Be 1
        @($run.Result.Errors).Count | Should -Be 0
    }

    It 'leaves no error record when an SDDL value does not parse, at Continue, and names it in Errors' {
        $state = Get-FakeFirewallState
        Add-FakeFirewallRule -State $state -Name 'Continue-Rule' -FilterSet @{ Security = @{ RemoteUser = 'not an sddl' } }
        $run = Get-WorkerResult -State $state -Preference 'Continue' -Full

        $run.ErrorRecords.Count | Should -Be 0
        $run.Result.SddlFailedCount | Should -Be 1
        @($run.Result.Errors).Count | Should -Be 1
    }

    It 'leaves no error record when a CIM query fails, at Continue' {
        Mock -ModuleName RemoteFirewall -CommandName Get-CimInstance -ParameterFilter { $true } -MockWith { throw 'CIM deliberately unavailable' }
        $state = Get-FakeFirewallState
        Add-FakeFirewallRule -State $state -Name 'Continue-Rule'
        $run = Get-WorkerResult -State $state -Preference 'Continue' -Full

        $run.ErrorRecords.Count | Should -Be 0
        @($run.Result.Errors).Count | Should -Be 2
    }

    It 'reports the same Errors at Stop and at Continue for a failed filter class' {
        $state = Get-FakeFirewallState
        Add-FakeFirewallRule -State $state -Name 'Continue-Rule'
        $state.Fail['Service'] = 'Access is denied.'
        $atStop = Get-WorkerResult -State $state -Preference 'Stop'
        $atContinue = Get-WorkerResult -State $state -Preference 'Continue'

        @($atStop.Errors) | Should -Be @($atContinue.Errors)
        @($atStop.Errors).Count | Should -Be 1
    }
}

Describe 'The NetSecurity calls against the real cmdlets' {
    BeforeAll {
        # Every call to a NetSecurity cmdlet in the worker text, read from its syntax tree: the command name (the filter call is a string with the class in it, expanded here for the seven classes) and the parameters named on the call.
        $workerBlock = & $script:Module { Get-FirewallInventoryWorker }
        $script:CallsWorkerBlock = $workerBlock
        $script:WorkerCalls = @()
        $commandNodes = $workerBlock.Ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.CommandAst] }, $true)
        foreach ($node in $commandNodes) {
            $first = $node.CommandElements[0]
            $names = @()
            if ($first -is [System.Management.Automation.Language.StringConstantExpressionAst]) {
                $names = @($first.Value)
            } elseif ($first -is [System.Management.Automation.Language.ExpandableStringExpressionAst]) {
                foreach ($class in $script:Fw.FilterClasses) { $names += $first.Value.Replace('$($class)', $class) }
            }
            $parameterNames = @($node.CommandElements | Where-Object { $_ -is [System.Management.Automation.Language.CommandParameterAst] } | ForEach-Object { $_.ParameterName })
            foreach ($name in $names) {
                if ($name -like 'Get-NetFirewall*') { $script:WorkerCalls += [pscustomobject]@{ Name = $name; Parameters = $parameterNames } }
            }
        }
    }

    It 'calls exactly the ten NetSecurity cmdlets the fakes replace, once each in the worker text' {
        @($script:WorkerCalls | ForEach-Object { $_.Name } | Sort-Object) | Should -Be @($script:Fw.CmdletCallOrder | Sort-Object)
    }

    It 'binds every call the worker makes to a parameter set of the real cmdlet that needs nothing else, so the call is not only valid against a fake' {
        if (-not $script:NetSecurityPresent) {
            Set-ItResult -Skipped -Because 'the NetSecurity module is not available on this host'
            return
        }
        foreach ($call in $script:WorkerCalls) {
            $command = Get-Command -Name $call.Name -ErrorAction Stop
            $used = @($call.Parameters | Where-Object { $_ -ne 'ErrorAction' })
            $command.Parameters.ContainsKey('ErrorAction') | Should -BeTrue -Because "$($call.Name) takes the common parameters"
            $bindable = @($command.ParameterSets | Where-Object {
                    $set = $_
                    $names = @($set.Parameters | ForEach-Object { $_.Name })
                    $missing = @($used | Where-Object { $_ -notin $names })
                    $stillMandatory = @($set.Parameters | Where-Object { $_.IsMandatory -and $_.Name -notin $used })
                    ($missing.Count -eq 0) -and ($stillMandatory.Count -eq 0)
                })
            $bindable.Count | Should -BeGreaterThan 0 -Because "$($call.Name) -$($used -join ' -') must fit one parameter set of the real cmdlet with nothing else mandatory"
        }
    }

    It 'binds the one Get-AppxPackage call of the worker, -AllUsers, to a parameter set of the real cmdlet that needs nothing else' {
        $appxCalls = @($script:CallsWorkerBlock.Ast.FindAll({ param($node) ($node -is [System.Management.Automation.Language.CommandAst]) -and ($node.GetCommandName() -eq 'Get-AppxPackage') }, $true))
        $appxCalls.Count | Should -Be 1
        $used = @($appxCalls[0].CommandElements | Where-Object { $_ -is [System.Management.Automation.Language.CommandParameterAst] } | ForEach-Object { $_.ParameterName } | Where-Object { $_ -ne 'ErrorAction' })
        $used | Should -Be @('AllUsers')

        $real = Get-Command -Name 'Get-AppxPackage' -ErrorAction SilentlyContinue
        if ($null -eq $real) {
            Set-ItResult -Skipped -Because 'the Appx module is not available on this host'
            return
        }
        $real.Parameters.ContainsKey('ErrorAction') | Should -BeTrue
        $bindable = @($real.ParameterSets | Where-Object {
                $set = $_
                $names = @($set.Parameters | ForEach-Object { $_.Name })
                $missing = @($used | Where-Object { $_ -notin $names })
                $stillMandatory = @($set.Parameters | Where-Object { $_.IsMandatory -and $_.Name -notin $used })
                ($missing.Count -eq 0) -and ($stillMandatory.Count -eq 0)
            })
        $bindable.Count | Should -BeGreaterThan 0 -Because 'Get-AppxPackage -AllUsers must fit one parameter set of the real cmdlet with nothing else mandatory'
    }

    It 'has the fake cmdlets take the same parameters the worker passes, so the fakes bind like the real ones' {
        Install-FakeNetSecurity -Module $script:Module
        try {
            foreach ($name in $script:Fw.CmdletCallOrder) {
                $fake = & $script:Module { param($n) Get-Command -Name $n -CommandType Function } $name
                $fake.ScriptBlock.ToString() | Should -Match 'FakeFirewallState'
                $fake.Parameters.ContainsKey('PolicyStore') | Should -BeTrue -Because $name
                $fake.Parameters.ContainsKey('ErrorAction') | Should -BeTrue -Because "$name is an advanced function"
            }
            $appxFake = & $script:Module { Get-Command -Name 'Get-AppxPackage' -CommandType Function }
            $appxFake.ScriptBlock.ToString() | Should -Match 'FakeFirewallState'
            $appxFake.Parameters.ContainsKey('AllUsers') | Should -BeTrue
            $appxFake.Parameters.ContainsKey('ErrorAction') | Should -BeTrue
            $ruleFake = & $script:Module { Get-Command -Name 'Get-NetFirewallRule' -CommandType Function }
            $ruleFake.Parameters.ContainsKey('TracePolicyStore') | Should -BeTrue
        } finally {
            Uninstall-FakeNetSecurity -Module $script:Module
        }
    }
}

Describe 'Complete-FirewallInventoryComputer - a successful worker object' {
    BeforeAll {
        $script:Worker = Get-FakeWorkerObject
        $script:RunFolder = Get-TestRunFolder
        $script:Row = Invoke-CompleteInModule -WorkerObject $script:Worker -RequestedName 'fakehost' -Transport 'WinRM' -RunFolder $script:RunFolder
        $script:Dir = $script:Row.OutputFolder
        $script:RulesText = Get-Content -LiteralPath (Join-Path $script:Dir 'rules.json') -Raw
        $script:RulesJson = @(ConvertFrom-JsonArray -Text $script:RulesText)
        $script:RulesCsv = @(Import-Csv -LiteralPath (Join-Path $script:Dir 'rules.csv'))
        $script:ByName = @{}
        foreach ($jsonRule in $script:RulesJson) { $script:ByName[$jsonRule.Name] = $jsonRule }
        $script:CsvByName = @{}
        foreach ($csvRule in $script:RulesCsv) { $script:CsvByName[$csvRule.Name] = $csvRule }
    }

    It 'gives Status Success, the requested name, the worker counts and the RemoteFirewall.Result type' {
        $script:Row.Status | Should -Be 'Success'
        $script:Row.PSObject.TypeNames[0] | Should -Be 'RemoteFirewall.Result'
        $script:Row.ComputerName | Should -BeExactly 'fakehost'
        $script:Row.ComputerId | Should -Be '11111111-2222-3333-4444-555555555555'
        $script:Row.Transport | Should -Be 'WinRM'
        $script:Row.IsElevated | Should -BeTrue
        $script:Row.ProfileCount | Should -Be 3
        $script:Row.RuleCount | Should -Be 7
        $script:Row.FilterFailedCount | Should -Be 0
        $script:Row.SddlFailedCount | Should -Be 0
        $script:Row.AccountCount | Should -Be 5
        $script:Row.AccountUnresolvedCount | Should -Be 4
        $script:Row.ErrorCount | Should -Be 0
        $script:Row.Error | Should -BeExactly ''
        @($script:Row.PSObject.Properties.Name) | Should -Be $script:Fw.ResultRowProperties
    }

    It 'names the folder after the reported computer name in upper case, the build and a UTC stamp, under the run folder' {
        (Split-Path -Path $script:Dir -Leaf) | Should -MatchExactly '^FAKEHOST01_20348_\d{8}-\d{6}Z$'
        (Split-Path -Path $script:Dir -Parent) | Should -Be $script:RunFolder
    }

    It 'writes exactly the nine files of the per-computer folder' {
        @(Get-ChildItem -LiteralPath $script:Dir -File | ForEach-Object { $_.Name } | Sort-Object) | Should -Be @(
            'accounts.csv', 'accounts.json', 'globalsettings.json', 'profiles.csv', 'profiles.json', 'rules.csv', 'rules.json', 'summary.json', 'system.json'
        )
    }

    It 'writes json without a byte order mark and csv with one' {
        foreach ($name in @('accounts.json', 'globalsettings.json', 'profiles.json', 'rules.json', 'summary.json', 'system.json')) {
            $bytes = [System.IO.File]::ReadAllBytes((Join-Path $script:Dir $name))
            ($bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) | Should -BeFalse -Because $name
        }
        foreach ($name in @('accounts.csv', 'profiles.csv', 'rules.csv')) {
            $bytes = [System.IO.File]::ReadAllBytes((Join-Path $script:Dir $name))
            $bytes[0] | Should -Be 0xEF -Because $name
            $bytes[1] | Should -Be 0xBB -Because $name
            $bytes[2] | Should -Be 0xBF -Because $name
        }
    }

    Context 'rules.json' {
        It 'holds the seven rules in the order the worker gave them, each with the 42 keys of DESIGN.md section 6.3 in that order' {
            $script:RulesJson.Count | Should -Be 7
            ((@($script:RulesJson | ForEach-Object { $_.Name })) -join '|') | Should -BeExactly 'CoreNet-DHCP-In|GP-Allow-RDP-In|Hyp-Owned-Rule|Pkg-App-Rule|Sddl-User-Rule|WINRM-HTTP-In-TCP|zz-Disabled-Rule'
            foreach ($jsonRule in $script:RulesJson) {
                @($jsonRule.PSObject.Properties.Name) | Should -Be $script:Fw.RuleColumnNames -Because $jsonRule.Name
            }
        }

        It 'writes an array of zero elements as [], of one element as an array of one, and of two as both, in the order given' {
            $script:RulesText | Should -Match '"Platform":\s*\[\s*\]'
            $script:RulesText | Should -Match '"LocalPort":\s*\[\s*"3389"\s*\]'
            $script:RulesText | Should -Match '"LocalPort":\s*\[\s*"68",\s*"67"\s*\]'
            $dhcp = $script:ByName['CoreNet-DHCP-In']
            ($dhcp.Platform -is [System.Array]) | Should -BeTrue
            @($dhcp.Platform).Count | Should -Be 0
            ($script:ByName['GP-Allow-RDP-In'].LocalPort -is [System.Array]) | Should -BeTrue
            @($script:ByName['GP-Allow-RDP-In'].LocalPort) | Should -Be @('3389')
            @($dhcp.LocalPort) | Should -Be @('68', '67')
            @($script:ByName['Hyp-Owned-Rule'].RemoteAddress) | Should -Be @('10.0.0.0/8', '192.168.0.0/16')
            ($script:ByName['Hyp-Owned-Rule'].LocalPort -is [System.Array]) | Should -BeTrue
            @($script:ByName['Hyp-Owned-Rule'].LocalPort).Count | Should -Be 0
        }

        It 'writes booleans as json booleans, StatusCode as a json number and a null as null' {
            $script:RulesText | Should -Match '"LooseSourceMapping":\s*true'
            $script:RulesText | Should -Match '"LocalOnlyMapping":\s*false'
            $script:RulesText | Should -Match '"StatusCode":\s*65536'
            $script:RulesText | Should -Match '"Owner":\s*null'
            $script:ByName['WINRM-HTTP-In-TCP'].LooseSourceMapping | Should -BeOfType [bool]
            $script:ByName['WINRM-HTTP-In-TCP'].StatusCode | Should -Not -BeOfType [string]
            ($null -eq $script:ByName['Pkg-App-Rule'].Owner) | Should -BeTrue
            $script:ByName['Hyp-Owned-Rule'].Owner | Should -Be 'S-1-5-21-1111111111-2222222222-3333333333-1001'
        }

        It 'keeps text exactly as the worker gave it, a line break and a double quote included' {
            $script:ByName['CoreNet-DHCP-In'].Description | Should -BeExactly "Allows DHCP messages`r`n   for stateless auto-configuration.`tSecond line"
            $script:ByName['GP-Allow-RDP-In'].DisplayName | Should -BeExactly 'Allow "RDP", from corp'
            $script:ByName['GP-Allow-RDP-In'].PolicyStoreSource | Should -BeExactly 'Default Domain Policy'
            $script:ByName['GP-Allow-RDP-In'].PolicyStoreSourceType | Should -BeExactly 'GroupPolicy'
        }
    }

    Context 'rules.csv' {
        It 'has the 42 columns of DESIGN.md section 6.3 in that order as its header, and one line per rule' {
            @($script:RulesCsv[0].PSObject.Properties.Name) | Should -Be $script:Fw.RuleColumnNames
            $script:RulesCsv.Count | Should -Be 7
            # A description with a line break must not add a line: the file is a header and seven lines.
            @(Get-Content -LiteralPath (Join-Path $script:Dir 'rules.csv')).Count | Should -Be 8
        }

        It 'joins an array with | : zero elements give an empty cell, one gives the element, two give both in order' {
            $script:CsvByName['CoreNet-DHCP-In'].Platform | Should -BeExactly ''
            $script:CsvByName['CoreNet-DHCP-In'].EnforcementStatus | Should -BeExactly ''
            $script:CsvByName['GP-Allow-RDP-In'].LocalPort | Should -BeExactly '3389'
            $script:CsvByName['GP-Allow-RDP-In'].Platform | Should -BeExactly '6.0+|10.0+'
            $script:CsvByName['CoreNet-DHCP-In'].LocalPort | Should -BeExactly '68|67'
            $script:CsvByName['Hyp-Owned-Rule'].RemoteAddress | Should -BeExactly '10.0.0.0/8|192.168.0.0/16'
            $script:CsvByName['Hyp-Owned-Rule'].LocalPort | Should -BeExactly ''
        }

        It 'collapses whitespace runs in a text cell so the row stays on one line, and keeps a comma and a double quote' {
            $script:CsvByName['CoreNet-DHCP-In'].Description | Should -BeExactly 'Allows DHCP messages for stateless auto-configuration. Second line'
            $script:CsvByName['GP-Allow-RDP-In'].DisplayName | Should -BeExactly 'Allow "RDP", from corp'
        }

        It 'writes a null as an empty cell and booleans and numbers as their text' {
            $script:CsvByName['Pkg-App-Rule'].Owner | Should -BeExactly ''
            $script:CsvByName['WINRM-HTTP-In-TCP'].PackageFamilyName | Should -BeExactly ''
            $script:CsvByName['Pkg-App-Rule'].PackageFamilyName | Should -BeExactly 'Contoso.App_abc'
            $script:CsvByName['WINRM-HTTP-In-TCP'].LooseSourceMapping | Should -BeExactly 'True'
            $script:CsvByName['Sddl-User-Rule'].OverrideBlockRules | Should -BeExactly 'True'
            $script:CsvByName['Sddl-User-Rule'].LocalOnlyMapping | Should -BeExactly 'False'
            $script:CsvByName['Sddl-User-Rule'].StatusCode | Should -BeExactly '65536'
        }

        It 'follows the rule order of the worker' {
            ((@($script:RulesCsv | ForEach-Object { $_.Name })) -join '|') | Should -BeExactly 'CoreNet-DHCP-In|GP-Allow-RDP-In|Hyp-Owned-Rule|Pkg-App-Rule|Sddl-User-Rule|WINRM-HTTP-In-TCP|zz-Disabled-Rule'
        }
    }

    Context 'profiles.json and profiles.csv' {
        BeforeAll {
            $script:ProfilesText = Get-Content -LiteralPath (Join-Path $script:Dir 'profiles.json') -Raw
            $script:ProfilesJson = @(ConvertFrom-JsonArray -Text $script:ProfilesText)
            $script:ProfilesCsv = @(Import-Csv -LiteralPath (Join-Path $script:Dir 'profiles.csv'))
        }

        It 'sorts the profiles Domain, Private, Public whatever order the worker object holds them in' {
            ((@($script:Worker.Profiles | ForEach-Object { $_.Name })) -join '|') | Should -BeExactly 'Public|Domain|Private'
            ((@($script:ProfilesJson | ForEach-Object { $_.Name })) -join '|') | Should -BeExactly 'Domain|Private|Public'
            ((@($script:ProfilesCsv | ForEach-Object { $_.Name })) -join '|') | Should -BeExactly 'Domain|Private|Public'
        }

        It 'gives the 18 columns of DESIGN.md section 6.1 in that order in both files' {
            @($script:ProfilesJson[0].PSObject.Properties.Name) | Should -Be $script:Fw.ProfileColumns
            @($script:ProfilesCsv[0].PSObject.Properties.Name) | Should -Be $script:Fw.ProfileColumns
        }

        It 'writes DisabledInterfaceAliases as an array of 0, 1 and 2 elements in json and joined with | in csv' {
            @($script:ProfilesJson[0].DisabledInterfaceAliases).Count | Should -Be 0
            ($script:ProfilesJson[0].DisabledInterfaceAliases -is [System.Array]) | Should -BeTrue
            @($script:ProfilesJson[1].DisabledInterfaceAliases) | Should -Be @('Ethernet 2')
            ($script:ProfilesJson[1].DisabledInterfaceAliases -is [System.Array]) | Should -BeTrue
            @($script:ProfilesJson[2].DisabledInterfaceAliases) | Should -Be @('Wi-Fi', 'Ethernet 3')
            $script:ProfilesText | Should -Match '"DisabledInterfaceAliases":\s*\[\s*\]'
            $script:ProfilesCsv[0].DisabledInterfaceAliases | Should -BeExactly ''
            $script:ProfilesCsv[1].DisabledInterfaceAliases | Should -BeExactly 'Ethernet 2'
            $script:ProfilesCsv[2].DisabledInterfaceAliases | Should -BeExactly 'Wi-Fi|Ethernet 3'
        }

        It 'writes LogMaxSizeKilobytes as a json number and the enumerations as strings' {
            $script:ProfilesText | Should -Match '"LogMaxSizeKilobytes":\s*4096'
            $script:ProfilesJson[0].DefaultInboundAction | Should -BeExactly 'Block'
            $script:ProfilesCsv[2].LogMaxSizeKilobytes | Should -BeExactly '4096'
        }
    }

    Context 'globalsettings.json' {
        It 'holds one object with the 14 keys of DESIGN.md section 6.2 in that order, and MaxSAIdleTimeSeconds as a number' {
            $text = Get-Content -LiteralPath (Join-Path $script:Dir 'globalsettings.json') -Raw
            $settings = $text | ConvertFrom-Json
            @($settings.PSObject.Properties.Name) | Should -Be $script:Fw.SettingColumns
            $settings.ActiveProfile | Should -BeExactly 'Domain'
            $settings.Exemptions | Should -BeExactly 'None'
            $settings.EnableStatefulFtp | Should -BeExactly 'True'
            $settings.KeyEncoding | Should -BeExactly 'UTF8'
            $text | Should -Match '"MaxSAIdleTimeSeconds":\s*300'
            $text.TrimStart().StartsWith('{') | Should -BeTrue
        }
    }

    Context 'accounts.json and accounts.csv' {
        It 'writes the accounts with References as an array in json, and without References in csv' {
            $accountsText = Get-Content -LiteralPath (Join-Path $script:Dir 'accounts.json') -Raw
            $accounts = @(ConvertFrom-JsonArray -Text $accountsText)
            $accounts.Count | Should -Be 5
            @($accounts[0].PSObject.Properties.Name) | Should -Be $script:Fw.AccountColumns
            ($accounts[0].References -is [System.Array]) | Should -BeTrue
            @($accounts[0].References) | Should -Be @('Pkg-App-Rule')
            $accountsCsv = @(Import-Csv -LiteralPath (Join-Path $script:Dir 'accounts.csv'))
            $accountsCsv.Count | Should -Be 5
            @($accountsCsv[0].PSObject.Properties.Name) | Should -Be $script:Fw.AccountCsvColumns
            ($accountsCsv | Where-Object { $_.Token -eq 'S-1-5-32-544' }).Status | Should -Be 'Resolved'
            ($accountsCsv | Where-Object { $_.Token -eq 'S-1-5-32-544' }).Name | Should -Be 'BUILTIN\Administrators'
        }
    }

    Context 'summary.json' {
        BeforeAll {
            $script:SummaryText = Get-Content -LiteralPath (Join-Path $script:Dir 'summary.json') -Raw
            $script:Summary = $script:SummaryText | ConvertFrom-Json
        }

        It 'has the 18 keys of DESIGN.md section 6.4 and 12.3 in that order' {
            @($script:Summary.PSObject.Properties.Name) | Should -Be $script:Fw.SummaryKeys
        }

        It 'carries the counts, the durations and the active profile of the worker object' {
            $script:Summary.ActiveProfile | Should -Be 'Domain'
            $script:Summary.ProfileCount | Should -Be 3
            $script:Summary.RuleCount | Should -Be 7
            $script:Summary.EnabledRuleCount | Should -Be 5
            $script:Summary.FilterFailedCount | Should -Be 0
            $script:Summary.SddlFailedCount | Should -Be 0
            $script:Summary.ProfilesDurationMs | Should -Be 12
            $script:Summary.RulesDurationMs | Should -Be 340
            $script:Summary.FiltersDurationMs | Should -Be 410
            $script:Summary.AccountsDurationMs | Should -Be 25
            $script:Summary.PackageCount | Should -Be 14
            $script:Summary.PackagesDurationMs | Should -Be 75
            $script:Summary.AccountCount | Should -Be 5
            $script:Summary.AccountUnresolvedCount | Should -Be 4
        }

        It 'counts the rules by PolicyStoreSourceType, one key per value seen, sorted by key' {
            @($script:Summary.RuleCountBySourceType.PSObject.Properties.Name) | Should -Be @('GroupPolicy', 'Local')
            $script:Summary.RuleCountBySourceType.GroupPolicy | Should -Be 1
            $script:Summary.RuleCountBySourceType.Local | Should -Be 6
        }

        It 'lists the unresolved tokens and keeps the two item lists arrays when they are empty' {
            @($script:Summary.AccountUnresolvedTokens).Count | Should -Be 4
            @($script:Summary.AccountUnresolvedTokens) | Should -Contain 'S-1-5-84-0-0-0-0-0'
            @($script:Summary.AccountUnresolvedTokens) | Should -Not -Contain 'S-1-5-32-544'
            $script:SummaryText | Should -Match '"FilterFailedItems":\s*\[\s*\]'
            $script:SummaryText | Should -Match '"SddlFailedItems":\s*\[\s*\]'
        }
    }

    Context 'system.json' {
        BeforeAll {
            $script:System = Get-Content -LiteralPath (Join-Path $script:Dir 'system.json') -Raw | ConvertFrom-Json
        }

        It 'has the keys of DESIGN.md section 6.5 in that order, from the fixed name lists' {
            @($script:System.PSObject.Properties.Name) | Should -Be $script:Fw.SystemKeys
        }

        It 'carries the collector, the collector version of the manifest, the run id, the transport, the requested name and the status' {
            $script:System.Collector | Should -Be 'RemoteFirewall'
            $script:System.CollectorVersion | Should -Be (Import-PowerShellDataFile -LiteralPath $script:ManifestPath).ModuleVersion
            $script:System.RunId | Should -Be (Split-Path -Path $script:RunFolder -Leaf)
            $script:System.Transport | Should -Be 'WinRM'
            $script:System.RequestedComputerName | Should -Be 'fakehost'
            $script:System.Status | Should -Be 'Success'
            $script:System.ComputerId | Should -Be '11111111-2222-3333-4444-555555555555'
            $script:System.RuleCount | Should -Be 7
            $script:System.ActiveProfile | Should -Be 'Domain'
            @($script:System.Errors).Count | Should -Be 0
        }

        It 'carries PackageCount and PackagesDurationMs of the worker object, PackageCount right after SddlFailedCount and PackagesDurationMs right after FiltersDurationMs' {
            $script:System.PackageCount | Should -Be 14
            $script:System.PackagesDurationMs | Should -Be 75
            $names = @($script:System.PSObject.Properties.Name)
            $names[[array]::IndexOf($names, 'SddlFailedCount') + 1] | Should -Be 'PackageCount'
            $names[[array]::IndexOf($names, 'FiltersDurationMs') + 1] | Should -Be 'PackagesDurationMs'
        }
    }
}

Describe 'Complete-FirewallInventoryComputer - PackageCount and PackagesDurationMs in summary.json and system.json' {
    It 'puts PackageCount right after SddlFailedItems and PackagesDurationMs right after FiltersDurationMs in summary.json' {
        $row = Invoke-CompleteInModule -WorkerObject (Get-FakeWorkerObject)
        $names = @((Get-Content -LiteralPath (Join-Path $row.OutputFolder 'summary.json') -Raw | ConvertFrom-Json).PSObject.Properties.Name)
        $names[[array]::IndexOf($names, 'SddlFailedItems') + 1] | Should -Be 'PackageCount'
        $names[[array]::IndexOf($names, 'FiltersDurationMs') + 1] | Should -Be 'PackagesDurationMs'
    }

    It 'writes null for both keys in summary.json and system.json when the worker read no packages, and the row is still Success' {
        $worker = Get-FakeWorkerObject
        $worker.PackageCount = $null
        $worker.PackagesDurationMs = 3
        $row = Invoke-CompleteInModule -WorkerObject $worker
        $summaryText = Get-Content -LiteralPath (Join-Path $row.OutputFolder 'summary.json') -Raw
        $summaryText | Should -Match '"PackageCount":\s*null'
        $summaryText | Should -Match '"PackagesDurationMs":\s*3\b'
        $systemText = Get-Content -LiteralPath (Join-Path $row.OutputFolder 'system.json') -Raw
        $systemText | Should -Match '"PackageCount":\s*null'
        $systemText | Should -Match '"PackagesDurationMs":\s*3\b'
        $row.Status | Should -Be 'Success'
    }

    It 'writes null for both keys when the worker object has neither, the shape of a 1.0.0 worker, without failing' {
        $worker = Get-FakeWorkerObject
        $worker.PSObject.Properties.Remove('PackageCount')
        $worker.PSObject.Properties.Remove('PackagesDurationMs')
        $row = Invoke-CompleteInModule -WorkerObject $worker
        $row.Status | Should -Be 'Success'
        $summary = Get-Content -LiteralPath (Join-Path $row.OutputFolder 'summary.json') -Raw | ConvertFrom-Json
        @($summary.PSObject.Properties.Name) | Should -Be $script:Fw.SummaryKeys
        ($null -eq $summary.PackageCount) | Should -BeTrue
        ($null -eq $summary.PackagesDurationMs) | Should -BeTrue
        $system = Get-Content -LiteralPath (Join-Path $row.OutputFolder 'system.json') -Raw | ConvertFrom-Json
        @($system.PSObject.Properties.Name) | Should -Be $script:Fw.SystemKeys
        ($null -eq $system.PackageCount) | Should -BeTrue
    }
}

Describe 'Complete-FirewallInventoryComputer - the unelevated shape, four filter classes failed' {
    BeforeAll {
        $script:Worker = Get-FakeWorkerObject -Scenario FilterFailed
        $script:Row = Invoke-CompleteInModule -WorkerObject $script:Worker
        $script:Dir = $script:Row.OutputFolder
        $script:RulesText = Get-Content -LiteralPath (Join-Path $script:Dir 'rules.json') -Raw
        $script:RulesJson = @(ConvertFrom-JsonArray -Text $script:RulesText)
        $script:RulesCsv = @(Import-Csv -LiteralPath (Join-Path $script:Dir 'rules.csv'))
    }

    It 'gives Status Partial with the four classes counted and the four errors on the row' {
        $script:Row.Status | Should -Be 'Partial'
        $script:Row.FilterFailedCount | Should -Be 4
        $script:Row.RuleCount | Should -Be 7
        $script:Row.ErrorCount | Should -Be 4
        $script:Row.Error | Should -Be 'filter Address: Access is denied.'
    }

    It 'writes null, not [] and not an empty string, for the array columns of a failed class in rules.json' {
        $script:RulesText | Should -Match '"LocalPort":\s*null'
        $script:RulesText | Should -Match '"RemoteAddress":\s*null'
        $script:RulesText | Should -Match '"InterfaceAlias":\s*null'
        foreach ($jsonRule in $script:RulesJson) {
            foreach ($column in @('LocalAddress', 'RemoteAddress', 'Protocol', 'LocalPort', 'RemotePort', 'IcmpType', 'DynamicTransport', 'InterfaceAlias', 'InterfaceType')) {
                ($null -eq $jsonRule.$column) | Should -BeTrue -Because "$column of $($jsonRule.Name) is null in the file"
            }
        }
        # A genuinely empty array of another column is still [] in the same file.
        $script:RulesText | Should -Match '"Platform":\s*\[\s*\]'
    }

    It 'writes an empty cell for a failed class in rules.csv, and keeps the columns of the classes that were read' {
        foreach ($csvRule in $script:RulesCsv) {
            $csvRule.LocalPort | Should -BeExactly ''
            $csvRule.InterfaceAlias | Should -BeExactly ''
            $csvRule.Protocol | Should -BeExactly ''
        }
        ($script:RulesCsv | Where-Object { $_.Name -eq 'CoreNet-DHCP-In' }).Service | Should -BeExactly 'dhcp'
        ($script:RulesCsv | Where-Object { $_.Name -eq 'Pkg-App-Rule' }).Package | Should -BeExactly 'S-1-15-2-1234567890-1234567890-1234567890-1234567890-1234567890-1234567890-1234567890'
    }

    It 'names the four classes in summary.json in the order they were read, and the errors in system.json' {
        $summary = Get-Content -LiteralPath (Join-Path $script:Dir 'summary.json') -Raw | ConvertFrom-Json
        $summary.FilterFailedCount | Should -Be 4
        @($summary.FilterFailedItems) | Should -Be @('Address', 'Port', 'Interface', 'InterfaceType')
        $system = Get-Content -LiteralPath (Join-Path $script:Dir 'system.json') -Raw | ConvertFrom-Json
        $system.Status | Should -Be 'Partial'
        @($system.Errors).Count | Should -Be 4
        $system.FilterFailedCount | Should -Be 4
    }
}

Describe 'Complete-FirewallInventoryComputer - the rules read failed' {
    BeforeAll {
        $script:Worker = Get-FakeWorkerObject -Scenario RulesFailed
        $script:Worker.Profiles = @()
        $script:Worker.ProfileCount = 0
        $script:Row = Invoke-CompleteInModule -WorkerObject $script:Worker
        $script:Dir = $script:Row.OutputFolder
    }

    It 'gives Status Failed, RuleCount null and the reason on the row, and still writes the folder' {
        $script:Row.Status | Should -Be 'Failed'
        ($null -eq $script:Row.RuleCount) | Should -BeTrue
        ($null -eq $script:Row.FilterFailedCount) | Should -BeTrue
        ($null -eq $script:Row.SddlFailedCount) | Should -BeTrue
        $script:Row.Error | Should -Be 'rules: The CIM provider failed.'
        $script:Row.ComputerId | Should -Not -BeNullOrEmpty
        (Test-Path -LiteralPath $script:Dir) | Should -BeTrue
    }

    It 'writes rules.json and accounts.json as [] and rules.csv as a header-only file with all 42 columns' {
        (Get-Content -LiteralPath (Join-Path $script:Dir 'rules.json') -Raw) | Should -Match '^\s*\[\s*\]\s*$'
        (Get-Content -LiteralPath (Join-Path $script:Dir 'accounts.json') -Raw) | Should -Match '^\s*\[\s*\]\s*$'
        (Get-Content -LiteralPath (Join-Path $script:Dir 'profiles.json') -Raw) | Should -Match '^\s*\[\s*\]\s*$'
        $lines = @(Get-Content -LiteralPath (Join-Path $script:Dir 'rules.csv'))
        $lines.Count | Should -Be 1
        $lines[0] | Should -Be (($script:Fw.RuleColumnNames | ForEach-Object { '"' + $_ + '"' }) -join ',')
    }

    It 'writes null counts and an empty source type object in summary.json, and null counts in system.json' {
        $summaryText = Get-Content -LiteralPath (Join-Path $script:Dir 'summary.json') -Raw
        $summary = $summaryText | ConvertFrom-Json
        $summaryText | Should -Match '"RuleCount":\s*null'
        $summaryText | Should -Match '"SddlFailedCount":\s*null'
        $summaryText | Should -Match '"RuleCountBySourceType":\s*\{\s*\}'
        @($summary.PSObject.Properties.Name) | Should -Be $script:Fw.SummaryKeys
        $system = Get-Content -LiteralPath (Join-Path $script:Dir 'system.json') -Raw | ConvertFrom-Json
        ($null -eq $system.RuleCount) | Should -BeTrue
        ($null -eq $system.EnabledRuleCount) | Should -BeTrue
        $system.Status | Should -Be 'Failed'
    }
}

Describe 'Complete-FirewallInventoryComputer - settings and source types' {
    It 'does not write globalsettings.json when the worker object carries no settings, and the other eight files are still there' {
        $worker = Get-FakeWorkerObject -WorkerErrors @('settings: boom')
        $worker.Settings = $null
        $worker.ActiveProfile = $null
        $row = Invoke-CompleteInModule -WorkerObject $worker

        (Test-Path -LiteralPath (Join-Path $row.OutputFolder 'globalsettings.json')) | Should -BeFalse
        @(Get-ChildItem -LiteralPath $row.OutputFolder -File).Count | Should -Be 8
        $row.Status | Should -Be 'Partial'
        $summary = Get-Content -LiteralPath (Join-Path $row.OutputFolder 'summary.json') -Raw | ConvertFrom-Json
        ($null -eq $summary.ActiveProfile) | Should -BeTrue
    }

    It 'counts the source types sorted by key with ordinal comparison, and leaves a rule without a source type out of the counts' {
        $worker = Get-FakeWorkerObject
        $worker.Rules = @(
            (Get-FakeHostRule -Name 'r1' -Set @{ PolicyStoreSourceType = 'Local' }),
            (Get-FakeHostRule -Name 'r2' -Set @{ PolicyStoreSourceType = 'alpha' }),
            (Get-FakeHostRule -Name 'r3' -Set @{ PolicyStoreSourceType = 'GroupPolicy' }),
            (Get-FakeHostRule -Name 'r4' -Set @{ PolicyStoreSourceType = $null }),
            (Get-FakeHostRule -Name 'r5' -Set @{ PolicyStoreSourceType = '' }),
            (Get-FakeHostRule -Name 'r6' -Set @{ PolicyStoreSourceType = 'Local' }),
            (Get-FakeHostRule -Name 'r7' -Set @{ PolicyStoreSourceType = 'Dynamic' })
        )
        $worker.RuleCount = 7
        $row = Invoke-CompleteInModule -WorkerObject $worker

        $summary = Get-Content -LiteralPath (Join-Path $row.OutputFolder 'summary.json') -Raw | ConvertFrom-Json
        @($summary.RuleCountBySourceType.PSObject.Properties.Name) | Should -Be @('Dynamic', 'GroupPolicy', 'Local', 'alpha')
        $summary.RuleCountBySourceType.Dynamic | Should -Be 1
        $summary.RuleCountBySourceType.GroupPolicy | Should -Be 1
        $summary.RuleCountBySourceType.Local | Should -Be 2
        $summary.RuleCountBySourceType.alpha | Should -Be 1
        $summary.RuleCount | Should -Be 7
    }

    It 'keeps a one-element FilterFailedItems and SddlFailedItems as arrays in summary.json' {
        $worker = Get-FakeWorkerObject -SddlFailedCount 1 -WorkerErrors @('sddl r RemoteUser: bad', 'filter Port: denied')
        $worker.FilterFailedItems = @('Port')
        $worker.FilterFailedCount = 1
        $worker.SddlFailedItems = @('r:RemoteUser')
        $row = Invoke-CompleteInModule -WorkerObject $worker

        $text = Get-Content -LiteralPath (Join-Path $row.OutputFolder 'summary.json') -Raw
        $text | Should -Match '"FilterFailedItems":\s*\[\s*"Port"\s*\]'
        $text | Should -Match '"SddlFailedItems":\s*\[\s*"r:RemoteUser"\s*\]'
    }

    It 'never changes the Status the worker object earned when a host-side write fails, and records the failure in Errors and in system.json' {
        Mock -ModuleName RemoteFirewall -CommandName Write-FirewallInventoryTextFile -MockWith {
            if ($Path -like '*rules.json') { throw 'simulated disk failure' }
            [System.IO.File]::WriteAllText($Path, $Content)
        }
        $row = Invoke-CompleteInModule -WorkerObject (Get-FakeWorkerObject)

        $row.Status | Should -Be 'Success'
        $row.ErrorCount | Should -Be 1
        $row.Errors[0] | Should -Match 'write rules.json'
        $row.Error | Should -Match 'write rules.json'
        $system = Get-Content -LiteralPath (Join-Path $row.OutputFolder 'system.json') -Raw | ConvertFrom-Json
        $system.Status | Should -Be 'Success'
        @($system.Errors).Count | Should -Be 1
    }

    It 'gives a Failed row with no folder and the reason when there is no worker object' {
        $row = Invoke-CompleteInModule -WorkerObject $null -ExtraErrors @('nothing came back')

        $row.Status | Should -Be 'Failed'
        $row.OutputFolder | Should -BeExactly ''
        $row.ComputerId | Should -BeNull
        $row.Error | Should -Be 'nothing came back'
        $row.ErrorCount | Should -Be 1
    }
}

Describe 'Status matrix, DESIGN.md section 8' {
    # Failed: no worker object, or RuleCount null or 0. Success: FilterFailedCount and SddlFailedCount present and 0 and the worker Errors empty. Partial: anything else.
    It 'gives <Expected> for <Case>' -ForEach @(
        @{ Case = 'no worker object'; Expected = 'Failed'; NoWorker = $true; Set = @{} }
        @{ Case = 'RuleCount null, everything else clean'; Expected = 'Failed'; NoWorker = $false; Set = @{ RuleCount = $null; Rules = @(); EnabledRuleCount = $null } }
        @{ Case = 'RuleCount 0, everything else clean'; Expected = 'Failed'; NoWorker = $false; Set = @{ RuleCount = 0; Rules = @(); EnabledRuleCount = 0 } }
        @{ Case = 'RuleCount 0 and a worker error'; Expected = 'Failed'; NoWorker = $false; Set = @{ RuleCount = 0; Rules = @(); Errors = @('rules: nothing') } }
        @{ Case = 'no failed class, no SDDL failure, no error'; Expected = 'Success'; NoWorker = $false; Set = @{} }
        @{ Case = 'unresolved accounts only (NotFound is data)'; Expected = 'Success'; NoWorker = $false; Set = @{ AccountUnresolvedCount = 4 } }
        @{ Case = 'an Errors list of blank entries only'; Expected = 'Success'; NoWorker = $false; Set = @{ Errors = @('', $null) } }
        @{ Case = 'FilterFailedCount 1 and an empty Errors list'; Expected = 'Partial'; NoWorker = $false; Set = @{ FilterFailedCount = 1; FilterFailedItems = @('Port') } }
        @{ Case = 'SddlFailedCount 1 and an empty Errors list'; Expected = 'Partial'; NoWorker = $false; Set = @{ SddlFailedCount = 1; SddlFailedItems = @('r:LocalUser') } }
        @{ Case = 'a worker error and both counts 0'; Expected = 'Partial'; NoWorker = $false; Set = @{ Errors = @('settings: no object returned') } }
        @{ Case = 'FilterFailedCount null with rules present'; Expected = 'Partial'; NoWorker = $false; Set = @{ FilterFailedCount = $null } }
        @{ Case = 'SddlFailedCount null with rules present'; Expected = 'Partial'; NoWorker = $false; Set = @{ SddlFailedCount = $null } }
        @{ Case = 'all seven filter classes failed'; Expected = 'Partial'; NoWorker = $false; Set = @{ FilterFailedCount = 7; FilterFailedItems = @('Address', 'Port', 'Application', 'Service', 'Interface', 'InterfaceType', 'Security') } }
        @{ Case = 'the profiles read failed but the rules were read'; Expected = 'Partial'; NoWorker = $false; Set = @{ Profiles = @(); ProfileCount = 0; Errors = @('profiles: boom') } }
    ) {
        if ($NoWorker) {
            $row = Invoke-CompleteInModule -WorkerObject $null -ExtraErrors @('no worker object came back')
        } else {
            $worker = Get-FakeWorkerObject
            foreach ($key in $Set.Keys) { $worker.$key = $Set[$key] }
            $row = Invoke-CompleteInModule -WorkerObject $worker
        }
        $row.Status | Should -Be $Expected
        if (-not $NoWorker) {
            $system = Get-Content -LiteralPath (Join-Path $row.OutputFolder 'system.json') -Raw | ConvertFrom-Json
            $system.Status | Should -Be $Expected
        }
    }

    It 'gives Partial for a real unelevated shape: the Address, Port, Interface and InterfaceType classes named' {
        $row = Invoke-CompleteInModule -WorkerObject (Get-FakeWorkerObject -Scenario FilterFailed)
        $row.Status | Should -Be 'Partial'
        $row.FilterFailedCount | Should -Be 4
    }

    It 'gives Failed and no ComputerId for a target that was never reached, and Failed with the ComputerId for one that answered with zero rules' {
        $unreached = Invoke-CompleteInModule -WorkerObject $null -ExtraErrors @('unreachable')
        $unreached.OutputFolder | Should -BeExactly ''
        $unreached.ComputerId | Should -BeNull

        $worker = Get-FakeWorkerObject
        $worker.RuleCount = 0
        $worker.Rules = @()
        $zero = Invoke-CompleteInModule -WorkerObject $worker
        $zero.Status | Should -Be 'Failed'
        $zero.ComputerId | Should -Not -BeNullOrEmpty
    }
}

Describe 'The rules.csv column list is written twice' {
    BeforeAll {
        # Complete-FirewallInventoryComputer holds $ruleColumns and ConvertTo-FirewallInventoryRuleCsvRow holds $columns: the same 42 names, typed out in two files. Read straight from the source text, so a name added to one and not the other is caught.
        function Get-AssignedStringList {
            param([string]$Path, [string]$Variable)
            $tokens = $null
            $parseErrors = $null
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$parseErrors)
            $found = @($ast.FindAll({
                        param($node)
                        $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and
                        $node.Left -is [System.Management.Automation.Language.VariableExpressionAst] -and
                        $node.Left.VariablePath.UserPath -eq $Variable
                    }, $true))
            $found.Count | Should -Be 1 -Because "$Variable is assigned once in $Path"
            return @($found[0].Right.Expression.SafeGetValue())
        }
        $script:SourceFolder = Join-Path -Path $script:ModuleFolder -ChildPath 'src\ps1'
    }

    It 'has the same list, in the same order, in both functions, and it is the 42 names of DESIGN.md section 6.3' {
        $inComplete = Get-AssignedStringList -Path (Join-Path $script:SourceFolder 'Complete-FirewallInventoryComputer.ps1') -Variable 'ruleColumns'
        $inCsvRow = Get-AssignedStringList -Path (Join-Path $script:SourceFolder 'ConvertTo-FirewallInventoryRuleCsvRow.ps1') -Variable 'columns'

        $inComplete.Count | Should -Be 42
        $inCsvRow.Count | Should -Be 42
        ($inComplete -join '|') | Should -BeExactly ($inCsvRow -join '|')
        ($inComplete -join '|') | Should -BeExactly ($script:Fw.RuleColumnNames -join '|')
    }

    It 'has the array columns of Complete-FirewallInventoryComputer equal to the array columns of DESIGN.md' {
        $arrayColumns = Get-AssignedStringList -Path (Join-Path $script:SourceFolder 'Complete-FirewallInventoryComputer.ps1') -Variable 'ruleArrayColumns'
        ((@($arrayColumns) | Sort-Object) -join '|') | Should -BeExactly ((@($script:Fw.RuleArrayColumnNames) | Sort-Object) -join '|')
        ((@($script:Fw.RuleColumns | Where-Object { $_.Kind -eq 'Array' } | ForEach-Object { $_.Name }) | Sort-Object) -join '|') | Should -BeExactly ((@($arrayColumns) | Sort-Object) -join '|')
    }

    It 'gives the same columns from what each function does: the header of rules.csv and the row of ConvertTo-FirewallInventoryRuleCsvRow' {
        $row = Invoke-CompleteInModule -WorkerObject (Get-FakeWorkerObject)
        $header = @(Import-Csv -LiteralPath (Join-Path $row.OutputFolder 'rules.csv'))[0].PSObject.Properties.Name
        $csvRow = & $script:Module { param($r) ConvertTo-FirewallInventoryRuleCsvRow -Rule $r } (Get-FakeHostRule -Name 'x')

        @($header) | Should -Be $script:Fw.RuleColumnNames
        @($csvRow.PSObject.Properties.Name) | Should -Be $script:Fw.RuleColumnNames
    }
}

Describe 'ConvertTo-FirewallInventoryRuleCsvRow' {
    BeforeAll {
        function Invoke-CsvRow {
            param([AllowNull()]$Rule)
            & $script:Module { param($r) ConvertTo-FirewallInventoryRuleCsvRow -Rule $r } $Rule
        }
    }

    It 'gives the 42 columns in order for a full rule and nothing else' {
        $row = Invoke-CsvRow -Rule (Get-FakeHostRule -Name 'x')
        @($row.PSObject.Properties.Name) | Should -Be $script:Fw.RuleColumnNames
    }

    It 'joins the <Column> array with | for 0, 1, 2 elements and for a list object' -ForEach @(
        @{ Column = 'Platform' }, @{ Column = 'EnforcementStatus' }, @{ Column = 'RemoteDynamicKeywordAddresses' }, @{ Column = 'LocalPort' }, @{ Column = 'RemotePort' },
        @{ Column = 'IcmpType' }, @{ Column = 'LocalAddress' }, @{ Column = 'RemoteAddress' }, @{ Column = 'InterfaceAlias' }
    ) {
        (Invoke-CsvRow -Rule (Get-FakeHostRule -Name 'x' -Set @{ $Column = @() })).$Column | Should -BeExactly ''
        (Invoke-CsvRow -Rule (Get-FakeHostRule -Name 'x' -Set @{ $Column = @('v1') })).$Column | Should -BeExactly 'v1'
        (Invoke-CsvRow -Rule (Get-FakeHostRule -Name 'x' -Set @{ $Column = @('v1', 'v2') })).$Column | Should -BeExactly 'v1|v2'
        $list = [System.Collections.ArrayList]::new()
        [void]$list.Add('a')
        [void]$list.Add('b')
        (Invoke-CsvRow -Rule (Get-FakeHostRule -Name 'x' -Set @{ $Column = $list })).$Column | Should -BeExactly 'a|b'
    }

    It 'keeps null as null, for an array column and a text column alike' {
        $row = Invoke-CsvRow -Rule (Get-FakeHostRule -Name 'x' -Set @{ LocalPort = $null; Description = $null; Owner = $null })
        ($null -eq $row.LocalPort) | Should -BeTrue
        ($null -eq $row.Description) | Should -BeTrue
        ($null -eq $row.Owner) | Should -BeTrue
    }

    It 'gives null for every column the rule object does not have, and for a null rule' {
        $sparse = Invoke-CsvRow -Rule ([pscustomobject]@{ Name = 'only' })
        $sparse.Name | Should -BeExactly 'only'
        foreach ($column in @($script:Fw.RuleColumnNames | Where-Object { $_ -ne 'Name' })) {
            ($null -eq $sparse.$column) | Should -BeTrue -Because $column
        }
        $none = Invoke-CsvRow -Rule $null
        @($none.PSObject.Properties.Name) | Should -Be $script:Fw.RuleColumnNames
        ($null -eq $none.Name) | Should -BeTrue
    }

    It 'collapses whitespace runs in text and in a joined array, so the row stays on one line' {
        $row = Invoke-CsvRow -Rule (Get-FakeHostRule -Name 'x' -Set @{ Description = "a  b`r`n c`td"; LocalPort = @('1  2', "3`r`n4") })
        $row.Description | Should -BeExactly 'a b c d'
        $row.LocalPort | Should -BeExactly '1 2|3 4'
    }

    It 'keeps a boolean a boolean and a number a number' {
        $row = Invoke-CsvRow -Rule (Get-FakeHostRule -Name 'x' -Set @{ LooseSourceMapping = $true; LocalOnlyMapping = $false; StatusCode = 65536; OverrideBlockRules = $true })
        $row.LooseSourceMapping | Should -BeOfType [bool]
        $row.LooseSourceMapping | Should -BeTrue
        $row.LocalOnlyMapping | Should -BeFalse
        $row.OverrideBlockRules | Should -BeTrue
        $row.StatusCode | Should -BeOfType [int]
        $row.StatusCode | Should -Be 65536
    }
}

Describe 'ConvertTo-FirewallInventoryResultRow' {
    It 'gives the 15 properties of the result row in order, with the type name RemoteFirewall.Result' {
        $row = & $script:Module { param($RequestedName) ConvertTo-FirewallInventoryResultRow -ComputerName $RequestedName -Status 'Failed' -Transport 'WinRM' -Errors @('first', 'second') } 'x'

        $row.PSObject.TypeNames[0] | Should -Be 'RemoteFirewall.Result'
        @($row.PSObject.Properties.Name) | Should -Be $script:Fw.ResultRowProperties
    }

    It 'derives Error and ErrorCount from Errors, and gives the not-reached shape when nothing else is supplied' {
        $row = & $script:Module { param($RequestedName) ConvertTo-FirewallInventoryResultRow -ComputerName $RequestedName -Status 'Failed' -Transport 'WinRM' -Errors @('first', 'second') } 'x'

        $row.Error | Should -Be 'first'
        $row.ErrorCount | Should -Be 2
        @($row.Errors) | Should -Be @('first', 'second')
        $row.OutputFolder | Should -BeExactly ''
        foreach ($name in @('ComputerId', 'IsElevated', 'ProfileCount', 'RuleCount', 'FilterFailedCount', 'SddlFailedCount', 'AccountCount', 'AccountUnresolvedCount')) {
            ($null -eq $row.$name) | Should -BeTrue -Because $name
        }
    }

    It 'gives an empty Error and an ErrorCount of 0 for no errors, and carries the four firewall counts through' {
        $row = & $script:Module {
            param($RequestedName)
            ConvertTo-FirewallInventoryResultRow -ComputerName $RequestedName -Status 'Success' -Transport 'Local' -Errors @() -ProfileCount 3 -RuleCount 574 -FilterFailedCount 0 -SddlFailedCount 2
        } 'x'

        $row.Error | Should -BeExactly ''
        $row.ErrorCount | Should -Be 0
        $row.ProfileCount | Should -Be 3
        $row.RuleCount | Should -Be 574
        $row.FilterFailedCount | Should -Be 0
        $row.SddlFailedCount | Should -Be 2
    }

    It 'collapses an Errors entry with an embedded line break to one line, in Error and in Errors' {
        $row = & $script:Module {
            param($RequestedName)
            ConvertTo-FirewallInventoryResultRow -ComputerName $RequestedName -Status 'Failed' -Transport 'WinRM' -Errors @("Connecting to remote server x failed:`r`n   WinRM  cannot process the request.`r`n", 'second')
        } 'x'

        $row.Error | Should -BeExactly 'Connecting to remote server x failed: WinRM cannot process the request.'
        @($row.Errors).Count | Should -Be 2
        $row.Errors[0] | Should -BeExactly 'Connecting to remote server x failed: WinRM cannot process the request.'
        $row.Errors[1] | Should -BeExactly 'second'
        $row.ErrorCount | Should -Be 2
    }
}

Describe 'The worker and the host joined, over fake NetSecurity cmdlets' {
    BeforeAll {
        Install-FakeNetSecurity -Module $script:Module
        Mock -ModuleName RemoteFirewall -CommandName Get-CimInstance -MockWith {
            switch ($ClassName) {
                'Win32_OperatingSystem' { [pscustomobject]@{ Caption = 'Fake OS'; Version = '10.0.1' } }
                'Win32_ComputerSystem' { [pscustomobject]@{ DNSHostName = 'fakehost'; Domain = 'corp.example'; PartOfDomain = $true; DomainRole = [uint16]3 } }
                'Win32_ComputerSystemProduct' { [pscustomobject]@{ UUID = 'AAAA' } }
                default { throw "unexpected CIM class $ClassName" }
            }
        }
    }

    AfterAll {
        Uninstall-FakeNetSecurity -Module $script:Module
    }

    Context 'every array column with 0, 1 and 2 elements, in rules.json and in rules.csv' {
        BeforeAll {
            $state = Get-FakeFirewallState
            foreach ($case in $script:Fw.ArrayCases) {
                $ruleSet = @{}
                $filterSet = @{}
                if ($case.Source -eq 'Rule') {
                    $ruleSet[$case.Column] = $case.Value
                } else {
                    $filterSet[$case.Source] = @{ $case.Column = $case.Value }
                }
                Add-FakeFirewallRule -State $state -Name ('Arr-{0:000}' -f $case.Id) -RuleSet $ruleSet -FilterSet $filterSet
            }
            # An empty array and an absent property side by side in one file: [] against null.
            Add-FakeFirewallRule -State $state -Name 'Zzz-Empty' -FilterSet @{ Port = @{ LocalPort = [string[]]@() } }
            Add-FakeFirewallRule -State $state -Name 'Zzz-Absent' -FilterOmit @{ Port = @('LocalPort') }
            $worker = Get-WorkerResult -State $state
            $script:Row = Invoke-CompleteInModule -WorkerObject $worker
            $script:JsonText = Get-Content -LiteralPath (Join-Path $script:Row.OutputFolder 'rules.json') -Raw
            $script:JsonByName = @{}
            foreach ($jsonRule in @(ConvertFrom-JsonArray -Text $script:JsonText)) { $script:JsonByName[$jsonRule.Name] = $jsonRule }
            $script:CsvByName = @{}
            foreach ($csvRule in @(Import-Csv -LiteralPath (Join-Path $script:Row.OutputFolder 'rules.csv'))) { $script:CsvByName[$csvRule.Name] = $csvRule }
        }

        It 'reads every case rule, all with Status Success' {
            $script:Row.RuleCount | Should -Be ($script:Fw.ArrayCases.Count + 2)
            $script:Row.Status | Should -Be 'Success'
        }

        It 'writes <Column> as a json array for <Label> (case <Id>)' -ForEach $ArrayColumnCases {
            $case = $script:Fw.ArrayCases | Where-Object { $_.Id -eq $Id }
            $value = $script:JsonByName[('Arr-{0:000}' -f $Id)].$Column
            ($value -is [System.Array]) | Should -BeTrue -Because "$Column is an array in the file, not a string or null"
            @($value).Count | Should -Be @($case.Expected).Count
            for ($i = 0; $i -lt @($case.Expected).Count; $i++) { $value[$i] | Should -BeExactly $case.Expected[$i] }
        }

        It 'writes <Column> joined with | in csv for <Label> (case <Id>)' -ForEach $ArrayColumnCases {
            $case = $script:Fw.ArrayCases | Where-Object { $_.Id -eq $Id }
            $script:CsvByName[('Arr-{0:000}' -f $Id)].$Column | Should -BeExactly (@($case.Expected) -join '|')
        }

        It 'writes [] for an empty array and null for an absent property in the same file, and an empty cell for both in csv' {
            ($script:JsonByName['Zzz-Empty'].LocalPort -is [System.Array]) | Should -BeTrue
            @($script:JsonByName['Zzz-Empty'].LocalPort).Count | Should -Be 0
            ($null -eq $script:JsonByName['Zzz-Absent'].LocalPort) | Should -BeTrue
            $script:JsonText | Should -Match '"LocalPort":\s*null'
            $script:JsonText | Should -Match '"LocalPort":\s*\[\s*\]'
            $script:CsvByName['Zzz-Empty'].LocalPort | Should -BeExactly ''
            $script:CsvByName['Zzz-Absent'].LocalPort | Should -BeExactly ''
        }
    }

    Context 'a failed filter class, read by the real worker and written by the real host' {
        BeforeAll {
            $state = Get-FakeFirewallState
            Add-FakeFirewallRule -State $state -Name 'E2E-A' -FilterSet @{ Port = @{ LocalPort = [string[]]@('80', '443') } }
            Add-FakeFirewallRule -State $state -Name 'E2E-B'
            $state.Fail['Port'] = 'Access is denied.'
            $state.Fail['Address'] = 'Access is denied.'
            $worker = Get-WorkerResult -State $state
            $script:Row = Invoke-CompleteInModule -WorkerObject $worker
            $script:JsonText = Get-Content -LiteralPath (Join-Path $script:Row.OutputFolder 'rules.json') -Raw
            $script:Summary = Get-Content -LiteralPath (Join-Path $script:Row.OutputFolder 'summary.json') -Raw | ConvertFrom-Json
        }

        It 'is Partial, with the two classes named in the row, in summary.json and in the errors' {
            $script:Row.Status | Should -Be 'Partial'
            $script:Row.FilterFailedCount | Should -Be 2
            @($script:Summary.FilterFailedItems) | Should -Be @('Address', 'Port')
            $script:Summary.FilterFailedCount | Should -Be 2
            @($script:Row.Errors) | Should -Be @('filter Address: Access is denied.', 'filter Port: Access is denied.')
        }

        It 'writes null for the columns of the failed classes and the values of the others' {
            $script:JsonText | Should -Match '"LocalPort":\s*null'
            $script:JsonText | Should -Match '"LocalAddress":\s*null'
            $script:JsonText | Should -Not -Match '"LocalPort":\s*\['
            $script:JsonText | Should -Match '"Service":\s*"Any"'
        }
    }

    Context 'an id shared by two rules that cannot be told apart, read by the real worker and written by the real host' {
        BeforeAll {
            $state = Get-FakeFirewallState
            Add-SharedIdRule -State $state -Number 1
            Add-SharedIdRule -State $state -Number 2
            Add-FakeFirewallRule -State $state -Name 'Unique-Id' -FilterSet @{ Port = @{ LocalPort = [string[]]@('7777') } }
            $portFilters = @($state.Filters['Port'])
            $state.Filters['Port'] = @($portFilters[2], $portFilters[0], $portFilters[1])
            $worker = Get-WorkerResult -State $state
            $script:Row = Invoke-CompleteInModule -WorkerObject $worker
            $script:JsonText = Get-Content -LiteralPath (Join-Path $script:Row.OutputFolder 'rules.json') -Raw
            $script:Summary = Get-Content -LiteralPath (Join-Path $script:Row.OutputFolder 'summary.json') -Raw | ConvertFrom-Json
        }

        It 'is Partial through the error, with no failed class counted' {
            $script:Row.Status | Should -Be 'Partial'
            $script:Row.FilterFailedCount | Should -Be 0
            $script:Row.SddlFailedCount | Should -Be 0
            @($script:Row.Errors) | Should -Be @('filter Port: ambiguous InstanceID Shared-Id')
            @($script:Summary.FilterFailedItems).Count | Should -Be 0
        }

        It 'writes null for the Port columns of the two rules with the shared id and the value of the rule with a unique id' {
            $rules = @(ConvertFrom-JsonArray -Text $script:JsonText)
            $rules.Count | Should -Be 3
            $byKey = @{}
            foreach ($rule in $rules) { $byKey[('{0}|{1}' -f $rule.Name, $rule.PolicyStoreSourceType)] = $rule }
            ($null -eq $byKey['Shared-Id|Local'].LocalPort) | Should -BeTrue
            ($null -eq $byKey['Shared-Id|GroupPolicy'].LocalPort) | Should -BeTrue
            @($byKey['Unique-Id|Local'].LocalPort) | Should -Be @('7777')
            $byKey['Shared-Id|Local'].Program | Should -BeExactly 'C:\Local.exe'
            $byKey['Shared-Id|GroupPolicy'].Program | Should -BeExactly 'C:\Gpo.exe'
        }
    }

    Context 'a number above the signed 64-bit range' {
        BeforeAll {
            $state = Get-FakeFirewallState
            $state.Profiles = @(
                (Get-FakeFirewallProfile -Name 'Domain' -Set @{ LogMaxSizeKilobytes = [uint64]::MaxValue }),
                (Get-FakeFirewallProfile -Name 'Private' -Set @{ LogMaxSizeKilobytes = [uint64]4096 }),
                (Get-FakeFirewallProfile -Name 'Public' -Set @{ LogMaxSizeKilobytes = [uint64]::MaxValue })
            )
            Add-FakeFirewallRule -State $state -Name 'Num-A'
            $script:Worker = Get-WorkerResult -State $state
        }

        It 'keeps the largest UInt64 as that number in the worker object, and a UInt32 as a number' {
            $domain = $script:Worker.Profiles | Where-Object { $_.Name -eq 'Domain' }
            $domain.LogMaxSizeKilobytes | Should -BeOfType [uint64]
            $domain.LogMaxSizeKilobytes | Should -Be ([uint64]::MaxValue)
            $script:Worker.Rules[0].StatusCode | Should -Be 65536
        }

        It 'writes 18446744073709551615 in profiles.json and 65536 as StatusCode in rules.json, live and after a PSSerializer round trip' {
            $roundTrip = [System.Management.Automation.PSSerializer]::Deserialize([System.Management.Automation.PSSerializer]::Serialize($script:Worker, 4))
            foreach ($worker in @($script:Worker, $roundTrip)) {
                $row = Invoke-CompleteInModule -WorkerObject $worker
                $profilesText = Get-Content -LiteralPath (Join-Path $row.OutputFolder 'profiles.json') -Raw
                $profilesText | Should -Match '"LogMaxSizeKilobytes":\s*18446744073709551615\b'
                ([regex]::Matches($profilesText, '"LogMaxSizeKilobytes":\s*18446744073709551615\b')).Count | Should -Be 2
                $profilesText | Should -Match '"LogMaxSizeKilobytes":\s*4096\b'
                $profilesText | Should -Not -Match '"LogMaxSizeKilobytes":\s*null'
                (Get-Content -LiteralPath (Join-Path $row.OutputFolder 'rules.json') -Raw) | Should -Match '"StatusCode":\s*65536\b'
                $profilesCsv = @(Import-Csv -LiteralPath (Join-Path $row.OutputFolder 'profiles.csv'))
                $profilesCsv[0].LogMaxSizeKilobytes | Should -BeExactly '18446744073709551615'
            }
        }
    }

    Context 'the public function on a local target, with the worker not mocked' {
        BeforeAll {
            $state = Get-FakeFirewallState
            Add-FakeFirewallRule -State $state -Name 'Pub-A' -RuleSet @{ Owner = 'S-1-5-18' }
            Add-FakeFirewallRule -State $state -Name 'Pub-B' -RuleSet @{ Enabled = [RemoteFirewallTests.FwBool]::False }
            Use-FakeFirewallState -Module $script:Module -State $state
            $outPath = Join-Path -Path $TestDrive -ChildPath ([guid]::NewGuid().ToString('N'))
            # -SkipSidReference: the identity mock of this Describe names a domain the test host is not in, and a read would send a real account lookup to it.
            $script:Rows = @(Get-FirewallInventory -ComputerName $env:COMPUTERNAME -OutputPath $outPath -SkipSidReference)
        }

        It 'gives one Success row with the counts of the fake target and all nine files' {
            $script:Rows.Count | Should -Be 1
            $script:Rows[0].Status | Should -Be 'Success'
            $script:Rows[0].Transport | Should -Be 'Local'
            $script:Rows[0].ProfileCount | Should -Be 3
            $script:Rows[0].RuleCount | Should -Be 2
            $script:Rows[0].AccountCount | Should -Be 1
            @(Get-ChildItem -LiteralPath $script:Rows[0].OutputFolder -File).Count | Should -Be 9
            (Get-Content -LiteralPath (Join-Path $script:Rows[0].OutputFolder 'summary.json') -Raw | ConvertFrom-Json).EnabledRuleCount | Should -Be 1
        }
    }
}

Describe 'Get-FirewallInventory - one real local run' {
    It 'reads this host with the real NetSecurity cmdlets and agrees with a direct read on what holds elevated or not' {
        if (-not $script:NetSecurityPresent) {
            Set-ItResult -Skipped -Because 'the NetSecurity module is not available on this host'
            return
        }
        # No fake may be left in the module, or this would read fake data and pass.
        $fakeLeft = & $script:Module { (Get-Command -Name 'Get-NetFirewallRule' -CommandType Function -ErrorAction SilentlyContinue).ScriptBlock.ToString().Contains('FakeFirewallState') }
        $fakeLeft | Should -BeFalse -Because 'the real cmdlet must be the one that runs'

        $outPath = Join-Path -Path $TestDrive -ChildPath ([guid]::NewGuid().ToString('N'))
        $rows = @(Get-FirewallInventory -ComputerName $env:COMPUTERNAME -OutputPath $outPath -WarningAction SilentlyContinue)
        $directCount = @(Get-NetFirewallRule -PolicyStore ActiveStore).Count

        $rows.Count | Should -Be 1
        $rows[0].Transport | Should -Be 'Local'
        $rows[0].IsElevated | Should -BeOfType [bool]
        $rows[0].RuleCount | Should -BeGreaterThan 0
        # The collection and the direct read are two reads a few seconds apart on a live host, where a rule can be added or removed in between (a Windows update, an installer, a Store app), so the counts may differ by a few rules; 5 either way keeps the check meaningful without making it depend on a quiet host.
        $rows[0].RuleCount | Should -BeGreaterOrEqual ($directCount - 5)
        $rows[0].RuleCount | Should -BeLessOrEqual ($directCount + 5)
        $rows[0].ProfileCount | Should -Be 3
        # Elevated the run is Success, unelevated Partial (four filter classes named); either way rules were read, so never Failed.
        $rows[0].Status | Should -BeIn @('Success', 'Partial')
        $rows[0].FilterFailedCount | Should -BeIn @(0, 1, 2, 3, 4, 5, 6, 7)

        $folder = $rows[0].OutputFolder
        $rules = @(ConvertFrom-JsonArray -Text (Get-Content -LiteralPath (Join-Path $folder 'rules.json') -Raw))
        # The files and the row come from the same read, so these agree exactly.
        $rules.Count | Should -Be $rows[0].RuleCount
        @($rules[0].PSObject.Properties.Name) | Should -Be $script:Fw.RuleColumnNames
        $profiles = @(ConvertFrom-JsonArray -Text (Get-Content -LiteralPath (Join-Path $folder 'profiles.json') -Raw))
        ((@($profiles | ForEach-Object { $_.Name })) -join '|') | Should -BeExactly 'Domain|Private|Public'
        $rulesCsv = @(Import-Csv -LiteralPath (Join-Path $folder 'rules.csv'))
        $rulesCsv.Count | Should -Be $rows[0].RuleCount
        (Test-Path -LiteralPath (Join-Path $folder 'globalsettings.json')) | Should -BeTrue
    }
}
