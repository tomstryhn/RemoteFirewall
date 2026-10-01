<#PSScriptInfo

.DESCRIPTION Installs functions that shadow the ten NetSecurity cmdlets and Get-AppxPackage, which the RemoteFirewall worker calls, inside the module session state

.VERSION 1.2.0

.GUID f5bd0e7d-e268-4d08-aeca-1742f877f557

.AUTHOR Tom Stryhn

.COMPANYNAME Tom Stryhn

.COPYRIGHT 2026 (c) Tom Stryhn

.LICENSEURI https://github.com/tomstryhn/RemoteFirewall/blob/main/LICENSE

.PROJECTURI https://github.com/tomstryhn/RemoteFirewall

#>

<#
The worker scriptblock is created inside the module and resolves every command through the module's
session state, so a function defined in a test's own scope is never seen by it. Install-FakeNetSecurity
defines the ten shadowing functions, and an eleventh for Get-AppxPackage, inside the module's own scope, from script text created there, so
they resolve $script:FakeFirewallState to a module variable that Use-FakeFirewallState sets from a state
built by Get-FakeFirewallState. Uninstall-FakeNetSecurity removes the functions and the variable again,
and only removes a function that is one of these fakes, never the real cmdlet.

Each fake is an advanced function with the real parameters the worker uses (PolicyStore, and
TracePolicyStore on the rule read), so -ErrorAction binds the way it does on the real cmdlet. A failing
read calls Write-Error, not throw: a real cmdlet fails with a non-terminating error that only the
worker's -ErrorAction Stop turns into an exception, and a worker that lost that switch would leak an
error record at Continue. Every call is recorded in the state's Calls list as the cmdlet name, the
PolicyStore value, -TracePolicyStore when set, and the error action preference in force inside the fake.
#>

function Get-FakeNetSecurityDefinition {
    [CmdletBinding()]
    param()

    $readTemplate = @'
[CmdletBinding()]
param([string]$PolicyStore@@EXTRAPARAM@@)
$fakeState = $script:FakeFirewallState
$callText = '@@NAME@@ -PolicyStore ' + $PolicyStore@@TRACETEXT@@ + ' EA=' + $ErrorActionPreference
[void]$fakeState.Calls.Add($callText)
if ($fakeState.Fail.ContainsKey('@@KEY@@')) { Write-Error -Message $fakeState.Fail['@@KEY@@']; return }
@@BODY@@
'@

    $definitions = [ordered]@{}

    $profileText = $readTemplate.Replace('@@EXTRAPARAM@@', '').Replace('@@TRACETEXT@@', '').Replace('@@NAME@@', 'Get-NetFirewallProfile').Replace('@@KEY@@', 'Profile')
    $profileText = $profileText.Replace('@@BODY@@', 'foreach ($item in @($fakeState.Profiles)) { $item }')
    $definitions['Get-NetFirewallProfile'] = $profileText

    $settingText = $readTemplate.Replace('@@EXTRAPARAM@@', '').Replace('@@TRACETEXT@@', '').Replace('@@NAME@@', 'Get-NetFirewallSetting').Replace('@@KEY@@', 'Setting')
    $settingText = $settingText.Replace('@@BODY@@', 'if ($fakeState.SettingNothing) { return }' + [Environment]::NewLine + 'if ($null -ne $fakeState.Setting) { $fakeState.Setting }')
    $definitions['Get-NetFirewallSetting'] = $settingText

    $ruleText = $readTemplate.Replace('@@EXTRAPARAM@@', ', [switch]$TracePolicyStore').Replace('@@TRACETEXT@@', ' + $(if ($TracePolicyStore) { '' -TracePolicyStore'' } else { '''' })').Replace('@@NAME@@', 'Get-NetFirewallRule').Replace('@@KEY@@', 'Rule')
    $ruleText = $ruleText.Replace('@@BODY@@', 'foreach ($item in @($fakeState.Rules)) { $item }')
    $definitions['Get-NetFirewallRule'] = $ruleText

    foreach ($class in @('Address', 'Port', 'Application', 'Service', 'Interface', 'InterfaceType', 'Security')) {
        $filterText = $readTemplate.Replace('@@EXTRAPARAM@@', '').Replace('@@TRACETEXT@@', '').Replace('@@NAME@@', "Get-NetFirewall${class}Filter").Replace('@@KEY@@', $class)
        $filterText = $filterText.Replace('@@BODY@@', "foreach (`$item in @(`$fakeState.Filters['$class'])) { `$item }")
        $definitions["Get-NetFirewall${class}Filter"] = $filterText
    }

    # The eleventh shadow is not a NetSecurity cmdlet: Get-AppxPackage, so a worker run never reaches the real one (unelevated it throws Access is denied, and its answer depends on the test host). Its calls go to AppxCalls, not to Calls.
    $appxText = @'
[CmdletBinding()]
param([switch]$AllUsers)
$fakeState = $script:FakeFirewallState
$callText = 'Get-AppxPackage' + $(if ($AllUsers) { ' -AllUsers' } else { '' }) + ' EA=' + $ErrorActionPreference
[void]$fakeState.AppxCalls.Add($callText)
if ($fakeState.Appx.Mode -eq 'Throw') { throw $fakeState.Appx.Message }
if ($fakeState.Appx.Mode -eq 'Error') { Write-Error -Message $fakeState.Appx.Message; return }
foreach ($item in @($fakeState.Appx.Packages)) { $item }
'@
    $definitions['Get-AppxPackage'] = $appxText
    return $definitions
}

function Install-FakeNetSecurity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.PSModuleInfo]$Module
    )

    $definitions = Get-FakeNetSecurityDefinition
    foreach ($name in $definitions.Keys) {
        & $Module {
            param($FunctionName, $Text)
            Set-Item -Path "function:script:$FunctionName" -Value ([scriptblock]::Create($Text))
        } $name $definitions[$name]
    }
}

function Uninstall-FakeNetSecurity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.PSModuleInfo]$Module
    )

    $definitions = Get-FakeNetSecurityDefinition
    foreach ($name in $definitions.Keys) {
        & $Module {
            param($FunctionName)
            $found = Get-Command -Name $FunctionName -CommandType Function -ErrorAction SilentlyContinue
            if ($null -ne $found -and $found.ScriptBlock.ToString().Contains('FakeFirewallState')) {
                Remove-Item -Path "function:$FunctionName"
            }
        } $name
    }
    & $Module {
        if (Get-Variable -Name FakeFirewallState -Scope Script -ErrorAction SilentlyContinue) { Remove-Variable -Name FakeFirewallState -Scope Script }
    }
}

function Use-FakeFirewallState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.PSModuleInfo]$Module,

        [Parameter(Mandatory = $true)]
        [hashtable]$State
    )

    & $Module {
        param($FakeState)
        $script:FakeFirewallState = $FakeState
    } $State
}
