<#PSScriptInfo

.DESCRIPTION Builds the rules.csv row for one firewall rule

.VERSION 1.2.0

.GUID 4a9c8182-be97-4e36-9015-a2457594083e

.AUTHOR Tom Stryhn

.COMPANYNAME Tom Stryhn

.COPYRIGHT 2026 (c) Tom Stryhn

.LICENSEURI https://github.com/tomstryhn/RemoteFirewall/blob/main/LICENSE

.PROJECTURI https://github.com/tomstryhn/RemoteFirewall

#>

function ConvertTo-FirewallInventoryRuleCsvRow {

    <#
    .SYNOPSIS
        Builds the rules.csv row for one firewall rule.

    .DESCRIPTION
        Produces one flat row in the exact column order rules.csv requires, by looping over the
        column list and reading each column from the rule object. A value that is a collection
        (the array columns: Platform, EnforcementStatus, RemoteDynamicKeywordAddresses,
        LocalPort, RemotePort, IcmpType, LocalAddress, RemoteAddress, InterfaceAlias) becomes its
        elements joined with a vertical bar, so an array of one element and a plain string give
        the same cell. Whitespace runs in text cells collapse to one space so a row stays on one
        line. A null value, and a property the rule object lacks, stays null (an empty csv cell);
        booleans and numbers keep their type.

    .PARAMETER Rule
        One rule object from the Rules array of the worker object, live or after a remoting hop.

    .NOTES
        FUNCTION: ConvertTo-FirewallInventoryRuleCsvRow
        AUTHOR:   Tom Stryhn
        GITHUB:   https://github.com/tomstryhn/

    .INPUTS
        None. Does not accept pipeline input.

    .OUTPUTS
        System.Management.Automation.PSObject
    #>

    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [psobject]$Rule
    )

    $columns = @('Name', 'InstanceID', 'DisplayName', 'Description', 'Group', 'DisplayGroup', 'Enabled', 'Profile', 'Direction', 'Action', 'EdgeTraversalPolicy', 'LooseSourceMapping', 'LocalOnlyMapping', 'Owner', 'Platform', 'PolicyStoreSource', 'PolicyStoreSourceType', 'PrimaryStatus', 'Status', 'StatusCode', 'EnforcementStatus', 'PackageFamilyName', 'PolicyAppId', 'RemoteDynamicKeywordAddresses', 'Protocol', 'LocalPort', 'RemotePort', 'IcmpType', 'DynamicTransport', 'LocalAddress', 'RemoteAddress', 'Program', 'Package', 'Service', 'InterfaceAlias', 'InterfaceType', 'Authentication', 'Encryption', 'OverrideBlockRules', 'LocalUser', 'RemoteUser', 'RemoteMachine')

    # The property collection of the rule is taken once per row, not once per column.
    $ruleProperties = $null
    if ($null -ne $Rule) { $ruleProperties = $Rule.PSObject.Properties }

    $row = [ordered]@{}
    foreach ($column in $columns) {
        # Read straight from PSObject.Properties, not through Get-FirewallInventorySafeProperty: a function that returns an empty array delivers nothing, so an empty array would arrive as $null and lose its empty cell.
        $value = $null
        if ($null -ne $ruleProperties) {
            $property = $ruleProperties[$column]
            if ($null -ne $property) { $value = $property.Value }
        }

        if ($null -eq $value) {
            $row[$column] = $null
        } elseif ($value -is [string]) {
            # The common case first: a text cell, whitespace runs collapsed.
            $row[$column] = $value -replace '\s+', ' '
        } elseif ($value -is [System.Collections.IEnumerable]) {
            # A generic list, not an array grown with +=, which is quadratic over the rules of a large target.
            $items = [System.Collections.Generic.List[string]]::new()
            foreach ($item in $value) { [void]$items.Add("$item") }
            $row[$column] = ($items -join '|') -replace '\s+', ' '
        } else {
            $row[$column] = $value
        }
    }

    return [pscustomobject]$row
}
