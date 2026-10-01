<#PSScriptInfo

.DESCRIPTION Writes rows to a csv file with a UTF-8 byte order mark on both engines

.VERSION 1.2.0

.GUID 8615e063-d531-454a-aca7-1c9238c41532

.AUTHOR Tom Stryhn

.COMPANYNAME Tom Stryhn

.COPYRIGHT 2026 (c) Tom Stryhn

.LICENSEURI https://github.com/tomstryhn/RemoteFirewall/blob/main/LICENSE

.PROJECTURI https://github.com/tomstryhn/RemoteFirewall

#>

function Write-FirewallInventoryCsvFile {

    <#
    .SYNOPSIS
        Writes rows to a csv file with a UTF-8 byte order mark on both engines.

    .DESCRIPTION
        Used for every csv file the module writes (results.csv, profiles.csv, rules.csv,
        accounts.csv), so all of them are built the same way: ConvertTo-Csv -NoTypeInformation
        turns the rows into lines, and [System.IO.File]::WriteAllLines writes them with a
        UTF8Encoding whose byte order mark is on, which is what Export-Csv -Encoding UTF8 does
        not give consistently across Windows PowerShell 5.1 and PowerShell 7. An empty Row
        collection writes no lines at all unless Column is supplied, in which case a header-only
        file is built from Column instead, since ConvertTo-Csv produces nothing at all, not even
        a header, for zero input objects. Every string cell is trimmed and its whitespace runs are
        collapsed to one space first, so a row is always one line; null, an empty string, numbers
        and booleans are written as they are, and the caller's row objects are not changed.

    .PARAMETER Row
        The rows to write. May be empty.

    .PARAMETER Path
        The file to write, as a literal path.

    .PARAMETER Column
        The column names, in order, used to build a header-only file when Row is empty. Ignored
        when Row is not empty, since ConvertTo-Csv derives the header from the rows themselves.

    .NOTES
        FUNCTION: Write-FirewallInventoryCsvFile
        AUTHOR:   Tom Stryhn
        GITHUB:   https://github.com/tomstryhn/

    .INPUTS
        None. Does not accept pipeline input.

    .OUTPUTS
        None.
    #>

    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [psobject[]]$Row,

        [Parameter(Mandatory = $true)]
        [string]$Path,

        [AllowNull()]
        [string[]]$Column
    )

    $rows = @($Row | Where-Object { $null -ne $_ })

    if ($rows.Count -gt 0) {
        # One line per csv cell: a string value is trimmed and its whitespace, line breaks included, collapsed to one space, so a line break inside a value can never split a csv row. Each row's strings are scanned once; a row with no string that needs a change goes in as the caller's own object, because copying every row cost most of the time on a 20,000-row file. Only a row that needs a change is rebuilt as a new ordered object with the same property names, so the caller's objects, and the json files written from them, keep the source form. The test is any whitespace other than single inner spaces, which is exactly the set the collapse would alter. Null, an empty string, numbers and booleans pass through untouched, which keeps a null a bare cell and an empty string a quoted empty cell.
        $outputRows = [System.Collections.Generic.List[object]]::new()
        foreach ($sourceRow in $rows) {
            $needsChange = $false
            foreach ($property in $sourceRow.PSObject.Properties) {
                $cellValue = $property.Value
                if ($cellValue -is [string] -and ($cellValue -ne $cellValue.Trim() -or $cellValue -match '\s{2,}|[^\S ]')) {
                    $needsChange = $true
                    break
                }
            }
            if (-not $needsChange) {
                [void]$outputRows.Add($sourceRow)
                continue
            }
            $cleanRow = [ordered]@{}
            foreach ($property in $sourceRow.PSObject.Properties) {
                $cellValue = $property.Value
                if ($cellValue -is [string]) { $cellValue = $cellValue.Trim() -replace '\s+', ' ' }
                $cleanRow[$property.Name] = $cellValue
            }
            [void]$outputRows.Add([pscustomobject]$cleanRow)
        }
        $lines = @($outputRows.ToArray() | ConvertTo-Csv -NoTypeInformation)
    } elseif ($Column -and @($Column).Count -gt 0) {
        # A single placeholder object with every Column property set to $null, so the header line ConvertTo-Csv builds for it matches profiles.csv, rules.csv or accounts.csv exactly, without hand-quoting column names here too.
        $placeholder = [ordered]@{}
        foreach ($name in @($Column)) { $placeholder[$name] = $null }
        $headerLines = @([pscustomobject]$placeholder | ConvertTo-Csv -NoTypeInformation)
        $lines = @($headerLines | Select-Object -First 1)
    } else {
        $lines = @()
    }

    $encoding = New-Object System.Text.UTF8Encoding($true)
    [System.IO.File]::WriteAllLines($Path, $lines, $encoding)
}
