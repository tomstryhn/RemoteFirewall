# Dot-source every function file. -LiteralPath and -Filter keep an install path with brackets or other wildcard characters from being read as a pattern (Get-ChildItem with a wildcard path and -Include would then import nothing, silently).
Get-ChildItem -LiteralPath (Join-Path -Path $PSScriptRoot -ChildPath 'src\ps1') -Filter '*.ps1' -File |
    ForEach-Object { . $_.FullName }
