# Security policy for RemoteFirewall

## What the module does
RemoteFirewall is a read-only collector. It reads configuration from local or remote Windows computers over WinRM and writes files under the output path the caller names. It changes nothing on a target, installs nothing, downloads nothing and sends data nowhere except back to the collecting computer. The README's Output Data Handling section says what the output contains and how to handle it.

## Supported versions
The latest release on the main branch. Older tags receive no fixes.

## Reporting a vulnerability
Open a private vulnerability report on the project repository (GitHub, Security tab) if available, otherwise an issue without exploit detail asking for a contact. Describe the module version, the engine (Windows PowerShell 5.1 or PowerShell 7), the target Windows version and the steps. Expect an acknowledgement within ten days. Fixes ship as a patch release with a note in the README's Version Changes.

## Known limits
The files are not signed, and the module needs FullLanguage mode; see the README's Known limits paragraph. The output is unredacted configuration data and may contain names, SIDs, paths, command lines and policy values: treat the output folder as confidential.
