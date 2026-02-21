# STIG: WN11-SO-000025 — Anonymous SID/Name translation must not be allowed

### Identifiers
- **STIG ID:** WN11-SO-000025
- **Vuln ID:** V-253438 (DISA STIG)
- **Severity:** CAT I (High)

## System / Scope
- **System:** Microsoft Windows 11 Pro 64-bit (Azure virtual machine, x64), standalone
- **Environment:** Azure-hosted virtual machine used for STIG testing
- **Role of system:** User workstation endpoint used for security testing and STIG remediation within a controlled lab environment

## Finding
- The local security policy was configured to allow anonymous SID/Name translation.
- This permits unauthenticated users to query Security Identifiers (SIDs) and resolve them to account names.

## Security Impact
- Unauthenticated attackers can enumerate user accounts and group memberships by resolving SIDs.
- Facilitates targeted attacks by exposing valid username information without credentials.
- Non-compliance with DISA STIG anonymous access restriction requirements.

## Remediation Performed
- Reviewed the `LSAAnonymousNameLookup` local security policy setting.
- Disabled anonymous SID/Name translation via a secedit security template.

## PowerShell Remediation Script

```powershell
#Requires -RunAsAdministrator

$infFile = "$env:TEMP\fix_anon_sid.inf"
$sdbFile = "$env:TEMP\fix_anon_sid.sdb"

@"
[Unicode]
Unicode=yes
[System Access]
LSAAnonymousNameLookup = 0
[Version]
signature="`$CHICAGO`$"
Revision=1
"@ | Out-File -FilePath $infFile -Encoding Unicode

secedit /configure /db $sdbFile /cfg $infFile /quiet

Remove-Item $infFile, $sdbFile -ErrorAction SilentlyContinue

Write-Host "Anonymous SID/Name translation disabled successfully."
```

## Validation
- Confirmed the policy reflects `LSAAnonymousNameLookup = 0` via secedit export.
- Performed a Tenable compliance rescan using the **DISA_STIG_Microsoft_Windows_11_v2r6** policy.
- Verified that **STIG WN11-SO-000025** passed successfully after remediation.

## PowerShell Validation Command

```powershell
$exportFile = "$env:TEMP\secedit_export.cfg"
secedit /export /cfg $exportFile /quiet
Select-String -Path $exportFile -Pattern "LSAAnonymousNameLookup"
# Expected: LSAAnonymousNameLookup = 0
Remove-Item $exportFile -ErrorAction SilentlyContinue
```

## Notes
- This setting does not require a reboot to take effect.
- This control is distinct from `RestrictAnonymous`; both should be configured per STIG requirements.
