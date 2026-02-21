# STIG: WN11-AC-000045 — Passwords must not be stored using reversible encryption

### Identifiers
- **STIG ID:** WN11-AC-000045
- **Vuln ID:** V-253305 (DISA STIG)
- **Severity:** CAT I (High)

## System / Scope
- **System:** Microsoft Windows 11 Pro 64-bit (Azure virtual machine, x64), standalone
- **Environment:** Azure-hosted virtual machine used for STIG testing
- **Role of system:** User workstation endpoint used for security testing and STIG remediation within a controlled lab environment

## Finding
- The local security policy was configured to store passwords using reversible encryption.
- This is functionally equivalent to storing plaintext passwords and allows password recovery from the SAM database.

## Security Impact
- An attacker with access to the SAM database can recover user passwords in cleartext.
- Violates the principle of one-way password hashing fundamental to Windows authentication security.
- Non-compliance with DISA STIG account policy requirements.

## Remediation Performed
- Reviewed the local security policy account settings via `secedit`.
- Disabled reversible password encryption via a secedit security template.

## PowerShell Remediation Script

```powershell
#Requires -RunAsAdministrator

$infFile = "$env:TEMP\fix_reversible_enc.inf"
$sdbFile = "$env:TEMP\fix_reversible_enc.sdb"

@"
[Unicode]
Unicode=yes
[System Access]
ClearTextPassword = 0
[Version]
signature="`$CHICAGO`$"
Revision=1
"@ | Out-File -FilePath $infFile -Encoding Unicode

secedit /configure /db $sdbFile /cfg $infFile /quiet

Remove-Item $infFile, $sdbFile -ErrorAction SilentlyContinue

Write-Host "Reversible password encryption disabled successfully."
```

## Validation
- Confirmed the policy reflects `ClearTextPassword = 0` via secedit export.
- Performed a Tenable compliance rescan using the **DISA_STIG_Microsoft_Windows_11_v2r6** policy.
- Verified that **STIG WN11-AC-000045** passed successfully after remediation.

## PowerShell Validation Command

```powershell
$exportFile = "$env:TEMP\secedit_export.cfg"
secedit /export /cfg $exportFile /quiet
Select-String -Path $exportFile -Pattern "ClearTextPassword"
# Expected: ClearTextPassword = 0
Remove-Item $exportFile -ErrorAction SilentlyContinue
```

## Notes
- Changing this setting does not retroactively re-hash existing passwords; users must change their passwords for the new policy to fully apply.
- A reboot is not required for this setting to take effect.
