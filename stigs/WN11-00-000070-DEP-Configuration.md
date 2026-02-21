# STIG: WN11-00-000070 — Data Execution Prevention (DEP) must be configured to at least OptOut

### Identifiers
- **STIG ID:** WN11-00-000070
- **Vuln ID:** V-253269 (DISA STIG)
- **Severity:** CAT I (High)

## System / Scope
- **System:** Microsoft Windows 11 Pro 64-bit (Azure virtual machine, x64), standalone
- **Environment:** Azure-hosted virtual machine used for STIG testing
- **Role of system:** User workstation endpoint used for security testing and STIG remediation within a controlled lab environment

## Finding
- Data Execution Prevention (DEP) was configured to `AlwaysOff` via the bcdedit boot configuration.
- With DEP disabled, the system provides no hardware-enforced memory protection against code injection attacks.

## Security Impact
- Removes a critical exploit mitigation that prevents shellcode execution in non-executable memory regions.
- Significantly increases exploitability of buffer overflow and memory corruption vulnerabilities.
- Non-compliance with DISA STIG memory protection requirements.

## Remediation Performed
- Reviewed the current DEP/NX boot policy using `bcdedit`.
- Re-enabled DEP using the `OptOut` policy, which applies DEP to all processes except those explicitly excluded.

## PowerShell Remediation Script

```powershell
#Requires -RunAsAdministrator

# Set DEP to OptOut (applies to all processes except those excluded)
bcdedit /set nx OptOut

Write-Host "DEP set to OptOut. A system reboot is required for this change to take effect."
```

## Validation
- Confirmed the boot configuration reflects `nx OptOut` after reboot.
- Performed a Tenable compliance rescan using the **DISA_STIG_Microsoft_Windows_11_v2r6** policy.
- Verified that **STIG WN11-00-000070** passed successfully after remediation.

## PowerShell Validation Command

```powershell
bcdedit /enum | Select-String "nx"
# Expected: nx    OptOut
```

## Notes
- **A system reboot is required** for the bcdedit NX policy change to take effect.
- `OptOut` is the minimum required value; `AlwaysOn` provides stronger protection if application compatibility allows.
- This setting applies system-wide and affects all running processes after reboot.
