# STIG: WN11-SO-000070 — Anonymous enumeration of SAM accounts must not be allowed

### Identifiers
- **STIG ID:** WN11-SO-000070
- **Vuln ID:** V-253458 (DISA STIG)
- **Severity:** CAT I (High)

## System / Scope
- **System:** Microsoft Windows 11 Pro 64-bit (Azure virtual machine, x64), standalone
- **Environment:** Azure-hosted virtual machine used for STIG testing
- **Role of system:** User workstation endpoint used for security testing and STIG remediation within a controlled lab environment

## Finding
- `RestrictAnonymous` and `RestrictAnonymousSAM` were both set to `0`, allowing null session connections to enumerate SAM accounts and shared resources.
- Unauthenticated users can query the system for a full list of local user accounts and network shares.

## Security Impact
- Enables attackers to enumerate all local accounts without credentials, supporting targeted brute-force and social engineering attacks.
- Null session enumeration can also expose group memberships and share names.
- Non-compliance with DISA STIG anonymous access restriction requirements.

## Remediation Performed
- Reviewed the LSA anonymous access registry values under `HKLM:\SYSTEM\CurrentControlSet\Control\Lsa`.
- Set both `RestrictAnonymous` and `RestrictAnonymousSAM` to `1` to block null session enumeration.

## PowerShell Remediation Script

```powershell
#Requires -RunAsAdministrator

$lsaPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'

Set-ItemProperty `
    -Path $lsaPath `
    -Name 'RestrictAnonymous' `
    -Value 1 `
    -Type DWord

Set-ItemProperty `
    -Path $lsaPath `
    -Name 'RestrictAnonymousSAM' `
    -Value 1 `
    -Type DWord

Write-Host "Anonymous SAM and share enumeration restricted successfully."
```

## Validation
- Confirmed both registry values are set to `1`.
- Performed a Tenable compliance rescan using the **DISA_STIG_Microsoft_Windows_11_v2r6** policy.
- Verified that **STIG WN11-SO-000070** passed successfully after remediation.

## PowerShell Validation Command

```powershell
Get-ItemProperty `
    -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' `
    -Name 'RestrictAnonymous', 'RestrictAnonymousSAM'
# Expected: RestrictAnonymous = 1
# Expected: RestrictAnonymousSAM = 1
```

## Notes
- These settings take effect immediately without a reboot.
- `RestrictAnonymous = 1` blocks enumeration of shares and users; `RestrictAnonymousSAM = 1` specifically blocks SAM account enumeration.
- In a domain environment, consult with the domain administrator before applying as it may affect legacy systems relying on null session access.
