# STIG: WN11-SO-000030 — The LAN Manager authentication level must be set to send NTLMv2 response only and refuse LM and NTLM

### Identifiers
- **STIG ID:** WN11-SO-000030
- **Vuln ID:** V-253443 (DISA STIG)
- **Severity:** CAT I (High)

## System / Scope
- **System:** Microsoft Windows 11 Pro 64-bit (Azure virtual machine, x64), standalone
- **Environment:** Azure-hosted virtual machine used for STIG testing
- **Role of system:** User workstation endpoint used for security testing and STIG remediation within a controlled lab environment

## Finding
- The LAN Manager Compatibility Level was set to `0`, allowing LM and NTLMv1 authentication responses.
- LM and NTLMv1 hashes are weak and can be cracked offline in seconds using modern hardware.

## Security Impact
- Network credential captures (e.g., via Responder) can yield crackable LM/NTLMv1 hashes.
- Enables pass-the-hash and offline brute-force attacks against user credentials.
- Non-compliance with DISA STIG network authentication hardening requirements.

## Remediation Performed
- Reviewed the `LmCompatibilityLevel` registry value under the LSA key.
- Set the value to `5` to enforce NTLMv2 only and refuse LM/NTLM responses.

## PowerShell Remediation Script

```powershell
#Requires -RunAsAdministrator

Set-ItemProperty `
    -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' `
    -Name 'LmCompatibilityLevel' `
    -Value 5 `
    -Type DWord

Write-Host "LAN Manager authentication level set to NTLMv2 only (level 5)."
```

## Validation
- Confirmed the registry value is set to `5`.
- Performed a Tenable compliance rescan using the **DISA_STIG_Microsoft_Windows_11_v2r6** policy.
- Verified that **STIG WN11-SO-000030** passed successfully after remediation.

## PowerShell Validation Command

```powershell
Get-ItemProperty `
    -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' `
    -Name 'LmCompatibilityLevel'
# Expected: LmCompatibilityLevel = 5
```

## Notes
- Value `5` means: Send NTLMv2 response only, refuse LM and NTLM.
- This change takes effect immediately without a reboot.
- Ensure all network clients and servers in the environment support NTLMv2 before enforcing in production.
