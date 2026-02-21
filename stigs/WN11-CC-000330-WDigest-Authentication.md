# STIG: WN11-CC-000330 — WDigest Authentication must be disabled

### Identifiers
- **STIG ID:** WN11-CC-000330
- **Vuln ID:** V-253416 (DISA STIG)
- **Severity:** CAT I (High)

## System / Scope
- **System:** Microsoft Windows 11 Pro 64-bit (Azure virtual machine, x64), standalone
- **Environment:** Azure-hosted virtual machine used for STIG testing
- **Role of system:** User workstation endpoint used for security testing and STIG remediation within a controlled lab environment

## Finding
- WDigest Authentication was enabled on the system, allowing Windows to store plaintext credentials in LSASS memory.
- An attacker with access to LSASS (e.g., via Mimikatz) can extract plaintext passwords directly from memory.

## Security Impact
- Plaintext credentials cached in LSASS memory are recoverable by credential-dumping tools.
- Significantly increases the impact of any privilege escalation or memory-read exploit.
- Non-compliance with DISA STIG credential protection requirements.

## Remediation Performed
- Reviewed the WDigest registry key under the WDigest security provider path.
- Set `UseLogonCredential` to `0` to prevent Windows from storing plaintext credentials in memory.

## PowerShell Remediation Script

```powershell
#Requires -RunAsAdministrator

$path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'

If (-not (Test-Path $path)) {
    New-Item -Path $path -Force | Out-Null
}

Set-ItemProperty `
    -Path $path `
    -Name 'UseLogonCredential' `
    -Value 0 `
    -Type DWord

Write-Host "WDigest Authentication disabled successfully."
```

## Validation
- Confirmed the registry value was correctly set to `0`.
- Performed a Tenable compliance rescan using the **DISA_STIG_Microsoft_Windows_11_v2r6** policy.
- Verified that **STIG WN11-CC-000330** passed successfully after remediation.

## PowerShell Validation Command

```powershell
Get-ItemProperty `
    -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' `
    -Name 'UseLogonCredential'
# Expected: UseLogonCredential = 0
```

## Notes
- A reboot is recommended after applying this setting to clear any already-cached credentials from LSASS memory.
- This setting does not affect normal user authentication — only the in-memory plaintext caching behavior.
