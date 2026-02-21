# STIG: WN11-CC-000210 — AutoPlay must be disabled for all drives

### Identifiers
- **STIG ID:** WN11-CC-000210
- **Vuln ID:** V-253390 (DISA STIG)
- **Severity:** CAT I (High)

## System / Scope
- **System:** Microsoft Windows 11 Pro 64-bit (Azure virtual machine, x64), standalone
- **Environment:** Azure-hosted virtual machine used for STIG testing
- **Role of system:** User workstation endpoint used for security testing and STIG remediation within a controlled lab environment

## Finding
- AutoPlay was enabled for all drive types via the `NoDriveTypeAutoRun` registry value set to `0`.
- This allows removable media and other drive types to automatically execute content upon connection.

## Security Impact
- Enables USB-based malware delivery attacks (e.g., BadUSB, malicious autorun executables).
- Malicious code can execute without any user interaction beyond inserting media.
- Non-compliance with DISA STIG removable media protection requirements.

## Remediation Performed
- Reviewed the AutoPlay policy registry setting under the Windows Explorer policy key.
- Set `NoDriveTypeAutoRun` to `0xFF` (255) to disable AutoPlay for all drive types.

## PowerShell Remediation Script

```powershell
#Requires -RunAsAdministrator

$path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'

If (-not (Test-Path $path)) {
    New-Item -Path $path -Force | Out-Null
}

Set-ItemProperty `
    -Path $path `
    -Name 'NoDriveTypeAutoRun' `
    -Value 0xFF `
    -Type DWord

Write-Host "AutoPlay disabled for all drive types (NoDriveTypeAutoRun = 255)."
```

## Validation
- Confirmed the registry value is set to `255` (0xFF).
- Performed a Tenable compliance rescan using the **DISA_STIG_Microsoft_Windows_11_v2r6** policy.
- Verified that **STIG WN11-CC-000210** passed successfully after remediation.

## PowerShell Validation Command

```powershell
Get-ItemProperty `
    -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' `
    -Name 'NoDriveTypeAutoRun'
# Expected: NoDriveTypeAutoRun = 255
```

## Notes
- This setting takes effect immediately without a reboot for new media insertions.
- This policy applies machine-wide and overrides any user-level AutoPlay settings.
- AutoRun (execution) and AutoPlay (UI prompt) are distinct features; this setting addresses both.
