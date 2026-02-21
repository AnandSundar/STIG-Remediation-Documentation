# STIG: WN11-SO-000060 — The SMB client must not send unencrypted passwords to third-party servers

### Identifiers
- **STIG ID:** WN11-SO-000060
- **Vuln ID:** V-253453 (DISA STIG)
- **Severity:** CAT I (High)

## System / Scope
- **System:** Microsoft Windows 11 Pro 64-bit (Azure virtual machine, x64), standalone
- **Environment:** Azure-hosted virtual machine used for STIG testing
- **Role of system:** User workstation endpoint used for security testing and STIG remediation within a controlled lab environment

## Finding
- The SMB client was configured to allow sending plaintext passwords to third-party SMB servers via `EnablePlainTextPassword = 1`.
- This allows credentials to be transmitted in cleartext over the network during SMB authentication.

## Security Impact
- Credentials can be captured by any attacker performing a network intercept or man-in-the-middle attack.
- Exposes domain and local credentials to passive eavesdropping on the network segment.
- Non-compliance with DISA STIG SMB client security requirements.

## Remediation Performed
- Reviewed the `LanmanWorkstation` registry parameters for plaintext password settings.
- Set `EnablePlainTextPassword` to `0` to prevent the SMB client from sending unencrypted passwords.

## PowerShell Remediation Script

```powershell
#Requires -RunAsAdministrator

$path = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'

If (-not (Test-Path $path)) {
    New-Item -Path $path -Force | Out-Null
}

Set-ItemProperty `
    -Path $path `
    -Name 'EnablePlainTextPassword' `
    -Value 0 `
    -Type DWord

Write-Host "SMB plaintext password transmission disabled successfully."
```

## Validation
- Confirmed the registry value is set to `0`.
- Performed a Tenable compliance rescan using the **DISA_STIG_Microsoft_Windows_11_v2r6** policy.
- Verified that **STIG WN11-SO-000060** passed successfully after remediation.

## PowerShell Validation Command

```powershell
Get-ItemProperty `
    -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' `
    -Name 'EnablePlainTextPassword'
# Expected: EnablePlainTextPassword = 0
```

## Notes
- This setting takes effect immediately without a reboot.
- This only affects connections to third-party (non-Windows) SMB servers that request plaintext credentials.
- Modern Windows SMB servers use challenge-response authentication and are unaffected by this setting.
