# STIG: WN11-00-000170 — The Server Message Block (SMB) v1 protocol must be disabled

### Identifiers
- **STIG ID:** WN11-00-000170
- **Vuln ID:** V-253253 (DISA STIG)
- **Severity:** CAT I (High)

## System / Scope
- **System:** Microsoft Windows 11 Pro 64-bit (Azure virtual machine, x64), standalone
- **Environment:** Azure-hosted virtual machine used for STIG testing
- **Role of system:** User workstation endpoint used for security testing and STIG remediation within a controlled lab environment

## Finding
- SMBv1 was enabled on the system, exposing it to legacy protocol exploits including EternalBlue (MS17-010).
- SMBv1 lacks modern security features such as encryption, integrity validation, and secure negotiation.

## Security Impact
- SMBv1 is the attack vector used by WannaCry and NotPetya ransomware campaigns.
- Enables unauthenticated remote code execution on unpatched systems.
- Non-compliance with DISA STIG network protocol hardening requirements.

## Remediation Performed
- Reviewed the SMB server configuration and Windows Optional Features state.
- Disabled SMBv1 via both the SMB server configuration cmdlet and Windows Optional Features.

## PowerShell Remediation Script

```powershell
#Requires -RunAsAdministrator

# Disable SMBv1 on the server side
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force

# Remove the SMBv1 Windows Optional Feature
Disable-WindowsOptionalFeature -Online -FeatureName 'SMB1Protocol' -NoRestart

Write-Host "SMBv1 disabled successfully. Reboot required."
```

## Validation
- Confirmed SMBv1 is disabled via `Get-SmbServerConfiguration`.
- Performed a Tenable compliance rescan using the **DISA_STIG_Microsoft_Windows_11_v2r6** policy.
- Verified that **STIG WN11-00-000170** passed successfully after remediation.

## PowerShell Validation Command

```powershell
Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol
# Expected: EnableSMB1Protocol = False

Get-WindowsOptionalFeature -Online -FeatureName 'SMB1Protocol' | Select-Object State
# Expected: State = Disabled
```

## Notes
- A system reboot is required after disabling the SMBv1 Windows Optional Feature.
- SMBv2 and SMBv3 remain unaffected and will continue to serve all modern file sharing needs.
