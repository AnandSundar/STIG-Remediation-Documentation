# STIG: WN11-AU-000050 — Logon/Logoff events must be audited for Success and Failure

### Identifiers
- **STIG ID:** WN11-AU-000050
- **Vuln ID:** V-253285 (DISA STIG)
- **Severity:** CAT I (High)

## System / Scope
- **System:** Microsoft Windows 11 Pro 64-bit (Azure virtual machine, x64), standalone
- **Environment:** Azure-hosted virtual machine used for STIG testing
- **Role of system:** User workstation endpoint used for security testing and STIG remediation within a controlled lab environment

## Finding
- Audit policy for Logon/Logoff events was configured to audit neither Success nor Failure.
- Without logon auditing, there is no forensic trail of authentication activity on the system.

## Security Impact
- Unauthorized access attempts and successful logins go undetected and unlogged.
- Incident response and forensic investigations are severely hampered.
- Non-compliance with DISA STIG audit and accountability requirements.

## Remediation Performed
- Reviewed the current advanced audit policy configuration using `auditpol`.
- Enabled both Success and Failure auditing for the Logon and Logoff subcategories.

## PowerShell Remediation Script

```powershell
#Requires -RunAsAdministrator

# Enable Success and Failure auditing for Logon events
auditpol /set /subcategory:"Logon" /success:enable /failure:enable

# Enable Success auditing for Logoff events
auditpol /set /subcategory:"Logoff" /success:enable /failure:enable

Write-Host "Logon/Logoff auditing enabled for Success and Failure."
```

## Validation
- Confirmed audit policy reflects Success and Failure for the Logon subcategory.
- Performed a Tenable compliance rescan using the **DISA_STIG_Microsoft_Windows_11_v2r6** policy.
- Verified that **STIG WN11-AU-000050** passed successfully after remediation.

## PowerShell Validation Command

```powershell
auditpol /get /subcategory:"Logon"
# Expected: Logon = Success and Failure
```

## Notes
- This setting does not require a reboot to take effect.
- Ensure the Security event log is sized appropriately (minimum 1024000 KB per STIG WN11-AU-000500) to retain audit records.
