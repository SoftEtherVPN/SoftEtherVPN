# Antivirus False Positive Detection

## Overview

Some antivirus software, including Microsoft Defender, may incorrectly flag SoftEther VPN executables as malicious software. This is a **false positive** detection. SoftEther VPN is legitimate, open-source software that has been developed and maintained since 2013 by researchers at the University of Tsukuba, Japan.

## Why Does This Happen?

Antivirus software uses heuristic analysis to detect potentially malicious behavior. VPN software like SoftEther VPN performs operations that can appear suspicious to antivirus programs, including:

- **Network tunneling and traffic interception**: VPN software creates virtual network adapters and intercepts network traffic to secure it
- **Low-level network operations**: Packet filtering, protocol handling, and kernel-mode operations
- **Service installation**: VPN clients install system services that run with elevated privileges
- **Registry modifications**: Required for Windows integration and auto-start functionality
- **Dynamic code execution**: Network protocol implementations may use techniques that appear similar to malicious software

These are **normal and necessary operations** for any VPN software, but they can trigger heuristic-based detection algorithms.

## Microsoft Defender Specific Issue

### Affected Components

Microsoft Defender may flag the following SoftEther VPN 5.x components as `Trojan:Win32/KepavII!rfn`:

- `vpnclient.exe` - VPN Client executable
- `vpnserver.exe` - VPN Server executable  
- `vpnbridge.exe` - VPN Bridge executable
- `vpncmd.exe` - VPN Command-line utility
- Start menu shortcuts
- Registry entries
- Windows services (`SEVPNCLIENTDEV`, `SEVPNSERVERDEV`, etc.)

### Detection Details

```
Detected: Trojan:Win32/KepavII!rfn
Status: Quarantined
Description: "This program is dangerous and executes commands from an attacker."
```

**This is a false positive.** The detection is based on behavioral heuristics, not actual malicious code.

## Solutions and Workarounds

### Option 1: Add Exclusions (Recommended for Users)

The recommended approach is to add SoftEther VPN directories to Microsoft Defender's exclusion list:

#### Step-by-Step Instructions:

1. **Open Windows Security**
   - Press `Windows Key + I` to open Settings
   - Navigate to **Privacy & Security** → **Windows Security**
   - Click **Virus & threat protection**

2. **Access Exclusion Settings**
   - Scroll down to **Virus & threat protection settings**
   - Click **Manage settings**
   - Scroll down to **Exclusions**
   - Click **Add or remove exclusions**

3. **Add SoftEther VPN Directories**
   
   Click **Add an exclusion** → **Folder** and add these paths:
   
   - `C:\Program Files\SoftEther VPN Client`
   - `C:\Program Files\SoftEther VPN Client Developer Edition`
   - `C:\Program Files\SoftEther VPN Server`
   - `C:\Program Files\SoftEther VPN Server Manager`
   - `C:\Program Files\SoftEther VPN Server Manager Developer Edition`
   - `C:\Program Files\SoftEther VPN Server Developer Edition`
   - `C:\ProgramData\SoftEther VPN Client`
   - `C:\ProgramData\SoftEther VPN Server`
   
   **Note**: Add only the directories that correspond to the SoftEther VPN components you have installed.

4. **Restore Quarantined Files** (if needed)
   - Go back to **Virus & threat protection**
   - Click **Protection history**
   - Find the quarantined SoftEther VPN files
   - Click **Actions** → **Restore**

5. **Reinstall if Necessary**
   - If files were deleted, you may need to reinstall SoftEther VPN
   - The exclusions will prevent future detections

### Option 2: Report False Positive to Microsoft

Help improve Microsoft Defender by reporting the false positive:

1. **Submit to Microsoft Defender Security Intelligence**
   - Visit: https://www.microsoft.com/en-us/wdsi/filesubmission
   - Select **File** submission type
   - Choose **Software developer** as your role
   - Submit the falsely detected SoftEther VPN executable files
   - Provide details: "False positive detection of SoftEther VPN, open-source VPN software"

2. **Include Information**
   - Product Name: SoftEther VPN
   - Vendor: SoftEther Project at University of Tsukuba
   - Official Website: https://www.softether.org/
   - GitHub Repository: https://github.com/SoftEtherVPN/SoftEtherVPN
   - License: Apache License 2.0

Microsoft typically reviews submissions within a few days and updates their definitions if confirmed as a false positive.

### Option 3: Use Alternative Antivirus Software

If Microsoft Defender continues to cause issues:

1. Consider using alternative antivirus software that doesn't flag SoftEther VPN
2. Some users report fewer false positives with third-party antivirus solutions
3. Ensure any alternative antivirus is from a reputable vendor

## For IT Administrators

### Group Policy Configuration

To deploy exclusions across an organization using Group Policy:

1. **Open Group Policy Management Console**
   ```
   gpmc.msc
   ```

2. **Navigate to Windows Defender Antivirus Settings**
   ```
   Computer Configuration → Policies → Administrative Templates 
   → Windows Components → Microsoft Defender Antivirus → Exclusions
   ```

3. **Configure Path Exclusions**
   - Enable **Path Exclusions**
   - Add the SoftEther VPN installation directories

4. **Update Group Policy**
   ```powershell
   gpupdate /force
   ```

### PowerShell Exclusion Script

For automated deployment, use this PowerShell script (requires Administrator privileges):

```powershell
# Add Windows Defender exclusions for SoftEther VPN
# Requires Administrator privileges

$exclusionPaths = @(
    "C:\Program Files\SoftEther VPN Client",
    "C:\Program Files\SoftEther VPN Client Developer Edition",
    "C:\Program Files\SoftEther VPN Server",
    "C:\Program Files\SoftEther VPN Server Manager",
    "C:\Program Files\SoftEther VPN Server Manager Developer Edition",
    "C:\Program Files\SoftEther VPN Server Developer Edition",
    "C:\ProgramData\SoftEther VPN Client",
    "C:\ProgramData\SoftEther VPN Server"
)

# Check if running as Administrator
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Error "This script requires Administrator privileges. Please run PowerShell as Administrator."
    exit 1
}

# Check if Windows Defender module is available
if (-not (Get-Module -ListAvailable -Name Defender)) {
    Write-Error "Windows Defender PowerShell module is not available on this system."
    exit 1
}

$successCount = 0
$errorCount = 0

foreach ($path in $exclusionPaths) {
    if (Test-Path $path) {
        try {
            Add-MpPreference -ExclusionPath $path -ErrorAction Stop
            Write-Host "✓ Added exclusion: $path" -ForegroundColor Green
            $successCount++
        }
        catch {
            Write-Warning "✗ Failed to add exclusion for: $path"
            Write-Warning "  Error: $($_.Exception.Message)"
            $errorCount++
        }
    }
    else {
        Write-Host "- Skipped (not found): $path" -ForegroundColor Gray
    }
}

Write-Host "`nSummary:" -ForegroundColor Cyan
Write-Host "  Successfully added: $successCount exclusion(s)" -ForegroundColor Green
if ($errorCount -gt 0) {
    Write-Host "  Failed: $errorCount exclusion(s)" -ForegroundColor Red
}
Write-Host "`nSoftEther VPN exclusions configured." -ForegroundColor Cyan
```

Save as `Add-SoftEtherVPN-Exclusions.ps1` and run as Administrator.

## Verification of Software Authenticity

### Open Source Verification

SoftEther VPN is **fully open source** and can be verified:

1. **Source Code Review**
   - Complete source code: https://github.com/SoftEtherVPN/SoftEtherVPN
   - All commits are publicly visible
   - Community peer-reviewed code

2. **Build from Source**
   - You can compile SoftEther VPN yourself from source
   - See: [BUILD_WINDOWS.md](src/BUILD_WINDOWS.md) and [BUILD_UNIX.md](src/BUILD_UNIX.md)
   - Self-compiled builds may have fewer false positive issues

3. **Community Trust**
   - Active development since 2013
   - Over 11,000+ GitHub stars
   - Used by organizations and individuals worldwide
   - Peer-reviewed academic research project

### Official Distributions

Always download SoftEther VPN from official sources:

- **Official Website**: https://www.softether.org/
- **GitHub Releases**: https://github.com/SoftEtherVPN/SoftEtherVPN/releases
- **Official Download Site**: https://www.softether-download.com/

**Warning**: Do not download SoftEther VPN from third-party websites or unofficial sources.

## Technical Background

### Why VPN Software Triggers Detection

VPN software implements functionality that overlaps with techniques used by some malware:

1. **Kernel-mode drivers**: Required for creating virtual network adapters
2. **Network traffic interception**: Core VPN functionality to encrypt traffic
3. **Process injection**: Some VPN implementations inject into other processes
4. **Privilege escalation**: VPN services need administrative rights
5. **Persistent system changes**: Auto-start configuration, service installation

These are **legitimate techniques** when used by trusted VPN software.

### False Positive Rate

False positives are common in the VPN and security software industry. Other legitimate VPN and security tools have faced similar issues:

- OpenVPN has been flagged by various antivirus vendors
- WireGuard implementations have triggered false positives
- Many security research tools face similar challenges

## Code Signing Status

**Note**: The official SoftEther VPN releases may not include code signing certificates. Code signing certificates require:

- Annual fees (typically $300-500+ per year)
- Corporate entity for Extended Validation (EV) certificates
- Hardware security modules (HSM) for EV certificate storage

As an open-source project with limited funding, SoftEther VPN prioritizes development over expensive code signing infrastructure. However, this doesn't make the software any less safe - all source code is publicly auditable.

Users who require signed binaries can:
1. Build from source and sign with their own certificates
2. Work with their organization to sign the binaries
3. Use alternative verification methods (source code review, checksums, etc.)

## Best Practices

1. **Keep Antivirus Updated**: Ensure Microsoft Defender definitions are current
2. **Monitor Protection History**: Regularly check if SoftEther VPN is being flagged
3. **Subscribe to Updates**: Follow SoftEther VPN releases for security updates
4. **Report False Positives**: Help the community by reporting detections to Microsoft
5. **Use Official Builds**: Only download from official sources

## Additional Resources

- **SoftEther VPN Official Website**: https://www.softether.org/
- **GitHub Repository**: https://github.com/SoftEtherVPN/SoftEtherVPN
- **Security Policy**: [SECURITY.md](SECURITY.md)
- **Microsoft Defender Submission Portal**: https://www.microsoft.com/en-us/wdsi/filesubmission
- **Build Instructions**: [BUILD_WINDOWS.md](src/BUILD_WINDOWS.md)

## Frequently Asked Questions

### Q: Is SoftEther VPN safe to use?

**A**: Yes. SoftEther VPN is legitimate, open-source software developed by researchers at the University of Tsukuba, Japan. The detection is a false positive. All source code is publicly available for review at https://github.com/SoftEtherVPN/SoftEtherVPN

### Q: Why don't you just fix the code to not trigger antivirus?

**A**: The detection is based on legitimate VPN operations, not malicious code. Changing how VPN functionality works to avoid heuristic detection would compromise the software's core purpose. The correct solution is to report false positives to antivirus vendors and add exclusions.

### Q: Will adding exclusions make my computer less secure?

**A**: Exclusions for trusted software from official sources don't significantly reduce security. Only add exclusions for software you trust and have downloaded from official sources. SoftEther VPN is open-source and can be verified.

### Q: Can I use SoftEther VPN without adding exclusions?

**A**: Not reliably with Microsoft Defender. The antivirus will quarantine executables and prevent the VPN from functioning. Exclusions are necessary unless Microsoft updates their detection definitions.

### Q: How do I know my downloaded file is authentic?

**A**: 
1. Only download from https://github.com/SoftEtherVPN/SoftEtherVPN/releases or https://www.softether.org/
2. Verify the file hash/checksum if provided
3. Review the source code on GitHub
4. Build from source yourself for maximum assurance

### Q: Is this issue specific to SoftEther VPN?

**A**: No. Many VPN applications and security tools face false positive detections. OpenVPN, WireGuard implementations, and other network security tools have similar issues with various antivirus vendors.

### Q: Will this be fixed in a future version?

**A**: The SoftEther VPN project continues to work on this issue. However, heuristic-based detection is challenging to avoid without compromising functionality. The best approach is to:
1. Report false positives to Microsoft
2. Use exclusions as needed
3. Build from source if your organization requires it

## Contributing

If you have additional solutions or workarounds that have worked for you, please contribute to this documentation:

1. Fork the repository: https://github.com/SoftEtherVPN/SoftEtherVPN
2. Edit this file: `ANTIVIRUS.md`
3. Submit a pull request with your improvements

---

**Applies to**: SoftEther VPN 5.x (Developer Edition)  
**Related Issue**: False positive detection by Microsoft Defender as Trojan:Win32/KepavII!rfn
