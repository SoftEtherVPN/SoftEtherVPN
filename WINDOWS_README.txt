================================================================================
SoftEther VPN - Windows Installation Notes
================================================================================

Thank you for installing SoftEther VPN!

SoftEther VPN is legitimate, open-source VPN software developed by researchers
at the University of Tsukuba, Japan. It has been in active development since
2013 and is used by organizations and individuals worldwide.

================================================================================
IMPORTANT: Antivirus False Positive Warning
================================================================================

Some antivirus software (including Microsoft Defender) may incorrectly flag
SoftEther VPN executables as malicious. This is a FALSE POSITIVE detection.

WHY THIS HAPPENS:
-----------------
VPN software performs operations that can appear suspicious to antivirus
programs:
  - Network tunneling and traffic interception
  - Low-level network operations
  - Service installation with elevated privileges
  - Registry modifications for Windows integration

These are NORMAL and NECESSARY operations for any VPN software.

IF MICROSOFT DEFENDER QUARANTINES SOFTETHER VPN:
------------------------------------------------

1. Add Exclusions to Microsoft Defender:
   
   a) Open Windows Security (Windows Key + I -> Privacy & Security -> 
      Windows Security -> Virus & threat protection)
   
   b) Click "Manage settings" under Virus & threat protection settings
   
   c) Scroll down to "Exclusions" and click "Add or remove exclusions"
   
   d) Click "Add an exclusion" -> "Folder" and add:
      
      C:\Program Files\SoftEther VPN Client
      C:\Program Files\SoftEther VPN Client Developer Edition
      C:\Program Files\SoftEther VPN Server
      C:\Program Files\SoftEther VPN Server Developer Edition
      
      (Add only the folders that exist for your installation)

2. Restore Quarantined Files:
   
   a) Go to "Virus & threat protection" -> "Protection history"
   b) Find quarantined SoftEther VPN files
   c) Click "Actions" -> "Restore"

3. Reinstall if Necessary:
   
   If files were deleted, reinstall SoftEther VPN. The exclusions will
   prevent future detections.

REPORT FALSE POSITIVE TO MICROSOFT:
------------------------------------

Help improve Microsoft Defender by reporting the false positive:

  Visit: https://www.microsoft.com/en-us/wdsi/filesubmission
  
  Submit the flagged file and indicate it's a false positive detection
  of SoftEther VPN, open-source software from the University of Tsukuba.

MORE INFORMATION:
-----------------

For detailed documentation about this issue and additional solutions, see:

  https://github.com/SoftEtherVPN/SoftEtherVPN/blob/master/ANTIVIRUS.md

VERIFY AUTHENTICITY:
--------------------

SoftEther VPN is open source. You can verify the software by:

  - Reviewing source code: https://github.com/SoftEtherVPN/SoftEtherVPN
  - Official website: https://www.softether.org/
  - Only download from official sources

WARNING: Do not download SoftEther VPN from third-party websites.

================================================================================
Getting Started
================================================================================

After adding antivirus exclusions (if needed):

1. Launch "SoftEther VPN Client Manager" from the Start Menu
2. Configure your VPN connection settings
3. Connect to your VPN server

For detailed documentation, visit: https://www.softether.org/

================================================================================
Support
================================================================================

Official Website: https://www.softether.org/
GitHub Repository: https://github.com/SoftEtherVPN/SoftEtherVPN
Security Issues: https://github.com/SoftEtherVPN/SoftEtherVPN/security

================================================================================

SoftEther VPN is licensed under the Apache License 2.0
Copyright (c) SoftEther VPN Project at University of Tsukuba, Japan

Thank you for using SoftEther VPN!

================================================================================
