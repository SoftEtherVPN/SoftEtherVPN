// SoftEther VPN Source Code - Developer Edition Master Branch
// 16-bit Driver Install Utility for Windows 9x


// vpn16.h
// 16-bit Driver Install Utility for Windows 9x

#ifndef	VPN16_H
#define	VPN16_H

void Test();
void Print(char *fmt, ...);
RETERR InstallNDIDevice(const char* szClass,
						const char* szDeviceID, 
						const char* szDriverPath,
						const char* szRegPath);
void InstallMain(char *name);
void GetDirFromPath(char *dst, char *src);
void NukuEn(char *dst, char *src);
BOOL IsFile(char *name);
BOOL IsSafeStr(char *str);
BOOL IsSafeChar(char c);

#endif	// VPN16_H


