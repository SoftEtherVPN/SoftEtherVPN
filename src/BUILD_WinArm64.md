# How to build and install SoftEther VPN on Windows ARM64

This document describes how to build SoftEther VPN for Windows ARM64 and how to install the VPN Client and Neo6 virtual network adapter on Windows on ARM devices.


## Requirements


- Build host: Windows x64

- Target device: Windows 10 / Windows 11 ARM64


## Building 
 
    **Notes before building**: ARM64 builds are cross-compiled from an x64 Windows host. An existing x64-native build is required to generate hamcore.se2.
1. Follow [BUILD_WINDOWS.md](BUILD_WINDOWS.md##Building)

1. Build x64 (Native): From the build menu, select x64-on-x64. Complete the build successfully. This build is required to generate shared resources

1. Build ARM64 (Cross-Compiled): From the same build menu, select arm64-on-x64. 
Build the ARM64 version of SoftEther VPN.

1. Building the Neo6 Virtual Network Adapter (ARM64)

    Open the following project in Visual Studio:
    ```
    .\src\Neo6\Neo6.vcxproj 
    ```
   
    SoftEther VPN Client uses the Neo6 virtual network adapter.


    Driver Output Files
    The ARM64 driver package includes:
    ```
    Neo6_arm64_VPN.sys
    Neo6_arm64_VPN.inf
    ```
    Driver Signing and Installation (Windows ARM64)
    ```
    Enable test-signing mode: bcdedit /set testsigning on
    Reboot the system.
    Testing signing:
    Install the Neo6 ARM64 driver.
    ```
# Summary

SoftEther VPN can be cross-compiled for Windows ARM64 on an x64 host
VPN Client works natively on Windows on ARM
Neo6 ARM64 driver requires Microsoft signing for production use
Test-signing is suitable for local development only
