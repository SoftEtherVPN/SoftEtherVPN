# STB File Multilanguage Full-Mesh Consistency Checker

September 20, 2018 By Daiyuu Nobori

## Overview
stbchecker is a utility to check the consistency between existing `*.stb` files (string resources) in the specified directory.

- Works on Windows, Linux, macOS with .NET Core 2.1.
- Written in C#.
- Easy to use.


When modifying or adding any stb files, you have to check the consistency between all existing `*.stb` files. If there are any error, the SoftEther VPN programs may fail or crash on runtime.


You must not publish any build which has failed to pass stbchecker.


## Usage
### 1. Install .NET Core 2.1
https://www.microsoft.com/net/download/dotnet-core/2.1


#### Option: Use Visual Studio 2017 on Windows
If you are using Visual Studio 2017 on Windows, you can open the `stbchecker.sln` file instead. With Visual Studio 2017 you do not need using .NET Core 2.1 command-line utility.

### 2. Go to the `developer_tools/stbchcker` directory
```
$ cd developer_tools/stbchcker/
```

### 3. Run stbchecker
```
$ dotnet run [hamcore_dir]
```
You need to specify the `src/bin/hamcore` directory of the SoftEther VPN repository. The `hamcore` directory has multiple `*.stb` files.


### 4. Show the result
#### In error cases
Errors as following will be displayed, and the program returns `non-zero` values as the exit code.

```
Comparing 'strtable_ko.stb' to 'strtable_cn.stb'...
File2: Error: Missing 'HUB_AO_DenyAllRadiusLoginWithNoVlanAssign'
File2: Error: Missing 'HUB_AO_UseHubNameAsDhcpUserClassOption'
File2: Error: Missing 'HUB_AO_UseHubNameAsRadiusNasId'
File2: Error: Missing 'CM_VLAN_REINSTALL_MSG'
--- Results ---
ERROR: There are 123 errors on multilanguage stb files. Please kindly correct them before submitting us Pull Requests.
```


#### In successful cases
The following message will be displayed, and the program returns `0` as the exit code.


```
OK: Excellent! There are no errors between multilanguage stb files.
```
