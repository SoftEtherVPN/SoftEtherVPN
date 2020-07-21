$ErrorActionPreference = 'Stop'

if (Test-Path "env:BUILD_BINARIESDIRECTORY") {
	$BUILD_BINARIESDIRECTORY = $env:BUILD_BINARIESDIRECTORY
} else {
	$BUILD_BINARIESDIRECTORY = "build"
}

# ('s', 'c', 'b', 'sm', 'cm') ??
('s', 'c', 'b') | % {

	[String] $mode = $_
	Write-Host "testing: $mode"

	$full = (Write-Output "q\n" | & "$BUILD_BINARIESDIRECTORY\vpntest.exe" $mode)
	$t = ($full | Select-String -Pattern 'NO MEMORY LEAKS' -CaseSensitive)

	if (($t).Count -ne 1) {
		$full
		Write-Error 'failed'
		return $false
	} else {
		Write-Host 'ok'
	}
}
