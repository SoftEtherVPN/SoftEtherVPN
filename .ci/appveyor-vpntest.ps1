$ErrorActionPreference = 'Stop'

# ('s', 'c', 'b', 'sm', 'cm') ??
('s', 'c', 'b') | % {

	[String] $mode = $_
	Write-Host "testing: $mode"

	$t = (Write-Output "q\n" | & .\build\vpntest.exe $mode | Select-String -Pattern 'NO MEMORY LEAKS' -CaseSensitive)

	if( ($t).Count -ne 1){
		Write-Error 'failed'
		return $false
	}else{
		Write-Host 'ok'
	}

}
