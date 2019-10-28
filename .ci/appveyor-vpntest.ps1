$ErrorActionPreference = 'Stop'

# ('s', 'c', 'b', 'sm', 'cm') ??
('s', 'c', 'b') | % {

	[String] $mode = $_
	Write-Host "testing: $mode"

	$full = (Write-Output "q\n" | & .\build\vpntest.exe $mode)
	$t = ($full | Select-String -Pattern 'NO MEMORY LEAKS' -CaseSensitive)

	if( ($t).Count -ne 1){
		$full
		Write-Error 'failed'
		return $false
	}else{
		Write-Host 'ok'
	}

}
