$ErrorActionPreference = 'Stop'
$taskPython = $null
$taskLauncher = Get-Command py.exe -ErrorAction SilentlyContinue
if ($taskLauncher) {
    $taskDetected = & $taskLauncher.Source -3 -c "import sys; print(sys.executable)" 2>$null
    if ($LASTEXITCODE -eq 0) { $taskPython = $taskDetected.Trim() }
}
if (-not $taskPython) {
    $taskCandidates = @(
        "$env:LOCALAPPDATA\Programs\Python\Python314\python.exe",
        "$env:USERPROFILE\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe"
    )
    $taskPython = $taskCandidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
}
if (-not $taskPython) {
    Add-Type -AssemblyName PresentationFramework
    [System.Windows.MessageBox]::Show('UPI Guard needs Python 3 with Tk. Install Python from python.org, then start this launcher again.', 'UPI Guard') | Out-Null
    exit 1
}
$taskWindowless = Join-Path (Split-Path -Parent $taskPython) 'pythonw.exe'
if (Test-Path -LiteralPath $taskWindowless) { $taskPython = $taskWindowless }
Start-Process -FilePath $taskPython -ArgumentList ('"' + (Join-Path $PSScriptRoot 'companion.py') + '"') -WorkingDirectory $PSScriptRoot -WindowStyle Hidden
