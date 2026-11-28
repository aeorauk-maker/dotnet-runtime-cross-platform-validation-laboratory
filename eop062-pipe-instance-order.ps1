param(
    [ValidateSet('main', 'serve', 'probe')][string]$Mode = 'main',
    [string]$PipeName,
    [string]$ResultPath,
    [string]$StopPath
)
$ErrorActionPreference = 'Stop'

Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Text;
public static class Eop062InstanceNative {
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct StartupInfo {
        public uint cb;
        public string lpReserved, lpDesktop, lpTitle;
        public uint dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars;
        public uint dwFillAttribute, dwFlags;
        public ushort wShowWindow, cbReserved2;
        public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError;
    }
    [StructLayout(LayoutKind.Sequential)]
    public struct ProcessInfo {
        public IntPtr hProcess, hThread;
        public uint dwProcessId, dwThreadId;
    }
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool CreateProcessWithLogonW(string user, string domain,
        string password, uint logonFlags, string application, StringBuilder commandLine,
        uint creationFlags, IntPtr environment, string currentDirectory,
        ref StartupInfo startup, out ProcessInfo process);
    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);
    [DllImport("kernel32.dll")]
    public static extern IntPtr GetCurrentProcess();
    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool GetTokenInformation(IntPtr token, int informationClass,
        IntPtr buffer, int length, out int returnLength);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool ConvertSidToStringSidW(IntPtr sid, out IntPtr result);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern uint WaitForSingleObject(IntPtr handle, uint timeout);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool GetExitCodeProcess(IntPtr handle, out uint exitCode);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool TerminateProcess(IntPtr handle, uint exitCode);
    [DllImport("kernel32.dll")]
    public static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll")]
    public static extern IntPtr LocalFree(IntPtr handle);
}
'@

function Get-IntegritySid {
    $token = [IntPtr]::Zero
    $buffer = [IntPtr]::Zero
    $sidString = [IntPtr]::Zero
    try {
        if (-not [Eop062InstanceNative]::OpenProcessToken([Eop062InstanceNative]::GetCurrentProcess(), 8, [ref]$token)) {
            throw "OpenProcessToken: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
        }
        $length = 0
        [void][Eop062InstanceNative]::GetTokenInformation($token, 25, [IntPtr]::Zero, 0, [ref]$length)
        if ($length -lt [IntPtr]::Size) { throw 'No token integrity label' }
        $buffer = [Runtime.InteropServices.Marshal]::AllocHGlobal($length)
        if (-not [Eop062InstanceNative]::GetTokenInformation($token, 25, $buffer, $length, [ref]$length)) {
            throw "GetTokenInformation: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
        }
        $sid = [Runtime.InteropServices.Marshal]::ReadIntPtr($buffer)
        if (-not [Eop062InstanceNative]::ConvertSidToStringSidW($sid, [ref]$sidString)) {
            throw "ConvertSidToStringSid: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
        }
        return [Runtime.InteropServices.Marshal]::PtrToStringUni($sidString)
    } finally {
        if ($sidString -ne [IntPtr]::Zero) { [void][Eop062InstanceNative]::LocalFree($sidString) }
        if ($buffer -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::FreeHGlobal($buffer) }
        if ($token -ne [IntPtr]::Zero) { [void][Eop062InstanceNative]::CloseHandle($token) }
    }
}

if ($Mode -ne 'main') {
    try {
        $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $il = Get-IntegritySid
        [System.IO.File]::AppendAllText($ResultPath, "IL=$il OWNER=$($identity.Owner.Value) USER=$($identity.User.Value)`n")
        if ($identity.Owner.Value -ne $identity.User.Value) { throw 'Owner and user SID differ' }
        if ($Mode -eq 'serve') {
            if ($il -ne 'S-1-16-8192') { throw 'Server is not Medium integrity' }
            $pipe = [System.IO.Pipes.NamedPipeServerStream]::new($PipeName,
                [System.IO.Pipes.PipeDirection]::InOut,
                [System.IO.Pipes.NamedPipeServerStream]::MaxAllowedServerInstances,
                [System.IO.Pipes.PipeTransmissionMode]::Byte,
                [System.IO.Pipes.PipeOptions]::CurrentUserOnly)
            try {
                [System.IO.File]::AppendAllText($ResultPath, "SERVER_READY`n")
                for ($i = 0; $i -lt 300; $i++) {
                    if (Test-Path -LiteralPath $StopPath) { break }
                    Start-Sleep -Milliseconds 100
                }
                if (-not (Test-Path -LiteralPath $StopPath)) { throw 'Server timed out waiting for stop' }
            } finally { $pipe.Dispose() }
            [System.IO.File]::AppendAllText($ResultPath, "SERVER_STOPPED`n")
        } else {
            try {
                $pipe = [System.IO.Pipes.NamedPipeServerStream]::new($PipeName,
                    [System.IO.Pipes.PipeDirection]::InOut,
                    [System.IO.Pipes.NamedPipeServerStream]::MaxAllowedServerInstances,
                    [System.IO.Pipes.PipeTransmissionMode]::Byte,
                    [System.IO.Pipes.PipeOptions]::CurrentUserOnly)
                $pipe.Dispose()
                [System.IO.File]::AppendAllText($ResultPath, "CREATE=ALLOWED`n")
            } catch {
                [System.IO.File]::AppendAllText($ResultPath,
                    "CREATE=DENIED TYPE=$($_.Exception.GetType().Name) MESSAGE=$($_.Exception.Message)`n")
            }
        }
    } catch {
        [System.IO.File]::AppendAllText($ResultPath, "FATAL=$($_.Exception.GetType().Name):$($_.Exception.Message)`n")
        exit 3
    }
    exit 0
}

$testUser = 'eop062i' + [guid]::NewGuid().ToString('N').Substring(0,8)
$testPassword = 'Aa1!' + [guid]::NewGuid().ToString('N').Substring(0,8)
$testAccount = "$env:COMPUTERNAME\$testUser"
$pipeName = 'eop062-instance-' + [guid]::NewGuid().ToString('N')
$pwshExe = (Get-Command pwsh).Source
$cmdExe = Join-Path $env:SystemRoot 'System32\cmd.exe'
$labRoot = Join-Path $env:PUBLIC ('Documents\eop062-instance-' + [guid]::NewGuid().ToString('N'))
[void](New-Item -ItemType Directory -Path $labRoot -Force)
$sharedScript = Join-Path $labRoot 'instance.ps1'
$lowCmdExe = Join-Path $labRoot 'low-cmd.exe'
$lowLauncher = Join-Path $labRoot 'low-launcher.cmd'
$serverResult = Join-Path $labRoot 'server.txt'
$mediumResult = Join-Path $labRoot 'medium.txt'
$lowLiveResult = Join-Path $labRoot 'low-live.txt'
$lowFreeResult = Join-Path $labRoot 'low-free.txt'
$stopPath = Join-Path $labRoot 'stop.txt'
$serverProc = [Eop062InstanceNative+ProcessInfo]::new()
try {
    & net.exe user $testUser $testPassword /add /expires:never /passwordchg:no | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not create isolated standard account' }
    [System.IO.File]::Copy($PSCommandPath, $sharedScript)
    [System.IO.File]::Copy($cmdExe, $lowCmdExe)
    & icacls.exe $labRoot /grant:r "${testAccount}:(OI)(CI)(RX)" /T | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Cannot grant standard account script read' }
    & icacls.exe $lowCmdExe /setintegritylevel L | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Cannot label actor executable Low' }
    foreach ($result in @($serverResult, $mediumResult, $lowLiveResult, $lowFreeResult)) {
        [System.IO.File]::WriteAllText($result, '')
        & icacls.exe $result /grant:r "${testAccount}:(M)" | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "Cannot grant result write: $result" }
        & icacls.exe $result /setintegritylevel L | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "Cannot label result Low: $result" }
    }
    $startup = [Eop062InstanceNative+StartupInfo]::new()
    $startup.cb = [Runtime.InteropServices.Marshal]::SizeOf([type][Eop062InstanceNative+StartupInfo])
    function Start-Standard([string]$application, [string]$commandLine) {
        $process = [Eop062InstanceNative+ProcessInfo]::new()
        $line = [System.Text.StringBuilder]::new($commandLine)
        if (-not [Eop062InstanceNative]::CreateProcessWithLogonW($testUser, '.', $testPassword,
            1, $application, $line, 0, [IntPtr]::Zero,
            (Join-Path $env:SystemRoot 'System32'), [ref]$startup, [ref]$process)) {
            throw "CreateProcessWithLogonW: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
        }
        if ($process.hThread -ne [IntPtr]::Zero) { [void][Eop062InstanceNative]::CloseHandle($process.hThread) }
        return $process
    }
    function Wait-Standard($process) {
        $wait = [Eop062InstanceNative]::WaitForSingleObject($process.hProcess, 20000)
        $code = [uint32]0
        [void][Eop062InstanceNative]::GetExitCodeProcess($process.hProcess, [ref]$code)
        if ($wait -ne 0 -or $code -ne 0) { throw "Child wait=$wait exit=$code" }
    }
    function Start-MediumProbe([string]$result) {
        $line = "`"$pwshExe`" -NoProfile -NonInteractive -File `"$sharedScript`" -Mode probe -PipeName $pipeName -ResultPath `"$result`""
        $process = Start-Standard $pwshExe $line
        try { Wait-Standard $process } finally { [void][Eop062InstanceNative]::CloseHandle($process.hProcess) }
    }
    function Start-LowProbe([string]$result) {
        [System.IO.File]::WriteAllText($lowLauncher,
            "@echo off`r`n`"$pwshExe`" -NoProfile -NonInteractive -File `"$sharedScript`" -Mode probe -PipeName $pipeName -ResultPath `"$result`"`r`nexit /b %ERRORLEVEL%`r`n")
        $line = "`"$lowCmdExe`" /D /C `"$lowLauncher`""
        $process = Start-Standard $lowCmdExe $line
        try { Wait-Standard $process } finally { [void][Eop062InstanceNative]::CloseHandle($process.hProcess) }
    }
    $serverLine = "`"$pwshExe`" -NoProfile -NonInteractive -File `"$sharedScript`" -Mode serve -PipeName $pipeName -ResultPath `"$serverResult`" -StopPath `"$stopPath`""
    $serverProc = Start-Standard $pwshExe $serverLine
    $ready = $false
    for ($i = 0; $i -lt 150; $i++) {
        $state = [System.IO.File]::ReadAllText($serverResult)
        if ($state.Contains('SERVER_READY')) { $ready = $true; break }
        if ($state.Contains('FATAL=')) { throw "Server failed: $state" }
        Start-Sleep -Milliseconds 100
    }
    if (-not $ready) { throw "Server not ready: $([System.IO.File]::ReadAllText($serverResult))" }
    Start-MediumProbe $mediumResult
    Start-LowProbe $lowLiveResult
    $mediumText = [System.IO.File]::ReadAllText($mediumResult)
    $lowLiveText = [System.IO.File]::ReadAllText($lowLiveResult)
    Write-Host "MEDIUM_SAME_OWNER_INSTANCE=$mediumText"
    Write-Host "LOW_LIVE_INSTANCE=$lowLiveText"
    if (-not $mediumText.Contains('IL=S-1-16-8192') -or -not $mediumText.Contains('CREATE=ALLOWED')) {
        throw 'Same-account Medium second instance did not succeed'
    }
    if (-not $lowLiveText.Contains('IL=S-1-16-4096') -or -not $lowLiveText.Contains('CREATE=DENIED')) {
        throw 'Low actor was not denied a second instance while Medium first server lived'
    }
    [System.IO.File]::WriteAllText($stopPath, 'STOP')
    Wait-Standard $serverProc
    [void][Eop062InstanceNative]::CloseHandle($serverProc.hProcess)
    $serverProc.hProcess = [IntPtr]::Zero
    Start-LowProbe $lowFreeResult
    $lowFreeText = [System.IO.File]::ReadAllText($lowFreeResult)
    Write-Host "LOW_FREE_INSTANCE=$lowFreeText"
    if (-not $lowFreeText.Contains('IL=S-1-16-4096') -or -not $lowFreeText.Contains('CREATE=ALLOWED')) {
        throw 'Low actor did not create same endpoint after Medium server closed'
    }
    Write-Host 'EOP062_INSTANCE_ORDER_PASS'
} finally {
    if ($serverProc.hProcess -ne [IntPtr]::Zero) {
        [void][Eop062InstanceNative]::TerminateProcess($serverProc.hProcess, 5)
        [void][Eop062InstanceNative]::CloseHandle($serverProc.hProcess)
    }
    & net.exe user $testUser /delete | Out-Null
}
