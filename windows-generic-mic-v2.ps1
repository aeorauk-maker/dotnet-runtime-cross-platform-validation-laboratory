$ErrorActionPreference = 'Stop'

$childPath = Join-Path $env:RUNNER_TEMP 'mic-child.ps1'
$resultPath = Join-Path $env:RUNNER_TEMP 'mic-child-result.txt'
$sentinelPath = Join-Path $env:RUNNER_TEMP 'mic-high-sentinel.txt'
$pipeName = 'mic-probe-' + [guid]::NewGuid().ToString('N')

@'
param(
    [string]$PipeName,
    [string]$ResultPath,
    [string]$SentinelPath
)
$ErrorActionPreference = 'Stop'
$label = (whoami /groups | Select-String 'Mandatory Label\\Medium Mandatory Level').ToString().Trim()
$write = 'unexpected-write'
try {
    [System.IO.File]::AppendAllText($SentinelPath, 'medium-write')
} catch [System.UnauthorizedAccessException] {
    $write = 'denied-unauthorized'
} catch [System.IO.IOException] {
    $write = 'denied-io'
}
[System.IO.File]::WriteAllText($ResultPath, "label=$label`nwrite=$write`nready=1`n")
$server = [System.IO.Pipes.NamedPipeServerStream]::new(
    $PipeName,
    [System.IO.Pipes.PipeDirection]::InOut,
    1,
    [System.IO.Pipes.PipeTransmissionMode]::Byte,
    [System.IO.Pipes.PipeOptions]::CurrentUserOnly)
try {
    $server.WaitForConnection()
    $byte = $server.ReadByte()
    [System.IO.File]::AppendAllText($ResultPath, "connected=$byte`n")
} finally {
    $server.Dispose()
}
'@ | Set-Content -LiteralPath $childPath -Encoding UTF8

[System.IO.File]::WriteAllText($sentinelPath, 'high-original')
& icacls.exe $sentinelPath /setintegritylevel H | Out-Host
if ($LASTEXITCODE -ne 0) { throw 'Could not label the sentinel high' }

Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Text;
public static class MicNative {
    [StructLayout(LayoutKind.Sequential)]
    public struct SidAndAttributes { public IntPtr Sid; public uint Attributes; }
    [StructLayout(LayoutKind.Sequential)]
    public struct MandatoryLabel { public SidAndAttributes Label; }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct StartupInfo {
        public uint cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
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
    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);
    [DllImport("kernel32.dll")]
    public static extern IntPtr GetCurrentProcess();
    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool CreateRestrictedToken(IntPtr token, uint flags,
        uint disabledCount, IntPtr disabled, uint removedCount, IntPtr removed,
        uint restrictedCount, IntPtr restricted, out IntPtr output);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool ConvertStringSidToSid(string sid, out IntPtr output);
    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern uint GetLengthSid(IntPtr sid);
    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool SetTokenInformation(IntPtr token, int infoClass,
        IntPtr label, int length);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool CreateProcessWithTokenW(IntPtr token, uint logonFlags,
        string application, StringBuilder commandLine, uint creationFlags,
        IntPtr environment, string currentDirectory, ref StartupInfo startup,
        out ProcessInfo process);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern uint WaitForSingleObject(IntPtr handle, uint timeout);
    [DllImport("kernel32.dll")]
    public static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll")]
    public static extern IntPtr LocalFree(IntPtr handle);
}
'@

$token = [IntPtr]::Zero
$medium = [IntPtr]::Zero
$sid = [IntPtr]::Zero
$labelBuffer = [IntPtr]::Zero
$proc = [MicNative+ProcessInfo]::new()
try {
    if (-not [MicNative]::OpenProcessToken([MicNative]::GetCurrentProcess(), 0xF01FF, [ref]$token)) {
        throw "OpenProcessToken failed: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
    }
    if (-not [MicNative]::CreateRestrictedToken($token, 0x4, 0, [IntPtr]::Zero,
        0, [IntPtr]::Zero, 0, [IntPtr]::Zero, [ref]$medium)) {
        throw "CreateRestrictedToken failed: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
    }
    if (-not [MicNative]::ConvertStringSidToSid('S-1-16-8192', [ref]$sid)) {
        throw "ConvertStringSidToSid failed: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
    }
    $headerLength = [Runtime.InteropServices.Marshal]::SizeOf([type][MicNative+MandatoryLabel])
    $sidLength = [int][MicNative]::GetLengthSid($sid)
    $labelLength = $headerLength + $sidLength
    $labelBuffer = [Runtime.InteropServices.Marshal]::AllocHGlobal($labelLength)
    $sidCopy = [IntPtr]::Add($labelBuffer, $headerLength)
    $sidBytes = [byte[]]::new($sidLength)
    [Runtime.InteropServices.Marshal]::Copy($sid, $sidBytes, 0, $sidLength)
    [Runtime.InteropServices.Marshal]::Copy($sidBytes, 0, $sidCopy, $sidLength)
    $label = [MicNative+MandatoryLabel]::new()
    $label.Label.Sid = $sidCopy
    $label.Label.Attributes = 0x20
    [Runtime.InteropServices.Marshal]::StructureToPtr($label, $labelBuffer, $false)
    if (-not [MicNative]::SetTokenInformation($medium, 25, $labelBuffer, $labelLength)) {
        throw "SetTokenInformation failed: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
    }
    $startup = [MicNative+StartupInfo]::new()
    $startup.cb = [Runtime.InteropServices.Marshal]::SizeOf([type][MicNative+StartupInfo])
    $commandLine = [System.Text.StringBuilder]::new("powershell.exe -NoProfile -NonInteractive -File `"$childPath`" -PipeName `"$pipeName`" -ResultPath `"$resultPath`" -SentinelPath `"$sentinelPath`"")
    if (-not [MicNative]::CreateProcessWithTokenW($medium, 0, $null, $commandLine,
        0, [IntPtr]::Zero, $null, [ref]$startup, [ref]$proc)) {
        throw "CreateProcessWithTokenW failed: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
    }
    $deadline = [DateTime]::UtcNow.AddSeconds(15)
    while (-not (Test-Path -LiteralPath $resultPath)) {
        if ([DateTime]::UtcNow -gt $deadline) { throw 'Medium child did not create its result file' }
        Start-Sleep -Milliseconds 100
    }
    $client = [System.IO.Pipes.NamedPipeClientStream]::new(
        '.', $pipeName, [System.IO.Pipes.PipeDirection]::InOut,
        [System.IO.Pipes.PipeOptions]::CurrentUserOnly)
    try {
        $client.Connect(5000)
        $client.WriteByte(42)
        $client.Flush()
    } finally {
        $client.Dispose()
    }
    $wait = [MicNative]::WaitForSingleObject($proc.hProcess, 15000)
    if ($wait -ne 0) { throw "Medium child did not exit: wait=$wait" }
    Write-Host 'GENERIC_MIC_RESULT'
    $result = Get-Content -LiteralPath $resultPath -Raw
    $result | Out-Host
    $sentinel = [System.IO.File]::ReadAllText($sentinelPath)
    Write-Host "sentinel=$sentinel"
    if ($result -notmatch 'write=denied-' -or $result -notmatch 'connected=42' -or
        $sentinel -ne 'high-original') {
        throw 'Generic MIC denial or downward pipe connection did not hold'
    }
} finally {
    if ($proc.hThread -ne [IntPtr]::Zero) { [void][MicNative]::CloseHandle($proc.hThread) }
    if ($proc.hProcess -ne [IntPtr]::Zero) { [void][MicNative]::CloseHandle($proc.hProcess) }
    if ($sid -ne [IntPtr]::Zero) { [void][MicNative]::LocalFree($sid) }
    if ($labelBuffer -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::FreeHGlobal($labelBuffer) }
    if ($medium -ne [IntPtr]::Zero) { [void][MicNative]::CloseHandle($medium) }
    if ($token -ne [IntPtr]::Zero) { [void][MicNative]::CloseHandle($token) }
}
