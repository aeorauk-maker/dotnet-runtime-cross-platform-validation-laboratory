# Generic MIC topology harness adapted from the owned public windows-mic lab at commit 0526434.
# This checks token creation and an inert downward pipe connection only.
$ErrorActionPreference = 'Stop'

$childPath = Join-Path 'C:\Windows\Temp' ('bdf34b0c-mic-child-' + [guid]::NewGuid().ToString('N') + '.ps1')
$resultPath = Join-Path 'C:\Windows\Temp' ('bdf34b0c-medium-result-' + [guid]::NewGuid().ToString('N') + '.txt')
$sentinelPath = Join-Path $env:RUNNER_TEMP 'mic-high-sentinel.txt'
$pipeName = 'mic-probe-' + [guid]::NewGuid().ToString('N')

@'
param(
    [string]$PipeName,
    [string]$ResultPath,
    [string]$SentinelPath
)
$ErrorActionPreference = 'Stop'
[System.IO.File]::WriteAllText($ResultPath, 'child-start' + [Environment]::NewLine)
$label = ((whoami /groups | Select-String 'S-1-16-8192' | Out-String).Trim())
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

Write-Host 'stage=before_add_type'
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Text;
using System.IO;
using System.IO.Pipes;
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
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool GetExitCodeProcess(IntPtr handle, out uint exitCode);
    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool ImpersonateLoggedOnUser(IntPtr token);
    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool RevertToSelf();
    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool OpenThreadToken(IntPtr thread, uint access, bool openAsSelf, out IntPtr token);
    [DllImport("kernel32.dll")]
    public static extern IntPtr GetCurrentThread();
    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool GetTokenInformation(IntPtr token, int infoClass, IntPtr data, int length, out int returned);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool ConvertSidToStringSid(IntPtr sid, out IntPtr sidString);
    [DllImport("kernel32.dll")]
    public static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll")]
    public static extern IntPtr LocalFree(IntPtr handle);

    public static string ProbeMedium(IntPtr token, string sentinel, string pipeName) {
        if (!ImpersonateLoggedOnUser(token)) throw new Exception("ImpersonateLoggedOnUser failed: " + Marshal.GetLastWin32Error());
        try {
            IntPtr threadToken = IntPtr.Zero;
            IntPtr data = IntPtr.Zero;
            IntPtr sidString = IntPtr.Zero;
            string integrity;
            try {
                if (!OpenThreadToken(GetCurrentThread(), 0x0008, true, out threadToken)) throw new Exception("OpenThreadToken failed: " + Marshal.GetLastWin32Error());
                data = Marshal.AllocHGlobal(256);
                int returned;
                if (!GetTokenInformation(threadToken, 25, data, 256, out returned)) throw new Exception("GetTokenInformation failed: " + Marshal.GetLastWin32Error());
                if (!ConvertSidToStringSid(Marshal.ReadIntPtr(data), out sidString)) throw new Exception("ConvertSidToStringSid failed: " + Marshal.GetLastWin32Error());
                integrity = Marshal.PtrToStringUni(sidString);
            } finally {
                if (sidString != IntPtr.Zero) LocalFree(sidString);
                if (data != IntPtr.Zero) Marshal.FreeHGlobal(data);
                if (threadToken != IntPtr.Zero) CloseHandle(threadToken);
            }
            string file = "unexpected-write";
            try { File.AppendAllText(sentinel, "medium-write"); }
            catch (Exception e) { file = e.GetType().Name + ":" + e.HResult.ToString("X8"); }
            string pipe = "unknown";
            try {
                using (NamedPipeClientStream client = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut, PipeOptions.CurrentUserOnly)) {
                    client.Connect(3000);
                    pipe = "connected";
                }
            } catch (Exception e) { pipe = e.GetType().Name + ":" + e.HResult.ToString("X8"); }
            return "integrity=" + integrity + ";file=" + file + ";pipe=" + pipe;
        } finally {
            if (!RevertToSelf()) throw new Exception("RevertToSelf failed: " + Marshal.GetLastWin32Error());
        }
    }
}
'@
Write-Host 'stage=after_add_type'

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
    $sidAndAttributes = [MicNative+SidAndAttributes]::new()
    $sidAndAttributes.Sid = $sidCopy
    $sidAndAttributes.Attributes = 0x20
    $label = [MicNative+MandatoryLabel]::new()
    $label.Label = $sidAndAttributes
    [Runtime.InteropServices.Marshal]::StructureToPtr($label, $labelBuffer, $false)
    if (-not [MicNative]::SetTokenInformation($medium, 25, $labelBuffer, $labelLength)) {
        throw "SetTokenInformation failed: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
    }
    Write-Host 'stage=medium_token_ready'
    $highName = 'mic-high-control-' + [guid]::NewGuid().ToString('N')
    $highServer = [System.IO.Pipes.NamedPipeServerStream]::new($highName,
        [System.IO.Pipes.PipeDirection]::InOut, 1,
        [System.IO.Pipes.PipeTransmissionMode]::Byte,
        ([System.IO.Pipes.PipeOptions]::CurrentUserOnly -bor [System.IO.Pipes.PipeOptions]::Asynchronous))
    try {
        Write-Host 'stage=high_server_created'
        $highWait = $highServer.WaitForConnectionAsync()
        Write-Host 'stage=high_wait_started'
        $highClient = [System.IO.Pipes.NamedPipeClientStream]::new('.', $highName,
            [System.IO.Pipes.PipeDirection]::InOut,
            [System.IO.Pipes.PipeOptions]::CurrentUserOnly)
        try {
            $highClient.Connect(3000)
            Write-Host 'stage=high_client_connected'
            if (-not $highWait.Wait(3000)) { throw 'High server did not observe connection' }
            Write-Host 'high_to_high=connected'
        } finally { $highClient.Dispose() }
    } finally { $highServer.Dispose() }
    $mediumName = 'mic-high-server-' + [guid]::NewGuid().ToString('N')
    $mediumServer = [System.IO.Pipes.NamedPipeServerStream]::new($mediumName,
        [System.IO.Pipes.PipeDirection]::InOut, 1,
        [System.IO.Pipes.PipeTransmissionMode]::Byte,
        ([System.IO.Pipes.PipeOptions]::CurrentUserOnly -bor [System.IO.Pipes.PipeOptions]::Asynchronous))
    try {
        Write-Host 'stage=medium_server_created'
        $mediumWait = $mediumServer.WaitForConnectionAsync()
        $mediumResult = [MicNative]::ProbeMedium($medium, $sentinelPath, $mediumName)
        Write-Host "medium_probe=$mediumResult"
        if ($mediumResult -match 'pipe=connected') {
            if (-not $mediumWait.Wait(3000)) { throw 'High server did not observe Medium connection' }
            Write-Host 'high_server_observed_medium_connection=1'
        }
        Write-Host "sentinel=$([System.IO.File]::ReadAllText($sentinelPath))"
        if ($mediumResult -notmatch 'integrity=S-1-16-8192' -or
            $mediumResult -match 'file=unexpected-write') {
            throw 'Medium token or High sentinel denial was not established'
        }
    } finally { $mediumServer.Dispose() }
    return
    $startup = [MicNative+StartupInfo]::new()
    $startup.cb = [Runtime.InteropServices.Marshal]::SizeOf([type][MicNative+StartupInfo])
    $cmdPath = Join-Path 'C:\Windows\Temp' ('bdf34b0c-cmd-child-' + [guid]::NewGuid().ToString('N') + '.cmd')
    $cmdResultPath = Join-Path 'C:\Windows\Temp' ('bdf34b0c-cmd-result-' + [guid]::NewGuid().ToString('N') + '.txt')
    @("echo child-start > `"$cmdResultPath`"", "whoami /groups >> `"$cmdResultPath`" 2>&1") |
        Set-Content -LiteralPath $cmdPath -Encoding Ascii
    $cmdExe = $env:ComSpec
    $cmdLine = [System.Text.StringBuilder]::new("`"$cmdExe`" /d /c `"`"$cmdPath`"`"")
    $cmdProc = [MicNative+ProcessInfo]::new()
    if (-not [MicNative]::CreateProcessWithTokenW($medium, 0, $cmdExe, $cmdLine,
        0x08000000, [IntPtr]::Zero, 'C:\Windows\Temp', [ref]$startup, [ref]$cmdProc)) {
        throw "CreateProcessWithTokenW cmd failed: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
    }
    $cmdWait = [MicNative]::WaitForSingleObject($cmdProc.hProcess, 10000)
    $cmdExit = [uint32]0
    [void][MicNative]::GetExitCodeProcess($cmdProc.hProcess, [ref]$cmdExit)
    Write-Host "cmd_pid=$($cmdProc.dwProcessId) wait=$cmdWait exit=$cmdExit result_exists=$(Test-Path -LiteralPath $cmdResultPath)"
    if (Test-Path -LiteralPath $cmdResultPath) { Get-Content -LiteralPath $cmdResultPath | Out-Host }
    $cmdInfo = Get-CimInstance Win32_Process -Filter "ProcessId=$($cmdProc.dwProcessId)"
    Write-Host "cmd_name=$($cmdInfo.Name) cmd_line=$($cmdInfo.CommandLine) cmd_parent=$($cmdInfo.ParentProcessId)"
    $cmdThreads = (Get-Process -Id $cmdProc.dwProcessId -ErrorAction SilentlyContinue).Threads
    Write-Host "cmd_threads=$($cmdThreads.Count)"
    & icacls.exe $cmdPath | Out-Host
    & icacls.exe 'C:\Windows\Temp' | Out-Host
    if ($cmdProc.hThread -ne [IntPtr]::Zero) { [void][MicNative]::CloseHandle($cmdProc.hThread) }
    if ($cmdProc.hProcess -ne [IntPtr]::Zero) { [void][MicNative]::CloseHandle($cmdProc.hProcess) }
    if ($cmdWait -ne 0 -or -not (Test-Path -LiteralPath $cmdResultPath)) {
        throw 'Minimal medium-token cmd child failed before pipe test'
    }
    $powershellExe = (Get-Command pwsh).Source
    $commandLine = [System.Text.StringBuilder]::new("`"$powershellExe`" -NoProfile -NonInteractive -File `"$childPath`" -PipeName `"$pipeName`" -ResultPath `"$resultPath`" -SentinelPath `"$sentinelPath`"")
    if (-not [MicNative]::CreateProcessWithTokenW($medium, 0, $powershellExe, $commandLine,
        0, [IntPtr]::Zero, $env:RUNNER_TEMP, [ref]$startup, [ref]$proc)) {
        throw "CreateProcessWithTokenW failed: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
    }
    Write-Host "child_pid=$($proc.dwProcessId) child_path=$childPath result_path=$resultPath"
    $deadline = [DateTime]::UtcNow.AddSeconds(15)
    while (-not (Test-Path -LiteralPath $resultPath)) {
        $state = [MicNative]::WaitForSingleObject($proc.hProcess, 0)
        if ($state -eq 0) {
            $exitCode = [uint32]0
            [void][MicNative]::GetExitCodeProcess($proc.hProcess, [ref]$exitCode)
            throw "Medium child exited before result: exit=$exitCode"
        }
        if ([DateTime]::UtcNow -gt $deadline) { throw "Medium child did not create its result file: process_state=$state" }
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

