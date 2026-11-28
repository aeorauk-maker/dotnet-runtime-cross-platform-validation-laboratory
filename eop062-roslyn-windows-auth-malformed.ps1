# Standard-account no-actor control, then low-integrity compiler preclaim.
$ErrorActionPreference = 'Stop'

$resultPath = Join-Path $env:RUNNER_TEMP 'mic-child-result.txt'
$runnerUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$highPath = Join-Path $env:RUNNER_TEMP 'mic-high-sentinel.txt'
[System.IO.File]::WriteAllText($highPath, 'HIGH_ONLY')
& icacls.exe $highPath /setintegritylevel H | Out-Host
if ($LASTEXITCODE -ne 0) { throw 'Could not label the high sentinel' }
& icacls.exe $highPath /grant:r "${runnerUser}:(M)" | Out-Host
if ($LASTEXITCODE -ne 0) { throw 'Could not grant same-user high sentinel access' }
[System.IO.File]::WriteAllText($highPath, 'HIGH_ONLY')
[System.IO.File]::WriteAllText($resultPath, '')
& icacls.exe $resultPath /setintegritylevel M | Out-Host
if ($LASTEXITCODE -ne 0) { throw 'Could not label the child result file medium' }
& icacls.exe $resultPath /grant:r "${runnerUser}:(M)" | Out-Host
if ($LASTEXITCODE -ne 0) { throw 'Could not grant child result write access' }

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
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool LogonUserW(string user, string domain, string password,
        int logonType, int logonProvider, out IntPtr token);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool CreateProcessWithLogonW(string user, string domain,
        string password, uint logonFlags, string application,
        StringBuilder commandLine, uint creationFlags, IntPtr environment,
        string currentDirectory, ref StartupInfo startup, out ProcessInfo process);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool CreateProcessAsUserW(IntPtr token, string application,
        StringBuilder commandLine, IntPtr processAttributes, IntPtr threadAttributes,
        bool inheritHandles, uint creationFlags, IntPtr environment, string currentDirectory,
        ref StartupInfo startup, out ProcessInfo process);
    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool GetTokenInformation(IntPtr token, int infoClass,
        IntPtr buffer, int length, out int returnLength);
    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool EqualSid(IntPtr a, IntPtr b);
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

$token = [IntPtr]::Zero
$medium = [IntPtr]::Zero
$sid = [IntPtr]::Zero
$labelBuffer = [IntPtr]::Zero
$adminSid = [IntPtr]::Zero
$disabledSids = [IntPtr]::Zero
$groupsBuffer = [IntPtr]::Zero
$ilBuffer = [IntPtr]::Zero
$low = [IntPtr]::Zero
$standardToken = [IntPtr]::Zero
$standardLow = [IntPtr]::Zero
$lowSid = [IntPtr]::Zero
$lowLabelBuffer = [IntPtr]::Zero
$proc = [MicNative+ProcessInfo]::new()
$pipeProc = [MicNative+ProcessInfo]::new()
$lowProc = [MicNative+ProcessInfo]::new()
$lowCmdProc = [MicNative+ProcessInfo]::new()
$mediumClientProc = [MicNative+ProcessInfo]::new()
$appProc = [MicNative+ProcessInfo]::new()
$validAppProc = [MicNative+ProcessInfo]::new()
$appEnvironmentPtr = [IntPtr]::Zero
try {
    if (-not [MicNative]::OpenProcessToken([MicNative]::GetCurrentProcess(), 0xF01FF, [ref]$token)) {
        throw "OpenProcessToken failed: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
    }
    if (-not [MicNative]::ConvertStringSidToSid('S-1-5-32-544', [ref]$adminSid)) {
        throw "ConvertStringSidToSid admin failed: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
    }
    $disabledSids = [Runtime.InteropServices.Marshal]::AllocHGlobal([Runtime.InteropServices.Marshal]::SizeOf([type][MicNative+SidAndAttributes]))
    $adminEntry = [MicNative+SidAndAttributes]::new()
    $adminEntry.Sid = $adminSid
    $adminEntry.Attributes = 0
    [Runtime.InteropServices.Marshal]::StructureToPtr($adminEntry, $disabledSids, $false)
    if (-not [MicNative]::CreateRestrictedToken($token, 0, 1, $disabledSids,
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
    $needed = 0
    [void][MicNative]::GetTokenInformation($medium, 2, [IntPtr]::Zero, 0, [ref]$needed)
    if ($needed -le 0) { throw 'TokenGroups sizing failed' }
    $groupsBuffer = [Runtime.InteropServices.Marshal]::AllocHGlobal($needed)
    if (-not [MicNative]::GetTokenInformation($medium, 2, $groupsBuffer, $needed, [ref]$needed)) {
        throw "TokenGroups read failed: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
    }
    $groupCount = [Runtime.InteropServices.Marshal]::ReadInt32($groupsBuffer)
    $offset = if ([IntPtr]::Size -eq 8) { 8 } else { 4 }
    $entrySize = [Runtime.InteropServices.Marshal]::SizeOf([type][MicNative+SidAndAttributes])
    $adminAttr = $null
    for ($i = 0; $i -lt $groupCount; $i++) {
        $entryPtr = [IntPtr]::Add($groupsBuffer, $offset + $i * $entrySize)
        $entry = [Runtime.InteropServices.Marshal]::PtrToStructure($entryPtr, [type][MicNative+SidAndAttributes])
        if ([MicNative]::EqualSid($entry.Sid, $adminSid)) { $adminAttr = $entry.Attributes; break }
    }
    Write-Host "admin-attributes=$adminAttr"
    if ($null -eq $adminAttr -or ($adminAttr -band 0x10) -eq 0 -or ($adminAttr -band 0x4) -ne 0) {
        throw 'Administrators SID is not deny-only'
    }
    $ilNeeded = 0
    [void][MicNative]::GetTokenInformation($medium, 25, [IntPtr]::Zero, 0, [ref]$ilNeeded)
    if ($ilNeeded -le 0) { throw 'TokenIntegrityLevel sizing failed' }
    $ilBuffer = [Runtime.InteropServices.Marshal]::AllocHGlobal($ilNeeded)
    if (-not [MicNative]::GetTokenInformation($medium, 25, $ilBuffer, $ilNeeded, [ref]$ilNeeded)) {
        throw "TokenIntegrityLevel read failed: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
    }
    $ilEntry = [Runtime.InteropServices.Marshal]::PtrToStructure($ilBuffer, [type][MicNative+MandatoryLabel])
    $isMedium = [MicNative]::EqualSid($ilEntry.Label.Sid, $sid)
    Write-Host "token-medium=$isMedium"
    if (-not $isMedium) { throw 'Restricted token is not medium integrity' }
    $startup = [MicNative+StartupInfo]::new()
    $startup.cb = [Runtime.InteropServices.Marshal]::SizeOf([type][MicNative+StartupInfo])
    $cmdExe = Join-Path $env:SystemRoot 'System32\cmd.exe'
    $commandLine = [System.Text.StringBuilder]::new("`"$cmdExe`" /D /C echo READY > $resultPath & echo CHANGED > $highPath")
    if (-not [MicNative]::CreateProcessAsUserW($medium, $cmdExe, $commandLine,
        [IntPtr]::Zero, [IntPtr]::Zero, $false, 0, [IntPtr]::Zero,
        (Join-Path $env:SystemRoot 'System32'), [ref]$startup, [ref]$proc)) {
        throw "CreateProcessAsUserW failed: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
    }
    Write-Host "child-pid=$($proc.dwProcessId)"
    $wait = [MicNative]::WaitForSingleObject($proc.hProcess, 15000)
    if ($wait -ne 0) {
        $child = Get-CimInstance Win32_Process -Filter "ProcessId=$($proc.dwProcessId)"
        throw "Restricted child did not exit: wait=$wait name=$($child.Name) result=$([System.IO.File]::ReadAllText($resultPath))"
    }
    $exitCode = [uint32]0
    [void][MicNative]::GetExitCodeProcess($proc.hProcess, [ref]$exitCode)
    Write-Host "child-exit=$exitCode"
    Write-Host 'GENERIC_MIC_CMD_RESULT'
    $result = Get-Content -LiteralPath $resultPath -Raw
    $result | Out-Host
    $highResult = [System.IO.File]::ReadAllText($highPath)
    Write-Host "high-result=$highResult"
    if ($result -notmatch 'READY' -or $highResult -ne 'HIGH_ONLY') {
        throw 'Restricted child did not write medium marker or high sentinel changed'
    }
    [System.IO.File]::WriteAllText($resultPath, '')
    $pipeName = 'generic-mic-' + [guid]::NewGuid().ToString('N')
    $childScript = Join-Path $env:PUBLIC 'Documents\mic-pipe-child.ps1'
    $childContent = @'
$ErrorActionPreference = 'Stop'
try {
    $server = [System.IO.Pipes.NamedPipeServerStream]::new('__PIPE__', [System.IO.Pipes.PipeDirection]::InOut, 1, [System.IO.Pipes.PipeTransmissionMode]::Byte, [System.IO.Pipes.PipeOptions]::None)
    [System.IO.File]::AppendAllText('__RESULT__', "PIPE_READY`n")
    $server.WaitForConnection()
    $reader = [System.IO.StreamReader]::new($server)
    $writer = [System.IO.StreamWriter]::new($server)
    $writer.AutoFlush = $true
    $message = $reader.ReadLine()
    $writer.WriteLine('PONG:' + $message)
    [System.IO.File]::AppendAllText('__RESULT__', "PIPE_DONE:$message`n")
    $server.Dispose()
} catch {
    [System.IO.File]::AppendAllText('__RESULT__', "PIPE_ERROR:$($_.Exception.Message)`n")
    exit 3
}
'@
    $childContent = $childContent.Replace('__PIPE__', $pipeName).Replace('__RESULT__', $resultPath)
    [System.IO.File]::WriteAllText($childScript, $childContent)
    & icacls.exe $childScript /setintegritylevel M | Out-Host
    if ($LASTEXITCODE -ne 0) { throw 'Could not label pipe child script medium' }
    & icacls.exe $childScript /grant:r "${runnerUser}:(R)" | Out-Host
    if ($LASTEXITCODE -ne 0) { throw 'Could not grant pipe child script read access' }
    $pwshExe = (Get-Command pwsh).Source
    $pipeCommand = [System.Text.StringBuilder]::new("`"$pwshExe`" -NoProfile -NonInteractive -File `"$childScript`"")
    if (-not [MicNative]::CreateProcessAsUserW($medium, $pwshExe, $pipeCommand,
        [IntPtr]::Zero, [IntPtr]::Zero, $false, 0, [IntPtr]::Zero,
        (Join-Path $env:SystemRoot 'System32'), [ref]$startup, [ref]$pipeProc)) {
        throw "Pipe child CreateProcessAsUserW failed: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
    }
    Write-Host "pipe-child-pid=$($pipeProc.dwProcessId)"
    $ready = $false
    for ($attempt = 0; $attempt -lt 100; $attempt++) {
        $status = [System.IO.File]::ReadAllText($resultPath)
        if ($status.Contains('PIPE_READY')) { $ready = $true; break }
        if ($status.Contains('PIPE_ERROR')) { throw "Pipe child error: $status" }
        Start-Sleep -Milliseconds 100
    }
    if (-not $ready) { throw "Pipe child did not become ready: $([System.IO.File]::ReadAllText($resultPath))" }
    $client = [System.IO.Pipes.NamedPipeClientStream]::new('.', $pipeName, [System.IO.Pipes.PipeDirection]::InOut)
    try {
        $client.Connect(5000)
        $reader = [System.IO.StreamReader]::new($client)
        $writer = [System.IO.StreamWriter]::new($client)
        $writer.AutoFlush = $true
        $writer.WriteLine('PING')
        $reply = $reader.ReadLine()
        Write-Host "pipe-reply=$reply"
        if ($reply -ne 'PONG:PING') { throw 'High client did not receive lower server reply' }
    } finally { $client.Dispose() }
    $pipeWait = [MicNative]::WaitForSingleObject($pipeProc.hProcess, 5000)
    if ($pipeWait -ne 0) { throw "Pipe child did not exit: wait=$pipeWait" }
    $pipeResult = [System.IO.File]::ReadAllText($resultPath)
    Write-Host "pipe-child-result=$pipeResult"
    if (-not $pipeResult.Contains('PIPE_DONE:PING')) { throw 'Pipe child did not observe high client message' }

    # EOP-062 prerequisite: a same-user low-integrity server must be accepted
    # by an ordinary medium-integrity CurrentUserOnly client. No Roslyn bytes
    # or project data are used in this generic transport discriminator.
    if (-not [MicNative]::CreateRestrictedToken($token, 0, 1, $disabledSids,
        0, [IntPtr]::Zero, 0, [IntPtr]::Zero, [ref]$low)) {
        throw "Low CreateRestrictedToken failed: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
    }
    if (-not [MicNative]::ConvertStringSidToSid('S-1-16-4096', [ref]$lowSid)) {
        throw "Low ConvertStringSidToSid failed: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
    }
    $lowHeaderLength = [Runtime.InteropServices.Marshal]::SizeOf([type][MicNative+MandatoryLabel])
    $lowSidLength = [int][MicNative]::GetLengthSid($lowSid)
    $lowLabelLength = $lowHeaderLength + $lowSidLength
    $lowLabelBuffer = [Runtime.InteropServices.Marshal]::AllocHGlobal($lowLabelLength)
    $lowSidCopy = [IntPtr]::Add($lowLabelBuffer, $lowHeaderLength)
    $lowSidBytes = [byte[]]::new($lowSidLength)
    [Runtime.InteropServices.Marshal]::Copy($lowSid, $lowSidBytes, 0, $lowSidLength)
    [Runtime.InteropServices.Marshal]::Copy($lowSidBytes, 0, $lowSidCopy, $lowSidLength)
    $lowSidAndAttributes = [MicNative+SidAndAttributes]::new()
    $lowSidAndAttributes.Sid = $lowSidCopy
    $lowSidAndAttributes.Attributes = 0x20
    $lowLabel = [MicNative+MandatoryLabel]::new()
    $lowLabel.Label = $lowSidAndAttributes
    [Runtime.InteropServices.Marshal]::StructureToPtr($lowLabel, $lowLabelBuffer, $false)
    if (-not [MicNative]::SetTokenInformation($low, 25, $lowLabelBuffer, $lowLabelLength)) {
        throw "Low SetTokenInformation failed: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
    }
    $lowResult = Join-Path $env:RUNNER_TEMP 'eop062-low-result.txt'
    [System.IO.File]::WriteAllText($lowResult, '')
    & icacls.exe $lowResult /setintegritylevel L | Out-Host
    if ($LASTEXITCODE -ne 0) { throw 'Could not label low result file' }
    & icacls.exe $lowResult /grant:r "${runnerUser}:(M)" | Out-Host
    if ($LASTEXITCODE -ne 0) { throw 'Could not grant low result write' }
    [System.IO.File]::WriteAllText($resultPath, '')

    $eopPipeName = 'eop062-generic-' + [guid]::NewGuid().ToString('N')
    $lowScript = Join-Path $env:PUBLIC 'Documents\eop062-low-server.ps1'
    $lowContent = @'
$ErrorActionPreference = 'Stop'
try {
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    [System.IO.File]::AppendAllText('__LOWRESULT__', "LOW_OWNER=$($identity.Owner.Value) LOW_USER=$($identity.User.Value)`n")
    try {
        [System.IO.File]::AppendAllText('__MEDIUMRESULT__', 'LOW_WRITE_UP')
        [System.IO.File]::AppendAllText('__LOWRESULT__', "LOW_MEDIUM_WRITE=ALLOWED`n")
    } catch {
        [System.IO.File]::AppendAllText('__LOWRESULT__', "LOW_MEDIUM_WRITE=DENIED`n")
    }
    $server = [System.IO.Pipes.NamedPipeServerStream]::new('__PIPE__', [System.IO.Pipes.PipeDirection]::InOut, 1, [System.IO.Pipes.PipeTransmissionMode]::Byte, [System.IO.Pipes.PipeOptions]::None)
    [System.IO.File]::AppendAllText('__LOWRESULT__', "LOW_PIPE_READY`n")
    $server.WaitForConnection()
    $reader = [System.IO.StreamReader]::new($server)
    $writer = [System.IO.StreamWriter]::new($server)
    $writer.AutoFlush = $true
    $message = $reader.ReadLine()
    $writer.WriteLine('PONG:' + $message)
    [System.IO.File]::AppendAllText('__LOWRESULT__', "LOW_PIPE_DONE:$message`n")
    $server.Dispose()
} catch {
    [System.IO.File]::AppendAllText('__LOWRESULT__', "LOW_ERROR:$($_.Exception.GetType().Name):$($_.Exception.Message)`n")
    exit 3
}
'@
    $lowContent = $lowContent.Replace('__LOWRESULT__', $lowResult).Replace('__MEDIUMRESULT__', $resultPath).Replace('__PIPE__', $eopPipeName)
    [System.IO.File]::WriteAllText($lowScript, $lowContent)
    & icacls.exe $lowScript /grant:r "${runnerUser}:(R)" | Out-Host
    if ($LASTEXITCODE -ne 0) { throw 'Could not grant low script read' }
    $lowCmdLine = [System.Text.StringBuilder]::new("`"$cmdExe`" /D /C echo LOW_CMD_READY > `"$lowResult`"")
    $lowCmdLaunched = [MicNative]::CreateProcessAsUserW($low, $cmdExe, $lowCmdLine,
        [IntPtr]::Zero, [IntPtr]::Zero, $false, 0, [IntPtr]::Zero,
        (Join-Path $env:SystemRoot 'System32'), [ref]$startup, [ref]$lowCmdProc)
    if (-not $lowCmdLaunched) {
        $lowCmdAsUserError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Host "low-cmd-CreateProcessAsUserW-error=$lowCmdAsUserError"
        if ($lowCmdAsUserError -ne 1314) { throw "Low cmd launch failed: $lowCmdAsUserError" }
        $lowCmdLine = [System.Text.StringBuilder]::new("`"$cmdExe`" /D /C echo LOW_CMD_READY > `"$lowResult`"")
        $lowCmdLaunched = [MicNative]::CreateProcessWithTokenW($low, 0, $cmdExe,
            $lowCmdLine, 0, [IntPtr]::Zero,
            (Join-Path $env:SystemRoot 'System32'), [ref]$startup, [ref]$lowCmdProc)
        if (-not $lowCmdLaunched) {
            throw "Low cmd CreateProcessWithTokenW failed: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
        }
    }
    $lowCmdWait = [MicNative]::WaitForSingleObject($lowCmdProc.hProcess, 10000)
    $lowCmdExit = [uint32]0
    [void][MicNative]::GetExitCodeProcess($lowCmdProc.hProcess, [ref]$lowCmdExit)
    Write-Host "low-cmd-wait=$lowCmdWait low-cmd-exit=$lowCmdExit low-cmd-result=$([System.IO.File]::ReadAllText($lowResult))"
    if ($lowCmdWait -ne 0 -or -not ([System.IO.File]::ReadAllText($lowResult)).Contains('LOW_CMD_READY')) {
        throw 'Low cmd could not write its low-integrity result file'
    }
    [System.IO.File]::WriteAllText($lowResult, '')
    $lowCommand = [System.Text.StringBuilder]::new("`"$pwshExe`" -NoProfile -NonInteractive -File `"$lowScript`"")
    $lowLaunched = [MicNative]::CreateProcessAsUserW($low, $pwshExe, $lowCommand,
        [IntPtr]::Zero, [IntPtr]::Zero, $false, 0, [IntPtr]::Zero,
        (Join-Path $env:SystemRoot 'System32'), [ref]$startup, [ref]$lowProc)
    if (-not $lowLaunched) {
        $asUserError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Host "low-CreateProcessAsUserW-error=$asUserError"
        if ($asUserError -ne 1314) { throw "Low server CreateProcessAsUserW failed: $asUserError" }
        $lowCommand = [System.Text.StringBuilder]::new("`"$pwshExe`" -NoProfile -NonInteractive -File `"$lowScript`"")
        $lowLaunched = [MicNative]::CreateProcessWithTokenW($low, 0, $pwshExe,
            $lowCommand, 0, [IntPtr]::Zero,
            (Join-Path $env:SystemRoot 'System32'), [ref]$startup, [ref]$lowProc)
        if (-not $lowLaunched) {
            throw "Low server CreateProcessWithTokenW failed: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
        }
        Write-Host 'low-launch=CreateProcessWithTokenW'
    } else {
        Write-Host 'low-launch=CreateProcessAsUserW'
    }
    Write-Host "low-server-pid=$($lowProc.dwProcessId)"
    $lowReady = $false
    for ($attempt = 0; $attempt -lt 300; $attempt++) {
        $status = [System.IO.File]::ReadAllText($lowResult)
        if ($status.Contains('LOW_PIPE_READY')) { $lowReady = $true; break }
        if ($status.Contains('LOW_ERROR')) { throw "Low server error: $status" }
        Start-Sleep -Milliseconds 100
    }
    if (-not $lowReady) {
        $lowWaitState = [MicNative]::WaitForSingleObject($lowProc.hProcess, 0)
        $lowExitCode = [uint32]0
        [void][MicNative]::GetExitCodeProcess($lowProc.hProcess, [ref]$lowExitCode)
        $lowProcess = Get-CimInstance Win32_Process -Filter "ProcessId=$($lowProc.dwProcessId)" -ErrorAction SilentlyContinue
        Write-Host "low-wait-state=$lowWaitState low-exit-code=$lowExitCode low-process=$($lowProcess.Name)"
        & icacls.exe $lowResult | Out-Host
        & icacls.exe (Split-Path $lowResult -Parent) | Out-Host
        throw "Low server not ready: $([System.IO.File]::ReadAllText($lowResult))"
    }

    $mediumClientScript = Join-Path $env:PUBLIC 'Documents\eop062-medium-client.ps1'
    $mediumClientContent = @'
$ErrorActionPreference = 'Stop'
try {
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    [System.IO.File]::AppendAllText('__MEDIUMRESULT__', "MEDIUM_OWNER=$($identity.Owner.Value) MEDIUM_USER=$($identity.User.Value)`n")
    $client = [System.IO.Pipes.NamedPipeClientStream]::new('.', '__PIPE__', [System.IO.Pipes.PipeDirection]::InOut, [System.IO.Pipes.PipeOptions]::CurrentUserOnly)
    $client.Connect(5000)
    $reader = [System.IO.StreamReader]::new($client)
    $writer = [System.IO.StreamWriter]::new($client)
    $writer.AutoFlush = $true
    $writer.WriteLine('PING')
    $reply = $reader.ReadLine()
    [System.IO.File]::AppendAllText('__MEDIUMRESULT__', "MEDIUM_PIPE_REPLY=$reply`n")
    $client.Dispose()
} catch {
    [System.IO.File]::AppendAllText('__MEDIUMRESULT__', "MEDIUM_ERROR:$($_.Exception.GetType().Name):$($_.Exception.Message)`n")
    exit 4
}
'@
    $mediumClientContent = $mediumClientContent.Replace('__MEDIUMRESULT__', $resultPath).Replace('__PIPE__', $eopPipeName)
    [System.IO.File]::WriteAllText($mediumClientScript, $mediumClientContent)
    & icacls.exe $mediumClientScript /grant:r "${runnerUser}:(R)" | Out-Host
    if ($LASTEXITCODE -ne 0) { throw 'Could not grant medium client script read' }
    $mediumClientCommand = [System.Text.StringBuilder]::new("`"$pwshExe`" -NoProfile -NonInteractive -File `"$mediumClientScript`"")
    if (-not [MicNative]::CreateProcessAsUserW($medium, $pwshExe, $mediumClientCommand,
        [IntPtr]::Zero, [IntPtr]::Zero, $false, 0, [IntPtr]::Zero,
        (Join-Path $env:SystemRoot 'System32'), [ref]$startup, [ref]$mediumClientProc)) {
        throw "Medium client CreateProcessAsUserW failed: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
    }
    Write-Host "medium-client-pid=$($mediumClientProc.dwProcessId)"
    $mediumWait = [MicNative]::WaitForSingleObject($mediumClientProc.hProcess, 15000)
    if ($mediumWait -ne 0) { throw "Medium client timed out: wait=$mediumWait" }
    $lowWait = [MicNative]::WaitForSingleObject($lowProc.hProcess, 5000)
    if ($lowWait -ne 0) { throw "Low server timed out: wait=$lowWait" }
    $lowText = [System.IO.File]::ReadAllText($lowResult)
    $mediumText = [System.IO.File]::ReadAllText($resultPath)
    Write-Host "LOW_RESULT:$lowText"
    Write-Host "MEDIUM_RESULT:$mediumText"
    if (-not $lowText.Contains('LOW_MEDIUM_WRITE=DENIED') -or
        -not $lowText.Contains('LOW_PIPE_DONE:PING') -or
        -not $mediumText.Contains('MEDIUM_PIPE_REPLY=PONG:PING')) {
        throw 'Low to medium generic CurrentUserOnly matrix did not reach protected transport terminal'
    }

    # Product join: use the installed SDK and its ordinary default pipe name.
    $sdkVersion = (& dotnet --version).Trim()
    Write-Host "installed-sdk=$sdkVersion"
    if ($sdkVersion -ne '11.0.100') { throw 'Expected released SDK 11.0.100' }
    $sdkList = & dotnet --list-sdks
    $sdkEntry = $sdkList | Where-Object { $_ -match '^11\.0\.100\s+\[' } | Select-Object -First 1
    $sdkMatch = [regex]::Match($sdkEntry, '^11\.0\.100\s+\[(.+)\]$')
    if (-not $sdkMatch.Success) { throw "Could not identify SDK root: $sdkEntry" }
    $sdkRoot = Join-Path $sdkMatch.Groups[1].Value '11.0.100'
    $compilerDir = Join-Path $sdkRoot 'Roslyn\bincore'
    if (-not (Test-Path (Join-Path $compilerDir 'csc.dll'))) { throw "Missing installed csc.dll: $compilerDir" }
    $testUser = 'eop062' + [guid]::NewGuid().ToString('N').Substring(0,8)
    $testPassword = 'Aa1!' + [guid]::NewGuid().ToString('N').Substring(0,8)
    $testAccount = "$env:COMPUTERNAME\$testUser"
    & net.exe user $testUser $testPassword /add /expires:never /passwordchg:no | Out-Host
    if ($LASTEXITCODE -ne 0) { throw 'Could not create isolated standard Windows account' }
    if (-not [MicNative]::LogonUserW($testUser, '.', $testPassword, 2, 0, [ref]$standardToken)) {
        throw "Isolated standard user logon failed: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
    }
    $standardIdentity = [System.Security.Principal.WindowsIdentity]::new($standardToken)
    Write-Host "STANDARD_OWNER=$($standardIdentity.Owner.Value) STANDARD_USER=$($standardIdentity.User.Value)"
    if ($standardIdentity.Owner.Value -ne $standardIdentity.User.Value) { throw 'Standard account owner/user mismatch' }
    $standardILNeeded = 0
    [void][MicNative]::GetTokenInformation($standardToken, 25, [IntPtr]::Zero, 0, [ref]$standardILNeeded)
    if ($standardILNeeded -le 0) { throw 'Standard token integrity sizing failed' }
    $standardILBuffer = [Runtime.InteropServices.Marshal]::AllocHGlobal($standardILNeeded)
    try {
        if (-not [MicNative]::GetTokenInformation($standardToken, 25, $standardILBuffer, $standardILNeeded, [ref]$standardILNeeded)) {
            throw "Standard token integrity read failed: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
        }
        $standardILEntry = [Runtime.InteropServices.Marshal]::PtrToStructure($standardILBuffer, [type][MicNative+MandatoryLabel])
        $standardIsMedium = [MicNative]::EqualSid($standardILEntry.Label.Sid, $sid)
        Write-Host "STANDARD_MEDIUM=$standardIsMedium"
        if (-not $standardIsMedium) { throw 'Standard account token is not medium integrity' }
    } finally { [Runtime.InteropServices.Marshal]::FreeHGlobal($standardILBuffer) }
    if (-not [MicNative]::CreateRestrictedToken($standardToken, 0, 0, [IntPtr]::Zero,
        0, [IntPtr]::Zero, 0, [IntPtr]::Zero, [ref]$standardLow)) {
        throw "Standard low-token duplication failed: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
    }
    if (-not [MicNative]::SetTokenInformation($standardLow, 25, $lowLabelBuffer, $lowLabelLength)) {
        throw "Standard low integrity assignment failed: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
    }
    $pipeInput = "{0}.False.{1}" -f $testUser, $compilerDir.TrimEnd('\').ToLowerInvariant()
    $pipeHash = [Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($pipeInput))
    $compilerPipe = [Convert]::ToBase64String($pipeHash).Replace('/', '_').Replace('=', '')
    Write-Host "compiler-dir=$compilerDir default-pipe=$compilerPipe"

    $labRoot = Join-Path $env:PUBLIC ('Documents\eop062-roslyn-auth-' + [guid]::NewGuid().ToString('N'))
    [void][System.IO.Directory]::CreateDirectory($labRoot)
    & icacls.exe $labRoot /grant:r "${testAccount}:(OI)(CI)(M)" | Out-Host
    if ($LASTEXITCODE -ne 0) { throw 'Could not grant lab directory' }
    & icacls.exe $labRoot /setintegritylevel '(OI)(CI)M' | Out-Host
    if ($LASTEXITCODE -ne 0) { throw 'Could not label lab directory medium' }
    $project = Join-Path $labRoot 'AdminApp.csproj'
    $source = Join-Path $labRoot 'Program.cs'
    $markerPath = Join-Path $labRoot 'protected-marker.txt'
    $baseUrl = 'http://127.0.0.1:50562'
    [System.IO.File]::WriteAllText($project, '<Project Sdk="Microsoft.NET.Sdk.Web"><PropertyGroup><TargetFramework>net11.0</TargetFramework><ImplicitUsings>enable</ImplicitUsings><Nullable>enable</Nullable><UseAppHost>false</UseAppHost></PropertyGroup></Project>')
    $oldSource = @'
using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddAuthentication("Lab").AddScheme<AuthenticationSchemeOptions, LabAuthHandler>("Lab", _ => { });
builder.Services.AddAuthorization(options => options.AddPolicy("Admin", policy => policy.RequireRole("Admin")));
var app = builder.Build();
app.UseAuthentication();
app.UseAuthorization();
app.MapGet("/health", () => Results.Ok("READY"));
app.MapPost("/admin", () =>
{
    var marker = Environment.GetEnvironmentVariable("EOP062_MARKER")!;
    File.WriteAllText(marker, "PROTECTED_INERT_MARKER_062");
    return Results.Ok("MARKER_WRITTEN");
}); // OLD_PUBLIC_ADMIN_062
app.Run();

sealed class LabAuthHandler : AuthenticationHandler<AuthenticationSchemeOptions>
{
    public LabAuthHandler(IOptionsMonitor<AuthenticationSchemeOptions> options,
        ILoggerFactory logger, UrlEncoder encoder) : base(options, logger, encoder) { }

    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (Request.Headers.TryGetValue("X-Lab-Admin", out var value) && value == "owner")
        {
            var identity = new ClaimsIdentity(new[] {
                new Claim(ClaimTypes.Name, "owner"), new Claim(ClaimTypes.Role, "Admin")
            }, "Lab");
            return Task.FromResult(AuthenticateResult.Success(
                new AuthenticationTicket(new ClaimsPrincipal(identity), "Lab")));
        }
        return Task.FromResult(AuthenticateResult.NoResult());
    }
}
'@
    $secureSource = $oldSource.Replace('}); // OLD_PUBLIC_ADMIN_062', '}).RequireAuthorization("Admin"); // NEW_PROTECTED_ADMIN_062')
    if ($secureSource -eq $oldSource) { throw 'Secure source transition failed' }
    [System.IO.File]::WriteAllText($source, $oldSource)
    $dotnetExe = (Get-Command dotnet).Source
    & $dotnetExe restore $project --ignore-failed-sources | Out-Host
    if ($LASTEXITCODE -ne 0) { throw 'Owned project restore failed' }
    & icacls.exe $labRoot /grant:r "${testAccount}:(OI)(CI)(M)" /T | Out-Host
    if ($LASTEXITCODE -ne 0) { throw 'Could not grant restored lab tree' }
    & icacls.exe $labRoot /setintegritylevel M /T | Out-Host
    if ($LASTEXITCODE -ne 0) { throw 'Could not label restored lab tree medium' }
    $outputDll = Join-Path $labRoot 'bin\Debug\net11.0\AdminApp.dll'
    & $dotnetExe build $project --no-restore -v:minimal '-p:UseSharedCompilation=false' | Out-Host
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path $outputDll)) { throw 'Public baseline build failed' }
    $oldHash = (Get-FileHash $outputDll -Algorithm SHA256).Hash
    Write-Host "PUBLIC_BASELINE hash=$oldHash"
    & icacls.exe $labRoot /grant:r "${testAccount}:(OI)(CI)(M)" /T | Out-Host
    if ($LASTEXITCODE -ne 0) { throw 'Could not grant baseline lab tree' }
    & icacls.exe $labRoot /setintegritylevel M /T | Out-Host
    if ($LASTEXITCODE -ne 0) { throw 'Could not label baseline lab tree medium' }
    [System.IO.File]::WriteAllText($source, $secureSource)
    Write-Host "SECURED_SOURCE hash=$((Get-FileHash $source -Algorithm SHA256).Hash)"

    function Invoke-MediumBuild([string]$label, [string]$extra) {
        $cmdFile = Join-Path $labRoot "$label.cmd"
        $logFile = Join-Path $labRoot "$label.log"
        $cmdText = "@echo off`r`nset DOTNET_CLI_HOME=$labRoot`r`nwhoami /user > `"$logFile`" 2>&1`r`nwhoami /groups >> `"$logFile`" 2>&1`r`n`"$dotnetExe`" build `"$project`" --no-restore -v:minimal $extra >> `"$logFile`" 2>&1`r`nexit /b %ERRORLEVEL%`r`n"
        [System.IO.File]::WriteAllText($cmdFile, $cmdText)
        $mediumCommand = [System.Text.StringBuilder]::new("`"$cmdExe`" /D /C `"$cmdFile`"")
        $buildProc = [MicNative+ProcessInfo]::new()
        if (-not [MicNative]::CreateProcessWithLogonW($testUser, '.', $testPassword,
            1, $cmdExe, $mediumCommand, 0, [IntPtr]::Zero,
            (Join-Path $env:SystemRoot 'System32'), [ref]$startup, [ref]$buildProc)) {
            throw "Standard-account build launch failed: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
        }
        $waitResult = [MicNative]::WaitForSingleObject($buildProc.hProcess, 120000)
        $buildExit = [uint32]0
        [void][MicNative]::GetExitCodeProcess($buildProc.hProcess, [ref]$buildExit)
        if ($buildProc.hThread -ne [IntPtr]::Zero) { [void][MicNative]::CloseHandle($buildProc.hThread) }
        if ($buildProc.hProcess -ne [IntPtr]::Zero) { [void][MicNative]::CloseHandle($buildProc.hProcess) }
        $buildLog = if (Test-Path $logFile) { [System.IO.File]::ReadAllText($logFile) } else { '<no log>' }
        Write-Host "MEDIUM_BUILD label=$label wait=$waitResult exit=$buildExit dll=$((Test-Path $outputDll))"
        if ($label -eq 'valid') {
            $interesting = $buildLog -split "`r?`n" | Select-String -Pattern 'MSB3883|Access is denied|Exception|Csc|CoreCompile|ToolPath|Task Parameter|UsingTask' -Context 2,2 | Select-Object -Last 25
            Write-Host "MEDIUM_BUILD_DIAGNOSTIC_BEGIN $label`n$($interesting | Out-String)`nMEDIUM_BUILD_DIAGNOSTIC_END $label"
        } else {
            Write-Host "MEDIUM_BUILD_LOG_BEGIN $label`n$buildLog`nMEDIUM_BUILD_LOG_END $label"
        }
        if ($waitResult -ne 0) { throw "Medium build timed out: $label" }
        return $buildExit
    }

    $prevalidExit = Invoke-MediumBuild 'prevalid' '-p:UseSharedCompilation=false'
    $prevalidHash = if (Test-Path $outputDll) { (Get-FileHash $outputDll -Algorithm SHA256).Hash } else { '<absent>' }
    Write-Host "PREVALID_NO_ACTOR exit=$prevalidExit hash=$prevalidHash"
    if ($prevalidExit -eq 0) {
        if ($prevalidHash -eq $oldHash) { throw 'No-actor medium build retained old output' }
        [System.IO.File]::WriteAllText($source, $oldSource)
        & $dotnetExe build $project --no-restore -v:minimal '-p:UseSharedCompilation=false' | Out-Host
        if ($LASTEXITCODE -ne 0) { throw 'Could not reseed public baseline after no-actor control' }
        & icacls.exe $labRoot /setintegritylevel '(OI)(CI)M' | Out-Host
        if ($LASTEXITCODE -ne 0) { throw 'Could not relabel reseeded lab root medium' }
        foreach ($protectedPath in @($source, $project, $outputDll, (Join-Path $labRoot 'obj\Debug\net11.0\AdminApp.dll'))) {
            & icacls.exe $protectedPath /setintegritylevel M | Out-Host
            if ($LASTEXITCODE -ne 0) { throw "Could not relabel reseeded protected path: $protectedPath" }
        }
        $oldHash = (Get-FileHash $outputDll -Algorithm SHA256).Hash
        [System.IO.File]::WriteAllText($source, $secureSource)
        Write-Host "RESEEDED_PUBLIC hash=$oldHash"
    }

    $actorResult = Join-Path $labRoot 'roslyn-low-result.txt'
    [System.IO.File]::WriteAllText($actorResult, '')
    & icacls.exe $actorResult /setintegritylevel L | Out-Host
    & icacls.exe $actorResult /grant:r "${testAccount}:(M)" | Out-Host
    $actorScript = Join-Path $labRoot 'roslyn-low-server.ps1'
    $actorContent = @'
$ErrorActionPreference = 'Stop'
$log = '__LOG__'
function Record([string]$value) { [System.IO.File]::AppendAllText($log, "$value`n") }
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public static class LowSelfNative {
    [StructLayout(LayoutKind.Sequential)] public struct SidAndAttributes { public IntPtr Sid; public uint Attributes; }
    [StructLayout(LayoutKind.Sequential)] public struct MandatoryLabel { public SidAndAttributes Label; }
    [DllImport("kernel32.dll")] public static extern IntPtr GetCurrentProcess();
    [DllImport("advapi32.dll", SetLastError=true)] public static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)] public static extern bool ConvertStringSidToSid(string sid, out IntPtr output);
    [DllImport("advapi32.dll", SetLastError=true)] public static extern uint GetLengthSid(IntPtr sid);
    [DllImport("advapi32.dll", SetLastError=true)] public static extern bool SetTokenInformation(IntPtr token, int infoClass, IntPtr label, int length);
    [DllImport("advapi32.dll", SetLastError=true)] public static extern bool GetTokenInformation(IntPtr token, int infoClass, IntPtr buffer, int length, out int returnLength);
    [DllImport("advapi32.dll", SetLastError=true)] public static extern bool EqualSid(IntPtr a, IntPtr b);
    [DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll")] public static extern IntPtr LocalFree(IntPtr handle);
}
"@
function ReadExact($stream, [int]$size) {
    $buffer = [byte[]]::new($size)
    $offset = 0
    while ($offset -lt $size) {
        $count = $stream.Read($buffer, $offset, $size - $offset)
        if ($count -le 0) { throw 'Short compiler request' }
        $offset += $count
    }
    return ,$buffer
}
try {
    $ownToken = [IntPtr]::Zero
    $lowSid = [IntPtr]::Zero
    $labelBuffer = [IntPtr]::Zero
    $ilBuffer = [IntPtr]::Zero
    try {
        if (-not [LowSelfNative]::OpenProcessToken([LowSelfNative]::GetCurrentProcess(), 0x88, [ref]$ownToken)) { throw "Self token open failed: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())" }
        if (-not [LowSelfNative]::ConvertStringSidToSid('S-1-16-4096', [ref]$lowSid)) { throw 'Low SID conversion failed' }
        $headerLength = [Runtime.InteropServices.Marshal]::SizeOf([type][LowSelfNative+MandatoryLabel])
        $sidLength = [int][LowSelfNative]::GetLengthSid($lowSid)
        $labelLength = $headerLength + $sidLength
        $labelBuffer = [Runtime.InteropServices.Marshal]::AllocHGlobal($labelLength)
        $sidCopy = [IntPtr]::Add($labelBuffer, $headerLength)
        $sidBytes = [byte[]]::new($sidLength)
        [Runtime.InteropServices.Marshal]::Copy($lowSid, $sidBytes, 0, $sidLength)
        [Runtime.InteropServices.Marshal]::Copy($sidBytes, 0, $sidCopy, $sidLength)
        $sidAndAttributes = [LowSelfNative+SidAndAttributes]::new()
        $sidAndAttributes.Sid = $sidCopy
        $sidAndAttributes.Attributes = 0x20
        $entry = [LowSelfNative+MandatoryLabel]::new()
        $entry.Label = $sidAndAttributes
        [Runtime.InteropServices.Marshal]::StructureToPtr($entry, $labelBuffer, $false)
        $checkEntry = [Runtime.InteropServices.Marshal]::PtrToStructure($labelBuffer, [type][LowSelfNative+MandatoryLabel])
        if ($checkEntry.Label.Sid -ne $sidCopy -or $checkEntry.Label.Attributes -ne 0x20) { throw 'Self low label buffer construction failed' }
        if (-not [LowSelfNative]::SetTokenInformation($ownToken, 25, $labelBuffer, $labelLength)) { throw "Self low downgrade failed: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())" }
        $ilNeeded = 0
        [void][LowSelfNative]::GetTokenInformation($ownToken, 25, [IntPtr]::Zero, 0, [ref]$ilNeeded)
        $ilBuffer = [Runtime.InteropServices.Marshal]::AllocHGlobal($ilNeeded)
        if (-not [LowSelfNative]::GetTokenInformation($ownToken, 25, $ilBuffer, $ilNeeded, [ref]$ilNeeded)) { throw 'Self low verification query failed' }
        $ilEntry = [Runtime.InteropServices.Marshal]::PtrToStructure($ilBuffer, [type][LowSelfNative+MandatoryLabel])
        if (-not [LowSelfNative]::EqualSid($ilEntry.Label.Sid, $lowSid)) { throw 'Self token did not become Low IL' }
        Record 'LOW_SELF_DOWNGRADE=VERIFIED'
    } finally {
        if ($ilBuffer -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::FreeHGlobal($ilBuffer) }
        if ($labelBuffer -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::FreeHGlobal($labelBuffer) }
        if ($lowSid -ne [IntPtr]::Zero) { [void][LowSelfNative]::LocalFree($lowSid) }
        if ($ownToken -ne [IntPtr]::Zero) { [void][LowSelfNative]::CloseHandle($ownToken) }
    }
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    Record "LOW_OWNER=$($identity.Owner.Value) LOW_USER=$($identity.User.Value)"
    try {
        [System.IO.File]::AppendAllText('__SOURCE__', 'LOW_UNAUTHORIZED_WRITE')
        Record 'LOW_SOURCE_WRITE=ALLOWED'
        throw 'Low actor unexpectedly wrote source'
    } catch [System.UnauthorizedAccessException] {
        Record 'LOW_SOURCE_WRITE=DENIED'
    }
    try {
        [System.IO.File]::WriteAllText('__PROJECT_PROBE__', 'LOW_UNAUTHORIZED_WRITE')
        Record 'LOW_PROJECT_WRITE=ALLOWED'
        throw 'Low actor unexpectedly wrote project directory'
    } catch [System.UnauthorizedAccessException] {
        Record 'LOW_PROJECT_WRITE=DENIED'
    }
    try {
        [System.IO.File]::WriteAllText('__MARKER__', 'LOW_UNAUTHORIZED_WRITE')
        Record 'LOW_MARKER_WRITE=ALLOWED'
        throw 'Low actor unexpectedly wrote protected marker'
    } catch [System.UnauthorizedAccessException] {
        Record 'LOW_MARKER_WRITE=DENIED'
    }
    $server = [System.IO.Pipes.NamedPipeServerStream]::new('__PIPE__', [System.IO.Pipes.PipeDirection]::InOut, 1, [System.IO.Pipes.PipeTransmissionMode]::Byte, [System.IO.Pipes.PipeOptions]::None)
    Record 'ROSLYN_PIPE_READY'
    $server.WaitForConnection()
    $lengthBytes = ReadExact $server 4
    $length = [BitConverter]::ToInt32($lengthBytes, 0)
    if ($length -le 0 -or $length -gt 4000000) { throw "Invalid request size $length" }
    $payload = ReadExact $server $length
    $hex = [Convert]::ToHexString($payload)
    $projectHex = [Convert]::ToHexString([Text.Encoding]::Unicode.GetBytes('AdminApp'))
    $sourceHex = [Convert]::ToHexString([Text.Encoding]::Unicode.GetBytes('Program.cs'))
    $target = $hex.Contains($projectHex) -and $hex.Contains($sourceHex)
    Record "ROSLYN_REQUEST_LENGTH=$length TARGET=$target"
    if (-not $target) { throw 'Refusing fake success for non-target request' }
    [byte[]]$response = @(255,255,255,255)
    $server.Write($response, 0, $response.Length)
    $server.Flush()
    Record 'SENT_MALFORMED_LENGTH'
    $server.Dispose()
    $http = [System.Net.Http.HttpClient]::new()
    $http.Timeout = [TimeSpan]::FromSeconds(2)
    $ready = $false
    for ($attempt = 0; $attempt -lt 150; $attempt++) {
        try {
            $health = $http.GetAsync('__URL__/health').GetAwaiter().GetResult()
            if ([int]$health.StatusCode -eq 200) { $ready = $true; break }
        } catch { }
        Start-Sleep -Milliseconds 100
    }
    if (-not $ready) { throw 'Launched application did not become healthy for low actor' }
    $post = $http.PostAsync('__URL__/admin', [System.Net.Http.StringContent]::new('')).GetAwaiter().GetResult()
    Record "LOW_ANON_ADMIN_STATUS=$([int]$post.StatusCode)"
    $http.Dispose()
} catch {
    Record "ROSLYN_ACTOR_ERROR=$($_.Exception.GetType().Name):$($_.Exception.Message)"
    exit 3
}
'@
    $actorContent = $actorContent.Replace('__LOG__', $actorResult).Replace('__SOURCE__', $source).Replace('__PROJECT_PROBE__', (Join-Path $labRoot 'low-probe.txt')).Replace('__MARKER__', $markerPath).Replace('__URL__', $baseUrl).Replace('__PIPE__', $compilerPipe)
    [System.IO.File]::WriteAllText($actorScript, $actorContent)
    $actorCommand = [System.Text.StringBuilder]::new("`"$pwshExe`" -NoProfile -NonInteractive -File `"$actorScript`"")
    $roslynActorProc = [MicNative+ProcessInfo]::new()
    if (-not [MicNative]::CreateProcessWithLogonW($testUser, '.', $testPassword,
        1, $pwshExe, $actorCommand, 0, [IntPtr]::Zero,
        (Join-Path $env:SystemRoot 'System32'), [ref]$startup, [ref]$roslynActorProc)) {
        throw "Standard actor logon launch failed: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
    }
    Write-Host 'STANDARD_LOW_LAUNCH=CreateProcessWithLogonW_then_self_downgrade'
    $actorReady = $false
    for ($attempt = 0; $attempt -lt 150; $attempt++) {
        $actorState = [System.IO.File]::ReadAllText($actorResult)
        if ($actorState.Contains('ROSLYN_PIPE_READY')) { $actorReady = $true; break }
        if ($actorState.Contains('ROSLYN_ACTOR_ERROR')) { throw "Low actor error: $actorState" }
        Start-Sleep -Milliseconds 100
    }
    if (-not $actorReady) { throw "Low actor not ready: $([System.IO.File]::ReadAllText($actorResult))" }
    $forgedExit = Invoke-MediumBuild 'forged' ''
    $forgedExists = Test-Path $outputDll
    $forgedHash = if ($forgedExists) { (Get-FileHash $outputDll -Algorithm SHA256).Hash } else { '<absent>' }
    Write-Host "FORGED_RESULT exit=$forgedExit dll=$forgedExists hash=$forgedHash"
    $markerBeforeLaunch = Test-Path $markerPath
    Write-Host "MARKER_BEFORE_LAUNCH=$markerBeforeLaunch"
    $dotnetRoot = [System.IO.Path]::GetDirectoryName($dotnetExe)
    $appEnvironment = @(
        "ASPNETCORE_URLS=$baseUrl",
        "DOTNET_ROOT=$dotnetRoot",
        "EOP062_MARKER=$markerPath",
        "PATH=$dotnetRoot;$env:SystemRoot\System32",
        "SystemRoot=$env:SystemRoot",
        "TEMP=$labRoot",
        "TMP=$labRoot",
        "WINDIR=$env:SystemRoot"
    ) | Sort-Object
    $appEnvironmentPtr = [Runtime.InteropServices.Marshal]::StringToHGlobalUni(($appEnvironment -join "`0") + "`0`0")
    Write-Host 'APP_ENVIRONMENT=explicit-minimal-profile-independent'
    $appCommand = [System.Text.StringBuilder]::new("`"$dotnetExe`" `"$outputDll`"")
    if (-not [MicNative]::CreateProcessWithLogonW($testUser, '.', $testPassword,
        1, $dotnetExe, $appCommand, 0x400, $appEnvironmentPtr,
        (Join-Path $env:SystemRoot 'System32'), [ref]$startup, [ref]$appProc)) {
        throw "Standard-account forged app launch failed: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
    }
    $actorWait = [MicNative]::WaitForSingleObject($roslynActorProc.hProcess, 30000)
    $actorText = [System.IO.File]::ReadAllText($actorResult)
    $forgedMarkerExists = Test-Path $markerPath
    $forgedMarkerText = if ($forgedMarkerExists) { [System.IO.File]::ReadAllText($markerPath) } else { '<absent>' }
    Write-Host "FORGED_AUTH actor-wait=$actorWait marker=$forgedMarkerExists text=$forgedMarkerText"
    Write-Host "ROSLYN_LOW_LOG_BEGIN`n$actorText`nROSLYN_LOW_LOG_END"
    [void][MicNative]::TerminateProcess($appProc.hProcess, 0)
    [void][MicNative]::WaitForSingleObject($appProc.hProcess, 5000)
    if ($appProc.hThread -ne [IntPtr]::Zero) { [void][MicNative]::CloseHandle($appProc.hThread); $appProc.hThread = [IntPtr]::Zero }
    if ($appProc.hProcess -ne [IntPtr]::Zero) { [void][MicNative]::CloseHandle($appProc.hProcess); $appProc.hProcess = [IntPtr]::Zero }
    if ($forgedMarkerExists) { [System.IO.File]::Delete($markerPath) }
    if ($roslynActorProc.hThread -ne [IntPtr]::Zero) { [void][MicNative]::CloseHandle($roslynActorProc.hThread) }
    if ($roslynActorProc.hProcess -ne [IntPtr]::Zero) { [void][MicNative]::CloseHandle($roslynActorProc.hProcess) }
    $validExit = Invoke-MediumBuild 'valid' '-v:diag'
    $validExists = Test-Path $outputDll
    $validHash = if ($validExists) { (Get-FileHash $outputDll -Algorithm SHA256).Hash } else { '<absent>' }
    Write-Host "VALID_RESULT exit=$validExit dll=$validExists hash=$validHash"
    $validCommand = [System.Text.StringBuilder]::new("`"$dotnetExe`" `"$outputDll`"")
    if (-not [MicNative]::CreateProcessWithLogonW($testUser, '.', $testPassword,
        1, $dotnetExe, $validCommand, 0x400, $appEnvironmentPtr,
        (Join-Path $env:SystemRoot 'System32'), [ref]$startup, [ref]$validAppProc)) {
        throw "Standard-account secured app launch failed: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
    }
    $client = [System.Net.Http.HttpClient]::new()
    $client.Timeout = [TimeSpan]::FromSeconds(2)
    $validReady = $false
    for ($attempt = 0; $attempt -lt 150; $attempt++) {
        try {
            $health = $client.GetAsync("$baseUrl/health").GetAwaiter().GetResult()
            if ([int]$health.StatusCode -eq 200) { $validReady = $true; break }
        } catch { }
        Start-Sleep -Milliseconds 100
    }
    if (-not $validReady) { throw 'Secured app did not become healthy' }
    $anonymous = $client.PostAsync("$baseUrl/admin", [System.Net.Http.StringContent]::new('')).GetAwaiter().GetResult()
    $anonStatus = [int]$anonymous.StatusCode
    $markerAfterAnon = Test-Path $markerPath
    $ownerRequest = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::Post, "$baseUrl/admin")
    [void]$ownerRequest.Headers.TryAddWithoutValidation('X-Lab-Admin', 'owner')
    $ownerResponse = $client.SendAsync($ownerRequest).GetAwaiter().GetResult()
    $ownerStatus = [int]$ownerResponse.StatusCode
    $markerAfterOwner = Test-Path $markerPath
    Write-Host "VALID_AUTH anonymous=$anonStatus marker-after-anonymous=$markerAfterAnon owner=$ownerStatus marker-after-owner=$markerAfterOwner"
    $client.Dispose()
    [void][MicNative]::TerminateProcess($validAppProc.hProcess, 0)
    [void][MicNative]::WaitForSingleObject($validAppProc.hProcess, 5000)
    if ($validAppProc.hThread -ne [IntPtr]::Zero) { [void][MicNative]::CloseHandle($validAppProc.hThread); $validAppProc.hThread = [IntPtr]::Zero }
    if ($validAppProc.hProcess -ne [IntPtr]::Zero) { [void][MicNative]::CloseHandle($validAppProc.hProcess); $validAppProc.hProcess = [IntPtr]::Zero }
    if ($prevalidExit -ne 0 -or $prevalidHash -eq $oldHash -or $forgedExit -ne 0 -or -not $forgedExists -or $forgedHash -eq $oldHash -or $markerBeforeLaunch -or $actorWait -ne 0 -or -not $actorText.Contains('LOW_SELF_DOWNGRADE=VERIFIED') -or -not $actorText.Contains('LOW_SOURCE_WRITE=DENIED') -or -not $actorText.Contains('LOW_PROJECT_WRITE=DENIED') -or -not $actorText.Contains('LOW_MARKER_WRITE=DENIED') -or -not $actorText.Contains('TARGET=True') -or -not $actorText.Contains('SENT_MALFORMED_LENGTH') -or -not $actorText.Contains('LOW_ANON_ADMIN_STATUS=401') -or $forgedMarkerExists -or $validExit -ne 0 -or -not $validExists -or $validHash -eq $oldHash -or $anonStatus -ne 401 -or $markerAfterAnon -or $ownerStatus -ne 200 -or -not $markerAfterOwner) {
        throw 'Released Roslyn Windows authorization malformed-response control did not pass'
    }
} finally {
    if ($appEnvironmentPtr -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::FreeHGlobal($appEnvironmentPtr) }
    if ($appProc.hProcess -ne [IntPtr]::Zero) { [void][MicNative]::TerminateProcess($appProc.hProcess, 0); [void][MicNative]::CloseHandle($appProc.hProcess) }
    if ($appProc.hThread -ne [IntPtr]::Zero) { [void][MicNative]::CloseHandle($appProc.hThread) }
    if ($validAppProc.hProcess -ne [IntPtr]::Zero) { [void][MicNative]::TerminateProcess($validAppProc.hProcess, 0); [void][MicNative]::CloseHandle($validAppProc.hProcess) }
    if ($validAppProc.hThread -ne [IntPtr]::Zero) { [void][MicNative]::CloseHandle($validAppProc.hThread) }
    if ($mediumClientProc.hThread -ne [IntPtr]::Zero) { [void][MicNative]::CloseHandle($mediumClientProc.hThread) }
    if ($mediumClientProc.hProcess -ne [IntPtr]::Zero) { [void][MicNative]::CloseHandle($mediumClientProc.hProcess) }
    if ($lowProc.hThread -ne [IntPtr]::Zero) { [void][MicNative]::CloseHandle($lowProc.hThread) }
    if ($lowProc.hProcess -ne [IntPtr]::Zero) { [void][MicNative]::CloseHandle($lowProc.hProcess) }
    if ($lowCmdProc.hThread -ne [IntPtr]::Zero) { [void][MicNative]::CloseHandle($lowCmdProc.hThread) }
    if ($lowCmdProc.hProcess -ne [IntPtr]::Zero) { [void][MicNative]::CloseHandle($lowCmdProc.hProcess) }
    if ($pipeProc.hThread -ne [IntPtr]::Zero) { [void][MicNative]::CloseHandle($pipeProc.hThread) }
    if ($pipeProc.hProcess -ne [IntPtr]::Zero) { [void][MicNative]::CloseHandle($pipeProc.hProcess) }
    if ($proc.hThread -ne [IntPtr]::Zero) { [void][MicNative]::CloseHandle($proc.hThread) }
    if ($proc.hProcess -ne [IntPtr]::Zero) { [void][MicNative]::CloseHandle($proc.hProcess) }
    if ($sid -ne [IntPtr]::Zero) { [void][MicNative]::LocalFree($sid) }
    if ($adminSid -ne [IntPtr]::Zero) { [void][MicNative]::LocalFree($adminSid) }
    if ($disabledSids -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::FreeHGlobal($disabledSids) }
    if ($groupsBuffer -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::FreeHGlobal($groupsBuffer) }
    if ($ilBuffer -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::FreeHGlobal($ilBuffer) }
    if ($labelBuffer -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::FreeHGlobal($labelBuffer) }
    if ($lowSid -ne [IntPtr]::Zero) { [void][MicNative]::LocalFree($lowSid) }
    if ($lowLabelBuffer -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::FreeHGlobal($lowLabelBuffer) }
    if ($low -ne [IntPtr]::Zero) { [void][MicNative]::CloseHandle($low) }
    if ($standardLow -ne [IntPtr]::Zero) { [void][MicNative]::CloseHandle($standardLow) }
    if ($standardToken -ne [IntPtr]::Zero) { [void][MicNative]::CloseHandle($standardToken) }
    if ($medium -ne [IntPtr]::Zero) { [void][MicNative]::CloseHandle($medium) }
    if ($token -ne [IntPtr]::Zero) { [void][MicNative]::CloseHandle($token) }
}
