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
$proc = [MicNative+ProcessInfo]::new()
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
} finally {
    if ($proc.hThread -ne [IntPtr]::Zero) { [void][MicNative]::CloseHandle($proc.hThread) }
    if ($proc.hProcess -ne [IntPtr]::Zero) { [void][MicNative]::CloseHandle($proc.hProcess) }
    if ($sid -ne [IntPtr]::Zero) { [void][MicNative]::LocalFree($sid) }
    if ($adminSid -ne [IntPtr]::Zero) { [void][MicNative]::LocalFree($adminSid) }
    if ($disabledSids -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::FreeHGlobal($disabledSids) }
    if ($groupsBuffer -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::FreeHGlobal($groupsBuffer) }
    if ($ilBuffer -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::FreeHGlobal($ilBuffer) }
    if ($labelBuffer -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::FreeHGlobal($labelBuffer) }
    if ($medium -ne [IntPtr]::Zero) { [void][MicNative]::CloseHandle($medium) }
    if ($token -ne [IntPtr]::Zero) { [void][MicNative]::CloseHandle($token) }
}
