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
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool ConvertSidToStringSid(IntPtr sid, out IntPtr text);
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
$pipeProc = [MicNative+ProcessInfo]::new()
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
    $highIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    Write-Host "high-token-user=$($highIdentity.User.Value) high-token-owner=$($highIdentity.Owner.Value)"
    foreach ($tokenLabel in @(@('medium-user', 1), @('medium-owner', 4))) {
        $infoSize = 0
        [void][MicNative]::GetTokenInformation($medium, $tokenLabel[1], [IntPtr]::Zero, 0, [ref]$infoSize)
        if ($infoSize -le 0) { throw "Token $($tokenLabel[0]) sizing failed" }
        $info = [Runtime.InteropServices.Marshal]::AllocHGlobal($infoSize)
        try {
            if (-not [MicNative]::GetTokenInformation($medium, $tokenLabel[1], $info, $infoSize, [ref]$infoSize)) {
                throw "Token $($tokenLabel[0]) read failed: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
            }
            $sidPtr = [Runtime.InteropServices.Marshal]::ReadIntPtr($info)
            $textPtr = [IntPtr]::Zero
            if (-not [MicNative]::ConvertSidToStringSid($sidPtr, [ref]$textPtr)) {
                throw "Token $($tokenLabel[0]) SID text failed"
            }
            try { Write-Host "$($tokenLabel[0])=$([Runtime.InteropServices.Marshal]::PtrToStringUni($textPtr))" }
            finally { [void][MicNative]::LocalFree($textPtr) }
        } finally { [Runtime.InteropServices.Marshal]::FreeHGlobal($info) }
    }
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
    # Benign product handshake: an unmodified medium MSBuild worker and an unmodified high build manager.
    $sdkDll = Join-Path $env:ProgramFiles 'dotnet\sdk\11.0.100\MSBuild.dll'
    $dotnetExe = Join-Path $env:ProgramFiles 'dotnet\dotnet.exe'
    if (-not (Test-Path -LiteralPath $sdkDll)) { throw "Missing SDK 11 MSBuild: $sdkDll" }
    $labDir = Join-Path $env:RUNNER_TEMP 'benign-msbuild-reuse'
    [System.IO.Directory]::CreateDirectory($labDir) | Out-Null
    $parentProject = Join-Path $labDir 'Parent.proj'
    $childA = Join-Path $labDir 'ChildA.proj'
    $childB = Join-Path $labDir 'ChildB.proj'
    [System.IO.File]::WriteAllText($parentProject, '<Project><Target Name="Build"><MSBuild Projects="ChildA.proj;ChildB.proj" BuildInParallel="true" /></Target></Project>')
    [System.IO.File]::WriteAllText($childA, '<Project><Target Name="Build"><Message Importance="High" Text="BENIGN_CHILD_A" /></Target></Project>')
    [System.IO.File]::WriteAllText($childB, '<Project><Target Name="Build"><Message Importance="High" Text="BENIGN_CHILD_B" /></Target></Project>')
    $workerLog = Join-Path $env:PUBLIC 'Documents\benign-msbuild-worker.log'
    [System.IO.File]::WriteAllText($workerLog, '')
    & icacls.exe $workerLog /setintegritylevel M | Out-Host
    if ($LASTEXITCODE -ne 0) { throw 'Could not label worker log medium' }
    & icacls.exe $workerLog /grant:r "${runnerUser}:(M)" | Out-Host
    if ($LASTEXITCODE -ne 0) { throw 'Could not grant worker log write' }
    $workerCmd = [System.Text.StringBuilder]::new("`"$cmdExe`" /D /C `"`"$dotnetExe`" exec `"$sdkDll`" /nodemode:1 > `"$workerLog`" 2>&1`"")
    if (-not [MicNative]::CreateProcessAsUserW($medium, $cmdExe, $workerCmd,
        [IntPtr]::Zero, [IntPtr]::Zero, $false, 0, [IntPtr]::Zero,
        (Join-Path $env:SystemRoot 'System32'), [ref]$startup, [ref]$pipeProc)) {
        throw "Worker CreateProcessAsUserW failed: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
    }
    Write-Host "medium-worker-wrapper-pid=$($pipeProc.dwProcessId)"
    $workerPid = $null
    for ($attempt = 0; $attempt -lt 80; $attempt++) {
        $children = @(Get-CimInstance Win32_Process -Filter "ParentProcessId=$($pipeProc.dwProcessId)")
        $worker = $children | Where-Object { $_.Name -eq 'dotnet.exe' } | Select-Object -First 1
        if ($worker) { $workerPid = [int]$worker.ProcessId; break }
        Start-Sleep -Milliseconds 100
    }
    if (-not $workerPid) {
        throw "Medium worker did not launch; log=$([System.IO.File]::ReadAllText($workerLog))"
    }
    Write-Host "medium-worker-pid=$workerPid"
    Start-Sleep -Seconds 2
    $buildLog = Join-Path $env:RUNNER_TEMP 'benign-msbuild-build.log'
    $env:MSBUILDDEBUGCOMM = '1'
    $env:MSBUILDDEBUGPATH = $labDir
    try {
        & $dotnetExe exec $sdkDll $parentProject '/m:2' '/nr:true' '/v:diag' *> $buildLog
        $buildExit = $LASTEXITCODE
    } finally { Remove-Item Env:MSBUILDDEBUGCOMM -ErrorAction SilentlyContinue; Remove-Item Env:MSBUILDDEBUGPATH -ErrorAction SilentlyContinue }
    Write-Host "benign-build-exit=$buildExit"
    $buildText = [System.IO.File]::ReadAllText($buildLog)
    Write-Host "benign-child-a=$($buildText.Contains('BENIGN_CHILD_A')) benign-child-b=$($buildText.Contains('BENIGN_CHILD_B'))"
    $workerState = Get-CimInstance Win32_Process -Filter "ProcessId=$workerPid"
    Write-Host "worker-alive-after-build=$([bool]$workerState)"
    $traceFiles = @(Get-ChildItem -LiteralPath $labDir -Filter 'MSBuild_CommTrace_PID_*.txt' -File -ErrorAction SilentlyContinue)
    Write-Host "comm-trace-file-count=$($traceFiles.Count)"
    foreach ($trace in $traceFiles) {
        $interesting = @(Get-Content -LiteralPath $trace.FullName | Where-Object { $_ -match $workerPid -or $_ -match 'candidate processes|Filtered to|existing processes|existing node' } | Select-Object -First 24)
        Write-Host "comm-trace-name=$($trace.Name) interesting-count=$($interesting.Count)"
        foreach ($line in $interesting) { Write-Host "COMM:$line" }
    }
    $nodeLines = @($buildText -split "`n" | Where-Object { $_ -match 'on node [0-9]|NodeReused|BENIGN_CHILD' } | Select-Object -First 15)
    foreach ($line in $nodeLines) { Write-Host "BUILD:$line" }
    $reused = $buildText -match "Successfully connected to existing node [0-9]+ which is PID $workerPid"
    Write-Host "medium-worker-reused=$reused"
    if (-not $reused) {
        $selected = $buildText -split "`n" | Where-Object { $_ -match 'existing node|existing process|FAILED TO CONNECT|Failed to connect' } | Select-Object -First 20
        $selected | Out-Host
        throw 'High manager did not reuse the medium worker in this run'
    }
    if ($buildExit -ne 0 -or -not $buildText.Contains('BENIGN_CHILD_A') -or -not $buildText.Contains('BENIGN_CHILD_B')) {
        throw 'Benign multi-project build did not complete'
    }
    $highResult = [System.IO.File]::ReadAllText($highPath)
    Write-Host "high-sentinel-preserved=$($highResult -eq 'HIGH_ONLY')"
    if ($highResult -ne 'HIGH_ONLY') { throw 'High sentinel changed unexpectedly' }
    Stop-Process -Id $workerPid -Force -ErrorAction SilentlyContinue
} finally {
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
    if ($medium -ne [IntPtr]::Zero) { [void][MicNative]::CloseHandle($medium) }
    if ($token -ne [IntPtr]::Zero) { [void][MicNative]::CloseHandle($token) }
}
