param(
    [ValidateSet('main', 'probe')][string]$Mode = 'main',
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
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool WaitNamedPipeW(string name, uint timeout);
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

if ($Mode -eq 'probe') {
    try {
        $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $il = Get-IntegritySid
        [System.IO.File]::AppendAllText($ResultPath, "IL=$il OWNER=$($identity.Owner.Value) USER=$($identity.User.Value)`n")
        if ($identity.Owner.Value -ne $identity.User.Value) { throw 'Owner and user SID differ' }
        if ($il -eq 'S-1-16-8192') {
            $fullName = "\\.\pipe\$PipeName"
            $present = [Eop062InstanceNative]::WaitNamedPipeW($fullName, 3000)
            [System.IO.File]::AppendAllText($ResultPath, "FIRST_SERVER_READY=$present`n")
        }
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
    } catch {
        [System.IO.File]::AppendAllText($ResultPath, "FATAL=$($_.Exception.GetType().Name):$($_.Exception.Message)`n")
        exit 3
    }
    exit 0
}

$testUser = 'eop062r' + [guid]::NewGuid().ToString('N').Substring(0,8)
$testPassword = 'Aa1!' + [guid]::NewGuid().ToString('N').Substring(0,8)
$testAccount = "$env:COMPUTERNAME\$testUser"
$pwshExe = (Get-Command pwsh).Source
$dotnetExe = (Get-Command dotnet).Source
$cmdExe = Join-Path $env:SystemRoot 'System32\cmd.exe'
$sdkVersion = (& $dotnetExe --version).Trim()
if ($sdkVersion -ne '10.0.404') { throw "Unexpected SDK $sdkVersion" }
$compilerDir = Join-Path (Split-Path -Parent $dotnetExe) "sdk\$sdkVersion\Roslyn\bincore"
$pipeInput = '{0}.False.{1}' -f $testUser, $compilerDir.TrimEnd('\').ToLowerInvariant()
$pipeHash = [Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($pipeInput))
$pipeName = [Convert]::ToBase64String($pipeHash).Replace('/', '_').Replace('=', '')
$labRoot = Join-Path $env:PUBLIC ('Documents\eop062-live-roslyn-' + [guid]::NewGuid().ToString('N'))
[void](New-Item -ItemType Directory -Path $labRoot -Force)
$sharedScript = Join-Path $labRoot 'live-roslyn.ps1'
$lowCmdExe = Join-Path $labRoot 'low-cmd.exe'
$lowLauncher = Join-Path $labRoot 'low-launcher.cmd'
$mediumResult = Join-Path $labRoot 'medium.txt'
$lowResult = Join-Path $labRoot 'low.txt'
$lowAfterIdleResult = Join-Path $labRoot 'low-after-idle.txt'
$project = Join-Path $labRoot 'Probe.csproj'
$sourcePath = Join-Path $labRoot 'Program.cs'
$buildLauncher = Join-Path $labRoot 'build.cmd'
$buildLog = Join-Path $labRoot 'build.log'
$startup = [Eop062InstanceNative+StartupInfo]::new()
$startup.cb = [Runtime.InteropServices.Marshal]::SizeOf([type][Eop062InstanceNative+StartupInfo])
function Start-Standard([string]$application, [string]$commandLine) {
    $process = [Eop062InstanceNative+ProcessInfo]::new()
    $line = [System.Text.StringBuilder]::new($commandLine)
    if (-not [Eop062InstanceNative]::CreateProcessWithLogonW($testUser, '.', $testPassword,
        1, $application, $line, 0, [IntPtr]::Zero,
        $labRoot, [ref]$startup, [ref]$process)) {
        throw "CreateProcessWithLogonW: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
    }
    if ($process.hThread -ne [IntPtr]::Zero) { [void][Eop062InstanceNative]::CloseHandle($process.hThread) }
    return $process
}
function Wait-Standard($process) {
    try {
        $wait = [Eop062InstanceNative]::WaitForSingleObject($process.hProcess, 30000)
        $code = [uint32]0
        [void][Eop062InstanceNative]::GetExitCodeProcess($process.hProcess, [ref]$code)
        if ($wait -ne 0 -or $code -ne 0) { throw "Child wait=$wait exit=$code" }
    } finally { if ($process.hProcess -ne [IntPtr]::Zero) { [void][Eop062InstanceNative]::CloseHandle($process.hProcess) } }
}
try {
    & net.exe user $testUser $testPassword /add /expires:never /passwordchg:no | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not create isolated standard account' }
    [System.IO.File]::Copy($PSCommandPath, $sharedScript)
    [System.IO.File]::Copy($cmdExe, $lowCmdExe)
    [System.IO.File]::WriteAllText((Join-Path $labRoot 'global.json'), '{"sdk":{"version":"10.0.404","rollForward":"disable"}}')
    [System.IO.File]::WriteAllText($project, '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net10.0</TargetFramework><OutputType>Exe</OutputType><UseAppHost>false</UseAppHost></PropertyGroup></Project>')
    [System.IO.File]::WriteAllText($sourcePath, 'System.Console.WriteLine("EOP062_INERT");')
    & $dotnetExe restore $project --ignore-failed-sources | Out-Host
    if ($LASTEXITCODE -ne 0) { throw 'Owned project restore failed' }
    & icacls.exe $labRoot /grant:r "${testAccount}:(OI)(CI)(M)" /T | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Cannot grant standard account lab access' }
    & icacls.exe $labRoot /setintegritylevel M /T | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Cannot label lab Medium' }
    & icacls.exe $lowCmdExe /setintegritylevel L | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Cannot label actor executable Low' }
    foreach ($result in @($mediumResult, $lowResult, $lowAfterIdleResult)) {
        [System.IO.File]::WriteAllText($result, '')
        & icacls.exe $result /grant:r "${testAccount}:(M)" | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "Cannot grant result write: $result" }
        & icacls.exe $result /setintegritylevel L | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "Cannot label result Low: $result" }
    }
    [System.IO.File]::WriteAllText($buildLauncher,
        "@echo off`r`nset `"DOTNET_CLI_HOME=$labRoot`"`r`n`"$dotnetExe`" build `"$project`" --no-restore -v:minimal > `"$buildLog`" 2>&1`r`nexit /b %ERRORLEVEL%`r`n")
    $build = Start-Standard $cmdExe "`"$cmdExe`" /D /C `"$buildLauncher`""
    $buildWaitError = $null
    try { Wait-Standard $build } catch { $buildWaitError = $_ }
    $buildText = [System.IO.File]::ReadAllText($buildLog)
    Write-Host "BUILD_LOG_BEGIN`n$buildText`nBUILD_LOG_END"
    if ($buildWaitError) { throw $buildWaitError }
    if (-not $buildText.Contains('Build succeeded.')) { throw 'Product build did not succeed' }
    $medium = Start-Standard $pwshExe "`"$pwshExe`" -NoProfile -NonInteractive -File `"$sharedScript`" -Mode probe -PipeName $pipeName -ResultPath `"$mediumResult`""
    Wait-Standard $medium
    [System.IO.File]::WriteAllText($lowLauncher,
        "@echo off`r`n`"$pwshExe`" -NoProfile -NonInteractive -File `"$sharedScript`" -Mode probe -PipeName $pipeName -ResultPath `"$lowResult`"`r`nexit /b %ERRORLEVEL%`r`n")
    $low = Start-Standard $lowCmdExe "`"$lowCmdExe`" /D /C `"$lowLauncher`""
    Wait-Standard $low
    $mediumText = [System.IO.File]::ReadAllText($mediumResult)
    $lowText = [System.IO.File]::ReadAllText($lowResult)
    Write-Host "SDK=$sdkVersion PIPE=$pipeName"
    Write-Host "MEDIUM_SAME_OWNER_INSTANCE=$mediumText"
    Write-Host "LOW_LIVE_ROSLYN_INSTANCE=$lowText"
    if (-not $mediumText.Contains('IL=S-1-16-8192') -or -not $mediumText.Contains('FIRST_SERVER_READY=True') -or -not $mediumText.Contains('CREATE=ALLOWED')) {
        throw 'Released Roslyn Medium first server was not confirmed live with same-owner Medium second instance'
    }
    if (-not $lowText.Contains('IL=S-1-16-4096') -or -not $lowText.Contains('CREATE=DENIED')) {
        throw 'Low actor was not denied a second instance with released Roslyn server live'
    }
    Write-Host 'EOP062_LIVE_ROSLYN_INSTANCE_PASS'
    Write-Host 'NATURAL_IDLE_WAIT_START seconds=675 no-shutdown-command=True'
    Start-Sleep -Seconds 675
    [System.IO.File]::WriteAllText($lowLauncher,
        "@echo off`r`n`"$pwshExe`" -NoProfile -NonInteractive -File `"$sharedScript`" -Mode probe -PipeName $pipeName -ResultPath `"$lowAfterIdleResult`"`r`nexit /b %ERRORLEVEL%`r`n")
    $lowAfterIdle = Start-Standard $lowCmdExe "`"$lowCmdExe`" /D /C `"$lowLauncher`""
    Wait-Standard $lowAfterIdle
    $afterText = [System.IO.File]::ReadAllText($lowAfterIdleResult)
    Write-Host "LOW_AFTER_NATURAL_IDLE=$afterText"
    if (-not $afterText.Contains('IL=S-1-16-4096') -or -not $afterText.Contains('CREATE=ALLOWED')) {
        throw 'Low actor could not create the default pipe after natural Roslyn idle interval'
    }
    Write-Host 'EOP062_NATURAL_IDLE_PRECLAIM_PASS'
} finally {
    & net.exe user $testUser /delete | Out-Null
}
