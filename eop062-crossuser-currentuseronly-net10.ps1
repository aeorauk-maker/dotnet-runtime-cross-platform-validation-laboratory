$ErrorActionPreference = 'Stop'
$dotnet = (Get-Command dotnet).Source
$labRoot = Join-Path $env:PUBLIC ('Documents\eop062-owner-' + [guid]::NewGuid().ToString('N'))
[void](New-Item -ItemType Directory -Path $labRoot -Force)
$project = Join-Path $labRoot 'PipeOwnerProbe.csproj'
$source = Join-Path $labRoot 'Program.cs'
$userA = 'eop062a' + [guid]::NewGuid().ToString('N').Substring(0,8)
$userB = 'eop062b' + [guid]::NewGuid().ToString('N').Substring(0,8)
$passwordA = 'Aa1!' + [guid]::NewGuid().ToString('N').Substring(0,8)
$passwordB = 'Aa1!' + [guid]::NewGuid().ToString('N').Substring(0,8)
$accountA = "$env:COMPUTERNAME\$userA"
$accountB = "$env:COMPUTERNAME\$userB"
$createdA = $false
$createdB = $false

Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Text;
public static class OwnerProbeNative {
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
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern uint WaitForSingleObject(IntPtr handle, uint timeout);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool GetExitCodeProcess(IntPtr handle, out uint exitCode);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool TerminateProcess(IntPtr handle, uint exitCode);
    [DllImport("kernel32.dll")]
    public static extern bool CloseHandle(IntPtr handle);
}
'@

$program = @'
using System;
using System.IO;
using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;

static void Record(string path, string line) => File.AppendAllText(path, line + Environment.NewLine);
if (args.Length != 4) throw new Exception("Usage: mode pipe result option");
string mode = args[0], name = args[1], result = args[2], option = args[3];
using var identity = WindowsIdentity.GetCurrent();
Record(result, $"IDENTITY USER={identity.User?.Value} OWNER={identity.Owner?.Value}");
if (mode == "server")
{
    var security = new PipeSecurity();
    security.SetOwner(identity.Owner!);
    security.AddAccessRule(new PipeAccessRule(
        new SecurityIdentifier(WellKnownSidType.WorldSid, null),
        PipeAccessRights.FullControl, AccessControlType.Allow));
    using var server = NamedPipeServerStreamAcl.Create(name, PipeDirection.InOut, 1,
        PipeTransmissionMode.Byte, PipeOptions.None, 0, 0, security);
    Record(result, "SERVER_READY DACL=EVERYONE_FULL OWNER=SERVER_ACCOUNT");
    server.WaitForConnection();
    Record(result, "SERVER_ACCEPTED");
    int value = server.ReadByte();
    Record(result, $"SERVER_BYTE={value}");
}
else if (mode == "client")
{
    PipeOptions options = option == "current" ? PipeOptions.CurrentUserOnly : PipeOptions.None;
    try
    {
        using var client = new NamedPipeClientStream(".", name, PipeDirection.InOut, options);
        client.Connect(5000);
        client.WriteByte(7);
        client.Flush();
        Record(result, $"CONNECT=ALLOWED OPTION={option}");
    }
    catch (Exception ex)
    {
        Record(result, $"CONNECT=DENIED OPTION={option} TYPE={ex.GetType().Name} MESSAGE={ex.Message}");
    }
}
else throw new Exception("Bad mode");
'@

function Start-AccountProcess([string]$user, [string]$password, [string]$commandLine) {
    $startup = [OwnerProbeNative+StartupInfo]::new()
    $startup.cb = [Runtime.InteropServices.Marshal]::SizeOf([type][OwnerProbeNative+StartupInfo])
    $process = [OwnerProbeNative+ProcessInfo]::new()
    $line = [System.Text.StringBuilder]::new($commandLine)
    $exe = Join-Path $labRoot 'bin\Release\net10.0\PipeOwnerProbe.exe'
    if (-not [OwnerProbeNative]::CreateProcessWithLogonW($user, '.', $password, 1,
        $exe, $line, 0, [IntPtr]::Zero, $labRoot, [ref]$startup, [ref]$process)) {
        throw "CreateProcessWithLogonW failed: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
    }
    if ($process.hThread -ne [IntPtr]::Zero) { [void][OwnerProbeNative]::CloseHandle($process.hThread) }
    return $process
}

function Await-AccountProcess($process, [uint32]$timeout) {
    $wait = [OwnerProbeNative]::WaitForSingleObject($process.hProcess, $timeout)
    $code = [uint32]0
    [void][OwnerProbeNative]::GetExitCodeProcess($process.hProcess, [ref]$code)
    if ($wait -ne 0 -or $code -ne 0) { throw "Child wait=$wait exit=$code" }
}

function Run-Case([string]$label, [string]$clientUser, [string]$clientPassword, [string]$clientOption, [bool]$expectAllowed) {
    $name = 'eop062-owner-' + [guid]::NewGuid().ToString('N')
    $serverResult = Join-Path $labRoot "$label-server.txt"
    $clientResult = Join-Path $labRoot "$label-client.txt"
    [System.IO.File]::WriteAllText($serverResult, '')
    [System.IO.File]::WriteAllText($clientResult, '')
    & icacls.exe $serverResult /grant:r "${accountB}:(M)" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Server result ACL failed' }
    & icacls.exe $clientResult /grant:r "${accountA}:(M)" "${accountB}:(M)" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Client result ACL failed' }
    $exe = Join-Path $labRoot 'bin\Release\net10.0\PipeOwnerProbe.exe'
    $serverLine = "`"$exe`" server $name `"$serverResult`" none"
    $serverProc = Start-AccountProcess $userB $passwordB $serverLine
    try {
        $ready = $false
        for ($i = 0; $i -lt 120; $i++) {
            if (([System.IO.File]::ReadAllText($serverResult)).Contains('SERVER_READY')) { $ready = $true; break }
            Start-Sleep -Milliseconds 100
        }
        if (-not $ready) { throw "Server readiness failed: $([System.IO.File]::ReadAllText($serverResult))" }
        $clientLine = "`"$exe`" client $name `"$clientResult`" $clientOption"
        $clientProc = Start-AccountProcess $clientUser $clientPassword $clientLine
        try { Await-AccountProcess $clientProc 15000 }
        finally { [void][OwnerProbeNative]::CloseHandle($clientProc.hProcess) }
        if ($expectAllowed) { Await-AccountProcess $serverProc 5000 }
        $serverText = [System.IO.File]::ReadAllText($serverResult)
        $clientText = [System.IO.File]::ReadAllText($clientResult)
        Write-Host "CASE=$label SERVER=$($serverText -replace "`r?`n", ';') CLIENT=$($clientText -replace "`r?`n", ';')"
        $serverUserSid = [regex]::Match($serverText, 'USER=(S-[0-9-]+)').Groups[1].Value
        $serverOwnerSid = [regex]::Match($serverText, 'OWNER=(S-[0-9-]+)').Groups[1].Value
        $clientUserSid = [regex]::Match($clientText, 'USER=(S-[0-9-]+)').Groups[1].Value
        $clientOwnerSid = [regex]::Match($clientText, 'OWNER=(S-[0-9-]+)').Groups[1].Value
        if (-not $serverUserSid -or -not $clientUserSid -or $serverOwnerSid -ne $serverUserSid -or $clientOwnerSid -ne $clientUserSid) {
            throw "Owner/User SID identity control failed: $label"
        }
        if ($label.StartsWith('cross-user') -and $serverUserSid -eq $clientUserSid) { throw 'Cross-user case used the same account' }
        if ($label.StartsWith('same-user') -and $serverUserSid -ne $clientUserSid) { throw 'Same-user case used different accounts' }
        if ($expectAllowed -and (-not $clientText.Contains('CONNECT=ALLOWED') -or -not $serverText.Contains('SERVER_ACCEPTED'))) {
            throw "Expected allowed client did not connect: $label"
        }
        if (-not $expectAllowed -and -not $clientText.Contains('CONNECT=DENIED')) {
            throw "Different-owner CurrentUserOnly client unexpectedly connected: $label"
        }
        if (-not $expectAllowed -and $serverText.Contains('SERVER_ACCEPTED')) {
            Write-Host 'OWNER_CHECK_DENIED_AFTER_SERVER_ACCEPT=True'
        }
    } finally {
        if ($serverProc.hProcess -ne [IntPtr]::Zero) {
            [void][OwnerProbeNative]::TerminateProcess($serverProc.hProcess, 0)
            [void][OwnerProbeNative]::WaitForSingleObject($serverProc.hProcess, 3000)
            [void][OwnerProbeNative]::CloseHandle($serverProc.hProcess)
        }
    }
}

try {
    [System.IO.File]::WriteAllText($project, '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><OutputType>Exe</OutputType><TargetFramework>net10.0</TargetFramework><ImplicitUsings>disable</ImplicitUsings></PropertyGroup></Project>')
    [System.IO.File]::WriteAllText($source, $program)
    & $dotnet build $project -c Release -v:minimal '-p:UseSharedCompilation=false' | Out-Host
    if ($LASTEXITCODE -ne 0) { throw 'Probe app build failed' }
    & net.exe user $userA $passwordA /add /expires:never /passwordchg:no | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Account A creation failed' }
    $createdA = $true
    & net.exe user $userB $passwordB /add /expires:never /passwordchg:no | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Account B creation failed' }
    $createdB = $true
    & icacls.exe $labRoot /grant:r "${accountA}:(OI)(CI)(RX)" "${accountB}:(OI)(CI)(RX)" /T | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Probe tree read ACL failed' }
    Write-Host "SDK_VERSION=$(& $dotnet --version)"
    Run-Case 'cross-user-no-owner-option' $userA $passwordA 'none' $true
    Run-Case 'same-user-current-owner' $userB $passwordB 'current' $true
    Run-Case 'cross-user-current-owner' $userA $passwordA 'current' $false
    Write-Host 'EOP062_CROSSUSER_CURRENTUSERONLY_PASS'
} finally {
    if ($createdA) { & net.exe user $userA /delete | Out-Null }
    if ($createdB) { & net.exe user $userB /delete | Out-Null }
}
