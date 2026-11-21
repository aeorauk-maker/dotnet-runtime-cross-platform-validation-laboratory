# Diagnostic collector for a researcher-owned Windows Insider Canary VM.
# Run elevated on a disposable clone. This does not configure a proxy or trigger NCSI.
param(
    [Parameter(Mandatory=$true)][string]$OutputDirectory,
    [ValidateRange(10,600)][int]$Seconds = 120
)

$ErrorActionPreference = 'Continue'
New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
$OutputDirectory = (Resolve-Path $OutputDirectory).Path
$runStart = (Get-Date).ToUniversalTime().ToString('o')
$prefix = Join-Path $OutputDirectory 'internetclient'
$processLog = Join-Path $OutputDirectory 'processes.jsonl'
$errors = Join-Path $OutputDirectory 'collector-errors.txt'

$tokenTypeSource = @'
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;

public static class LabTokenReader {
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern IntPtr OpenProcess(uint access, bool inherit, uint pid);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool CloseHandle(IntPtr handle);
    [DllImport("advapi32.dll", SetLastError=true)]
    static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);
    [DllImport("advapi32.dll", SetLastError=true)]
    static extern bool GetTokenInformation(IntPtr token, int tokenClass, IntPtr buffer,
        int bufferLength, out int returnLength);

    static IntPtr ReadClass(IntPtr token, int tokenClass, out int error) {
        int size;
        GetTokenInformation(token, tokenClass, IntPtr.Zero, 0, out size);
        if (size <= 0) { error = Marshal.GetLastWin32Error(); return IntPtr.Zero; }
        IntPtr buffer = Marshal.AllocHGlobal(size);
        if (!GetTokenInformation(token, tokenClass, buffer, size, out size)) {
            error = Marshal.GetLastWin32Error(); Marshal.FreeHGlobal(buffer); return IntPtr.Zero;
        }
        error = 0;
        return buffer;
    }

    static string SidClass(IntPtr token, int tokenClass) {
        int error;
        IntPtr buffer = ReadClass(token, tokenClass, out error);
        if (buffer == IntPtr.Zero) return "query-error:" + error;
        try {
            IntPtr sid = Marshal.ReadIntPtr(buffer);
            return sid == IntPtr.Zero ? "none" : new SecurityIdentifier(sid).Value;
        } finally { Marshal.FreeHGlobal(buffer); }
    }

    static string DwordClass(IntPtr token, int tokenClass) {
        int error;
        IntPtr buffer = ReadClass(token, tokenClass, out error);
        if (buffer == IntPtr.Zero) return "query-error:" + error;
        try { return Marshal.ReadInt32(buffer).ToString(); }
        finally { Marshal.FreeHGlobal(buffer); }
    }

    public static string Describe(int pid) {
        IntPtr process = OpenProcess(0x1000, false, (uint)pid);
        if (process == IntPtr.Zero) return "open-process-error:" + Marshal.GetLastWin32Error();
        try {
            IntPtr token;
            if (!OpenProcessToken(process, 0x0008, out token))
                return "open-token-error:" + Marshal.GetLastWin32Error();
            try {
                // Windows SDK TOKEN_INFORMATION_CLASS values: 25, 29, 31, 46.
                // A class unsupported by this build is recorded as an error, never assumed false.
                return "IL=" + SidClass(token, 25)
                    + ";AppContainer=" + DwordClass(token, 29)
                    + ";AppContainerSid=" + SidClass(token, 31)
                    + ";LPAC=" + DwordClass(token, 46);
            } finally { CloseHandle(token); }
        } finally { CloseHandle(process); }
    }
}
'@
Add-Type -TypeDefinition $tokenTypeSource -ErrorAction Stop
Write-Output 'COLLECTOR_STAGE=TYPE_COMPILED'

$baseline = [ordered]@{
    UtcStart = $runStart
    Build = $(Write-Host 'COLLECTOR_BASELINE=BUILD'; Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' | Select-Object CurrentBuildNumber, UBR, BuildLabEx)
    OS = $(Write-Host 'COLLECTOR_BASELINE=OS'; Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, OSArchitecture)
    WinHttpProxy = $(Write-Host 'COLLECTOR_BASELINE=WINHTTP_PROXY'; netsh winhttp show proxy | Out-String)
    WinHttpAdvancedProxy = $(Write-Host 'COLLECTOR_BASELINE=WINHTTP_ADVPROXY'; netsh winhttp show advproxy | Out-String)
    IpConfig = $(Write-Host 'COLLECTOR_BASELINE=IPCONFIG'; ipconfig /all | Out-String)
    NCSI = $(Write-Host 'COLLECTOR_BASELINE=NCSI'; Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet' -ErrorAction SilentlyContinue | Select-Object EnableActiveProbing,ActiveWebProbeHost,ActiveWebProbePath,ActiveWebProbeContent,ActiveDnsProbeHost,ActiveDnsProbeContent,DisablePassivePolling)
    AutoproxyService = $(Write-Host 'COLLECTOR_BASELINE=AUTOPROXY_SERVICE'; Get-CimInstance Win32_Service -Filter "Name='WinHttpAutoProxySvc'" | Select-Object Name, State, StartMode, ProcessId, PathName)
    Files = $(Write-Host 'COLLECTOR_BASELINE=FILES'; @(foreach ($name in 'ncsi.dll','winhttp.dll','jsproxy.dll','pacjsworker.exe') {
        $file = Join-Path $env:windir "System32\$name"
        if (Test-Path $file) {
            $item = Get-Item $file
            [ordered]@{Path=$file;Version=$item.VersionInfo.FileVersion;SHA256=(Get-FileHash -Algorithm SHA256 $file).Hash}
        }
    }))
}
$baseline | ConvertTo-Json -Depth 5 -ErrorAction Stop | Out-File (Join-Path $OutputDirectory 'baseline.json') -Encoding utf8
if ((Get-Item (Join-Path $OutputDirectory 'baseline.json')).Length -lt 100) { throw 'Baseline JSON is empty or truncated' }
Write-Output 'COLLECTOR_STAGE=BASELINE_WRITTEN'

# Microsoft documents this InternetClient scenario for WinHTTP function/packet tracing.
# Diagnostic ETW may alter timing; any final terminal must reproduce on stock settings.
& netsh trace start scenario=InternetClient capture=yes report=no persistent=no maxsize=512 tracefile="$prefix.etl" 2>&1 |
    Out-File (Join-Path $OutputDirectory 'trace-start.txt') -Encoding utf8
if ($LASTEXITCODE -ne 0) { "netsh trace start exit=$LASTEXITCODE" | Out-File $errors -Append }
Write-Output 'COLLECTOR_STAGE=TRACE_START_RETURNED'

$seen = @{}
$end = (Get-Date).AddSeconds($Seconds)
try {
    while ((Get-Date) -lt $end) {
        foreach ($p in @(Get-Process -Name 'pacjsworker' -ErrorAction SilentlyContinue)) {
            try {
                $startUtc = $p.StartTime.ToUniversalTime()
                $key = "$($p.Id):$($startUtc.Ticks)"
                if ($seen.ContainsKey($key)) { continue }
                $seen[$key] = $true
                $row = [ordered]@{
                    Utc = (Get-Date).ToUniversalTime().ToString('o')
                    Name = $p.ProcessName
                    Pid = $p.Id
                    StartUtc = $startUtc.ToString('o')
                    Path = $p.Path
                    Token = [LabTokenReader]::Describe($p.Id)
                }
                try {
                    $cim = Get-CimInstance Win32_Process -Filter "ProcessId=$($p.Id)" -ErrorAction Stop
                    $row.ParentPid = $cim.ParentProcessId
                    $row.CommandLine = $cim.CommandLine
                } catch { $row.CimError = $_.Exception.Message }
                $row | ConvertTo-Json -Compress -Depth 5 | Out-File $processLog -Append -Encoding utf8
            } catch { $_.Exception.Message | Out-File $errors -Append -Encoding utf8 }
        }
        Start-Sleep -Milliseconds 200
    }
} finally {
    & netsh trace stop 2>&1 | Out-File (Join-Path $OutputDirectory 'trace-stop.txt') -Encoding utf8
    Write-Output 'COLLECTOR_STAGE=TRACE_STOP_RETURNED'
    Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-NCSI/Operational';StartTime=[datetime]::Parse($runStart)} -ErrorAction SilentlyContinue |
        Select-Object TimeCreated, Id, ProviderName, Message |
        ConvertTo-Json -Depth 4 | Out-File (Join-Path $OutputDirectory 'ncsi-operational.json') -Encoding utf8
    Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-NCSI/Analytic';StartTime=[datetime]::Parse($runStart)} -Oldest -ErrorAction SilentlyContinue |
        Select-Object TimeCreated, Id, ProviderName, Message |
        ConvertTo-Json -Depth 4 | Out-File (Join-Path $OutputDirectory 'ncsi-analytic.json') -Encoding utf8
    "StartUtc=$runStart`nEndUtc=$((Get-Date).ToUniversalTime().ToString('o'))" |
        Out-File (Join-Path $OutputDirectory 'window.txt') -Encoding utf8
}
