$ErrorActionPreference = 'Stop'
$lab = Join-Path $env:PUBLIC ('Documents\eop062-edge-download-' + [guid]::NewGuid().ToString('N'))
[void](New-Item -ItemType Directory -Path $lab -Force)
$project = Join-Path $lab 'Actor.csproj'
$source = Join-Path $lab 'Program.cs'
$nodeSource = Join-Path $lab 'download.js'
$downloadDir = Join-Path $lab 'downloaded'
[void](New-Item -ItemType Directory -Path $downloadDir -Force)
$protected = Join-Path $lab 'protected.txt'
[IO.File]::WriteAllText($protected, 'original')
& icacls.exe $protected /setintegritylevel M | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Medium sentinel label failed' }

@'
<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><OutputType>Exe</OutputType><TargetFramework>net10.0</TargetFramework><ImplicitUsings>enable</ImplicitUsings></PropertyGroup></Project>
'@ | Set-Content -Path $project -Encoding utf8
'{"sdk":{"version":"10.0.404","rollForward":"disable"}}' | Set-Content -Path (Join-Path $lab 'global.json') -Encoding utf8
@'
using System.Diagnostics;
using System.IO.Pipes;
using System.Security.Principal;
using System.Text.RegularExpressions;

using var identity = WindowsIdentity.GetCurrent();
var who = Process.Start(new ProcessStartInfo("whoami.exe", "/groups /fo csv /nh") { UseShellExecute = false, RedirectStandardOutput = true })!;
string groupText = who.StandardOutput.ReadToEnd();
who.WaitForExit();
var match = Regex.Match(groupText, @"S-1-16-(\d+)");
Console.WriteLine($"USER={identity.User?.Value} OWNER={identity.Owner?.Value} IL_RID={(match.Success ? match.Groups[1].Value : "UNKNOWN")} RUNTIME={Environment.Version}");
try { File.AppendAllText(args[0], "changed"); Console.WriteLine("PROTECTED_WRITE=ALLOWED"); }
catch (Exception e) { Console.WriteLine($"PROTECTED_WRITE=DENIED TYPE={e.GetType().Name}"); }
try
{
    using var pipe = new NamedPipeServerStream(args[1], PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous);
    Console.WriteLine("PIPE_CREATE=ALLOWED");
    using var timeout = new CancellationTokenSource(10000);
    await pipe.WaitForConnectionAsync(timeout.Token);
    Console.WriteLine("PIPE_HOST_CONNECT=YES");
}
catch (Exception e) { Console.WriteLine($"PIPE_CREATE_OR_CONNECT=DENIED TYPE={e.GetType().Name}"); }
'@ | Set-Content -Path $source -Encoding utf8

@'
const http = require('http');
const fs = require('fs');
const { chromium } = require('playwright');
const source = process.argv[2], target = process.argv[3];
const body = fs.readFileSync(source);
const server = http.createServer((req,res) => {
  if (req.url === '/download') {
    res.writeHead(200, {'Content-Type':'application/octet-stream', 'Content-Disposition':'attachment; filename="eop062-actor.exe"', 'Content-Length':body.length});
    res.end(body);
  } else {
    res.writeHead(200, {'Content-Type':'text/html'});
    res.end('<a href="/download">Download</a>');
  }
});
server.listen(0,'127.0.0.1',async () => {
  let browser;
  try {
    browser = await chromium.launch({channel:'msedge',headless:true});
    const context = await browser.newContext({acceptDownloads:true});
    const page = await context.newPage();
    await page.goto(`http://127.0.0.1:${server.address().port}/`);
    const [download] = await Promise.all([page.waitForEvent('download',{timeout:20000}),page.getByText('Download').click()]);
    const path = await download.path();
    fs.renameSync(path,target);
    console.log(`EDGE_DOWNLOAD=COMPLETE SUGGESTED=${download.suggestedFilename()}`);
  } catch (e) {
    console.log(`EDGE_DOWNLOAD=FAILED TYPE=${e.name} MESSAGE=${String(e.message).split('\n')[0]}`);
    process.exitCode = 2;
  } finally {
    if (browser) await browser.close();
    server.close();
  }
});
'@ | Set-Content -Path $nodeSource -Encoding utf8

& dotnet publish $project -c Release -r win-x64 -v:q '-p:UseSharedCompilation=false' '-p:PublishSingleFile=true' '-p:SelfContained=false' | Out-Host
if ($LASTEXITCODE -ne 0) { throw 'Actor publish failed' }
$original = Join-Path $lab 'bin\Release\net10.0\win-x64\publish\Actor.exe'
$downloaded = Join-Path $downloadDir 'eop062-actor.exe'
Push-Location $lab
try {
    & npm.cmd install --no-save --silent playwright | Out-Host
    if ($LASTEXITCODE -ne 0) { throw 'Playwright package install failed' }
    & node.exe $nodeSource $original $downloaded | Out-Host
    if ($LASTEXITCODE -ne 0) { Write-Host 'EOP062_EDGE_DOWNLOAD_ACTOR_UNAVAILABLE'; exit 0 }
} finally { Pop-Location }

$originalHash = (Get-FileHash $original -Algorithm SHA256).Hash
$downloadHash = (Get-FileHash $downloaded -Algorithm SHA256).Hash
Write-Host "BINARY_HASH_EQUAL=$($originalHash -eq $downloadHash) SDK_VERSION=$(& dotnet --version)"
if ($originalHash -ne $downloadHash) { throw 'Browser download bytes changed' }
$lowControl = Join-Path $lab 'low-labeled-actor.exe'
Copy-Item $original $lowControl
& icacls.exe $lowControl /setintegritylevel Low | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Low actor control label failed' }
Write-Host "ORIGINAL_ACL=$((& icacls.exe $original) -join ';')"
Write-Host "DOWNLOADED_ACL=$((& icacls.exe $downloaded) -join ';')"
Write-Host "LOW_CONTROL_ACL=$((& icacls.exe $lowControl) -join ';')"

function Run-ActorCase([string]$label, [string]$executable) {
    [IO.File]::WriteAllText($protected, 'original')
    $pipeName = 'eop062-download-' + [guid]::NewGuid().ToString('N')
    $job = Start-Job -ArgumentList $pipeName -ScriptBlock {
        param($name)
        try {
            $client = [IO.Pipes.NamedPipeClientStream]::new('.', $name, [IO.Pipes.PipeDirection]::InOut)
            $client.Connect(10000)
            Start-Sleep -Milliseconds 1000
            $client.Dispose()
            'HOST_CONNECT=YES'
        } catch { 'HOST_CONNECT=NO TYPE=' + $_.Exception.GetType().Name }
    }
    try {
        $actorOutput = & $executable $protected $pipeName 2>&1
        $hostOutput = Receive-Job $job -Wait
        return "CASE=$label ACTOR=$(($actorOutput -join ';')) HOST=$(($hostOutput -join ';')) SENTINEL=$([IO.File]::ReadAllText($protected))"
    } finally { Remove-Job $job -Force -ErrorAction SilentlyContinue }
}

$originalResult = Run-ActorCase 'original' $original
$downloadResult = Run-ActorCase 'edge-downloaded' $downloaded
$lowResult = Run-ActorCase 'explicit-low-label' $lowControl
Write-Host $originalResult
Write-Host $downloadResult
Write-Host $lowResult
if ($originalResult -notmatch 'IL_RID=12288.*PROTECTED_WRITE=ALLOWED.*PIPE_HOST_CONNECT=YES') { throw 'Original positive control failed' }
if ($downloadResult -notmatch 'IL_RID=12288.*PROTECTED_WRITE=ALLOWED.*PIPE_HOST_CONNECT=YES') { throw 'Edge download result changed' }
if ($lowResult -notmatch 'IL_RID=4096.*PROTECTED_WRITE=DENIED.*PIPE_HOST_CONNECT=YES') { throw 'Explicit Low measurement control failed' }
Write-Host 'EOP062_EDGE_DOWNLOAD_ACTOR_DIAGNOSTIC_COMPLETE'

# Separate ordinary-standard-account check: the previous download used the High runner account.
$stdName = 'eop062b' + [guid]::NewGuid().ToString('N').Substring(0, 6)
$stdPass = [Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(18)) + 'aA1!'
& net.exe user $stdName $stdPass /add /y | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Standard account creation failed' }
try {
    $stdIdentity = "$env:COMPUTERNAME\$stdName"
    $stdSecure = ConvertTo-SecureString $stdPass -AsPlainText -Force
    $stdCredential = [pscredential]::new($stdIdentity, $stdSecure)
    & icacls.exe $lab /grant "${stdIdentity}:(OI)(CI)M" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Standard lab ACL failed' }
    $stdDir = Join-Path $lab 'standard-downloaded'
    [void](New-Item -ItemType Directory -Path $stdDir -Force)
    $stdDownloaded = Join-Path $stdDir 'eop062-actor.exe'
    $stdNodeOut = Join-Path $lab 'standard-node-out.txt'
    $stdNodeErr = Join-Path $lab 'standard-node-err.txt'
    $nodeExe = (Get-Command node.exe).Source
    $nodeProcess = Start-Process -FilePath $nodeExe -Credential $stdCredential -ArgumentList @($nodeSource, $original, $stdDownloaded) -RedirectStandardOutput $stdNodeOut -RedirectStandardError $stdNodeErr -PassThru -Wait
    Write-Host "STANDARD_EDGE_EXIT=$($nodeProcess.ExitCode) NODE_OUT=$(([IO.File]::ReadAllText($stdNodeOut)).Trim()) NODE_ERR=$(([IO.File]::ReadAllText($stdNodeErr)).Trim())"
    if ($nodeProcess.ExitCode -ne 0 -or -not (Test-Path $stdDownloaded)) { Write-Host 'STANDARD_EDGE_DOWNLOAD_UNAVAILABLE'; exit 0 }
    $stdHashEqual = ((Get-FileHash $stdDownloaded -Algorithm SHA256).Hash -eq $originalHash)
    Write-Host "STANDARD_BINARY_HASH_EQUAL=$stdHashEqual STANDARD_DOWNLOADED_ACL=$((& icacls.exe $stdDownloaded) -join ';')"
    if (-not $stdHashEqual) { throw 'Standard Edge download bytes changed' }
    [IO.File]::WriteAllText($protected, 'original')
    $stdPipe = 'eop062-standard-' + [guid]::NewGuid().ToString('N')
    $stdOut = Join-Path $lab 'standard-actor-out.txt'
    $stdErr = Join-Path $lab 'standard-actor-err.txt'
    $hostJob = Start-Job -ArgumentList $stdPipe -ScriptBlock {
        param($name)
        try {
            $client = [IO.Pipes.NamedPipeClientStream]::new('.', $name, [IO.Pipes.PipeDirection]::InOut)
            $client.Connect(10000)
            Start-Sleep -Milliseconds 1000
            $client.Dispose()
            'HOST_CONNECT=YES'
        } catch { 'HOST_CONNECT=NO TYPE=' + $_.Exception.GetType().Name }
    }
    try {
        $stdActor = Start-Process -FilePath $stdDownloaded -Credential $stdCredential -ArgumentList @($protected, $stdPipe) -RedirectStandardOutput $stdOut -RedirectStandardError $stdErr -PassThru -Wait
        $stdHost = Receive-Job $hostJob -Wait
        $stdText = ([IO.File]::ReadAllText($stdOut)).Trim() -replace "`r?`n", ';'
        $stdErrorText = ([IO.File]::ReadAllText($stdErr)).Trim() -replace "`r?`n", ';'
        Write-Host "STANDARD_CASE EXIT=$($stdActor.ExitCode) ACTOR=$stdText STDERR=$stdErrorText HOST=$stdHost SENTINEL=$([IO.File]::ReadAllText($protected))"
        if ($stdActor.ExitCode -ne 0) { throw 'Standard downloaded actor failed' }
        if ($stdText -notmatch 'IL_RID=8192.*PROTECTED_WRITE=ALLOWED.*PIPE_HOST_CONNECT=YES') { throw 'Standard downloaded actor was not Medium and writable' }
        if ($stdHost -ne 'HOST_CONNECT=YES') { throw 'Host did not see standard actor pipe' }
        Write-Host 'EOP062_STANDARD_EDGE_DOWNLOAD_MEDIUM_CONFIRMED'
    } finally { Remove-Job $hostJob -Force -ErrorAction SilentlyContinue }
} finally {
    & net.exe user $stdName /delete | Out-Null
}
