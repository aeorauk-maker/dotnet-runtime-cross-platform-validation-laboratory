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
Console.WriteLine($"USER={identity.User?.Value} OWNER={identity.Owner?.Value} IL_RID={(match.Success ? match.Groups[1].Value : "UNKNOWN")}");
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

& dotnet build $project -c Release -v:q '-p:UseSharedCompilation=false' | Out-Host
if ($LASTEXITCODE -ne 0) { throw 'Actor build failed' }
$original = Join-Path $lab 'bin\Release\net10.0\Actor.exe'
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
Write-Host "ORIGINAL_ACL=$((& icacls.exe $original) -join ';')"
Write-Host "DOWNLOADED_ACL=$((& icacls.exe $downloaded) -join ';')"

function Run-ActorCase([string]$label, [string]$executable) {
    [IO.File]::WriteAllText($protected, 'original')
    $pipeName = 'eop062-download-' + [guid]::NewGuid().ToString('N')
    $job = Start-Job -ArgumentList $pipeName -ScriptBlock {
        param($name)
        try {
            $client = [IO.Pipes.NamedPipeClientStream]::new('.', $name, [IO.Pipes.PipeDirection]::InOut)
            $client.Connect(10000)
            $client.Dispose()
            'HOST_CONNECT=YES'
        } catch { 'HOST_CONNECT=NO TYPE=' + $_.Exception.GetType().Name }
    }
    try {
        $actorOutput = & $executable $protected $pipeName 2>&1
        $hostOutput = Receive-Job $job -Wait
        Write-Host "CASE=$label ACTOR=$(($actorOutput -join ';')) HOST=$(($hostOutput -join ';')) SENTINEL=$([IO.File]::ReadAllText($protected))"
    } finally { Remove-Job $job -Force -ErrorAction SilentlyContinue }
}

Run-ActorCase 'original' $original
Run-ActorCase 'edge-downloaded' $downloaded
Write-Host 'EOP062_EDGE_DOWNLOAD_ACTOR_DIAGNOSTIC_COMPLETE'
