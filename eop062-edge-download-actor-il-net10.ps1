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
const path = require('path');
if (process.argv[4]) {
  process.env.USERPROFILE = process.argv[4];
  process.env.LOCALAPPDATA = path.join(process.argv[4], 'AppData', 'Local');
  process.env.APPDATA = path.join(process.argv[4], 'AppData', 'Roaming');
}
process.env.TEMP = path.dirname(process.argv[3]);
process.env.TMP = process.env.TEMP;
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
    const savedPath = await download.path();
    fs.renameSync(savedPath,target);
    console.log(`EDGE_DOWNLOAD=COMPLETE SUGGESTED=${download.suggestedFilename()}`);
  } catch (e) {
    console.log(`EDGE_DOWNLOAD=FAILED TYPE=${e.name} MESSAGE=${String(e.message).replace(/\r?\n/g,' | ').slice(0,2500)}`);
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
if ($env:GITHUB_WORKSPACE) {
    $artifactActor = Join-Path $env:GITHUB_WORKSPACE 'eop062-actor-inert.exe'
    Copy-Item -LiteralPath $original -Destination $artifactActor -Force
    Write-Host "ARTIFACT_ACTOR_SHA256=$((Get-FileHash $artifactActor -Algorithm SHA256).Hash)"
}
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
$stdPass = [Convert]::ToHexString([Security.Cryptography.RandomNumberGenerator]::GetBytes(18)) + 'aA1!'
& net.exe user $stdName $stdPass /add /y 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Standard account creation failed' }
try {
    $stdIdentity = "$env:COMPUTERNAME\$stdName"
    $stdProfile = Join-Path $env:SystemDrive "Users\$stdName"
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
    $nodeProcess = Start-Process -FilePath $nodeExe -Credential $stdCredential -LoadUserProfile -ArgumentList @($nodeSource, $original, $stdDownloaded, $stdProfile) -RedirectStandardOutput $stdNodeOut -RedirectStandardError $stdNodeErr -PassThru -Wait
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
        $stdActor = Start-Process -FilePath $stdDownloaded -Credential $stdCredential -LoadUserProfile -ArgumentList @($protected, $stdPipe) -RedirectStandardOutput $stdOut -RedirectStandardError $stdErr -PassThru -Wait
        $stdHost = Receive-Job $hostJob -Wait
        $stdText = ([IO.File]::ReadAllText($stdOut)).Trim() -replace "`r?`n", ';'
        $stdErrorText = ([IO.File]::ReadAllText($stdErr)).Trim() -replace "`r?`n", ';'
        Write-Host "STANDARD_CASE EXIT=$($stdActor.ExitCode) ACTOR=$stdText STDERR=$stdErrorText HOST=$stdHost SENTINEL=$([IO.File]::ReadAllText($protected))"
        if ($stdActor.ExitCode -ne 0) { throw 'Standard downloaded actor failed' }
        if ($stdText -notmatch 'IL_RID=8192.*PROTECTED_WRITE=ALLOWED.*PIPE_HOST_CONNECT=YES') { throw 'Standard downloaded actor was not Medium and writable' }
        if ($stdHost -ne 'HOST_CONNECT=YES') { throw 'Host did not see standard actor pipe' }
        Write-Host 'EOP062_STANDARD_EDGE_DOWNLOAD_MEDIUM_CONFIRMED'
    } finally { Remove-Job $hostJob -Force -ErrorAction SilentlyContinue }

    # Public Internet-zone comparison. Inspect the downloaded Microsoft executable; do not execute it.
    $publicNodeSource = Join-Path $lab 'public-download.js'
    @'
const fs = require('fs');
const path = require('path');
const profile = process.argv[2], target = process.argv[3], directUrl = process.argv[4];
process.env.USERPROFILE = profile;
process.env.LOCALAPPDATA = path.join(profile, 'AppData', 'Local');
process.env.APPDATA = path.join(profile, 'AppData', 'Roaming');
process.env.TEMP = path.dirname(target);
process.env.TMP = process.env.TEMP;
const { chromium } = require('playwright');
(async () => {
  let browser;
  try {
    browser = await chromium.launch({channel:'msedge',headless:true});
    const context = await browser.newContext({acceptDownloads:true});
    const page = await context.newPage();
    let downloadPromise;
    if (directUrl) {
      downloadPromise = page.waitForEvent('download',{timeout:30000});
      await page.goto(directUrl).catch(e => {
        const message = String(e.message);
        if (!message.includes('ERR_ABORTED') && !message.includes('Download is starting')) throw e;
      });
    } else {
      await page.goto('https://live.sysinternals.com/tools/');
      downloadPromise = page.waitForEvent('download',{timeout:30000});
      await page.getByRole('link',{name:/^sigcheck\.exe$/i}).click();
    }
    const download = await downloadPromise;
    fs.renameSync(await download.path(), target);
    console.log((directUrl ? 'EXACT' : 'PUBLIC') + '_EDGE_DOWNLOAD=COMPLETE SUGGESTED=' + download.suggestedFilename());
  } catch (e) {
    console.log((directUrl ? 'EXACT' : 'PUBLIC') + '_EDGE_DOWNLOAD=FAILED TYPE=' + e.name + ' MESSAGE=' + String(e.message).replace(/\r?\n/g,' | ').slice(0,1500));
    process.exitCode = 2;
  } finally {
    if (browser) await browser.close();
  }
})();
'@ | Set-Content -Path $publicNodeSource -Encoding utf8
    $publicTarget = Join-Path $stdDir 'sigcheck-public.exe'
    $publicOut = Join-Path $lab 'public-node-out.txt'
    $publicErr = Join-Path $lab 'public-node-err.txt'
    $publicRun = Start-Process -FilePath $nodeExe -Credential $stdCredential -LoadUserProfile -ArgumentList @($publicNodeSource, $stdProfile, $publicTarget) -RedirectStandardOutput $publicOut -RedirectStandardError $publicErr -PassThru -Wait
    Write-Host "PUBLIC_EDGE_EXIT=$($publicRun.ExitCode) NODE_OUT=$(([IO.File]::ReadAllText($publicOut)).Trim()) NODE_ERR=$(([IO.File]::ReadAllText($publicErr)).Trim())"
    if ($publicRun.ExitCode -eq 0 -and (Test-Path $publicTarget)) {
        Write-Host "PUBLIC_FILE_ACL=$((& icacls.exe $publicTarget) -join ';')"
        $publicStreams = @(Get-Item -LiteralPath $publicTarget -Stream * | ForEach-Object Stream)
        Write-Host "PUBLIC_FILE_STREAMS=$($publicStreams -join ',')"
        if ($publicStreams -contains 'Zone.Identifier') {
            Write-Host "PUBLIC_FILE_ZONE=$((Get-Content -LiteralPath $publicTarget -Stream Zone.Identifier) -join ';')"
        }
        $publicSig = Get-AuthenticodeSignature -LiteralPath $publicTarget
        Write-Host "PUBLIC_FILE_SIGNATURE=$($publicSig.Status) SIGNER=$($publicSig.SignerCertificate.Subject)"
        Write-Host 'EOP062_PUBLIC_INTERNET_ZONE_CONTROL_COMPLETE'
    } else { Write-Host 'EOP062_PUBLIC_INTERNET_ZONE_CONTROL_UNAVAILABLE' }

    $exactUrl = 'https://raw.githubusercontent.com/aeorauk-maker/dotnet-runtime-cross-platform-validation-laboratory/9a15ee0347cd3f45ef5c5996383cf575bdffd14b/eop062-actor-inert.exe'
    $exactHash = 'F63C534A2F18EDC7CAE544E62C23F0757ADE9325157CF3799FC1DEDED06693D5'
    $exactTarget = Join-Path $stdDir 'eop062-actor-https.exe'
    $exactNodeOut = Join-Path $lab 'exact-node-out.txt'
    $exactNodeErr = Join-Path $lab 'exact-node-err.txt'
    $exactRun = Start-Process -FilePath $nodeExe -Credential $stdCredential -LoadUserProfile -ArgumentList @($publicNodeSource, $stdProfile, $exactTarget, $exactUrl) -RedirectStandardOutput $exactNodeOut -RedirectStandardError $exactNodeErr -PassThru -Wait
    Write-Host "EXACT_EDGE_EXIT=$($exactRun.ExitCode) NODE_OUT=$(([IO.File]::ReadAllText($exactNodeOut)).Trim()) NODE_ERR=$(([IO.File]::ReadAllText($exactNodeErr)).Trim())"
    if ($exactRun.ExitCode -eq 0 -and (Test-Path $exactTarget)) {
        $actualExactHash = (Get-FileHash $exactTarget -Algorithm SHA256).Hash
        Write-Host "EXACT_BINARY_HASH=$actualExactHash EXPECTED=$exactHash"
        if ($actualExactHash -ne $exactHash) { throw 'Exact public actor hash mismatch' }
        Write-Host "EXACT_FILE_ACL=$((& icacls.exe $exactTarget) -join ';')"
        $exactStreams = @(Get-Item -LiteralPath $exactTarget -Stream * | ForEach-Object Stream)
        Write-Host "EXACT_FILE_STREAMS=$($exactStreams -join ',')"
        if ($exactStreams -contains 'Zone.Identifier') {
            Write-Host "EXACT_FILE_ZONE=$((Get-Content -LiteralPath $exactTarget -Stream Zone.Identifier) -join ';')"
        }
        [IO.File]::WriteAllText($protected, 'original')
        $exactPipe = 'eop062-https-' + [guid]::NewGuid().ToString('N')
        $exactActorOut = Join-Path $lab 'exact-actor-out.txt'
        $exactActorErr = Join-Path $lab 'exact-actor-err.txt'
        $exactHostJob = Start-Job -ArgumentList $exactPipe -ScriptBlock {
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
            $exactActor = Start-Process -FilePath $exactTarget -Credential $stdCredential -LoadUserProfile -ArgumentList @($protected, $exactPipe) -RedirectStandardOutput $exactActorOut -RedirectStandardError $exactActorErr -PassThru -Wait
            $exactHost = Receive-Job $exactHostJob -Wait
            $exactText = ([IO.File]::ReadAllText($exactActorOut)).Trim() -replace "`r?`n", ';'
            $exactErrorText = ([IO.File]::ReadAllText($exactActorErr)).Trim() -replace "`r?`n", ';'
            Write-Host "EXACT_CASE EXIT=$($exactActor.ExitCode) ACTOR=$exactText STDERR=$exactErrorText HOST=$exactHost SENTINEL=$([IO.File]::ReadAllText($protected))"
            if ($exactActor.ExitCode -ne 0) { throw 'Exact public actor failed' }
            if ($exactHost -ne 'HOST_CONNECT=YES') { throw 'Exact public actor pipe invisible' }
            if ($exactText -match 'IL_RID=4096.*PROTECTED_WRITE=DENIED.*PIPE_HOST_CONNECT=YES') { Write-Host 'EOP062_EXACT_HTTPS_LOW_ACTOR_CANDIDATE' }
            elseif ($exactText -match 'IL_RID=8192.*PROTECTED_WRITE=ALLOWED.*PIPE_HOST_CONNECT=YES') { Write-Host 'EOP062_EXACT_HTTPS_MEDIUM_ACTOR_CONFIRMED' }
            else { throw 'Exact public actor token/write result unexpected' }
        } finally { Remove-Job $exactHostJob -Force -ErrorAction SilentlyContinue }
    } else { Write-Host 'EOP062_EXACT_HTTPS_ACTOR_UNAVAILABLE' }
} finally {
    & net.exe user $stdName /delete | Out-Null
}
