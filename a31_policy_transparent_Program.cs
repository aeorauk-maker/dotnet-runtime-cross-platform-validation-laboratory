using System.Net;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;

var fixtureDir = Path.GetFullPath(args.SingleOrDefault() ?? "fixtures");
using var intermediate = X509CertificateLoader.LoadCertificateFromFile(Path.Combine(fixtureDir, "intermediate.der"));
using var legitimate = X509CertificateLoader.LoadPkcs12FromFile(Path.Combine(fixtureDir, "valid_direct_root.pfx"), null);
var builder = WebApplication.CreateBuilder();
builder.Logging.ClearProviders();
builder.WebHost.UseKestrel(options => options.Listen(IPAddress.Loopback, 0, endpoint => endpoint.UseHttps(legitimate)));
var keyDirectory = Directory.CreateDirectory(Path.Combine(fixtureDir, "owned-keys"));
builder.Services.AddDataProtection().PersistKeysToFileSystem(keyDirectory);
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme).AddCookie(options => {
    options.Cookie.Name = "G09L016OwnedSession";
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.Cookie.HttpOnly = true;
    options.Cookie.SameSite = SameSiteMode.Strict;
    options.Events.OnRedirectToLogin = context => {
        context.Response.StatusCode = 401;
        return Task.CompletedTask;
    };
});
builder.Services.AddAuthorization();
var app = builder.Build();
app.UseAuthentication();
app.UseAuthorization();
int writes = 0;
string ownerProof = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
app.MapPost("/issue", async context => {
    if (context.Request.Headers["X-Owner-Proof"] != ownerProof) {
        context.Response.StatusCode = 403;
        return;
    }
    var principal = new ClaimsPrincipal(new ClaimsIdentity(
        [new Claim(ClaimTypes.NameIdentifier, "owned-user")], CookieAuthenticationDefaults.AuthenticationScheme));
    await context.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal);
    context.Response.StatusCode = 204;
});
app.MapPost("/protected", () => Results.Json(new { writes = Interlocked.Increment(ref writes) })).RequireAuthorization();
await app.StartAsync();
int servicePort = new Uri(app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!
    .Addresses.Single()).Port;
await using var route = new TcpRouteSwitch(servicePort);

HttpClient ClientFor(CookieContainer? cookieJar) {
    var handler = new SocketsHttpHandler {
        UseProxy = false,
        UseCookies = cookieJar is not null, CookieContainer = cookieJar ?? new CookieContainer()
    };
    return new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(10) };
}
async Task<(int Status, string? Error)> Post(int targetPort, string path, CookieContainer? cookieJar, string? manualCookie = null) {
    route.RouteTo(targetPort);
    using var client = ClientFor(cookieJar);
    using var request = new HttpRequestMessage(HttpMethod.Post, $"https://forbidden.test:{route.Port}{path}");
    if (manualCookie is not null) request.Headers.TryAddWithoutValidation("Cookie", manualCookie);
    try {
        using var response = await client.SendAsync(request);
        return ((int)response.StatusCode, null);
    } catch (Exception e) {
        return (0, e.GetType().Name + ": " + e.Message);
    }
}
string Hash(string value) => Convert.ToHexString(SHA256.HashData(Encoding.ASCII.GetBytes(value))).ToLowerInvariant();

try {
    var victimCookieJar = new CookieContainer();
    var noCookie = await Post(servicePort, "/protected", victimCookieJar);
    var noOwnerProof = await Post(servicePort, "/issue", victimCookieJar);
    route.RouteTo(servicePort);
    using var issuer = ClientFor(victimCookieJar);
    using var issueRequest = new HttpRequestMessage(HttpMethod.Post, $"https://forbidden.test:{route.Port}/issue");
    issueRequest.Headers.Add("X-Owner-Proof", ownerProof);
    using var issueResponse = await issuer.SendAsync(issueRequest);
    string issuedCookie = issueResponse.Headers.GetValues("Set-Cookie").Single().Split(';')[0];
    string setCookie = issueResponse.Headers.GetValues("Set-Cookie").Single();
    bool hardenedFlags = setCookie.Contains("secure", StringComparison.OrdinalIgnoreCase) &&
        setCookie.Contains("httponly", StringComparison.OrdinalIgnoreCase) &&
        setCookie.Contains("samesite=strict", StringComparison.OrdinalIgnoreCase);
    Console.WriteLine(JsonSerializer.Serialize(new { step = "cookie_flags", hardened_flags = hardenedFlags,
        secure = setCookie.Contains("secure", StringComparison.OrdinalIgnoreCase),
        http_only = setCookie.Contains("httponly", StringComparison.OrdinalIgnoreCase),
        same_site_strict = setCookie.Contains("samesite=strict", StringComparison.OrdinalIgnoreCase) }));
    bool jarContainsIssuedCookie = victimCookieJar.GetCookieHeader(
        new Uri($"https://forbidden.test:{route.Port}/protected")) == issuedCookie;
    var valid = await Post(servicePort, "/protected", victimCookieJar);
    Console.WriteLine(JsonSerializer.Serialize(new { step = "auth_baselines", no_cookie_status = noCookie.Status,
        no_owner_proof_status = noOwnerProof.Status,
        issue_status = (int)issueResponse.StatusCode, valid_status = valid.Status, writes,
        issued_cookie_sha256 = Hash(issuedCookie), jar_contains_issued_cookie = jarContainsIssuedCookie }));

    async Task<(int Status, string? Error, string Captured, string ServerError)> Intercept(string label) {
        using var actorCert = X509CertificateLoader.LoadPkcs12FromFile(Path.Combine(fixtureDir, label + ".pfx"), null);
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int actorPort = ((IPEndPoint)listener.LocalEndpoint).Port;
        var receiver = Task.Run(async () => {
            try {
                using var socket = await listener.AcceptTcpClientAsync();
                using var tls = new SslStream(socket.GetStream(), false);
                var context = SslStreamCertificateContext.Create(actorCert, [intermediate]);
                await tls.AuthenticateAsServerAsync(new SslServerAuthenticationOptions {
                    ServerCertificateContext = context, EnabledSslProtocols = SslProtocols.None });
                var buffer = new byte[4096];
                var message = new StringBuilder();
                using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
                while (message.Length < 16384) {
                    int count = await tls.ReadAsync(buffer, timeout.Token);
                    if (count == 0) break;
                    message.Append(Encoding.ASCII.GetString(buffer, 0, count));
                    if (message.ToString().Contains("\r\n\r\n", StringComparison.Ordinal)) break;
                }
                await tls.WriteAsync(Encoding.ASCII.GetBytes("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK"));
                return (message.ToString(), "");
            } catch (Exception e) { return ("", e.GetType().Name); }
        });
        var sent = await Post(actorPort, "/protected", victimCookieJar);
        var received = await receiver.WaitAsync(TimeSpan.FromSeconds(10));
        string cookie = received.Item1.Split("\r\n")
            .FirstOrDefault(line => line.StartsWith("Cookie: ", StringComparison.OrdinalIgnoreCase))?
            .Substring("Cookie: ".Length) ?? "";
        Console.WriteLine(JsonSerializer.Serialize(new { step = "intercept", certificate = label,
            victim_status = sent.Status, victim_error = sent.Error, server_error = received.Item2,
            captured_cookie = cookie.Length > 0, captured_cookie_sha256 = cookie.Length > 0 ? Hash(cookie) : "",
            cookie_equals_issued = cookie == issuedCookie, raw_server_request = received.Item1, writes }));
        return (sent.Status, sent.Error, cookie, received.Item2);
    }

    var deniedSan = await Intercept("denied_forbidden_san");
    var actor = await Intercept("attack_no_san_forbidden_cn");
    var wrongName = await Intercept("allowed_san_wrong_host");
    var wrongCookie = await Post(servicePort, "/protected", null, "G09L016OwnedSession=bogus");
    int writesAfterWrongCookie = writes;
    var replay = actor.Captured.Length > 0 ? await Post(servicePort, "/protected", null, actor.Captured) : (0, "no cookie captured");
    Console.WriteLine(JsonSerializer.Serialize(new { step = "replay", actor_capture = actor.Captured.Length > 0,
        wrong_cookie_status = wrongCookie.Status, writes_after_wrong_cookie = writesAfterWrongCookie,
        attacker_replay_status = replay.Item1, replay_error = replay.Item2, writes,
        replay_cookie_sha256 = actor.Captured.Length > 0 ? Hash(actor.Captured) : "" }));
    var repeat = await Intercept("attack_no_san_forbidden_cn");
    bool pass = hardenedFlags && noCookie.Status == 401 && noOwnerProof.Status == 403 && jarContainsIssuedCookie &&
        (int)issueResponse.StatusCode == 204 && valid.Status == 200 &&
        deniedSan.Status == 0 && deniedSan.Captured.Length == 0 && actor.Status == 200 &&
        actor.Captured == issuedCookie && wrongName.Status == 0 && wrongName.Captured.Length == 0 &&
        wrongCookie.Status == 401 && writesAfterWrongCookie == 1 &&
        replay.Item1 == 200 && repeat.Status == 200 &&
        repeat.Captured == issuedCookie && writes == 2;
    Console.WriteLine(JsonSerializer.Serialize(new { step = "verdict", pass, writes,
        routed_connections = route.Forwarded, route_errors = route.Errors }));
    return pass ? 0 : 1;
} finally {
    await app.StopAsync();
}

sealed class TcpRouteSwitch : IAsyncDisposable {
    private readonly TcpListener listener;
    private readonly CancellationTokenSource stop = new();
    private readonly Task serving;
    private int targetPort;
    private int forwarded;
    private int errors;
    public int Port { get; }
    public int Forwarded => Volatile.Read(ref forwarded);
    public int Errors => Volatile.Read(ref errors);

    public TcpRouteSwitch(int targetPort) {
        this.targetPort = targetPort;
        listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        Port = ((IPEndPoint)listener.LocalEndpoint).Port;
        serving = Serve();
    }

    public void RouteTo(int port) => Volatile.Write(ref targetPort, port);

    private async Task Serve() {
        try {
            while (!stop.IsCancellationRequested) {
                var victim = await listener.AcceptTcpClientAsync(stop.Token);
                int port = Volatile.Read(ref targetPort);
                _ = Forward(victim, port);
            }
        } catch (OperationCanceledException) {
        } catch (ObjectDisposedException) {
        }
    }

    private async Task Forward(TcpClient victim, int port) {
        try {
            using (victim) {
                using var upstream = new TcpClient();
                await upstream.ConnectAsync(IPAddress.Loopback, port, stop.Token);
                Interlocked.Increment(ref forwarded);
                using var a = victim.GetStream();
                using var b = upstream.GetStream();
                var forward = a.CopyToAsync(b, stop.Token);
                var backward = b.CopyToAsync(a, stop.Token);
                await Task.WhenAny(forward, backward);
            }
        } catch (OperationCanceledException) {
        } catch (IOException) {
            // A TLS-denied or completed peer can close one copy direction first.
        } catch (ObjectDisposedException) {
        } catch (Exception) {
            Interlocked.Increment(ref errors);
        }
    }

    public async ValueTask DisposeAsync() {
        stop.Cancel();
        listener.Stop();
        await serving;
        stop.Dispose();
    }
}
