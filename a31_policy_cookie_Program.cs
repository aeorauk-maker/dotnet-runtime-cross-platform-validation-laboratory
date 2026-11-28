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

HttpClient ClientFor(int proxyPort, CookieContainer? cookieJar) {
    var handler = new SocketsHttpHandler {
        UseProxy = true,
        Proxy = new WebProxy($"http://127.0.0.1:{proxyPort}"),
        UseCookies = cookieJar is not null, CookieContainer = cookieJar ?? new CookieContainer()
    };
    return new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(10) };
}
async Task<(int Status, string? Error)> Post(int targetPort, string path, CookieContainer? cookieJar, string? manualCookie = null) {
    await using var proxy = new OneShotConnectProxy(targetPort);
    using var client = ClientFor(proxy.Port, cookieJar);
    using var request = new HttpRequestMessage(HttpMethod.Post, $"https://forbidden.test{path}");
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
    await using var issueProxy = new OneShotConnectProxy(servicePort);
    using var issuer = ClientFor(issueProxy.Port, victimCookieJar);
    using var issueRequest = new HttpRequestMessage(HttpMethod.Post, "https://forbidden.test/issue");
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
        new Uri("https://forbidden.test/protected")) == issuedCookie;
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
    Console.WriteLine(JsonSerializer.Serialize(new { step = "verdict", pass, writes }));
    return pass ? 0 : 1;
} finally {
    await app.StopAsync();
}

sealed class OneShotConnectProxy : IAsyncDisposable {
    private readonly TcpListener listener;
    private readonly CancellationTokenSource stop = new(TimeSpan.FromSeconds(15));
    private readonly Task serving;
    private readonly int targetPort;
    public int Port { get; }
    public bool SawExpectedConnect { get; private set; }
    public string? Error { get; private set; }

    public OneShotConnectProxy(int targetPort) {
        this.targetPort = targetPort;
        listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        Port = ((IPEndPoint)listener.LocalEndpoint).Port;
        serving = Serve();
    }

    private async Task Serve() {
        try {
            using var victim = await listener.AcceptTcpClientAsync(stop.Token);
            using var victimStream = victim.GetStream();
            var bytes = new List<byte>();
            var one = new byte[1];
            while (bytes.Count < 8192) {
                int count = await victimStream.ReadAsync(one, stop.Token);
                if (count == 0) throw new IOException("CONNECT closed before headers");
                bytes.Add(one[0]);
                if (bytes.Count >= 4 && bytes[^4] == '\r' && bytes[^3] == '\n' &&
                    bytes[^2] == '\r' && bytes[^1] == '\n') break;
            }
            string header = Encoding.ASCII.GetString(bytes.ToArray());
            SawExpectedConnect = header.StartsWith("CONNECT forbidden.test:443 HTTP/1.1\r\n", StringComparison.Ordinal);
            if (!SawExpectedConnect) throw new IOException("unexpected CONNECT target");
            using var upstream = new TcpClient();
            await upstream.ConnectAsync(IPAddress.Loopback, targetPort, stop.Token);
            using var upstreamStream = upstream.GetStream();
            await victimStream.WriteAsync(Encoding.ASCII.GetBytes(
                "HTTP/1.1 200 Connection Established\r\n\r\n"), stop.Token);
            var forward = victimStream.CopyToAsync(upstreamStream, stop.Token);
            var backward = upstreamStream.CopyToAsync(victimStream, stop.Token);
            await Task.WhenAny(forward, backward);
        } catch (OperationCanceledException) {
        } catch (Exception e) {
            Error = e.GetType().Name + ": " + e.Message;
        }
    }

    public async ValueTask DisposeAsync() {
        stop.Cancel();
        listener.Stop();
        try { await serving.WaitAsync(TimeSpan.FromSeconds(5)); }
        catch (TimeoutException) { Error = "proxy shutdown timed out"; }
        Console.Error.WriteLine($"proxy connect={SawExpectedConnect} error={Error ?? "none"}");
        stop.Dispose();
    }
}
