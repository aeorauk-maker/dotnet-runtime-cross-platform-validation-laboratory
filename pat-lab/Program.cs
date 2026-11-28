using System.Security.Claims;
using System.Runtime.CompilerServices;
using ContactsApi.Infrastructure.Atlas;
using ContactsApi.Infrastructure.Tenancy;
using ContactsApi.WebApi.Configuration;
using ContactsApi.WebApi.Controllers;
using ContactsApi.WebApi.Middleware;
using ContactsApi.WebApi.Services;
using ContactsApi.WebApi.Services.KeyRing;
using Google.Apis.Auth;
using Google.Apis.Auth.OAuth2.Responses;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using StackExchange.Redis;

// The decision points are exact pinned Contacts/.NET types. Only the operator and
// external Google service are inert lab plumbing; no real account is used.
var redisAddress = Environment.GetEnvironmentVariable("L077_REDIS_ADDRESS") ?? "localhost:6379";
var postgresAddress = Environment.GetEnvironmentVariable("L077_POSTGRES") ??
    "Host=localhost;Port=5432;Database=inert_pat;Username=postgres;Password=inert-lab";
var operatorToken = "inert-lab-operator";
using var redis = ConnectionMultiplexer.Connect(redisAddress);
var builder = WebApplication.CreateBuilder(args);
builder.Logging.ClearProviders();
builder.Logging.AddConsole();
builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
{
    ["Echo:AllowedEmails"] = "owner@example.invalid,peer@example.invalid",
    ["Echo:AdminEmails"] = "owner@example.invalid"
});
builder.Services.AddSingleton<IConnectionMultiplexer>(redis);
builder.Services.AddEchoDataProtection(builder.Configuration, redis);
builder.Services.AddStackExchangeRedisCache(o => { o.Configuration = redisAddress; o.InstanceName = "ContactsApi_"; });
builder.Services.AddEchoSession(builder.Configuration);
builder.Services.Configure<GoogleOAuthOptions>(_ => { });
builder.Services.AddSingleton<IGoogleSignIn, InertGoogle>();
builder.Services.AddSingleton<GoogleTokenService>();
builder.Services.AddEchoRowLevelSecurity(builder.Configuration);
builder.Services.AddDbContext<AtlasDbContext>((sp, o) => OwnerScopeServices.UseOwnerRls(
    o.UseNpgsql(postgresAddress, n => n.MigrationsHistoryTable("__ef_migrations", "atlas")), sp));
builder.Services.AddScoped<AccessTokenService>();
var readiness = new AtlasReadiness { Configured = true };
builder.Services.AddSingleton(readiness);
builder.Services.AddSingleton(new CsrfOptions { PublicOrigin = "https://contacts.example.invalid", IsDevelopment = false });
builder.Services.AddControllers().AddApplicationPart(typeof(AtlasController).Assembly);
builder.Services.AddAuthorization();
var app = builder.Build();
using (var scope = app.Services.CreateScope())
{
    using var unscoped = scope.ServiceProvider.GetRequiredService<OwnerScope>().AllowUnscoped();
    await EchoMigrator.MigrateAsync(scope.ServiceProvider.GetRequiredService<AtlasDbContext>(),
        ContactsApi.Infrastructure.Atlas.Migrations.AtlasRowLevelSecurity.Id, false,
        scope.ServiceProvider.GetRequiredService<ILoggerFactory>().CreateLogger("migration"), CancellationToken.None);
}
readiness.Ready = true;
var pauseSource = new PausingProtectedValueSource();
Task<RotationReport>? pendingRetirement = null;
CancellationToken? pendingCacheToken = null;
app.UseMiddleware<CsrfProtectionMiddleware>();
app.UseSession();
app.UseMiddleware<EchoSessionMiddleware>();
app.UseMiddleware<OwnerScopeMiddleware>();
app.UseAuthorization();
app.MapControllers();
app.MapGet("/operator/ping", () => Results.Ok(new { ready = readiness.Ready }));
app.MapGet("/operator/repository", (HttpContext ctx) =>
{
    if (ctx.Request.Headers["X-Operator"].ToString() != operatorToken) return Results.Unauthorized();
    var keys = KeyRingInspector.Keys(new RedisKeyRingRepository(() => redis.GetDatabase(), DataProtectionConfig.RedisKey));
    return Results.Ok(new { count = keys.Count, keyIds = keys.Keys });
});
app.MapPost("/operator/issue", async (HttpContext ctx, GoogleTokenService tokens, IKeyManager keys) =>
{
    if (ctx.Request.Headers["X-Operator"].ToString() != operatorToken) return Results.Unauthorized();
    var principal = new ClaimsPrincipal(new ClaimsIdentity(new[]
    {
        new Claim(EchoSessionDefaults.SubClaim, "owner1"),
        new Claim(EchoSessionDefaults.EmailClaim, "owner@example.invalid")
    }, EchoSessionDefaults.Scheme));
    var properties = new AuthenticationProperties();
    properties.Items[EchoSessionDefaults.SignedInItem] = DateTimeOffset.UtcNow.ToString("O");
    tokens.SetAccessToken(properties, "inert-google-token", DateTime.UtcNow.AddHours(1));
    await ctx.SignInAsync(EchoSessionDefaults.Scheme, principal, properties);
    return Results.Ok(new { issued = true });
});
app.MapPost("/operator/create-key", (HttpContext ctx, IKeyManager keys) =>
{
    if (ctx.Request.Headers["X-Operator"].ToString() != operatorToken) return Results.Unauthorized();
    var now = DateTimeOffset.UtcNow;
    var key = keys.CreateNewKey(now, now.AddDays(90));
    return Results.Ok(new { count = keys.GetAllKeys().Count, newKey = key.KeyId });
});
app.MapPost("/operator/revoke-key", (HttpContext ctx, RevokeRequest input, IKeyManager keys) =>
{
    if (ctx.Request.Headers["X-Operator"].ToString() != operatorToken) return Results.Unauthorized();
    keys.RevokeKey(input.KeyId, "isolated foreign revocation");
    return Results.Ok(new { revoked = input.KeyId });
});
app.MapPost("/operator/begin-retire", async (HttpContext ctx, IKeyManager keys,
    IDataProtectionProvider provider, DataProtectionCertificates certificates,
    IOptions<KeyManagementOptions> options) =>
{
    if (ctx.Request.Headers["X-Operator"].ToString() != operatorToken) return Results.Unauthorized();
    if (pendingRetirement != null) return Results.Conflict("already started");
    var before = keys.GetAllKeys().Select(k => new { k.KeyId, k.IsRevoked }).ToArray();
    if (before.Length != 2 || before.Any(k => k.IsRevoked))
        return Results.Conflict("expected two unrevoked keys");
    pendingCacheToken = keys.GetCacheExpirationToken();
    var repository = options.Value.XmlRepository ?? throw new InvalidOperationException("repository required");
    var rotator = new KeyRingRotator(provider, keys, repository, certificates,
        new IProtectedValueSource[] { pauseSource }, NullLogger.Instance);
    pendingRetirement = rotator.RunAsync(RotationMode.Retire, CancellationToken.None);
    await pauseSource.Entered.WaitAsync(TimeSpan.FromSeconds(30), ctx.RequestAborted);
    return Results.Ok(new { before, retirementCompleted = pendingRetirement.IsCompleted,
        cacheCanceled = pendingCacheToken.Value.IsCancellationRequested });
});
app.MapPost("/operator/finish-retire", async (HttpContext ctx, IKeyManager keys) =>
{
    if (ctx.Request.Headers["X-Operator"].ToString() != operatorToken) return Results.Unauthorized();
    if (pendingRetirement == null || pendingCacheToken == null) return Results.Conflict("not started");
    pauseSource.Release();
    var report = await pendingRetirement;
    var ring = KeyRingInspector.Keys(new RedisKeyRingRepository(() => redis.GetDatabase(), DataProtectionConfig.RedisKey));
    return Results.Ok(new { report.Refused, report.KeysRetired, report.RetireBlocked,
        cacheCanceled = pendingCacheToken.Value.IsCancellationRequested, keyIds = ring.Keys });
});
app.MapPost("/operator/invalidate-local", (HttpContext ctx, IKeyManager keys) =>
{
    if (ctx.Request.Headers["X-Operator"].ToString() != operatorToken) return Results.Unauthorized();
    var before = keys.GetCacheExpirationToken();
    var now = DateTimeOffset.UtcNow;
    keys.CreateNewKey(now, now.AddDays(90));
    return Results.Ok(new { cacheCanceled = before.IsCancellationRequested });
});
app.MapGet("/operator/check-pat", async (HttpContext ctx, AccessTokenService tokens) =>
{
    if (ctx.Request.Headers["X-Operator"].ToString() != operatorToken) return Results.Unauthorized();
    var header = ctx.Request.Headers.Authorization.ToString();
    var checkedToken = await tokens.CheckAsync(header.StartsWith("Bearer ") ? header[7..] : "");
    return Results.Ok(new { accepted = checkedToken != null, owner = checkedToken?.OwnerId,
        canWrite = checkedToken?.CanWrite });
});
app.Run();

record RevokeRequest(Guid KeyId);

sealed class PausingProtectedValueSource : IProtectedValueSource
{
    private readonly TaskCompletionSource<bool> _entered = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly TaskCompletionSource<bool> _released = new(TaskCreationOptions.RunContinuationsAsynchronously);
    public string Kind => "inert-rotation-gate";
    public string Purpose => "C2-L077.inert-rotation-gate";
    public Task Entered => _entered.Task;
    public void Release() => _released.TrySetResult(true);
    public async IAsyncEnumerable<ProtectedValue> ReadAllAsync([EnumeratorCancellation] CancellationToken ct)
    {
        _entered.TrySetResult(true);
        await _released.Task.WaitAsync(ct);
        yield break;
    }
    public Task<bool> ReplaceAsync(ProtectedValue value, string newProtected, CancellationToken ct) =>
        throw new InvalidOperationException("The inert rotation gate has no values to replace");
}

sealed class InertGoogle : IGoogleSignIn
{
    public Task<TokenResponse> ExchangeCodeAsync(string code, CancellationToken ct) => throw new NotSupportedException();
    public Task<GoogleJsonWebSignature.Payload> ValidateIdTokenAsync(string token) => throw new NotSupportedException();
    public Task<(string AccessToken, DateTime ExpiresAt)?> RefreshAsync(string token) =>
        Task.FromResult<(string, DateTime)?>(null);
    public Task RevokeAsync(string token, CancellationToken ct) => Task.CompletedTask;
}
