using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;

using var rsa = RSA.Create(2048);
var certReq = new CertificateRequest("CN=owned-l40-server", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
certReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
certReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, false));
certReq.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(certReq.PublicKey, false));
var sans = new SubjectAlternativeNameBuilder();
sans.AddDnsName("localhost");
certReq.CertificateExtensions.Add(sans.Build());
using var serverCert = certReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddHours(1));

var listener = new TcpListener(IPAddress.Loopback, 0);
listener.Start();
var port = ((IPEndPoint)listener.LocalEndpoint).Port;
var rejectServerCertificateNow = false;
var totalCallbackCalls = 0;
RemoteCertificateValidationCallback sharedValidationCallback = (_, peer, _, _) =>
{
    Interlocked.Increment(ref totalCallbackCalls);
    return !rejectServerCertificateNow && peer?.GetCertHashString() == serverCert.GetCertHashString();
};

async Task<object> Attempt(string name, bool rejectServerCertificate, bool allowResume)
{
    rejectServerCertificateNow = rejectServerCertificate;
    var callbacksBefore = Volatile.Read(ref totalCallbackCalls);
    using var client = new TcpClient();
    var acceptTask = listener.AcceptTcpClientAsync();
    await client.ConnectAsync(IPAddress.Loopback, port);
    using var serverTcp = await acceptTask;
    using var serverCapture = new CaptureStream(serverTcp.GetStream());
    using var serverSsl = new SslStream(serverCapture, leaveInnerStreamOpen: true);
    using var clientSsl = new SslStream(client.GetStream(), leaveInnerStreamOpen: false);

    var serverOptions = new SslServerAuthenticationOptions
    {
        ServerCertificate = serverCert,
        EnabledSslProtocols = SslProtocols.None,
        ClientCertificateRequired = false,
        AllowTlsResume = allowResume,
    };
    var clientOptions = new SslClientAuthenticationOptions
    {
        TargetHost = "localhost",
        EnabledSslProtocols = SslProtocols.None,
        AllowTlsResume = allowResume,
        RemoteCertificateValidationCallback = sharedValidationCallback,
    };

    string? serverError = null;
    string? clientError = null;
    bool serverOk = false;
    bool clientOk = false;
    var serverAuth = Task.Run(async () =>
    {
        try
        {
            await serverSsl.AuthenticateAsServerAsync(serverOptions).WaitAsync(TimeSpan.FromSeconds(10));
            serverOk = true;
        }
        catch (Exception ex) { serverError = ex.GetType().Name + ": " + ex.Message; }
    });
    var clientAuth = Task.Run(async () =>
    {
        try
        {
            await clientSsl.AuthenticateAsClientAsync(clientOptions).WaitAsync(TimeSpan.FromSeconds(10));
            clientOk = true;
        }
        catch (Exception ex) { clientError = ex.GetType().Name + ": " + ex.Message; }
    });
    await Task.WhenAll(serverAuth, clientAuth);

    if (serverOk && clientOk)
    {
        // The client must read server data to process TLS 1.3 NewSessionTicket.
        await serverSsl.WriteAsync(new byte[] { 0x42 });
        await serverSsl.FlushAsync();
        var one = new byte[1];
        var got = await clientSsl.ReadAsync(one).AsTask().WaitAsync(TimeSpan.FromSeconds(5));
        if (got != 1 || one[0] != 0x42) throw new Exception("Owned server-data witness failed");
        await clientSsl.WriteAsync(new byte[] { 0x41 });
        await clientSsl.FlushAsync();
        got = await serverSsl.ReadAsync(one).AsTask().WaitAsync(TimeSpan.FromSeconds(5));
        if (got != 1 || one[0] != 0x41) throw new Exception("Owned application-data witness failed");
        // Give OpenSSL a chance to process post-handshake TLS 1.3 NewSessionTicket.
        await Task.Delay(100);
    }

    return new
    {
        name,
        rejectServerCertificate,
        allowResume,
        callbackCalls = Volatile.Read(ref totalCallbackCalls) - callbacksBefore,
        serverOk,
        clientOk,
        serverError,
        clientError,
        serverHelloPsk = ServerHelloHasPsk(serverCapture.Captured),
        negotiatedProtocol = serverOk ? serverSsl.SslProtocol.ToString() : null,
        serverRemoteCertificatePresent = serverOk ? serverSsl.RemoteCertificate is not null : (bool?)null,
        applicationDataTransferred = serverOk && clientOk,
    };
}

var results = new List<object>();
results.Add(await Attempt("cold-accept", false, true));
if (Environment.GetEnvironmentVariable("L40_DEBUG") == "1")
{
    Console.WriteLine(JsonSerializer.Serialize(results));
    return;
}
for (var i = 0; i < 4; i++)
    results.Add(await Attempt($"warm-accept-{i}", false, true));
results.Add(await Attempt("mutate-reject-current-callback", true, true));
results.Add(await Attempt("negative-reject-no-resume", true, false));
results.Add(await Attempt("reverse-order-accept-again", false, true));

Console.WriteLine(JsonSerializer.Serialize(new
{
    runtime = System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription,
    os = System.Runtime.InteropServices.RuntimeInformation.OSDescription,
    tls = "platform-selected; require TLS 1.3 in Linux evidence",
    port,
    certSha256 = Convert.ToHexString(SHA256.HashData(serverCert.RawData)),
    results,
}));
listener.Stop();

static bool? ServerHelloHasPsk(byte[] bytes)
{
    var pos = 0;
    while (pos + 5 <= bytes.Length)
    {
        var recordType = bytes[pos];
        var length = (bytes[pos + 3] << 8) | bytes[pos + 4];
        pos += 5;
        if (pos + length > bytes.Length) return null;
        if (recordType == 22 && length >= 44 && bytes[pos] == 2)
        {
            var hsLength = (bytes[pos + 1] << 16) | (bytes[pos + 2] << 8) | bytes[pos + 3];
            var end = pos + 4 + hsLength;
            if (end > pos + length) return null;
            var cursor = pos + 4 + 2 + 32;
            var sessionIdLength = bytes[cursor++];
            cursor += sessionIdLength + 2 + 1;
            if (cursor + 2 > end) return null;
            var extensionsLength = (bytes[cursor] << 8) | bytes[cursor + 1];
            cursor += 2;
            var extensionsEnd = cursor + extensionsLength;
            if (extensionsEnd > end) return null;
            while (cursor + 4 <= extensionsEnd)
            {
                var extType = (bytes[cursor] << 8) | bytes[cursor + 1];
                var extLength = (bytes[cursor + 2] << 8) | bytes[cursor + 3];
                cursor += 4;
                if (cursor + extLength > extensionsEnd) return null;
                if (extType == 0x0029) return true; // TLS 1.3 pre_shared_key selected identity.
                cursor += extLength;
            }
            return false;
        }
        pos += length;
    }
    return null;
}

sealed class CaptureStream(Stream inner) : Stream
{
    private readonly MemoryStream _capture = new();
    public byte[] Captured => _capture.ToArray();
    public override bool CanRead => inner.CanRead;
    public override bool CanSeek => false;
    public override bool CanWrite => inner.CanWrite;
    public override long Length => throw new NotSupportedException();
    public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
    public override void Flush() => inner.Flush();
    public override Task FlushAsync(CancellationToken cancellationToken) => inner.FlushAsync(cancellationToken);
    public override int Read(byte[] buffer, int offset, int count) => inner.Read(buffer, offset, count);
    public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) => inner.ReadAsync(buffer, cancellationToken);
    public override void Write(byte[] buffer, int offset, int count)
    {
        _capture.Write(buffer, offset, count);
        inner.Write(buffer, offset, count);
    }
    public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        _capture.Write(buffer.Span);
        return inner.WriteAsync(buffer, cancellationToken);
    }
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    protected override void Dispose(bool disposing)
    {
        if (disposing) { _capture.Dispose(); inner.Dispose(); }
        base.Dispose(disposing);
    }
}
