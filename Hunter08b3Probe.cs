using System.Formats.Tar;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;

var mutation = Environment.GetEnvironmentVariable("HUNTER_08B3_ENTRY");
if (string.IsNullOrEmpty(mutation))
{
    Console.Error.WriteLine("MISSING_PRIVATE_ENTRY");
    return 2;
}

var assembly = typeof(TarFile).Assembly;
Console.WriteLine($"RUNTIME={Environment.Version}");
Console.WriteLine($"TAR_ASSEMBLY={assembly.GetName().Version}");
Console.WriteLine($"TAR_SHA256={Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(assembly.Location)))}");

var baseDir = Path.Combine(Path.GetTempPath(), "hunter08b3-" + Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(baseDir);
int failures = 0;

try
{
    Probe("VALID", "inside.txt", expectOutside: false);
    Probe("DENIED", "../outside.txt", expectOutside: false);
    Probe("MUTATION_A", mutation, expectOutside: true);
    Probe("MUTATION_B", mutation, expectOutside: true);
}
finally
{
    try { Directory.Delete(baseDir, recursive: true); } catch (IOException) { }
}

return failures;

void Probe(string label, string entryName, bool expectOutside)
{
    string caseDir = Path.Combine(baseDir, label);
    string destination = Path.Combine(caseDir, "dest");
    Directory.CreateDirectory(destination);
    string outside = Path.Combine(caseDir, "outside.txt");
    string inside = Path.Combine(destination, "inside.txt");
    byte[] contents = Encoding.UTF8.GetBytes("HUNTER08B3_" + label);

    using var stream = new MemoryStream();
    using (var writer = new TarWriter(stream, leaveOpen: true))
    {
        var entry = new PaxTarEntry(TarEntryType.RegularFile, entryName)
        {
            DataStream = new MemoryStream(contents)
        };
        writer.WriteEntry(entry);
    }
    stream.Position = 0;

    string outcome = "SUCCESS";
    try
    {
        TarFile.ExtractToDirectory(stream, destination, overwriteFiles: true);
    }
    catch (Exception e)
    {
        outcome = e.GetType().Name;
    }

    bool outsideWritten = File.Exists(outside) && File.ReadAllBytes(outside).SequenceEqual(contents);
    bool insideWritten = File.Exists(inside) && File.ReadAllBytes(inside).SequenceEqual(contents);
    bool anyDestinationFile = Directory.EnumerateFiles(destination, "*", SearchOption.AllDirectories).Any();
    Console.WriteLine($"{label}:OUTCOME={outcome};OUTSIDE={outsideWritten};INSIDE={insideWritten};DESTINATION_FILE={anyDestinationFile}");

    if (label == "VALID" && (!insideWritten || outsideWritten)) failures |= 1;
    if (label == "DENIED" && (outcome == "SUCCESS" || outsideWritten)) failures |= 2;
    if (expectOutside && !outsideWritten) failures |= 4;
}
