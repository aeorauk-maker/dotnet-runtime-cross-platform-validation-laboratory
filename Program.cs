using System.ComponentModel;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.Principal;

internal static class Program
{
    private const uint TokenAllAccess = 0xF01FF;
    private const uint DisableMaxPrivilege = 1;
    private const uint Integrity = 0x20;
    private const uint WaitTimeout = 258;

    private static int Main(string[] args)
    {
        if (args.Length != 3 || (args[0] != "parent" && args[0] != "child"))
        {
            Console.Error.WriteLine("usage: parent|child PIPE_NAME RESULT_PATH");
            return 2;
        }

        if (args[0] == "child")
        {
            var result = $"CHILD_SID={WindowsIdentity.GetCurrent().User?.Value}\n" +
                         $"CHILD_ADMIN={new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator)}\n" +
                         $"CHILD_IL={CurrentIntegrity()}\n";
            try
            {
                using var pipe = new NamedPipeClientStream(".", args[1], PipeDirection.InOut);
                pipe.Connect(3000);
                result += "CHILD_CONNECT=SUCCESS\n";
            }
            catch (Exception ex)
            {
                result += $"CHILD_CONNECT={ex.GetType().Name}: {ex.Message}\n";
            }
            File.WriteAllText(args[2], result);
            return 0;
        }

        Console.WriteLine($"PARENT_SID={WindowsIdentity.GetCurrent().User?.Value}");
        Console.WriteLine($"PARENT_ADMIN={new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator)}");
        Console.WriteLine($"PARENT_IL={CurrentIntegrity()}");
        if (!OpenProcessToken(GetCurrentProcess(), TokenAllAccess, out var token)) Throw("OpenProcessToken");
        if (!ConvertStringSidToSid("S-1-5-32-544", out var adminSid)) Throw("ConvertStringSidToSid(admin)");
        if (!ConvertStringSidToSid("S-1-16-8192", out var mediumSid)) Throw("ConvertStringSidToSid(medium)");
        var disableSid = Marshal.AllocHGlobal(Marshal.SizeOf<SidAndAttributes>());
        var labelSize = Marshal.SizeOf<TokenMandatoryLabel>();
        var mediumSidSize = (int)GetLengthSid(mediumSid);
        var labelBuffer = Marshal.AllocHGlobal(labelSize + mediumSidSize);
        IntPtr restricted = IntPtr.Zero;
        try
        {
            Marshal.StructureToPtr(new SidAndAttributes { Sid = adminSid }, disableSid, false);
            if (!CreateRestrictedToken(token, DisableMaxPrivilege, 1, disableSid, 0, IntPtr.Zero, 0, IntPtr.Zero, out restricted))
                Throw("CreateRestrictedToken");
            var copiedSid = IntPtr.Add(labelBuffer, labelSize);
            var sidBytes = new byte[mediumSidSize];
            Marshal.Copy(mediumSid, sidBytes, 0, mediumSidSize);
            Marshal.Copy(sidBytes, 0, copiedSid, mediumSidSize);
            Marshal.StructureToPtr(new TokenMandatoryLabel { Label = new SidAndAttributes { Sid = copiedSid, Attributes = Integrity } }, labelBuffer, false);
            if (!SetTokenInformation(restricted, 25, labelBuffer, labelSize + mediumSidSize))
                Throw("SetTokenInformation(TokenIntegrityLevel)");

            var dotnet = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "dotnet", "dotnet.exe");
            var dll = typeof(Program).Assembly.Location;
            var command = $"\"{dotnet}\" \"{dll}\" child \"{args[1]}\" \"{args[2]}\"";
            var startup = new StartupInfo { Size = Marshal.SizeOf<StartupInfo>() };
            if (!CreateProcessWithTokenW(restricted, 0, dotnet, command, 0x08000000, IntPtr.Zero, Path.GetDirectoryName(dll), ref startup, out var process))
                Throw("CreateProcessWithTokenW");
            try
            {
                Console.WriteLine($"CHILD_PID={process.ProcessId}");
                var wait = WaitForSingleObject(process.Process, 10000);
                Console.WriteLine($"CHILD_WAIT={wait}");
                if (wait == WaitTimeout) return 3;
                if (!File.Exists(args[2]))
                {
                    Console.WriteLine("CHILD_RESULT=MISSING");
                    return 4;
                }
                Console.Write(File.ReadAllText(args[2]));
                return 0;
            }
            finally
            {
                CloseHandle(process.Thread);
                CloseHandle(process.Process);
            }
        }
        finally
        {
            if (restricted != IntPtr.Zero) CloseHandle(restricted);
            Marshal.FreeHGlobal(labelBuffer);
            Marshal.FreeHGlobal(disableSid);
            LocalFree(mediumSid);
            LocalFree(adminSid);
            CloseHandle(token);
        }
    }

    private static string CurrentIntegrity()
    {
        if (!OpenProcessToken(GetCurrentProcess(), 0x0008, out var token)) Throw("OpenProcessToken(query)");
        try
        {
            GetTokenInformation(token, 25, IntPtr.Zero, 0, out var length);
            var buffer = Marshal.AllocHGlobal(length);
            try
            {
                if (!GetTokenInformation(token, 25, buffer, length, out _)) Throw("GetTokenInformation");
                var label = Marshal.PtrToStructure<TokenMandatoryLabel>(buffer);
                if (!ConvertSidToStringSid(label.Label.Sid, out var sidString)) Throw("ConvertSidToStringSid");
                try { return Marshal.PtrToStringUni(sidString) ?? "UNKNOWN"; }
                finally { LocalFree(sidString); }
            }
            finally { Marshal.FreeHGlobal(buffer); }
        }
        finally { CloseHandle(token); }
    }

    private static void Throw(string api) => throw new Win32Exception(Marshal.GetLastWin32Error(), api);

    [StructLayout(LayoutKind.Sequential)] private struct SidAndAttributes { public IntPtr Sid; public uint Attributes; }
    [StructLayout(LayoutKind.Sequential)] private struct TokenMandatoryLabel { public SidAndAttributes Label; }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)] private struct StartupInfo
    {
        public int Size; public string? Reserved; public string? Desktop; public string? Title;
        public int X; public int Y; public int XSize; public int YSize; public int XCountChars; public int YCountChars;
        public int FillAttribute; public int Flags; public short ShowWindow; public short Reserved2;
        public IntPtr Reserved3; public IntPtr StandardInput; public IntPtr StandardOutput; public IntPtr StandardError;
    }
    [StructLayout(LayoutKind.Sequential)] private struct ProcessInformation
    { public IntPtr Process; public IntPtr Thread; public int ProcessId; public int ThreadId; }

    [DllImport("kernel32.dll")] private static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32.dll", SetLastError = true)] private static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);
    [DllImport("kernel32.dll")] private static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll")] private static extern IntPtr LocalFree(IntPtr handle);
    [DllImport("advapi32.dll", SetLastError = true)] private static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);
    [DllImport("advapi32.dll", SetLastError = true)] private static extern bool CreateRestrictedToken(IntPtr token, uint flags, uint disableSidCount, IntPtr sidsToDisable, uint deletePrivilegeCount, IntPtr privilegesToDelete, uint restrictSidCount, IntPtr sidsToRestrict, out IntPtr restricted);
    [DllImport("advapi32.dll", SetLastError = true)] private static extern bool SetTokenInformation(IntPtr token, int infoClass, IntPtr info, int infoLength);
    [DllImport("advapi32.dll", SetLastError = true)] private static extern bool GetTokenInformation(IntPtr token, int infoClass, IntPtr info, int infoLength, out int returnLength);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern bool ConvertStringSidToSid(string text, out IntPtr sid);
    [DllImport("advapi32.dll", SetLastError = true)] private static extern uint GetLengthSid(IntPtr sid);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern bool ConvertSidToStringSid(IntPtr sid, out IntPtr text);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern bool CreateProcessWithTokenW(IntPtr token, int logonFlags, string app, string command, int creationFlags, IntPtr environment, string? currentDirectory, ref StartupInfo startup, out ProcessInformation process);
}
