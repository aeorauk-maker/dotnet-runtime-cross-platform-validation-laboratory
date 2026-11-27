using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;

internal static class Program
{
    private const uint TokenAllAccess = 0xF01FF;
    private const uint DisableMaxPrivilege = 1;
    private const uint Integrity = 0x20;
    private const uint GenericReadWrite = 0xC0000000;
    private static readonly IntPtr InvalidHandle = new(-1);

    private static int Main(string[] args)
    {
        if (args.Length != 3 || args[0] != "parent")
        {
            Console.Error.WriteLine("usage: parent PIPE_NAME UNUSED_RESULT_PATH");
            return 2;
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

            var pipePath = @"\\.\pipe\" + args[1];
            if (!ImpersonateLoggedOnUser(restricted)) Throw("ImpersonateLoggedOnUser");
            try
            {
                Console.WriteLine($"MEDIUM_SID={WindowsIdentity.GetCurrent().User?.Value}");
                Console.WriteLine($"MEDIUM_ADMIN={new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator)}");
                Console.WriteLine($"MEDIUM_IL={CurrentIntegrity(thread: true)}");
                TryPipe(pipePath, "MEDIUM");
            }
            finally
            {
                if (!RevertToSelf()) Throw("RevertToSelf");
            }
            TryPipe(pipePath, "HIGH");
            return 0;
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

    private static void TryPipe(string path, string label)
    {
        var handle = CreateFile(path, GenericReadWrite, 0, IntPtr.Zero, 3, 0, IntPtr.Zero);
        var error = Marshal.GetLastWin32Error();
        Console.WriteLine($"{label}_PIPE_OPEN={(handle != InvalidHandle ? "SUCCESS" : "DENIED_OR_UNAVAILABLE")}");
        Console.WriteLine($"{label}_PIPE_WIN32={error}");
        if (handle != InvalidHandle) CloseHandle(handle);
    }

    private static string CurrentIntegrity(bool thread = false)
    {
        if (thread)
        {
            if (!OpenThreadToken(GetCurrentThread(), 0x0008, out var threadToken, true)) Throw("OpenThreadToken(query)");
            return IntegrityOf(threadToken);
        }
        if (!OpenProcessToken(GetCurrentProcess(), 0x0008, out var token)) Throw("OpenProcessToken(query)");
        return IntegrityOf(token);
    }

    private static string IntegrityOf(IntPtr token)
    {
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
    [DllImport("kernel32.dll")] private static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32.dll")] private static extern IntPtr GetCurrentThread();
    [DllImport("kernel32.dll")] private static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll")] private static extern IntPtr LocalFree(IntPtr handle);
    [DllImport("advapi32.dll", SetLastError = true)] private static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);
    [DllImport("advapi32.dll", SetLastError = true)] private static extern bool OpenThreadToken(IntPtr thread, uint access, out IntPtr token, bool openAsSelf);
    [DllImport("advapi32.dll", SetLastError = true)] private static extern bool ImpersonateLoggedOnUser(IntPtr token);
    [DllImport("advapi32.dll", SetLastError = true)] private static extern bool RevertToSelf();
    [DllImport("advapi32.dll", SetLastError = true)] private static extern bool CreateRestrictedToken(IntPtr token, uint flags, uint disableSidCount, IntPtr sidsToDisable, uint deletePrivilegeCount, IntPtr privilegesToDelete, uint restrictSidCount, IntPtr sidsToRestrict, out IntPtr restricted);
    [DllImport("advapi32.dll", SetLastError = true)] private static extern bool SetTokenInformation(IntPtr token, int infoClass, IntPtr info, int infoLength);
    [DllImport("advapi32.dll", SetLastError = true)] private static extern bool GetTokenInformation(IntPtr token, int infoClass, IntPtr info, int infoLength, out int returnLength);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern bool ConvertStringSidToSid(string text, out IntPtr sid);
    [DllImport("advapi32.dll", SetLastError = true)] private static extern uint GetLengthSid(IntPtr sid);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern bool ConvertSidToStringSid(IntPtr sid, out IntPtr text);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern IntPtr CreateFile(string path, uint access, uint share, IntPtr security, uint creation, uint flags, IntPtr template);
}
