using System;
using System.Collections;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;


namespace ComponentUtil
{
    using SizeT = UIntPtr;

    public enum MemPageState : uint
    {
        MEM_COMMIT = 0x1000,
        MEM_RESERVE = 0x2000,
        MEM_FREE = 0x10000,
    }

    public enum MemPageType : uint
    {
        MEM_PRIVATE = 0x20000,
        MEM_MAPPED = 0x40000,
        MEM_IMAGE = 0x1000000
    }

    [Flags]
    public enum MemPageProtect : uint
    {
        PAGE_NOACCESS = 0x01,
        PAGE_READONLY = 0x02,
        PAGE_READWRITE = 0x04,
        PAGE_WRITECOPY = 0x08,
        PAGE_EXECUTE = 0x10,
        PAGE_EXECUTE_READ = 0x20,
        PAGE_EXECUTE_READWRITE = 0x40,
        PAGE_EXECUTE_WRITECOPY = 0x80,
        PAGE_GUARD = 0x100,
        PAGE_NOCACHE = 0x200,
        PAGE_WRITECOMBINE = 0x400,
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct MemoryBasicInformation // MEMORY_BASIC_INFORMATION
    {
        public IntPtr BaseAddress;
        public IntPtr AllocationBase;
        public MemPageProtect AllocationProtect;
        public SizeT RegionSize;
        public MemPageState State;
        public MemPageProtect Protect;
        public MemPageType Type;
    }

    public static class WinAPI
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer,
            SizeT nSize, out SizeT lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer,
            SizeT nSize, out SizeT lpNumberOfBytesWritten);

        [DllImport("psapi.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool EnumProcessModulesEx(IntPtr hProcess, [Out] IntPtr[] lphModule, uint cb,
            out uint lpcbNeeded, uint dwFilterFlag);

        [DllImport("psapi.dll", SetLastError = true)]
        public static extern uint GetModuleFileNameEx(IntPtr hProcess, IntPtr hModule, [Out] StringBuilder lpBaseName,
            uint nSize);

        [DllImport("psapi.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool GetModuleInformation(IntPtr hProcess, IntPtr hModule, [Out] out MODULEINFO lpmodinfo,
            uint cb);

        [DllImport("psapi.dll")]
        public static extern uint GetModuleBaseName(IntPtr hProcess, IntPtr hModule, [Out] StringBuilder lpBaseName,
            uint nSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool IsWow64Process(IntPtr hProcess,
            [Out, MarshalAs(UnmanagedType.Bool)] out bool wow64Process);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern SizeT VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress,
            [Out] out MemoryBasicInformation lpBuffer, SizeT dwLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, SizeT dwSize, uint flAllocationType,
            MemPageProtect flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool VirtualFreeEx(IntPtr hProcess, IntPtr lpAddress, SizeT dwSize, uint dwFreeType);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, SizeT dwSize,
            MemPageProtect flNewProtect, [Out] out MemPageProtect lpflOldProtect);

        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern IntPtr NtSuspendProcess(IntPtr hProcess);

        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern IntPtr NtResumeProcess(IntPtr hProcess);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, SizeT dwStackSize,
            IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out IntPtr lpThreadId);

        [StructLayout(LayoutKind.Sequential)]
        public struct MODULEINFO
        {
            public IntPtr lpBaseOfDll;
            public uint SizeOfImage;
            public IntPtr EntryPoint;
        }
    }

    public class ProcessModuleWow64Safe
    {
        public IntPtr BaseAddress { get; set; }
        public IntPtr EntryPointAddress { get; set; }
        public string FileName { get; set; }
        public int ModuleMemorySize { get; set; }
        public string ModuleName { get; set; }
        public FileVersionInfo FileVersionInfo
        {
            get { return FileVersionInfo.GetVersionInfo(FileName); }
        }
        public override string ToString()
        {
            return ModuleName ?? base.ToString();
        }
    }

    public enum ReadStringType
    {
        AutoDetect,
        ASCII,
        UTF8,
        UTF16
    }

    public static class ExtensionMethods
    {
        private static readonly Dictionary<int, ProcessModuleWow64Safe[]> ModuleCache = new Dictionary<int, ProcessModuleWow64Safe[]>();

        public static ProcessModuleWow64Safe MainModuleWow64Safe(this Process p)
        {
            return p.ModulesWow64Safe().First();
        }

        public static ProcessModuleWow64Safe[] ModulesWow64Safe(this Process p)
        {
            if (ModuleCache.Count > 100)
                ModuleCache.Clear();

            const int LIST_MODULES_ALL = 3;
            const int MAX_PATH = 260;

            var hModules = new IntPtr[1024];

            uint cb = (uint)IntPtr.Size * (uint)hModules.Length;

            if (!WinAPI.EnumProcessModulesEx(p.Handle, hModules, cb, out uint cbNeeded, LIST_MODULES_ALL))
                throw new Win32Exception();
            uint numMods = cbNeeded / (uint)IntPtr.Size;

            int hash = p.StartTime.GetHashCode() + p.Id + (int)numMods;
            if (ModuleCache.ContainsKey(hash))
                return ModuleCache[hash];

            var ret = new List<ProcessModuleWow64Safe>();

            // everything below is fairly expensive, which is why we cache!
            var sb = new StringBuilder(MAX_PATH);
            for (int i = 0; i < numMods; i++)
            {
                sb.Clear();
                if (WinAPI.GetModuleFileNameEx(p.Handle, hModules[i], sb, (uint)sb.Capacity) == 0)
                    throw new Win32Exception();
                string fileName = sb.ToString();

                sb.Clear();
                if (WinAPI.GetModuleBaseName(p.Handle, hModules[i], sb, (uint)sb.Capacity) == 0)
                    throw new Win32Exception();
                string baseName = sb.ToString();

                WinAPI.MODULEINFO _moduleInfo = new WinAPI.MODULEINFO();
                if (!WinAPI.GetModuleInformation(p.Handle, hModules[i], out _moduleInfo, (uint)Marshal.SizeOf(_moduleInfo)))
                    throw new Win32Exception();

                ret.Add(new ProcessModuleWow64Safe()
                {
                    FileName = fileName,
                    BaseAddress = _moduleInfo.lpBaseOfDll,
                    ModuleMemorySize = (int)_moduleInfo.SizeOfImage,
                    EntryPointAddress = _moduleInfo.EntryPoint,
                    ModuleName = baseName
                });
            }

            ModuleCache.Add(hash, ret.ToArray());

            return ret.ToArray();
        }

        public static IEnumerable<MemoryBasicInformation> MemoryPages(this Process process, bool all = false)
        {
            // hardcoded values because GetSystemInfo / GetNativeSystemInfo can't return info for remote process
            var min = 0x10000L;
            var max = process.Is64Bit() ? 0x00007FFFFFFEFFFFL : 0x7FFEFFFFL;

            var mbiSize = (SizeT)Marshal.SizeOf(typeof(MemoryBasicInformation));

            var addr = min;
            do
            {
                if (WinAPI.VirtualQueryEx(process.Handle, (IntPtr)addr, out MemoryBasicInformation mbi, mbiSize) == (SizeT)0)
                    break;
                addr += (long)mbi.RegionSize;

                // don't care about reserved/free pages
                if (mbi.State != MemPageState.MEM_COMMIT)
                    continue;

                // probably don't care about guarded pages
                if (!all && (mbi.Protect & MemPageProtect.PAGE_GUARD) != 0)
                    continue;

                // probably don't care about image/file maps
                if (!all && mbi.Type != MemPageType.MEM_PRIVATE)
                    continue;

                yield return mbi;

            } while (addr < max);
        }

        public static bool Is64Bit(this Process process)
        {
            WinAPI.IsWow64Process(process.Handle, out bool procWow64);
            if (Environment.Is64BitOperatingSystem && !procWow64)
                return true;
            return false;
        }

        public static bool ReadValue<T>(this Process process, IntPtr addr, out T val) where T : struct
        {
            var type = typeof(T);
            type = type.IsEnum ? Enum.GetUnderlyingType(type) : type;

            val = default;
            if (!ReadValue(process, addr, type, out object val2))
                return false;

            val = (T)val2;

            return true;
        }

        public static bool ReadValue(Process process, IntPtr addr, Type type, out object val)
        {

            val = null;
            int size = type == typeof(bool) ? 1 : Marshal.SizeOf(type);
            if (!ReadBytes(process, addr, size, out byte[] bytes))
                return false;

            val = ResolveToType(bytes, type);

            return true;
        }

        public static bool ReadBytes(this Process process, IntPtr addr, int count, out byte[] val)
        {
            var bytes = new byte[count];

            val = null;
            if (!WinAPI.ReadProcessMemory(process.Handle, addr, bytes, (SizeT)bytes.Length, out SizeT read)
                || read != (SizeT)bytes.Length)
                return false;

            val = bytes;

            return true;
        }

        public static bool ReadPointer(this Process process, IntPtr addr, out IntPtr val)
        {
            return ReadPointer(process, addr, process.Is64Bit(), out val);
        }

        public static bool ReadPointer(this Process process, IntPtr addr, bool is64Bit, out IntPtr val)
        {
            var bytes = new byte[is64Bit ? 8 : 4];

            val = IntPtr.Zero;
            if (!WinAPI.ReadProcessMemory(process.Handle, addr, bytes, (SizeT)bytes.Length, out SizeT read)
                || read != (SizeT)bytes.Length)
                return false;

            val = is64Bit ? (IntPtr)BitConverter.ToInt64(bytes, 0) : (IntPtr)BitConverter.ToUInt32(bytes, 0);

            return true;
        }

        public static bool ReadString(this Process process, IntPtr addr, int numBytes, out string str)
        {
            return ReadString(process, addr, ReadStringType.AutoDetect, numBytes, out str);
        }

        public static bool ReadString(this Process process, IntPtr addr, ReadStringType type, int numBytes, out string str)
        {
            var sb = new StringBuilder(numBytes);
            if (!ReadString(process, addr, type, sb))
            {
                str = string.Empty;
                return false;
            }

            str = sb.ToString();

            return true;
        }

        public static bool ReadString(this Process process, IntPtr addr, StringBuilder sb)
        {
            return ReadString(process, addr, ReadStringType.AutoDetect, sb);
        }

        public static bool ReadString(this Process process, IntPtr addr, ReadStringType type, StringBuilder sb)
        {
            var bytes = new byte[sb.Capacity];
            if (!WinAPI.ReadProcessMemory(process.Handle, addr, bytes, (SizeT)bytes.Length, out SizeT read)
                || read != (SizeT)bytes.Length)
                return false;

            if (type == ReadStringType.AutoDetect)
            {
                if (read.ToUInt64() >= 2 && bytes[1] == '\x0')
                    sb.Append(Encoding.Unicode.GetString(bytes));
                else
                    sb.Append(Encoding.UTF8.GetString(bytes));
            }
            else if (type == ReadStringType.UTF8)
                sb.Append(Encoding.UTF8.GetString(bytes));
            else if (type == ReadStringType.UTF16)
                sb.Append(Encoding.Unicode.GetString(bytes));
            else
                sb.Append(Encoding.ASCII.GetString(bytes));

            for (int i = 0; i < sb.Length; i++)
            {
                if (sb[i] == '\0')
                {
                    sb.Remove(i, sb.Length - i);
                    break;
                }
            }

            return true;
        }

        public static T ReadValue<T>(this Process process, IntPtr addr, T default_ = default) where T : struct
        {
            if (!process.ReadValue(addr, out T val))
                val = default_;
            return val;
        }

        public static byte[] ReadBytes(this Process process, IntPtr addr, int count)
        {
            if (!process.ReadBytes(addr, count, out byte[] bytes))
                return null;
            return bytes;
        }

        public static IntPtr ReadPointer(this Process process, IntPtr addr, IntPtr default_ = default)
        {
            if (!process.ReadPointer(addr, out IntPtr ptr))
                return default_;
            return ptr;
        }

        public static string ReadString(this Process process, IntPtr addr, int numBytes, string default_ = null)
        {
            if (!process.ReadString(addr, numBytes, out string str))
                return default_;
            return str;
        }

        public static string ReadString(this Process process, IntPtr addr, ReadStringType type, int numBytes, string default_ = null)
        {
            if (!process.ReadString(addr, type, numBytes, out string str))
                return default_;
            return str;
        }

        public static bool WriteValue<T>(this Process process, IntPtr addr, T obj) where T : struct
        {
            int size = Marshal.SizeOf(obj);
            byte[] arr = new byte[size];

            IntPtr ptr = Marshal.AllocHGlobal(size);
            Marshal.StructureToPtr(obj, ptr, true);
            Marshal.Copy(ptr, arr, 0, size);
            Marshal.FreeHGlobal(ptr);

            return process.WriteBytes(addr, arr);
        }

        public static bool WriteBytes(this Process process, IntPtr addr, byte[] bytes)
        {
            if (!WinAPI.WriteProcessMemory(process.Handle, addr, bytes, (SizeT)bytes.Length, out SizeT written)
                || written != (SizeT)bytes.Length)
                return false;

            return true;
        }

        private static bool WriteJumpOrCall(Process process, IntPtr addr, IntPtr dest, bool call)
        {
            var x64 = process.Is64Bit();

            int jmpLen = x64 ? 12 : 5;

            var instruction = new List<byte>(jmpLen);
            if (x64)
            {
                instruction.AddRange(new byte[] { 0x48, 0xB8 }); // mov rax immediate
                instruction.AddRange(BitConverter.GetBytes((long)dest));
                instruction.AddRange(new byte[] { 0xFF, call ? (byte)0xD0 : (byte)0xE0 }); // jmp/call rax
            }
            else
            {
                int offset = unchecked((int)dest - (int)(addr + jmpLen));
                instruction.AddRange(new byte[] { call ? (byte)0xE8 : (byte)0xE9 }); // jmp/call immediate
                instruction.AddRange(BitConverter.GetBytes(offset));
            }

            process.VirtualProtect(addr, jmpLen, MemPageProtect.PAGE_EXECUTE_READWRITE, out MemPageProtect oldProtect);
            bool success = process.WriteBytes(addr, instruction.ToArray());
            process.VirtualProtect(addr, jmpLen, oldProtect);

            return success;
        }

        public static bool WriteJumpInstruction(this Process process, IntPtr addr, IntPtr dest)
        {
            return WriteJumpOrCall(process, addr, dest, false);
        }

        public static bool WriteCallInstruction(this Process process, IntPtr addr, IntPtr dest)
        {
            return WriteJumpOrCall(process, addr, dest, true);
        }

        public static IntPtr WriteDetour(this Process process, IntPtr src, int overwrittenBytes, IntPtr dest)
        {
            int jmpLen = process.Is64Bit() ? 12 : 5;
            if (overwrittenBytes < jmpLen)
                throw new ArgumentOutOfRangeException(nameof(overwrittenBytes),
                    $"must be >= length of jmp instruction ({jmpLen})");

            // allocate memory to store the original src prologue bytes we overwrite with jump to dest
            // along with the jump back to src
            IntPtr gate;
            if ((gate = process.AllocateMemory(jmpLen + overwrittenBytes)) == IntPtr.Zero)
                throw new Win32Exception();

            try
            {
                // read the original bytes from the prologue of src
                var origSrcBytes = process.ReadBytes(src, overwrittenBytes);
                if (origSrcBytes == null)
                    throw new Win32Exception();

                // write the original prologue of src into the start of gate
                if (!process.WriteBytes(gate, origSrcBytes))
                    throw new Win32Exception();

                // write the jump from the end of the gate back to src
                if (!process.WriteJumpInstruction(gate + overwrittenBytes, src + overwrittenBytes))
                    throw new Win32Exception();

                // finally write the jump from src to dest
                if (!process.WriteJumpInstruction(src, dest))
                    throw new Win32Exception();

                // nop the leftover bytes in the src prologue
                int extraBytes = overwrittenBytes - jmpLen;
                if (extraBytes > 0)
                {
                    var nops = Enumerable.Repeat((byte)0x90, extraBytes).ToArray();
                    if (!process.VirtualProtect(src + jmpLen, nops.Length, MemPageProtect.PAGE_EXECUTE_READWRITE,
                        out MemPageProtect oldProtect))
                        throw new Win32Exception();
                    if (!process.WriteBytes(src + jmpLen, nops))
                        throw new Win32Exception();
                    process.VirtualProtect(src + jmpLen, nops.Length, oldProtect);
                }
            }
            catch
            {
                process.FreeMemory(gate);
                throw;
            }

            return gate;
        }

        static object ResolveToType(byte[] bytes, Type type)
        {
            object val;

            if (type == typeof(int))
            {
                val = BitConverter.ToInt32(bytes, 0);
            }
            else if (type == typeof(uint))
            {
                val = BitConverter.ToUInt32(bytes, 0);
            }
            else if (type == typeof(float))
            {
                val = BitConverter.ToSingle(bytes, 0);
            }
            else if (type == typeof(double))
            {
                val = BitConverter.ToDouble(bytes, 0);
            }
            else if (type == typeof(byte))
            {
                val = bytes[0];
            }
            else if (type == typeof(bool))
            {
                if (bytes == null)
                    val = false;
                else
                    val = (bytes[0] != 0);
            }
            else if (type == typeof(short))
            {
                val = BitConverter.ToInt16(bytes, 0);
            }
            else // probably a struct
            {
                var handle = GCHandle.Alloc(bytes, GCHandleType.Pinned);
                try
                {
                    val = Marshal.PtrToStructure(handle.AddrOfPinnedObject(), type);
                }
                finally
                {
                    handle.Free();
                }
            }

            return val;
        }

        public static IntPtr AllocateMemory(this Process process, int size)
        {
            return WinAPI.VirtualAllocEx(process.Handle, IntPtr.Zero, (SizeT)size, (uint)MemPageState.MEM_COMMIT,
                MemPageProtect.PAGE_EXECUTE_READWRITE);
        }

        public static bool FreeMemory(this Process process, IntPtr addr)
        {
            const uint MEM_RELEASE = 0x8000;
            return WinAPI.VirtualFreeEx(process.Handle, addr, SizeT.Zero, MEM_RELEASE);
        }

        public static bool VirtualProtect(this Process process, IntPtr addr, int size, MemPageProtect protect,
            out MemPageProtect oldProtect)
        {
            return WinAPI.VirtualProtectEx(process.Handle, addr, (SizeT)size, protect, out oldProtect);
        }

        public static bool VirtualProtect(this Process process, IntPtr addr, int size, MemPageProtect protect)
        {
            return WinAPI.VirtualProtectEx(process.Handle, addr, (SizeT)size, protect, out _);
        }

        public static IntPtr CreateThread(this Process process, IntPtr startAddress, IntPtr parameter)
        {
            return WinAPI.CreateRemoteThread(process.Handle, IntPtr.Zero, (SizeT)0, startAddress, parameter, 0,
                out _);
        }

        public static IntPtr CreateThread(this Process process, IntPtr startAddress)
        {
            return CreateThread(process, startAddress, IntPtr.Zero);
        }

        public static void Suspend(this Process process)
        {
            WinAPI.NtSuspendProcess(process.Handle);
        }

        public static void Resume(this Process process)
        {
            WinAPI.NtResumeProcess(process.Handle);
        }

        public static float ToFloatBits(this uint i)
        {
            return BitConverter.ToSingle(BitConverter.GetBytes(i), 0);
        }

        public static uint ToUInt32Bits(this float f)
        {
            return BitConverter.ToUInt32(BitConverter.GetBytes(f), 0);
        }

        public static bool BitEquals(this float f, float o)
        {
            return ToUInt32Bits(f) == ToUInt32Bits(o);
        }
    }

    public class SignatureScanner
    {
        private byte[] _memory;
        private Process _process;
        private IntPtr _address;
        private int _size;

        public IntPtr Address
        {
            get { return _address; }
            set
            {
                _memory = null;
                _address = value;
            }
        }

        public int Size
        {
            get { return _size; }
            set
            {
                _memory = null;
                _size = value;
            }
        }

        public Process Process
        {
            get { return _process; }
            set
            {
                _memory = null;
                _process = value;
            }
        }

        public byte[] Memory
        {
            get { return _memory; }
            set
            {
                _memory = value;
                _size = value.Length;
            }
        }

        public SignatureScanner(Process proc, IntPtr addr, int size)
        {
            if (addr == IntPtr.Zero)
                throw new ArgumentException("addr cannot be IntPtr.Zero.", nameof(addr));
            if (size <= 0)
                throw new ArgumentException("size cannot be less than zero.", nameof(size));

            _process = proc ?? throw new ArgumentNullException(nameof(proc));
            _address = addr;
            _size = size;
            _memory = new byte[1];
        }

        public SignatureScanner(byte[] mem)
        {
            _memory = mem ?? throw new ArgumentNullException(nameof(mem));
            _size = mem.Length;
        }

        // backwards compat method signature
        public IntPtr Scan(SigScanTarget target)
        {
            return Scan(target, 1);
        }

        public IntPtr Scan(SigScanTarget target, int align)
        {
            if ((long)_address % align != 0)
                throw new ArgumentOutOfRangeException(nameof(align), "start address must be aligned");

            return ScanAll(target, align).FirstOrDefault();
        }

        public IEnumerable<IntPtr> ScanAll(SigScanTarget target, int align = 1)
        {
            if ((long)_address % align != 0)
                throw new ArgumentOutOfRangeException(nameof(align), "start address must be aligned");

            return ScanInternal(target, align);
        }

        IEnumerable<IntPtr> ScanInternal(SigScanTarget target, int align)
        {
            if (_memory == null || _memory.Length != _size)
            {

                if (!_process.ReadBytes(_address, _size, out byte[] bytes))
                {
                    _memory = null;
                    yield break;
                }

                _memory = bytes;
            }

            foreach (SigScanTarget.Signature sig in target.Signatures)
            {
                // have to implement IEnumerator manually because you can't yield in an unsafe block...
                foreach (int off in new ScanEnumerator(_memory, align, sig))
                {
                    var ptr = _address + off + sig.Offset;
                    if (target.OnFound != null)
                        ptr = target.OnFound(_process, this, ptr);
                    yield return ptr;
                }
            }
        }

        class ScanEnumerator : IEnumerator<int>, IEnumerable<int>
        {
            // IEnumerator
            public int Current { get; private set; }
            object IEnumerator.Current { get { return Current; } }

            private readonly byte[] _memory;
            private readonly int _align;
            private readonly SigScanTarget.Signature _sig;

            private readonly int _sigLen;
            private readonly int _end;

            private int _nextIndex;

            public ScanEnumerator(byte[] mem, int align, SigScanTarget.Signature sig)
            {
                if (mem.Length < sig.Pattern.Length)
                    throw new ArgumentOutOfRangeException(nameof(mem), "memory buffer length must be >= pattern length");

                _memory = mem;
                _align = align;
                _sig = sig;

                _sigLen = _sig.Pattern.Length;
                _end = _memory.Length - _sigLen;
            }

            // IEnumerator
            public bool MoveNext()
            {
                return _sig.Mask != null ? NextPattern() : NextBytes();
            }
            public void Reset()
            {
                _nextIndex = 0;
            }
            public void Dispose()
            {
            }

            // IEnumerable
            public IEnumerator<int> GetEnumerator()
            {
                return this;
            }
            IEnumerator IEnumerable.GetEnumerator()
            {
                return this;
            }

            unsafe bool NextPattern()
            {
                fixed (bool* mask = _sig.Mask)
                fixed (byte* mem = _memory, sig = _sig.Pattern)
                {
                    // perf: locals are MUCH faster than properties and fields, especially on writes
                    int end = _end;
                    int sigLen = _sigLen;
                    int align = _align;
                    int index = _nextIndex; // biggest speed increase

                    for (; index < end; index += align) // index++ would be ~7% faster
                    {
                        for (int sigIndex = 0; sigIndex < sigLen; sigIndex++)
                        {
                            if (mask[sigIndex])
                                continue;
                            if (sig[sigIndex] != mem[index + sigIndex])
                                goto next;
                        }

                        // fully matched
                        Current = index;
                        _nextIndex = index + align;
                        return true;

                    next:
                        ;
                    }

                    return false;
                }
            }

            unsafe bool NextBytes()
            {
                // just a straight memory compare
                fixed (byte* mem = _memory, sig = _sig.Pattern)
                {
                    int end = _end;
                    int index = _nextIndex;
                    int align = _align;
                    int sigLen = _sigLen;

                    for (; index < end; index += align)
                    {
                        for (int sigIndex = 0; sigIndex < sigLen; sigIndex++)
                        {
                            if (sig[sigIndex] != mem[index + sigIndex])
                                goto next;
                        }

                        // fully matched
                        Current = index;
                        _nextIndex = index + align;
                        return true;

                    next:
                        ;
                    }

                    return false;
                }
            }
        }
    }

    public class SigScanTarget
    {
        public struct Signature
        {
            public byte[] Pattern;
            public bool[] Mask;
            public int Offset;
        }

        public delegate IntPtr OnFoundCallback(Process proc, SignatureScanner scanner, IntPtr ptr);
        public OnFoundCallback OnFound { get; set; }

        private readonly List<Signature> _sigs;
        public ReadOnlyCollection<Signature> Signatures
        {
            get { return _sigs.AsReadOnly(); }
        }

        public SigScanTarget()
        {
            _sigs = new List<Signature>();
        }

        public SigScanTarget(int offset, params string[] signature)
            : this()
        {
            AddSignature(offset, signature);
        }

        public SigScanTarget(int offset, params byte[] signature)
            : this()
        {
            AddSignature(offset, signature);
        }

        public SigScanTarget(params string[] signature) : this(0, signature) { }
        // make sure to cast the first arg to byte if using params, so you don't accidentally use offset ctor
        public SigScanTarget(params byte[] binary) : this(0, binary) { }

        public void AddSignature(int offset, params string[] signature)
        {
            string sigStr = string.Join(string.Empty, signature).Replace(" ", string.Empty);
            if (sigStr.Length % 2 != 0)
                throw new ArgumentException(nameof(signature));

            var sigBytes = new List<byte>();
            var sigMask = new List<bool>();
            var hasMask = false;

            for (int i = 0; i < sigStr.Length; i += 2)
            {
                if (byte.TryParse(sigStr.Substring(i, 2), NumberStyles.HexNumber, null, out byte b))
                {
                    sigBytes.Add(b);
                    sigMask.Add(false);
                }
                else
                {
                    sigBytes.Add(0);
                    sigMask.Add(true);
                    hasMask = true;
                }
            }

            _sigs.Add(new Signature
            {
                Pattern = sigBytes.ToArray(),
                Mask = hasMask ? sigMask.ToArray() : null,
                Offset = offset,
            });
        }

        public void AddSignature(int offset, params byte[] binary)
        {
            _sigs.Add(new Signature
            {
                Pattern = binary,
                Mask = null,
                Offset = offset,
            });
        }

        public void AddSignature(params string[] signature)
        {
            AddSignature(0, signature);
        }

        public void AddSignature(params byte[] binary)
        {
            AddSignature(0, binary);
        }
    }
}