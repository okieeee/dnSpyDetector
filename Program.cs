// Credits to: https://github.com/XenocodeRCE/dnSpyDetector/tree/master, i did just rewrite it using NativeLibrary and Unsafe.  

using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

class Program
{
    unsafe static void Main(string[] args)
    {
        int hooksFoundCount = 0;

        IntPtr kernel32 = NativeLibrary.Load("kernel32.dll");
        IntPtr getProcAddressPtr = NativeLibrary.GetExport(kernel32, "GetProcAddress");
        var getProcAddress = Marshal.GetDelegateForFunctionPointer<GetProcAddressDelegate>(getProcAddressPtr);

        IntPtr isDebuggerPresentPtr = getProcAddress(kernel32, "IsDebuggerPresent");
        byte isDebOpCode = Unsafe.Read<byte>((void*)isDebuggerPresentPtr);

        if (isDebOpCode == 0xE9)
        {
            Console.WriteLine($"IsDebuggerPresent hook detected.");
            hooksFoundCount++;
        }

        IntPtr checkRemoteDebuggerPresentPtr = getProcAddress(kernel32, "CheckRemoteDebuggerPresent");
        byte isCheckRemOpCode = Unsafe.Read<byte>((void*)checkRemoteDebuggerPresentPtr);

        if (isCheckRemOpCode == 0xE9)
        {
            Console.WriteLine($"CheckRemoteDebuggerPresent hook detected.");
            hooksFoundCount++;
        }

        var getIsAttached = typeof(Debugger).GetMethod("get_IsAttached");
        if (getIsAttached != null)
        {
            IntPtr targetAddress = getIsAttached.MethodHandle.GetFunctionPointer();
            byte opcode = Unsafe.Read<byte>((void*)targetAddress);
            if (opcode == 0x33)
            {
                Console.WriteLine("Debugger.IsAttached hook detected.");
            }
        }

        if (hooksFoundCount == 0)
        {
            Console.WriteLine("No dnSpy hooks found!");
        }

        Console.ReadLine();

        NativeLibrary.Free(kernel32);
    }

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    internal delegate IntPtr GetProcAddressDelegate(IntPtr module, string procName);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    internal delegate bool IsDebuggerPresentDelegate();
}