// Credits to: https://github.com/XenocodeRCE/dnSpyDetector/tree/master, i did just rewrite it using NativeLibrary and Unsafe.  

using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

class Program
{
    static IntPtr kernel32;
    static IntPtr ntDll;

    unsafe static void Main(string[] args)
    {
        int hooksFoundCount = 0;

        kernel32 = NativeLibrary.Load("kernel32.dll");
        ntDll = NativeLibrary.Load("ntdll.dll");

        hooksFoundCount += DetectHook(kernel32, "IsDebuggerPresent", 0xE9, "IsDebuggerPresent hook detected.");
        hooksFoundCount += DetectHook(kernel32, "CheckRemoteDebuggerPresent", 0xE9, "CheckRemoteDebuggerPresent hook detected.");
        hooksFoundCount += DetectHook(typeof(Debugger), "get_IsAttached", 0x33, "Debugger.IsAttached hook detected.");
        hooksFoundCount += DetectHook(ntDll, "NtRaiseHardError", 0xE9, "NtRaiseHardError hook detected.");
        hooksFoundCount += DetectHook(kernel32, "CloseHandle", 0xE9, "CloseHandle hook detected.");

        if (hooksFoundCount == 0)
        {
            Console.WriteLine("No hooks found!");
        }

        Console.ReadLine();

        NativeLibrary.Free(kernel32);
        NativeLibrary.Free(ntDll);
    }

    unsafe static int DetectHook(IntPtr module, string functionName, byte expectedOpcode, string hookMessage)
    {
        IntPtr getProcAddressPtr = NativeLibrary.GetExport(kernel32, "GetProcAddress");
        var getProcAddress = Marshal.GetDelegateForFunctionPointer<GetProcAddressDelegate>(getProcAddressPtr);

        IntPtr functionPtr = getProcAddress(module, functionName);
        byte opcode = Unsafe.Read<byte>((void*)functionPtr);

        if (opcode == expectedOpcode)
        {
            Console.WriteLine(hookMessage);
            return 1;
        }

        return 0;
    }

    unsafe static int DetectHook(Type type, string methodName, byte expectedOpcode, string hookMessage)
    {
        var method = type.GetMethod(methodName);
        if (method != null)
        {
            IntPtr targetAddress = method.MethodHandle.GetFunctionPointer();
            byte opcode = Unsafe.Read<byte>((void*)targetAddress);

            if (opcode == expectedOpcode)
            {
                Console.WriteLine(hookMessage);
                return 1;
            }
        }

        return 0;
    }

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    internal delegate IntPtr GetProcAddressDelegate(IntPtr module, string procName);
}
