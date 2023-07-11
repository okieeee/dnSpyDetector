using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

internal class Program
{
    private static IntPtr kernel32;
    private static IntPtr ntDll;

    private static void Main(string[] args)
    {
        try
        {
            int hooksFoundCount = 0;

            kernel32 = LoadLibrary("kernel32.dll");
            ntDll = LoadLibrary("ntdll.dll");

            hooksFoundCount += DetectHook(kernel32, "IsDebuggerPresent", 0xE9, "IsDebuggerPresent hook detected.");
            hooksFoundCount += DetectHook(kernel32, "CheckRemoteDebuggerPresent", 0xE9, "CheckRemoteDebuggerPresent hook detected.");
            hooksFoundCount += DetectHook(typeof(Debugger), "get_IsAttached", 0x33, "Debugger.IsAttached hook detected.");
            hooksFoundCount += DetectHook(ntDll, "NtRaiseHardError", 0xE9, "NtRaiseHardError hook detected.");
            hooksFoundCount += DetectHook(kernel32, "CloseHandle", 0xE9, "CloseHandle hook detected.");

            if (hooksFoundCount == 0)
            {
                Console.WriteLine("No hooks found!");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine("An error occurred: " + ex.Message);
        }
        finally
        {
            FreeLibrary(kernel32);
            FreeLibrary(ntDll);
        }

        Console.ReadLine();
    }

    private static IntPtr LoadLibrary(string libraryName)
    {
        IntPtr library = NativeLibrary.Load(libraryName);
        if (library == IntPtr.Zero)
        {
            throw new Exception($"Failed to load library: {libraryName}");
        }
        return library;
    }

    private static void FreeLibrary(IntPtr library)
    {
        if (library != IntPtr.Zero)
        {
            NativeLibrary.Free(library);
        }
    }

    private static unsafe int DetectHook(IntPtr module, string functionName, byte expectedOpcode, string hookMessage)
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

    private static unsafe int DetectHook(Type type, string methodName, byte expectedOpcode, string hookMessage)
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
