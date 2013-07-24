/*
 * Injector
 * Copyright (c) 2013-2014 LexManos.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the GNU Lesser Public License v2.1
 * which accompanies this distribution, and is available at
 * http://www.gnu.org/licenses/old-licenses/gpl-2.0.html
 *
 */
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
using System.Diagnostics;

namespace Injector
{
    public static class WinAPI
    {
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public UInt32 dwProcessId;
            public UInt32 dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct STARTUPINFO
        {
            public UInt32 cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public UInt32 dwX;
            public UInt32 dwY;
            public UInt32 dwXSize;
            public UInt32 dwYSize;
            public UInt32 dwXCountChars;
            public UInt32 dwYCountChars;
            public UInt32 dwFillAttribute;
            public UInt32 dwFlags;
            public Int16 wShowWindow;
            public Int16 cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        public const int CREATE_SUSPENDED   = 0x00000004;
        public const int CREATE_NEW_CONSOLE = 0x00000010;
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CreateProcess(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes,
                                bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment,
                                string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern uint ResumeThread(IntPtr hThread);

        public const int PROCESS_TERMINATE                 = 0x0001;
        public const int PROCESS_CREATE_THREAD             = 0x0002;
        public const int PROCESS_VM_OPERATION              = 0x0008;
        public const int PROCESS_VM_READ                   = 0x0010;
        public const int PROCESS_VM_WRITE                  = 0x0020;
        public const int PROCESS_DUP_HANDLE                = 0x0040;
        public const int PROCESS_CREATE_PROCESS            = 0x0080;
        public const int PROCESS_SET_QUOTA                 = 0x0100;
        public const int PROCESS_SET_INFORMATION           = 0x0200;
        public const int PROCESS_QUERY_INFORMATION         = 0x0400;
        public const int PROCESS_SUSPEND_RESUME            = 0x0800;
        public const int PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
        public const int PROCESS_ALL_ACCESS                = 0xFFFF;
        public const int DELETE                        = 0x00010000;
        public const int READ_CONTROL                  = 0x00020000;
        public const int WRITE_DAC                     = 0x00040000;
        public const int WRITE_OWNER                   = 0x00080000;
        public const int SYNCHRONIZE                   = 0x00100000;

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr handle);

        [DllImport("kernel32.dll")]
        private static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress,
                        uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll")]
        private static extern Boolean WriteProcessMemory(IntPtr hProcess, uint lpBaseAddress,
                        byte[] lpBuffer, int nSize, IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32", CharSet = CharSet.Ansi)]
        private extern static IntPtr GetProcAddress(IntPtr hwnd, string procedureName);

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32")]
        private static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize,
                                IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out IntPtr lpThreadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        private static extern bool VirtualFreeEx(IntPtr hProcess, IntPtr lpAddress, int dwSize, AllocationType dwFreeType);

        [DllImport("kernel32.dll", SetLastError = true, CallingConvention = CallingConvention.Winapi)]
        private static extern bool IsWow64Process([In] IntPtr hProcess, [Out] out bool wow64Process);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize, 
                                                    out uint lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern int GetProcessId(IntPtr handle);

        [Flags]
        public enum AllocationType
        {
            Commit     = 0x1000,
            Reserve    = 0x2000,
            Decommit   = 0x4000,
            Release    = 0x8000,
            Reset      = 0x80000,
            Physical   = 0x400000,
            TopDown    = 0x100000,
            WriteWatch = 0x200000,
            LargePages = 0x20000000
        }


        public static Tuple<IntPtr, IntPtr> StartProcess(string target_path, string command_line, string work_dir)
        {
            Console.WriteLine("Attempting to load: {0}", target_path);
            if (command_line != null)
                Console.WriteLine("  Command Line: {0}", command_line);
            if (work_dir != null)
                Console.WriteLine("  Working Dir: {0}", work_dir);

            var si = new STARTUPINFO();
            var pi = new PROCESS_INFORMATION();

            if (!CreateProcess(target_path, command_line,
                IntPtr.Zero, IntPtr.Zero, false, WinAPI.CREATE_SUSPENDED | WinAPI.CREATE_NEW_CONSOLE,
                IntPtr.Zero, work_dir, ref si, out pi))
            {
                Console.WriteLine("Failed to create process... Exiting");
                return null;
            }

            Console.WriteLine("Process created successfully PID: {0}", pi.dwProcessId);

            return Tuple.Create(pi.hProcess, pi.hThread);
        }

        public static bool Is32BitProcess(IntPtr process)
        {
            bool retVal;
            return !Environment.Is64BitOperatingSystem || (IsWow64Process(process, out retVal) && retVal);
        }

        public static byte[] ReadProcessMemory(IntPtr hProc, IntPtr address, uint len)
        {
            byte[] buf = new byte[len];
            uint bytes = 0;
            if (!ReadProcessMemory(hProc, address, buf, buf.Length, out bytes) || bytes != len)
            {
                buf = null;
            }
            return buf;
        }
    }
}
