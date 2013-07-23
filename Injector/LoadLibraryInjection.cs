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

namespace Injector
{
    class LoadLibraryInjection
    {
        public static bool InjectDLL(IntPtr ProcessID, String DLL)
        {
            bool success = false;
            byte[] dll_str = Encoding.ASCII.GetBytes(DLL);

            IntPtr fnRemote = VirtualAllocEx(ProcessID, IntPtr.Zero, (uint)(dll_str.Length + 1), 0x1000, 0x04);

            if (fnRemote != IntPtr.Zero)
            {
                /* Write the filename to the remote process. */
                IntPtr written = IntPtr.Zero;
                if (WriteProcessMemory(ProcessID, (uint)fnRemote.ToInt32(), dll_str, dll_str.Length, written))
                {
                    /* Get the address of the LoadLibraryA function */
                    IntPtr procLoadLibraryA = GetProcAddress(GetModuleHandle("Kernel32"), "LoadLibraryA");
                    IntPtr ThreadID = new IntPtr();
                    IntPtr hThread = CreateRemoteThread(ProcessID, IntPtr.Zero, 0, procLoadLibraryA, fnRemote, 0, out ThreadID);
                    if (hThread != IntPtr.Zero)
                    {
                        WaitForSingleObject(hThread, 0xFFFFFFFF);
                        success = true;
                    }
                }
                VirtualFreeEx(ProcessID, fnRemote, 0, AllocationType.Release);
            }

            return success;
        }
    }
}
