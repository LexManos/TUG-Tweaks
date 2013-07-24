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
using System.Diagnostics;
using System.IO;
using Mono.Options;

namespace Injector
{
    class Injector
    {
#if DEBUG
        public class DebugTextWriter : TextWriter
        {
            public override Encoding Encoding{ get { return Encoding.UTF8; } }
            public override void Write(char value){ Debug.Write(value); }
            public override void Write(string value){ Debug.Write(value); }
            public override void WriteLine(string value){ Debug.WriteLine(value); }
        }
#endif

        static void Main(string[] args)
        {

#if DEBUG
            Console.SetOut(new DebugTextWriter());
#endif
            string command_line = null;
            string target_path = null;
            string work_dir = null;
            int process_id = -1;
            var to_inject = new List<string>();

            var ops = new OptionSet()
            {
                {"p|process-id=", "Process ID to attach, optional if target is specified", v => process_id = Int32.Parse(v)},
                {"t|target=", "Target path to run, optional if process-id is set", v => target_path = v},
                {"c|command-line=", "Command like to pass to the new process", v => command_line = v},
                {"w|working-dir=", "Working directory of the new process", v => work_dir = v},
                {"d|dll=", "DLL to inject into new process", v => to_inject.Add(v)}
            };

            List<string> extra;
            try
            {
                extra = ops.Parse(args);
            }
            catch (OptionException e)
            {
                Console.Write("Error reading command line: ");
                Console.WriteLine(e.Message);
                return;
            }

            IntPtr process_handle = IntPtr.Zero;
            IntPtr thread_handle = IntPtr.Zero;
            if (process_id == -1)
            {
                if (target_path == null)
                {
                    Console.WriteLine("ProcessID and Target not specified, one must be provided");
                    return;
                }

                var ret = WinAPI.StartProcess(target_path, command_line, work_dir);
                if (ret == null)
                {
                    return;
                }
                process_handle = ret.Item1;
                thread_handle  = ret.Item2;
            }
            else
            {
                process_handle = WinAPI.OpenProcess(WinAPI.PROCESS_ALL_ACCESS, false, process_id);
            }

            if (process_handle == IntPtr.Zero)
            {
                Console.WriteLine("Failed to obtain process handle");
                return;
            }

            Console.WriteLine("is64BitProcess: {0}", Environment.Is64BitProcess);
            Console.WriteLine("is65BitOS:      {0}", Environment.Is64BitOperatingSystem);
            Console.WriteLine("is64BitTarget:  {0}", !WinAPI.Is32BitProcess(process_handle));

            var pe = new PortableExecutable(process_handle);

            if (thread_handle != IntPtr.Zero)
            {
                WinAPI.ResumeThread(thread_handle);
            }
            
            return;
        }
    }
}
