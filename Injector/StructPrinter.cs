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
    public class StructPrinter : Dictionary<string, Func<object, string>>
    {
        private static bool _init = false;
        private static Dictionary<Type, StructPrinter> printers = new Dictionary<Type, StructPrinter>();
        private static StructPrinter defaultPrinter = new StructPrinter();

        private static void Init()
        {
            if (_init) return;
            #region macros
            Func<string, int, object, string> hex16A = (name, pad, values) =>
                {
                    var buf = new StringBuilder();
                    buf.Append("  ").Append((name + ":").PadRight(pad));
                    foreach (var value in (UInt16[])values)
                    {
                        buf.AppendFormat(" 0x{0:x4}", value);
                    }
                    return buf.ToString();
                };
            Func<string, int, Enum, string> flags = (name, pad, value) =>
                {
                    var buf = new StringBuilder();
                    buf.Append("  ").Append((name + ":").PadRight(pad));
                    bool hasOne = false;
                    foreach (Enum f in Enum.GetValues(value.GetType()))
                    {
                        if (value.HasFlag(f))
                        {
                            buf.Append(" ").Append(f.ToString());
                            hasOne = true;
                        }
                    }
                    if (!hasOne)
                    {
                        buf.Append(" NONE");
                    }
                    return buf.ToString();
                };
            Func<string, int, object, string> dec16 = (name, pad, value) => String.Format("  {0} {1}",       (name + ":").PadRight(pad), (UInt16)value);
            Func<string, int, object, string> dec32 = (name, pad, value) => String.Format("  {0} {1}",       (name + ":").PadRight(pad), (UInt32)value);
            Func<string, int, object, string> hex16 = (name, pad, value) => String.Format("  {0} 0x{1:x4}",  (name + ":").PadRight(pad), (UInt16)value);
            Func<string, int, object, string> hex32 = (name, pad, value) => String.Format("  {0} 0x{1:x8}",  (name + ":").PadRight(pad), (UInt32)value);
            Func<string, int, object, string> hex64 = (name, pad, value) => String.Format("  {0} 0x{1:x16}", (name + ":").PadRight(pad), (UInt64)value);
            #endregion macros
            #region IMAGE_DOS_HEADER
            printers.Add(typeof(PE.IMAGE_DOS_HEADER), new StructPrinter()
            {
                {"e_magic",    v => hex16 ("Magic",             20, v)},
                {"e_cblp",     v => hex16 ("CLBP",              20, v)},
                {"e_cp",       v => dec16 ("Pages",             20, v)},
                {"e_crlc",     v => dec16 ("Relocations",       20, v)},
                {"e_cparhdr",  v => dec16 ("Header Size",       20, v)},
                {"e_minalloc", v => hex16 ("Min Alloc",         20, v)},
                {"e_maxalloc", v => hex16 ("Max Alloc",         20, v)},
                {"e_ss",       v => dec16 ("SS",                20, v)},
                {"e_sp",       v => dec16 ("SP",                20, v)},
                {"e_csum",     v => hex16 ("Checksum",          20, v)},
                {"e_ip",       v => dec16 ("IP",                20, v)},
                {"e_cs",       v => dec16 ("CS",                20, v)},
                {"e_lfarlc",   v => hex16 ("Reloc Address",     20, v)},
                {"e_ovno",     v => dec16 ("Overlay Number",    20, v)},
                {"e_res1",     v => hex16A("Reserved1",         20, v)},
                {"e_oemid",    v => dec16 ("OEM ID",            20, v)},
                {"e_oeminfo",  v => dec16 ("OEM Info",          20, v)},
                {"e_res2",     v => hex16A("Reserved2",         20, v)},
                {"e_lfanew",   v => hex32 ("New Hader Address", 20, v)},
            });
            #endregion IMAGE_DOS_HEADER
            #region IMAGE_FILE_HEADER
            printers.Add(typeof(PE.IMAGE_FILE_HEADER), new StructPrinter()
            {
                {"TimeDateStamp", v =>
                    {
                        var epoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc).AddSeconds((UInt32)v);
                        return "  Time Date Stamp:      " + epoch;
                    }
                },
                {"NumberOfSections",     v => dec16("Section Count",        21, v)},
                {"PointerToSymbolTable", v => hex32("Symbol Table Address", 21, v)},
                {"NumberOfSymbols",      v => dec32("Symbol Count",         21, v)},
                {"SizeOfOptionalHeader", v => hex16("Optional Header Size", 21, v)},
                {"Characteristics",      v => flags("Characteristics",      21, (PE.IMAGE_FILE)v)}
            });
            #endregion IMAGE_FILE_HEADER
            #region IMAGE_NT_HEADERS32
            printers.Add(typeof(PE.IMAGE_NT_HEADERS32), new StructPrinter()
            {
                {"Signature", v => hex32("Signature", 10, v)},
                {"FileHeader",     v => new StringBuilder().AppendLine("  FileHeader:"    ).Append(Print((PE.IMAGE_FILE_HEADER)v      , "  ")).ToString()},
                {"OptionalHeader", v => new StringBuilder().AppendLine("  OptionalHeader:").Append(Print((PE.IMAGE_OPTIONAL_HEADER32)v, "  ")).ToString()}
            });
            #endregion IMAGE_NT_HEADERS32
            #region IMAGE_NT_HEADERS64
            printers.Add(typeof(PE.IMAGE_NT_HEADERS64), new StructPrinter()
            {
                {"Signature", v => hex32("Signature", 10, v)},
                {"FileHeader",     v => new StringBuilder().AppendLine("  FileHeader:"    ).Append(Print((PE.IMAGE_FILE_HEADER)v      , "  ")).ToString()},
                {"OptionalHeader", v => new StringBuilder().AppendLine("  OptionalHeader:").Append(Print((PE.IMAGE_OPTIONAL_HEADER64)v, "  ")).ToString()}
            });
            #endregion IMAGE_NT_HEADERS64
            #region IMAGE_OPTIONAL_HEADER
            var hex32Names = new String[]
            {
                "SizeOfCode", "SizeOfInitializedData", "SizeOfUninitializedData", "AddressOfEntryPoint", "BaseOfCode", "BaseOfData", 
                "ImageBase", "SectionAlignment", "FileAlignment", "SizeOfImage", "SizeOfHeaders", "CheckSum", "SizeOfStackReserve", 
                "SizeOfStackCommit", "SizeOfHeapReserve", "SizeOfHeapCommit", "LoaderFlags"
            };
            var dataNames = new String[]
            {
                "ExportTable", "ImportTable", "ResourceTable", "ExceptionTable", "CertificateTable", "BaseRelocationTable", "Debug", "Reserved",
                "Architecture", "GlobalPtr", "TLSTable", "LoadConfigTable", "BoundImport", "IAT", "DelayImportDescriptor", "CLRRuntimeHeader"
            };
            var tmp32 = new StructPrinter();
            var tmp64 = new StructPrinter();
            foreach (var s in hex32Names)
            {
                tmp32.Add(s, value => hex32(s, 28, value));
                tmp64.Add(s, value => hex32(s, 28, value));
            }
            foreach (var s in dataNames)
            {
                Func<object, string> func = v =>
                    {
                        var data = (PE.IMAGE_DATA_DIRECTORY)v;
                        return String.Format("  {0} 0x{1:x8} @ 0x{1:x8}", (s + ":").PadRight(28), data.Size, data.VirtualAddress);
                    };
                tmp32.Add(s, func);
                tmp64.Add(s, func);
            }
            foreach (var s in new String[] { "ImageBase", "SizeOfStackReserve", "SizeOfStackCommit", "SizeOfHeapReserve", "SizeOfHeapCommit" })
            {
                tmp64[s] = value => hex64(s, 28, value);
            }
            tmp32.Add("DllCharacteristics", value => flags("DLLCharacteristics", 28, (PE.OptionalDllCharacteristics)value));
            tmp64.Add("DllCharacteristics", value => flags("DLLCharacteristics", 28, (PE.OptionalDllCharacteristics)value));
            printers.Add(typeof(PE.IMAGE_OPTIONAL_HEADER32), tmp32);
            printers.Add(typeof(PE.IMAGE_OPTIONAL_HEADER64), tmp64);
            #endregion IMAGE_OPTIONAL_HEADER
            _init = true;
        }


        public static String Print<T>(T data, string indent = null) where T : struct
        {
            Init();
            StructPrinter printer;
            printers.TryGetValue(typeof(T), out printer);
            if (printer == null)
            {
                printer = defaultPrinter; 
            }

            var buf = new StringBuilder();
            if (indent == null)
            {
                buf.AppendLine(typeof(T).Name);
                indent = "";
            }
            buf.Append(indent).AppendLine("{");

            int max = 0;
            foreach (var field in typeof(T).GetFields())
            {
                max = Math.Max(max, field.Name.Length + 2);
            }

            foreach (var field in typeof(T).GetFields())
            {
                Func<object, string> func;
                printer.TryGetValue(field.Name, out func);
                var value = field.GetValue(data);

                if (func != null)
                {
                    buf.Append(indent).AppendLine(func(value));
                }
                else
                {
                    buf.Append(indent).Append("  ").Append((field.Name + ":") .PadRight(max, ' '));
                    
                    if (value == null)
                    {
                        buf.Append(" null");
                    }
                    else if (value is ValueType || value is string)
                    {
                        buf.Append(value.ToString());
                    }
                    else
                    {
                        buf.Append(value);
                    }

                    buf.AppendLine();
                }
            }

            return buf.Append(indent).Append("}").ToString();
        }
    }
    
    public static class Extensions
    {
        public static String DebugString<T>(this T data) where T : struct
        {
            return StructPrinter.Print(data);
        }
    }

    public class DisplayTypeAttribute : Attribute
    {
        public string Format { get; set; }
        public DisplayTypeAttribute(String format)
        {
            Format = format;
        }
    }
}
