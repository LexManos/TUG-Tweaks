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
    public class PE
    {
        #region IMAGE_DOS_HEADER
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct IMAGE_DOS_HEADER
        {
            public UInt16 e_magic;          // Magic number                      : 0x00
            public UInt16 e_cblp;           // Bytes on last page of file        : 0x02
            public UInt16 e_cp;             // Pages in file                     : 0x04
            public UInt16 e_crlc;           // Relocations                       : 0x06
            public UInt16 e_cparhdr;        // Size of header in paragraphs      : 0x08
            public UInt16 e_minalloc;       // Minimum extra paragraphs needed   : 0x0a
            public UInt16 e_maxalloc;       // Maximum extra paragraphs needed   : 0x0c
            public UInt16 e_ss;             // Initial (relative) SS value       : 0x0e
            public UInt16 e_sp;             // Initial SP value                  : 0x10
            public UInt16 e_csum;           // Checksum                          : 0x12
            public UInt16 e_ip;             // Initial IP value                  : 0x14
            public UInt16 e_cs;             // Initial (relative) CS value       : 0x16
            public UInt16 e_lfarlc;         // File address of relocation table  : 0x18
            public UInt16 e_ovno;           // Overlay number                    : 0x1a
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public UInt16[] e_res1;         // Reserved words                    : 0x1c
            public UInt16 e_oemid;          // OEM identifier (for e_oeminfo)    : 0x24
            public UInt16 e_oeminfo;        // OEM information; e_oemid specific : 0x26
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 10)]
            public UInt16[] e_res2;         // Reserved words                    : 0x28
            public UInt32 e_lfanew;         // File address of new exe header    : 0x3c
        }
        public const uint IMAGE_DOS_HEADER_SIZE = 0x40;
        #endregion IMAGE_DOS_HEADER
        #region IMAGE_NT_HEADERS32
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct IMAGE_NT_HEADERS32
        {
            public UInt32 Signature; //PE image signature: "PE\0\0" : 0x00
            public IMAGE_FILE_HEADER FileHeader;
            public IMAGE_OPTIONAL_HEADER32 OptionalHeader;
        }
        public const uint IMAGE_NT_HEADERS32_SIZE = 4 + IMAGE_FILE_HEADER_SIZE + IMAGE_OPTIONAL_HEADER32_SIZE;
        #endregion IMAGE_NT_HEADERS32
        #region IMAGE_NT_HEADERS64
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct IMAGE_NT_HEADERS64
        {
            public UInt32 Signature; //PE image signature: "PE\0\0" : 0x00
            public IMAGE_FILE_HEADER FileHeader;
            public IMAGE_OPTIONAL_HEADER64 OptionalHeader;
        }
        public const uint IMAGE_NT_HEADERS64_SIZE = 4 + IMAGE_FILE_HEADER_SIZE + IMAGE_OPTIONAL_HEADER64_SIZE;
        #endregion IMAGE_NT_HEADERS64
        #region IMAGE_FILE_HEADER
        [StructLayout(LayoutKind.Sequential, Pack = 1)]

        public struct IMAGE_FILE_HEADER
        {
            public FileMachine Machine;         // Architecture type of the image.                   : 0x00
            public UInt16 NumberOfSections;     // Number of sections immediately after the headers. : 0x02
            public UInt32 TimeDateStamp;        // Low 32 bits of the time stamp of the image.       : 0x04
            public UInt32 PointerToSymbolTable; // RVA for the symbol table, if it exists.           : 0x08
            public UInt32 NumberOfSymbols;      // Number of symbols in the symbol table.            : 0x0c
            public UInt16 SizeOfOptionalHeader; // Optional Header Size in bytes.                    : 0x10
            public UInt16 Characteristics;      // Characteristics of the image.                     : 0x12
        }
        public const uint IMAGE_FILE_HEADER_SIZE   = 0x14;
        public enum FileMachine : ushort
        {
            IMAGE_FILE_MACHINE_I386  = 0x014C,
            IMAGE_FILE_MACHINE_IA64  = 0x0200,
            IMAGE_FILE_MACHINE_AMD64 = 0x8664
        }
        [Flags]
        public enum IMAGE_FILE : ushort
        {
            RELOCS_STRIPPED         = 0x0001, // Relocation information was stripped from the file.
            EXECUTABLE_IMAGE        = 0x0002, // The file is executable (there are no unresolved external references).
            LINE_NUMS_STRIPPED      = 0x0004, // COFF line numbers were stripped from the file.
            LOCAL_SYMS_STRIPPED     = 0x0008, // COFF symbol table entries were stripped from file.
            AGGRESIVE_WS_TRIM       = 0x0010, // Aggressively trim the working set. This value is obsolete.
            LARGE_ADDRESS_AWARE     = 0x0020, // The application can handle addresses larger than 2 GB.
            BYTES_REVERSED_LO       = 0x0080, // The bytes of the word are reversed. This flag is obsolete.
            _32BIT_MACHINE          = 0x0100, // The computer supports 32-bit words.
            DEBUG_STRIPPED          = 0x0200, // Debugging information was removed and stored separately in another file.
            REMOVABLE_RUN_FROM_SWAP = 0x0400, // If the image is on removable media, copy it to and run it from the swap file.
            NET_RUN_FROM_SWAP       = 0x0800, // If the image is on the network, copy it to and run it from the swap file.
            SYSTEM                  = 0x1000, // The image is a system file.
            DLL                     = 0x2000, // The image is a DLL file. While it is an executable file, it cannot be run directly.
            UP_SYSTEM_ONLY          = 0x4000, // The file should be run only on a uniprocessor computer.
            BYTES_REVERSED_HI       = 0x8000, // The bytes of the word are reversed. This flag is obsolete.
        }
        #endregion IMAGE_FILE_HEADER
        #region IMAGE_OPTIONAL_HEADER32
        public enum OptionalMagic : ushort
        {
            IMAGE_ROM_OPTIONAL_HDR_MAGIC  = 0x107,
            IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10b,
            IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20b
        }
        public enum OptionalSubSystem : ushort
        {
            UNKNOWN                 = 0,
            NATIVE                  = 1,
            WINDOWS_GUI             = 2,
            WINDOWS_CUI             = 3,
            POSIX_CUI               = 7,
            WINDOWS_CE_GUI          = 9,
            EFI_APPLICATION         = 10,
            EFI_BOOT_SERVICE_DRIVER = 11,
            EFI_RUNTIME_DRIVER      = 12,
            EFI_ROM                 = 13,
            XBOX                    = 14
        }
        [Flags]
        public enum OptionalDllCharacteristics : ushort
        {
            RES_0                 = 0x0001,
            RES_1                 = 0x0002,
            RES_2                 = 0x0004,
            RES_3                 = 0x0008,
            DYNAMIC_BASE          = 0x0040, // The DLL can be relocated at load time.
            FORCE_INTEGRITY       = 0x0080, // Code integrity checks are forced.
            NX_COMPAT             = 0x0100, // The image is compatible with data execution prevention (DEP).
            NO_ISOLATION          = 0x0200, // The image is isolation aware, but should not be isolated.
            NO_SEH                = 0x0400, // The image does not use structured exception handling (SEH). No handlers can be called in this image.
            NO_BIND               = 0x0800, // Do not bind the image.
            RES_4                 = 0x1000,
            WDM_DRIVER            = 0x2000, // A WDM Driver
            TERMINAL_SERVER_AWARE = 0x8000  // The image is terminal server aware
        }
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct IMAGE_OPTIONAL_HEADER32
        {
            public OptionalMagic Magic;                           // Header magic                                      : 0x00
            public byte MajorLinkerVersion;                       // Major version number of the linker.               : 0x02
            public byte MinorLinkerVersion;                       // Minor version number of the linker.               : 0x03
            public UInt32 SizeOfCode;                             // Size of the code section, in bytes.               : 0x04
            public UInt32 SizeOfInitializedData;                  // Size of the initialized data section, in bytes.   : 0x08
            public UInt32 SizeOfUninitializedData;                // Size of the uninitialized data section, in bytes. : 0x0c
            public UInt32 AddressOfEntryPoint;                    // RVA of the entry point function.                  : 0x10
            public UInt32 BaseOfCode;                             // RVA to the base of the code section.              : 0x14
            public UInt32 BaseOfData;                             // RVA to the base of the data section.              : 0x18
            public UInt32 ImageBase;                              // Default base address of the image.                : 0x1c
            public UInt32 SectionAlignment;                       // Alignment of sections loaded in memory, in bytes. : 0x20
            public UInt32 FileAlignment;                          // Alignment of raw sections in the image, in bytes. : 0x24
            public UInt16 MajorOperatingSystemVersion;            // Required operating system major version number.   : 0x28
            public UInt16 MinorOperatingSystemVersion;            // Required operating system minor version number.   : 0x2a
            public UInt16 MajorImageVersion;                      // Image major version.                              : 0x2c
            public UInt16 MinorImageVersion;                      // Image minor version.                              : 0x2e
            public UInt16 MajorSubsystemVersion;                  // Subsystem major version.                          : 0x30
            public UInt16 MinorSubsystemVersion;                  // Subsystem minor version.                          : 0x32
            public UInt32 Win32VersionValue;                      // This member is reserved and must be 0.            : 0x34
            public UInt32 SizeOfImage;                            // The size of the image, including all headers.     : 0x38
            public UInt32 SizeOfHeaders;                          // The combined size of the following items, rounded : 0x3C
                                                                  //   to a multiple of the value specified in the     :
                                                                  //   FileAlignment member.                           :
                                                                  //      - e_lfanew member of IMAGE_DOS_HEADER        :
                                                                  //      - 4 byte signature                           :
                                                                  //      - size of IMAGE_FILE_HEADER                  :
                                                                  //      - size of optional header                    :
                                                                  //      - size of all section headers                :
            public UInt32 CheckSum;                               // Image file checksum.                              : 0x40
            public OptionalSubSystem Subsystem;                   // Subsystem required to run this image.             : 0x44
            public OptionalDllCharacteristics DllCharacteristics; // The DLL characteristics of the image.             : 0x46
            public UInt32 SizeOfStackReserve;                     // The number of bytes to reserve for the stack.     : 0x48
            public UInt32 SizeOfStackCommit;                      // The number of bytes to commit for the stack.      : 0x4c
            public UInt32 SizeOfHeapReserve;                      // The number of bytes to reserve for the local heap : 0x50
            public UInt32 SizeOfHeapCommit;                       // The number of bytes to commit for the local heap. : 0x54
            public UInt32 LoaderFlags;                            // This member is obsolete.                          : 0x58
            public UInt32 NumberOfRvaAndSizes;                    // The number of directory entries.                  : 0x5c
            public IMAGE_DATA_DIRECTORY ExportTable;
            public IMAGE_DATA_DIRECTORY ImportTable;
            public IMAGE_DATA_DIRECTORY ResourceTable;
            public IMAGE_DATA_DIRECTORY ExceptionTable;
            public IMAGE_DATA_DIRECTORY CertificateTable;
            public IMAGE_DATA_DIRECTORY BaseRelocationTable;
            public IMAGE_DATA_DIRECTORY Debug;
            public IMAGE_DATA_DIRECTORY Architecture;
            public IMAGE_DATA_DIRECTORY GlobalPtr;
            public IMAGE_DATA_DIRECTORY TLSTable;
            public IMAGE_DATA_DIRECTORY LoadConfigTable;
            public IMAGE_DATA_DIRECTORY BoundImport;
            public IMAGE_DATA_DIRECTORY IAT;
            public IMAGE_DATA_DIRECTORY DelayImportDescriptor;
            public IMAGE_DATA_DIRECTORY CLRRuntimeHeader;
            public IMAGE_DATA_DIRECTORY Reserved;
        }
        public const uint IMAGE_OPTIONAL_HEADER32_SIZE = 0x60 + (IMAGE_DATA_DIRECTORY_SIZE * 16);
        #endregion IMAGE_OPTIONAL_HEADER32
        #region IMAGE_OPTIONAL_HEADER64
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct IMAGE_OPTIONAL_HEADER64
        {
            public OptionalMagic Magic;                           // Header magic                                      : 0x00
            public byte MajorLinkerVersion;                       // Major version number of the linker.               : 0x02
            public byte MinorLinkerVersion;                       // Minor version number of the linker.               : 0x03
            public UInt32 SizeOfCode;                             // Size of the code section, in bytes.               : 0x04
            public UInt32 SizeOfInitializedData;                  // Size of the initialized data section, in bytes.   : 0x08
            public UInt32 SizeOfUninitializedData;                // Size of the uninitialized data section, in bytes. : 0x0c
            public UInt32 AddressOfEntryPoint;                    // RVA of the entry point function.                  : 0x10
            public UInt32 BaseOfCode;                             // RVA to the base of the code section.              : 0x14
            public UInt64 ImageBase;                              // Default base address of the image.                : 0x18
            public UInt32 SectionAlignment;                       // Alignment of sections loaded in memory, in bytes. : 0x20
            public UInt32 FileAlignment;                          // Alignment of raw sections in the image, in bytes. : 0x24
            public UInt16 MajorOperatingSystemVersion;            // Required operating system major version number.   : 0x28
            public UInt16 MinorOperatingSystemVersion;            // Required operating system minor version number.   : 0x2a
            public UInt16 MajorImageVersion;                      // Image major version.                              : 0x2c
            public UInt16 MinorImageVersion;                      // Image minor version.                              : 0x2e
            public UInt16 MajorSubsystemVersion;                  // Subsystem major version.                          : 0x30
            public UInt16 MinorSubsystemVersion;                  // Subsystem minor version.                          : 0x32
            public UInt32 Win32VersionValue;                      // This member is reserved and must be 0.            : 0x34
            public UInt32 SizeOfImage;                            // The size of the image, including all headers.     : 0x38
            public UInt32 SizeOfHeaders;                          // The combined size of the following items, rounded : 0x3C
                                                                  //   to a multiple of the value specified in the     :
                                                                  //   FileAlignment member.                           :
                                                                  //      - e_lfanew member of IMAGE_DOS_HEADER        :
                                                                  //      - 4 byte signature                           :
                                                                  //      - size of IMAGE_FILE_HEADER                  :
                                                                  //      - size of optional header                    :
                                                                  //      - size of all section headers                :
            public UInt32 CheckSum;                               // Image file checksum.                              : 0x40
            public OptionalSubSystem Subsystem;                   // Subsystem required to run this image.             : 0x44
            public OptionalDllCharacteristics DllCharacteristics; // The DLL characteristics of the image.             : 0x46
            public UInt64 SizeOfStackReserve;                     // The number of bytes to reserve for the stack.     : 0x48
            public UInt64 SizeOfStackCommit;                      // The number of bytes to commit for the stack.      : 0x50
            public UInt64 SizeOfHeapReserve;                      // The number of bytes to reserve for the local heap : 0x58
            public UInt64 SizeOfHeapCommit;                       // The number of bytes to commit for the local heap. : 0x60
            public UInt32 LoaderFlags;                            // This member is obsolete.                          : 0x68
            public UInt32 NumberOfRvaAndSizes;                    // The number of directory entries.                  : 0x6c
            public IMAGE_DATA_DIRECTORY ExportTable;
            public IMAGE_DATA_DIRECTORY ImportTable;
            public IMAGE_DATA_DIRECTORY ResourceTable;
            public IMAGE_DATA_DIRECTORY ExceptionTable;
            public IMAGE_DATA_DIRECTORY CertificateTable;
            public IMAGE_DATA_DIRECTORY BaseRelocationTable;
            public IMAGE_DATA_DIRECTORY Debug;
            public IMAGE_DATA_DIRECTORY Architecture;
            public IMAGE_DATA_DIRECTORY GlobalPtr;
            public IMAGE_DATA_DIRECTORY TLSTable;
            public IMAGE_DATA_DIRECTORY LoadConfigTable;
            public IMAGE_DATA_DIRECTORY BoundImport;
            public IMAGE_DATA_DIRECTORY IAT;
            public IMAGE_DATA_DIRECTORY DelayImportDescriptor;
            public IMAGE_DATA_DIRECTORY CLRRuntimeHeader;
            public IMAGE_DATA_DIRECTORY Reserved;
        }
        public const uint IMAGE_OPTIONAL_HEADER64_SIZE = 0x70 + (IMAGE_DATA_DIRECTORY_SIZE * 16);
        #endregion IMAGE_OPTIONAL_HEADER64
        #region IMAGE_DATA_DIRECTORY
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct IMAGE_DATA_DIRECTORY
        {
            public UInt32 VirtualAddress;
            public UInt32 Size;
        }
        public const uint IMAGE_DATA_DIRECTORY_SIZE = 0x08;
        #endregion IMAGE_DATA_DIRECTORY
    }

    public class PortableExecutable
    {
        private UnmanagedHelper helper;
        public PortableExecutable(IntPtr process_handle)
        {
            bool is32Bit = WinAPI.Is32BitProcess(process_handle);
            Process proc = Process.GetProcessById(WinAPI.GetProcessId(process_handle));
            if (proc == null)
            {
                throw new ArgumentException("Could not load PE infor for process, Process could not be found");
            }

            helper = new UnmanagedHelper(0x100);
            byte[] dos_data = WinAPI.ReadProcessMemory(process_handle, proc.MainModule.BaseAddress, PE.IMAGE_DOS_HEADER_SIZE);
            var dos = default(PE.IMAGE_DOS_HEADER);

            helper.Write(dos_data);
            helper.Read(out dos);
            Console.WriteLine(dos.DebugString());

            IntPtr nt_addr = new IntPtr(proc.MainModule.BaseAddress.ToInt64() + dos.e_lfanew);
            byte[] nt_header = WinAPI.ReadProcessMemory(process_handle, nt_addr, (is32Bit ? PE.IMAGE_NT_HEADERS32_SIZE : PE.IMAGE_NT_HEADERS64_SIZE));
            helper.Write(nt_header);
            if (is32Bit)
            {
                var nt = default(PE.IMAGE_NT_HEADERS32);
                helper.Read(out nt);
                Console.WriteLine(nt.DebugString());
            }
            else
            {
                var nt = default(PE.IMAGE_NT_HEADERS64);
                helper.Read(out nt);
                Console.WriteLine(nt.DebugString());
            }
        }
    }
}
