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
using System.Reflection;
using System.Threading.Tasks;
using System.Runtime.InteropServices;

namespace Injector
{
    public class UnmanagedHelper : IDisposable
    {
        private int _size = 0;
        public IntPtr Pointer { get; private set; }
        public int ReadOffset { get; set; }
        public int WriteOffset { get; set; }
        public int Size
        {
            get
            {
                return _size;
            }
            set
            {
                Allocate(value);
            }
        }
        public UnmanagedHelper() : this(0) { }
        public UnmanagedHelper(int baseSize)
        {
            Pointer = IntPtr.Zero;
            Size = baseSize;
            ReadOffset = 0;
            WriteOffset = 0;
        }

        public bool Allocate(int newSize, bool fast = false)
        {
            if (newSize < 0)
            {
                throw new ArgumentException("UnmanagedHelper.Allocate called with invalid new size, size must be greater then zero", "newSize");
            }

            if (newSize == Size)
            {
                return true;
            }
            else if (newSize == 0)
            {
                if (Pointer != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(Pointer);
                    Pointer = IntPtr.Zero;
                }
            }
            else if (newSize > Size)
            {
                if (Pointer != IntPtr.Zero)
                {
                    if (fast)
                    {
                        Marshal.FreeHGlobal(Pointer);
                        Pointer = Marshal.AllocHGlobal(newSize);
                    }
                    else
                    {
                        Pointer = Marshal.ReAllocHGlobal(Pointer, new IntPtr(newSize));
                    }
                }
                else
                {
                    Pointer = Marshal.AllocHGlobal(newSize);
                }
            }
            else
            {
                Pointer = Marshal.ReAllocHGlobal(Pointer, new IntPtr(newSize));
            }
            _size = (Pointer == IntPtr.Zero ? 0 : newSize);
            return (Pointer == IntPtr.Zero) == (newSize == 0);
        }

        public byte[] Read(int count)
        {
            byte[] data = Read(count, ReadOffset);
            ReadOffset += count;
            return data;
        }

        public byte[] Read(int count, int offset)
        {
            if (count <= 0 || count > Size - offset)
            {
                throw new ArgumentException(String.Format("UnmanagedHelper.Read, Attempted to read an invalid number of bytes '{0}', '{1}'", count, Size - offset));
            }

            byte[] data = new byte[count];
            Marshal.Copy(Pointer, data, offset, count);
            return data;
        }

        public bool Write(byte[] data)
        {
            return Write(data, 0, data.Length);
        }

        public bool Write(byte[] data, int start, int length)
        {
            if (Write(data, start, length, WriteOffset))
            {
                WriteOffset += length;
                return true;
            }
            return false;
        }

        public bool Write(byte[] data, int start, int length, int offset)
        {
            if (offset + length > Size)
            {
                if (!Allocate(offset + length))
                {
                    return false;
                }
            }

            Marshal.Copy(data, start, Pointer + offset, length);
            return true;
        }

        public bool Read<T>(out T dest) where T : struct
        {
            if (Read(out dest, ReadOffset))
            {
                ReadOffset += Marshal.SizeOf(typeof(T));
                return true;
            }
            return false;
        }

        public bool Read<T>(out T dest, int offset) where T : struct
        {
            dest = default(T);
            if (Size >= offset + Marshal.SizeOf(typeof(T)))
            {
                dest = (T)Marshal.PtrToStructure(Pointer + offset, typeof(T));
                return true;
            }
            return false;
        }

        public bool Write<T>(T data) where T : struct
        {
            if (Write(data, WriteOffset))
            {
                WriteOffset += Marshal.SizeOf(typeof(T));
                return true;
            }
            return false;
        }

        public bool Write<T>(T data, int offset, bool fDeleteOld = false) where T : struct
        {
            int length = Marshal.SizeOf(typeof(T));
            if (Size < offset + length)
            {
                if (!Allocate(offset + length, fast:false))
                {
                    return false;
                }
            }
            Marshal.StructureToPtr(data, Pointer + offset, fDeleteOld);
            return true;
        }

        public virtual byte[] ToByteArray()
        {
            byte[] data = new byte[Size];
            Marshal.Copy(Pointer, data, 0, Size);
            return data;
        }

        public void ResetOffsets()
        {
            ReadOffset = 0;
            WriteOffset = 0;
        }

        public String DebugOutput()
        {
            return UnmanagedHelper.DebugOutput(ToByteArray(), ReadOffset);
        }

        public void Dispose()
        {
            Allocate(0); //Free up everything
        }

        public static String DebugOutput(Byte[] data, int Position = 0)
        {
            StringBuilder builder = new StringBuilder();
            StringBuilder ascii = new StringBuilder(16, 16);
            UInt32 x = 0;

            for (x = 0; x < data.Length; x++)
            {
                if (x % 16 == 0)
                    builder.AppendFormat("{0:x4} {1}", x, (x == Position ? "<" : " "));

                if ((x + 1 == Position) && (x + 1 != data.Length) && ((x + 1) % 16 != 0))
                    builder.AppendFormat("{0:x2}<", data[x]);
                else
                    builder.AppendFormat("{0:x2}{1}", data[x], (x == Position ? ">" : " "));

                if (Char.IsLetterOrDigit((Char)data[x]) || Char.IsPunctuation((Char)data[x]) ||
                    Char.IsSymbol((Char)data[x]) || Char.IsSeparator((Char)data[x]) || data[x] == ' ')
                {
                    ascii.Append((Char)data[x]);
                }
                else
                {
                    ascii.Append(".");
                }

                if (((x + 1) % 16 == 0) && ((x + 1) != data.Length))
                {
                    builder.AppendFormat(" {0}{1}", ascii.ToString(), Environment.NewLine);
                    ascii = new StringBuilder(16, 16);
                }
            }
            while (x % 16 != 0)
            {
                builder.Append("   ");
                x++;
            }
            builder.AppendFormat(" {0}{1}", ascii.ToString(), Environment.NewLine);
            builder.AppendFormat("Length:   0x{0:x4} ({0}) ", data.Length);
            builder.AppendFormat("Position: 0x{0:x4} ({0})", Position);

            return builder.ToString();
        }
    }
}
