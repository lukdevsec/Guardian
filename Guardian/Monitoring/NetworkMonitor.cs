
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Net;
using System.Runtime.InteropServices;

namespace Guardian.Monitoring;

public sealed record TcpConnectionInfo(
    int ProcessId,
    string LocalAddress,
    int LocalPort,
    string RemoteAddress,
    int RemotePort,
    uint State);

public static class NetworkMonitor
{
    private const int AddressFamilyIpv4 = 2;
    private const uint ErrorInsufficientBuffer = 122;

    private enum TcpTableClass
    {
        TcpTableBasicListener = 0,
        TcpTableBasicConnections = 1,
        TcpTableBasicAll = 2,
        TcpTableOwnerPidListener = 3,
        TcpTableOwnerPidConnections = 4,
        TcpTableOwnerPidAll = 5
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MibTcpRowOwnerPid
    {
        public uint State;
        public uint LocalAddr;
        public uint LocalPort;
        public uint RemoteAddr;
        public uint RemotePort;
        public uint OwningPid;
    }

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(
        IntPtr table,
        ref int size,
        [MarshalAs(UnmanagedType.Bool)] bool order,
        int addressFamily,
        TcpTableClass tableClass,
        uint reserved);

    public static IReadOnlyList<TcpConnectionInfo> GetConnections()
    {
        int size = 0;

        uint result = GetExtendedTcpTable(
            IntPtr.Zero,
            ref size,
            true,
            AddressFamilyIpv4,
            TcpTableClass.TcpTableOwnerPidConnections,
            0);

        if (result != ErrorInsufficientBuffer && result != 0)
            throw new Win32Exception((int)result);

        if (size < sizeof(int))
            return Array.Empty<TcpConnectionInfo>();

        IntPtr buffer = Marshal.AllocHGlobal(size);

        try
        {
            result = GetExtendedTcpTable(
                buffer,
                ref size,
                true,
                AddressFamilyIpv4,
                TcpTableClass.TcpTableOwnerPidConnections,
                0);

            if (result != 0)
                throw new Win32Exception((int)result);

            int count = Marshal.ReadInt32(buffer);

            int rowSize = Marshal.SizeOf<MibTcpRowOwnerPid>();

            int maxRows = (size - sizeof(int)) / rowSize;

            if (count < 0 || count > maxRows)
                throw new InvalidOperationException(
                    "Invalid TCP table returned by Windows.");

            var connections = new List<TcpConnectionInfo>(count);

            for (int i = 0; i < count; i++)
            {
                IntPtr rowAddress = IntPtr.Add(
                    buffer,
                    sizeof(int) + i * rowSize);

                var row =
                    Marshal.PtrToStructure<MibTcpRowOwnerPid>(
                        rowAddress);

                // 5 = ESTABLISHED
                if (row.State != 5)
                    continue;

                connections.Add(new TcpConnectionInfo(
                    checked((int)row.OwningPid),
                    ConvertAddress(row.LocalAddr),
                    ConvertPort(row.LocalPort),
                    ConvertAddress(row.RemoteAddr),
                    ConvertPort(row.RemotePort),
                    row.State));
            }

            return connections;
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static string ConvertAddress(uint value)
    {
        return new IPAddress(
            BitConverter.GetBytes(value)).ToString();
    }

    private static int ConvertPort(uint value)
    {
        byte[] bytes = BitConverter.GetBytes(value);

        return (bytes[0] << 8) | bytes[1];
    }
}
