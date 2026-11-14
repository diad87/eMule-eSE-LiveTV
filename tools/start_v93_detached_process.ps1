function Start-V93DetachedProcess {
    param(
        [Parameter(Mandatory=$true)][string]$FilePath,
        [Parameter(Mandatory=$true)][string]$WorkingDirectory,
        [Parameter(Mandatory=$true)][string[]]$ArgumentList
    )
    if (!('EseV93.DetachedProcess' -as [type])) {
        Add-Type -ErrorAction Stop -TypeDefinition @'
using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using Microsoft.Win32.SafeHandles;

namespace EseV93
{
    public sealed class DetachedProcess : IDisposable
    {
        private const uint DesktopReadObjects = 0x0001;
        private const uint DesktopCreateWindow = 0x0002;
        private const uint DesktopCreateMenu = 0x0004;
        private const int UserObjectName = 2;
        private const uint CreateNoWindow = 0x08000000;
        private const uint StartfUseShowWindow = 0x00000001;
        private const ushort SwHide = 0;

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct StartupInfo
        {
            public int Size;
            public string Reserved, Desktop, Title;
            public uint X, Y, XSize, YSize, XCountChars, YCountChars, FillAttribute, Flags;
            public ushort ShowWindow, ReservedCount;
            public IntPtr ReservedBytes, StdInput, StdOutput, StdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct ProcessInfo
        {
            public IntPtr Process, Thread;
            public int ProcessId, ThreadId;
        }

        private sealed class DesktopHandle : SafeHandleZeroOrMinusOneIsInvalid
        {
            public DesktopHandle() : base(true) { }
            protected override bool ReleaseHandle() { return CloseDesktop(handle); }
        }

        [DllImport("user32.dll")]
        private static extern IntPtr GetProcessWindowStation();

        [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool GetUserObjectInformationW(IntPtr handle, int index, StringBuilder name, int size, out int needed);

        [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern DesktopHandle CreateDesktopW(string name, IntPtr device, IntPtr devMode, uint flags, uint access, IntPtr security);

        [DllImport("user32.dll", SetLastError = true)]
        private static extern bool CloseDesktop(IntPtr desktop);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool CreateProcessW(string executable, StringBuilder cmd, IntPtr processSecurity,
            IntPtr threadSecurity, bool inheritHandles, uint flags, IntPtr environment, string cwd,
            ref StartupInfo startup, out ProcessInfo result);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetExitCodeProcess(SafeWaitHandle process, out int code);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool TerminateProcess(SafeWaitHandle process, int code);

        [DllImport("kernel32.dll")]
        private static extern bool CloseHandle(IntPtr handle);

        private readonly DesktopHandle desktop;
        private readonly ManualResetEvent process;

        public int Id { get; private set; }
        public string Desktop { get; private set; }
        public bool HasExited { get { return WaitForExit(0); } }

        public int ExitCode
        {
            get
            {
                if (!HasExited) throw new InvalidOperationException("Process has not exited.");
                int code;
                if (!GetExitCodeProcess(process.SafeWaitHandle, out code)) throw Error("GetExitCodeProcess");
                return code;
            }
        }

        public bool WaitForExit(int milliseconds) { return process.WaitOne(milliseconds); }

        public void StopIncompleteLaunch()
        {
            if (!HasExited && !TerminateProcess(process.SafeWaitHandle, 2) && !HasExited)
                throw Error("TerminateProcess after incomplete pair launch");
        }

        public void Dispose()
        {
            process.Dispose();
            desktop.Dispose();
        }

        private DetachedProcess(int id, string desktopName, DesktopHandle desktopHandle, ManualResetEvent processHandle)
        {
            Id = id;
            Desktop = desktopName;
            desktop = desktopHandle;
            process = processHandle;
        }

        private static Win32Exception Error(string operation)
        {
            int code = Marshal.GetLastWin32Error();
            return new Win32Exception(code, operation + ": " + new Win32Exception(code).Message);
        }

        // CreateProcess receives one mutable command line. Preserve the argv
        // boundaries, including empty arguments, quotes and trailing slashes.
        private static string Quote(string value)
        {
            if (value == null || value.IndexOf('\0') >= 0) throw new ArgumentException("Invalid process argument.");
            var quoted = new StringBuilder().Append('"');
            int slashes = 0;
            foreach (char c in value)
            {
                if (c == '\\') { ++slashes; continue; }
                quoted.Append('\\', c == '"' ? 2 * slashes + 1 : slashes).Append(c);
                slashes = 0;
            }
            return quoted.Append('\\', 2 * slashes).Append('"').ToString();
        }

        public static DetachedProcess Start(string filePath, string directory, string[] arguments)
        {
            filePath = Path.GetFullPath(filePath);
            directory = Path.GetFullPath(directory);
            var command = new StringBuilder(Quote(filePath));
            foreach (string argument in arguments) command.Append(' ').Append(Quote(argument));

            var station = new StringBuilder(256);
            int needed;
            if (!GetUserObjectInformationW(GetProcessWindowStation(), UserObjectName, station, station.Capacity * 2, out needed))
                throw Error("GetUserObjectInformationW");

            string name = "eSEv93-" + Guid.NewGuid().ToString("N");
            string qualifiedName = station.ToString() + "\\" + name;
            var startup = new StartupInfo {
                Size = Marshal.SizeOf(typeof(StartupInfo)), Desktop = qualifiedName,
                Flags = StartfUseShowWindow, ShowWindow = SwHide
            };
            var desktop = CreateDesktopW(name, IntPtr.Zero, IntPtr.Zero, 0,
                DesktopReadObjects | DesktopCreateWindow | DesktopCreateMenu, IntPtr.Zero);
            if (desktop.IsInvalid) throw Error("CreateDesktopW");

            ManualResetEvent wait = null;
            try
            {
                wait = new ManualResetEvent(false);
                ProcessInfo info;
                if (!CreateProcessW(filePath, command, IntPtr.Zero, IntPtr.Zero, false, CreateNoWindow,
                    IntPtr.Zero, directory, ref startup, out info)) throw Error("CreateProcessW on private desktop");
                CloseHandle(info.Thread);
                wait.SafeWaitHandle = new SafeWaitHandle(info.Process, true);
                return new DetachedProcess(info.ProcessId, qualifiedName, desktop, wait);
            }
            catch
            {
                if (wait != null) wait.Dispose();
                desktop.Dispose();
                throw;
            }
        }
    }
}
'@
    }
    [EseV93.DetachedProcess]::Start($FilePath,$WorkingDirectory,$ArgumentList)
}
