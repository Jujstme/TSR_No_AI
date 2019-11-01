using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Windows.Forms;

namespace TsrNoAI
{
    public class Program
    {
        [DllImport("kernel32")]
        private static extern int OpenProcess(int dwDesiredAccess, int bInheritHandle, int dwProcessId);

        [DllImport("kernel32")]
        private static extern bool WriteProcessMemory(int hProcess, Int64 lpBaseAddress, byte[] lpbuffer, int nSize, int lpNumberOfBytesWritten);

        [DllImport("kernel32")]
        private static extern bool ReadProcessMemory(int hProcess, Int64 lpBaseAddress, byte[] lpBuffer, int nSize, int lpNumberOfBytesRead);

        private static int processHandle;

        public static void Main()
        {
            Application.EnableVisualStyles();

            Process[] processList = Process.GetProcessesByName("GameApp_PcDx11_x64Final");

            if (processList.Length == 0)
            {
                MessageBox.Show("Please start the game first!", "TSR NO AI", MessageBoxButtons.OK, MessageBoxIcon.Error);
                Environment.Exit(0);
            }

            foreach (Process process in processList)
            {
                processHandle = OpenProcess(0x38, 0, process.Id);

                if (processHandle == 0)
                {
                    MessageBox.Show("Could not access the game, please run as administrator!", "TSR NO AI", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    Environment.Exit(2);
                }

                if (process.MainModule.ModuleMemorySize != 0x15E9D000)
                {
                    MessageBox.Show("Cannot apply patch. Please ensure you are\n" +
                                    "running the correct version of the game!", "TSR NO AI", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    Environment.Exit(2);
                }

                byte[] status = new byte[1];
                ReadProcessMemory(processHandle, 0x14027F88C, status, 1, 0);

                if (status[0] != 0xE9)
                {
                    // Code gets applied if the application determines the game is unpatched
                    byte[] injectedcode = new byte[] { 0x83, 0x3D, 0x61, 0x67, 0xEB, 0x00, 0x01, 0x75, 0x17, 0x53, 0x48, 0x8B, 0x1D, 0x9B, 0x21, 0xEC, 0x00, 0x8A, 0x9B, 0x60, 0x56,
                        0x00, 0x00, 0x84, 0xDB, 0x5B, 0x75, 0x04, 0x31, 0xC0, 0xEB, 0x06, 0x8B, 0x81, 0x04, 0x02, 0x00, 0x00, 0xE9, 0x63, 0x01, 0x00, 0x00 };
                    WriteProcessMemory(processHandle, 0x14027F704, injectedcode, injectedcode.Length, 0);
                    byte[] injectedcodecall = new byte[] { 0xE9, 0x73, 0xFE, 0xFF, 0xFF, 0x90 };
                    WriteProcessMemory(processHandle, 0x14027F88C, injectedcodecall, injectedcodecall.Length, 0);
                    MessageBox.Show(
                    "In exhibition races (standard race) you are now\n" +
                    "free from AI players!!!\n\n" +
                    "To restore the default behaviour, either restart the game\nor launch this tool again!\n\n" +
                    "Note: this tool does not apply to team races!\n\n" +
                    "Enjoy! :)", "TSR NO AI", MessageBoxButtons.OK, MessageBoxIcon.Information);

                }
                else
                {
                    // Unpatching the game if the no patch was already applied, but ask for confirmation first
                    if (MessageBox.Show("It appears your game is already patched\n" +
                                       "Do you want to remove the patch and restore stock settings?", "TSR NO AI", MessageBoxButtons.YesNo, MessageBoxIcon.Question) == DialogResult.No)
                    {
                        Environment.Exit(0);
                    }

                    WriteProcessMemory(processHandle, 0x14027F88C, new byte[] { 0x8B, 0x81, 0x04, 0x02, 0x00, 0x00 }, 6, 0);

                    byte[] buffer = new byte[43];
                    for (int index = 0; index < buffer.Length; ++index) buffer[index] = 0xCC;
                    WriteProcessMemory(processHandle, 0x14027F704, buffer, buffer.Length, 0);

                    MessageBox.Show(
                    "The patch has been removed!\n" +
                    "Enjoy your stock experience!", "TSR NO AI", MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
            }
        }
    }
}