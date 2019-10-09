using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Windows.Forms;

namespace TsrNoAi
{
    public class Program
    {
		[DllImport("kernel32")]
		private static extern int OpenProcess(int dwDesiredAccess, int bInheritHandle, int dwProcessId);
		 
		[DllImport("kernel32")]
		private static extern bool WriteProcessMemory(int hProcess, Int64 lpBaseAddress, byte[] lpbuffer, int nSize, int lpNumberOfBytesWritten);
		
		[DllImport("kernel32.dll")]
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
				
				if (process.MainModule.ModuleMemorySize != 367644672)
				{
					MessageBox.Show("Cannot apply patch. Please ensure you are\n" +
									"running the correct version of the game!", "TSR NO AI", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    Environment.Exit(2);
                }
	
				byte[] status = new byte[6];
				int bytesRead = 0;
				ReadProcessMemory(processHandle, 0x145B2A1FD, status, status.Length, bytesRead);

				if (BitConverter.ToString(status, 0) == "89-88-04-02-00-00")
				{
					// Code gets applied if the application determines the game is unpatched
					byte[] buffer = new byte[8];
					ReadProcessMemory(processHandle, 0x14102DE40, buffer, buffer.Length, bytesRead);
					Int64 baseValue = BitConverter.ToInt64(buffer, 0);
					baseValue = baseValue + 0x340;
					buffer = new byte[8];
					ReadProcessMemory(processHandle, baseValue, buffer, 4, bytesRead);
					baseValue = BitConverter.ToInt64(buffer, 0);
					
					if (baseValue == 2) {
						WriteProcessMemory(processHandle, 0x140C0AC80, new byte[] {0x00, 0x00, 0x00, 0x00}, 4, 0);
					}
					WriteProcessMemory(processHandle, 0x145B2A1FD, new byte[] {0xE8, 0x19, 0x29, 0x00, 0x00, 0x90}, 6, 0);
					WriteProcessMemory(processHandle, 0x145B2CB1B, new byte[] {0x48, 0x8B, 0x1D, 0x1E, 0x13, 0x50, 0xFB, 0x83, 0xBB, 0x40, 0x03, 0x00, 0x00, 0x02, 0x89, 0x88, 0x04, 0x02, 0x00, 0x00, 0x75, 0x0A, 0xC7, 0x80, 0x04, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC3}, 33, 0);
					
					MessageBox.Show(
					"In exhibition races (standard race) you are now\n" +
					"free from AI players!!!\n\n" +
					"To restore the default behaviour, either restart the game\nor launch this tool again!\n\n" +
					"Note: this tool does not apply to team races!\n\n"+
					"Enjoy! :)", "TSR NO AI", MessageBoxButtons.OK, MessageBoxIcon.Information);
				}
				else
				{
					// Unpatching the game is the no AI patch was already applied
					WriteProcessMemory(processHandle, 0x140C0AC80, new byte[] {0xFF, 0xFF, 0xFF, 0xFF}, 4, 0);
					WriteProcessMemory(processHandle, 0x145B2A1FD, new byte[] {0x89, 0x88, 0x04, 0x02, 0x00, 0x00}, 6, 0);
					
					byte[] buffer = new byte[33];
					for (int index = 0; index < buffer.Length; ++index)
					{
						buffer[index] = 0x00;
					}
					WriteProcessMemory(processHandle, 0x145B2CB1B, buffer, 33, 0);
					
					MessageBox.Show(
					"TSR NO AI patch has been removed!\n" +
					"Enjoy your stock experience!", "TSR NO AI", MessageBoxButtons.OK, MessageBoxIcon.Information);
				}
			}
        }
    }
}