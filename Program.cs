﻿using System;
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
		
        private static int processHandle;
		
		private int ModuleMemorySize { get; set;}

		public static void Main()
		{
			Application.EnableVisualStyles();
			
			Process[] processList = Process.GetProcessesByName("GameApp_PcDx11_x64Final");
			
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
				
				WriteProcessMemory(processHandle, 0x140C0AC80, new byte[] {0x00, 0x00, 0x00, 0x00}, 4, 0);
				WriteProcessMemory(processHandle, 0x145B2A1FD, new byte[] {0xE9, 0x19, 0x29, 0x00, 0x00, 0x90}, 6, 0);
				WriteProcessMemory(processHandle, 0x145B2CB1B, new byte[] {0xC7, 0x80, 0x04, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xE9, 0xD9, 0xD6, 0xFF, 0xFF}, 15, 0);
			}
			
			 if (processList.Length > 0)
            {
                MessageBox.Show(
                    "In exhibition races you are now\n" +
                    "free from AI players!!!\n\n" +
                    "To restore the default behaviour,\n" +
					"just restart the game.\n\n" +
                    "Enjoy! :)", "TSR NO AI", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            else
            {
                MessageBox.Show("Please start the game first!", "TSR NO AI", MessageBoxButtons.OK, MessageBoxIcon.Error);
                Environment.Exit(0);
            }
        }
	 
    }
}