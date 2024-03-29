﻿using System;
using System.Diagnostics;
using System.Linq;
using System.Windows.Forms;
using ComponentUtil;

namespace TsrNoAI
{
    class Program
    {
        static void Main()
        {
            if (Process.GetProcessesByName(Process.GetCurrentProcess().ProcessName).Length > 1) return;
            var game = new GameManager();
            Application.EnableVisualStyles();
            game.MainScript();
        }
    }

    class GameManager
    {
        private Process game;
        private SignatureScanner scanner;
        private IntPtr InjectionAddress;
        private bool IsAlreadyPatched = false;

        public void MainScript()
        {
            if (!HookGameProcess())
            {
                MessageBox.Show("Please start the game first!", "TSR NO AI", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }

            switch (IsAlreadyPatched)
            {
                case false:
                    Patch();
                    MessageBox.Show("In exhibition races (standard race) you are now\n" +
                                    "free from AI players!!!\n\n" +
                                    "To restore the default behaviour, either restart the game\nor launch this tool again!\n\n" +
                                    "Note: this tool does not apply to team races!\n\n" +
                                    "Enjoy! :)", "TSR NO AI", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    break;
                case true:
                    // Unpatching the game if the no patch was already applied, but ask for confirmation first
                    if (MessageBox.Show("It appears your game is already patched\n" +
                                        "Do you want to remove the patch and restore stock settings?", "TSR NO AI", MessageBoxButtons.YesNo, MessageBoxIcon.Question) == DialogResult.No) break;
                    Unpatch();
                    MessageBox.Show("The patch has been removed!\n" +
                                    "Enjoy your stock experience!", "TSR NO AI", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    break;
            }
        }

        private bool HookGameProcess()
        {
            game = Process.GetProcessesByName("GameApp_PcDx11_x64Final").FirstOrDefault(x => !x.HasExited);
            switch (game)
            {
                case null:
                    return false;
                default:
                    scanner = new SignatureScanner(game, game.MainModuleWow64Safe().BaseAddress, game.MainModuleWow64Safe().ModuleMemorySize);
                    InjectionAddress = scanner.Scan(new SigScanTarget(7, "48 8B 0D ???????? 8B 81 ???????? 89 05 ???????? 8B 81 ???????? 89 05 ???????? 8B 81 ???????? 89 05 ???????? 4C 8D 4D B0"));
                    if (InjectionAddress == IntPtr.Zero)
                    {
                        IsAlreadyPatched = true;
                        InjectionAddress = scanner.Scan(new SigScanTarget(7, "48 8B 0D ???????? E9 ???????? 90 89 05 ???????? 8B 81 ???????? 89 05 ???????? 8B 81 ???????? 89 05 ???????? 4C 8D 4D B0"));
                    }
                    return true;
            }   
        }

        private void Patch()
        {
            byte[] injectedcode = new byte[] { 0x83, 0x3D, 0x00, 0x00, 0x00, 0x00, 0x01, 0x75, 0x17, 0x53, 0x48, 0x8B, 0x1D, 0x00, 0x00, 0x00, 0x00, 0x8A, 0x9B, 0x60, 0x56, 0x00,
                    0x00, 0x84, 0xDB, 0x5B, 0x75, 0x04, 0x31, 0xC0, 0xEB, 0x06, 0x8B, 0x81, 0x04, 0x02, 0x00, 0x00, 0xE9, 0x63, 0x01, 0x00, 0x00 };
            byte[] injectedcodecall = new byte[] { 0xE9, 0x73, 0xFE, 0xFF, 0xFF, 0x90 };

            // Game Mode pointer
            IntPtr ptr2;
            ptr2 = scanner.Scan(new SigScanTarget(1, "74 56 8D 4B 38"));
            ptr2 += game.ReadValue<byte>(ptr2) + 0x1 + 0x2;
            ptr2 += 4 + game.ReadValue<int>(ptr2);

            // Data to calculate on the fly and inject
            BitConverter.GetBytes((int)((Int64)ptr2 - (Int64)InjectionAddress + 0x181)).CopyTo(injectedcode, 2);

            // Other pointer
            ptr2 = scanner.Scan(new SigScanTarget(7, "48 83 C4 08 48 8B 35 ???????? 41 83 E6 00"));
            if (ptr2 != IntPtr.Zero)
            {
                ptr2 += 4 + game.ReadValue<int>(ptr2);
                BitConverter.GetBytes((int)((Int64)ptr2 - (Int64)InjectionAddress + 0x177)).CopyTo(injectedcode, 13);
            }
            else
            {
                new byte[] { 0xEB, 0x11, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 }.CopyTo(injectedcode, 9);
            }

            game.WriteBytes(InjectionAddress - 0x188, injectedcode);
            game.WriteBytes(InjectionAddress, injectedcodecall);
        }

        private void Unpatch()
        {
            byte[] buffer = new byte[43];
            for (int index = 0; index < buffer.Length; ++index) buffer[index] = 0xCC;
            game.WriteBytes(InjectionAddress, new byte[] { 0x8B, 0x81, 0x04, 0x02, 0x00, 0x00 });
            game.WriteBytes(InjectionAddress - 0x188, buffer);
        }
    }
}