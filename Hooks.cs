using keyvault_certsync.Models;
using Serilog;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;

namespace keyvault_certsync
{
    public static class Hooks
    {
        private static readonly Dictionary<string, List<DownloadResult>> postHooks = new();

        public static void AddPostHook(string command, IEnumerable<DownloadResult> results)
        {
            if (!postHooks.ContainsKey(command))
                postHooks.Add(command, new List<DownloadResult>());

            postHooks[command].AddRange(results);
        }

        public static int RunPostHooks()
        {
            bool hookFailed = false;
            foreach(var entry in postHooks)
            {
                if (RunPostHook(entry.Key, entry.Value) != 0)
                    hookFailed = true;
            }

            return hookFailed ? -1 : 0;
        }

        public static int RunDeployHook(string command, DownloadResult result)
        {
            string[] parts = command.Split(new[] { ' ' }, 2);
            string executablePath = parts[0];

            // Security: Require absolute paths for hook executables to prevent PATH injection
            if (!Path.IsPathRooted(executablePath))
            {
                Log.Error("Hook executable must be an absolute path: {Path}", executablePath);
                return -1;
            }

            // Security: Validate that the executable exists
            if (!File.Exists(executablePath))
            {
                Log.Error("Hook executable not found: {Path}", executablePath);
                return -1;
            }

            var startInfo = new ProcessStartInfo(executablePath)
            {
                UseShellExecute = false // Security: Prevent shell interpretation of arguments
            };

            startInfo.EnvironmentVariables.Add("CERTIFICATE_NAME", result.CertificateName);
            startInfo.EnvironmentVariables.Add("CERTIFICATE_THUMBPRINT", result.Thumbprint);

            if (!string.IsNullOrEmpty(result.Path))
                startInfo.EnvironmentVariables.Add("CERTIFICATE_PATH", result.Path);

            if (parts.Length > 1)
                startInfo.Arguments = parts[1];

            Log.Debug("Running deploy hook with environment variables: CERTIFICATE_NAME={CertificateName}, CERTIFICATE_THUMBPRINT={Thumbprint}, CERTIFICATE_PATH={Path}",
                result.CertificateName, result.Thumbprint, result.Path ?? "(not set)");

            return RunHook(startInfo, "Deploy");
        }

        private static int RunPostHook(string command, IEnumerable<DownloadResult> results)
        {
            string[] parts = command.Split(new[] { ' ' }, 2);
            string executablePath = parts[0];

            // Security: Require absolute paths for hook executables to prevent PATH injection
            if (!Path.IsPathRooted(executablePath))
            {
                Log.Error("Hook executable must be an absolute path: {Path}", executablePath);
                return -1;
            }

            // Security: Validate that the executable exists
            if (!File.Exists(executablePath))
            {
                Log.Error("Hook executable not found: {Path}", executablePath);
                return -1;
            }

            var startInfo = new ProcessStartInfo(executablePath)
            {
                UseShellExecute = false // Security: Prevent shell interpretation of arguments
            };

            var certificateNames = string.Join(",", results.Select(s => s.CertificateName));
            var certificateThumbprints = string.Join(",", results.Select(s => s.Thumbprint));

            startInfo.EnvironmentVariables.Add("CERTIFICATE_NAMES", certificateNames);
            startInfo.EnvironmentVariables.Add("CERTIFICATE_THUMBPRINTS", certificateThumbprints);

            if (parts.Length > 1)
                startInfo.Arguments = parts[1];

            Log.Debug("Running post hook with environment variables: CERTIFICATE_NAMES={CertificateNames}, CERTIFICATE_THUMBPRINTS={Thumbprints}",
                certificateNames, certificateThumbprints);

            return RunHook(startInfo, "Post");
        }

        private static int RunHook(ProcessStartInfo startInfo, string type)
        {
            int exitCode;
            try
            {
                using var process = Process.Start(startInfo);
                process.WaitForExit();
                exitCode = process.ExitCode;
            }
            catch (Exception ex)
            {
                Log.Error(ex, "{HookType} hook '{Hook}' '{HookArguments}' failed to run",
                    type, startInfo.FileName, startInfo.Arguments);
                return -1;
            }

            if (exitCode == 0)
            {
                Log.Information("{HookType} hook '{Hook}' '{HookArguments}' completed successfully",
                    type, startInfo.FileName, startInfo.Arguments);
                return 0;
            }

            Log.Warning("{HookType} hook '{Hook}' '{HookArguments}' completed with exit code {ExitCode}",
                type, startInfo.FileName, startInfo.Arguments, exitCode);
            return exitCode;
        }
    }
}
