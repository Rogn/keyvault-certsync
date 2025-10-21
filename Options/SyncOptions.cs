using CommandLine;

namespace keyvault_certsync.Options
{
    [Verb("sync", HelpText = "Sync certificates using automation config")]
    public class SyncOptions : BaseOptions
    {
        [Option('f', "force", HelpText = "Force even when identical certificate exists")]
        public bool Force { get; set; }

        [Option("dry-run", HelpText = "Show the automations that would run")]
        public bool DryRun { get; set; }
    }
}
