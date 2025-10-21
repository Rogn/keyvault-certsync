using System.Collections.Generic;
using System.Linq;

namespace keyvault_certsync.Models
{
    public class ChainValidationResult
    {
        public bool IsValid { get; set; } = true;
        public Dictionary<string, string> Errors { get; set; } = new Dictionary<string, string>();
        public Dictionary<string, string> Warnings { get; set; } = new Dictionary<string, string>();

        public bool HasWarnings => Warnings.Any();
        public bool HasErrors => Errors.Any();
    }
}
