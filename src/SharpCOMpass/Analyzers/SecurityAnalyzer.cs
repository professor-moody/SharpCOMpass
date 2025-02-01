using Microsoft.Extensions.Logging;
using SharpCOMpass.Core.Interfaces;
using SharpCOMpass.Core.Models;
using SharpCOMpass.Core.Security;

namespace SharpCOMpass.Analyzers;

public class SecurityAnalyzer : IAnalyzer<SecurityResult>
{
    private readonly ILogger<SecurityAnalyzer> _logger;
    private readonly SecurityChecker _securityChecker;

    public string Name => "Security";
    public string Description => "Analyzes COM object security settings and identifies risks";

    public SecurityAnalyzer(ILogger<SecurityAnalyzer> logger)
    {
        _logger = logger;
        _securityChecker = new SecurityChecker();
    }

    public async Task<Dictionary<string, SecurityResult>> AnalyzeAsync(
        IReadOnlyDictionary<string, object> previousResults,
        IProgress<ProgressInfo>? progress = null,
        CancellationToken cancellationToken = default)
    {
        var results = new Dictionary<string, SecurityResult>();
        var registryResults = previousResults["RegistryAnalyzer"] as Dictionary<string, COMObjectInfo>;

        if (registryResults == null)
        {
            _logger.LogError("Registry analysis results not found");
            return results;
        }

        int current = 0;
        int total = registryResults.Count;

        foreach (var (clsid, comInfo) in registryResults)
        {
            cancellationToken.ThrowIfCancellationRequested();
            current++;

            progress?.Report(new ProgressInfo
            {
                CurrentOperation = "Analyzing Security",
                CurrentItem = current,
                TotalItems = total,
                AdditionalInfo = $"CLSID: {clsid}"
            });

            try
            {
                var comSecurity = _securityChecker.AnalizeComSecurity(clsid, comInfo);
                var securityResult = new SecurityResult
                {
                    Clsid = clsid,
                    Owner = comSecurity.Owner,
                    Permissions = comSecurity.AccessPermissions,
                    SecurityRisks = comSecurity.Risks,
                    IsSystemObject = comSecurity.TrustLevel == TrustLevel.System,
                    AuthenticationLevel = comSecurity.AuthenticationLevel,
                    ImpersonationLevel = comSecurity.ImpersonationLevel,
                    Capabilities = comSecurity.Capabilities
                };

                results[clsid] = securityResult;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error analyzing security for {Clsid}", clsid);
            }
        }

        return results;
    }

    public bool ValidateDependencies() => true;
}