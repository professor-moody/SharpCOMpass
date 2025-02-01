// Analyzers/RegistryAnalyzer.cs
using Microsoft.Extensions.Logging;
using Microsoft.Win32;
using SharpCOMpass.Core.Interfaces;
using SharpCOMpass.Core.Models;
using SharpCOMpass.Common.Extensions;

namespace SharpCOMpass.Analyzers;

public class RegistryAnalyzer : IAnalyzer<COMObjectInfo>
{
    private readonly ILogger<RegistryAnalyzer> _logger;

    public string Name => "Registry";
    public string Description => "Analyzes COM object registry entries";

    public RegistryAnalyzer(ILogger<RegistryAnalyzer> logger)
    {
        _logger = logger;
    }

    public async Task<Dictionary<string, COMObjectInfo>> AnalyzeAsync(
        IReadOnlyDictionary<string, object> previousResults,
        IProgress<ProgressInfo>? progress = null,
        CancellationToken cancellationToken = default)
    {
        var results = new Dictionary<string, COMObjectInfo>();
        
        try
        {
            using var clsidKey = Registry.ClassesRoot.OpenSubKey("CLSID");
            if (clsidKey == null)
            {
                _logger.LogError("Unable to open CLSID registry key");
                return results;
            }

            var clsids = clsidKey.GetSubKeyNames();
            var total = clsids.Length;
            
            for (int i = 0; i < total; i++)
            {
                cancellationToken.ThrowIfCancellationRequested();
                
                var clsid = clsids[i];
                try
                {
                    progress?.Report(new ProgressInfo 
                    { 
                        CurrentOperation = "Analyzing COM Objects",
                        CurrentItem = i + 1,
                        TotalItems = total,
                        AdditionalInfo = clsid
                    });

                    var comInfo = await AnalyzeCOMObjectAsync(clsid, cancellationToken);
                    if (comInfo != null)
                    {
                        results[clsid] = comInfo;
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Error analyzing COM object {Clsid}", clsid);
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error enumerating COM objects");
            throw;
        }

        return results;
    }

    private async Task<COMObjectInfo?> AnalyzeCOMObjectAsync(string clsid, CancellationToken cancellationToken)
    {
        using var objectKey = Registry.ClassesRoot.OpenSubKey($"CLSID\\{clsid}");
        if (objectKey == null) return null;

        var defaultValue = objectKey.GetValue("")?.ToString();
        if (string.IsNullOrWhiteSpace(defaultValue)) return null;

        // Server information
        var (serverType, serverPath, threadingModel) = GetServerInfo(objectKey);
        
        // Check for elevation
        bool isElevated = false;
        using var elevationKey = objectKey.OpenSubKey("Elevation");
        if (elevationKey != null)
        {
            isElevated = true;
        }

        // Get ProgID if available
        string? progId = null;
        using var progIdKey = objectKey.OpenSubKey("ProgID");
        if (progIdKey != null)
        {
            progId = progIdKey.GetValue("")?.ToString();
        }

        // Get TypeLib path
        var typeLibPath = await GetTypeLibPathAsync(objectKey, cancellationToken);

        var lastWriteTime = objectKey.GetLastWriteTime();

        return new COMObjectInfo
        {
            Clsid = clsid,
            Name = defaultValue,
            ServerType = serverType,
            ServerPath = serverPath,
            ThreadingModel = threadingModel,
            TypeLibPath = typeLibPath,
            IsElevated = isElevated,
            ProgId = progId,
            LastModified = lastWriteTime
        };
    }

    private static (string? serverType, string? serverPath, string? threadingModel) GetServerInfo(RegistryKey objectKey)
    {
        foreach (var serverType in new[] { "InprocServer32", "LocalServer32" })
        {
            using var serverKey = objectKey.OpenSubKey(serverType);
            if (serverKey == null) continue;

            var serverPath = serverKey.GetValue("")?.ToString();
            var threadingModel = serverKey.GetValue("ThreadingModel")?.ToString();

            if (!string.IsNullOrWhiteSpace(serverPath))
            {
                return (serverType, serverPath, threadingModel);
            }
        }

        return (null, null, null);
    }

    private async Task<string?> GetTypeLibPathAsync(RegistryKey objectKey, CancellationToken cancellationToken)
    {
        return await Task.Run(() =>
        {
            try
            {
                using var typeLibKey = objectKey.OpenSubKey("TypeLib");
                if (typeLibKey == null) return null;

                var typeLibId = typeLibKey.GetValue("")?.ToString();
                if (string.IsNullOrWhiteSpace(typeLibId)) return null;

                using var rootTypeLibKey = Registry.ClassesRoot.OpenSubKey($"TypeLib\\{typeLibId}");
                if (rootTypeLibKey == null) return null;

                var versions = rootTypeLibKey.GetSubKeyNames();
                if (versions.Length == 0) return null;

                var latestVersion = versions.OrderByDescending(v => v).First();
                using var versionKey = rootTypeLibKey.OpenSubKey(latestVersion);
                if (versionKey == null) return null;

                using var win32Key = versionKey.OpenSubKey("win32");
                return win32Key?.GetValue("")?.ToString();
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Error getting TypeLib path");
                return null;
            }
        }, cancellationToken);
    }

    public bool ValidateDependencies() => true;
}