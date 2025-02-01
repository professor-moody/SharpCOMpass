// Core/Models/AnalysisResults.cs
namespace SharpCOMpass.Core.Models;

public class AnalysisResults
{
    public Dictionary<string, COMObjectInfo> RegistryResults { get; init; } = new();
    public Dictionary<string, SecurityDescriptorInfo> SecurityResults { get; init; } = new();
    public Dictionary<string, List<VulnerabilityInfo>> VulnerabilityResults { get; init; } = new();
}