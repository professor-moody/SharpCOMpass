// Core/Models/RegistryAnalysisResult.cs
namespace SharpCOMpass.Core.Models;

public record RegistryAnalysisResult : BaseAnalysisResult
{
    public required COMObjectInfo ComObject { get; init; }
    public Dictionary<string, string> AdditionalKeys { get; init; } = new();
    public List<string> Warnings { get; init; } = new();
    public bool HasElevationRequirement => ComObject.IsElevated;
    public bool IsInSystemDirectory { get; init; }
}