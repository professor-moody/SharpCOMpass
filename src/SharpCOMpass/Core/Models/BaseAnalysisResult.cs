// Core/Models/BaseAnalysisResult.cs
namespace SharpCOMpass.Core.Models;

public abstract record BaseAnalysisResult
{
    public required DateTime AnalysisTime { get; init; }
    public bool Success { get; init; }
    public string? Error { get; init; }
}