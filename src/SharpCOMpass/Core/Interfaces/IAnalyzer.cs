// Core/Interfaces/IAnalyzer.cs
using SharpCOMpass.Core.Models;

namespace SharpCOMpass.Core.Interfaces;

public interface IAnalyzer<TResult> where TResult : class
{
    string Name { get; }
    string Description { get; }
    
    Task<Dictionary<string, TResult>> AnalyzeAsync(
        IReadOnlyDictionary<string, object> previousResults,
        IProgress<ProgressInfo>? progress = null,
        CancellationToken cancellationToken = default);
    
    bool ValidateDependencies();
}