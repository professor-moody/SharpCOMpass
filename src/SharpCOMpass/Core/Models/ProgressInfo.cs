// Core/Models/ProgressInfo.cs
namespace SharpCOMpass.Core.Models;

public record ProgressInfo
{
    public required string CurrentOperation { get; init; }
    public int CurrentItem { get; init; }
    public int TotalItems { get; init; }
    public string? AdditionalInfo { get; init; }

    public double PercentComplete => TotalItems == 0 ? 0 : (double)CurrentItem / TotalItems * 100;
}