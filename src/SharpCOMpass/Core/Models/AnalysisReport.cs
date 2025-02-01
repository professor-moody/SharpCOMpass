// Core/Models/AnalysisReport.cs
using SharpCOMpass.Core.Models;

public record AnalysisReport
{
   public DateTime AnalysisTime { get; init; } = DateTime.Now;
   public Dictionary<string, COMObjectInfo> Registry { get; init; } = new();
   public Dictionary<string, SecurityResult> Security { get; init; } = new();
   
   public ReportSummary GenerateSummary()
   {
       return new ReportSummary
       {
           TotalObjects = Registry.Count,
           ElevatedObjects = Registry.Count(r => r.Value.IsElevated),
           ServerTypes = Registry
               .GroupBy(r => r.Value.ServerType ?? "Unknown")
               .ToDictionary(g => g.Key, g => g.Count()),
           SecurityRisks = Security.Values
               .SelectMany(s => s.SecurityRisks)
               .GroupBy(r => r.Level)
               .ToDictionary(g => g.Key, g => g.Count()),
           RiskyObjects = Security.Count(s => s.Value.SecurityRisks.Any())
       };
   }
}

public record ReportSummary
{
   public int TotalObjects { get; init; }
   public int ElevatedObjects { get; init; }
   public Dictionary<string, int> ServerTypes { get; init; } = new();
   public Dictionary<RiskLevel, int> SecurityRisks { get; init; } = new();
   public int RiskyObjects { get; init; }
}