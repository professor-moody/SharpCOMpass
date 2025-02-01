// Infrastructure/Reporting/ReportGenerator.cs
using Microsoft.Extensions.Logging;
using System.Text;
using System.Text.Json;
using SharpCOMpass.Core.Models;

namespace SharpCOMpass.Infrastructure.Reporting;

public enum ReportFormat
{
    Json,
    Text,
    Html
}

public class ReportGenerator
{
    private readonly ILogger<ReportGenerator> _logger;

    public ReportGenerator(ILogger<ReportGenerator> logger)
    {
        _logger = logger;
    }

    public async Task GenerateReportAsync(AnalysisReport report, string outputPath, ReportFormat format)
    {
        try
        {
            var content = format switch
            {
                ReportFormat.Json => await GenerateJsonReport(report),
                ReportFormat.Text => await GenerateTextReport(report),
                ReportFormat.Html => await GenerateHtmlReport(report),
                _ => throw new ArgumentException($"Unsupported format: {format}")
            };

            await File.WriteAllTextAsync(outputPath, content);
            _logger.LogInformation("Report generated: {Path}", outputPath);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to generate report");
            throw;
        }
    }

    private async Task<string> GenerateJsonReport(AnalysisReport report)
    {
        var options = new JsonSerializerOptions
        {
            WriteIndented = true,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
        };
        return JsonSerializer.Serialize(report, options);
    }

    private async Task<string> GenerateTextReport(AnalysisReport report)
    {
        var summary = report.GenerateSummary();
        var sb = new StringBuilder();

        sb.AppendLine("COM Security Analysis Report");
        sb.AppendLine($"Generated: {report.AnalysisTime:yyyy-MM-dd HH:mm:ss}");
        sb.AppendLine();
        sb.AppendLine($"Total Objects Analyzed: {summary.TotalObjects}");
        sb.AppendLine($"Objects Requiring Elevation: {summary.ElevatedObjects}");
        
        sb.AppendLine("\nServer Types:");
        foreach (var (type, count) in summary.ServerTypes.OrderByDescending(x => x.Value))
        {
            sb.AppendLine($"  {type}: {count}");
        }

        if (summary.SecurityRisks.Any())
        {
            sb.AppendLine($"\nSecurity Risks Found: {summary.RiskyObjects} objects");
            foreach (var (level, count) in summary.SecurityRisks.OrderByDescending(x => x.Key))
            {
                sb.AppendLine($"  {level}: {count}");
            }

            sb.AppendLine("\nDetailed Security Findings:");
            foreach (var (clsid, secResult) in report.Security.Where(s => s.Value.SecurityRisks.Any()))
            {
                var comInfo = report.Registry[clsid];
                sb.AppendLine($"\nCLSID: {clsid}");
                sb.AppendLine($"Name: {comInfo.Name}");
                
                foreach (var risk in secResult.SecurityRisks.OrderByDescending(r => r.Level))
                {
                    sb.AppendLine($"  Risk Level: {risk.Level}");
                    sb.AppendLine($"  Description: {risk.Description}");
                    sb.AppendLine($"  Account: {risk.AffectedAccount}");
                    sb.AppendLine($"  Remediation: {risk.Remediation}");
                    sb.AppendLine();
                }
            }
        }

        return sb.ToString();
    }

    private async Task<string> GenerateHtmlReport(AnalysisReport report)
    {
        // TODO: Implement HTML report generation
        throw new NotImplementedException();
    }
}