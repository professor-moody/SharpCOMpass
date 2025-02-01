// Program.cs
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Configuration;
using System.CommandLine;
using SharpCOMpass.Core.Models;
using SharpCOMpass.Core.Interfaces;
using SharpCOMpass.Analyzers;
using SharpCOMpass.Infrastructure;
using SharpCOMpass.Infrastructure.Reporting;
using Serilog;
using Serilog.Events;

namespace SharpCOMpass;

public class Program
{
    public static async Task<int> Main(string[] args)
    {
        var rootCommand = new RootCommand("SharpCOMcompass - COM Security Analysis Tool");
        
        var debugOption = new Option<bool>(
            name: "--debug",
            description: "Enable debug logging");
           
        var outputOption = new Option<FileInfo?>(
            name: "--output",
            description: "Save results to specified file");
          
        var formatOption = new Option<ReportFormat>(
            name: "--format",
            description: "Output format (json, text, or html)",
            getDefaultValue: () => ReportFormat.Text);
  
        var configOption = new Option<FileInfo?>(
            name: "--config",
            description: "Path to configuration file");
      
        rootCommand.AddGlobalOption(debugOption);
        rootCommand.AddGlobalOption(outputOption);
        rootCommand.AddGlobalOption(formatOption);
        rootCommand.AddGlobalOption(configOption);
       
        rootCommand.SetHandler(async (bool debug, FileInfo? output, ReportFormat format, FileInfo? config) =>
        {
            await RunAnalysis(new AnalysisOptions
            {
                Debug = debug,
                OutputFile = output,
                OutputFormat = format,
                ConfigFile = config
            });
        }, debugOption, outputOption, formatOption, configOption);
   
        return await rootCommand.InvokeAsync(args);
    }  

    private static async Task RunAnalysis(AnalysisOptions options) 
    {
        try
        {
            var configuration = new ConfigurationBuilder()
                .SetBasePath(Directory.GetCurrentDirectory())
                .AddJsonFile("appsettings.json", optional: true)
                .AddJsonFile(options.ConfigFile?.FullName ?? "config.json", optional: true)
                .AddEnvironmentVariables()
                .Build();
  
            var services = new ServiceCollection();
            ConfigureServices(services, configuration, options);
             
            using var serviceProvider = services.BuildServiceProvider();
            var logger = serviceProvider.GetRequiredService<ILogger<Program>>(); 
      
            try
            {
                if (!OperatingSystem.IsWindows())
                {
                    throw new PlatformNotSupportedException("SharpCOMcompass requires Windows to analyze COM objects.");
                }  
             
                logger.LogInformation("Starting COM analysis..."); 
                var report = new AnalysisReport();   
      
                var registryAnalyzer = serviceProvider.GetRequiredService<RegistryAnalyzer>(); 
                var securityAnalyzer = serviceProvider.GetRequiredService<SecurityAnalyzer>();  
                var reportGenerator = serviceProvider.GetRequiredService<ReportGenerator>();    
          
                var progress = new Progress<ProgressInfo>(info =>   
                {    
                    Console.Write($"\r{info.CurrentOperation}: {info.CurrentItem}/{info.TotalItems} ({info.PercentComplete:F1}%)");  
                });     
              
                // Run registry analysis 
                report = new AnalysisReport 
                {   
                    Registry = await registryAnalyzer.AnalyzeAsync(new Dictionary<string, object>(), progress, CancellationToken.None),  
                    Security = await securityAnalyzer.AnalyzeAsync(new Dictionary<string,object> {["RegistryAnalyzer"] = report.Registry},progress,CancellationToken.None) 
                };   
              
                if (options.OutputFile != null)   
                {    
                    await reportGenerator.GenerateReportAsync(report, options.OutputFile.FullName, options.OutputFormat);  
                }     
                else   
                {      
                    var summary = report.GenerateSummary();       
                    Console.WriteLine("\n\nAnalysis Summary:"); 
                    Console.WriteLine($"Total COM Objects analyzed: {summary.TotalObjects}"); 
                    Console.WriteLine($"Objects requiring elevation: {summary.ElevatedObjects}"); 
                    Console.WriteLine($"Objects with security risks: {summary.RiskyObjects}");  
      
                    Console.WriteLine("\nServer Types:");   
                    foreach (var (type, count) in summary.ServerTypes.OrderByDescending(x => x.Value)) 
                    {     
                        Console.WriteLine($"  {type}: {count}");      
                    }         
          
                    if (summary.SecurityRisks.Any())   
                    {       
                        Console.WriteLine("\nSecurity Risks:"); 
                        foreach (var (level, count) in summary.SecurityRisks.OrderByDescending(x => x.Key))  
                        {      
                            Console.WriteLine($"  {level}: {count}");       
                        }    
                    }   
                }

                logger.LogInformation("Analysis complete.");     
            } 
            catch (Exception ex) when (ex is not PlatformNotSupportedException)      
            {         
                logger.LogError(ex, "Analysis failed");          
                throw;       
            }  
        } 
        catch (Exception ex)    
        {      
            Console.WriteLine($"Fatal error: {ex.Message}");       
            if (options.Debug)     
            {         
                Console.WriteLine(ex.StackTrace);          
            }   
            Environment.Exit(1);    
        } 
    }  
      
    private static void ConfigureServices(IServiceCollection services, IConfiguration configuration, AnalysisOptions options)  
    {       
        services.AddLogging(builder =>         
        {                     
           var logConfig = new LoggerConfiguration()             
               .MinimumLevel.Is(options.Debug ? LogEventLevel.Debug : LogEventLevel.Information)              
               .WriteTo.Console()              
               .WriteTo.File(Path.Combine("logs", $"sharpcompass_{DateTime.Now:yyyyMMdd}.log"), rollingInterval: RollingInterval.Day);       
           
            builder.AddSerilog(logConfig.CreateLogger());         
        });          
  
        services.AddSingleton(configuration);      
        services.AddSingleton(options);     
        services.AddTransient<RegistryAnalyzer>(); 
        services.AddTransient<SecurityAnalyzer>();       
        services.AddTransient<ReportGenerator>();         
    }  
}  

public class AnalysisOptions  
{      
   public bool Debug { get; set; }     
   public FileInfo? OutputFile { get; set; } 
   public ReportFormat OutputFormat { get; set; }    
   public FileInfo? ConfigFile { get; set; }       
}