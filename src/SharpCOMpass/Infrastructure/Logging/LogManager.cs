// Infrastructure/Logging/LogManager.cs
using Microsoft.Extensions.Logging;
using Serilog;
using Serilog.Extensions.Logging;

namespace SharpCOMpass.Infrastructure.Logging;

public static class LogManager
{
    private static ILoggerFactory? _loggerFactory;

    public static void Initialize()
    {
        var serilogLogger = new LoggerConfiguration()
            .MinimumLevel.Debug()
            .WriteTo.Console(
                outputTemplate: "[{Timestamp:HH:mm:ss} {Level:u3}] {Message:lj}{NewLine}{Exception}")
            .WriteTo.File("logs/sharpcompass_.log", 
                rollingInterval: RollingInterval.Day,
                outputTemplate: "{Timestamp:yyyy-MM-dd HH:mm:ss.fff zzz} [{Level:u3}] {Message:lj}{NewLine}{Exception}")
            .CreateLogger();

        _loggerFactory = new LoggerFactory().AddSerilog(serilogLogger);
    }

    public static ILogger<T> CreateLogger<T>() => 
        _loggerFactory?.CreateLogger<T>() ?? throw new InvalidOperationException("Logger not initialized");
}