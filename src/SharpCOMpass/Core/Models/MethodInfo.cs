// Core/Models/MethodInfo.cs
namespace SharpCOMpass.Core.Models;

public record MethodInfo
{
    public required string Name { get; init; }
    public required string ReturnType { get; init; }
    public required List<ParameterInfo> Parameters { get; init; }
    public int DispId { get; init; }
    public bool IsHidden { get; init; }
}

public record ParameterInfo
{
    public required string Name { get; init; }
    public required string Type { get; init; }
    public bool IsOptional { get; init; }
    public int Position { get; init; }
}