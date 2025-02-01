// Core/Models/COMObjectInfo.cs
namespace SharpCOMpass.Core.Models;

/// <summary>
/// Represents detailed information about a COM object from the registry
/// </summary>
public record COMObjectInfo
{
    /// <summary>
    /// The Class ID (CLSID) of the COM object
    /// </summary>
    public required string Clsid { get; init; }

    /// <summary>
    /// The friendly name of the COM object
    /// </summary>
    public required string Name { get; init; }

    /// <summary>
    /// The server type (InprocServer32 or LocalServer32)
    /// </summary>
    public string? ServerType { get; init; }

    /// <summary>
    /// Path to the server executable or DLL
    /// </summary>
    public string? ServerPath { get; init; }

    /// <summary>
    /// COM threading model (Apartment, Free, Both, or Neutral)
    /// </summary>
    public string? ThreadingModel { get; init; }

    /// <summary>
    /// Path to the type library if available
    /// </summary>
    public string? TypeLibPath { get; init; }

    /// <summary>
    /// Whether the COM object requires elevation
    /// </summary>
    public bool IsElevated { get; init; }

    /// <summary>
    /// The ProgID associated with this COM object
    /// </summary>
    public string? ProgId { get; init; }

    /// <summary>
    /// When the COM object was last modified in the registry
    /// </summary>
    public DateTime? LastModified { get; init; }
}