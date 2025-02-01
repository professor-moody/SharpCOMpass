// Core/Models/SecurityDescriptorInfo.cs
namespace SharpCOMpass.Core.Models;

/// <summary>
/// Represents a Windows security descriptor for COM objects
/// </summary>
public record SecurityDescriptorInfo
{
    /// <summary>
    /// The owner of the object
    /// </summary>
    public required string Owner { get; init; }

    /// <summary>
    /// The primary group of the object
    /// </summary>
    public required string Group { get; init; }

    /// <summary>
    /// List of access control entries defining permissions
    /// </summary>
    public required List<AccessControlEntry> Permissions { get; init; }
}

/// <summary>
/// Represents a single access control entry in a security descriptor
/// </summary>
public record AccessControlEntry
{
    /// <summary>
    /// The account (user or group) this entry applies to
    /// </summary>
    public required string Account { get; init; }

    /// <summary>
    /// The access mask defining the permissions
    /// </summary>
    public required AccessMask AccessMask { get; init; }

    /// <summary>
    /// Human-readable list of granted rights
    /// </summary>
    public required List<string> Rights { get; init; }

    /// <summary>
    /// Whether this is an allow or deny entry
    /// </summary>
    public required AccessControlType Type { get; init; }
}