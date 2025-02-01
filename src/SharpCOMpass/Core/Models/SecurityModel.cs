// Core/Models/SecurityModels.cs
using System.Security.AccessControl;

namespace SharpCOMpass.Core.Models;

public class SecurityInfo
{
    public required string Clsid { get; init; }
    public required string ObjectName { get; init; }
    public required string Owner { get; init; }
    public string? ServerType { get; init; }
    public List<AccessPermission> AccessPermissions { get; init; } = new();
    public List<LaunchPermission> LaunchPermissions { get; init; } = new();
    public AuthenticationLevel DefaultAccessLevel { get; init; }
    public AuthenticationLevel AuthenticationLevel { get; init; }
    public ImpersonationLevel ImpersonationLevel { get; init; }
    public ComCapabilities Capabilities { get; init; }
    public TrustLevel TrustLevel { get; init; }
    public List<SecurityRisk> Risks { get; init; } = new();
}

public record SecurityResult
{
    public required string Clsid { get; init; }
    public required string Owner { get; init; }
    public required List<AccessPermission> Permissions { get; init; }
    public required List<SecurityRisk> SecurityRisks { get; init; }
    public bool IsSystemObject { get; init; }
    public AuthenticationLevel AuthenticationLevel { get; init; }
    public ImpersonationLevel ImpersonationLevel { get; init; }
    public ComCapabilities Capabilities { get; init; }
}

public record AccessPermission
{
    public required string Principal { get; init; }
    public required RegistryRights AccessMask { get; init; }
    public required AccessControlType AccessType { get; init; }
    public bool IsInherited { get; init; }
    public RiskLevel RiskLevel { get; init; }
}

public record LaunchPermission : AccessPermission
{
    public bool AllowRemoteLaunch { get; init; }
    public bool AllowLocalLaunch { get; init; }
}

public record SecurityRisk
{
    public required RiskLevel Level { get; init; }
    public required string Description { get; init; }
    public required string AffectedAccount { get; init; }
    public required string Remediation { get; init; }
}

public enum RiskLevel
{
    Low,
    Medium,
    High,
    Critical
}

public enum AuthenticationLevel
{
    Default = 0,
    None = 1,
    Connect = 2,
    Call = 3,
    Packet = 4,
    PacketIntegrity = 5,
    PacketPrivacy = 6
}

public enum ImpersonationLevel
{
    Default = 0,
    Anonymous = 1,
    Identify = 2,
    Impersonate = 3,
    Delegate = 4
}

[Flags]
public enum ComCapabilities
{
    None = 0,
    RemoteActivation = 1,
    Surrogate = 2,
    RunAs = 4,
    AppContainer = 8,
    ActivationInPackage = 16
}

public enum TrustLevel
{
    Custom = 0,
    ProgramFiles = 1,
    System = 2,
    Elevated = 3
}