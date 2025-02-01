// Core/Security/SecurityChecker.cs
using Microsoft.Win32;
using System.Security.AccessControl;
using System.Security.Principal;
using SharpCOMpass.Core.Models;

namespace SharpCOMpass.Core.Security;

public class SecurityChecker
{
   private const string DCOM_SECURITY_KEY = @"SOFTWARE\Microsoft\Ole";
   private const string DCOM_MACHINE_ACCESS_KEY = @"SOFTWARE\Microsoft\Ole\MachineLaunchRestriction";
   private const string DCOM_MACHINE_LAUNCH_KEY = @"SOFTWARE\Microsoft\Ole\DefaultLaunchPermission";

   public SecurityInfo AnalizeComSecurity(string clsid, COMObjectInfo comInfo)
   {
       var owner = GetOwner(clsid);
       
       var securityInfo = new SecurityInfo
       {
           Clsid = clsid,
           ObjectName = comInfo.Name,
           Owner = owner,
           ServerType = comInfo.ServerType,
           AccessPermissions = GetAccessPermissions(clsid),
           LaunchPermissions = GetLaunchPermissions(clsid),
           DefaultAccessLevel = GetDefaultAccessLevel(clsid),
           AuthenticationLevel = GetAuthenticationLevel(clsid),
           ImpersonationLevel = GetImpersonationLevel(clsid),
           Capabilities = GetComCapabilities(clsid),
           TrustLevel = CalculateTrustLevel(comInfo)
       };

       securityInfo.Risks.AddRange(AnalyzeSecurityRisks(securityInfo));
       return securityInfo;
   }

   private string GetOwner(string clsid)
   {
       try
       {
           using var key = Registry.ClassesRoot.OpenSubKey($@"CLSID\{clsid}");
           if (key == null) return "Unknown";

           var sd = key.GetAccessControl();
           var owner = sd.GetOwner(typeof(NTAccount));
           return owner?.ToString() ?? "Unknown";
       }
       catch
       {
           return "Unknown";
       }
   }

   private List<AccessPermission> GetAccessPermissions(string clsid)
   {
       var permissions = new List<AccessPermission>();
       try
       {
           using var key = Registry.ClassesRoot.OpenSubKey($@"CLSID\{clsid}");
           if (key == null) return permissions;

           var sd = key.GetAccessControl();
           var rules = sd.GetAccessRules(true, true, typeof(NTAccount));

           foreach (RegistryAccessRule rule in rules)
           {
               permissions.Add(new AccessPermission
               {
                   Principal = rule.IdentityReference.ToString(),
                   AccessMask = rule.RegistryRights,
                   AccessType = rule.AccessControlType,
                   IsInherited = rule.IsInherited,
                   RiskLevel = EvaluatePermissionRisk(rule)
               });
           }
       }
       catch (Exception)
       {
           // Log or handle error as needed
       }
       return permissions;
   }

   private RiskLevel EvaluatePermissionRisk(RegistryAccessRule rule)
   {
       var account = rule.IdentityReference.ToString().ToLower();
       var rights = rule.RegistryRights;

       if (account.Contains("everyone") || account.Contains("authenticated users"))
       {
           if ((rights & RegistryRights.FullControl) == RegistryRights.FullControl)
               return RiskLevel.Critical;
           if ((rights & RegistryRights.WriteKey) == RegistryRights.WriteKey)
               return RiskLevel.High;
       }

       if (rights.HasFlag(RegistryRights.ChangePermissions) || 
           rights.HasFlag(RegistryRights.TakeOwnership))
           return RiskLevel.High;

       return RiskLevel.Low;
   }

   private List<LaunchPermission> GetLaunchPermissions(string clsid)
   {
       var permissions = new List<LaunchPermission>();
       try
       {
           using var key = Registry.ClassesRoot.OpenSubKey($@"AppID\{clsid}");
           if (key == null) return permissions;

           var sd = key.GetAccessControl();
           var rules = sd.GetAccessRules(true, true, typeof(NTAccount));

           foreach (RegistryAccessRule rule in rules)
           {
               var remoteAccess = HasRemoteAccess(rule.RegistryRights);
               var localAccess = HasLocalAccess(rule.RegistryRights);

               if (remoteAccess || localAccess)
               {
                   permissions.Add(new LaunchPermission
                   {
                       Principal = rule.IdentityReference.ToString(),
                       AccessMask = rule.RegistryRights,
                       AccessType = rule.AccessControlType,
                       IsInherited = rule.IsInherited,
                       RiskLevel = EvaluatePermissionRisk(rule),
                       AllowRemoteLaunch = remoteAccess,
                       AllowLocalLaunch = localAccess
                   });
               }
           }
       }
       catch
       {
           // Log error
       }
       return permissions;
   }

   private bool HasRemoteAccess(RegistryRights rights)
   {
       return (rights & RegistryRights.FullControl) == RegistryRights.FullControl ||
              (rights & RegistryRights.ReadKey) == RegistryRights.ReadKey;
   }

   private bool HasLocalAccess(RegistryRights rights)
   {
       return (rights & RegistryRights.FullControl) == RegistryRights.FullControl ||
              (rights & RegistryRights.ExecuteKey) == RegistryRights.ExecuteKey;
   }

   private AuthenticationLevel GetAuthenticationLevel(string clsid)
   {
       try
       {
           using var key = Registry.ClassesRoot.OpenSubKey($@"AppID\{clsid}");
           if (key == null) return AuthenticationLevel.Default;

           var authLevel = key.GetValue("AuthenticationLevel");
           return authLevel != null 
               ? (AuthenticationLevel)Convert.ToInt32(authLevel) 
               : AuthenticationLevel.Default;
       }
       catch
       {
           return AuthenticationLevel.Default;
       }
   }

   private ImpersonationLevel GetImpersonationLevel(string clsid)
   {
       try
       {
           using var key = Registry.ClassesRoot.OpenSubKey($@"AppID\{clsid}");
           if (key == null) return ImpersonationLevel.Default;

           var impLevel = key.GetValue("ImpersonationLevel");
           return impLevel != null 
               ? (ImpersonationLevel)Convert.ToInt32(impLevel) 
               : ImpersonationLevel.Default;
       }
       catch
       {
           return ImpersonationLevel.Default;
       }
   }

   private ComCapabilities GetComCapabilities(string clsid)
   {
       var capabilities = ComCapabilities.None;
       try
       {
           using var key = Registry.ClassesRoot.OpenSubKey($@"AppID\{clsid}");
           if (key == null) return capabilities;

           if (key.GetValue("RemoteServerName") != null)
               capabilities |= ComCapabilities.RemoteActivation;

           if (key.GetValue("DllSurrogate") != null)
               capabilities |= ComCapabilities.Surrogate;

           if (IsRunAsEnabled(key))
               capabilities |= ComCapabilities.RunAs;

           if (IsAppContainer(key))
               capabilities |= ComCapabilities.AppContainer;

           return capabilities;
       }
       catch
       {
           return capabilities;
       }
   }

   private bool IsRunAsEnabled(RegistryKey key)
   {
       var runAs = key.GetValue("RunAs");
       return runAs != null && !string.IsNullOrEmpty(runAs.ToString());
   }

   private bool IsAppContainer(RegistryKey key)
   {
       var enableAppContainer = key.GetValue("EnableAppContainer");
       return enableAppContainer != null && Convert.ToBoolean(enableAppContainer);
   }

   private TrustLevel CalculateTrustLevel(COMObjectInfo comInfo)
   {
       if (comInfo.IsElevated)
           return TrustLevel.Elevated;

       if (IsSystemDirectory(comInfo.ServerPath))
           return TrustLevel.System;

       if (IsProgramFiles(comInfo.ServerPath))
           return TrustLevel.ProgramFiles;

       return TrustLevel.Custom;
   }

   private bool IsSystemDirectory(string? path)
   {
       if (string.IsNullOrEmpty(path)) return false;
       return path.StartsWith(Environment.SystemDirectory, StringComparison.OrdinalIgnoreCase) ||
              path.StartsWith(Environment.GetFolderPath(Environment.SpecialFolder.System), StringComparison.OrdinalIgnoreCase);
   }

   private bool IsProgramFiles(string? path)
   {
       if (string.IsNullOrEmpty(path)) return false;
       return path.StartsWith(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), StringComparison.OrdinalIgnoreCase) ||
              path.StartsWith(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), StringComparison.OrdinalIgnoreCase);
   }

   private AuthenticationLevel GetDefaultAccessLevel(string clsid)
   {
       try
       {
           using var key = Registry.LocalMachine.OpenSubKey(DCOM_SECURITY_KEY);
           if (key == null) return AuthenticationLevel.Default;

           var defaultLevel = key.GetValue("DefaultAccessLevel");
           return defaultLevel != null 
               ? (AuthenticationLevel)Convert.ToInt32(defaultLevel) 
               : AuthenticationLevel.Default;
       }
       catch
       {
           return AuthenticationLevel.Default;
       }
   }

   private List<SecurityRisk> AnalyzeSecurityRisks(SecurityInfo securityInfo)
   {
       var risks = new List<SecurityRisk>();
       
       // Check for dangerous permissions
       foreach (var perm in securityInfo.AccessPermissions.Where(p => p.RiskLevel >= RiskLevel.High))
       {
           risks.Add(new SecurityRisk
           {
               Level = perm.RiskLevel,
               Description = $"Dangerous permissions granted to {perm.Principal}",
               AffectedAccount = perm.Principal,
               Remediation = $"Review and restrict permissions for {perm.Principal}"
           });
       }

       // Check remote activation risks
       if ((securityInfo.Capabilities & ComCapabilities.RemoteActivation) != 0)
       {
           var remotePermissions = securityInfo.LaunchPermissions.Count(p => p.AllowRemoteLaunch);
           if (remotePermissions > 0)
           {
               risks.Add(new SecurityRisk
               {
                   Level = RiskLevel.High,
                   Description = "COM object allows remote activation",
                   AffectedAccount = "Multiple",
                   Remediation = "Review and restrict remote launch permissions"
               });
           }
       }

       // Check elevation risks
       if (securityInfo.TrustLevel == TrustLevel.Elevated)
       {
           risks.Add(new SecurityRisk
           {
               Level = RiskLevel.High,
               Description = "COM object runs with elevated privileges",
               AffectedAccount = "System",
               Remediation = "Review necessity of elevation and consider alternatives"
           });
       }

       return risks;
   }
}