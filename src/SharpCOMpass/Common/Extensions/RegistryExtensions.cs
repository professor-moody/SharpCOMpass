using Microsoft.Win32;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using System.Text;
using System.Security.AccessControl;

namespace SharpCOMpass.Common.Extensions;

public static class RegistryExtensions
{
   [DllImport("advapi32.dll", CharSet = CharSet.Auto)]
   private static extern int RegQueryInfoKey(
       SafeRegistryHandle hKey,
       StringBuilder? lpClass,
       int[]? lpcbClass,
       IntPtr lpReserved,
       int[]? lpcSubKeys,
       int[]? lpcbMaxSubKeyLen,
       int[]? lpcbMaxClassLen,
       int[]? lpcValues,
       int[]? lpcbMaxValueNameLen,
       int[]? lpcbMaxValueLen,
       int[]? lpcbSecurityDescriptor,
       ref long lpftLastWriteTime);

   public static DateTime? GetLastWriteTime(this RegistryKey key)
   {
       try
       {
           long lastWriteTime = 0;
           var result = RegQueryInfoKey(
               key.Handle,
               null, null,
               IntPtr.Zero,
               null, null, null, null, null, null, null,
               ref lastWriteTime);
               
           return result == 0 ? DateTime.FromFileTime(lastWriteTime) : null;
       }
       catch
       {
           return null;
       }
   }

   public static bool HasSubKey(this RegistryKey key, string name)
   {
       using var subKey = key.OpenSubKey(name);
       return subKey != null;
   }

   public static bool TryGetStringValue(this RegistryKey key, string? valueName, out string value)
   {
       value = string.Empty;
       try
       {
           var obj = key.GetValue(valueName ?? "");
           if (obj == null) return false;
           
           value = obj.ToString()!;
           return true;
       }
       catch
       {
           return false;
       }
   }

   public static string? GetStringValue(this RegistryKey key, string? valueName = null)
   {
       try
       {
           return key.GetValue(valueName ?? "")?.ToString();
       }
       catch
       {
           return null;
       }
   }

   public static IEnumerable<string> EnumerateSubKeysAndValues(this RegistryKey key)
   {
       foreach (var name in key.GetSubKeyNames())
       {
           using var subKey = key.OpenSubKey(name);
           if (subKey == null) continue;

           foreach (var valueName in subKey.GetValueNames())
           {
               var value = subKey.GetValue(valueName);
               if (value != null)
               {
                   yield return $"{name}\\{valueName}={value}";
               }
           }
       }
   }

   public static RegistrySecurity? GetAccessControl(this RegistryKey key)
   {
       try
       {
           return key.GetAccessControl();
       }
       catch
       {
           return null;
       }
   }

   public static bool IsWriteable(this RegistryKey key)
   {
       try
       {
           using var writable = key.OpenSubKey("", true);
           return writable != null;
       }
       catch
       {
           return false;
       }
   }

   public static bool TryOpenSubKey(this RegistryKey key, string name, out RegistryKey? subKey)
   {
       try
       {
           subKey = key.OpenSubKey(name);
           return subKey != null;
       }
       catch
       {
           subKey = null;
           return false;
       }
   }

   public static bool TryOpenSubKeyWithWrite(this RegistryKey key, string name, out RegistryKey? subKey)
   {
       try
       {
           subKey = key.OpenSubKey(name, true);
           return subKey != null;
       }
       catch
       {
           subKey = null;
           return false;
       }
   }

   public static IEnumerable<(string Name, object? Value)> GetAllValues(this RegistryKey key)
   {
       foreach (var valueName in key.GetValueNames())
       {
           var value = key.GetValue(valueName);
           yield return (valueName, value);
       }
   }
}