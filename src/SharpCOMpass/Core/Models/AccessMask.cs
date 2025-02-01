// Core/Models/AccessMask.cs
namespace SharpCOMpass.Core.Models;

/// <summary>
/// Represents access control rights for COM objects and Registry keys
/// </summary>
[Flags]
public enum AccessMask : uint
{
    // Standard Rights
    Delete = 0x00010000,                 // Right to delete the object
    ReadControl = 0x00020000,            // Right to read the security descriptor
    WriteDac = 0x00040000,              // Right to modify the DACL
    WriteOwner = 0x00080000,            // Right to change the owner
    Synchronize = 0x00100000,           // Right to use the object for synchronization

    // Standard Rights Combinations
    StandardRightsRequired = 0x000F0000, // Standard rights required for all objects
    StandardRightsRead = ReadControl,
    StandardRightsWrite = ReadControl,
    StandardRightsExecute = ReadControl,
    StandardRightsAll = 0x001F0000,

    // COM-Specific Rights
    ComExecute = 0x0001,                // Right to execute the COM object
    ComExecuteLocal = 0x0002,           // Right to execute locally
    ComExecuteRemote = 0x0004,          // Right to execute remotely
    ComActivateLocal = 0x0008,          // Right to activate locally
    ComActivateRemote = 0x0010,         // Right to activate remotely

    // Registry-Specific Rights
    QueryValue = 0x0001,                // Required to query the values of a registry key
    SetValue = 0x0002,                  // Required to create, delete, or set a registry value
    CreateSubKey = 0x0004,              // Required to create a subkey of a registry key
    EnumerateSubKeys = 0x0008,          // Required to enumerate subkeys of a registry key
    CreateLink = 0x0020,                // Reserved for system use
    
    // Combined Rights
    KeyQueryRead = QueryValue | EnumerateSubKeys | ReadControl,
    KeyAllAccess = 0xF003F,            // All possible access rights for a key
    FullControl = StandardRightsAll | KeyAllAccess,

    // Special Masks
    SpecificRightsAll = 0x0000FFFF,    // Mask for all specific rights
    AccessSystemSecurity = 0x01000000   // Required to get or set the SACL
}