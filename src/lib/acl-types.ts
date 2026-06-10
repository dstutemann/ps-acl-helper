export interface AclRule {
  id: string
  principalType: 'sid' | 'name'
  principal: string
  principalDisplayName: string
  accessType: 'Allow' | 'Deny'
  permissions: string[]
  inheritance: string[]
  propagation: string
}

export const WELL_KNOWN_SIDS = [
  { sid: 'S-1-5-32-544', name: 'Administrators', description: 'BUILTIN\\Administrators' },
  { sid: 'S-1-5-18', name: 'SYSTEM', description: 'NT AUTHORITY\\SYSTEM' },
  { sid: 'S-1-5-32-545', name: 'Users', description: 'BUILTIN\\Users' },
  { sid: 'S-1-5-32-546', name: 'Guests', description: 'BUILTIN\\Guests' },
  { sid: 'S-1-5-32-547', name: 'Power Users', description: 'BUILTIN\\Power Users' },
  { sid: 'S-1-5-11', name: 'Authenticated Users', description: 'NT AUTHORITY\\Authenticated Users' },
  { sid: 'S-1-1-0', name: 'Everyone', description: 'Everyone' },
  { sid: 'S-1-5-19', name: 'LOCAL SERVICE', description: 'NT AUTHORITY\\LOCAL SERVICE' },
  { sid: 'S-1-5-20', name: 'NETWORK SERVICE', description: 'NT AUTHORITY\\NETWORK SERVICE' },
  { sid: 'S-1-5-32-551', name: 'Backup Operators', description: 'BUILTIN\\Backup Operators' },
  { sid: 'S-1-5-32-555', name: 'Remote Desktop Users', description: 'BUILTIN\\Remote Desktop Users' },
  { sid: 'S-1-5-32-580', name: 'Remote Management Users', description: 'BUILTIN\\Remote Management Users' },
  { sid: 'S-1-3-0', name: 'Creator Owner', description: 'CREATOR OWNER' },
  { sid: 'S-1-3-1', name: 'Creator Group', description: 'CREATOR GROUP' },
  { sid: 'S-1-5-32-548', name: 'Account Operators', description: 'BUILTIN\\Account Operators' },
  { sid: 'S-1-5-32-549', name: 'Server Operators', description: 'BUILTIN\\Server Operators' },
  { sid: 'S-1-5-32-550', name: 'Print Operators', description: 'BUILTIN\\Print Operators' },
  { sid: 'S-1-5-9', name: 'Enterprise Domain Controllers', description: 'NT AUTHORITY\\ENTERPRISE DOMAIN CONTROLLERS' },
  { sid: 'S-1-5-32-573', name: 'Event Log Readers', description: 'BUILTIN\\Event Log Readers' },
  { sid: 'S-1-5-32-578', name: 'Hyper-V Administrators', description: 'BUILTIN\\Hyper-V Administrators' },
  { sid: 'S-1-5-113', name: 'Local Account', description: 'NT AUTHORITY\\Local account' },
  { sid: 'S-1-5-114', name: 'Local Account (Admin)', description: 'NT AUTHORITY\\Local account and member of Administrators group' },
  { sid: 'S-1-5-32-556', name: 'Network Configuration Operators', description: 'BUILTIN\\Network Configuration Operators' },
  { sid: 'S-1-5-32-559', name: 'Performance Log Users', description: 'BUILTIN\\Performance Log Users' },
  { sid: 'S-1-5-32-558', name: 'Performance Monitor Users', description: 'BUILTIN\\Performance Monitor Users' },
] as const

export const FILE_SYSTEM_RIGHTS = [
  { value: 'FullControl', label: 'Full Control' },
  { value: 'Modify', label: 'Modify' },
  { value: 'ReadAndExecute', label: 'Read & Execute' },
  { value: 'ListDirectory', label: 'List Folder Contents' },
  { value: 'Read', label: 'Read' },
  { value: 'Write', label: 'Write' },
  { value: 'ExecuteFile', label: 'Execute File' },
  { value: 'Delete', label: 'Delete' },
  { value: 'ReadPermissions', label: 'Read Permissions' },
  { value: 'ChangePermissions', label: 'Change Permissions' },
  { value: 'TakeOwnership', label: 'Take Ownership' },
  { value: 'CreateFiles', label: 'Create Files' },
  { value: 'CreateDirectories', label: 'Create Directories' },
  { value: 'WriteAttributes', label: 'Write Attributes' },
  { value: 'WriteExtendedAttributes', label: 'Write Extended Attributes' },
  { value: 'ReadAttributes', label: 'Read Attributes' },
  { value: 'ReadExtendedAttributes', label: 'Read Extended Attributes' },
  { value: 'DeleteSubdirectoriesAndFiles', label: 'Delete Subdirectories and Files' },
  { value: 'Traverse', label: 'Traverse Folder' },
  { value: 'Synchronize', label: 'Synchronize' },
] as const

export const INHERITANCE_FLAGS = [
  { value: 'ContainerInherit', label: 'Container Inherit', description: 'Apply to subfolders' },
  { value: 'ObjectInherit', label: 'Object Inherit', description: 'Apply to files' },
] as const

export const PROPAGATION_FLAGS = [
  { value: 'None', label: 'None', description: 'This folder, subfolders and files' },
  { value: 'InheritOnly', label: 'Inherit Only', description: 'Subfolders and files only (not this folder)' },
  { value: 'NoPropagateInherit', label: 'No Propagate Inherit', description: 'This folder and immediate children only' },
  { value: 'NoPropagateInherit, InheritOnly', label: 'No Propagate + Inherit Only', description: 'Immediate children only' },
] as const

export const APPLIES_TO_PRESETS = [
  { label: 'This folder, subfolders and files', inheritance: ['ContainerInherit', 'ObjectInherit'], propagation: 'None' },
  { label: 'This folder only', inheritance: [], propagation: 'None' },
  { label: 'This folder and subfolders', inheritance: ['ContainerInherit'], propagation: 'None' },
  { label: 'This folder and files', inheritance: ['ObjectInherit'], propagation: 'None' },
  { label: 'Subfolders and files only', inheritance: ['ContainerInherit', 'ObjectInherit'], propagation: 'InheritOnly' },
  { label: 'Subfolders only', inheritance: ['ContainerInherit'], propagation: 'InheritOnly' },
  { label: 'Files only', inheritance: ['ObjectInherit'], propagation: 'InheritOnly' },
] as const

export function getAppliesToLabel(inheritance: string[], propagation: string): string {
  const preset = APPLIES_TO_PRESETS.find(
    p => arraysEqual(p.inheritance as unknown as string[], inheritance) && p.propagation === propagation
  )
  return preset?.label ?? 'Custom'
}

function arraysEqual(a: string[], b: string[]): boolean {
  if (a.length !== b.length) return false
  const sortedA = [...a].sort()
  const sortedB = [...b].sort()
  return sortedA.every((val, i) => val === sortedB[i])
}
