/**
 * Parser für SDDL-Strings (Security Descriptor Definition Language),
 * z.B. "D:AR(A;OICI;0x1301bf;;;BU)".
 *
 * Unterstützt werden die Abschnitte O: (Owner), G: (Group), D: (DACL) und
 * S: (SACL) sowie einzelne ACEs in der Form
 * (ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid[;condition])
 */

import type { AclRule } from './acl-types'

export interface SddlPrincipal {
  /** Token wie es im SDDL steht, z.B. "BU" oder "S-1-5-32-545" */
  raw: string
  /** Aufgelöste SID, sofern bekannt (bei domänenabhängigen Kürzeln leer) */
  sid?: string
  name: string
  description?: string
  /** true, wenn die SID von der Domäne abhängt und nicht statisch auflösbar ist */
  domainRelative: boolean
}

export interface SddlAceFlag {
  code: string
  label: string
  description: string
}

export interface SddlRight {
  /** Name des FileSystemRights-Wertes, z.B. "Modify" */
  name: string
  label: string
  mask: number
}

export interface SddlAce {
  raw: string
  aceType: string
  aceTypeLabel: string
  /** Allow/Deny-ACE, die sich in eine FileSystemAccessRule übersetzen lässt */
  accessType?: 'Allow' | 'Deny'
  flags: SddlAceFlag[]
  rightsRaw: string
  accessMask: number
  /** Zusammengefasste Rechte (FullControl, Modify, ...) */
  rights: SddlRight[]
  /** Einzelne gesetzte Bits des Access Mask */
  detailedRights: SddlRight[]
  objectGuid?: string
  inheritObjectGuid?: string
  condition?: string
  principal: SddlPrincipal
  inheritance: string[]
  propagation: string
  appliesTo: string
  /** ACE ist geerbt (ID-Flag) und wird nicht explizit gesetzt */
  inherited: boolean
  /** ACE kann in eine Regel des Builders übernommen werden */
  convertible: boolean
  warnings: string[]
}

export interface SddlAcl {
  section: 'D' | 'S'
  flags: SddlAceFlag[]
  aces: SddlAce[]
}

export interface SddlParseResult {
  ok: boolean
  errors: string[]
  warnings: string[]
  owner?: SddlPrincipal
  group?: SddlPrincipal
  dacl?: SddlAcl
  sacl?: SddlAcl
}

/** Bit-Werte der einzelnen FileSystemRights */
const RIGHT_BITS: SddlRight[] = [
  { mask: 0x00000001, name: 'ListDirectory', label: 'Ordner auflisten / Daten lesen' },
  { mask: 0x00000002, name: 'CreateFiles', label: 'Dateien erstellen / Daten schreiben' },
  { mask: 0x00000004, name: 'CreateDirectories', label: 'Ordner erstellen / Daten anhängen' },
  { mask: 0x00000008, name: 'ReadExtendedAttributes', label: 'Erweiterte Attribute lesen' },
  { mask: 0x00000010, name: 'WriteExtendedAttributes', label: 'Erweiterte Attribute schreiben' },
  { mask: 0x00000020, name: 'ExecuteFile', label: 'Datei ausführen / Ordner durchlaufen' },
  { mask: 0x00000040, name: 'DeleteSubdirectoriesAndFiles', label: 'Unterordner und Dateien löschen' },
  { mask: 0x00000080, name: 'ReadAttributes', label: 'Attribute lesen' },
  { mask: 0x00000100, name: 'WriteAttributes', label: 'Attribute schreiben' },
  { mask: 0x00010000, name: 'Delete', label: 'Löschen' },
  { mask: 0x00020000, name: 'ReadPermissions', label: 'Berechtigungen lesen' },
  { mask: 0x00040000, name: 'ChangePermissions', label: 'Berechtigungen ändern' },
  { mask: 0x00080000, name: 'TakeOwnership', label: 'Besitz übernehmen' },
  { mask: 0x00100000, name: 'Synchronize', label: 'Synchronisieren' },
]

/** Zusammengesetzte Rechte, absteigend nach Umfang sortiert */
const RIGHT_COMBINATIONS: SddlRight[] = [
  { mask: 0x001f01ff, name: 'FullControl', label: 'Vollzugriff' },
  { mask: 0x000301bf, name: 'Modify', label: 'Ändern' },
  { mask: 0x000200a9, name: 'ReadAndExecute', label: 'Lesen, Ausführen' },
  { mask: 0x00020089, name: 'Read', label: 'Lesen' },
  { mask: 0x00000116, name: 'Write', label: 'Schreiben' },
]

/** Generische Rechte-Bits mit ihrer Entsprechung im Dateisystem */
const GENERIC_BITS: { mask: number; code: string; label: string; fileMask: number }[] = [
  { mask: 0x10000000, code: 'GA', label: 'Generic All', fileMask: 0x001f01ff },
  { mask: 0x20000000, code: 'GX', label: 'Generic Execute', fileMask: 0x001200a0 },
  { mask: 0x40000000, code: 'GW', label: 'Generic Write', fileMask: 0x00120116 },
  { mask: 0x80000000, code: 'GR', label: 'Generic Read', fileMask: 0x00120089 },
]

const ACCESS_SYSTEM_SECURITY = 0x01000000

/** Zwei-Buchstaben-Kürzel für Zugriffsrechte */
const RIGHTS_ALIASES: Record<string, { mask: number; label: string }> = {
  // Generische Rechte
  GA: { mask: 0x10000000, label: 'Generic All' },
  GX: { mask: 0x20000000, label: 'Generic Execute' },
  GW: { mask: 0x40000000, label: 'Generic Write' },
  GR: { mask: 0x80000000, label: 'Generic Read' },
  // Standardrechte
  SD: { mask: 0x00010000, label: 'Delete' },
  RC: { mask: 0x00020000, label: 'Read Control' },
  WD: { mask: 0x00040000, label: 'Write DAC' },
  WO: { mask: 0x00080000, label: 'Write Owner' },
  // Datei- und Ordnerrechte
  FA: { mask: 0x001f01ff, label: 'File All Access' },
  FR: { mask: 0x00120089, label: 'File Generic Read' },
  FW: { mask: 0x00120116, label: 'File Generic Write' },
  FX: { mask: 0x001200a0, label: 'File Generic Execute' },
  // Registry-Rechte
  KA: { mask: 0x000f003f, label: 'Key All Access' },
  KR: { mask: 0x00020019, label: 'Key Read' },
  KW: { mask: 0x00020006, label: 'Key Write' },
  KX: { mask: 0x00020019, label: 'Key Execute' },
  // Verzeichnisdienst-Rechte
  CC: { mask: 0x00000001, label: 'Create Child' },
  DC: { mask: 0x00000002, label: 'Delete Child' },
  LC: { mask: 0x00000004, label: 'List Children' },
  SW: { mask: 0x00000008, label: 'Self Write' },
  RP: { mask: 0x00000010, label: 'Read Property' },
  WP: { mask: 0x00000020, label: 'Write Property' },
  DT: { mask: 0x00000040, label: 'Delete Tree' },
  LO: { mask: 0x00000080, label: 'List Object' },
  CR: { mask: 0x00000100, label: 'Control Access' },
  // Mandatory Label
  NR: { mask: 0x00000001, label: 'No Read Up' },
  NW: { mask: 0x00000002, label: 'No Write Up' },
  NX: { mask: 0x00000004, label: 'No Execute Up' },
}

/** Kürzel, die typischerweise nicht auf Dateisystemobjekte angewendet werden */
const NON_FILE_ALIASES = new Set([
  'KA', 'KR', 'KW', 'KX',
  'CC', 'DC', 'LC', 'SW', 'RP', 'WP', 'DT', 'LO', 'CR',
  'NR', 'NW', 'NX',
])

const ACE_TYPES: Record<string, { label: string; accessType?: 'Allow' | 'Deny' }> = {
  A: { label: 'Access Allowed (Zulassen)', accessType: 'Allow' },
  D: { label: 'Access Denied (Verweigern)', accessType: 'Deny' },
  OA: { label: 'Object Access Allowed' },
  OD: { label: 'Object Access Denied' },
  AU: { label: 'System Audit (Überwachung)' },
  AL: { label: 'System Alarm' },
  OU: { label: 'Object System Audit' },
  OL: { label: 'Object System Alarm' },
  ML: { label: 'Mandatory Label (Integritätsstufe)' },
  XA: { label: 'Callback Access Allowed (bedingt)' },
  XD: { label: 'Callback Access Denied (bedingt)' },
  ZA: { label: 'Callback Object Access Allowed (bedingt)' },
  XU: { label: 'Callback Audit (bedingt)' },
  RA: { label: 'Resource Attribute' },
  SP: { label: 'Scoped Policy ID' },
  TL: { label: 'Process Trust Label' },
  FL: { label: 'Access Filter' },
}

const ACE_FLAGS: Record<string, { label: string; description: string }> = {
  CI: { label: 'Container Inherit', description: 'Wird an Unterordner vererbt' },
  OI: { label: 'Object Inherit', description: 'Wird an Dateien vererbt' },
  NP: { label: 'No Propagate Inherit', description: 'Vererbung nur eine Ebene tief' },
  IO: { label: 'Inherit Only', description: 'Gilt nicht für dieses Objekt selbst' },
  ID: { label: 'Inherited', description: 'Der Eintrag ist geerbt und nicht explizit gesetzt' },
  SA: { label: 'Successful Access', description: 'Überwachung erfolgreicher Zugriffe' },
  FA: { label: 'Failed Access', description: 'Überwachung fehlgeschlagener Zugriffe' },
  CR: { label: 'Critical', description: 'Der Eintrag ist als kritisch markiert' },
  TP: { label: 'Trust Protected Filter', description: 'Trust-Protected-Filter-Flag' },
}

const ACL_FLAGS: Record<string, { label: string; description: string }> = {
  P: { label: 'Protected', description: 'Vererbung von übergeordneten Objekten ist deaktiviert' },
  AR: { label: 'Auto Inherit Required', description: 'Vererbte Berechtigungen werden neu berechnet' },
  AI: { label: 'Auto Inherited', description: 'Die ACL wurde automatisch von der übergeordneten ACL vererbt' },
  NO_ACCESS_CONTROL: { label: 'No Access Control', description: 'Es ist keine ACL vorhanden (NULL-ACL)' },
}

/** SID-Kürzel gemäß SDDL */
const SID_ALIASES: Record<string, { name: string; sid?: string; description?: string }> = {
  AO: { name: 'Account Operators', sid: 'S-1-5-32-548', description: 'BUILTIN\\Account Operators' },
  AN: { name: 'Anonymous Logon', sid: 'S-1-5-7', description: 'NT AUTHORITY\\ANONYMOUS LOGON' },
  AU: { name: 'Authenticated Users', sid: 'S-1-5-11', description: 'NT AUTHORITY\\Authenticated Users' },
  BA: { name: 'Administrators', sid: 'S-1-5-32-544', description: 'BUILTIN\\Administrators' },
  BG: { name: 'Guests', sid: 'S-1-5-32-546', description: 'BUILTIN\\Guests' },
  BO: { name: 'Backup Operators', sid: 'S-1-5-32-551', description: 'BUILTIN\\Backup Operators' },
  BU: { name: 'Users', sid: 'S-1-5-32-545', description: 'BUILTIN\\Users' },
  CA: { name: 'Certificate Publishers', description: 'Domänenabhängig (DOMAIN\\Cert Publishers)' },
  CD: { name: 'Certificate Service DCOM Access', sid: 'S-1-5-32-574', description: 'BUILTIN\\Certificate Service DCOM Access' },
  CG: { name: 'Creator Group', sid: 'S-1-3-1', description: 'CREATOR GROUP' },
  CO: { name: 'Creator Owner', sid: 'S-1-3-0', description: 'CREATOR OWNER' },
  CY: { name: 'Cryptographic Operators', sid: 'S-1-5-32-569', description: 'BUILTIN\\Cryptographic Operators' },
  DA: { name: 'Domain Admins', description: 'Domänenabhängig (DOMAIN\\Domain Admins)' },
  DC: { name: 'Domain Computers', description: 'Domänenabhängig (DOMAIN\\Domain Computers)' },
  DD: { name: 'Domain Controllers', description: 'Domänenabhängig (DOMAIN\\Domain Controllers)' },
  DG: { name: 'Domain Guests', description: 'Domänenabhängig (DOMAIN\\Domain Guests)' },
  DU: { name: 'Domain Users', description: 'Domänenabhängig (DOMAIN\\Domain Users)' },
  EA: { name: 'Enterprise Admins', description: 'Domänenabhängig (DOMAIN\\Enterprise Admins)' },
  ED: { name: 'Enterprise Domain Controllers', sid: 'S-1-5-9', description: 'NT AUTHORITY\\ENTERPRISE DOMAIN CONTROLLERS' },
  ER: { name: 'Event Log Readers', sid: 'S-1-5-32-573', description: 'BUILTIN\\Event Log Readers' },
  HA: { name: 'Hyper-V Administrators', sid: 'S-1-5-32-578', description: 'BUILTIN\\Hyper-V Administrators' },
  IS: { name: 'IIS_IUSRS', sid: 'S-1-5-17', description: 'NT AUTHORITY\\IUSR' },
  IU: { name: 'Interactive Users', sid: 'S-1-5-4', description: 'NT AUTHORITY\\INTERACTIVE' },
  LA: { name: 'Local Administrator', description: 'Lokales Administratorkonto (rechnerabhängig)' },
  LG: { name: 'Local Guest', description: 'Lokales Gastkonto (rechnerabhängig)' },
  LS: { name: 'Local Service', sid: 'S-1-5-19', description: 'NT AUTHORITY\\LOCAL SERVICE' },
  LU: { name: 'Performance Log Users', sid: 'S-1-5-32-559', description: 'BUILTIN\\Performance Log Users' },
  MU: { name: 'Performance Monitor Users', sid: 'S-1-5-32-558', description: 'BUILTIN\\Performance Monitor Users' },
  NO: { name: 'Network Configuration Operators', sid: 'S-1-5-32-556', description: 'BUILTIN\\Network Configuration Operators' },
  NS: { name: 'Network Service', sid: 'S-1-5-20', description: 'NT AUTHORITY\\NETWORK SERVICE' },
  NU: { name: 'Network Logon Users', sid: 'S-1-5-2', description: 'NT AUTHORITY\\NETWORK' },
  OW: { name: 'Owner Rights', sid: 'S-1-3-4', description: 'OWNER RIGHTS' },
  PO: { name: 'Print Operators', sid: 'S-1-5-32-550', description: 'BUILTIN\\Print Operators' },
  PS: { name: 'Principal Self', sid: 'S-1-5-10', description: 'NT AUTHORITY\\SELF' },
  PU: { name: 'Power Users', sid: 'S-1-5-32-547', description: 'BUILTIN\\Power Users' },
  RC: { name: 'Restricted Code', sid: 'S-1-5-12', description: 'NT AUTHORITY\\RESTRICTED' },
  RD: { name: 'Remote Desktop Users', sid: 'S-1-5-32-555', description: 'BUILTIN\\Remote Desktop Users' },
  RE: { name: 'Replicator', sid: 'S-1-5-32-552', description: 'BUILTIN\\Replicator' },
  RM: { name: 'Remote Management Users', sid: 'S-1-5-32-580', description: 'BUILTIN\\Remote Management Users' },
  RS: { name: 'RAS Servers', description: 'Domänenabhängig (DOMAIN\\RAS and IAS Servers)' },
  RU: { name: 'Pre-Windows 2000 Compatible Access', sid: 'S-1-5-32-554', description: 'BUILTIN\\Pre-Windows 2000 Compatible Access' },
  SA: { name: 'Schema Admins', description: 'Domänenabhängig (DOMAIN\\Schema Admins)' },
  SO: { name: 'Server Operators', sid: 'S-1-5-32-549', description: 'BUILTIN\\Server Operators' },
  SU: { name: 'Service Logon Users', sid: 'S-1-5-6', description: 'NT AUTHORITY\\SERVICE' },
  SY: { name: 'SYSTEM', sid: 'S-1-5-18', description: 'NT AUTHORITY\\SYSTEM' },
  WD: { name: 'Everyone', sid: 'S-1-1-0', description: 'Jeder' },
  WR: { name: 'Write Restricted Code', sid: 'S-1-5-33', description: 'NT AUTHORITY\\WRITE RESTRICTED' },
  AC: { name: 'All Application Packages', sid: 'S-1-15-2-1', description: 'APPLICATION PACKAGE AUTHORITY\\ALL APPLICATION PACKAGES' },
  // Integritätsstufen (Mandatory Label)
  LW: { name: 'Low Integrity Level', sid: 'S-1-16-4096', description: 'Mandatory Label\\Low Mandatory Level' },
  ME: { name: 'Medium Integrity Level', sid: 'S-1-16-8192', description: 'Mandatory Label\\Medium Mandatory Level' },
  MP: { name: 'Medium Plus Integrity Level', sid: 'S-1-16-8448', description: 'Mandatory Label\\Medium Plus Mandatory Level' },
  HI: { name: 'High Integrity Level', sid: 'S-1-16-12288', description: 'Mandatory Label\\High Mandatory Level' },
  SI: { name: 'System Integrity Level', sid: 'S-1-16-16384', description: 'Mandatory Label\\System Mandatory Level' },
}

/** Namen bekannter SIDs, damit auch numerische SIDs übersetzt werden */
const SID_TO_ALIAS = new Map<string, { name: string; description?: string }>()
for (const entry of Object.values(SID_ALIASES)) {
  if (entry.sid && !SID_TO_ALIAS.has(entry.sid)) {
    SID_TO_ALIAS.set(entry.sid, { name: entry.name, description: entry.description })
  }
}

const SID_PATTERN = /^S-1-\d+(-\d+)*$/i

export function resolvePrincipal(raw: string): SddlPrincipal {
  const token = raw.trim()
  const alias = SID_ALIASES[token.toUpperCase()]
  if (alias) {
    return {
      raw: token,
      sid: alias.sid,
      name: alias.name,
      description: alias.description,
      domainRelative: !alias.sid,
    }
  }
  if (SID_PATTERN.test(token)) {
    const known = SID_TO_ALIAS.get(token.toUpperCase())
    return {
      raw: token,
      sid: token.toUpperCase(),
      name: known?.name ?? token.toUpperCase(),
      description: known?.description,
      domainRelative: false,
    }
  }
  return { raw: token, name: token, domainRelative: false }
}

/** Zerlegt einen Access Mask in zusammengefasste Rechte (FullControl, Modify, ...) */
export function describeAccessMask(mask: number): { rights: SddlRight[]; detailed: SddlRight[] } {
  const normalized = mask >>> 0
  const rights: SddlRight[] = []
  let remaining = normalized

  for (const combo of RIGHT_COMBINATIONS) {
    if ((remaining & combo.mask) === combo.mask) {
      rights.push(combo)
      remaining &= ~combo.mask
    }
  }

  for (const bit of RIGHT_BITS) {
    if (remaining & bit.mask) {
      rights.push(bit)
      remaining &= ~bit.mask
    }
  }

  for (const generic of GENERIC_BITS) {
    if (remaining & generic.mask) {
      rights.push({ mask: generic.mask, name: generic.code, label: generic.label })
      remaining &= ~generic.mask
    }
  }

  if (remaining & ACCESS_SYSTEM_SECURITY) {
    rights.push({ mask: ACCESS_SYSTEM_SECURITY, name: 'AccessSystemSecurity', label: 'Zugriff auf Systemsicherheit (SACL)' })
    remaining &= ~ACCESS_SYSTEM_SECURITY
  }

  const detailed = RIGHT_BITS.filter(bit => (normalized & bit.mask) !== 0)

  if (remaining !== 0) {
    rights.push({
      mask: remaining,
      name: `0x${remaining.toString(16)}`,
      label: 'Unbekannte Bits',
    })
  }

  return { rights, detailed }
}

function parseRights(raw: string): { mask: number; errors: string[]; warnings: string[] } {
  const errors: string[] = []
  const warnings: string[] = []
  const token = raw.trim()

  if (!token) return { mask: 0, errors, warnings }

  if (/^0x[0-9a-f]+$/i.test(token)) {
    return { mask: parseInt(token.slice(2), 16) >>> 0, errors, warnings }
  }

  if (/^\d+$/.test(token)) {
    return { mask: Number(token) >>> 0, errors, warnings }
  }

  if (token.length % 2 !== 0) {
    errors.push(`Rechte "${token}" können nicht gelesen werden – Kürzel bestehen aus je zwei Zeichen.`)
    return { mask: 0, errors, warnings }
  }

  let mask = 0
  for (let i = 0; i < token.length; i += 2) {
    const code = token.slice(i, i + 2).toUpperCase()
    const alias = RIGHTS_ALIASES[code]
    if (!alias) {
      errors.push(`Unbekanntes Rechte-Kürzel "${code}".`)
      continue
    }
    mask |= alias.mask
    if (NON_FILE_ALIASES.has(code)) {
      warnings.push(`"${code}" (${alias.label}) ist kein Dateisystem-Recht – die Übersetzung ist nur eine Bit-Interpretation.`)
    }
  }

  return { mask: mask >>> 0, errors, warnings }
}

function parseAceFlags(raw: string): { flags: SddlAceFlag[]; errors: string[] } {
  const errors: string[] = []
  const flags: SddlAceFlag[] = []
  const token = raw.trim().toUpperCase()

  if (!token) return { flags, errors }

  if (token.length % 2 !== 0) {
    errors.push(`ACE-Flags "${token}" können nicht gelesen werden – Kürzel bestehen aus je zwei Zeichen.`)
    return { flags, errors }
  }

  for (let i = 0; i < token.length; i += 2) {
    const code = token.slice(i, i + 2)
    const flag = ACE_FLAGS[code]
    if (!flag) {
      errors.push(`Unbekanntes ACE-Flag "${code}".`)
      continue
    }
    flags.push({ code, ...flag })
  }

  return { flags, errors }
}

/** Zerlegt die Klammerausdrücke einer ACL, ohne verschachtelte Bedingungen zu zerreißen */
function splitAces(input: string): { aces: string[]; errors: string[] } {
  const aces: string[] = []
  const errors: string[] = []
  let depth = 0
  let start = -1

  for (let i = 0; i < input.length; i++) {
    const char = input[i]
    if (char === '(') {
      if (depth === 0) start = i
      depth++
    } else if (char === ')') {
      depth--
      if (depth === 0 && start >= 0) {
        aces.push(input.slice(start, i + 1))
        start = -1
      } else if (depth < 0) {
        errors.push('Unerwartete schließende Klammer im ACL-Abschnitt.')
        depth = 0
      }
    }
  }

  if (depth > 0) errors.push('Nicht geschlossene Klammer im ACL-Abschnitt.')

  return { aces, errors }
}

/** Trennt die Felder einer ACE an Semikola der obersten Ebene */
function splitAceFields(body: string): string[] {
  const fields: string[] = []
  let depth = 0
  let current = ''

  for (const char of body) {
    if (char === '(') depth++
    if (char === ')') depth--
    if (char === ';' && depth === 0) {
      fields.push(current)
      current = ''
      continue
    }
    current += char
  }
  fields.push(current)

  return fields
}

function propagationFromFlags(codes: Set<string>): string {
  const noPropagate = codes.has('NP')
  const inheritOnly = codes.has('IO')
  if (noPropagate && inheritOnly) return 'NoPropagateInherit, InheritOnly'
  if (noPropagate) return 'NoPropagateInherit'
  if (inheritOnly) return 'InheritOnly'
  return 'None'
}

const APPLIES_TO_LABELS: Record<string, string> = {
  'ContainerInherit,ObjectInherit|None': 'Diesen Ordner, Unterordner und Dateien',
  '|None': 'Nur diesen Ordner',
  'ContainerInherit|None': 'Diesen Ordner und Unterordner',
  'ObjectInherit|None': 'Diesen Ordner und Dateien',
  'ContainerInherit,ObjectInherit|InheritOnly': 'Nur Unterordner und Dateien',
  'ContainerInherit|InheritOnly': 'Nur Unterordner',
  'ObjectInherit|InheritOnly': 'Nur Dateien',
  'ContainerInherit,ObjectInherit|NoPropagateInherit': 'Diesen Ordner, Unterordner und Dateien (nur eine Ebene)',
  'ContainerInherit|NoPropagateInherit': 'Diesen Ordner und Unterordner (nur eine Ebene)',
  'ObjectInherit|NoPropagateInherit': 'Diesen Ordner und Dateien (nur eine Ebene)',
  'ContainerInherit,ObjectInherit|NoPropagateInherit, InheritOnly': 'Nur direkte Unterordner und Dateien',
  'ContainerInherit|NoPropagateInherit, InheritOnly': 'Nur direkte Unterordner',
  'ObjectInherit|NoPropagateInherit, InheritOnly': 'Nur direkte Dateien',
}

export function appliesToLabel(inheritance: string[], propagation: string): string {
  const key = `${[...inheritance].sort().join(',')}|${propagation}`
  return APPLIES_TO_LABELS[key] ?? 'Benutzerdefiniert'
}

function parseAce(raw: string): SddlAce {
  const warnings: string[] = []
  const body = raw.startsWith('(') && raw.endsWith(')') ? raw.slice(1, -1) : raw
  const fields = splitAceFields(body)

  const [typeField = '', flagField = '', rightsField = '', objectGuid = '', inheritObjectGuid = '', sidField = '', ...rest] =
    fields.map(f => f.trim())

  if (fields.length < 6) {
    warnings.push(`Die ACE hat nur ${fields.length} statt mindestens 6 Feldern.`)
  }

  const aceTypeCode = typeField.toUpperCase()
  const aceType = ACE_TYPES[aceTypeCode]
  if (!aceType) warnings.push(`Unbekannter ACE-Typ "${typeField}".`)

  const { flags, errors: flagErrors } = parseAceFlags(flagField)
  warnings.push(...flagErrors)

  const { mask, errors: rightErrors, warnings: rightWarnings } = parseRights(rightsField)
  warnings.push(...rightErrors, ...rightWarnings)

  const { rights, detailed } = describeAccessMask(mask)

  const flagCodes = new Set(flags.map(f => f.code))
  const inheritance: string[] = []
  if (flagCodes.has('CI')) inheritance.push('ContainerInherit')
  if (flagCodes.has('OI')) inheritance.push('ObjectInherit')
  const propagation = propagationFromFlags(flagCodes)

  const inherited = flagCodes.has('ID')
  if (inherited) {
    warnings.push('Der Eintrag ist geerbt (ID) – geerbte Berechtigungen werden nicht explizit gesetzt.')
  }

  const condition = rest.length > 0 ? rest.join(';').trim() : undefined
  if (condition) {
    warnings.push('Bedingte ACE (Conditional ACE) – die Bedingung wird nicht in die Regel übernommen.')
  }

  if (objectGuid || inheritObjectGuid) {
    warnings.push('Object-GUIDs betreffen Verzeichnisdienst-Objekte und werden für Dateisystemrechte ignoriert.')
  }

  const principal = resolvePrincipal(sidField)
  if (!sidField) warnings.push('Es ist kein Prinzipal (SID) angegeben.')
  if (principal.domainRelative) {
    warnings.push(`"${principal.raw}" ist domänenabhängig – die Regel wird über den Kontonamen aufgelöst.`)
  }

  const hasGeneric = GENERIC_BITS.some(g => (mask & g.mask) !== 0)
  if (hasGeneric) {
    warnings.push('Generische Rechte (GA/GR/GW/GX) werden beim Übernehmen auf die entsprechenden Dateisystemrechte abgebildet.')
  }

  const accessType = aceType?.accessType
  const convertible = Boolean(accessType) && Boolean(sidField) && mask !== 0 && !inherited

  return {
    raw,
    aceType: aceTypeCode,
    aceTypeLabel: aceType?.label ?? `Unbekannt (${typeField})`,
    accessType,
    flags,
    rightsRaw: rightsField,
    accessMask: mask,
    rights,
    detailedRights: detailed,
    objectGuid: objectGuid || undefined,
    inheritObjectGuid: inheritObjectGuid || undefined,
    condition,
    principal,
    inheritance,
    propagation,
    appliesTo: appliesToLabel(inheritance, propagation),
    inherited,
    convertible,
    warnings,
  }
}

function parseAclFlags(raw: string): { flags: SddlAceFlag[]; errors: string[] } {
  const errors: string[] = []
  const flags: SddlAceFlag[] = []
  let rest = raw.trim().toUpperCase()

  if (rest.startsWith('NO_ACCESS_CONTROL')) {
    flags.push({ code: 'NO_ACCESS_CONTROL', ...ACL_FLAGS.NO_ACCESS_CONTROL })
    rest = rest.slice('NO_ACCESS_CONTROL'.length)
  }

  while (rest.length > 0) {
    if (rest.startsWith('P')) {
      flags.push({ code: 'P', ...ACL_FLAGS.P })
      rest = rest.slice(1)
      continue
    }
    const two = rest.slice(0, 2)
    if (two === 'AR' || two === 'AI') {
      flags.push({ code: two, ...ACL_FLAGS[two] })
      rest = rest.slice(2)
      continue
    }
    errors.push(`Unbekanntes ACL-Flag "${rest}".`)
    break
  }

  return { flags, errors }
}

/**
 * Findet die Abschnittsmarker O:/G:/D:/S: außerhalb von Klammern. Werte von
 * Abschnitten (SIDs, Flags, Rechte) enthalten nie einen Doppelpunkt, daher ist
 * jedes [OGDS] direkt vor einem ":" auf oberster Ebene ein Abschnittsbeginn.
 */
function splitSections(input: string): { section: string; value: string }[] {
  const sections: { section: string; value: string }[] = []
  let depth = 0
  let currentSection: string | null = null
  let currentStart = 0
  let leading = ''

  for (let i = 0; i < input.length; i++) {
    const char = input[i]
    if (char === '(') depth++
    else if (char === ')') depth = Math.max(0, depth - 1)

    if (depth === 0 && input[i + 1] === ':' && /[OGDS]/i.test(char)) {
      if (currentSection) {
        sections.push({ section: currentSection, value: input.slice(currentStart, i) })
      } else {
        leading = input.slice(0, i)
      }
      currentSection = char.toUpperCase()
      currentStart = i + 2
      i++
    }
  }

  if (currentSection) {
    sections.push({ section: currentSection, value: input.slice(currentStart) })
  }

  if (leading.trim().length > 0) {
    sections.unshift({ section: '?', value: leading })
  }

  return sections
}

export function parseSddl(input: string): SddlParseResult {
  const errors: string[] = []
  const warnings: string[] = []
  const trimmed = input.trim()

  if (!trimmed) {
    return { ok: false, errors: [], warnings: [] }
  }

  const result: SddlParseResult = { ok: false, errors, warnings }

  // Nur ACEs ohne Abschnittsmarker (z.B. "(A;OICI;0x1301bf;;;BU)") als DACL behandeln
  const sections = trimmed.startsWith('(')
    ? [{ section: 'D', value: trimmed }]
    : splitSections(trimmed)

  if (sections.length === 0) {
    errors.push('Kein gültiger SDDL-Abschnitt gefunden. Erwartet wird z.B. "D:AR(A;OICI;0x1301bf;;;BU)".')
    return result
  }

  for (const { section, value } of sections) {
    if (section === '?') {
      errors.push(`Unerwarteter Text vor dem ersten Abschnitt: "${value.trim()}".`)
      continue
    }

    if (section === 'O' || section === 'G') {
      const token = value.trim()
      if (!token) {
        errors.push(`Der Abschnitt "${section}:" enthält keinen Wert.`)
        continue
      }
      const principal = resolvePrincipal(token)
      if (section === 'O') result.owner = principal
      else result.group = principal
      continue
    }

    const aclSection = section as 'D' | 'S'
    const firstParen = value.indexOf('(')
    const flagPart = firstParen === -1 ? value : value.slice(0, firstParen)
    const acePart = firstParen === -1 ? '' : value.slice(firstParen)

    const { flags, errors: flagErrors } = parseAclFlags(flagPart)
    errors.push(...flagErrors)

    const { aces: aceStrings, errors: aceErrors } = splitAces(acePart)
    errors.push(...aceErrors)

    const aces = aceStrings.map(parseAce)

    if (aclSection === 'S') {
      warnings.push('Der SACL-Abschnitt (S:) beschreibt Überwachung und wird nicht in Zugriffsregeln übernommen.')
    }

    const acl: SddlAcl = { section: aclSection, flags, aces }
    if (aclSection === 'D') result.dacl = acl
    else result.sacl = acl
  }

  if (!result.dacl && !result.sacl && !result.owner && !result.group) {
    errors.push('Der String enthält keine auswertbaren Angaben.')
  }

  if (result.dacl?.flags.some(f => f.code === 'P')) {
    warnings.push('Die DACL ist geschützt (P) – das entspricht dem Modus "Ersetzen" mit deaktivierter Vererbung.')
  }

  result.ok = errors.length === 0 && Boolean(result.dacl || result.sacl || result.owner || result.group)
  return result
}

/** Rechte-Namen für die Übernahme in eine FileSystemAccessRule */
export function toFileSystemRights(ace: SddlAce): string[] {
  let mask = ace.accessMask >>> 0

  for (const generic of GENERIC_BITS) {
    if (mask & generic.mask) {
      mask = (mask & ~generic.mask) | generic.fileMask
    }
  }
  mask &= ~ACCESS_SYSTEM_SECURITY

  const { rights } = describeAccessMask(mask >>> 0)
  const names = rights.map(r => r.name).filter(name => !name.startsWith('0x'))
  return names.length > 0 ? names : ['Read']
}

/** Übersetzt eine Allow/Deny-ACE in eine Regel des Builders */
export function aceToAclRule(ace: SddlAce): Omit<AclRule, 'id'> | null {
  if (!ace.accessType) return null

  const useSid = Boolean(ace.principal.sid)

  return {
    principalType: useSid ? 'sid' : 'name',
    principal: useSid ? ace.principal.sid! : ace.principal.name,
    principalDisplayName: ace.principal.name,
    accessType: ace.accessType,
    permissions: toFileSystemRights(ace),
    inheritance: [...ace.inheritance],
    propagation: ace.propagation,
  }
}

export const SDDL_EXAMPLES = [
  {
    label: 'Benutzer: Ändern (vererbt)',
    value: 'D:AR(A;OICI;0x1301bf;;;BU)',
  },
  {
    label: 'Typische Freigabe',
    value: 'O:BAG:BAD:PAI(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)(A;OICI;0x1301bf;;;AU)',
  },
  {
    label: 'Lesen für Jeder, Vollzugriff Admins',
    value: 'D:P(A;OICI;FR;;;WD)(A;OICI;FA;;;BA)',
  },
  {
    label: 'Zugriff verweigern (nur Unterordner)',
    value: 'D:(D;CIIO;0x1f01ff;;;S-1-5-32-546)',
  },
] as const
