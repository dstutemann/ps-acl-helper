import { useMemo, useState, type ReactNode } from 'react'
import { Button } from '@/components/ui/button'
import { Textarea } from '@/components/ui/textarea'
import { Label } from '@/components/ui/label'
import type { AclRule } from '@/lib/acl-types'
import {
  parseSddl,
  aceToAclRule,
  SDDL_EXAMPLES,
  type SddlAce,
  type SddlAcl,
  type SddlPrincipal,
} from '@/lib/sddl'
import {
  AlertTriangle,
  ChevronDown,
  ChevronRight,
  FileCode2,
  Info,
  ShieldCheck,
  ShieldX,
  Shield,
  XCircle,
} from 'lucide-react'

interface SddlImportProps {
  onApply: (rules: Omit<AclRule, 'id'>[]) => void
}

export function SddlImport({ onApply }: SddlImportProps) {
  const [open, setOpen] = useState(false)
  const [input, setInput] = useState('')
  const [applied, setApplied] = useState<number | null>(null)

  const result = useMemo(() => parseSddl(input), [input])

  const convertibleAces = useMemo(
    () => (result.dacl?.aces ?? []).filter(ace => ace.convertible),
    [result]
  )

  const handleApply = () => {
    const rules = convertibleAces
      .map(aceToAclRule)
      .filter((r): r is Omit<AclRule, 'id'> => r !== null)
    if (rules.length === 0) return
    onApply(rules)
    setApplied(rules.length)
    setTimeout(() => setApplied(null), 3000)
  }

  const hasInput = input.trim().length > 0

  return (
    <div className="border rounded-lg overflow-hidden">
      <button
        onClick={() => setOpen(!open)}
        className="flex items-center justify-between w-full px-4 py-3 bg-muted/30 border-b hover:bg-muted/50 transition-colors"
      >
        <div className="flex items-center gap-2">
          {open ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
          <FileCode2 className="h-4 w-4 text-primary" />
          <h2 className="font-semibold text-sm">SDDL / Permission-String übersetzen</h2>
        </div>
        <span className="text-xs text-muted-foreground font-mono hidden sm:inline">
          D:AR(A;OICI;0x1301bf;;;BU)
        </span>
      </button>

      {open && (
        <div className="p-4 space-y-4">
          <div className="space-y-2">
            <Label>SDDL-String</Label>
            <Textarea
              value={input}
              onChange={e => setInput(e.target.value)}
              placeholder="z.B. D:AR(A;OICI;0x1301bf;;;BU)"
              className="font-mono text-sm"
              spellCheck={false}
              rows={3}
            />
            <div className="flex flex-wrap items-center gap-1.5">
              <span className="text-xs text-muted-foreground">Beispiele:</span>
              {SDDL_EXAMPLES.map(example => (
                <button
                  key={example.value}
                  onClick={() => setInput(example.value)}
                  className="text-xs px-2 py-0.5 rounded-full border hover:bg-muted transition-colors"
                  title={example.value}
                >
                  {example.label}
                </button>
              ))}
              {hasInput && (
                <button
                  onClick={() => setInput('')}
                  className="text-xs px-2 py-0.5 rounded-full border hover:bg-muted transition-colors text-muted-foreground"
                >
                  Zurücksetzen
                </button>
              )}
            </div>
            <p className="text-xs text-muted-foreground">
              Unterstützt werden die Abschnitte <code className="bg-muted px-1 rounded">O:</code> Besitzer,{' '}
              <code className="bg-muted px-1 rounded">G:</code> Gruppe, <code className="bg-muted px-1 rounded">D:</code> DACL
              und <code className="bg-muted px-1 rounded">S:</code> SACL – oder einzelne ACEs wie{' '}
              <code className="bg-muted px-1 rounded">(A;OICI;FA;;;BA)</code>.
            </p>
          </div>

          {hasInput && result.errors.length > 0 && (
            <div className="rounded-md border border-destructive/40 bg-destructive/5 p-3 space-y-1">
              {result.errors.map((error, i) => (
                <div key={i} className="flex items-start gap-2 text-sm text-destructive">
                  <XCircle className="h-4 w-4 mt-0.5 shrink-0" />
                  <span>{error}</span>
                </div>
              ))}
            </div>
          )}

          {hasInput && (result.owner || result.group) && (
            <div className="grid gap-2 sm:grid-cols-2">
              {result.owner && <PrincipalCard title="Besitzer (O:)" principal={result.owner} />}
              {result.group && <PrincipalCard title="Primäre Gruppe (G:)" principal={result.group} />}
            </div>
          )}

          {result.dacl && <AclSection title="DACL – Zugriffsberechtigungen (D:)" acl={result.dacl} />}
          {result.sacl && <AclSection title="SACL – Überwachung (S:)" acl={result.sacl} />}

          {hasInput && result.warnings.length > 0 && (
            <div className="rounded-md border border-amber-300 bg-amber-50 p-3 space-y-1">
              {result.warnings.map((warning, i) => (
                <div key={i} className="flex items-start gap-2 text-sm text-amber-900">
                  <Info className="h-4 w-4 mt-0.5 shrink-0" />
                  <span>{warning}</span>
                </div>
              ))}
            </div>
          )}

          {result.dacl && result.dacl.aces.length > 0 && (
            <div className="flex flex-wrap items-center gap-3 pt-1">
              <Button onClick={handleApply} disabled={convertibleAces.length === 0}>
                {convertibleAces.length > 0
                  ? `${convertibleAces.length} ${convertibleAces.length === 1 ? 'Eintrag' : 'Einträge'} übernehmen`
                  : 'Keine übernehmbaren Einträge'}
              </Button>
              {applied !== null && (
                <span className="text-sm text-green-700">
                  {applied} {applied === 1 ? 'Regel' : 'Regeln'} zur Liste hinzugefügt
                </span>
              )}
              {convertibleAces.length < result.dacl.aces.length && (
                <span className="text-xs text-muted-foreground">
                  {result.dacl.aces.length - convertibleAces.length} Eintrag/Einträge werden übersprungen (geerbt,
                  ohne Rechte oder kein Allow/Deny)
                </span>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  )
}

function PrincipalCard({ title, principal }: { title: string; principal: SddlPrincipal }) {
  return (
    <div className="border rounded-md p-3">
      <div className="text-xs text-muted-foreground">{title}</div>
      <div className="font-medium text-sm mt-0.5">{principal.name}</div>
      <div className="text-xs text-muted-foreground font-mono">
        {principal.raw}
        {principal.sid && principal.sid !== principal.raw ? ` → ${principal.sid}` : ''}
      </div>
      {principal.description && (
        <div className="text-xs text-muted-foreground mt-1">{principal.description}</div>
      )}
    </div>
  )
}

function AclSection({ title, acl }: { title: string; acl: SddlAcl }) {
  return (
    <div className="border rounded-md overflow-hidden">
      <div className="px-3 py-2 bg-muted/30 border-b">
        <div className="font-medium text-sm">{title}</div>
        {acl.flags.length > 0 && (
          <div className="flex flex-wrap gap-1.5 mt-1.5">
            {acl.flags.map(flag => (
              <span
                key={flag.code}
                className="inline-flex items-center gap-1 rounded-full bg-primary/10 text-primary px-2 py-0.5 text-xs"
                title={flag.description}
              >
                <span className="font-mono font-semibold">{flag.code}</span>
                <span>{flag.label}</span>
              </span>
            ))}
          </div>
        )}
      </div>

      {acl.aces.length === 0 ? (
        <div className="px-3 py-4 text-sm text-muted-foreground">
          Keine Einträge in diesem Abschnitt
        </div>
      ) : (
        <div className="divide-y">
          {acl.aces.map((ace, i) => (
            <AceRow key={`${ace.raw}-${i}`} ace={ace} />
          ))}
        </div>
      )}
    </div>
  )
}

function AceRow({ ace }: { ace: SddlAce }) {
  const [showDetails, setShowDetails] = useState(false)

  const icon =
    ace.accessType === 'Allow' ? (
      <ShieldCheck className="h-4 w-4 text-green-600 shrink-0" />
    ) : ace.accessType === 'Deny' ? (
      <ShieldX className="h-4 w-4 text-destructive shrink-0" />
    ) : (
      <Shield className="h-4 w-4 text-muted-foreground shrink-0" />
    )

  return (
    <div className="p-3 space-y-2">
      <div className="flex items-start gap-2">
        {icon}
        <div className="min-w-0 flex-1 space-y-1">
          <code className="text-xs font-mono text-muted-foreground break-all">{ace.raw}</code>

          <div className="grid gap-x-4 gap-y-1 sm:grid-cols-2 text-sm">
            <Field label="Typ" value={ace.aceTypeLabel} />
            <Field
              label="Prinzipal"
              value={
                <>
                  {ace.principal.name}
                  {ace.principal.sid && ace.principal.sid !== ace.principal.name && (
                    <span className="text-xs text-muted-foreground font-mono"> ({ace.principal.sid})</span>
                  )}
                  {ace.principal.domainRelative && (
                    <span className="text-xs text-muted-foreground"> – domänenabhängig</span>
                  )}
                </>
              }
            />
            <Field
              label="Rechte"
              value={
                <>
                  {ace.rights.length > 0 ? ace.rights.map(r => r.label).join(', ') : 'Keine'}
                  <span className="text-xs text-muted-foreground font-mono"> ({rightsSource(ace)})</span>
                </>
              }
            />
            <Field label="Gilt für" value={ace.appliesTo} />
          </div>

          {ace.flags.length > 0 && (
            <div className="flex flex-wrap gap-1.5 pt-0.5">
              {ace.flags.map(flag => (
                <span
                  key={flag.code}
                  className="inline-flex items-center gap-1 rounded-full bg-muted px-2 py-0.5 text-xs"
                  title={flag.description}
                >
                  <span className="font-mono font-semibold">{flag.code}</span>
                  <span className="text-muted-foreground">{flag.label}</span>
                </span>
              ))}
            </div>
          )}

          {ace.detailedRights.length > 0 && (
            <>
              <button
                onClick={() => setShowDetails(!showDetails)}
                className="text-xs text-primary hover:underline"
              >
                {showDetails ? 'Einzelrechte ausblenden' : 'Einzelrechte anzeigen'}
              </button>
              {showDetails && (
                <ul className="mt-1 grid gap-0.5 sm:grid-cols-2 text-xs text-muted-foreground">
                  {ace.detailedRights.map(right => (
                    <li key={right.name} className="flex items-center gap-1.5">
                      <span className="font-mono">0x{right.mask.toString(16).padStart(5, '0')}</span>
                      <span>{right.label}</span>
                    </li>
                  ))}
                </ul>
              )}
            </>
          )}

          {ace.condition && (
            <div className="text-xs">
              <span className="text-muted-foreground">Bedingung: </span>
              <code className="font-mono break-all">{ace.condition}</code>
            </div>
          )}

          {ace.warnings.length > 0 && (
            <div className="space-y-0.5 pt-0.5">
              {ace.warnings.map((warning, i) => (
                <div key={i} className="flex items-start gap-1.5 text-xs text-amber-700">
                  <AlertTriangle className="h-3.5 w-3.5 mt-0.5 shrink-0" />
                  <span>{warning}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

/** Zeigt das Rechte-Kürzel und den Access Mask, ohne den Hex-Wert zu doppeln */
function rightsSource(ace: SddlAce): string {
  const hex = `0x${(ace.accessMask >>> 0).toString(16)}`
  if (!ace.rightsRaw) return hex
  if (ace.rightsRaw.toLowerCase() === hex) return hex
  return `${ace.rightsRaw} = ${hex}`
}

function Field({ label, value }: { label: string; value: ReactNode }) {
  return (
    <div className="flex gap-1.5 min-w-0">
      <span className="text-muted-foreground shrink-0">{label}:</span>
      <span className="min-w-0 break-words">{value}</span>
    </div>
  )
}
