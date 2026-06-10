import { useState } from 'react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Select } from '@/components/ui/select'
import { RuleEditor } from './RuleEditor'
import { CodeOutput } from './CodeOutput'
import {
  type AclRule,
  type AclMode,
  WELL_KNOWN_SIDS,
  getAppliesToLabel,
} from '@/lib/acl-types'
import { generatePowerShell } from '@/lib/codegen'
import {
  Plus,
  Pencil,
  Trash2,
  ShieldCheck,
  ShieldX,
  ArrowUp,
  ArrowDown,
  Shield,
  ChevronDown,
  ChevronRight,
  FolderOpen,
} from 'lucide-react'

const ACL_MODE_OPTIONS = [
  { value: 'replace', label: 'Ersetzen – Alle bestehenden Berechtigungen entfernen und neu setzen' },
  { value: 'add', label: 'Hinzufügen – Regeln zu bestehenden Berechtigungen hinzufügen' },
  { value: 'update', label: 'Aktualisieren – Bestehende Regeln pro Benutzer/SID ersetzen oder hinzufügen' },
]

export function AclBuilder() {
  const [rules, setRules] = useState<AclRule[]>([])
  const [editingRule, setEditingRule] = useState<AclRule | null>(null)
  const [isAdding, setIsAdding] = useState(false)
  const [variableName, setVariableName] = useState('$aclPath')
  const [filePath, setFilePath] = useState('')
  const [aclMode, setAclMode] = useState<AclMode>('replace')
  const [showAdvanced, setShowAdvanced] = useState(false)

  const effectiveVariable = filePath || variableName

  const addRule = (rule: Omit<AclRule, 'id'>) => {
    setRules(prev => [...prev, { ...rule, id: crypto.randomUUID() }])
    setIsAdding(false)
  }

  const updateRule = (rule: Omit<AclRule, 'id'>) => {
    if (!editingRule) return
    setRules(prev => prev.map(r => r.id === editingRule.id ? { ...rule, id: r.id } : r))
    setEditingRule(null)
  }

  const deleteRule = (id: string) => {
    setRules(prev => prev.filter(r => r.id !== id))
  }

  const moveRule = (id: string, direction: 'up' | 'down') => {
    setRules(prev => {
      const idx = prev.findIndex(r => r.id === id)
      if (idx === -1) return prev
      const newIdx = direction === 'up' ? idx - 1 : idx + 1
      if (newIdx < 0 || newIdx >= prev.length) return prev
      const copy = [...prev]
      ;[copy[idx], copy[newIdx]] = [copy[newIdx], copy[idx]]
      return copy
    })
  }

  const code = generatePowerShell(rules, effectiveVariable, aclMode)

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center gap-3">
        <div className="p-2 rounded-lg bg-primary/10">
          <Shield className="h-6 w-6 text-primary" />
        </div>
        <div>
          <h1 className="text-xl font-bold">PowerShell ACL Builder</h1>
          <p className="text-sm text-muted-foreground">
            Define NTFS permissions visually and generate PowerShell code
          </p>
        </div>
      </div>

      {/* Path & Mode Configuration */}
      <div className="border rounded-lg overflow-hidden">
        <div className="px-4 py-3 bg-muted/30 border-b">
          <h2 className="font-semibold text-sm">Ziel & Modus</h2>
        </div>
        <div className="p-4 space-y-4">
          {/* File Path Input */}
          <div className="space-y-2">
            <Label className="flex items-center gap-1.5">
              <FolderOpen className="h-3.5 w-3.5" />
              Dateipfad
            </Label>
            <Input
              value={filePath}
              onChange={e => setFilePath(e.target.value)}
              placeholder="z.B. C:\Shares\Daten oder leer lassen für Variable"
              className="font-mono"
            />
            <p className="text-xs text-muted-foreground">
              {filePath
                ? <>Der Pfad wird direkt im generierten Code verwendet: <code className="bg-muted px-1 rounded">{effectiveVariable}</code></>
                : <>Kein Pfad angegeben – es wird die Variable <code className="bg-muted px-1 rounded">{variableName}</code> verwendet</>
              }
            </p>
          </div>

          {/* ACL Mode */}
          <div className="space-y-2">
            <Label>Modus</Label>
            <Select
              value={aclMode}
              onChange={e => setAclMode(e.target.value as AclMode)}
              options={ACL_MODE_OPTIONS}
              className="max-w-2xl"
            />
          </div>

          {/* Advanced: Variable Name */}
          <div>
            <button
              onClick={() => setShowAdvanced(!showAdvanced)}
              className="flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground transition-colors"
            >
              {showAdvanced ? <ChevronDown className="h-3 w-3" /> : <ChevronRight className="h-3 w-3" />}
              Erweitert
            </button>
            {showAdvanced && (
              <div className="mt-2 pl-4 border-l-2 border-muted space-y-2">
                <Label className="text-xs">Variablenname</Label>
                <Input
                  value={variableName}
                  onChange={e => setVariableName(e.target.value)}
                  placeholder="$aclPath"
                  className="max-w-xs font-mono text-sm h-8"
                  disabled={!!filePath}
                />
                <p className="text-xs text-muted-foreground">
                  {filePath
                    ? 'Wird ignoriert, wenn ein Dateipfad angegeben ist'
                    : 'PowerShell-Variable, die im generierten Code verwendet wird'
                  }
                </p>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Permission Entries - Windows-style table */}
      <div className="border rounded-lg overflow-hidden">
        <div className="flex items-center justify-between px-4 py-3 bg-muted/30 border-b">
          <h2 className="font-semibold text-sm">Permission Entries</h2>
          <Button size="sm" onClick={() => setIsAdding(true)} className="gap-1.5">
            <Plus className="h-3.5 w-3.5" />
            Add
          </Button>
        </div>

        {rules.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
            <Shield className="h-10 w-10 mb-3 opacity-30" />
            <p className="text-sm">No permission entries defined</p>
            <p className="text-xs mt-1">Click "Add" to create a new permission entry</p>
          </div>
        ) : (
          <div className="divide-y">
            {/* Table Header */}
            <div className="grid grid-cols-[1fr_100px_1fr_1fr_auto] gap-2 px-4 py-2 bg-muted/20 text-xs font-medium text-muted-foreground">
              <div>Principal</div>
              <div>Type</div>
              <div>Permission</div>
              <div>Applies to</div>
              <div className="w-24"></div>
            </div>

            {/* Rules */}
            {rules.map((rule, idx) => (
              <div
                key={rule.id}
                className="grid grid-cols-[1fr_100px_1fr_1fr_auto] gap-2 px-4 py-2.5 items-center hover:bg-muted/20 text-sm group"
              >
                <div className="flex items-center gap-2 min-w-0">
                  {rule.accessType === 'Allow' ? (
                    <ShieldCheck className="h-4 w-4 text-green-600 shrink-0" />
                  ) : (
                    <ShieldX className="h-4 w-4 text-destructive shrink-0" />
                  )}
                  <div className="truncate">
                    <div className="font-medium truncate">{rule.principalDisplayName}</div>
                    <div className="text-xs text-muted-foreground truncate">
                      {rule.principalType === 'sid'
                        ? WELL_KNOWN_SIDS.find(s => s.sid === rule.principal)?.description ?? rule.principal
                        : rule.principal}
                    </div>
                  </div>
                </div>

                <div>
                  <span className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ${
                    rule.accessType === 'Allow'
                      ? 'bg-green-100 text-green-800'
                      : 'bg-red-100 text-red-800'
                  }`}>
                    {rule.accessType}
                  </span>
                </div>

                <div className="text-xs truncate" title={rule.permissions.join(', ')}>
                  {rule.permissions.join(', ')}
                </div>

                <div className="text-xs text-muted-foreground truncate">
                  {getAppliesToLabel(rule.inheritance, rule.propagation)}
                </div>

                <div className="flex items-center gap-0.5 opacity-0 group-hover:opacity-100 transition-opacity">
                  <button
                    onClick={() => moveRule(rule.id, 'up')}
                    disabled={idx === 0}
                    className="p-1 rounded hover:bg-muted disabled:opacity-30"
                  >
                    <ArrowUp className="h-3.5 w-3.5" />
                  </button>
                  <button
                    onClick={() => moveRule(rule.id, 'down')}
                    disabled={idx === rules.length - 1}
                    className="p-1 rounded hover:bg-muted disabled:opacity-30"
                  >
                    <ArrowDown className="h-3.5 w-3.5" />
                  </button>
                  <button
                    onClick={() => setEditingRule(rule)}
                    className="p-1 rounded hover:bg-muted text-primary"
                  >
                    <Pencil className="h-3.5 w-3.5" />
                  </button>
                  <button
                    onClick={() => deleteRule(rule.id)}
                    className="p-1 rounded hover:bg-muted text-destructive"
                  >
                    <Trash2 className="h-3.5 w-3.5" />
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Generated Code */}
      {rules.length > 0 && (
        <div className="space-y-2">
          <h2 className="font-semibold text-sm">Generated PowerShell Code</h2>
          <CodeOutput code={code} />
        </div>
      )}

      {/* Rule Editor Modal */}
      {isAdding && (
        <RuleEditor
          onSave={addRule}
          onCancel={() => setIsAdding(false)}
        />
      )}
      {editingRule && (
        <RuleEditor
          rule={editingRule}
          onSave={updateRule}
          onCancel={() => setEditingRule(null)}
        />
      )}
    </div>
  )
}
