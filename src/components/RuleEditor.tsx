import { useState } from 'react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Select } from '@/components/ui/select'
import { Label } from '@/components/ui/label'
import {
  type AclRule,
  WELL_KNOWN_SIDS,
  FILE_SYSTEM_RIGHTS,
  APPLIES_TO_PRESETS,
} from '@/lib/acl-types'
import { Shield, X } from 'lucide-react'

interface RuleEditorProps {
  rule?: AclRule
  onSave: (rule: Omit<AclRule, 'id'>) => void
  onCancel: () => void
}

export function RuleEditor({ rule, onSave, onCancel }: RuleEditorProps) {
  const [principalType, setPrincipalType] = useState<'sid' | 'name'>(rule?.principalType ?? 'sid')
  const [selectedSid, setSelectedSid] = useState(rule?.principalType === 'sid' ? rule.principal : '')
  const [customName, setCustomName] = useState(rule?.principalType === 'name' ? rule.principal : '')
  const [accessType, setAccessType] = useState<'Allow' | 'Deny'>(rule?.accessType ?? 'Allow')
  const [permissions, setPermissions] = useState<string[]>(rule?.permissions ?? ['ReadAndExecute'])
  const [appliesTo, setAppliesTo] = useState(() => {
    if (!rule) return 0
    return APPLIES_TO_PRESETS.findIndex(
      p =>
        arrEq([...p.inheritance], rule.inheritance) &&
        p.propagation === rule.propagation
    )
  })

  function arrEq(a: readonly string[], b: string[]) {
    if (a.length !== b.length) return false
    const sa = [...a].sort()
    const sb = [...b].sort()
    return sa.every((v, i) => v === sb[i])
  }

  const handlePermissionToggle = (perm: string) => {
    if (perm === 'FullControl') {
      setPermissions(['FullControl'])
      return
    }
    const without = permissions.filter(p => p !== 'FullControl')
    if (without.includes(perm)) {
      setPermissions(without.filter(p => p !== perm))
    } else {
      setPermissions([...without, perm])
    }
  }

  const handleSave = () => {
    const principal = principalType === 'sid' ? selectedSid : customName
    if (!principal) return

    const displayName = principalType === 'sid'
      ? WELL_KNOWN_SIDS.find(s => s.sid === selectedSid)?.name ?? selectedSid
      : customName

    const preset = APPLIES_TO_PRESETS[appliesTo] ?? APPLIES_TO_PRESETS[0]

    onSave({
      principalType,
      principal,
      principalDisplayName: displayName,
      accessType,
      permissions: permissions.length > 0 ? permissions : ['ReadAndExecute'],
      inheritance: [...preset.inheritance],
      propagation: preset.propagation,
    })
  }

  const isValid = (principalType === 'sid' ? selectedSid : customName) && permissions.length > 0

  const commonPermissions = FILE_SYSTEM_RIGHTS.slice(0, 6)
  const advancedPermissions = FILE_SYSTEM_RIGHTS.slice(6)
  const [showAdvanced, setShowAdvanced] = useState(false)

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
      <div className="bg-background border rounded-lg shadow-xl w-full max-w-xl max-h-[90vh] overflow-y-auto">
        <div className="flex items-center justify-between p-4 border-b bg-muted/30">
          <div className="flex items-center gap-2">
            <Shield className="h-5 w-5 text-primary" />
            <h3 className="font-semibold">Permission Entry</h3>
          </div>
          <button onClick={onCancel} className="text-muted-foreground hover:text-foreground">
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="p-4 space-y-4">
          <div className="space-y-2">
            <Label>Principal</Label>
            <div className="flex gap-2">
              <Select
                className="w-32 shrink-0"
                value={principalType}
                onChange={e => setPrincipalType(e.target.value as 'sid' | 'name')}
                options={[
                  { value: 'sid', label: 'Well-Known SID' },
                  { value: 'name', label: 'Name' },
                ]}
              />
              {principalType === 'sid' ? (
                <Select
                  className="flex-1"
                  value={selectedSid}
                  onChange={e => setSelectedSid(e.target.value)}
                  placeholder="Select a principal..."
                  options={WELL_KNOWN_SIDS.map(s => ({
                    value: s.sid,
                    label: `${s.name} (${s.sid})`,
                  }))}
                />
              ) : (
                <Input
                  className="flex-1"
                  placeholder="DOMAIN\\User or DOMAIN\\Group"
                  value={customName}
                  onChange={e => setCustomName(e.target.value)}
                />
              )}
            </div>
          </div>

          <div className="space-y-2">
            <Label>Type</Label>
            <Select
              value={accessType}
              onChange={e => setAccessType(e.target.value as 'Allow' | 'Deny')}
              options={[
                { value: 'Allow', label: 'Allow' },
                { value: 'Deny', label: 'Deny' },
              ]}
            />
          </div>

          <div className="space-y-2">
            <Label>Applies to</Label>
            <Select
              value={String(appliesTo)}
              onChange={e => setAppliesTo(Number(e.target.value))}
              options={APPLIES_TO_PRESETS.map((p, i) => ({
                value: String(i),
                label: p.label,
              }))}
            />
          </div>

          <div className="space-y-2">
            <Label>Permissions</Label>
            <div className="border rounded-md p-3 space-y-1">
              {commonPermissions.map(p => (
                <label key={p.value} className="flex items-center gap-2 py-1 hover:bg-muted/50 px-2 rounded cursor-pointer">
                  <input
                    type="checkbox"
                    checked={permissions.includes(p.value)}
                    onChange={() => handlePermissionToggle(p.value)}
                    className="rounded border-primary text-primary focus:ring-primary"
                  />
                  <span className="text-sm">{p.label}</span>
                </label>
              ))}

              {showAdvanced && advancedPermissions.map(p => (
                <label key={p.value} className="flex items-center gap-2 py-1 hover:bg-muted/50 px-2 rounded cursor-pointer">
                  <input
                    type="checkbox"
                    checked={permissions.includes(p.value)}
                    onChange={() => handlePermissionToggle(p.value)}
                    className="rounded border-primary text-primary focus:ring-primary"
                  />
                  <span className="text-sm">{p.label}</span>
                </label>
              ))}

              <button
                onClick={() => setShowAdvanced(!showAdvanced)}
                className="text-xs text-primary hover:underline mt-1 pl-2"
              >
                {showAdvanced ? 'Hide advanced permissions' : 'Show advanced permissions...'}
              </button>
            </div>
          </div>
        </div>

        <div className="flex justify-end gap-2 p-4 border-t bg-muted/30">
          <Button variant="outline" onClick={onCancel}>Cancel</Button>
          <Button disabled={!isValid} onClick={handleSave}>
            {rule ? 'Update' : 'Add'}
          </Button>
        </div>
      </div>
    </div>
  )
}
