import type { AclRule } from './acl-types'

export function generatePowerShell(rules: AclRule[], variableName: string): string {
  if (rules.length === 0) return '# No ACL rules defined'

  const lines: string[] = []
  lines.push(`$acl = Get-Acl -LiteralPath ${variableName}`)
  lines.push(`$acl.SetAccessRuleProtection($true, $false)`)
  lines.push(`@($acl.Access) | ForEach-Object { [void]$acl.RemoveAccessRule($_) }`)
  lines.push(``)

  const usedInheritances = new Set<string>()
  const usedPropagations = new Set<string>()

  for (const rule of rules) {
    const inhKey = rule.inheritance.length > 0 ? rule.inheritance.sort().join(', ') : 'None'
    usedInheritances.add(inhKey)
    usedPropagations.add(rule.propagation)
  }

  const inheritVars = new Map<string, string>()
  const propVars = new Map<string, string>()

  if (usedInheritances.size === 1) {
    const inh = [...usedInheritances][0]
    lines.push(`$inherit = [System.Security.AccessControl.InheritanceFlags]'${inh}'`)
    inheritVars.set(inh, '$inherit')
  } else {
    let idx = 0
    for (const inh of usedInheritances) {
      const varName = idx === 0 ? '$inherit' : `$inherit${idx + 1}`
      lines.push(`${varName} = [System.Security.AccessControl.InheritanceFlags]'${inh}'`)
      inheritVars.set(inh, varName)
      idx++
    }
  }

  if (usedPropagations.size === 1) {
    const prop = [...usedPropagations][0]
    lines.push(`$propagation = [System.Security.AccessControl.PropagationFlags]::${prop.replace(', ', ' -bor [System.Security.AccessControl.PropagationFlags]::')}`)
    propVars.set(prop, '$propagation')
  } else {
    let idx = 0
    for (const prop of usedPropagations) {
      const varName = idx === 0 ? '$propagation' : `$propagation${idx + 1}`
      const propValue = prop.includes(', ')
        ? prop.split(', ').map(p => `[System.Security.AccessControl.PropagationFlags]::${p}`).join(' -bor ')
        : `[System.Security.AccessControl.PropagationFlags]::${prop}`
      lines.push(`${varName} = ${propValue}`)
      propVars.set(prop, varName)
      idx++
    }
  }

  lines.push(``)
  lines.push(`$rules = @(`)

  for (let i = 0; i < rules.length; i++) {
    const rule = rules[i]
    const inhKey = rule.inheritance.length > 0 ? rule.inheritance.sort().join(', ') : 'None'
    const inhVar = inheritVars.get(inhKey) ?? '$inherit'
    const propVar = propVars.get(rule.propagation) ?? '$propagation'
    const permissions = rule.permissions.join(', ')

    const principal = rule.principalType === 'sid'
      ? `[System.Security.Principal.SecurityIdentifier]'${rule.principal}'`
      : `[System.Security.Principal.NTAccount]'${rule.principal}'`

    const comment = `    # ${rule.principalDisplayName}`
    const ruleStr = `    [System.Security.AccessControl.FileSystemAccessRule]::new(${principal}, '${permissions}', ${inhVar}, ${propVar}, '${rule.accessType}')`

    lines.push(comment)
    lines.push(ruleStr)
  }

  lines.push(`)`)
  lines.push(``)
  lines.push(`$rules | ForEach-Object { $acl.AddAccessRule($_) }`)
  lines.push(``)
  lines.push(`Set-Acl -LiteralPath ${variableName} -AclObject $acl`)

  return lines.join('\n')
}
