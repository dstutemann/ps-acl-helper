import type { AclRule, AclMode } from './acl-types'

function inheritanceVarName(flags: string): string {
  if (flags === 'None') return '$inheritNone'
  const parts = flags.split(', ').map(f => f.replace('Inherit', ''))
  return `$inherit${parts.join('And')}`
}

function propagationVarName(flags: string): string {
  const parts = flags.split(', ').map(f => {
    if (f === 'None') return 'None'
    if (f === 'InheritOnly') return 'InheritOnly'
    if (f === 'NoPropagateInherit') return 'NoPropagate'
    return f
  })
  return `$propagation${parts.join('')}`
}

export function generatePowerShell(rules: AclRule[], variableName: string, mode: AclMode): string {
  if (rules.length === 0) return '# No ACL rules defined'

  const lines: string[] = []

  const isVariable = variableName.trim().startsWith('$')
  const pathVar = isVariable ? variableName.trim() : '$aclPath'

  if (!isVariable) {
    lines.push(`${pathVar} = '${variableName}'`)
  }

  lines.push(`$acl = Get-Acl -LiteralPath ${pathVar}`)

  if (mode === 'replace') {
    lines.push(`$acl.SetAccessRuleProtection($true, $false)`)
    lines.push(`@($acl.Access) | ForEach-Object { [void]$acl.RemoveAccessRule($_) }`)
  }

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
    const varName = inheritanceVarName(inh)
    lines.push(`${varName} = [System.Security.AccessControl.InheritanceFlags]'${inh}'`)
    inheritVars.set(inh, varName)
  } else {
    for (const inh of usedInheritances) {
      const varName = inheritanceVarName(inh)
      lines.push(`${varName} = [System.Security.AccessControl.InheritanceFlags]'${inh}'`)
      inheritVars.set(inh, varName)
    }
  }

  if (usedPropagations.size === 1) {
    const prop = [...usedPropagations][0]
    const varName = propagationVarName(prop)
    const propValue = prop.includes(', ')
      ? prop.split(', ').map(p => `[System.Security.AccessControl.PropagationFlags]::${p}`).join(' -bor ')
      : `[System.Security.AccessControl.PropagationFlags]::${prop}`
    lines.push(`${varName} = ${propValue}`)
    propVars.set(prop, varName)
  } else {
    for (const prop of usedPropagations) {
      const varName = propagationVarName(prop)
      const propValue = prop.includes(', ')
        ? prop.split(', ').map(p => `[System.Security.AccessControl.PropagationFlags]::${p}`).join(' -bor ')
        : `[System.Security.AccessControl.PropagationFlags]::${prop}`
      lines.push(`${varName} = ${propValue}`)
      propVars.set(prop, varName)
    }
  }

  lines.push(``)
  lines.push(`$rules = @(`)

  for (const rule of rules) {
    const inhKey = rule.inheritance.length > 0 ? rule.inheritance.sort().join(', ') : 'None'
    const inhVar = inheritVars.get(inhKey)!
    const propVar = propVars.get(rule.propagation)!
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

  if (mode === 'update') {
    lines.push(`foreach ($rule in $rules) {`)
    lines.push(`    $existing = $acl.Access | Where-Object { $_.IdentityReference.Value -eq $rule.IdentityReference.Value -and $_.AccessControlType -eq $rule.AccessControlType }`)
    lines.push(`    foreach ($old in $existing) { [void]$acl.RemoveAccessRule($old) }`)
    lines.push(`    $acl.AddAccessRule($rule)`)
    lines.push(`}`)
  } else {
    lines.push(`$rules | ForEach-Object { $acl.AddAccessRule($_) }`)
  }

  lines.push(``)
  lines.push(`Set-Acl -LiteralPath ${pathVar} -AclObject $acl`)

  return lines.join('\n')
}
