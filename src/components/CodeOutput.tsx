import { useState } from 'react'
import { Button } from '@/components/ui/button'
import { Copy, Check, Code } from 'lucide-react'

interface CodeOutputProps {
  code: string
}

export function CodeOutput({ code }: CodeOutputProps) {
  const [copied, setCopied] = useState(false)

  const handleCopy = async () => {
    await navigator.clipboard.writeText(code)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <div className="border rounded-lg overflow-hidden">
      <div className="flex items-center justify-between px-4 py-2 bg-muted/50 border-b">
        <div className="flex items-center gap-2 text-sm font-medium">
          <Code className="h-4 w-4" />
          PowerShell
        </div>
        <Button variant="ghost" size="sm" onClick={handleCopy} className="gap-1.5">
          {copied ? <Check className="h-3.5 w-3.5 text-green-600" /> : <Copy className="h-3.5 w-3.5" />}
          {copied ? 'Copied!' : 'Copy'}
        </Button>
      </div>
      <pre className="p-4 overflow-x-auto text-sm leading-relaxed bg-[#1e1e2e] text-[#cdd6f4]">
        <code>{code}</code>
      </pre>
    </div>
  )
}
