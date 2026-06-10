import * as React from "react"
import { cn } from "@/lib/utils"
import { Check } from "lucide-react"

export interface CheckboxProps extends Omit<React.InputHTMLAttributes<HTMLInputElement>, 'type'> {
  label?: string
}

const Checkbox = React.forwardRef<HTMLInputElement, CheckboxProps>(
  ({ className, label, id, ...props }, ref) => {
    const checkboxId = id || React.useId()
    return (
      <div className="flex items-center gap-2">
        <div className="relative">
          <input
            type="checkbox"
            id={checkboxId}
            className="peer sr-only"
            ref={ref}
            {...props}
          />
          <div className={cn(
            "h-4 w-4 shrink-0 rounded-sm border border-primary shadow-sm peer-focus-visible:ring-1 peer-focus-visible:ring-ring peer-checked:bg-primary peer-checked:text-primary-foreground flex items-center justify-center cursor-pointer",
            className
          )}>
            <Check className="h-3 w-3 hidden peer-checked:block" />
          </div>
        </div>
        {label && (
          <label htmlFor={checkboxId} className="text-sm cursor-pointer select-none">
            {label}
          </label>
        )}
      </div>
    )
  }
)
Checkbox.displayName = "Checkbox"

export { Checkbox }
