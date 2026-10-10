import { cn } from '@workspace/ui/lib/utils'
import lockupOnDark from '@/assets/thyra-lockup-on-dark.svg'
import lockupOnLight from '@/assets/thyra-lockup-on-light.svg'

/** Official Thyra lockup (brand/identity/logo). The variant follows the theme via CSS, so there is no flash. */
export function ThyraLogo({ className }: { className?: string }) {
  return (
    <span className={cn('inline-flex', className)}>
      <img src={lockupOnLight} alt="Thyra" className="h-7 w-auto dark:hidden" />
      <img src={lockupOnDark} alt="Thyra" className="hidden h-7 w-auto dark:block" />
    </span>
  )
}
