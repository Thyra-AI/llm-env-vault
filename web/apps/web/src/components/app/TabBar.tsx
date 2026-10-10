import { RefreshCw, Settings, Vault } from 'lucide-react'
import { motion } from 'motion/react'
import { useTranslation } from '@workspace/i18n'
import { cn } from '@workspace/ui/lib/utils'
import type { AppTab } from '@/protocol'

const TABS = [
  { id: 'vault', icon: Vault, key: 'vaultApp.tabs.vault' },
  { id: 'generator', icon: RefreshCw, key: 'vaultApp.tabs.generator' },
  { id: 'settings', icon: Settings, key: 'vaultApp.tabs.settings' },
] as const

/** The bottom navigation of the app, like the password-manager popups it follows. */
export function TabBar({ value, onChange }: { value: AppTab; onChange: (tab: AppTab) => void }) {
  const { t } = useTranslation()
  return (
    <nav role="tablist" aria-label={t('app.name')} className="grid shrink-0 grid-cols-3 border-t bg-background/95 backdrop-blur">
      {TABS.map(({ id, icon: Icon, key }) => {
        const active = value === id
        return (
          <button
            key={id}
            type="button"
            role="tab"
            aria-selected={active}
            onClick={() => onChange(id)}
            className={cn(
              'relative flex flex-col items-center gap-1 px-2 pt-2.5 pb-2 text-xs font-medium outline-none transition-colors',
              'focus-visible:bg-muted',
              active ? 'text-primary' : 'text-muted-foreground hover:text-foreground',
            )}
          >
            {active && (
              <motion.span
                layoutId="tab-indicator"
                className="absolute inset-x-6 top-0 h-0.5 rounded-full bg-primary"
                transition={{ type: 'spring', stiffness: 500, damping: 36 }}
              />
            )}
            <motion.span whileTap={{ scale: 0.88 }} className="flex">
              <Icon className="size-5" aria-hidden />
            </motion.span>
            {t(key)}
          </button>
        )
      })}
    </nav>
  )
}
