import { LogOut, Lock, Plus } from 'lucide-react'
import { AnimatePresence, motion } from 'motion/react'
import { useState } from 'react'
import { toast } from 'sonner'
import { useTranslation } from '@workspace/i18n'
import { Button } from '@workspace/ui/components/button'
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuSeparator, DropdownMenuTrigger } from '@workspace/ui/components/dropdown-menu'
import { TooltipProvider } from '@workspace/ui/components/tooltip'
import { useTheme } from '@workspace/ui/hooks/use-theme'
import type { AppItem, AppPrefs, AppTab, FormValues, Screen } from '@/protocol'
import type { GeneratorOptions } from './generator'
import { GeneratorTab } from './GeneratorTab'
import { LockView } from './LockView'
import { SettingsTab } from './SettingsTab'
import { TabBar } from './TabBar'
import { ALL_KINDS, VaultTab } from './VaultTab'

interface VaultAppProps {
  screen: Screen
  busy: boolean
  onAction: (actionId: string, values: FormValues) => void
}

/** The Bitwarden-style app: lock screen, or header + tab content + bottom navigation. */
export function VaultApp({ screen, busy, onAction }: VaultAppProps) {
  const app = screen.app
  if (!app) return null
  if (app.view === 'lock') return <LockView screen={screen} busy={busy} onAction={onAction} />
  return <Home screen={screen} app={app} busy={busy} onAction={onAction} />
}

function Home({ screen, app, busy, onAction }: VaultAppProps & { app: Extract<NonNullable<Screen['app']>, { view: 'home' }> }) {
  const { t } = useTranslation()
  const { setTheme } = useTheme()
  const [tab, setTab] = useState<AppTab>(app.tab)
  const [search, setSearch] = useState('')
  const [kind, setKind] = useState<string>(ALL_KINDS)

  const send = (id: string, extra: FormValues = {}) => {
    if (!busy) onAction(id, { tab, ...extra })
  }

  const copyName = async (item: AppItem) => {
    try {
      await navigator.clipboard.writeText(item.name)
      toast.success(t('vaultApp.toast.nameCopied'))
    } catch {
      toast.error(t('vaultApp.toast.copy_failed'))
    }
  }

  const changePrefs = (changes: Partial<AppPrefs>) => {
    if (changes.theme && changes.theme !== 'system') setTheme(changes.theme)
    if (changes.theme === 'system') setTheme(matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light')
    send('prefs', { changes })
  }
  const persistGenerator = (generator: GeneratorOptions) => send('prefs', { changes: { generator } })

  const title = t(`vaultApp.tabs.${tab}`)
  return (
    <TooltipProvider delayDuration={300}>
      <div className="mx-auto flex h-dvh w-full max-w-md flex-col border-x bg-background">
        <header className="flex h-14 shrink-0 items-center gap-2 border-b px-4">
          <h1 className="font-heading text-lg font-semibold tracking-tight">{title}</h1>
          <div className="ml-auto flex items-center gap-2">
            {tab === 'vault' && (
              <motion.div whileTap={{ scale: 0.95 }}>
                <Button type="button" className="h-9 rounded-xl px-3.5 font-semibold" disabled={busy} onClick={() => send('add')}>
                  <Plus aria-hidden /> {t('vaultApp.vault.add')}
                </Button>
              </motion.div>
            )}
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <button
                  type="button"
                  aria-label={t('vaultApp.menu.account')}
                  className="flex size-9 items-center justify-center rounded-full bg-primary text-xs font-bold text-primary-foreground outline-none transition-transform hover:scale-105 focus-visible:ring-2 focus-visible:ring-ring/60"
                >
                  TV
                </button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end">
                <DropdownMenuItem onSelect={() => send('lock')}>
                  <Lock aria-hidden /> {t('vaultApp.settings.lockNow')}
                </DropdownMenuItem>
                <DropdownMenuSeparator />
                <DropdownMenuItem variant="destructive" onSelect={() => send('close')}>
                  <LogOut aria-hidden /> {t('vaultApp.menu.close')}
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          </div>
        </header>

        <main className="min-h-0 flex-1 overflow-y-auto">
          <AnimatePresence mode="wait" initial={false}>
            <motion.div key={tab} initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }} transition={{ duration: 0.14 }}>
              {tab === 'vault' && (
                <VaultTab
                  items={app.items}
                  search={search}
                  kind={kind}
                  onSearch={setSearch}
                  onKind={setKind}
                  onCopy={(item) => send(item.type === 'secret' ? `copy:${item.id}` : `icopy:${item.id}`)}
                  onOpen={(item) => send(`view:${item.id}`)}
                  onAdd={() => send('add')}
                  onEdit={(item) => send(item.type === 'secret' ? `edit:${item.id}` : `iedit:${item.id}`)}
                  onDelete={(item) => send(item.type === 'secret' ? `delete:${item.id}` : `idelete:${item.id}`)}
                  onCopyName={copyName}
                />
              )}
              {tab === 'generator' && <GeneratorTab initial={app.prefs.generator} onPersist={persistGenerator} onCopy={(text) => send('gcopy', { text })} />}
              {tab === 'settings' && (
                <SettingsTab prefs={app.prefs} info={app.info} onPrefs={changePrefs} onManage={() => send('manage')} onLock={() => send('lock')} onClose={() => send('close')} />
              )}
            </motion.div>
          </AnimatePresence>
        </main>

        <TabBar value={tab} onChange={setTab} />
      </div>
      <span hidden data-screen={screen.id} />
    </TooltipProvider>
  )
}
