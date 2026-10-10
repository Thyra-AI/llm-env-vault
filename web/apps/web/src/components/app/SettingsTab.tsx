import { ArrowLeft, ChevronRight, Info, Lock, LogOut, Palette, ShieldCheck, SlidersHorizontal, TriangleAlert, type LucideIcon } from 'lucide-react'
import { AnimatePresence, motion } from 'motion/react'
import { useState } from 'react'
import { LANGUAGES, useTranslation } from '@workspace/i18n'
import { Button } from '@workspace/ui/components/button'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@workspace/ui/components/select'
import { ToggleGroup, ToggleGroupItem } from '@workspace/ui/components/toggle-group'
import { cn } from '@workspace/ui/lib/utils'
import { ThyraLogo } from '@/components/molecules'
import type { AppInfo, AppPrefs } from '@/protocol'

const AUTO_LOCK = [1, 2, 5, 10, 15, 30, 60]
const CLIPBOARD = [10, 20, 30, 60, 120]

type Page = 'options' | 'appearance' | 'about'

function Row({ icon: Icon, label, onClick, tone }: { icon: LucideIcon; label: string; onClick: () => void; tone?: 'danger' }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={cn(
        'flex w-full items-center gap-3 rounded-xl border bg-card px-3.5 py-3 text-left text-sm font-medium outline-none transition-colors',
        'hover:border-primary/40 hover:bg-muted/60 focus-visible:ring-2 focus-visible:ring-ring/50',
        tone === 'danger' && 'text-destructive',
      )}
    >
      <Icon className="size-[18px] shrink-0" aria-hidden />
      <span className="flex-1">{label}</span>
      <ChevronRight className="size-4 text-muted-foreground" aria-hidden />
    </button>
  )
}

function Setting({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex flex-col gap-2 rounded-xl border bg-card p-4">
      <span className="text-sm font-medium">{label}</span>
      {children}
    </div>
  )
}

interface SettingsTabProps {
  prefs: AppPrefs
  info: AppInfo
  onPrefs: (changes: Partial<AppPrefs>) => void
  onManage: () => void
  onLock: () => void
  onClose: () => void
}

export function SettingsTab({ prefs, info, onPrefs, onManage, onLock, onClose }: SettingsTabProps) {
  const { t, i18n } = useTranslation()
  const [page, setPage] = useState<Page | null>(null)

  const titles: Record<Page, string> = {
    options: t('vaultApp.settings.vaultOptions'),
    appearance: t('vaultApp.settings.appearance'),
    about: t('vaultApp.settings.about'),
  }

  return (
    <AnimatePresence mode="wait" initial={false}>
      <motion.div
        key={page ?? 'root'}
        initial={{ opacity: 0, x: page ? 16 : -16 }}
        animate={{ opacity: 1, x: 0 }}
        exit={{ opacity: 0, x: page ? -16 : 16 }}
        transition={{ duration: 0.16 }}
        className="flex flex-col gap-3 px-4 pt-3 pb-5"
      >
        {page === null && (
          <>
            {!info.recovery && (
              <button
                type="button"
                onClick={onManage}
                className="flex items-start gap-2.5 rounded-xl border border-primary/30 bg-primary/10 px-3.5 py-3 text-left text-sm outline-none focus-visible:ring-2 focus-visible:ring-ring/50"
              >
                <TriangleAlert className="mt-0.5 size-4 shrink-0 text-primary" aria-hidden />
                <span>
                  {t('vaultApp.settings.noRecovery')} <strong className="text-primary">{t('vaultApp.settings.noRecoveryAction')}</strong>
                </span>
              </button>
            )}
            <Row icon={ShieldCheck} label={t('vaultApp.settings.accountSecurity')} onClick={onManage} />
            <Row icon={SlidersHorizontal} label={t('vaultApp.settings.vaultOptions')} onClick={() => setPage('options')} />
            <Row icon={Palette} label={t('vaultApp.settings.appearance')} onClick={() => setPage('appearance')} />
            <Row icon={Info} label={t('vaultApp.settings.about')} onClick={() => setPage('about')} />
            <Row icon={Lock} label={t('vaultApp.settings.lockNow')} onClick={onLock} />
            <Row icon={LogOut} label={t('vaultApp.menu.close')} onClick={onClose} tone="danger" />
          </>
        )}

        {page !== null && (
          <>
            <Button type="button" variant="ghost" size="sm" className="-ml-2 w-fit" onClick={() => setPage(null)}>
              <ArrowLeft aria-hidden /> {titles[page]}
            </Button>

            {page === 'options' && (
              <>
                <Setting label={t('vaultApp.settings.autoLock')}>
                  <Select value={String(prefs.autoLockMinutes)} onValueChange={(v) => onPrefs({ autoLockMinutes: Number(v) })}>
                    <SelectTrigger className="h-10 w-full rounded-xl" aria-label={t('vaultApp.settings.autoLock')}>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {AUTO_LOCK.map((m) => (
                        <SelectItem key={m} value={String(m)}>{t('vaultApp.settings.minutes', { count: m })}</SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                  <p className="text-xs text-muted-foreground">{t('vaultApp.settings.autoLockHint')}</p>
                </Setting>
                <Setting label={t('vaultApp.settings.clipboardClear')}>
                  <Select value={String(prefs.clipboardSeconds)} onValueChange={(v) => onPrefs({ clipboardSeconds: Number(v) })}>
                    <SelectTrigger className="h-10 w-full rounded-xl" aria-label={t('vaultApp.settings.clipboardClear')}>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {CLIPBOARD.map((s) => (
                        <SelectItem key={s} value={String(s)}>{t('vaultApp.settings.seconds', { count: s })}</SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                  <p className="text-xs text-muted-foreground">{t('vaultApp.settings.clipboardHint')}</p>
                </Setting>
              </>
            )}

            {page === 'appearance' && (
              <>
                <Setting label={t('common.language')}>
                  <Select
                    value={LANGUAGES.some((l) => l.code === i18n.language) ? i18n.language : 'en'}
                    onValueChange={(code) => {
                      void i18n.changeLanguage(code)
                      onPrefs({ language: code })
                    }}
                  >
                    <SelectTrigger className="h-10 w-full rounded-xl" aria-label={t('common.language')}>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {LANGUAGES.map((l) => (
                        <SelectItem key={l.code} value={l.code}>{l.label}</SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </Setting>
                <Setting label={t('common.theme')}>
                  <ToggleGroup type="single" variant="outline" value={prefs.theme} onValueChange={(v) => v && onPrefs({ theme: v as AppPrefs['theme'] })} className="w-full rounded-xl" aria-label={t('common.theme')}>
                    {(['light', 'dark', 'system'] as const).map((m) => (
                      <ToggleGroupItem key={m} value={m} className="h-9 flex-1 text-sm">{t(`common.${m}`)}</ToggleGroupItem>
                    ))}
                  </ToggleGroup>
                </Setting>
              </>
            )}

            {page === 'about' && (
              <div className="flex flex-col items-center gap-4 rounded-xl border bg-card p-5 text-center">
                <ThyraLogo />
                <dl className="grid w-full grid-cols-[auto_1fr] gap-x-4 gap-y-2 text-left text-sm">
                  {info.version && (<><dt className="text-muted-foreground">{t('vaultApp.settings.version')}</dt><dd className="font-mono">{info.version}</dd></>)}
                  <dt className="text-muted-foreground">{t('vaultApp.settings.format')}</dt>
                  <dd className="font-mono">{info.format ?? '?'}</dd>
                  <dt className="text-muted-foreground">{t('vaultApp.settings.secrets')}</dt>
                  <dd className="font-mono">{info.count}</dd>
                  <dt className="text-muted-foreground">{t('vaultApp.settings.recoveryKey')}</dt>
                  <dd>{info.recovery ? t('vaultApp.settings.recoveryOn') : t('vaultApp.settings.recoveryOff')}</dd>
                  <dt className="text-muted-foreground">{t('vaultApp.settings.location')}</dt>
                  <dd className="font-mono text-xs break-all">{info.location}</dd>
                </dl>
              </div>
            )}
          </>
        )}
      </motion.div>
    </AnimatePresence>
  )
}
