import { Check, Copy, CreditCard, Eye, EyeOff, FileText, Folder, Globe, IdCard, SquareTerminal, type LucideIcon } from 'lucide-react'
import { useState } from 'react'
import { useTranslation } from '@workspace/i18n'
import { Button } from '@workspace/ui/components/button'
import { cn } from '@workspace/ui/lib/utils'
import type { Block } from '@/protocol'
import { useMsg } from './MsgText'

export const ITEM_ICONS: Record<string, LucideIcon> = {
  login: Globe, card: CreditCard, identity: IdCard, note: FileText, ssh: SquareTerminal,
}

type Header = Extract<Block, { type: 'itemHeader' }>
type Fields = Extract<Block, { type: 'fields' }>
type History = Extract<Block, { type: 'history' }>

/** Name, type icon and folder: the top of an item's view. */
export function ItemHeader({ block }: { block: Header }) {
  const { t } = useTranslation()
  const Icon = ITEM_ICONS[block.itemType] ?? FileText
  return (
    <div className="flex flex-col gap-3 rounded-xl border bg-card p-4">
      <div className="flex items-center gap-3">
        <span className="flex size-10 shrink-0 items-center justify-center rounded-full bg-primary/15 text-primary">
          <Icon className="size-5" aria-hidden />
        </span>
        <h3 className="min-w-0 flex-1 font-heading text-lg leading-tight font-semibold break-words">{block.name}</h3>
      </div>
      <p className="flex items-center gap-2 text-sm text-muted-foreground">
        <Folder className="size-4 shrink-0" aria-hidden /> {block.folder || t('vaultApp.item.noFolder')}
      </p>
    </div>
  )
}

/**
 * The fields of an item. A hidden field arrives WITHOUT its text (value is null)
 * and shows dots until the person asks to reveal it; the page never has it
 * before that. Copy goes through the server, which wipes the clipboard later.
 */
export function ItemFields({ block, onMenu }: { block: Fields; onMenu: (id: string) => void }) {
  const { t } = useTranslation()
  const { msg } = useMsg()
  return (
    <div className="flex flex-col gap-3">
      {block.rows.map((row) => {
        const shown = row.value !== null
        return (
          <section key={row.id} className="flex flex-col gap-1.5 rounded-xl border bg-card p-3.5">
            <div className="flex items-start gap-2">
              <div className="min-w-0 flex-1">
                <p className="text-xs font-medium text-muted-foreground">{msg(row.label)}</p>
                <p
                  className={cn(
                    'mt-1 text-sm leading-relaxed break-all select-text',
                    (row.multiline || row.hidden) && 'font-mono',
                    row.multiline && shown && 'max-h-56 overflow-auto text-xs whitespace-pre-wrap',
                    !shown && 'tracking-widest text-muted-foreground',
                  )}
                  aria-live="polite"
                >
                  {shown ? row.value : '••••••••••'}
                </p>
              </div>
              {row.hidden && (
                <Button type="button" variant="ghost" size="icon" aria-pressed={row.revealed}
                  aria-label={`${row.revealed ? t('common.hide') : t('common.show')}: ${msg(row.label)}`}
                  onClick={() => onMenu(`${row.revealed ? 'hide' : 'reveal'}:${row.id}`)}>
                  {row.revealed ? <EyeOff aria-hidden /> : <Eye aria-hidden />}
                </Button>
              )}
              <CopyButton label={`${t('vaultApp.vault.copy')}: ${msg(row.label)}`} onClick={() => onMenu(`copy:${row.id}`)} />
            </div>
          </section>
        )
      })}
    </div>
  )
}

function CopyButton({ label, onClick }: { label: string; onClick: () => void }) {
  const [done, setDone] = useState(false)
  return (
    <Button type="button" variant="ghost" size="icon" aria-label={label}
      onClick={() => {
        onClick()
        setDone(true)
        window.setTimeout(() => setDone(false), 1200)
      }}>
      {done ? <Check aria-hidden /> : <Copy aria-hidden />}
    </Button>
  )
}

/** "Item history", with the dates in the person's language. */
export function ItemHistory({ block }: { block: History }) {
  const { t, i18n } = useTranslation()
  const format = (iso: string) => {
    const date = new Date(iso)
    return Number.isNaN(date.getTime()) ? iso : new Intl.DateTimeFormat(i18n.language, { dateStyle: 'medium', timeStyle: 'medium' }).format(date)
  }
  return (
    <section className="flex flex-col gap-1.5 rounded-xl border bg-card p-3.5">
      <h4 className="text-sm font-semibold">{t('vaultApp.item.history')}</h4>
      <p className="text-xs text-muted-foreground">{t('vaultApp.item.lastEdited')}: {format(block.updated)}</p>
      <p className="text-xs text-muted-foreground">{t('vaultApp.item.created')}: {format(block.created)}</p>
    </section>
  )
}
