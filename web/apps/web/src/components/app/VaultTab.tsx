import { Copy, Database, FileText, Globe, KeyRound, Lock, MoreVertical, Pencil, Plus, Search, Ticket, Trash2, X, type LucideIcon } from 'lucide-react'
import { motion } from 'motion/react'
import { useTranslation } from '@workspace/i18n'
import { Button } from '@workspace/ui/components/button'
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuSeparator, DropdownMenuTrigger } from '@workspace/ui/components/dropdown-menu'
import { InputGroup, InputGroupAddon, InputGroupButton, InputGroupInput } from '@workspace/ui/components/input-group'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@workspace/ui/components/select'
import { Tooltip, TooltipContent, TooltipTrigger } from '@workspace/ui/components/tooltip'
import { cn } from '@workspace/ui/lib/utils'
import { ITEM_ICONS } from '@/components/molecules'
import type { AppItem, ItemKind, ItemType } from '@/protocol'

const KIND_ICON: Record<ItemKind, LucideIcon> = {
  apiKey: KeyRound, token: Ticket, password: Lock, url: Globe, database: Database, other: FileText,
}
const TYPES: ItemType[] = ['secret', 'login', 'card', 'identity', 'note', 'ssh']

function iconFor(item: AppItem): LucideIcon {
  return item.type === 'secret' ? KIND_ICON[item.kind as ItemKind] ?? KeyRound : ITEM_ICONS[item.type] ?? FileText
}

export const ALL_KINDS = 'all'

interface RowProps {
  item: AppItem
  index: number
  onCopy: (item: AppItem) => void
  onOpen: (item: AppItem) => void
  onEdit: (item: AppItem) => void
  onDelete: (item: AppItem) => void
  onCopyName: (item: AppItem) => void
}

function ItemRow({ item, index, onCopy, onOpen, onEdit, onDelete, onCopyName }: RowProps) {
  const { t } = useTranslation()
  const Icon = iconFor(item)
  const where = item.type !== 'secret'
    ? item.sub || item.folder || t(`vaultApp.types.${item.type}`)
    : item.fileCount
    ? item.files.join(', ') + (item.fileCount > item.files.length ? ` +${item.fileCount - item.files.length}` : '')
    : item.number
      ? t('vaultApp.vault.placeholder', { n: item.number })
      : t('vaultApp.vault.notUsed')
  return (
    <motion.li
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.22, delay: Math.min(index, 10) * 0.02, ease: [0.22, 1, 0.36, 1] }}
      className="flex items-center gap-3 rounded-xl border bg-card px-3 py-2.5 transition-colors hover:border-primary/40"
    >
      <span className="flex size-9 shrink-0 items-center justify-center rounded-lg bg-primary/10 text-primary" title={t(`vaultApp.types.${item.type}`)}>
        <Icon className="size-[18px]" aria-hidden />
      </span>
      <button type="button" onClick={() => (item.type === 'secret' ? onCopy(item) : onOpen(item))} className="min-w-0 flex-1 rounded-md text-left outline-none focus-visible:ring-2 focus-visible:ring-ring/50" aria-label={`${item.type === 'secret' ? t('vaultApp.vault.copy') : t('vaultApp.vault.open')}: ${item.name}`}>
        <p className="truncate font-mono text-sm font-medium">{item.name}</p>
        <p className="truncate text-xs text-muted-foreground">{where}</p>
      </button>
      <Tooltip>
        <TooltipTrigger asChild>
          <Button type="button" variant="ghost" size="icon" aria-label={`${t('vaultApp.vault.copy')}: ${item.name}`} onClick={() => onCopy(item)}>
            <Copy aria-hidden />
          </Button>
        </TooltipTrigger>
        <TooltipContent>{t('vaultApp.vault.copy')}</TooltipContent>
      </Tooltip>
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button type="button" variant="ghost" size="icon" aria-label={`${t('vaultApp.vault.more')}: ${item.name}`}>
            <MoreVertical aria-hidden />
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end">
          <DropdownMenuItem onSelect={() => onEdit(item)}>
            <Pencil aria-hidden /> {t('vaultApp.vault.edit')}
          </DropdownMenuItem>
          <DropdownMenuItem onSelect={() => onCopyName(item)}>
            <Copy aria-hidden /> {t('vaultApp.vault.copyName')}
          </DropdownMenuItem>
          <DropdownMenuSeparator />
          <DropdownMenuItem variant="destructive" onSelect={() => onDelete(item)}>
            <Trash2 aria-hidden /> {t('vaultApp.vault.delete')}
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>
    </motion.li>
  )
}

interface VaultTabProps {
  items: AppItem[]
  search: string
  kind: string
  onSearch: (value: string) => void
  onKind: (value: string) => void
  onCopy: (item: AppItem) => void
  onOpen: (item: AppItem) => void
  onAdd: () => void
  onEdit: (item: AppItem) => void
  onDelete: (item: AppItem) => void
  onCopyName: (item: AppItem) => void
}

export function VaultTab({ items, search, kind, onSearch, onKind, onCopy, onOpen, onAdd, onEdit, onDelete, onCopyName }: VaultTabProps) {
  const { t } = useTranslation()
  const needle = search.trim().toLowerCase()
  const shown = items.filter((i) => (kind === ALL_KINDS || i.type === kind) && (!needle || i.name.toLowerCase().includes(needle) || i.files.some((f) => f.toLowerCase().includes(needle))))
  const present = TYPES.filter((k) => items.some((i) => i.type === k))

  return (
    <div className="flex flex-col gap-3 px-4 pt-3 pb-4">
      <div className="sticky top-0 z-[5] -mx-4 flex flex-col gap-2 bg-background/95 px-4 pb-2 backdrop-blur">
        <InputGroup className="h-10 rounded-xl">
          <InputGroupAddon>
            <Search aria-hidden />
          </InputGroupAddon>
          <InputGroupInput value={search} onChange={(e) => onSearch(e.target.value)} placeholder={t('vaultApp.vault.search')} aria-label={t('vaultApp.vault.search')} autoComplete="off" spellCheck={false} />
          {search && (
            <InputGroupAddon align="inline-end">
              <InputGroupButton size="icon-xs" aria-label={t('common.cancel')} onClick={() => onSearch('')}>
                <X aria-hidden />
              </InputGroupButton>
            </InputGroupAddon>
          )}
        </InputGroup>
        <Select value={kind} onValueChange={onKind}>
          <SelectTrigger className="h-9 w-full rounded-xl" aria-label={t('vaultApp.vault.type')}>
            <SelectValue placeholder={t('vaultApp.vault.type')} />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value={ALL_KINDS}>{t('vaultApp.vault.allTypes')}</SelectItem>
            {present.map((k) => (
              <SelectItem key={k} value={k}>
                {t(`vaultApp.types.${k}`)}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      {items.length === 0 ? (
        <Empty icon={KeyRound} title={t('vaultApp.vault.emptyTitle')} hint={t('vaultApp.vault.emptyHint')}>
          <Button type="button" onClick={onAdd}>
            <Plus aria-hidden /> {t('vaultApp.vault.add')}
          </Button>
        </Empty>
      ) : shown.length === 0 ? (
        <Empty icon={Search} title={t('vaultApp.vault.noMatch')} hint={t('vaultApp.vault.noMatchHint')} />
      ) : (
        <>
          <p className="px-1 text-xs font-medium tracking-wide text-muted-foreground uppercase">{t('vaultApp.vault.count', { count: shown.length })}</p>
          <ul className={cn('flex flex-col gap-2')}>
            {shown.map((item, i) => (
              <ItemRow key={item.id} item={item} index={i} onCopy={onCopy} onOpen={onOpen} onEdit={onEdit} onDelete={onDelete} onCopyName={onCopyName} />
            ))}
          </ul>
        </>
      )}
    </div>
  )
}

function Empty({ icon: Icon, title, hint, children }: { icon: LucideIcon; title: string; hint: string; children?: React.ReactNode }) {
  return (
    <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="flex flex-col items-center gap-2 px-6 py-12 text-center">
      <span className="flex size-12 items-center justify-center rounded-2xl bg-muted text-muted-foreground">
        <Icon className="size-6" aria-hidden />
      </span>
      <p className="font-heading text-base font-semibold">{title}</p>
      <p className="text-sm text-muted-foreground">{hint}</p>
      {children && <div className="mt-2">{children}</div>}
    </motion.div>
  )
}
