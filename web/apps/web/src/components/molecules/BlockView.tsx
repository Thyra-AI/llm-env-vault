import {
  ChevronRight, CreditCard, FileLock, FileLock2, FileText, Folders, Globe, IdCard, KeyRound, LifeBuoy, Plus, RefreshCw,
  ShieldCheck, SquareTerminal, StickyNote, Trash2, TriangleAlert, Variable, Download, Lock, type LucideIcon,
} from 'lucide-react'
import { Badge } from '@workspace/ui/components/badge'
import { Field, FieldLabel } from '@workspace/ui/components/field'
import { Item, ItemActions, ItemContent, ItemDescription, ItemGroup, ItemMedia, ItemTitle } from '@workspace/ui/components/item'
import { cn } from '@workspace/ui/lib/utils'
import type { Block } from '@/protocol'
import { CopyKeyButton } from './CopyKeyButton'
import { ItemFields, ItemHeader, ItemHistory } from './ItemBlocks'
import { useMsg } from './MsgText'
import { Notice } from './Notice'

export const ICONS: Record<string, LucideIcon> = {
  lock: Lock, key: KeyRound, plus: Plus, trash: Trash2, download: Download, 'file-lock': FileLock2,
  'file-unlock': FileLock, 'alert-triangle': TriangleAlert, 'life-buoy': LifeBuoy, 'file-text': FileText,
  shield: ShieldCheck, variable: Variable, refresh: RefreshCw, folder: Folders, pencil: FileText,
  globe: Globe, 'credit-card': CreditCard, 'id-card': IdCard, note: StickyNote, terminal: SquareTerminal,
}

/** One content block of a server-sent screen. Untrusted text is rendered as text, never as HTML. */
export function BlockView({ block, onMenu }: { block: Block; onMenu: (id: string) => void }) {
  const { msg } = useMsg()
  switch (block.type) {
    case 'text':
      return <p className={cn('text-sm leading-relaxed', block.muted && 'text-muted-foreground')}>{msg(block.msg)}</p>
    case 'notice':
      return <Notice tone={block.tone}>{block.raw ?? (block.msg ? msg(block.msg) : null)}</Notice>
    case 'code': {
      const body = block.lines ? block.lines.join('\n') : (block.text ?? '')
      return (
        <Field>
          {block.label && <FieldLabel>{msg(block.label)}</FieldLabel>}
          <pre className="max-h-48 overflow-auto rounded-lg bg-muted px-3 py-2.5 font-mono text-xs leading-relaxed break-all whitespace-pre-wrap select-text">{body}</pre>
        </Field>
      )
    }
    case 'items':
      return (
        <Field>
          {block.label && <FieldLabel>{msg(block.label)}</FieldLabel>}
          <ul className="max-h-48 divide-y overflow-auto rounded-lg border bg-muted/40 text-xs">
            {block.rows.map((row, i) => (
              <li key={i} className="flex flex-wrap items-center gap-x-2 gap-y-1 px-3 py-1.5 font-mono break-all select-text">
                <span>{row.text}</span>
                {row.tag && <Badge variant="destructive">{msg(row.tag)}</Badge>}
              </li>
            ))}
          </ul>
        </Field>
      )
    case 'keyBox':
      return (
        <pre className="rounded-lg border-2 border-primary/30 bg-muted px-4 py-4 text-center font-mono text-lg leading-loose font-semibold tracking-wider text-primary select-all">
          {block.rows.join('\n')}
        </pre>
      )
    case 'itemHeader':
      return <ItemHeader block={block} />
    case 'fields':
      return <ItemFields block={block} onMenu={onMenu} />
    case 'history':
      return <ItemHistory block={block} />
    case 'copy':
      return <CopyKeyButton value={block.value} clearSeconds={block.clearSeconds} />
    case 'menu':
      return (
        <ItemGroup className="gap-2">
          {block.entries.map((e) => {
            const Icon = ICONS[e.icon] ?? ShieldCheck
            return (
              <Item key={e.id} variant="outline" size="sm" asChild>
                <button type="button" className="w-full text-left" onClick={() => onMenu(e.id)}>
                  <ItemMedia variant="icon">
                    <Icon aria-hidden />
                  </ItemMedia>
                  <ItemContent>
                    <ItemTitle>{msg(e.label)}</ItemTitle>
                    {e.description && <ItemDescription>{msg(e.description)}</ItemDescription>}
                  </ItemContent>
                  <ItemActions>
                    <ChevronRight className="size-4 text-muted-foreground" aria-hidden />
                  </ItemActions>
                </button>
              </Item>
            )
          })}
        </ItemGroup>
      )
  }
}
