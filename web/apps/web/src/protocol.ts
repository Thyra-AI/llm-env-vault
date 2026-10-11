/** The screen schema the Python flows send (src/webui/schema.py). */
export type Params = Record<string, string | number>
export interface Msg {
  key: string
  params?: Params
}
export type ErrorMsg = Msg | { raw: string }
export type Tone = 'info' | 'warning' | 'danger' | 'success'

export type Block =
  | { type: 'text'; msg: Msg; muted: boolean }
  | { type: 'notice'; tone: Tone; msg?: Msg; raw?: string }
  | { type: 'code'; label?: Msg; text?: string; lines?: string[] }
  | { type: 'items'; label?: Msg; rows: { text: string; tag?: Msg }[] }
  | { type: 'keyBox'; rows: string[] }
  | { type: 'copy'; value: string; clearSeconds: number }
  | { type: 'menu'; entries: { id: string; icon: string; label: Msg; description?: Msg }[] }
  | { type: 'itemHeader'; name: string; itemType: string; folder: string }
  | {
      type: 'fields'
      label?: Msg
      rows: { id: string; label: Msg; hidden: boolean; multiline: boolean; revealed: boolean; empty: boolean; value: string | null }[]
    }
  | { type: 'history'; created: string; updated: string }

export type Field =
  | { type: 'password'; name: string; label: Msg; new: boolean; strength: boolean; toggle: boolean; autofocus: boolean; initial?: string }
  | { type: 'text'; name: string; label: Msg; mono: boolean; placeholder?: string; autofocus: boolean; initial?: string }
  | { type: 'textarea'; name: string; label: Msg; rows: number; mono: boolean; autofocus: boolean; initial?: string }
  | { type: 'checkbox'; name: string; label: Msg }

export interface ScreenAction {
  id: string
  label: Msg
  variant: 'primary' | 'outline' | 'danger'
}

export type ItemKind = 'apiKey' | 'token' | 'password' | 'url' | 'database' | 'other'
export type ItemType = 'secret' | 'login' | 'card' | 'identity' | 'note' | 'ssh'

/** One secret as the list shows it: a NAME and metadata, never a value. */
export interface AppItem {
  /** A secret's id is its name; a personal item's is a random hex id. */
  id: string
  type: ItemType
  name: string
  number: number | null
  kind: ItemKind | ItemType
  files: string[]
  fileCount: number
  sub?: string
  folder?: string
}

export interface AppPrefs {
  language: string | null
  theme: 'light' | 'dark' | 'system'
  autoLockMinutes: number
  clipboardSeconds: number
  generator: import('./components/app/generator').GeneratorOptions
}

export interface AppInfo {
  format: number | null
  recovery: boolean
  location: string
  count: number
  version: string
}

export type AppTab = 'vault' | 'generator' | 'settings'

/** The Bitwarden-style frame (src/webui/appflow.py). */
export type AppView =
  | { view: 'lock'; firstRun: boolean; location: string; prefs: AppPrefs }
  | { view: 'home'; tab: AppTab; items: AppItem[]; prefs: AppPrefs; info: AppInfo }

export interface Toast {
  tone: 'success' | 'warning' | 'error' | 'info'
  msg: Msg | { raw: string }
}

export interface Screen {
  id: string
  title: Msg
  icon: string
  tone: 'default' | 'danger' | 'warning'
  blocks: Block[]
  fields: Field[]
  actions: ScreenAction[]
  defaultAction: string | null
  error: ErrorMsg | null
  step?: { current: number; total: number }
  badge?: Msg
  app?: AppView
  toast?: Toast
}

export type DoneStatus = 'approved' | 'declined' | null
export type View = { screen: Screen } | { done: true; reason: string; status: DoneStatus }
export type FormValues = Record<string, unknown>
