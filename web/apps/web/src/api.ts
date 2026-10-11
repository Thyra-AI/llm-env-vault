import type { FormValues, View } from './protocol'

const TOKEN_KEY = 'vault-session-token'

export class SessionError extends Error {}

function readStoredToken(): string | null {
  try {
    return sessionStorage.getItem(TOKEN_KEY)
  } catch {
    return null
  }
}

function storeToken(token: string) {
  try {
    sessionStorage.setItem(TOKEN_KEY, token)
  } catch {
    /* storage unavailable: the page then cannot survive a reload, which is fine */
  }
}

/** The single-use launch code lives in the URL fragment (never sent to a server). */
function takeLaunchCode(): string | null {
  const match = /(?:^|&)c=([\w-]+)/.exec(location.hash.slice(1))
  if (!match) return null
  history.replaceState(null, '', location.pathname + location.search)
  return match[1]
}

function dropToken() {
  try {
    sessionStorage.removeItem(TOKEN_KEY)
  } catch {
    /* nothing stored */
  }
}

function hasStoredSession(): boolean {
  return readStoredToken() !== null
}

export class Client {
  private token: string | null = readStoredToken()

  async connect(code: string | null): Promise<void> {
    if (code) {
      const res = await fetch('/api/exchange', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code }),
      })
      if (!res.ok) throw new SessionError('invalid_code')
      this.token = (await res.json()).token as string
      storeToken(this.token)
    }
    if (!this.token) throw new SessionError('no_session')
  }

  private async call(method: 'GET' | 'POST', path: string, body?: unknown, keepalive = false): Promise<Response> {
    const res = await fetch(path, {
      method,
      keepalive,
      headers: {
        Authorization: `Bearer ${this.token}`,
        ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}),
      },
      body: body !== undefined ? JSON.stringify(body) : undefined,
    })
    if (res.status === 401 || res.status === 403) throw new SessionError('unauthorized')
    return res
  }

  async screen(): Promise<View> {
    return (await this.call('GET', '/api/screen')).json()
  }

  async act(screenId: string, action: string, values: FormValues): Promise<View> {
    const res = await this.call('POST', '/api/action', { screen: screenId, action, values })
    // 409 = the page was out of date; the body already carries the current view.
    return res.json()
  }

  async ping(): Promise<void> {
    await this.call('POST', '/api/ping', {})
  }

  /** The session is over: forget the token so this page can never talk to that port again. */
  forget(): void {
    this.token = null
    dropToken()
  }

  /** Best effort on pagehide: lets the server end the dialog promptly. */
  closing(): void {
    if (this.token) void this.call('POST', '/api/closing', {}, true).catch(() => undefined)
  }
}

/** True when this page was opened from an assistant (launch code or live session). */
export const HAS_LAUNCH = /(?:^|&)c=/.test(location.hash.slice(1)) || hasStoredSession()

let session: Promise<Client> | null = null

/** One connection per page load (React StrictMode runs effects twice in dev). */
export function openSession(): Promise<Client> {
  if (!session) {
    const client = new Client()
    session = client.connect(takeLaunchCode()).then(() => client)
  }
  return session
}
