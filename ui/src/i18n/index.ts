import { motorBridge } from '../bridge'
import { CATALOG, detectBrowserLang, type Lang, type Strings } from './catalog'

export type { Lang, Strings }
export { detectBrowserLang, CATALOG }

let lang: Lang = 'tr'
let strings: Strings = { ...CATALOG.tr }
const listeners = new Set<() => void>()

export function t(key: string, vars?: Record<string, string | number>): string {
  let text = strings[key] || CATALOG.en[key] || CATALOG.tr[key] || key
  if (vars) {
    for (const [k, v] of Object.entries(vars)) {
      text = text.split(`{${k}}`).join(String(v))
    }
  }
  return text
}

export function currentLang(): Lang {
  return lang
}

export function subscribeI18n(fn: () => void): () => void {
  listeners.add(fn)
  return () => listeners.delete(fn)
}

function notify() {
  listeners.forEach((fn) => fn())
}

function apply(next: Lang, host?: Strings) {
  lang = next
  strings = { ...CATALOG[next], ...(host || {}) }
  try {
    document.documentElement.lang = next
  } catch {
    /* ignore */
  }
  notify()
}

/** Load language: empty = host/OS auto; explicit tr|en = user choice (persisted by host). */
export async function loadI18n(next?: string): Promise<Lang> {
  const requested = (next || '').trim().toLowerCase()
  try {
    const result = await motorBridge.i18n(requested)
    if (result.ok) {
      const resolved = (String(result.lang || '') === 'en' ? 'en' : 'tr') as Lang
      const table =
        result.strings && typeof result.strings === 'object'
          ? (result.strings as Strings)
          : undefined
      apply(resolved, table)
      return lang
    }
  } catch {
    /* fall through to local catalog */
  }
  const fallback = requested === 'en' || requested === 'tr' ? (requested as Lang) : detectBrowserLang()
  apply(fallback)
  return lang
}
