export type PageId = 'status' | 'threat' | 'iplist' | 'services' | 'layers' | 'settings'

export function asRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === 'object' ? (value as Record<string, unknown>) : {}
}

export function pick(obj: Record<string, unknown> | null | undefined, ...keys: string[]): string {
  if (!obj) return '—'
  for (const key of keys) {
    const current = obj[key]
    if (current !== undefined && current !== null && String(current) !== '') {
      return String(current)
    }
  }
  return '—'
}

export function boolLabel(value: unknown, yes?: string, no?: string): string {
  // Callers should pass t('label_on') / t('label_off'); keep defaults Latin for safety.
  return value ? (yes ?? 'ON') : (no ?? 'OFF')
}

/** On / Off / … — use when value may still be loading (undefined/null ≠ Off). */
export function triLabel(
  value: unknown,
  opts: { yes: string; no: string; loading: string; pending?: boolean },
): string {
  if (opts.pending || value === undefined || value === null) return opts.loading
  return value ? opts.yes : opts.no
}

export function formatBps(bps: unknown): string {
  if (bps == null || bps === '') return '—'
  const v = Number(bps)
  if (!Number.isFinite(v) || v < 0) return '—'
  if (v < 1024) return `${v.toFixed(0)}B/s`
  if (v < 1024 * 1024) return `${(v / 1024).toFixed(0)}KB/s`
  return `${(v / (1024 * 1024)).toFixed(1)}MB/s`
}

/** Relative age for live meters (epoch seconds or ms). */
export function formatAgo(ts: unknown): string {
  const raw = Number(ts)
  if (!Number.isFinite(raw) || raw <= 0) return '—'
  const ms = raw > 1e12 ? raw : raw * 1000
  const sec = Math.max(0, Math.round((Date.now() - ms) / 1000))
  if (sec < 5) return '<5s'
  if (sec < 60) return `${sec}s`
  if (sec < 3600) return `${Math.floor(sec / 60)}m`
  if (sec < 86400) return `${Math.floor(sec / 3600)}h`
  return `${Math.floor(sec / 86400)}d`
}
