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
