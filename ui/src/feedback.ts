/** U4: one toast / error format for every page. */
import type { BridgeResult } from './bridge'
import { t } from './i18n'

export type ToastFn = (msg: string, kind?: 'ok' | 'err') => void

const TECH_CODE = /^[A-Za-z0-9_:.\-]+$/

/** Human-readable error: known bridge codes get a friendly text; raw codes are kept as a short suffix. */
export function errorText(result: BridgeResult | null | undefined): string {
  const raw = String(result?.error ?? '').trim()
  if (!raw) return t('toast_error_generic')
  if (raw === 'bridge_not_ready' || raw.startsWith('bridge_method_missing')) return t('motor_unreachable')
  if (/timed? ?out|timeout/i.test(raw)) return `${t('toast_error_generic')} (timeout)`
  if (TECH_CODE.test(raw)) return `${t('toast_error_generic')} (${raw})`
  return raw
}

/** Toast a bridge result: success text on ok, unified error text otherwise. */
export function toastResult(onToast: ToastFn, result: BridgeResult, okMsg: string): boolean {
  const ok = Boolean(result?.ok)
  onToast(ok ? okMsg : errorText(result), ok ? 'ok' : 'err')
  return ok
}
