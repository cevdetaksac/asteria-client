import { motorBridge } from '../../bridge'
import { t } from '../../i18n'
import { asRecord } from '../../lib'

export type DashPath =
  | 'dash_home'
  | 'dash_attacks'
  | 'dash_threats'
  | 'dash_blocks'
  | 'dash_users'
  | 'dash_remote'
  | 'dash_settings'
  | 'dash_servers'
  | 'alerts'
  | 'blocking'
  | 'webhooks'
  | 'blocks_auto'
  | 'blocks_notifications'

export type FieldKind = 'bool' | 'int' | 'str' | 'choice' | 'time'

export type Field = {
  key: string
  kind: FieldKind
  labelKey: string
  helpKey: string
  dash: DashPath
  min?: number
  max?: number
  choices?: { value: string; labelKey: string }[]
  sectionKey: string
}

export type BlockRule = {
  id: string
  name: string
  enabled: boolean
  service: string
  event: string
  threshold: number
  window_seconds: number
  action: string
  alert: boolean
  severity: string
}

/** Contract register-protection seed — used when cloud returns empty rules. */
export const DEFAULT_BLOCK_RULES: BlockRule[] = [
  { id: 'rdp-fail-3', name: 'RDP brute force', enabled: true, service: 'RDP', event: 'failed_auth', threshold: 3, window_seconds: 1800, action: 'block_ip', alert: true, severity: 'high' },
  { id: 'ssh-fail-3', name: 'SSH brute force', enabled: true, service: 'SSH', event: 'failed_auth', threshold: 3, window_seconds: 1800, action: 'block_ip', alert: true, severity: 'high' },
  { id: 'ftp-fail-3', name: 'FTP brute force', enabled: true, service: 'FTP', event: 'failed_auth', threshold: 3, window_seconds: 1800, action: 'block_ip', alert: true, severity: 'high' },
  { id: 'mssql-fail-3', name: 'MSSQL brute force', enabled: true, service: 'MSSQL', event: 'failed_auth', threshold: 3, window_seconds: 1800, action: 'block_ip', alert: true, severity: 'high' },
  { id: 'mysql-fail-3', name: 'MySQL brute force', enabled: true, service: 'MYSQL', event: 'failed_auth', threshold: 3, window_seconds: 1800, action: 'block_ip', alert: true, severity: 'high' },
  { id: 'network-fail-10', name: 'Network auth fails', enabled: true, service: 'Network', event: 'failed_auth', threshold: 10, window_seconds: 1800, action: 'block_ip', alert: true, severity: 'high' },
]

export function normalizeBlockRules(raw: unknown): BlockRule[] {
  const list = Array.isArray(raw) ? raw : []
  const byService = new Map<string, BlockRule>()
  for (const def of DEFAULT_BLOCK_RULES) {
    byService.set(def.service.toUpperCase(), { ...def })
  }
  for (const item of list) {
    if (!item || typeof item !== 'object') continue
    const row = item as Record<string, unknown>
    const service = String(row.service || '').trim()
    if (!service) continue
    const key = service.toUpperCase()
    const prev = byService.get(key) || {
      id: String(row.id || `${service.toLowerCase()}-fail`),
      name: String(row.name || `${service} brute force`),
      enabled: true,
      service,
      event: 'failed_auth',
      threshold: 3,
      window_seconds: 1800,
      action: 'block_ip',
      alert: true,
      severity: 'high',
    }
    const threshold = Number(row.threshold ?? row.threshold_count ?? prev.threshold)
    let windowSec = Number(row.window_seconds ?? prev.window_seconds)
    if (!Number.isFinite(windowSec) || windowSec <= 0) {
      const mins = Number(row.window_minutes)
      windowSec = Number.isFinite(mins) && mins > 0 ? mins * 60 : prev.window_seconds
    }
    byService.set(key, {
      ...prev,
      id: String(row.id || prev.id),
      name: String(row.name || prev.name),
      enabled: row.enabled !== false,
      service: prev.service || service,
      event: String(row.event || prev.event),
      threshold: Number.isFinite(threshold) && threshold >= 1 ? Math.floor(threshold) : prev.threshold,
      window_seconds: Math.floor(windowSec),
      action: String(row.action || prev.action),
      alert: row.alert !== false,
      severity: String(row.severity || prev.severity),
    })
  }
  return Array.from(byService.values())
}

/** Mirrors client_settings_util.SECTIONS — cloud threats/config SoT. */
export const FIELDS: Field[] = [
  {
    key: 'alert_email_enabled',
    kind: 'bool',
    labelKey: 'settings_field_email',
    helpKey: 'settings_help_email',
    dash: 'blocks_notifications',
    sectionKey: 'settings_sec_email',
  },
  {
    key: 'instant_email_for_critical',
    kind: 'bool',
    labelKey: 'settings_field_critical',
    helpKey: 'settings_help_critical',
    dash: 'blocks_notifications',
    sectionKey: 'settings_sec_email',
  },
  {
    key: 'min_severity_for_email',
    kind: 'choice',
    labelKey: 'settings_email_min_severity',
    helpKey: 'settings_help_min_severity',
    dash: 'blocks_notifications',
    sectionKey: 'settings_sec_email',
    choices: [
      { value: 'low', labelKey: 'settings_sev_low' },
      { value: 'medium', labelKey: 'settings_sev_medium' },
      { value: 'high', labelKey: 'settings_sev_high' },
      { value: 'critical', labelKey: 'settings_sev_critical' },
    ],
  },
  {
    key: 'daily_digest_enabled',
    kind: 'bool',
    labelKey: 'settings_field_digest',
    helpKey: 'settings_help_digest',
    dash: 'blocks_notifications',
    sectionKey: 'settings_sec_email',
  },
  {
    key: 'auto_block_enabled',
    kind: 'bool',
    labelKey: 'settings_field_autoblock',
    helpKey: 'settings_help_autoblock',
    dash: 'blocks_auto',
    sectionKey: 'settings_sec_autoblock',
  },
  {
    key: 'auto_block_threshold',
    kind: 'int',
    labelKey: 'settings_field_threshold',
    helpKey: 'settings_help_threshold',
    dash: 'blocks_auto',
    sectionKey: 'settings_sec_autoblock',
    min: 1,
    max: 100,
  },
  {
    key: 'auto_block_duration_hours',
    kind: 'int',
    labelKey: 'settings_field_duration',
    helpKey: 'settings_help_duration',
    dash: 'blocks_auto',
    sectionKey: 'settings_sec_autoblock',
    min: 0,
    max: 8760,
  },
  {
    key: 'max_auto_blocks_per_hour',
    kind: 'int',
    labelKey: 'settings_autoblock_max_hour',
    helpKey: 'settings_help_max_hour',
    dash: 'blocks_auto',
    sectionKey: 'settings_sec_autoblock',
    min: 1,
    max: 1000,
  },
  {
    key: 'max_auto_blocks_per_day',
    kind: 'int',
    labelKey: 'settings_autoblock_max_day',
    helpKey: 'settings_help_max_day',
    dash: 'blocks_auto',
    sectionKey: 'settings_sec_autoblock',
    min: 1,
    max: 10000,
  },
  {
    key: 'silent_hours.enabled',
    kind: 'bool',
    labelKey: 'settings_silent_enabled',
    helpKey: 'settings_help_silent',
    dash: 'dash_settings',
    sectionKey: 'settings_sec_silent',
  },
  {
    key: 'silent_hours.mode',
    kind: 'choice',
    labelKey: 'settings_silent_mode',
    helpKey: 'settings_help_silent_mode',
    dash: 'dash_settings',
    sectionKey: 'settings_sec_silent',
    choices: [
      { value: 'disabled', labelKey: 'settings_mode_disabled' },
      { value: 'night_only', labelKey: 'settings_mode_night' },
      { value: 'outside_working', labelKey: 'settings_mode_outside' },
      { value: 'always', labelKey: 'settings_mode_always' },
    ],
  },
  {
    key: 'silent_hours.night_start',
    kind: 'time',
    labelKey: 'settings_silent_night_start',
    helpKey: 'settings_help_night_start',
    dash: 'dash_settings',
    sectionKey: 'settings_sec_silent',
  },
  {
    key: 'silent_hours.night_end',
    kind: 'time',
    labelKey: 'settings_silent_night_end',
    helpKey: 'settings_help_night_end',
    dash: 'dash_settings',
    sectionKey: 'settings_sec_silent',
  },
  {
    key: 'silent_hours.weekend_all_day_silent',
    kind: 'bool',
    labelKey: 'settings_silent_weekend',
    helpKey: 'settings_help_silent_weekend',
    dash: 'dash_settings',
    sectionKey: 'settings_sec_silent',
  },
  {
    key: 'silent_hours.auto_block_ip',
    kind: 'bool',
    labelKey: 'settings_silent_auto_block',
    helpKey: 'settings_help_silent_auto_block',
    dash: 'dash_settings',
    sectionKey: 'settings_sec_silent',
  },
  {
    key: 'silent_hours.auto_logoff',
    kind: 'bool',
    labelKey: 'settings_silent_auto_logoff',
    helpKey: 'settings_help_silent_auto_logoff',
    dash: 'dash_settings',
    sectionKey: 'settings_sec_silent',
  },
  {
    key: 'silent_hours.auto_disable_account',
    kind: 'bool',
    labelKey: 'settings_silent_auto_disable',
    helpKey: 'settings_help_silent_auto_disable',
    dash: 'dash_settings',
    sectionKey: 'settings_sec_silent',
  },
  {
    key: 'webhook_enabled',
    kind: 'bool',
    labelKey: 'settings_field_webhook',
    helpKey: 'settings_help_webhook',
    dash: 'dash_settings',
    sectionKey: 'settings_sec_webhook',
  },
  {
    key: 'webhook_url',
    kind: 'str',
    labelKey: 'settings_field_webhook_url',
    helpKey: 'settings_help_webhook_url',
    dash: 'dash_settings',
    sectionKey: 'settings_sec_webhook',
  },
]

export function nestedGet(obj: Record<string, unknown>, path: string): unknown {
  return path.split('.').reduce<unknown>((acc, key) => {
    if (acc && typeof acc === 'object') return (acc as Record<string, unknown>)[key]
    return undefined
  }, obj)
}

export function nestedSet(obj: Record<string, unknown>, path: string, value: unknown): Record<string, unknown> {
  const parts = path.split('.')
  const root = { ...obj }
  let cursor: Record<string, unknown> = root
  for (let i = 0; i < parts.length - 1; i++) {
    const key = parts[i]
    const next = asRecord(cursor[key])
    cursor[key] = { ...next }
    cursor = cursor[key] as Record<string, unknown>
  }
  cursor[parts[parts.length - 1]] = value
  return root
}

export function openDash(path: DashPath) {
  void motorBridge.shell('open_dashboard', path)
}

export function mapSettingsAccountError(code: string): string {
  if (code === 'invalid_credentials') return t('claim_bad_credentials')
  if (code === 'already_linked_other' || code === 'conflict_other_account') return t('claim_other_account')
  if (code === 'missing_confirm_code') return t('account_unlink_need_mail_first')
  if (code === 'unlink_mail_unavailable') return t('account_unlink_mail_unavailable')
  if (code === 'invalid_confirm_code' || code === 'confirm_code_invalid') {
    return t('account_unlink_need_mail_first')
  }
  if (code === 'pin_verification_failed' || code === 'pin_set_failed') return t('account_pin_wrong')
  if (code === 'pin_required') return t('account_pin_required')
  if (code === 'missing_credentials') return t('toast_need_creds')
  if (code === 'token_missing') return t('toast_token_missing')
  return t('toast_account_failed')
}
