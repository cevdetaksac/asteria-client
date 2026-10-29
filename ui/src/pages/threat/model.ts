import { asRecord, pick } from '../../lib'

export type ThreatTab = 'threats' | 'accounts' | 'system' | 'network'

export type Attacker = Record<string, unknown>

export type LocalUser = {
  username: string
  full_name?: string
  enabled: boolean
  status: string
  protected?: boolean
  is_admin?: boolean
  is_self?: boolean
  groups?: string[]
  last_logon?: string | null
  has_session?: boolean
  session_status?: string | null
  can_enable?: boolean
  can_disable?: boolean
  can_logoff?: boolean
  can_reset_password?: boolean
}

export function formatLogon(value?: string | null): string {
  if (!value) return '—'
  try {
    const d = new Date(value)
    if (Number.isNaN(d.getTime())) return value
    return d.toLocaleString()
  } catch {
    return value
  }
}

export function formatThreatTime(value: unknown): string {
  if (value == null || value === '') return '—'
  if (typeof value === 'number') {
    const ms = value > 1e12 ? value : value * 1000
    const d = new Date(ms)
    return Number.isNaN(d.getTime()) ? String(value) : d.toLocaleString()
  }
  return formatLogon(String(value))
}

export function normalizeAlertList(payload: unknown): Attacker[] {
  if (Array.isArray(payload)) return payload as Attacker[]
  const rec = asRecord(payload)
  for (const key of ['alerts', 'items', 'results', 'data', 'critical_alerts']) {
    const v = rec[key]
    if (Array.isArray(v)) return v as Attacker[]
  }
  const nested = asRecord(rec.data)
  if (Array.isArray(nested.alerts)) return nested.alerts as Attacker[]
  return []
}

export function alertFields(row: Record<string, unknown>) {
  const title = pick(row, 'title', 'name', 'rule_name', 'threat_title')
  const description = pick(row, 'description', 'detail', 'message', 'summary', 'reason')
  const threatType = pick(row, 'threat_type', 'event_type', 'type', 'last_event_type')
  const ip = pick(row, 'source_ip', 'ip', 'src_ip', 'address')
  const score = pick(row, 'threat_score', 'score')
  const when = pick(row, 'timestamp', 'created_at', 'time', 'last_seen')
  const severity = pick(row, 'severity', 'level')
  const service = pick(row, 'target_service', 'service')
  const user = pick(row, 'username', 'user', 'account')
  const action = pick(row, 'recommended_action', 'action')
  return { title, description, threatType, ip, score, when, severity, service, user, action }
}
