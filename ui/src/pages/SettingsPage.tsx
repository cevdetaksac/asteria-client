import { type FormEvent, useEffect, useState } from 'react'
import { motorBridge } from '../bridge'
import { PasswordInput } from '../components/PasswordInput'
import { Switch } from '../components/Switch'
import { t } from '../i18n'
import { asRecord } from '../lib'

type Props = {
  pinEnabled: boolean
  onToast: (msg: string, kind?: 'ok' | 'err') => void
  onSession: () => void
}

type DashPath =
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

type FieldKind = 'bool' | 'int' | 'str' | 'choice' | 'time'

type Field = {
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

type BlockRule = {
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
const DEFAULT_BLOCK_RULES: BlockRule[] = [
  { id: 'rdp-fail-3', name: 'RDP brute force', enabled: true, service: 'RDP', event: 'failed_auth', threshold: 3, window_seconds: 1800, action: 'block_ip', alert: true, severity: 'high' },
  { id: 'ssh-fail-3', name: 'SSH brute force', enabled: true, service: 'SSH', event: 'failed_auth', threshold: 3, window_seconds: 1800, action: 'block_ip', alert: true, severity: 'high' },
  { id: 'ftp-fail-3', name: 'FTP brute force', enabled: true, service: 'FTP', event: 'failed_auth', threshold: 3, window_seconds: 1800, action: 'block_ip', alert: true, severity: 'high' },
  { id: 'mssql-fail-3', name: 'MSSQL brute force', enabled: true, service: 'MSSQL', event: 'failed_auth', threshold: 3, window_seconds: 1800, action: 'block_ip', alert: true, severity: 'high' },
  { id: 'mysql-fail-3', name: 'MySQL brute force', enabled: true, service: 'MYSQL', event: 'failed_auth', threshold: 3, window_seconds: 1800, action: 'block_ip', alert: true, severity: 'high' },
  { id: 'network-fail-10', name: 'Network auth fails', enabled: true, service: 'Network', event: 'failed_auth', threshold: 10, window_seconds: 1800, action: 'block_ip', alert: true, severity: 'high' },
]

function normalizeBlockRules(raw: unknown): BlockRule[] {
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
const FIELDS: Field[] = [
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

function nestedGet(obj: Record<string, unknown>, path: string): unknown {
  return path.split('.').reduce<unknown>((acc, key) => {
    if (acc && typeof acc === 'object') return (acc as Record<string, unknown>)[key]
    return undefined
  }, obj)
}

function nestedSet(obj: Record<string, unknown>, path: string, value: unknown): Record<string, unknown> {
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

function openDash(path: DashPath) {
  void motorBridge.shell('open_dashboard', path)
}

export function SettingsPage({ pinEnabled, onToast, onSession }: Props) {
  const [draft, setDraft] = useState<Record<string, unknown>>({})
  const [blockRules, setBlockRules] = useState<BlockRule[]>(DEFAULT_BLOCK_RULES)
  const [pin, setPin] = useState('')
  const [pinCurrent, setPinCurrent] = useState('')
  const [busy, setBusy] = useState(false)
  const [cfgReady, setCfgReady] = useState(false)
  const [linked, setLinked] = useState(false)
  const [accountEmail, setAccountEmail] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [accountPin, setAccountPin] = useState('')

  const load = async () => {
    const result = await motorBridge.cloud('GET', 'threats/config')
    if (result.ok && result.data && typeof result.data === 'object') {
      const data = result.data as Record<string, unknown>
      setDraft(data)
      const prot = asRecord(data.protection)
      setBlockRules(normalizeBlockRules(prot?.block_rules))
    } else {
      setBlockRules(DEFAULT_BLOCK_RULES)
    }
    setCfgReady(true)
  }

  const loadAccount = async () => {
    const result = await motorBridge.account('status')
    if (result.ok) {
      setLinked(Boolean(result.linked))
      setAccountEmail(String(result.email || ''))
    }
  }

  useEffect(() => {
    void load()
    void loadAccount()
  }, [])

  const updateRule = (service: string, patch: Partial<BlockRule>) => {
    setBlockRules((prev) =>
      prev.map((row) => (row.service === service ? { ...row, ...patch } : row)),
    )
  }

  const save = async (event: FormEvent) => {
    event.preventDefault()
    setBusy(true)
    try {
      const patch: Record<string, unknown> = {}
      for (const field of FIELDS) {
        const value = nestedGet(draft, field.key)
        if (value !== undefined) {
          Object.assign(patch, nestedSet({}, field.key, value))
        }
      }
      patch.protection = {
        block_rules: blockRules.map((row) => ({
          id: row.id,
          name: row.name,
          enabled: row.enabled,
          service: row.service,
          event: row.event,
          threshold: Math.max(1, Math.min(100, Math.floor(Number(row.threshold) || 1))),
          window_seconds: Math.max(60, Math.min(86400, Math.floor(Number(row.window_seconds) || 1800))),
          action: row.action || 'block_ip',
          alert: row.alert !== false,
          severity: row.severity || 'high',
        })),
      }
      const result = await motorBridge.cloud('POST', 'threats/config', patch)
      onToast(result.ok ? t('toast_settings_saved') : String(result.error || 'save'), result.ok ? 'ok' : 'err')
      await load()
    } finally {
      setBusy(false)
    }
  }

  const setPinAction = async () => {
    const result = await motorBridge.pin('set', pin, pinCurrent)
    onToast(result.ok ? t('toast_pin_saved') : String(result.reason || result.error || 'PIN'), result.ok ? 'ok' : 'err')
    if (result.ok) {
      setPin('')
      setPinCurrent('')
      onSession()
    }
  }

  const clearPin = async () => {
    const result = await motorBridge.pin('clear', '', pinCurrent || pin)
    onToast(result.ok ? t('toast_pin_cleared') : String(result.reason || result.error || 'PIN'), result.ok ? 'ok' : 'err')
    if (result.ok) onSession()
  }

  const submitAccount = async (action: 'link' | 'unlink') => {
    const targetEmail = action === 'unlink' ? accountEmail : email
    if (!targetEmail || !password) {
      onToast(t('toast_need_creds'), 'err')
      return
    }
    if (!accountPin) {
      onToast(t('account_pin_required'), 'err')
      return
    }
    setBusy(true)
    try {
      const result = await motorBridge.account(action, targetEmail, password, accountPin)
      onToast(
        result.ok
          ? action === 'link'
            ? t('toast_link_ok')
            : t('toast_unlink_ok')
          : result.error === 'pin_verification_failed'
            ? t('account_pin_wrong')
            : String(result.error || 'account'),
        result.ok ? 'ok' : 'err',
      )
      if (result.ok) {
        setPassword('')
        setAccountPin('')
        await loadAccount()
        onSession()
      }
    } finally {
      setBusy(false)
    }
  }

  const sections = FIELDS.reduce<string[]>((acc, field) => {
    if (!acc.includes(field.sectionKey)) acc.push(field.sectionKey)
    return acc
  }, [])

  return (
    <section className="page">
      <div className="page-head">
        <div>
          <p className="eyebrow">{t('settings_eyebrow')}</p>
          <h2>{t('settings_title')}</h2>
          <p className="muted">{t('settings_blurb')}</p>
        </div>
        <button type="button" className="btn ghost" onClick={() => void motorBridge.shell('open_servers')}>
          {t('btn_servers_web')}
        </button>
      </div>

      <article className="panel">
        <p className="eyebrow">{t('settings_account')}</p>
        <h3>
          {linked
            ? t('settings_linked', { email: accountEmail ? `: ${accountEmail}` : '' })
            : t('settings_not_linked')}
        </h3>
        <p className="muted">{t('settings_account_blurb')}</p>
        <div className="inline-form" style={{ marginTop: 12 }}>
          {!linked && (
            <input
              type="email"
              placeholder={t('settings_email_ph')}
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              autoComplete="username"
            />
          )}
          <PasswordInput value={password} onChange={setPassword} placeholder={t('settings_password_ph')} />
          <PasswordInput
            value={accountPin}
            onChange={setAccountPin}
            placeholder={t('account_pin_reauth')}
            numeric
          />
          <button type="button" className="btn" disabled={busy || linked} onClick={() => void submitAccount('link')}>
            {t('btn_link_account')}
          </button>
          <button type="button" className="btn danger" disabled={busy || !linked} onClick={() => void submitAccount('unlink')}>
            {t('btn_unlink_account')}
          </button>
        </div>
      </article>

      <form className="settings-form" onSubmit={(e) => void save(e)} style={{ marginTop: 24 }}>
        {!cfgReady && <p className="muted status-loading-hint">{t('status_section_loading')}</p>}
        {sections.map((sectionKey) => (
          <article key={sectionKey} className="panel" style={{ marginBottom: 16 }}>
            <p className="eyebrow">{t(sectionKey)}</p>
            {FIELDS.filter((f) => f.sectionKey === sectionKey).map((field) => {
              const value = nestedGet(draft, field.key)
              const label = t(field.labelKey)
              return (
                <div key={field.key} className={`field field-stack${!cfgReady ? ' loading' : ''}`}>
                  <div className="field-main">
                    <div className="field-copy">
                      <span className="field-label">{label}</span>
                      <p className="field-help">
                        {t(field.helpKey)}{' '}
                        <button type="button" className="field-dash-link" onClick={() => openDash(field.dash)}>
                          {t('settings_dash_link')}
                        </button>
                      </p>
                    </div>
                    {field.kind === 'bool' ? (
                      <Switch
                        checked={Boolean(value)}
                        loading={!cfgReady}
                        disabled={busy || !cfgReady}
                        label={label}
                        onChange={(next) => setDraft((prev) => nestedSet(prev, field.key, next))}
                      />
                    ) : field.kind === 'choice' ? (
                      <select
                        disabled={!cfgReady || busy}
                        value={value == null ? '' : String(value)}
                        onChange={(e) => setDraft((prev) => nestedSet(prev, field.key, e.target.value))}
                      >
                        {(field.choices || []).map((opt) => (
                          <option key={opt.value} value={opt.value}>
                            {t(opt.labelKey)}
                          </option>
                        ))}
                      </select>
                    ) : (
                      <input
                        type={field.kind === 'int' ? 'number' : field.kind === 'time' ? 'text' : 'text'}
                        inputMode={field.kind === 'time' ? 'numeric' : undefined}
                        placeholder={field.kind === 'time' ? 'HH:MM' : undefined}
                        min={field.min}
                        max={field.max}
                        disabled={!cfgReady || busy}
                        value={value == null ? '' : String(value)}
                        onChange={(e) =>
                          setDraft((prev) =>
                            nestedSet(
                              prev,
                              field.key,
                              field.kind === 'int' ? Number(e.target.value) : e.target.value,
                            ),
                          )
                        }
                      />
                    )}
                  </div>
                </div>
              )
            })}
          </article>
        ))}

        <article className="panel" style={{ marginBottom: 16 }}>
          <p className="eyebrow">{t('settings_sec_block_rules')}</p>
          <p className="muted" style={{ marginBottom: 12 }}>{t('settings_block_rules_blurb')}</p>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>{t('settings_br_service')}</th>
                  <th>{t('settings_br_enabled')}</th>
                  <th>{t('settings_br_threshold')}</th>
                  <th>{t('settings_br_window')}</th>
                </tr>
              </thead>
              <tbody>
                {blockRules.map((row) => (
                  <tr key={row.id || row.service}>
                    <td className="mono">{row.service}</td>
                    <td>
                      <Switch
                        checked={row.enabled}
                        loading={!cfgReady}
                        disabled={busy || !cfgReady}
                        label={row.service}
                        onChange={(next) => updateRule(row.service, { enabled: next })}
                      />
                    </td>
                    <td>
                      <input
                        type="number"
                        min={1}
                        max={100}
                        disabled={!cfgReady || busy}
                        value={row.threshold}
                        onChange={(e) =>
                          updateRule(row.service, { threshold: Math.max(1, Number(e.target.value) || 1) })
                        }
                        style={{ width: 88 }}
                      />
                    </td>
                    <td>
                      <input
                        type="number"
                        min={1}
                        max={1440}
                        disabled={!cfgReady || busy}
                        value={Math.max(1, Math.round(row.window_seconds / 60))}
                        onChange={(e) => {
                          const mins = Math.max(1, Math.min(1440, Number(e.target.value) || 30))
                          updateRule(row.service, { window_seconds: mins * 60 })
                        }}
                        style={{ width: 88 }}
                      />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </article>

        <button type="submit" className="btn" disabled={busy}>{t('btn_save')}</button>
      </form>

      <article className="panel" style={{ marginTop: 24 }}>
        <p className="eyebrow">{t('settings_pin')}</p>
        <h3>{pinEnabled ? t('settings_pin_set') : t('settings_pin_none')}</h3>
        <p className="muted">{t('settings_pin_desc')}</p>
        {linked && (
          <div className="lock-callout linked" style={{ marginTop: 12, marginBottom: 12 }} role="status">
            <p style={{ marginBottom: 0 }}>{t('settings_pin_dashboard_hint')}</p>
          </div>
        )}
        <div className="inline-form">
          {pinEnabled && (
            <PasswordInput
              value={pinCurrent}
              onChange={setPinCurrent}
              placeholder={t('settings_pin_current')}
              numeric
            />
          )}
          <PasswordInput
            value={pin}
            onChange={setPin}
            placeholder={t('settings_pin_new')}
            numeric
            autoComplete="new-password"
          />
          <button type="button" className="btn" onClick={() => void setPinAction()}>{t('btn_save')}</button>
          {pinEnabled && (
            <button type="button" className="btn danger" onClick={() => void clearPin()}>{t('btn_remove')}</button>
          )}
        </div>
      </article>
    </section>
  )
}
