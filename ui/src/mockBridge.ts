import type { MotorStatus } from './bridge'
import { CATALOG, detectBrowserLang, type Lang } from './i18n/catalog'

type AsteriaApi = {
  session(): Promise<{
    ok: boolean
    locked: boolean
    pin_enabled: boolean
    account_linked?: boolean
    account_email?: string
  }>
  unlock(pin: string): Promise<{ ok: boolean; reason: string; lockout_seconds: number }>
  ping(): Promise<{ ok: boolean; motor: 'online' | 'offline' }>
  status(): Promise<MotorStatus>
  catalog(): Promise<{ ok: boolean; services: Array<{ port: string; service: string }>; rdp_secure_port?: number }>
  ipc(cmd: string, args?: Record<string, unknown>): Promise<Record<string, unknown>>
  cloud(method: string, path: string, body?: Record<string, unknown>): Promise<Record<string, unknown>>
  pin(action: string, value?: string, current?: string): Promise<Record<string, unknown>>
  shell(action: string): Promise<Record<string, unknown>>
  account(action?: string, email?: string, password?: string, pin?: string): Promise<Record<string, unknown>>
  harden(action?: string, target?: string): Promise<Record<string, unknown>>
  rdp(action?: string, mode?: string): Promise<Record<string, unknown>>
  ir(action: string, username?: string): Promise<Record<string, unknown>>
  update_banner(action?: string): Promise<Record<string, unknown>>
  i18n(lang?: string): Promise<Record<string, unknown>>
}

const MOCK_SERVICES = [
  { port: '3389', service: 'RDP' },
  { port: '1433', service: 'MSSQL' },
  { port: '3306', service: 'MYSQL' },
  { port: '21', service: 'FTP' },
  { port: '22', service: 'SSH' },
]

// Browser UX testing: ?locked=1 exercises the PIN gate; ?linked=0 hides account recovery.
let locked = new URLSearchParams(window.location.search).get('locked') === '1'
let pinEnabled = true
let accountLinked = new URLSearchParams(window.location.search).get('linked') !== '0'
let accountEmail = accountLinked ? 'ops@asteria.run' : ''
let rdpProtected = false
let lang: Lang = detectBrowserLang()
const running = new Set<string>(['SSH'])
const blocked = new Set<string>(['203.0.113.10'])
let updateStatus: Record<string, unknown> | null = {
  phase: 'downloading',
  to_version: '4.9.35',
  from_version: '4.9.34',
  progress: 42,
  detail: 'Mock update download',
}
let config: Record<string, unknown> = {
  alert_email_enabled: true,
  instant_email_for_critical: true,
  daily_digest_enabled: false,
  auto_block_enabled: true,
  auto_block_threshold: 3,
  auto_block_duration_hours: 24,
  webhook_enabled: false,
  webhook_url: '',
  whitelist_ips: ['192.168.1.1'],
  ransomware_protection_enabled: true,
  canary_files_enabled: true,
  protection: { defense_policy: 'observe', defense_policy_locked: false, network_guard: { enabled: true } },
}

function statusPayload(): MotorStatus {
  return {
    ok: true,
    daemon: true,
    motor_ok: true,
    version: '4.9.35-mock',
    protection_mode: running.size ? 'active' : 'inactive',
    running_services: Array.from(running),
    ransomware_running: Boolean(config.ransomware_protection_enabled),
    token_present: true,
    defense_policy: {
      present: true,
      defense_policy: (config.protection as { defense_policy?: string })?.defense_policy || 'observe',
      defense_policy_version: 'mock',
      defense_policy_locked: Boolean((config.protection as { defense_policy_locked?: boolean })?.defense_policy_locked),
    },
    network_guard: {
      present: true,
      enabled: Boolean((config.protection as { network_guard?: { enabled?: boolean } })?.network_guard?.enabled),
      running: true,
      maintenance: false,
      drift: true,
      internet_ok: true,
      baseline_version: 14,
    },
    rs_quarantine: { active: false, entries: 0, canary_files: 42, alerts_total: 1 },
    resources: { cpu_percent: 12, ram_percent: 48 },
  }
}

export function installMockBridge(): void {
  const api: AsteriaApi = {
    async session() {
      return {
        ok: true,
        locked,
        pin_enabled: pinEnabled,
        account_linked: accountLinked,
        account_email: accountEmail,
        server_name: 'DESKTOP-MOCK',
        token_present: true,
        token_preview: 'a1b2c3d4e5f60718…',
        client_id: '57',
      }
    },
    async unlock(pin: string) {
      if (pin === '0000' || pin.length >= 4) {
        locked = false
        return { ok: true, reason: 'ok', lockout_seconds: 0 }
      }
      return { ok: false, reason: 'bad_pin', lockout_seconds: 0 }
    },
    async ping() {
      return { ok: true, motor: 'online' }
    },
    async status() {
      if (locked) return { ok: false, error: 'gui_locked' }
      return statusPayload()
    },
    async catalog() {
      if (locked) return { ok: false, error: 'gui_locked', services: [] }
      return { ok: true, services: MOCK_SERVICES, rdp_secure_port: 53389 }
    },
    async ipc(cmd, args = {}) {
      if (locked) return { ok: false, error: 'gui_locked' }
      const name = cmd.toUpperCase()
      if (name === 'THREAT_TOP') {
        return {
          ok: true,
          total: blocked.size,
          attackers: Array.from(blocked).map((ip, i) => ({
            ip,
            score: 80 - i * 10,
            events: 3 + i,
            last_seen: new Date().toISOString(),
            username: i === 0 ? 'attacker' : '',
          })),
        }
      }
      if (name === 'BLOCK_IP') {
        blocked.add(String(args.ip || ''))
        return { ok: true }
      }
      if (name === 'UNBLOCK_IP') {
        blocked.delete(String(args.ip || ''))
        return { ok: true }
      }
      if (name === 'CLEAR_FIREWALL') {
        blocked.clear()
        return { ok: true }
      }
      if (name === 'HONEYPOT_LIST') {
        return { ok: true, services: Array.from(running).map((service) => ({ service })) }
      }
      if (name === 'HONEYPOT_START') {
        running.add(String(args.service || '').toUpperCase())
        return { ok: true }
      }
      if (name === 'HONEYPOT_STOP') {
        running.delete(String(args.service || '').toUpperCase())
        return { ok: true }
      }
      if (name.startsWith('NG_') || name.startsWith('RS_')) {
        return { ok: true }
      }
      if (name === 'STATUS') return statusPayload()
      return { ok: false, error: `mock_ipc_denied:${name}` }
    },
    async cloud(method, path, body) {
      if (locked) return { ok: false, error: 'gui_locked' }
      if (path.replace(/^\//, '') !== 'threats/config') {
        return { ok: false, error: 'cloud_denied' }
      }
      if (method.toUpperCase() === 'GET') return { ok: true, data: config }
      config = { ...config, ...(body || {}) }
      if (body?.protection && typeof body.protection === 'object') {
        config.protection = { ...(config.protection as object), ...(body.protection as object) }
      }
      return { ok: true, data: config }
    },
    async pin(action, value = '', current = '') {
      if (action === 'set' && value.length >= 4) {
        pinEnabled = true
        locked = false
        return { ok: true, reason: 'ok' }
      }
      if (action === 'clear' && (current || value)) {
        pinEnabled = false
        locked = false
        return { ok: true, reason: 'ok' }
      }
      return { ok: false, reason: 'bad_pin' }
    },
    async shell(action) {
      console.info('[mock shell]', action)
      if (action === 'minimize' && pinEnabled) {
        locked = true
        window.dispatchEvent(new CustomEvent('asteria-session-gate'))
      }
      if (action === 'about') {
        return {
          ok: true,
          version: '4.9.35-mock',
          website: 'https://asteria.run',
          github: 'https://github.com/cevdetaksac/asteria-client',
          log_path: 'C:\\ProgramData\\YesNext\\CloudHoneypotClient\\logs\\mock.log',
        }
      }
      if (action === 'check_updates') {
        if (locked) return { ok: false, error: 'gui_locked' }
        return {
          ok: true,
          update_available: false,
          installed: '4.9.35-mock',
          latest: '4.9.35',
          message: 'already_current',
        }
      }
      if (action === 'open_github' || action === 'open_website' || action === 'open_servers') {
        return { ok: true, mock: true, action }
      }
      return { ok: true, mock: true, action }
    },
    async account(action = 'status', email = '', password = '', pin = '') {
      if (locked) return { ok: false, error: 'gui_locked' }
      if (action === 'status') return { ok: true, linked: accountLinked, email: accountEmail }
      if (!pinEnabled) return { ok: false, error: 'pin_required' }
      if (pin.length < 4) return { ok: false, error: 'pin_verification_failed', reason: 'bad_pin' }
      if (!email || !password) return { ok: false, error: 'missing_credentials' }
      if (action === 'link') {
        accountLinked = true
        accountEmail = email
        return { ok: true, account_linked: true, email }
      }
      if (action === 'unlink') {
        accountLinked = false
        accountEmail = ''
        return { ok: true, account_linked: false }
      }
      return { ok: false, error: 'account_unknown_action' }
    },
    async harden(action = 'status', target = '') {
      if (locked) return { ok: false, error: 'gui_locked' }
      if (action === 'status') {
        return {
          ok: true,
          checks: [
            { id: 'firewall', label: 'Windows Firewall', ok: true, detail: 'Aktif', fixable: false },
            { id: 'antivirus', label: 'Windows Defender', ok: false, detail: 'Kapalı — risk', fixable: true },
            { id: 'winrm', label: 'WinRM', ok: false, detail: 'Açık — uzaktan risk', fixable: true },
            { id: 'nla', label: 'RDP NLA', ok: false, detail: 'Kapalı — risk', fixable: true },
          ],
        }
      }
      if (action === 'fix') return { ok: true, target, mock: true }
      return { ok: false, error: 'harden_unknown_action' }
    },
    async rdp(action = 'status', mode = '') {
      if (locked) return { ok: false, error: 'gui_locked' }
      if (action === 'status') {
        return {
          ok: true,
          protected: rdpProtected,
          current_port: rdpProtected ? 53389 : 3389,
          secure_port: 53389,
          admin: true,
        }
      }
      if (action === 'move') {
        const mv = mode || (rdpProtected ? 'rollback' : 'secure')
        rdpProtected = mv === 'secure'
        return {
          ok: true,
          protected: rdpProtected,
          current_port: rdpProtected ? 53389 : 3389,
          secure_port: 53389,
          mode: mv,
        }
      }
      return { ok: false, error: 'rdp_unknown_action' }
    },
    async ir(action, username = '') {
      if (locked) return { ok: false, error: 'gui_locked' }
      if (!username) return { ok: false, error: 'username_required' }
      return { ok: true, action, username, mock: true }
    },
    async update_banner(action = 'status') {
      if (locked) return { ok: false, error: 'gui_locked' }
      if (action === 'dismiss') {
        updateStatus = null
        return { ok: true, dismissed: true }
      }
      return { ok: true, status: updateStatus, current_version: '4.9.35-mock' }
    },
    async i18n(next = '') {
      const requested = String(next || '').trim().toLowerCase()
      if (requested === 'tr' || requested === 'en') lang = requested
      else if (!requested) lang = detectBrowserLang()
      return { ok: true, lang, strings: CATALOG[lang], restart_hint: Boolean(requested) }
    },
  }

  window.pywebview = { api }
  window.dispatchEvent(new Event('pywebviewready'))
  console.info('[Asteria] Mock bridge installed for browser UX testing (PIN: any 4+ digits)')
}
