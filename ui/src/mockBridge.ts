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
  shell(action: string, path?: string): Promise<Record<string, unknown>>
  account(action?: string, email?: string, password?: string, pin?: string): Promise<Record<string, unknown>>
  harden(action?: string, target?: string): Promise<Record<string, unknown>>
  rdp(action?: string, mode?: string): Promise<Record<string, unknown>>
  relocate?(action?: string, service?: string, port?: number, autoStartBait?: boolean): Promise<Record<string, unknown>>
  ir(action: string, username?: string, newPassword?: string): Promise<Record<string, unknown>>
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
const blocked = new Set<string>([
  '34.204.119.63',
  '50.16.16.211',
  '162.243.103.246',
  '185.220.101.45',
  '203.0.113.10',
])
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
  whitelist_ips: ['1.1.1.1'],
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
    public_ip: '203.0.113.42',
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
    resources: {
      host_cpu_percent: 18,
      host_memory_percent: 52,
      process_cpu_percent: 3,
      process_rss_mb: 86,
      net_recv_bps: 12000,
      net_sent_bps: 4200,
    },
    api: {
      ok: true,
      heartbeat_ok: true,
      last_ok_at: Date.now() / 1000 - 12,
      last_check_at: Date.now() / 1000 - 12,
      last_heartbeat_at: Date.now() / 1000 - 12,
    },
    commands_recent: [
      {
        command_type: 'status_ping',
        ok: true,
        executed_at: Date.now() / 1000 - 45,
        source: 'cloud',
        message: 'ok',
      },
    ],
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
          recent_alerts: Array.from(blocked).map((ip, i) => ({
            source_ip: ip,
            timestamp: Date.now() / 1000 - i * 90,
            threat_score: 95 - i,
            severity: 'critical',
            threat_type: 'failed_logon',
            title: 'Block Rule: Network logon brute force',
            description: `Repeated failed logons from ${ip}; rule matched failed_logon burst.`,
            username: i === 0 ? 'attacker' : 'admin',
            target_service: 'RDP',
            recommended_action: 'Block IP and review account lockouts',
          })),
          attackers: Array.from(blocked).map((ip, i) => ({
            ip,
            threat_score: 80 - i * 10,
            score: 80 - i * 10,
            failed_attempts: 3 + i * 4,
            events: 3 + i * 4,
            last_seen: Date.now() / 1000 - i * 40,
            username: i === 0 ? 'attacker' : '',
            usernames: i === 0 ? ['attacker', 'admin'] : ['guest'],
            services: i === 0 ? ['RDP', 'SMB'] : ['SSH'],
            title: i === 0 ? 'Block Rule: Network logon brute force' : 'Failed Logon',
            description:
              i === 0
                ? `failed×${12 + i} · failed_logon · RDP; users: attacker, admin`
                : `failed×${3 + i} · SSH`,
            threat_type: 'failed_logon',
            is_blocked: true,
          })),
        }
      }
      if (name === 'IP_TABLE') {
        const watch = [
          {
            ip: '198.51.100.44',
            attempts: 12,
            score: 64,
            services: ['RDP'],
            reason: 'failed×12 · failed_logon · RDP',
            status: 'watching',
            last_seen: Date.now() / 1000 - 30,
          },
          {
            ip: '203.0.113.77',
            attempts: 4,
            score: 28,
            services: ['SSH'],
            reason: 'failed×4 · brute_force · SSH',
            status: 'watching',
            last_seen: Date.now() / 1000 - 90,
          },
        ]
        const blockedRows = Array.from(blocked).map((ip) => ({
          ip,
          attempts: 0,
          score: 0,
          reason: 'firewall',
          status: 'blocked',
          last_seen: Date.now() / 1000 - 120,
        }))
        const wl = Array.isArray(config.whitelist_ips) ? config.whitelist_ips.map(String) : []
        return {
          ok: true,
          engine: true,
          watching: watch,
          blocked: blockedRows,
          whitelist: wl.map((ip) => ({ ip, reason: 'whitelist', status: 'whitelisted' })),
          totals: { watching: watch.length, blocked: blockedRows.length, whitelist: wl.length },
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
      if (name === 'SHARES_LIST') {
        return {
          ok: true,
          custom_count: 1,
          default_only: false,
          shares: [
            { name: 'ADMIN$', path: 'C:\\Windows', is_default: true, current_users: 0 },
            { name: 'C$', path: 'C:\\', is_default: true, current_users: 0 },
            { name: 'IPC$', path: '', is_default: true, current_users: 0 },
            { name: 'paylas', path: 'D:\\share', is_default: false, current_users: 1 },
          ],
        }
      }
      if (name === 'SHARE_REMOVE') {
        return { ok: true, name: String(args.name || '') }
      }
      if (name === 'SVC_LIST') {
        return {
          ok: true,
          unknown_count: 2,
          total_matched: 3,
          services: [
            {
              name: 'EvlWatcher',
              display: 'EvlWatcher service',
              path: 'C:\\Program Files\\EvlWatcher\\EvlWatcher.exe',
              known: false,
              status: 'Running',
            },
            {
              name: 'RadminVPN',
              display: 'Radmin VPN Control Service',
              path: 'C:\\Program Files\\Radmin VPN\\RvService.exe',
              known: false,
              status: 'Running',
            },
            {
              name: 'MySQL80',
              display: 'MySQL80',
              path: 'C:\\Program Files\\MySQL\\MySQL Server 8.0\\bin\\mysqld.exe',
              known: true,
              status: 'Running',
            },
          ],
        }
      }
      if (name === 'SVC_STOP') {
        return { ok: true, name: String(args.name || ''), status: 'stop_pending' }
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
      const p = path.replace(/^\//, '')
      if (p === 'alerts/list' && method.toUpperCase() === 'GET') {
        return {
          ok: true,
          data: {
            alerts: Array.from(blocked).map((ip, i) => ({
              source_ip: ip,
              timestamp: new Date(Date.now() - i * 120000).toISOString(),
              threat_score: 95,
              severity: 'critical',
              threat_type: 'failed_logon',
              title: 'Block Rule: Network logon brute force',
              description: `Cloud alert detail for ${ip}: repeated failed network logons.`,
              username: 'attacker',
              target_service: 'RDP',
              recommended_action: 'Block IP immediately',
            })),
          },
        }
      }
      if (p !== 'threats/config') {
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
    async shell(action, path = '') {
      console.info('[mock shell]', action, path || undefined)
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
        // Simulate silent motor update path (no browser).
        return {
          ok: true,
          update_available: true,
          started: true,
          installed: '4.9.47-mock',
          latest: '4.9.48',
          tag: 'v4.9.48',
          message: 'update_started',
        }
      }
      if (action === 'open_github' || action === 'open_website' || action === 'open_servers') {
        return { ok: true, mock: true, action }
      }
      return { ok: true, mock: true, action }
    },
    async account(action = 'status', email = '', password = '', pin = '', code = '') {
      if (locked) return { ok: false, error: 'gui_locked' }
      if (action === 'status') {
        return { ok: true, linked: accountLinked, email: accountEmail, needs_account_link: !accountLinked }
      }
      if (action === 'link') {
        if (!pinEnabled) {
          if (pin.length < 4) return { ok: false, error: 'pin_required' }
          pinEnabled = true
        } else if (pin.length < 4) {
          return { ok: false, error: 'pin_verification_failed', reason: 'bad_pin' }
        }
        if (!email || !password) return { ok: false, error: 'missing_credentials' }
        accountLinked = true
        accountEmail = email
        return { ok: true, account_linked: true, email }
      }
      if (!pinEnabled) return { ok: false, error: 'pin_required' }
      if (pin.length < 4) return { ok: false, error: 'pin_verification_failed', reason: 'bad_pin' }
      if (!email || !password) return { ok: false, error: 'missing_credentials' }
      if (action === 'unlink_request') {
        // Simulate cloud mailer missing in browser mock → soft fallback path.
        return { ok: false, error: 'unlink_mail_unavailable', mail_confirm: false }
      }
      if (action === 'unlink' || action === 'unlink_confirm') {
        if (action === 'unlink_confirm' && !code) {
          return { ok: false, error: 'missing_confirm_code' }
        }
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
          current_port: rdpProtected ? 43389 : 3389,
          secure_port: 43389,
          standard_port: 3389,
          admin: true,
          confirm_seconds: 60,
          pending: false,
          seconds_left: 0,
        }
      }
      if (action === 'begin' || action === 'move') {
        const mv = mode || (rdpProtected ? 'rollback' : 'secure')
        rdpProtected = mv === 'secure'
        return {
          ok: true,
          mode: mv,
          pending: action === 'begin',
          protected: rdpProtected,
          current_port: rdpProtected ? 43389 : 3389,
          secure_port: 43389,
          from_port: mv === 'secure' ? 3389 : 43389,
          to_port: rdpProtected ? 43389 : 3389,
          seconds_left: action === 'begin' ? 60 : 0,
          confirm_seconds: 60,
        }
      }
      if (action === 'confirm') {
        return {
          ok: true,
          confirmed: true,
          protected: rdpProtected,
          current_port: rdpProtected ? 43389 : 3389,
          secure_port: 43389,
        }
      }
      if (action === 'cancel') {
        rdpProtected = !rdpProtected
        return {
          ok: true,
          cancelled: true,
          protected: rdpProtected,
          current_port: rdpProtected ? 43389 : 3389,
          secure_port: 43389,
        }
      }
      return { ok: false, error: 'rdp_unknown_action' }
    },
    async relocate(action = 'prefill', service = '', port = 0, autoStartBait = false) {
      if (locked) return { ok: false, error: 'gui_locked' }
      const defaults: Record<string, number> = {
        RDP: 43389, MSSQL: 41433, MYSQL: 43306, SSH: 40022, FTP: 40021,
      }
      const known: Record<string, number> = {
        RDP: 3389, MSSQL: 1433, MYSQL: 3306, SSH: 22, FTP: 21,
      }
      if (action === 'prefill') {
        return {
          ok: true,
          admin: true,
          targets: defaults,
          services: Object.keys(defaults).map((svc) => ({
            service: svc,
            well_known: known[svc],
            current_port: svc === 'RDP' && rdpProtected ? 43389 : known[svc],
            target_port: defaults[svc],
            default_safe_port: defaults[svc],
            supported: svc !== 'FTP',
          })),
          defaults,
          well_known: known,
          relocate_state: {},
        }
      }
      if (action === 'run') {
        const svc = String(service || 'RDP').toUpperCase()
        const target = Number(port || defaults[svc] || 0)
        if (target === 53389 || (target >= 90000 && target <= 99999)) {
          return { ok: false, error: 'FORBIDDEN_PORT_53389', status: 'error' }
        }
        if (svc === 'RDP') rdpProtected = target !== 3389
        return {
          ok: true,
          status: 'ok',
          service: svc,
          old_port: known[svc] || 0,
          new_port: target,
          bait_started: Boolean(autoStartBait),
          reported: true,
        }
      }
      return { ok: false, error: 'relocate_unknown_action' }
    },
    async ir(action, username = '', newPassword = '') {
      if (locked) return { ok: false, error: 'gui_locked' }
      if (action === 'list') {
        return {
          ok: true,
          action: 'list',
          current_user: 'ops',
          counts: { total: 3, active: 2, disabled: 1 },
          users: [
            {
              username: 'ops',
              enabled: true,
              status: 'active',
              is_admin: true,
              is_self: true,
              has_session: true,
              session_status: 'Active',
              groups: ['Administrators'],
              last_logon: '2026-07-25T12:00:00Z',
              can_enable: false,
              can_disable: false,
              can_logoff: false,
              can_reset_password: true,
              protected: false,
            },
            {
              username: 'attacker',
              enabled: true,
              status: 'active',
              is_admin: false,
              is_self: false,
              has_session: true,
              session_status: 'Active',
              groups: ['Users', 'Remote Desktop Users'],
              last_logon: '2026-07-25T11:00:00Z',
              can_enable: false,
              can_disable: true,
              can_logoff: true,
              can_reset_password: true,
              protected: false,
            },
            {
              username: 'oldguest',
              enabled: false,
              status: 'disabled',
              is_admin: false,
              is_self: false,
              has_session: false,
              groups: ['Users'],
              last_logon: null,
              can_enable: true,
              can_disable: false,
              can_logoff: false,
              can_reset_password: true,
              protected: false,
            },
          ],
        }
      }
      if (!username) return { ok: false, error: 'username_required' }
      if (action === 'reset_password' && String(newPassword || '').length < 8) {
        return { ok: false, error: 'password_too_short' }
      }
      if (username === 'ops' && (action === 'logoff' || action === 'disable')) {
        return { ok: false, error: 'self_account' }
      }
      return { ok: true, action, username, mock: true }
    },
    async update_banner(action = 'status') {
      if (locked) return { ok: false, error: 'gui_locked' }
      if (action === 'dismiss') {
        updateStatus = null
        return { ok: true, dismissed: true }
      }
      if (action === 'abort' || action === 'recover') {
        updateStatus = {
          phase: 'failed',
          to_version: '4.9.35',
          from_version: '4.9.34',
          detail: 'operator_recover',
          error: 'operator_recover',
        }
        return {
          ok: true,
          aborted: true,
          motor_ok: true,
          status: updateStatus,
          current_version: '4.9.35-mock',
        }
      }
      const status = updateStatus
        ? { ...updateStatus, can_abort: true }
        : null
      return {
        ok: true,
        status,
        current_version: '4.9.35-mock',
        recovery: { stuck: false, actionable: Boolean(status), reasons: [], motor_ok: true },
      }
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
