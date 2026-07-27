export type MotorStatus = Record<string, unknown> & {
  ok?: boolean
  motor_ok?: boolean
  daemon?: boolean
  version?: string
  running_services?: string[]
  protection_mode?: string
  ransomware_running?: boolean
  defense_policy?: Record<string, unknown>
  network_guard?: Record<string, unknown>
  rs_quarantine?: Record<string, unknown>
  resources?: Record<string, unknown>
  persistence?: Record<string, unknown>
  public_ip?: string | null
}

export type BridgeResult = Record<string, unknown> & {
  ok?: boolean
  error?: string
  reason?: string
}

type AsteriaApi = {
  session(): Promise<{
    ok: boolean
    locked: boolean
    pin_enabled: boolean
    account_linked?: boolean
    account_email?: string
    server_name?: string
    token_present?: boolean
    token_preview?: string
    client_id?: string
  }>
  unlock(pin: string): Promise<{ ok: boolean; reason: string; lockout_seconds: number }>
  ping(): Promise<{
    ok: boolean
    motor: 'online' | 'offline'
    update_stuck?: boolean
    recovered?: boolean
    update_recovery?: Record<string, unknown>
  }>
  status(): Promise<MotorStatus>
  catalog(): Promise<{ ok: boolean; services: Array<{ port: string; service: string }>; rdp_secure_port?: number }>
  ipc(cmd: string, args?: Record<string, unknown>): Promise<BridgeResult>
  cloud(method: string, path: string, body?: Record<string, unknown>): Promise<BridgeResult>
  pin(action: string, value?: string, current?: string): Promise<BridgeResult>
  shell(action: string, path?: string): Promise<BridgeResult>
  account(action?: string, email?: string, password?: string, pin?: string): Promise<BridgeResult>
  harden(action?: string, target?: string): Promise<BridgeResult>
  rdp(action?: string, mode?: string): Promise<BridgeResult>
  ir(action: string, username?: string, newPassword?: string): Promise<BridgeResult>
  update_banner(action?: string): Promise<BridgeResult>
  i18n(lang?: string): Promise<BridgeResult>
}

declare global {
  interface Window {
    pywebview?: { api?: Partial<AsteriaApi> }
    chrome?: { webview?: unknown }
  }
}

const READY_TIMEOUT_MS = 20000
const POLL_MS = 60

/** pywebview publishes `api` progressively; only trust it once methods exist. */
function resolveApi(): AsteriaApi | null {
  const api = window.pywebview?.api
  return api && typeof api.session === 'function' ? (api as AsteriaApi) : null
}

export function isNativeHost(): boolean {
  return Boolean(window.chrome?.webview) || Boolean(window.pywebview)
}

let pending: Promise<void> | null = null

/** Resolves when the native (or mock) bridge has finished injecting its API. */
export function bridgeReady(): Promise<void> {
  if (resolveApi()) return Promise.resolve()
  if (!pending) {
    pending = new Promise<void>((resolve, reject) => {
      const started = Date.now()
      let timer = 0
      const done = (fail?: Error) => {
        window.clearTimeout(timer)
        window.removeEventListener('pywebviewready', tick)
        if (fail) reject(fail)
        else resolve()
      }
      function tick() {
        if (resolveApi()) {
          done()
          return
        }
        if (Date.now() - started > READY_TIMEOUT_MS) {
          done(new Error('Asteria köprüsü yüklenemedi (pywebview API yanıt vermiyor)'))
          return
        }
        timer = window.setTimeout(tick, POLL_MS)
      }
      window.addEventListener('pywebviewready', tick)
      tick()
    }).finally(() => {
      pending = null
    })
  }
  return pending
}

async function withApi<T>(run: (api: AsteriaApi) => Promise<T>): Promise<T> {
  await bridgeReady()
  const api = resolveApi()
  if (!api) throw new Error('Asteria köprüsü hazır değil')
  return run(api)
}

/** Optional ops: an older asteria-gui.exe may not expose newer methods yet. */
async function optional(
  name: keyof AsteriaApi,
  run: (api: AsteriaApi) => Promise<BridgeResult>,
): Promise<BridgeResult> {
  await bridgeReady()
  const api = resolveApi()
  if (!api) return { ok: false, error: 'bridge_not_ready' }
  if (typeof api[name] !== 'function') {
    return { ok: false, error: `bridge_method_missing:${String(name)}` }
  }
  return run(api)
}

export const motorBridge = {
  session: () => withApi((api) => api.session()),
  unlock: (pin: string) => withApi((api) => api.unlock(pin)),
  ping: () => withApi((api) => api.ping()),
  status: () => withApi((api) => api.status()),
  catalog: () => withApi((api) => api.catalog()),
  ipc: (cmd: string, args?: Record<string, unknown>) => withApi((api) => api.ipc(cmd, args)),
  cloud: (method: string, path: string, body?: Record<string, unknown>) =>
    withApi((api) => api.cloud(method, path, body)),
  pin: (action: string, value = '', current = '') =>
    withApi((api) => api.pin(action, value, current)),
  shell: (action: string, path = '') => withApi((api) => api.shell(action, path)),
  account: (action = 'status', email = '', password = '', pin = '') =>
    optional('account', (api) => api.account(action, email, password, pin)),
  harden: (action = 'status', target = '') => optional('harden', (api) => api.harden(action, target)),
  rdp: (action = 'status', mode = '') => optional('rdp', (api) => api.rdp(action, mode)),
  ir: (action: string, username = '', newPassword = '') =>
    optional('ir', (api) => api.ir(action, username, newPassword)),
  update_banner: (action = 'status') => optional('update_banner', (api) => api.update_banner(action)),
  i18n: (lang = '') => optional('i18n', (api) => api.i18n(lang)),
}
