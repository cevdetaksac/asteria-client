import { useCallback, useEffect, useState } from 'react'
import { motorBridge } from '../bridge'
import { DetailModal } from '../components/DetailModal'
import { FeatureGuide } from '../components/FeatureGuide'
import { t } from '../i18n'

type Props = {
  onToast: (msg: string, kind?: 'ok' | 'err') => void
}

type CatalogService = { port: string; service: string }

type RelocateRow = {
  service: string
  well_known: number
  current_port: number
  target_port: number
  default_safe_port: number
  supported?: boolean
  relocated?: boolean
  relocating?: boolean
  port_available?: boolean | null
  target_busy?: boolean
  last_status?: string | null
  last_reason?: string | null
}

const FALLBACK_ROWS: RelocateRow[] = [
  { service: 'RDP', well_known: 3389, current_port: 3389, target_port: 43389, default_safe_port: 43389, supported: true },
  { service: 'MSSQL', well_known: 1433, current_port: 1433, target_port: 41433, default_safe_port: 41433, supported: true },
  { service: 'MYSQL', well_known: 3306, current_port: 3306, target_port: 43306, default_safe_port: 43306, supported: true },
  { service: 'SSH', well_known: 22, current_port: 22, target_port: 40022, default_safe_port: 40022, supported: true },
  { service: 'FTP', well_known: 21, current_port: 21, target_port: 40021, default_safe_port: 40021, supported: false },
]

export function ServicesPage({ onToast }: Props) {
  const [catalog, setCatalog] = useState<CatalogService[]>([])
  const [running, setRunning] = useState<string[]>([])
  const [busy, setBusy] = useState<string>('')
  const [loading, setLoading] = useState(true)
  const [catalogHydrated, setCatalogHydrated] = useState(false)
  const [pageHelp, setPageHelp] = useState(false)
  const [relocateRows, setRelocateRows] = useState<RelocateRow[]>(FALLBACK_ROWS)
  const [relocateBusy, setRelocateBusy] = useState<string>('')
  const [autoBait, setAutoBait] = useState(true)
  const [targets, setTargets] = useState<Record<string, number>>({})

  const refreshRelocate = useCallback(async () => {
    const result = await motorBridge.relocate('prefill')
    if (!result.ok) {
      // Prefer cloud tunnel-status via host allowlist when relocate bridge missing
      const tunnel = await motorBridge.cloud('GET', 'premium/tunnel-status')
      if (tunnel.ok && tunnel.data && typeof tunnel.data === 'object') {
        const state = (tunnel.data as Record<string, unknown>).relocate_state
        if (state && typeof state === 'object') {
          setRelocateRows((prev) =>
            prev.map((row) => {
              const entry = (state as Record<string, unknown>)[row.service]
              let target = row.default_safe_port
              if (entry && typeof entry === 'object') {
                const saved = (entry as Record<string, unknown>).saved_target_port
                const dsp = (entry as Record<string, unknown>).default_safe_port
                const n = Number(saved ?? dsp ?? target)
                if (n > 0 && n !== 53389 && !(n >= 90000 && n <= 99999)) target = n
              }
              return { ...row, target_port: target }
            }),
          )
        }
      }
      return
    }
    const services = Array.isArray(result.services) ? (result.services as RelocateRow[]) : []
    if (services.length) {
      setRelocateRows(
        services.map((row) => ({
          service: String(row.service || '').toUpperCase(),
          well_known: Number(row.well_known || 0),
          current_port: Number(row.current_port || row.well_known || 0),
          target_port: Number(row.target_port || row.default_safe_port || 0),
          default_safe_port: Number(row.default_safe_port || 0),
          supported: row.supported !== false,
          // Local truth: only badge when port actually left the well-known.
          relocated:
            Number(row.current_port || row.well_known || 0) !==
            Number(row.well_known || 0),
          relocating: Boolean(row.relocating),
          port_available: row.port_available as boolean | null | undefined,
          target_busy: Boolean(row.target_busy),
          last_status: row.last_status ? String(row.last_status) : null,
          last_reason: row.last_reason ? String(row.last_reason) : null,
        })),
      )
    }
    if (result.targets && typeof result.targets === 'object') {
      const next: Record<string, number> = {}
      for (const [k, v] of Object.entries(result.targets as Record<string, unknown>)) {
        next[k] = Number(v)
      }
      setTargets(next)
    }
  }, [])

  const refresh = useCallback(async () => {
    setLoading(true)
    try {
      const [cat, list, status] = await Promise.all([
        motorBridge.catalog(),
        motorBridge.ipc('HONEYPOT_LIST'),
        motorBridge.status(),
      ])
      setCatalog(Array.isArray(cat.services) ? cat.services : [])
      setCatalogHydrated(true)
      const fromList = Array.isArray(list.services) ? list.services : []
      const names = fromList
        .map((row) => {
          if (typeof row === 'string') return row.toUpperCase()
          if (row && typeof row === 'object' && 'service' in row) {
            return String((row as { service: string }).service).toUpperCase()
          }
          return ''
        })
        .filter(Boolean)
      const fromStatus = Array.isArray(status.running_services)
        ? status.running_services.map((s) => String(s).toUpperCase())
        : []
      setRunning(Array.from(new Set([...names, ...fromStatus])))
      await refreshRelocate()
    } catch (reason) {
      onToast(reason instanceof Error ? reason.message : String(reason), 'err')
    } finally {
      setLoading(false)
    }
  }, [onToast, refreshRelocate])

  useEffect(() => {
    void refresh()
    const timer = window.setInterval(() => void refresh(), 12000)
    return () => window.clearInterval(timer)
  }, [refresh])

  const toggle = async (svc: CatalogService, start: boolean) => {
    setBusy(svc.service)
    try {
      const result = start
        ? await motorBridge.ipc('HONEYPOT_START', { service: svc.service, port: Number(svc.port) })
        : await motorBridge.ipc('HONEYPOT_STOP', { service: svc.service })
      onToast(
        result.ok
          ? start
            ? t('toast_svc_start', { service: svc.service })
            : t('toast_svc_stop', { service: svc.service })
          : String(result.error || 'HONEYPOT'),
        result.ok ? 'ok' : 'err',
      )
      await refresh()
    } finally {
      setBusy('')
    }
  }

  const setTarget = (service: string, value: string) => {
    const n = Number(value)
    setRelocateRows((rows) =>
      rows.map((row) => (row.service === service ? { ...row, target_port: Number.isFinite(n) ? n : row.target_port } : row)),
    )
    if (Number.isFinite(n)) {
      setTargets((prev) => ({ ...prev, [service]: n }))
    }
  }

  const runRelocate = async (row: RelocateRow) => {
    const target = Number(targets[row.service] ?? row.target_port ?? row.default_safe_port)
    if (!target || target < 1024 || target > 65535 || target === 53389 || (target >= 90000 && target <= 99999)) {
      onToast(t('relocate_forbidden_port'), 'err')
      return
    }
    if (row.target_busy || row.port_available === false) {
      onToast(t('relocate_target_busy', { port: target }), 'err')
      return
    }
    if (row.relocating) {
      onToast(t('relocate_in_progress'), 'err')
      return
    }
    if (!window.confirm(t('relocate_confirm', { service: row.service, port: target }))) return
    setRelocateBusy(row.service)
    try {
      const result = await motorBridge.relocate('run', row.service, target, autoBait)
      if (result.ok || result.status === 'ok') {
        onToast(
          t('toast_relocate_ok', {
            service: row.service,
            old: String(result.old_port ?? row.current_port),
            port: String(result.new_port ?? result.target_port ?? target),
          }),
          'ok',
        )
      } else if (result.status === 'rollback') {
        onToast(
          t('toast_relocate_rollback', {
            service: row.service,
            reason: String(result.reason || result.error || 'rollback'),
          }),
          'err',
        )
      } else {
        onToast(String(result.error || result.reason || t('toast_relocate_fail')), 'err')
      }
      await refreshRelocate()
    } finally {
      setRelocateBusy('')
    }
  }

  return (
    <section className="page">
      <div className="page-head">
        <div>
          <p className="eyebrow">{t('services_eyebrow')}</p>
          <h2>{t('services_title')}{loading && catalogHydrated && <span className="inline-spinner" />}</h2>
          <p className="muted">{t('services_blurb')}</p>
        </div>
        <div className="btn-row">
          <button type="button" className="btn ghost sm" onClick={() => setPageHelp(true)}>
            {t('help_more')}
          </button>
          <button type="button" className="btn" onClick={() => void refresh()}>{t('btn_refresh')}</button>
        </div>
      </div>

      <div className="service-grid">
        {!catalogHydrated && <p className="muted">{t('status_section_loading')}</p>}
        {catalogHydrated && catalog.length === 0 && <p className="muted">{t('services_empty')}</p>}
        {catalog.map((svc) => {
          const active = running.includes(svc.service.toUpperCase())
          const listenPort = Number(svc.port)
          const rowBusy = loading || busy === svc.service
          return (
            <article
              key={`${svc.service}-${svc.port}`}
              className={`service-card ${active ? 'active' : ''}${loading ? ' loading' : ''}`}
            >
              <h3 className="service-card-title">
                {svc.service}
                <span className="port"> : {listenPort}</span>
              </h3>
              <div className="service-actions">
                <button
                  type="button"
                  className={`btn ${active && !loading ? 'danger' : ''}`}
                  disabled={rowBusy}
                  onClick={() => void toggle(svc, !active)}
                >
                  {loading
                    ? t('label_loading')
                    : active
                      ? t('layers_close')
                      : t('layers_open')}
                </button>
              </div>
            </article>
          )
        })}
      </div>

      <article className={`panel rdp-tool-card${loading ? ' loading' : ''}`}>
        <div className="rdp-tool-head">
          <div>
            <p className="eyebrow">{t('relocate_eyebrow')}</p>
            <h3>{t('relocate_title')}</h3>
            <p className="muted">{t('relocate_blurb')}</p>
          </div>
        </div>
        <label className="relocate-bait">
          <input
            type="checkbox"
            checked={autoBait}
            onChange={(e) => setAutoBait(e.target.checked)}
          />
          <span>{t('relocate_auto_bait')}</span>
        </label>
        <div className="table-wrap" style={{ marginTop: 12 }}>
          <table>
            <thead>
              <tr>
                <th>{t('relocate_col_service')}</th>
                <th>{t('relocate_col_known')}</th>
                <th>{t('relocate_col_current')}</th>
                <th>{t('relocate_col_target')}</th>
                <th className="actions-head">{t('threat_col_actions')}</th>
              </tr>
            </thead>
            <tbody>
              {relocateRows.map((row) => {
                const target = targets[row.service] ?? row.target_port
                const busyRow = relocateBusy === row.service || Boolean(row.relocating)
                const anyBusy = Boolean(relocateBusy) || relocateRows.some((r) => r.relocating)
                return (
                  <tr key={row.service}>
                    <td>
                      <strong>{row.service}</strong>
                      {row.relocated ? (
                        <span className="pill ok" style={{ marginLeft: 8 }}>{t('relocate_badge_ok', { port: row.current_port })}</span>
                      ) : null}
                      {row.relocating ? (
                        <span className="pill muted" style={{ marginLeft: 8 }}>{t('relocate_badge_busy')}</span>
                      ) : null}
                    </td>
                    <td className="mono">{row.well_known}</td>
                    <td className="mono">{row.current_port}</td>
                    <td>
                      <input
                        className="input sm mono"
                        type="number"
                        min={1024}
                        max={65535}
                        value={target}
                        disabled={busyRow || row.supported === false}
                        onChange={(e) => setTarget(row.service, e.target.value)}
                        aria-label={`${row.service} target port`}
                      />
                      {row.target_busy || row.port_available === false ? (
                        <div className="muted" style={{ fontSize: 11 }}>{t('relocate_target_busy', { port: target })}</div>
                      ) : null}
                    </td>
                    <td className="actions-cell">
                      <button
                        type="button"
                        className="btn sm"
                        disabled={
                          busyRow
                          || row.supported === false
                          || anyBusy
                          || row.target_busy
                          || row.port_available === false
                        }
                        onClick={() => void runRelocate(row)}
                      >
                        {busyRow ? t('label_loading') : t('relocate_btn')}
                      </button>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
        <p className="muted" style={{ marginTop: 10, fontSize: 12 }}>{t('relocate_hint_4xxxx')}</p>
      </article>

      {pageHelp && (
        <DetailModal
          title={t('services_title')}
          guide={<FeatureGuide prefix="help_services" />}
          onClose={() => setPageHelp(false)}
        />
      )}
    </section>
  )
}
