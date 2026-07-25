import { useEffect, useState } from 'react'
import { motorBridge, type MotorStatus } from '../bridge'
import { t } from '../i18n'
import { asRecord, boolLabel, pick } from '../lib'

type Props = {
  status: MotorStatus | null
  online: boolean
  updatedAt: string
  onRefresh: () => void
  onToast: (msg: string, kind?: 'ok' | 'err') => void
  onNavigate: (page: 'services' | 'layers' | 'threat') => void
}

type HardenCheck = {
  id?: string
  label?: string
  ok?: boolean | null
  detail?: string
  fixable?: boolean
}

export function StatusPage({ status, online, updatedAt, onRefresh, onToast, onNavigate }: Props) {
  const running = Array.isArray(status?.running_services) ? status.running_services : []
  const defense = asRecord(status?.defense_policy)
  const ng = asRecord(status?.network_guard)
  const rs = asRecord(status?.rs_quarantine)
  const resources = asRecord(status?.resources)
  const [checks, setChecks] = useState<HardenCheck[]>([])
  const [rdp, setRdp] = useState<{ protected?: boolean; current_port?: number; secure_port?: number }>({})
  const [busy, setBusy] = useState(false)

  const loadExtras = async () => {
    const [h, r] = await Promise.all([motorBridge.harden('status'), motorBridge.rdp('status')])
    if (h.ok && Array.isArray(h.checks)) setChecks(h.checks as HardenCheck[])
    if (r.ok) {
      setRdp({
        protected: Boolean(r.protected),
        current_port: Number(r.current_port || 0) || undefined,
        secure_port: Number(r.secure_port || 0) || undefined,
      })
    }
  }

  useEffect(() => {
    void loadExtras()
  }, [status])

  const unlockRs = async () => {
    const result = await motorBridge.ipc('RS_UNLOCK')
    onToast(result.ok ? t('toast_rs_cleared') : String(result.error || 'RS unlock'), result.ok ? 'ok' : 'err')
    onRefresh()
  }

  const ngAccept = async () => {
    const result = await motorBridge.ipc('NG_ACCEPT_SURFACE')
    onToast(result.ok ? t('toast_ng_accept') : String(result.error || 'NG accept'), result.ok ? 'ok' : 'err')
    onRefresh()
  }

  const ngMaint = async (start: boolean) => {
    const result = await motorBridge.ipc(start ? 'NG_MAINT_START' : 'NG_MAINT_END_SNAPSHOT')
    onToast(
      result.ok ? (start ? t('toast_ng_maint_on') : t('toast_ng_maint_off')) : String(result.error || 'NG'),
      result.ok ? 'ok' : 'err',
    )
    onRefresh()
  }

  const fixHarden = async (target: string) => {
    setBusy(true)
    try {
      const result = await motorBridge.harden('fix', target)
      onToast(
        result.ok ? t('toast_fix_ok', { target }) : String(result.error || t('toast_fix_fail')),
        result.ok ? 'ok' : 'err',
      )
      await loadExtras()
    } finally {
      setBusy(false)
    }
  }

  const moveRdp = async () => {
    if (!window.confirm(t('status_rdp_confirm'))) return
    setBusy(true)
    try {
      const result = await motorBridge.rdp('move')
      onToast(
        result.ok
          ? t('toast_rdp_ok', { port: String(result.current_port ?? '') })
          : String(result.error || result.detail || t('toast_rdp_fail')),
        result.ok ? 'ok' : 'err',
      )
      await loadExtras()
      onRefresh()
    } finally {
      setBusy(false)
    }
  }

  const rdpTarget = rdp.protected ? 3389 : rdp.secure_port || 53389

  return (
    <section className="page">
      <div className="page-head">
        <div>
          <p className="eyebrow">{t('status_eyebrow')}</p>
          <h2>{online ? t('status_title_online') : t('status_title_offline')}</h2>
          <p className="muted">{t('status_blurb')}</p>
        </div>
        <button type="button" className="btn" onClick={onRefresh}>{t('btn_refresh')}</button>
      </div>

      <div className="chip-row">
        <button type="button" className={`chip ${online ? 'on' : ''}`}>
          {t('status_card_motor')} {online ? t('label_ok') : t('status_motor_down')}
        </button>
        <button type="button" className={`chip ${status?.ransomware_running ? 'on' : ''}`} onClick={() => onNavigate('layers')}>
          {t('layers_rs')} {boolLabel(status?.ransomware_running, t('label_on'), t('label_off'))}
        </button>
        <button type="button" className={`chip ${ng.running ? 'on' : ''}`} onClick={() => onNavigate('layers')}>
          NetGuard {boolLabel(ng.running, t('label_on'), t('label_off'))}
        </button>
        <button type="button" className={`chip ${running.length ? 'on' : ''}`} onClick={() => onNavigate('services')}>
          {t('status_chip_honeypot', { count: running.length })}
        </button>
        <button type="button" className={`chip ${rs.active ? 'warn' : ''}`} onClick={() => void unlockRs()}>
          {t('status_quarantine', { count: pick(rs, 'entries') })}
        </button>
      </div>

      <div className="cards">
        <article>
          <p>{t('status_card_motor')}</p>
          <strong>{online ? t('label_active') : t('status_motor_down')}</strong>
          <small>IPC 127.0.0.1:58632 · {pick(status, 'version')}</small>
        </article>
        <article>
          <p>{t('status_card_mode')}</p>
          <strong>{pick(status, 'protection_mode')}</strong>
          <small>{t('status_policy', { policy: pick(defense, 'defense_policy') })}</small>
        </article>
        <article className="clickable" onClick={() => onNavigate('services')}>
          <p>{t('status_card_honeypot')}</p>
          <strong>{running.length}</strong>
          <small>{running.length ? running.join(', ') : t('status_no_services')}</small>
        </article>
        <article className="clickable" onClick={() => onNavigate('threat')}>
          <p>{t('status_card_resources')}</p>
          <strong>{pick(resources, 'cpu_percent', 'cpu')}%</strong>
          <small>{t('status_ram', { ram: pick(resources, 'ram_percent', 'memory_percent'), updated: updatedAt || '—' })}</small>
        </article>
      </div>

      <div className="split">
        <article className="panel">
          <p className="eyebrow">{t('status_ng_eyebrow')}</p>
          <h3>{ng.maintenance ? t('status_ng_maint') : ng.drift ? t('status_ng_drift') : t('status_ng_stable')}</h3>
          <p className="muted">
            {t('status_ng_baseline', {
              version: pick(ng, 'baseline_version'),
              inet: boolLabel(ng.internet_ok, t('label_ok'), t('layers_none')),
            })}
          </p>
          <div className="btn-row">
            <button type="button" className="btn ghost" onClick={() => void ngMaint(true)}>{t('status_ng_start')}</button>
            <button type="button" className="btn ghost" onClick={() => void ngMaint(false)}>{t('status_ng_end')}</button>
            <button type="button" className="btn" onClick={() => void ngAccept()}>{t('status_ng_accept')}</button>
          </div>
        </article>
        <article className="panel">
          <p className="eyebrow">{t('status_rs_eyebrow')}</p>
          <h3>{rs.active ? t('status_rs_active') : t('status_rs_watch')}</h3>
          <p className="muted">
            {t('status_rs_meta', { canary: pick(rs, 'canary_files'), alerts: pick(rs, 'alerts_total') })}
          </p>
          <div className="btn-row">
            <button type="button" className="btn danger" disabled={!rs.active && Number(rs.entries || 0) === 0} onClick={() => void unlockRs()}>
              {t('status_rs_unlock')}
            </button>
          </div>
        </article>
      </div>

      <div className="split" style={{ marginTop: 18 }}>
        <article className="panel">
          <p className="eyebrow">{t('status_harden_eyebrow')}</p>
          <h3>{t('status_harden_title')}</h3>
          <div className="check-list">
            {checks.length === 0 && <p className="muted">{t('status_harden_loading')}</p>}
            {checks.map((c) => (
              <div key={String(c.id || c.label)} className="check-row">
                <div>
                  <strong className={c.ok === false ? 'bad' : c.ok ? 'good' : ''}>{c.label}</strong>
                  <p className="muted">{c.detail}</p>
                </div>
                {c.fixable && c.id && (
                  <button type="button" className="btn sm" disabled={busy} onClick={() => void fixHarden(String(c.id))}>
                    {t('btn_fix')}
                  </button>
                )}
              </div>
            ))}
          </div>
        </article>
        <article className="panel">
          <p className="eyebrow">{t('status_rdp_eyebrow')}</p>
          <h3>
            {rdp.protected
              ? t('status_rdp_protected', { port: String(rdp.current_port ?? '') })
              : t('status_rdp_standard', { port: String(rdp.current_port || 3389) })}
          </h3>
          <p className="muted">{t('status_rdp_blurb', { target: String(rdpTarget) })}</p>
          <div className="btn-row">
            <button type="button" className="btn" disabled={busy} onClick={() => void moveRdp()}>
              {t('status_rdp_btn', { target: String(rdpTarget) })}
            </button>
          </div>
        </article>
      </div>
    </section>
  )
}
