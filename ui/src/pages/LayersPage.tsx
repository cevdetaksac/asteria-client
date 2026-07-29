import { useEffect, useState, type ReactNode } from 'react'
import { motorBridge, type MotorStatus } from '../bridge'
import { DetailModal, type DetailRow } from '../components/DetailModal'
import { FeatureGuide } from '../components/FeatureGuide'
import { Switch } from '../components/Switch'
import { t } from '../i18n'
import { asRecord, pick, triLabel } from '../lib'

type Props = {
  status: MotorStatus | null
  statusLoading?: boolean
  onRefresh: () => void
  onToast: (msg: string, kind?: 'ok' | 'err') => void
}

type LayerKey = 'ransomware' | 'canary' | 'network_guard'

export function LayersPage({ status, statusLoading = false, onRefresh, onToast }: Props) {
  const defense = asRecord(status?.defense_policy)
  const ng = asRecord(status?.network_guard)
  const rs = asRecord(status?.rs_quarantine)
  const current = pick(defense, 'defense_policy')
  const locked = Boolean(defense.defense_policy_locked)
  const pending = statusLoading || !status
  const [cfg, setCfg] = useState<Record<string, unknown>>({})
  const [cfgLoading, setCfgLoading] = useState(true)
  const [toggleBusy, setToggleBusy] = useState(false)
  const [detail, setDetail] = useState<LayerKey | null>(null)
  const [pageHelp, setPageHelp] = useState(false)

  const policies = [
    { id: 'observe', title: t('layers_policy_observe'), blurb: t('layers_policy_observe_blurb') },
    { id: 'balanced', title: t('layers_policy_balanced'), blurb: t('layers_policy_balanced_blurb') },
    { id: 'paranoid', title: t('layers_policy_paranoid'), blurb: t('layers_policy_paranoid_blurb') },
  ] as const

  useEffect(() => {
    let cancelled = false
    setCfgLoading(true)
    void motorBridge.cloud('GET', 'threats/config').then((result) => {
      if (cancelled) return
      if (result.ok && result.data && typeof result.data === 'object') {
        setCfg(result.data as Record<string, unknown>)
      }
      setCfgLoading(false)
    })
    return () => {
      cancelled = true
    }
  }, [status])

  const setPolicy = async (policy: string) => {
    if (pending || toggleBusy) return
    setToggleBusy(true)
    try {
      const result = await motorBridge.cloud('POST', 'threats/config', {
        protection: { defense_policy: policy },
      })
      onToast(result.ok ? t('toast_policy', { policy }) : String(result.error || 'policy'), result.ok ? 'ok' : 'err')
      onRefresh()
    } finally {
      setToggleBusy(false)
    }
  }

  const lockObserve = async () => {
    if (pending || toggleBusy) return
    setToggleBusy(true)
    try {
      const result = await motorBridge.cloud('POST', 'threats/config', {
        protection: { defense_policy: 'observe', defense_policy_locked: true },
      })
      onToast(result.ok ? t('toast_lock_ok') : String(result.error || 'lock'), result.ok ? 'ok' : 'err')
      onRefresh()
    } finally {
      setToggleBusy(false)
    }
  }

  const toggleLayer = async (key: string, value: boolean) => {
    if (pending || toggleBusy) return
    setToggleBusy(true)
    try {
      const patch: Record<string, unknown> = {}
      if (key === 'ransomware') patch.ransomware_protection_enabled = value
      if (key === 'canaries') patch.canary_files_enabled = value
      if (key === 'network_guard') patch.protection = { network_guard: { enabled: value } }
      const result = await motorBridge.cloud('POST', 'threats/config', patch)
      onToast(result.ok ? t('toast_layer_ok') : String(result.error || 'layer'), result.ok ? 'ok' : 'err')
      onRefresh()
    } finally {
      setToggleBusy(false)
    }
  }

  const ngMaint = async (start: boolean) => {
    if (pending || toggleBusy) return
    setToggleBusy(true)
    try {
      const result = await motorBridge.ipc(start ? 'NG_MAINT_START' : 'NG_MAINT_END_SNAPSHOT')
      onToast(
        result.ok ? (start ? t('toast_ng_maint_on') : t('toast_ng_maint_off')) : String(result.error || 'NG'),
        result.ok ? 'ok' : 'err',
      )
      onRefresh()
    } finally {
      setToggleBusy(false)
    }
  }

  const ngAccept = async () => {
    if (pending || toggleBusy) return
    setToggleBusy(true)
    try {
      const result = await motorBridge.ipc('NG_ACCEPT_SURFACE')
      onToast(result.ok ? t('toast_ng_accept') : String(result.error || 'NG accept'), result.ok ? 'ok' : 'err')
      onRefresh()
    } finally {
      setToggleBusy(false)
    }
  }

  const rsOn = Boolean(status?.ransomware_running)
  const ngOn = Boolean(ng.enabled ?? ng.running)
  const canaries = Number(rs.canary_files || 0) > 0
  const ngMaintOn = Boolean(ng.maintenance)
  const switchLoading = pending || toggleBusy

  const onOff = (on: boolean) =>
    triLabel(on, {
      yes: t('label_on'),
      no: t('label_off'),
      loading: t('label_loading'),
      pending,
    })

  const detailContent = (): {
    title: string
    blurb: string
    guide: string
    rows: DetailRow[]
    actions?: ReactNode
  } => {
    if (detail === 'ransomware') {
      return {
        title: t('layers_rs'),
        blurb: t('layers_rs_detail_blurb'),
        guide: 'help_rs',
        rows: [
          {
            label: t('layers_rs'),
            value: onOff(rsOn),
            tone: pending ? 'plain' : rsOn ? 'ok' : 'bad',
            toggle: {
              checked: rsOn,
              loading: switchLoading,
              label: t('layers_rs'),
              onChange: (next) => void toggleLayer('ransomware', next),
            },
          },
          { label: t('layers_detail_canary_files'), value: pending ? t('label_loading') : pick(rs, 'canary_files') },
          { label: t('layers_detail_canary_alerts'), value: pending ? t('label_loading') : pick(rs, 'canary_alerts', 'alerts_canary') },
          { label: t('layers_detail_fs_alerts'), value: pending ? t('label_loading') : pick(rs, 'fs_alerts', 'alerts_fs') },
          { label: t('layers_detail_proc_alerts'), value: pending ? t('label_loading') : pick(rs, 'process_alerts', 'alerts_process') },
          { label: t('layers_detail_vss_alerts'), value: pending ? t('label_loading') : pick(rs, 'vss_alerts', 'alerts_vss') },
          { label: t('layers_detail_total_alerts'), value: pending ? t('label_loading') : pick(rs, 'alerts_total', 'entries') },
          {
            label: t('status_quarantine', { count: pick(rs, 'entries') }),
            value: pending ? t('label_loading') : rs.active ? t('status_rs_active') : t('label_ok'),
            tone: pending ? 'plain' : rs.active ? 'bad' : 'ok',
          },
        ],
      }
    }
    if (detail === 'canary') {
      return {
        title: t('layers_canary'),
        blurb: t('layers_canary_detail_blurb'),
        guide: 'help_rs',
        rows: [
          {
            label: t('layers_canary'),
            value: pending ? t('label_loading') : canaries ? t('layers_has') : t('layers_none'),
            tone: pending ? 'plain' : canaries ? 'ok' : 'plain',
            toggle: {
              checked: canaries,
              loading: switchLoading,
              label: t('layers_canary'),
              onChange: (next) => void toggleLayer('canaries', next),
            },
          },
          { label: t('layers_detail_canary_files'), value: pending ? t('label_loading') : pick(rs, 'canary_files') },
          { label: t('layers_detail_canary_alerts'), value: pending ? t('label_loading') : pick(rs, 'canary_alerts', 'alerts_canary') },
        ],
      }
    }
    return {
      title: t('layers_ng'),
      blurb: t('layers_ng_detail_blurb'),
      guide: 'help_ng',
      rows: [
        {
          label: t('layers_ng'),
          value: onOff(ngOn),
          tone: pending ? 'plain' : ngOn ? 'ok' : 'bad',
          toggle: {
            checked: ngOn,
            loading: switchLoading,
            label: t('layers_ng'),
            onChange: (next) => void toggleLayer('network_guard', next),
          },
        },
        {
          label: t('status_ng_surface'),
          value: pending
            ? t('label_loading')
            : ngMaintOn
              ? t('status_ng_maint')
              : ng.drift
                ? t('status_ng_drift')
                : t('status_ng_stable'),
        },
        {
          label: t('status_ng_maint_mode'),
          value: onOff(ngMaintOn),
          tone: pending ? 'plain' : ngMaintOn ? 'plain' : 'ok',
          toggle: {
            checked: ngMaintOn,
            loading: switchLoading,
            label: t('status_ng_maint_mode'),
            onChange: (next) => void ngMaint(next),
          },
        },
        { label: t('layers_detail_baseline'), value: pending ? t('label_loading') : pick(ng, 'baseline_version') },
        {
          label: t('layers_detail_internet'),
          value: pending ? t('label_loading') : ng.internet_ok ? t('label_ok') : t('layers_none'),
          tone: pending ? 'plain' : ng.internet_ok ? 'ok' : 'bad',
        },
      ],
      actions: (
        <button type="button" className="btn sm" disabled={switchLoading} onClick={() => void ngAccept()}>
          {t('status_ng_accept')}
        </button>
      ),
    }
  }

  const modal = detail ? detailContent() : null

  return (
    <section className="page">
      <div className="page-head">
        <div>
          <p className="eyebrow">{t('layers_eyebrow')}</p>
          <h2>{t('layers_title')}</h2>
          <p className="muted">{t('layers_blurb')}</p>
        </div>
        <button type="button" className="btn ghost sm" onClick={() => setPageHelp(true)}>
          {t('help_more')}
        </button>
      </div>

      {pending && <p className="muted status-loading-hint">{t('status_section_loading')}</p>}

      <div className={`policy-grid${pending ? ' is-loading' : ''}`}>
        {policies.map((policy) => {
          const selected = !pending && current === policy.id
          const guidePrefix =
            policy.id === 'observe'
              ? 'help_policy_observe'
              : policy.id === 'balanced'
                ? 'help_policy_balanced'
                : 'help_policy_paranoid'
          return (
            <article key={policy.id} className={`policy-card ${selected ? 'selected' : ''}${pending ? ' loading' : ''}`}>
              <div>
                <p className="eyebrow">
                  {pending ? t('label_loading') : selected ? t('label_active') : t('label_select')}
                </p>
                <h3>{policy.title}</h3>
                <p className="muted">{policy.blurb}</p>
                <p className="feature-card-help">{t(`${guidePrefix}_what`)}</p>
              </div>
              <button
                type="button"
                className={`btn ${selected ? 'policy-selected' : ''}`}
                disabled={pending || toggleBusy || selected || (locked && policy.id !== 'observe')}
                onClick={() => void setPolicy(policy.id)}
              >
                {pending ? t('label_loading') : selected ? t('layers_policy_selected') : t('btn_apply')}
              </button>
            </article>
          )
        })}
      </div>

      <div className="btn-row" style={{ marginTop: 16 }}>
        <button
          type="button"
          className="btn ghost"
          disabled={pending || toggleBusy || locked}
          onClick={() => void lockObserve()}
        >
          {t('layers_lock_observe')}
        </button>
        <span className="muted">
          {pending
            ? t('label_loading')
            : t('layers_version', { version: pick(defense, 'defense_policy_version') })}
        </span>
      </div>

      <div className="cards three layer-toggles" style={{ marginTop: 28 }}>
        <article className={`layer-card clickable${pending ? ' loading' : ''}`} onClick={() => setDetail('ransomware')}>
          <div className="layer-card-top">
            <p>{t('layers_rs')}</p>
            <div className="layer-actions" onClick={(e) => e.stopPropagation()}>
              <Switch
                checked={rsOn}
                loading={switchLoading}
                label={t('layers_rs')}
                onChange={(next) => void toggleLayer('ransomware', next)}
              />
            </div>
          </div>
          <strong className={pending ? '' : rsOn ? 'good' : 'bad'}>{onOff(rsOn)}</strong>
          <small>{pending ? t('status_section_loading') : t('layers_click_detail')}</small>
        </article>
        <article className={`layer-card clickable${pending ? ' loading' : ''}`} onClick={() => setDetail('canary')}>
          <div className="layer-card-top">
            <p>{t('layers_canary')}</p>
            <div className="layer-actions" onClick={(e) => e.stopPropagation()}>
              <Switch
                checked={canaries}
                loading={switchLoading}
                label={t('layers_canary')}
                onChange={(next) => void toggleLayer('canaries', next)}
              />
            </div>
          </div>
          <strong>
            {pending ? t('label_loading') : canaries ? t('layers_has') : t('layers_none')}
          </strong>
          <small>{pending ? t('status_section_loading') : t('layers_click_detail')}</small>
        </article>
        <article className={`layer-card clickable${pending ? ' loading' : ''}`} onClick={() => setDetail('network_guard')}>
          <div className="layer-card-top">
            <p>{t('layers_ng')}</p>
            <div className="layer-actions" onClick={(e) => e.stopPropagation()}>
              <Switch
                checked={ngOn}
                loading={switchLoading}
                label={t('layers_ng')}
                onChange={(next) => void toggleLayer('network_guard', next)}
              />
            </div>
          </div>
          <strong className={pending ? '' : ngOn ? 'good' : 'bad'}>{onOff(ngOn)}</strong>
          <small>{pending ? t('status_section_loading') : t('layers_click_detail')}</small>
        </article>
      </div>

      {(cfgLoading || Object.keys(cfg).length > 0) && (
        <p className="muted" style={{ marginTop: 18 }}>
          {cfgLoading
            ? t('status_section_loading')
            : t('layers_cfg_loaded', { count: Object.keys(cfg).length })}
        </p>
      )}

      {modal && detail && (
        <DetailModal
          title={modal.title}
          eyebrow={t('layers_eyebrow')}
          blurb={modal.blurb}
          guide={<FeatureGuide prefix={modal.guide} />}
          rows={modal.rows}
          actions={modal.actions}
          onClose={() => setDetail(null)}
        />
      )}
      {pageHelp && (
        <DetailModal
          title={t('layers_title')}
          eyebrow={t('layers_eyebrow')}
          blurb={t('layers_blurb')}
          guide={<FeatureGuide prefix="help_layers" />}
          onClose={() => setPageHelp(false)}
        />
      )}
    </section>
  )
}
