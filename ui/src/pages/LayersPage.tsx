import { useEffect, useState } from 'react'
import { motorBridge, type MotorStatus } from '../bridge'
import { DetailModal, type DetailRow } from '../components/DetailModal'
import { FeatureGuide } from '../components/FeatureGuide'
import { t } from '../i18n'
import { asRecord, pick } from '../lib'

type Props = {
  status: MotorStatus | null
  onRefresh: () => void
  onToast: (msg: string, kind?: 'ok' | 'err') => void
}

type LayerKey = 'ransomware' | 'canary' | 'network_guard'

export function LayersPage({ status, onRefresh, onToast }: Props) {
  const defense = asRecord(status?.defense_policy)
  const ng = asRecord(status?.network_guard)
  const rs = asRecord(status?.rs_quarantine)
  const current = pick(defense, 'defense_policy')
  const locked = Boolean(defense.defense_policy_locked)
  const [cfg, setCfg] = useState<Record<string, unknown>>({})
  const [detail, setDetail] = useState<LayerKey | null>(null)
  const [pageHelp, setPageHelp] = useState(false)

  const policies = [
    { id: 'observe', title: t('layers_policy_observe'), blurb: t('layers_policy_observe_blurb') },
    { id: 'balanced', title: t('layers_policy_balanced'), blurb: t('layers_policy_balanced_blurb') },
    { id: 'paranoid', title: t('layers_policy_paranoid'), blurb: t('layers_policy_paranoid_blurb') },
  ] as const

  useEffect(() => {
    void motorBridge.cloud('GET', 'threats/config').then((result) => {
      if (result.ok && result.data && typeof result.data === 'object') {
        setCfg(result.data as Record<string, unknown>)
      }
    })
  }, [status])

  const setPolicy = async (policy: string) => {
    const result = await motorBridge.cloud('POST', 'threats/config', {
      protection: { defense_policy: policy },
    })
    onToast(result.ok ? t('toast_policy', { policy }) : String(result.error || 'policy'), result.ok ? 'ok' : 'err')
    onRefresh()
  }

  const lockObserve = async () => {
    const result = await motorBridge.cloud('POST', 'threats/config', {
      protection: { defense_policy: 'observe', defense_policy_locked: true },
    })
    onToast(result.ok ? t('toast_lock_ok') : String(result.error || 'lock'), result.ok ? 'ok' : 'err')
    onRefresh()
  }

  const toggleLayer = async (key: string, value: boolean) => {
    const patch: Record<string, unknown> = {}
    if (key === 'ransomware') patch.ransomware_protection_enabled = value
    if (key === 'canaries') patch.canary_files_enabled = value
    if (key === 'network_guard') patch.protection = { network_guard: { enabled: value } }
    const result = await motorBridge.cloud('POST', 'threats/config', patch)
    onToast(result.ok ? t('toast_layer_ok') : String(result.error || 'layer'), result.ok ? 'ok' : 'err')
    onRefresh()
  }

  const rsOn = Boolean(status?.ransomware_running)
  const ngOn = Boolean(ng.enabled ?? ng.running)
  const canaries = Number(rs.canary_files || 0) > 0

  const detailContent = (): {
    title: string
    blurb: string
    guide: string
    rows: DetailRow[]
    onToggle?: () => void
    toggleLabel?: string
  } => {
    if (detail === 'ransomware') {
      return {
        title: t('layers_rs'),
        blurb: t('layers_rs_detail_blurb'),
        guide: 'help_rs',
        rows: [
          { label: t('layers_rs'), value: rsOn ? t('label_on') : t('label_off'), tone: rsOn ? 'ok' : 'bad' },
          { label: t('layers_detail_canary_files'), value: pick(rs, 'canary_files') },
          { label: t('layers_detail_canary_alerts'), value: pick(rs, 'canary_alerts', 'alerts_canary') },
          { label: t('layers_detail_fs_alerts'), value: pick(rs, 'fs_alerts', 'alerts_fs') },
          { label: t('layers_detail_proc_alerts'), value: pick(rs, 'process_alerts', 'alerts_process') },
          { label: t('layers_detail_vss_alerts'), value: pick(rs, 'vss_alerts', 'alerts_vss') },
          { label: t('layers_detail_total_alerts'), value: pick(rs, 'alerts_total', 'entries') },
          {
            label: t('status_quarantine', { count: pick(rs, 'entries') }),
            value: rs.active ? t('status_rs_active') : t('label_ok'),
            tone: rs.active ? 'bad' : 'ok',
          },
        ],
        onToggle: () => void toggleLayer('ransomware', !rsOn),
        toggleLabel: rsOn ? t('layers_close') : t('layers_open'),
      }
    }
    if (detail === 'canary') {
      return {
        title: t('layers_canary'),
        blurb: t('layers_canary_detail_blurb'),
        guide: 'help_rs',
        rows: [
          { label: t('layers_canary'), value: canaries ? t('layers_has') : t('layers_none'), tone: canaries ? 'ok' : 'plain' },
          { label: t('layers_detail_canary_files'), value: pick(rs, 'canary_files') },
          { label: t('layers_detail_canary_alerts'), value: pick(rs, 'canary_alerts', 'alerts_canary') },
        ],
        onToggle: () => void toggleLayer('canaries', !canaries),
        toggleLabel: t('layers_sync'),
      }
    }
    return {
      title: t('layers_ng'),
      blurb: t('layers_ng_detail_blurb'),
      guide: 'help_ng',
      rows: [
        { label: t('layers_ng'), value: ngOn ? t('label_on') : t('label_off'), tone: ngOn ? 'ok' : 'bad' },
        { label: t('status_ng_eyebrow'), value: ng.maintenance ? t('status_ng_maint') : ng.drift ? t('status_ng_drift') : t('status_ng_stable') },
        { label: t('layers_detail_baseline'), value: pick(ng, 'baseline_version') },
        {
          label: t('layers_detail_internet'),
          value: ng.internet_ok ? t('label_ok') : t('layers_none'),
          tone: ng.internet_ok ? 'ok' : 'bad',
        },
      ],
      onToggle: () => void toggleLayer('network_guard', !ngOn),
      toggleLabel: ngOn ? t('layers_close') : t('layers_open'),
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

      <div className="policy-grid">
        {policies.map((policy) => {
          const selected = current === policy.id
          const guidePrefix =
            policy.id === 'observe'
              ? 'help_policy_observe'
              : policy.id === 'balanced'
                ? 'help_policy_balanced'
                : 'help_policy_paranoid'
          return (
            <article key={policy.id} className={`policy-card ${selected ? 'selected' : ''}`}>
              <div>
                <p className="eyebrow">{selected ? t('label_active') : t('label_select')}</p>
                <h3>{policy.title}</h3>
                <p className="muted">{policy.blurb}</p>
                <p className="feature-card-help">{t(`${guidePrefix}_what`)}</p>
              </div>
              <button
                type="button"
                className={`btn ${selected ? 'policy-selected' : ''}`}
                disabled={selected || (locked && policy.id !== 'observe')}
                onClick={() => void setPolicy(policy.id)}
              >
                {selected ? t('layers_policy_selected') : t('btn_apply')}
              </button>
            </article>
          )
        })}
      </div>

      <div className="btn-row" style={{ marginTop: 16 }}>
        <button type="button" className="btn ghost" disabled={locked} onClick={() => void lockObserve()}>
          {t('layers_lock_observe')}
        </button>
        <span className="muted">{t('layers_version', { version: pick(defense, 'defense_policy_version') })}</span>
      </div>

      <div className="cards three layer-toggles" style={{ marginTop: 28 }}>
        <article className="layer-card clickable" onClick={() => setDetail('ransomware')}>
          <p>{t('layers_rs')}</p>
          <strong className={rsOn ? 'good' : 'bad'}>{rsOn ? t('label_on') : t('label_off')}</strong>
          <small>{t('layers_click_detail')}</small>
          <div className="layer-actions" onClick={(e) => e.stopPropagation()}>
            <button type="button" className="btn sm ghost" onClick={() => void toggleLayer('ransomware', !rsOn)}>
              {rsOn ? t('layers_close') : t('layers_open')}
            </button>
          </div>
        </article>
        <article className="layer-card clickable" onClick={() => setDetail('canary')}>
          <p>{t('layers_canary')}</p>
          <strong>{canaries ? t('layers_has') : t('layers_none')}</strong>
          <small>{t('layers_click_detail')}</small>
          <div className="layer-actions" onClick={(e) => e.stopPropagation()}>
            <button type="button" className="btn sm ghost" onClick={() => void toggleLayer('canaries', !canaries)}>
              {t('layers_sync')}
            </button>
          </div>
        </article>
        <article className="layer-card clickable" onClick={() => setDetail('network_guard')}>
          <p>{t('layers_ng')}</p>
          <strong className={ngOn ? 'good' : 'bad'}>{ngOn ? t('label_on') : t('label_off')}</strong>
          <small>{t('layers_click_detail')}</small>
          <div className="layer-actions" onClick={(e) => e.stopPropagation()}>
            <button type="button" className="btn sm ghost" onClick={() => void toggleLayer('network_guard', !ngOn)}>
              {ngOn ? t('layers_close') : t('layers_open')}
            </button>
          </div>
        </article>
      </div>

      {Object.keys(cfg).length > 0 && (
        <p className="muted" style={{ marginTop: 18 }}>
          {t('layers_cfg_loaded', { count: Object.keys(cfg).length })}
        </p>
      )}

      {modal && detail && (
        <DetailModal
          title={modal.title}
          eyebrow={t('layers_eyebrow')}
          blurb={modal.blurb}
          guide={<FeatureGuide prefix={modal.guide} />}
          rows={modal.rows}
          actions={
            modal.onToggle ? (
              <button type="button" className="btn sm" onClick={modal.onToggle}>
                {modal.toggleLabel}
              </button>
            ) : null
          }
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
