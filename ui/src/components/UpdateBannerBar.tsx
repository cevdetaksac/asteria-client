import { t } from '../i18n'

export type UpdateBanner = {
  phase?: string
  to_version?: string
  from_version?: string
  progress?: number
  detail?: string
  error?: string
  can_abort?: boolean
}

/** Update still in flight (or failed) -> offer the recover button. */
export const canRecover = (b: UpdateBanner) =>
  b.phase === 'failed' || Boolean(b.can_abort) || ['accepted', 'downloading', 'staging', 'installing'].includes(String(b.phase || ''))

type Props = { banner: UpdateBanner; recoverBusy: boolean; onRecover: () => void; onDismiss: () => void }

export function UpdateBannerBar({ banner, recoverBusy, onRecover, onDismiss }: Props) {
  const bannerText = (() => {
    if (!banner) return ''
    const phase = String(banner.phase || '').toLowerCase()
    const pct = banner.progress != null ? Number(banner.progress) : null
    let title = t('update_banner_default')
    if (phase === 'accepted') title = t('update_banner_accepted')
    else if (phase === 'downloading' && pct != null && Number.isFinite(pct)) {
      title = t('update_banner_downloading_pct', { pct: Math.round(pct) })
    } else if (phase === 'downloading') title = t('update_banner_downloading')
    else if (phase === 'staging') title = t('update_banner_staging')
    else if (phase === 'installing') title = t('update_banner_installing')
    else if (phase === 'done') title = t('update_banner_done')
    else if (phase === 'failed') {
      title = banner.detail === 'update_stalled' ? t('update_banner_stalled') : t('update_banner_failed')
    }
    const fromV = String(banner.from_version || '')
    const toV = String(banner.to_version || '')
    const ver =
      fromV || toV
        ? t('update_banner_version_line', { from_v: fromV || '—', to_v: toV || '—' })
        : ''
    const err = phase === 'failed' ? String(banner.error || banner.detail || '') : ''
    return [title, ver, err].filter(Boolean).join(' · ')
  })()

  const bannerProgress =
    banner?.progress != null && Number.isFinite(Number(banner.progress))
      ? Math.max(0, Math.min(100, Number(banner.progress)))
      : banner?.phase === 'installing' || banner?.phase === 'staging'
        ? 100
        : banner?.phase === 'accepted'
          ? 5
          : null

  return (
    <div className={`update-banner ${banner.phase === 'failed' ? 'fail' : banner.phase === 'done' ? 'ok' : ''}`}>
        <div className="update-banner-copy">
          <span>{bannerText}</span>
          {bannerProgress != null && (
            <div className="update-banner-track" aria-hidden="true">
              <div className="update-banner-fill" style={{ width: `${bannerProgress}%` }} />
            </div>
          )}
        </div>
        <div className="update-banner-actions">
          {canRecover(banner) && (
            <button
              type="button"
              className="btn ghost sm"
              disabled={recoverBusy}
              onClick={onRecover}
            >
              {t('update_recover')}
            </button>
          )}
          <button type="button" className="btn ghost sm" onClick={onDismiss}>
            {t('btn_close')}
          </button>
        </div>
      </div>
  )
}
