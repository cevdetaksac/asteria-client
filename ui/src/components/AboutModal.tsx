import { t } from '../i18n'

export type AboutInfo = {
  version: string
  website: string
  github: string
  log_path: string
}

type Props = {
  info: AboutInfo
  onClose: () => void
  onOpenWebsite: () => void
  onOpenGithub: () => void
  onOpenLogs: () => void
}

export function AboutModal({ info, onClose, onOpenWebsite, onOpenGithub, onOpenLogs }: Props) {
  return (
    <div className="modal-backdrop" role="presentation" onClick={onClose}>
      <div
        className="modal-card about-modal"
        role="dialog"
        aria-modal="true"
        aria-labelledby="about-title"
        onClick={(event) => event.stopPropagation()}
      >
        <p className="eyebrow">{t('control_center')}</p>
        <h2 id="about-title">{t('about_title')}</h2>
        <dl className="about-grid">
          <div>
            <dt>{t('about_version')}</dt>
            <dd className="mono">{info.version || '—'}</dd>
          </div>
          <div>
            <dt>{t('about_website')}</dt>
            <dd>
              <button type="button" className="linkish" onClick={onOpenWebsite}>
                {info.website || 'https://asteria.run'}
              </button>
            </dd>
          </div>
          <div>
            <dt>{t('about_github')}</dt>
            <dd>
              <button type="button" className="linkish" onClick={onOpenGithub}>
                {info.github || 'GitHub'}
              </button>
            </dd>
          </div>
          <div>
            <dt>{t('about_log')}</dt>
            <dd className="mono about-log">{info.log_path || '—'}</dd>
          </div>
        </dl>
        <div className="btn-row about-actions">
          <button type="button" className="btn ghost sm" onClick={onOpenLogs}>
            {t('menu_logs')}
          </button>
          <button type="button" className="btn sm" onClick={onClose}>
            {t('btn_close')}
          </button>
        </div>
      </div>
    </div>
  )
}
