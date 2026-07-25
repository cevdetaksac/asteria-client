import { t } from '../i18n'

type Props = {
  serverName: string
  tokenPreview: string
  tokenPresent: boolean
  clientId?: string
  publicIp?: string
  onCopyToken: () => void
}

export function IdentityStrip({
  serverName,
  tokenPreview,
  tokenPresent,
  clientId,
  publicIp,
  onCopyToken,
}: Props) {
  const host = serverName.trim() || '—'
  const ip = (publicIp || '').trim() || '—'
  const tokenLabel = tokenPresent
    ? tokenPreview || t('identity_token_present')
    : t('identity_token_missing')

  return (
    <div className="identity-strip">
      {clientId ? (
        <>
          <span className="identity-cid mono tip" data-tooltip={t('identity_id')} tabIndex={0}>
            #{clientId}
          </span>
          <span className="identity-sep" aria-hidden="true" />
        </>
      ) : null}
      <span className="identity-host tip" data-tooltip={t('identity_device')} tabIndex={0}>
        {host}
      </span>
      <span className="identity-sep" aria-hidden="true" />
      <span className="identity-ip mono tip" data-tooltip={t('identity_ip')} tabIndex={0}>
        {ip}
      </span>
      <span className="identity-sep" aria-hidden="true" />
      <span className={`identity-token mono ${tokenPresent ? '' : 'missing'}`}>
        {t('identity_token')}: {tokenLabel}
      </span>
      <button
        type="button"
        className="btn ghost sm identity-copy tip"
        disabled={!tokenPresent}
        onClick={onCopyToken}
        data-tooltip={t('btn_copy_token')}
        aria-label={t('btn_copy_token')}
      >
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" aria-hidden="true">
          <rect x="9" y="9" width="11" height="11" rx="2" />
          <path d="M5 15V7a2 2 0 0 1 2-2h8" />
        </svg>
      </button>
    </div>
  )
}
