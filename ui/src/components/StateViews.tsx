/** U4: shared loading / empty / error views. */
import type { ReactNode } from 'react'
import { t } from '../i18n'

export function LoadingState({ label }: { label?: ReactNode }) {
  return (
    <div className="state-view loading" role="status" aria-live="polite">
      <span className="state-spinner" aria-hidden="true" />
      <span>{label ?? t('label_loading')}</span>
    </div>
  )
}

export function EmptyState({ children }: { children?: ReactNode }) {
  return <div className="state-view empty">{children ?? t('dt_empty')}</div>
}

export function ErrorState({ message, onRetry }: { message: ReactNode; onRetry?: () => void }) {
  return (
    <div className="state-view error" role="alert">
      <span>{message}</span>
      {onRetry ? (
        <button type="button" className="btn ghost sm" onClick={onRetry}>
          {t('btn_refresh')}
        </button>
      ) : null}
    </div>
  )
}
