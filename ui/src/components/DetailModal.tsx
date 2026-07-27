import type { ReactNode } from 'react'
import { Switch } from './Switch'
import { t } from '../i18n'

export type DetailRow = {
  label: string
  value: ReactNode
  tone?: 'ok' | 'bad' | 'plain'
  /** Inline on/off shortcut next to the status value. */
  toggle?: {
    checked: boolean
    onChange: (next: boolean) => void
    label?: string
    disabled?: boolean
  }
}

type Props = {
  title: string
  eyebrow?: string
  blurb?: string
  guide?: ReactNode
  rows?: DetailRow[]
  children?: ReactNode
  actions?: ReactNode
  onClose: () => void
}

export function DetailModal({
  title,
  eyebrow,
  blurb,
  guide,
  rows,
  children,
  actions,
  onClose,
}: Props) {
  return (
    <div className="modal-backdrop" role="presentation" onClick={onClose}>
      <div
        className="modal-card detail-modal"
        role="dialog"
        aria-modal="true"
        aria-labelledby="detail-modal-title"
        onClick={(event) => event.stopPropagation()}
      >
        <div className="detail-modal-head">
          <div>
            {eyebrow ? <p className="eyebrow">{eyebrow}</p> : null}
            <h2 id="detail-modal-title">{title}</h2>
          </div>
          <button type="button" className="btn ghost sm detail-modal-x" onClick={onClose} aria-label={t('btn_close')}>
            ×
          </button>
        </div>
        {blurb ? <p className="detail-blurb">{blurb}</p> : null}
        {guide}
        {rows && rows.length > 0 && (
          <div className="detail-rows">
            {rows.map((row, index) => (
              <div className="detail-row" key={`${row.label}-${index}`}>
                <span className="label">{row.label}</span>
                <div className="detail-row-end">
                  <span className={`value ${row.tone === 'ok' ? 'ok' : row.tone === 'bad' ? 'bad' : ''}`}>
                    {row.value}
                  </span>
                  {row.toggle ? (
                    <Switch
                      checked={row.toggle.checked}
                      onChange={row.toggle.onChange}
                      label={row.toggle.label || String(row.label)}
                      disabled={row.toggle.disabled}
                    />
                  ) : null}
                </div>
              </div>
            ))}
          </div>
        )}
        {children}
        {actions ? <div className="btn-row modal-actions">{actions}</div> : null}
      </div>
    </div>
  )
}
