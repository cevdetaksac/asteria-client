import { useEffect, useId, useRef, useState } from 'react'
import { t } from '../i18n'

export type RowAction = {
  id: string
  label: string
  onClick: () => void
  danger?: boolean
  disabled?: boolean
}

type Props = {
  /** Always visible (keep to 1–2). */
  primary: RowAction[]
  /** Overflow menu items. */
  more?: RowAction[]
}

/** Compact row actions: primary buttons + overflow menu (avoids tall stacked cells). */
export function RowActionMenu({ primary, more = [] }: Props) {
  const [open, setOpen] = useState(false)
  const rootRef = useRef<HTMLDivElement>(null)
  const menuId = useId()

  useEffect(() => {
    if (!open) return
    const onDoc = (ev: MouseEvent) => {
      if (!rootRef.current?.contains(ev.target as Node)) setOpen(false)
    }
    const onKey = (ev: KeyboardEvent) => {
      if (ev.key === 'Escape') setOpen(false)
    }
    document.addEventListener('mousedown', onDoc)
    document.addEventListener('keydown', onKey)
    return () => {
      document.removeEventListener('mousedown', onDoc)
      document.removeEventListener('keydown', onKey)
    }
  }, [open])

  return (
    <div className="row-actions row-action-menu" ref={rootRef}>
      {primary.map((a) => (
        <button
          key={a.id}
          type="button"
          className={`btn sm ${a.danger ? 'danger' : 'ghost'}`.trim()}
          disabled={a.disabled}
          onClick={a.onClick}
        >
          {a.label}
        </button>
      ))}
      {more.length > 0 && (
        <div className={`action-more${open ? ' open' : ''}`}>
          <button
            type="button"
            className="btn ghost sm action-more-toggle"
            aria-expanded={open}
            aria-controls={menuId}
            aria-label={t('dt_more_actions')}
            title={t('dt_more_actions')}
            onClick={() => setOpen((v) => !v)}
          >
            ···
          </button>
          {open && (
            <div id={menuId} className="action-more-panel" role="menu">
              {more.map((a) => (
                <button
                  key={a.id}
                  type="button"
                  role="menuitem"
                  className={`action-more-item${a.danger ? ' danger' : ''}`}
                  disabled={a.disabled}
                  onClick={() => {
                    setOpen(false)
                    a.onClick()
                  }}
                >
                  {a.label}
                </button>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  )
}
