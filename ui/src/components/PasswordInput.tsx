import { useState } from 'react'
import { t } from '../i18n'

type Props = {
  value: string
  onChange: (value: string) => void
  placeholder?: string
  ariaLabel?: string
  autoComplete?: string
  numeric?: boolean
  autoFocus?: boolean
}

function EyeIcon({ off }: { off: boolean }) {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" aria-hidden="true">
      <path d="M2.5 12S6 5.5 12 5.5 21.5 12 21.5 12 18 18.5 12 18.5 2.5 12 2.5 12Z" />
      <circle cx="12" cy="12" r="3.2" />
      {off && <path d="M4 20 20 4" />}
    </svg>
  )
}

/** Password field with a themed reveal toggle (native Edge glyph is hidden). */
export function PasswordInput({
  value,
  onChange,
  placeholder,
  ariaLabel,
  autoComplete = 'current-password',
  numeric = false,
  autoFocus = false,
}: Props) {
  const [shown, setShown] = useState(false)
  return (
    <div className="pw-field">
      <input
        type={shown ? 'text' : 'password'}
        inputMode={numeric ? 'numeric' : undefined}
        value={value}
        onChange={(event) => onChange(event.target.value)}
        placeholder={placeholder}
        aria-label={ariaLabel || placeholder}
        autoComplete={autoComplete}
        autoFocus={autoFocus}
      />
      <button
        type="button"
        className="pw-toggle tip"
        onClick={() => setShown((prev) => !prev)}
        aria-label={shown ? t('hide') : t('show')}
        data-tooltip={shown ? t('hide') : t('show')}
        tabIndex={-1}
      >
        <EyeIcon off={shown} />
      </button>
    </div>
  )
}
