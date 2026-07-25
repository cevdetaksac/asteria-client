type Props = {
  checked: boolean
  onChange: (next: boolean) => void
  disabled?: boolean
  label?: string
}

/** Accessible toggle styled as a modern switch (replaces bare checkboxes). */
export function Switch({ checked, onChange, disabled, label }: Props) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      aria-label={label}
      className={`switch${checked ? ' on' : ''}`}
      disabled={disabled}
      onClick={() => onChange(!checked)}
    >
      <span className="switch-thumb" aria-hidden />
    </button>
  )
}
