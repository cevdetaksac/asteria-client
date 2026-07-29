type Props = {
  checked: boolean
  onChange: (next: boolean) => void
  disabled?: boolean
  /** True while value is unknown / refresh in flight — not Off. */
  loading?: boolean
  label?: string
}

/** Accessible toggle; loading = indeterminate (never fake Off). */
export function Switch({ checked, onChange, disabled, loading, label }: Props) {
  const blocked = Boolean(disabled || loading)
  return (
    <button
      type="button"
      role="switch"
      aria-checked={loading ? 'mixed' : checked}
      aria-busy={loading || undefined}
      aria-label={label}
      className={`switch${checked && !loading ? ' on' : ''}${loading ? ' loading' : ''}`}
      disabled={blocked}
      onClick={() => {
        if (blocked) return
        onChange(!checked)
      }}
    >
      <span className="switch-thumb" aria-hidden />
    </button>
  )
}
