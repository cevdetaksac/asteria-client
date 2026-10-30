/** U6: heavy / rarely used views live on the dashboard; link there instead of rendering everything here. */
import { motorBridge } from '../bridge'

export function DashLink({ path, label }: { path: string; label: string }) {
  return (
    <button type="button" className="btn ghost sm dash-link" onClick={() => void motorBridge.shell('open_dashboard', path)}>
      {label} <span aria-hidden="true">{'\u2197'}</span>
    </button>
  )
}
