import { asRecord, formatAgo, formatBps, pick } from '../lib'
import { t } from '../i18n'
import type { MotorStatus } from '../bridge'

type Props = {
  status: MotorStatus | null
}

function num(value: unknown): number | null {
  if (value == null || value === '') return null
  const n = Number(value)
  return Number.isFinite(n) ? n : null
}

/** Compact live meters in the top bar (old GUI resource badge + API/commands). */
export function LiveMeters({ status }: Props) {
  const resources = asRecord(status?.resources)
  const api = asRecord(status?.api)
  const commands = Array.isArray(status?.commands_recent) ? status.commands_recent : []
  const lastCmd = commands.length ? asRecord(commands[0]) : null

  const pCpu = num(resources.process_cpu_percent)
  const pRam = num(resources.process_rss_mb)
  const hCpu = num(resources.host_cpu_percent ?? resources.cpu_percent)
  const hRam = num(resources.host_memory_percent ?? resources.ram_percent ?? resources.memory_percent)
  const down = formatBps(resources.net_recv_bps)
  const up = formatBps(resources.net_sent_bps)

  const procBit =
    pCpu != null && pRam != null
      ? `${pCpu.toFixed(0)}%/${pRam.toFixed(0)}MB`
      : pRam != null
        ? `${pRam.toFixed(0)}MB`
        : '—'
  const hostBit =
    hCpu != null && hRam != null ? `${hCpu.toFixed(0)}%/${hRam.toFixed(0)}%` : '—'

  const hot = (hCpu != null && hCpu >= 90) || (pCpu != null && pCpu >= 40)
  const apiOk = Boolean(api.ok)
  const apiAgo = formatAgo(api.last_ok_at ?? api.last_check_at ?? api.last_heartbeat_at)
  const cmdLabel = lastCmd
    ? `${pick(lastCmd, 'command_type')}${lastCmd.ok === false ? ' ✗' : ''}`
    : t('live_cmd_none')
  const cmdAgo = lastCmd ? formatAgo(lastCmd.executed_at) : ''

  const tip = [
    t('live_tip_resources'),
    apiOk ? t('live_tip_api_ok', { ago: apiAgo }) : t('live_tip_api_down', { ago: apiAgo }),
    lastCmd
      ? t('live_tip_cmd', { cmd: pick(lastCmd, 'command_type'), ago: cmdAgo })
      : t('live_tip_cmd_none'),
  ].join('\n')

  return (
    <div className={`live-meters${hot ? ' hot' : ''}`} title={tip} aria-label={t('live_aria')}>
      <span className="live-chip resources">
        <span className="live-k">{t('live_app')}</span>
        <strong>{procBit}</strong>
        <span className="live-sep">·</span>
        <span className="live-k">{t('live_host')}</span>
        <strong>{hostBit}</strong>
        <span className="live-sep">·</span>
        <span>↓{down}</span>
        <span>↑{up}</span>
      </span>
      <span className={`live-chip api${apiOk ? ' ok' : ' bad'}`}>
        <span className="live-k">API</span>
        <strong>{apiOk ? t('label_ok') : t('live_api_down')}</strong>
        <span className="live-ago">{apiAgo}</span>
      </span>
      <span className="live-chip cmd">
        <span className="live-k">{t('live_cmd')}</span>
        <strong className="mono">{cmdLabel}</strong>
        {cmdAgo ? <span className="live-ago">{cmdAgo}</span> : null}
      </span>
    </div>
  )
}
