import { useEffect, useRef } from 'react'

/** True when the Control Center is actually on screen. */
export function isUiVisible(): boolean {
  if (typeof document !== 'undefined' && document.hidden) return false
  return !(window as unknown as { __asteriaHostHidden?: boolean }).__asteriaHostHidden
}

/**
 * P1 + P2: poll `fn` every `ms` while the window is visible.
 * - Next tick is scheduled only after the previous one finished (no pile-up).
 * - Paused while minimized / hidden to tray; runs immediately when shown again.
 */
export function usePoll(fn: () => unknown | Promise<unknown>, ms: number, enabled = true): void {
  const ref = useRef(fn)
  ref.current = fn
  useEffect(() => {
    if (!enabled) return
    let stopped = false
    let running = false
    let timer = 0
    const schedule = () => {
      window.clearTimeout(timer)
      if (!stopped) timer = window.setTimeout(() => void tick(), ms)
    }
    const tick = async () => {
      if (stopped || running) return
      if (!isUiVisible()) {
        schedule()
        return
      }
      running = true
      try {
        await ref.current()
      } catch {
        /* callers surface their own errors */
      } finally {
        running = false
        schedule()
      }
    }
    const onVisible = () => {
      if (isUiVisible() && !running) {
        window.clearTimeout(timer)
        void tick()
      }
    }
    document.addEventListener('visibilitychange', onVisible)
    window.addEventListener('asteria-host-visibility', onVisible)
    void tick()
    return () => {
      stopped = true
      window.clearTimeout(timer)
      document.removeEventListener('visibilitychange', onVisible)
      window.removeEventListener('asteria-host-visibility', onVisible)
    }
  }, [ms, enabled])
}
