import { useEffect, useState } from 'react'
import { riskStyle } from './riskStyles'

const SIZE = 200
const STROKE = 14
const RADIUS = (SIZE - STROKE) / 2
const CIRCUMFERENCE = 2 * Math.PI * RADIUS

/**
 * Reusable circular SVG risk meter.
 *
 * Props:
 *  - score: 0–100, or null for an unknown risk
 *  - level: "Low" | "Medium" | "High" | "Unknown"
 *
 * The ring animates smoothly between values and renders gray with
 * "Unable to determine risk" when the score is unknown — it never implies a
 * safe result it does not have.
 */
export default function RiskMeter({ score = null, level = 'Unknown' }) {
  const style = riskStyle(level)
  const known = typeof score === 'number' && Number.isFinite(score)
  const clamped = known ? Math.min(100, Math.max(0, score)) : 0

  // Draw the ring from 0 up to the *supplied* score on mount. The numeric
  // score itself is displayed immediately and never altered.
  const [drawn, setDrawn] = useState(false)
  useEffect(() => {
    const raf = requestAnimationFrame(() => setDrawn(true))
    return () => cancelAnimationFrame(raf)
  }, [])

  const shown = drawn ? clamped : 0
  const offset = CIRCUMFERENCE * (1 - shown / 100)

  const ariaLabel = known
    ? `Risk score ${Math.round(clamped)} out of 100 — ${style.text}`
    : 'Unable to determine risk'

  return (
    <div
      className="relative mx-auto w-full max-w-[220px]"
      role="img"
      aria-label={ariaLabel}
    >
      <svg viewBox={`0 0 ${SIZE} ${SIZE}`} className="w-full -rotate-90">
        <title>{ariaLabel}</title>
        <circle
          cx={SIZE / 2}
          cy={SIZE / 2}
          r={RADIUS}
          fill="none"
          stroke="#e2e8f0"
          strokeWidth={STROKE}
        />
        <circle
          cx={SIZE / 2}
          cy={SIZE / 2}
          r={RADIUS}
          fill="none"
          stroke={style.hex}
          strokeWidth={STROKE}
          strokeLinecap="round"
          strokeDasharray={CIRCUMFERENCE}
          strokeDashoffset={known ? offset : CIRCUMFERENCE}
          style={{
            transition: 'stroke-dashoffset 1s cubic-bezier(0.22, 1, 0.36, 1), stroke 0.4s ease',
          }}
          opacity={!known ? 0.55 : 1}
        />
      </svg>

      <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center text-center">
        {known ? (
          <>
            <span className="tabular text-4xl font-extrabold tracking-tight text-ink sm:text-5xl">
              {Math.round(clamped)}
            </span>
            <span className="text-sm font-medium text-muted">out of 100</span>
            <span
              className={`mt-1.5 text-xs font-bold uppercase tracking-[0.14em] ${style.solid}`}
            >
              {style.text}
            </span>
          </>
        ) : (
          <>
            <span className="px-6 text-lg font-bold leading-snug text-risk-unknown">
              Unable to determine risk
            </span>
            <span className="mt-1 text-xs font-medium uppercase tracking-wider text-muted">
              No score available
            </span>
          </>
        )}
      </div>
    </div>
  )
}
