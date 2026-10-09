import { useEffect, useState } from 'react'
import { LoaderCircle, Shield, WifiOff } from 'lucide-react'
import { USE_MOCK } from '../services/analysisApi'

const STAGE_META = [
  { label: 'Validating URL format', progress: 14 },
  { label: 'Preparing URL analysis', progress: 40 },
  {
    label: USE_MOCK ? 'Processing mock results' : 'Waiting for the backend response',
    progress: 70,
  },
  { label: 'Preparing the report', progress: 92 },
]

const STAGE_INTERVAL_MS = 650

/**
 * Animated analyzing state: scanning shield, progress bar, and the four
 * processing labels. In demo mode it states plainly that progress and
 * results are simulated — it never implies live threat-intel checks.
 */
export default function LoadingState({ url }) {
  const [stage, setStage] = useState(0)

  useEffect(() => {
    const id = setInterval(() => {
      setStage((s) => (s < STAGE_META.length - 1 ? s + 1 : s))
    }, STAGE_INTERVAL_MS)
    return () => clearInterval(id)
  }, [])

  const current = STAGE_META[stage]

  return (
    <section
      className="card animate-fade-up overflow-hidden p-6 sm:p-8"
      role="status"
      aria-live="polite"
      aria-busy="true"
    >
      {/* Scanning shield visual */}
      <div className="mx-auto mb-6 flex justify-center">
        <div className="relative">
          <span
            className="absolute inset-0 animate-ping-soft rounded-full bg-blue-200"
            aria-hidden="true"
          />
          <div className="relative flex size-24 items-center justify-center overflow-hidden rounded-3xl bg-gradient-to-br from-brand to-brand-dark text-white shadow-lg shadow-blue-500/30">
            <Shield size={40} aria-hidden="true" />
            <span
              className="animate-scan absolute inset-x-0 top-0 h-1.5 bg-white/70 shadow-[0_0_12px_rgba(255,255,255,0.9)]"
              aria-hidden="true"
            />
          </div>
          <LoaderCircle
            size={20}
            className="absolute -bottom-1 -right-1 animate-spin rounded-full bg-white p-0.5 text-brand"
            aria-hidden="true"
          />
        </div>
      </div>

      <h2 className="text-center text-xl font-bold text-ink sm:text-2xl">
        Analyzing URL…
      </h2>
      <p
        className="mx-auto mt-1 max-w-lg break-all text-center text-sm text-muted"
        title={url}
      >
        {url}
      </p>

      {/* Progress bar */}
      <div
        className="mx-auto mt-6 max-w-lg"
        role="progressbar"
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuenow={current.progress}
        aria-label="Analysis progress"
      >
        <div className="h-2.5 overflow-hidden rounded-full bg-line">
          <div
            className="h-full rounded-full bg-gradient-to-r from-brand to-blue-400 transition-all duration-500 ease-out"
            style={{ width: `${current.progress}%` }}
          />
        </div>
        <div className="mt-2 flex items-center justify-between text-xs font-medium text-muted">
          <span>{current.label}</span>
          <span className="tabular">{current.progress}%</span>
        </div>
      </div>

      {/* Stage checklist */}
      <ol className="mx-auto mt-5 max-w-lg space-y-2">
        {STAGE_META.map((s, i) => (
          <li
            key={s.label}
            className={`flex items-center gap-2.5 text-sm transition-colors ${
              i < stage
                ? 'text-slate-500'
                : i === stage
                  ? 'font-semibold text-brand'
                  : 'text-slate-500'
            }`}
          >
            <span
              className={`flex size-5 items-center justify-center rounded-full text-[10px] font-bold ${
                i < stage
                  ? 'bg-risk-low-soft text-risk-low'
                  : i === stage
                    ? 'bg-brand text-white'
                    : 'bg-slate-100 text-slate-500'
              }`}
              aria-hidden="true"
            >
              {i < stage ? '✓' : i + 1}
            </span>
            {s.label}
          </li>
        ))}
      </ol>

      {/* Honest explanation of what is (not) happening */}
      <div className="mx-auto mt-6 flex max-w-lg items-start gap-2.5 rounded-xl border border-blue-100 bg-brand-soft p-3.5">
        {USE_MOCK ? (
          <Shield size={16} className="mt-0.5 shrink-0 text-brand" aria-hidden="true" />
        ) : (
          <WifiOff size={16} className="mt-0.5 shrink-0 text-brand" aria-hidden="true" />
        )}
        <p className="text-xs leading-relaxed text-blue-900">
          {USE_MOCK ? (
            <>
              <strong>Demo mode:</strong> these progress steps and the resulting
              report are simulated locally in your browser. No live
              threat-intelligence checks are being performed and no website is
              being visited.
            </>
          ) : (
            <>
              <strong>API mode:</strong> this URL has been sent to the
              configured analysis backend, which responds with the risk score,
              findings, and advice shown in the report. Progress labels here
              reflect request stages only.
            </>
          )}
        </p>
      </div>
    </section>
  )
}
