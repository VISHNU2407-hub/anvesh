import { Eraser, Link2, ScanSearch, ShieldAlert, ShieldCheck, Wand2 } from 'lucide-react'
import { SAMPLE_URLS } from '../data/mockResults'
import ErrorMessage from './ErrorMessage'

const SAMPLES = [
  {
    key: 'low',
    label: 'Normal sample',
    url: SAMPLE_URLS.low,
    icon: ShieldCheck,
    iconClass: 'text-risk-low',
  },
  {
    key: 'medium',
    label: 'Suspicious pattern sample',
    url: SAMPLE_URLS.medium,
    icon: ShieldAlert,
    iconClass: 'text-risk-medium',
  },
  {
    key: 'high',
    label: 'Phishing-style sample',
    url: SAMPLE_URLS.high,
    icon: ShieldAlert,
    iconClass: 'text-risk-high',
  },
]

/**
 * URL input card: labeled input, Analyze + Clear buttons, one-click sample
 * URLs, inline validation errors, and a privacy/security notice.
 */
export default function UrlScanner({
  url,
  onUrlChange,
  onSubmit,
  onClear,
  disabled = false,
  error = null,
}) {
  return (
    <div className="card p-5 sm:p-6">
      <form onSubmit={onSubmit} noValidate>
        <label
          htmlFor="url-input"
          className="mb-2 block text-sm font-semibold text-ink"
        >
          URL to analyze
        </label>

        <div className="relative">
          <span
            className="pointer-events-none absolute left-4 top-1/2 -translate-y-1/2 text-muted"
            aria-hidden="true"
          >
            <Link2 size={18} />
          </span>
          <input
            id="url-input"
            name="url"
            type="url"
            inputMode="url"
            autoComplete="url"
            spellCheck={false}
            placeholder="https://example.com"
            value={url}
            onChange={(e) => onUrlChange(e.target.value)}
            disabled={disabled}
            aria-invalid={Boolean(error)}
            aria-describedby={error ? 'url-error' : undefined}
            className={`w-full rounded-xl border bg-white py-3.5 pl-11 pr-12 text-[15px] text-ink placeholder:text-slate-400 transition duration-200 focus:border-brand focus:outline-none focus:ring-4 focus:ring-blue-100 disabled:bg-slate-50 disabled:text-muted ${
              error ? 'border-red-300' : 'border-line'
            }`}
          />
          {url ? (
            <button
              type="button"
              onClick={onClear}
              disabled={disabled}
              aria-label="Clear URL input"
              title="Clear URL"
              className="absolute right-3 top-1/2 flex size-8 -translate-y-1/2 items-center justify-center rounded-full text-muted transition hover:bg-canvas hover:text-ink disabled:opacity-40"
            >
              <Eraser size={16} aria-hidden="true" />
            </button>
          ) : null}
        </div>

        {error ? (
          <div id="url-error">
            <ErrorMessage code={error.code} message={error.message} variant="inline" />
          </div>
        ) : null}

        <div className="mt-4 flex flex-col gap-3 sm:flex-row sm:items-center">
          <button
            type="submit"
            disabled={disabled}
            className="btn-primary w-full sm:w-auto"
          >
            <ScanSearch size={18} aria-hidden="true" />
            {disabled ? 'Analyzing…' : 'Analyze Link'}
          </button>
          <button
            type="button"
            onClick={onClear}
            disabled={disabled || !url}
            className="btn-secondary w-full text-sm sm:w-auto"
          >
            <Eraser size={15} aria-hidden="true" />
            Clear
          </button>
        </div>
      </form>

      {/* Sample URL buttons */}
      <div className="mt-5 border-t border-line pt-4">
        <p className="mb-2.5 flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wide text-muted">
          <Wand2 size={13} aria-hidden="true" />
          Demonstration inputs
        </p>
        <div className="flex flex-wrap gap-2">
          {SAMPLES.map((sample) => (
            <button
              key={sample.key}
              type="button"
              className="chip"
              disabled={disabled}
              title={sample.url}
              onClick={() => onUrlChange(sample.url)}
            >
              <sample.icon
                size={14}
                className={sample.iconClass}
                aria-hidden="true"
              />
              {sample.label}
            </button>
          ))}
        </div>
      </div>
    </div>
  )
}
