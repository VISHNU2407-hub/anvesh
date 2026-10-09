import { Globe, Link2, Lock, FileText } from 'lucide-react'

function Row({ icon: Icon, label, value, mono = false }) {
  return (
    <div className="flex items-start gap-3 py-3">
      <span
        className="flex size-8 shrink-0 items-center justify-center rounded-lg bg-brand-soft text-brand"
        aria-hidden="true"
      >
        <Icon size={16} />
      </span>
      <div className="min-w-0 flex-1">
        <dt className="text-xs font-semibold uppercase tracking-wide text-muted">
          {label}
        </dt>
        <dd
          className={`mt-0.5 break-all text-sm font-medium text-ink ${mono ? 'font-mono text-[13px]' : ''}`}
        >
          {value}
        </dd>
      </div>
    </div>
  )
}

/**
 * URL details card: the scanned address, extracted hostname, and scheme —
 * everything shown here is derived from the actual input/response, nothing
 * is fabricated.
 */
export default function UrlDetails({ result }) {
  if (!result) return null

  let scheme = '—'
  try {
    const u = new URL(result.url)
    scheme = u.protocol.replace(':', '').toUpperCase()
  } catch {
    /* keep placeholder */
  }

  return (
    <div className="card p-5">
      <h3 className="flex items-center gap-2 text-sm font-bold uppercase tracking-wide text-muted">
        <FileText size={15} aria-hidden="true" />
        URL details
      </h3>
      <dl className="mt-2 divide-y divide-line">
        <Row icon={Link2} label="Scanned URL" value={result.url} mono />
        <Row icon={Globe} label="Hostname" value={result.domain} mono />
        <Row
          icon={Lock}
          label="Scheme"
          value={
            <span className="inline-flex items-center gap-1.5">
              {scheme}
              {scheme === 'HTTPS' ? (
                <span className="rounded-full bg-risk-low-soft px-2 py-0.5 text-[11px] font-semibold text-risk-low">
                  Encrypted
                </span>
              ) : scheme === 'HTTP' ? (
                <span className="rounded-full bg-risk-medium-soft px-2 py-0.5 text-[11px] font-semibold text-risk-medium">
                  Not encrypted
                </span>
              ) : null}
            </span>
          }
        />
      </dl>
    </div>
  )
}
