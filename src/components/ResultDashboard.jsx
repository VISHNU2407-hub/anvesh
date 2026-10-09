import {
  ArrowLeft,
  CircleHelp,
  FileSearch,
  Radar,
  ShieldAlert,
  ShieldCheck,
  TriangleAlert,
} from 'lucide-react'
import FindingCard from './FindingCard'
import Recommendations from './Recommendations'
import RiskBadge from './RiskBadge'
import RiskMeter from './RiskMeter'
import ThreatStatus from './ThreatStatus'
import UrlDetails from './UrlDetails'
import { formatTimestamp, riskStyle } from './riskStyles'

function SectionCard({ icon: Icon, title, children, className = '' }) {
  return (
    <section className={`card p-5 sm:p-6 ${className}`}>
      <h3 className="mb-4 flex items-center gap-2 text-sm font-bold uppercase tracking-wide text-muted">
        <Icon size={15} aria-hidden="true" />
        {title}
      </h3>
      {children}
    </section>
  )
}

const VERDICT_META = {
  confirmed_malicious: {
    label: 'Confirmed Malicious',
    chip: 'bg-red-600 text-white',
    icon: ShieldAlert,
    bg: 'bg-red-100',
    iconClass: 'text-red-600',
  },
  suspicious: {
    label: 'Suspicious',
    chip: 'bg-amber-500 text-white',
    icon: TriangleAlert,
    bg: 'bg-amber-100',
    iconClass: 'text-amber-600',
  },
  unknown: {
    label: 'Needs Verification',
    chip: 'bg-slate-600 text-white',
    icon: CircleHelp,
    bg: 'bg-slate-100',
    iconClass: 'text-slate-600',
  },
  verified_safe: {
    label: 'No Known Threat',
    chip: 'bg-emerald-600 text-white',
    icon: ShieldCheck,
    bg: 'bg-emerald-100',
    iconClass: 'text-emerald-600',
  },
}

function VerdictBadge({ verdict }) {
  if (!verdict) return null
  const key = String(verdict).toLowerCase()
  const meta = VERDICT_META[key]
  if (!meta) return null
  return (
    <span className={`inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-bold uppercase tracking-wide ${meta.chip}`}>
      {meta.label}
    </span>
  )
}

function VerdictBanner({ result }) {
  const verdict = String(result.verdict ?? '').toLowerCase()
  const reputationStatus = String(result.reputation_status ?? result.reputation?.rawStatus ?? '').toLowerCase()
  const score = result.risk_score ?? result.score

  if (verdict === 'confirmed_malicious') {
    const matches = result.reputation?.matches?.map((m) => m.threat_type).filter(Boolean).join(', ')
    return (
      <div role="alert" className="mb-4 flex items-start gap-3 rounded-2xl border border-red-300 bg-gradient-to-r from-red-50 to-rose-50 p-4">
        <ShieldAlert size={20} className="mt-0.5 shrink-0 text-risk-high" aria-hidden="true" />
        <div className="text-sm leading-relaxed text-red-700">
          <p className="font-bold text-red-800">Confirmed threat — do not visit this URL.</p>
          <p className="mt-1">
            Google Safe Browsing matched this address to a known threat list{matches ? ` (${matches})` : ''}.
            Do not enter credentials, download files, or share this link.
          </p>
        </div>
      </div>
    )
  }

  if (verdict === 'suspicious') {
    return (
      <div role="alert" className="mb-4 flex items-start gap-3 rounded-2xl border border-amber-300 bg-amber-50 p-4">
        <TriangleAlert size={20} className="mt-0.5 shrink-0 text-risk-medium" aria-hidden="true" />
        <div className="text-sm leading-relaxed text-amber-800">
          <p className="font-bold text-amber-900">Suspicious patterns detected — review before trusting.</p>
          <p className="mt-1">
            Detection flagged {result.findings?.length ?? 0} signal(s) (score {score ?? '—'}/100).
            This is not a confirmed malicious verdict, but independent verification is required before entering information.
          </p>
        </div>
      </div>
    )
  }

  if (verdict === 'verified_safe') {
    return (
      <div className="mb-4 flex items-start gap-3 rounded-2xl border border-emerald-200 bg-emerald-50 p-4">
        <ShieldCheck size={20} className="mt-0.5 shrink-0 text-emerald-600" aria-hidden="true" />
        <div className="text-sm leading-relaxed text-emerald-800">
          <p className="font-bold text-emerald-900">No known threat — not a guarantee of safety.</p>
          <p className="mt-1">No threat list match was found, but this does not prove the URL is safe. Verify through an official source before sharing sensitive information.</p>
        </div>
      </div>
    )
  }

  if (verdict === 'unknown') {
    if (reputationStatus === 'unavailable') {
      const reason = result.reputation?.error_reason
        ? ` Reason: ${result.reputation.error_reason}.`
        : ''
      return (
        <div className="mb-4 flex items-start gap-3 rounded-2xl border border-slate-300 bg-slate-50 p-4">
          <CircleHelp size={20} className="mt-0.5 shrink-0 text-slate-600" aria-hidden="true" />
          <div className="text-sm leading-relaxed text-slate-700">
            <p className="font-bold text-slate-800">Unable to verify — treat as unverified.</p>
            <p className="mt-1">
              The reputation check could not be completed, and only weak or no signals were observed.{reason} No safe verdict can be given — verify manually before trusting.
            </p>
          </div>
        </div>
      )
    }
    if (reputationStatus === 'no_known_threat') {
      return (
        <div className="mb-4 flex items-start gap-3 rounded-2xl border border-slate-300 bg-slate-50 p-4">
          <CircleHelp size={20} className="mt-0.5 shrink-0 text-slate-600" aria-hidden="true" />
          <div className="text-sm leading-relaxed text-slate-700">
            <p className="font-bold text-slate-800">No known threats found — safety is not guaranteed.</p>
            <p className="mt-1">
              No threat list match was found. This is not proof the URL is safe. Verify the destination through an official channel before entering credentials.
            </p>
          </div>
        </div>
      )
    }
    return (
      <div className="mb-4 rounded-2xl border border-slate-300 bg-slate-50 p-4 text-sm text-slate-700">
        The service could not determine a risk level for this URL. Only weak or insufficient signals were observed. Treat the result as unverified and verify manually before trusting.
      </div>
    )
  }

  // Fallback for legacy/mock shapes without verdict
  if (result.risk_level === 'Unknown') {
    return (
      <div className="mb-4 rounded-2xl border border-slate-300 bg-slate-50 p-4 text-sm text-slate-700">
        The service could not determine a risk level for this URL. Treat the result cautiously.
      </div>
    )
  }

  return null
}

/**
 * Analysis report dashboard. Renders every scenario with risk-consistent
 * accents, verdict-aware banners, findings, threat-intelligence status, and
 * safety recommendations. Never presents `unknown` or `no_known_threat` as
 * guaranteed safe.
 */
export default function ResultDashboard({ result, onNewScan }) {
  if (!result) return null

  const style = riskStyle(result.risk_level)
  const hasVerdict = Boolean(result.verdict)

  return (
    <div className="animate-fade-up">
      {/* Header row */}
      <div className="animate-rise mb-5 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex flex-wrap items-center gap-3">
          <h1 className="section-title text-2xl sm:text-3xl">Analysis report</h1>
          <RiskBadge level={result.risk_level} />
          {hasVerdict ? <VerdictBadge verdict={result.verdict} /> : null}
        </div>
        <button type="button" onClick={onNewScan} className="btn-primary self-start text-sm sm:self-auto">
          <ArrowLeft size={16} aria-hidden="true" />
          New Scan
        </button>
      </div>

      {hasVerdict ? (
        <VerdictBanner result={result} />
      ) : result.risk_level === 'Unknown' ? (
        <div className="mb-4 rounded-2xl border border-slate-300 bg-slate-50 p-4 text-sm text-slate-700">
          The service could not determine a risk level for this URL. Treat the result cautiously.
        </div>
      ) : null}

      {/* Result cards, in decision order: risk → URL → findings → threat → advice */}
      <div className="flex flex-col gap-4">
        <section
          className="card animate-rise anim-delay-1 border-t-4 p-6"
          style={{ borderTopColor: style.hex }}
          aria-label="Risk score summary"
        >
          <div className="mb-4 flex items-center justify-between gap-2">
            <h3 className="text-sm font-bold uppercase tracking-wide text-muted">Risk score</h3>
            <RiskBadge level={result.risk_level} size="sm" />
          </div>

          <RiskMeter score={result.risk_score ?? result.score} level={result.risk_level} />

          <div className="mt-4 text-center text-xs font-medium text-muted">
            <p>
              Score ·{' '}
              <span className="font-semibold">
                {typeof (result.risk_score ?? result.score) === 'number'
                  ? `${result.risk_score ?? result.score}/100`
                  : 'no score available'}
              </span>
              {hasVerdict ? (
                <span className="ml-2">· Verdict: <span className="font-semibold capitalize">{String(result.verdict).replace(/_/g, ' ')}</span></span>
              ) : null}
            </p>
            {hasVerdict && result.reputation_status ? (
              <p className="mt-1">Reputation: <span className="font-semibold">{String(result.reputation_status).replace(/_/g, ' ')}</span></p>
            ) : null}
          </div>
        </section>

        <div className="animate-rise anim-delay-2">
          <UrlDetails result={result} />
        </div>

        <SectionCard
          icon={FileSearch}
          title="Security findings"
          className="animate-rise anim-delay-3"
        >
          {result.findings.length > 0 ? (
            <ul className="stagger-children space-y-3">
              {result.findings.map((finding, i) => (
                <FindingCard key={`${finding.name}-${i}-${finding.rule_id ?? ''}`} finding={finding} />
              ))}
            </ul>
          ) : (
            <div className="rounded-xl border border-dashed border-line bg-canvas p-5 text-sm text-muted">
              No findings were returned for this scan. An absence of findings is not proof that the URL is safe.
            </div>
          )}
        </SectionCard>

        <SectionCard
          icon={Radar}
          title="Threat intelligence status"
          className="animate-rise anim-delay-4"
        >
          <ThreatStatus
            status={result.reputation?.status ?? result.reputation_status}
            message={result.reputation?.message}
          />
        </SectionCard>

        <SectionCard
          icon={ShieldCheck}
          title="Safety recommendations"
          className="animate-rise anim-delay-5"
        >
          <Recommendations
            items={result.advice}
            accent={style.key === 'unknown' ? 'brand' : style.key}
          />
        </SectionCard>
      </div>

      {/* Scan time */}
      <p className="animate-rise anim-delay-6 mt-5 text-xs text-muted">
        Scan completed · {formatTimestamp(result.scanned_at)}
        {hasVerdict ? ` · Verdict: ${String(result.verdict).replace(/_/g, ' ')}` : ''}
      </p>
    </div>
  )
}
