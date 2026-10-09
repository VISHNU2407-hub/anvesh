import { Link } from 'lucide-react'
import { NavLink } from 'react-router-dom'

const YEAR = new Date().getFullYear()

const FOOTER_LINKS = [
  { to: '/', label: 'Home', end: true },
  { to: '/how-it-works', label: 'How It Works' },
  { to: '/history', label: 'History' },
]

/**
 * Professional footer with navigation and an honest disclaimer about the
 * demonstration nature of the results.
 */
export default function Footer() {
  return (
    <footer className="border-t border-line bg-white">
      <div className="mx-auto max-w-6xl px-4 py-10 sm:px-6">
        <div className="flex flex-col gap-8 md:flex-row md:items-start md:justify-between">
          <div className="max-w-sm">
            <p className="flex items-center gap-2 text-base font-extrabold tracking-tight text-ink">
              <span className="flex size-8 items-center justify-center rounded-lg bg-gradient-to-br from-brand to-brand-dark text-white">
                <Link size={16} aria-hidden="true" />
              </span>
              URL<span className="text-brand">ens</span>
            </p>
            <p className="mt-2 text-sm font-semibold text-ink">
              See the threat before you click.
            </p>
            <p className="mt-1 text-sm text-muted">
              Phishing &amp; Malicious Link Detection
            </p>
          </div>

          <nav aria-label="Footer navigation">
            <h2 className="text-xs font-bold uppercase tracking-wider text-muted">
              Navigate
            </h2>
            <ul className="mt-3 grid grid-cols-2 gap-x-8 gap-y-2">
              {FOOTER_LINKS.map((item) => (
                <li key={item.to}>
                  <NavLink
                    to={item.to}
                    end={item.end}
                    className="text-sm text-slate-600 transition hover:text-brand"
                  >
                    {item.label}
                  </NavLink>
                </li>
              ))}
            </ul>
          </nav>
        </div>

        <div className="mt-8 border-t border-line pt-6">
          <p className="text-xs text-muted">
            © {YEAR} URLens · Demonstration build with simulated results.
          </p>
        </div>
      </div>
    </footer>
  )
}
