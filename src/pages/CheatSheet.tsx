import { Link } from 'react-router-dom'
import { ZEEK_CHEATSHEET } from '../content/zeek/cheatsheet'
import { CopyButton } from '../content/ui'

export function CheatSheet() {
  return (
    <main className="cheat">
      <header className="module-head">
        <h1>Cheat sheet Zeek</h1>
        <p className="lead">
          Perintah, pola pipe, dan lokasi yang paling sering dipakai. Kembali ke{' '}
          <Link to="/zeek" className="text-link">
            modul Zeek
          </Link>
          .
        </p>
      </header>
      <div className="cheat-grid">
        {ZEEK_CHEATSHEET.map((s) => (
          <section key={s.title} className="cheat-section">
            <h2>{s.title}</h2>
            {s.note && <p className="cheat-note">{s.note}</p>}
            <dl>
              {s.rows.map(([cmd, desc]) => (
                <div key={cmd} className="cheat-row">
                  <dt>
                    <code>{cmd}</code>
                    <CopyButton text={cmd} />
                  </dt>
                  <dd>{desc}</dd>
                </div>
              ))}
            </dl>
          </section>
        ))}
      </div>
    </main>
  )
}
