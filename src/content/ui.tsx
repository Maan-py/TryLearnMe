// Komponen kecil untuk menulis materi.
import { useState, type ReactNode } from 'react'
import { useRunInTerminal } from '../components/TerminalContext'

export const C = ({ children }: { children: ReactNode }) => <code className="inline-code">{children}</code>
export const H = ({ children }: { children: ReactNode }) => <h3 className="sub">{children}</h3>

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false)
  return (
    <button
      type="button"
      className="ghost-btn"
      onClick={() => {
        navigator.clipboard?.writeText(text).then(() => {
          setCopied(true)
          setTimeout(() => setCopied(false), 1500)
        })
      }}
    >
      {copied ? 'Tersalin' : 'Salin'}
    </button>
  )
}

/** Tiga titik ala jendela terminal di kepala blok kode. */
const Dots = () => (
  <span className="dots" aria-hidden="true">
    <i />
    <i />
    <i />
  </span>
)

/** Blok kode (isi berkas signature, script, dan sejenisnya). */
export function Code({ title, children }: { title?: string; children: string }) {
  const text = children.replace(/^\n/, '').replace(/\n$/, '')
  return (
    <figure className="code">
      <figcaption>
        <Dots />
        <span className="code-title">{title ?? 'Kode'}</span>
        <CopyButton text={text} />
      </figcaption>
      <pre>{text}</pre>
    </figure>
  )
}

/** Contoh sesi terminal. Baris yang diawali "$ " adalah perintah dan bisa dijalankan di terminal simulasi. */
export function Term({ title, children }: { title?: string; children: string }) {
  const run = useRunInTerminal()
  const lines = children.replace(/^\n/, '').replace(/\n$/, '').split('\n')
  return (
    <figure className="code term-example">
      <figcaption>
        <Dots />
        <span className="code-title">{title ?? 'Terminal'}</span>
        <span className="code-spacer" />
      </figcaption>
      <pre>
        {lines.map((line, i) =>
          line.startsWith('$ ') ? (
            <span key={i} className="cmd-line">
              <span className="ps">ubuntu@ubuntu$</span> {line.slice(2)}
              {run && (
                <button type="button" className="run-btn" onClick={() => run(line.slice(2))} title="Jalankan di terminal simulasi">
                  Jalankan
                </button>
              )}
              {'\n'}
            </span>
          ) : (
            <span key={i} className="out-line">
              {line}
              {'\n'}
            </span>
          ),
        )}
      </pre>
    </figure>
  )
}

export function Table({ head, rows }: { head: ReactNode[]; rows: ReactNode[][] }) {
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>{head.map((h, i) => <th key={i}>{h}</th>)}</tr>
        </thead>
        <tbody>
          {rows.map((r, i) => (
            <tr key={i}>{r.map((c, j) => <td key={j}>{c}</td>)}</tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

export function Note({ kind = 'info', children }: { kind?: 'info' | 'warn' | 'sim'; children: ReactNode }) {
  const label = kind === 'warn' ? 'Perhatian' : kind === 'sim' ? 'Di simulator' : 'Catatan'
  return (
    <aside className={`note note-${kind}`}>
      <strong>{label}.</strong> {children}
    </aside>
  )
}

export { CopyButton }
