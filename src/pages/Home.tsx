import { useRef } from 'react'
import { Link } from 'react-router-dom'
import { MODULES, isTaskDone } from '../content/modules'
import { useSolved } from '../lib/progress'
import { Terminal, type TerminalHandle } from '../components/Terminal'
import { EX } from '../terminal/lab'

const DEMO = [
  'zeek -C -r sample.pcap',
  'ls',
  'cat conn.log | zeek-cut id.orig_h id.resp_h service | head -n 5',
  'cat conn.log | zeek-cut service | sort | uniq -c | sort -nr',
]

export function Home() {
  const solved = useSolved()
  const termRef = useRef<TerminalHandle>(null)
  // Arahkan tombol utama ke modul pertama yang belum selesai.
  const next = MODULES.find((m) => !m.tasks.every((t) => isTaskDone(t, solved))) ?? MODULES[0]
  const started = next.tasks.some((t) => t.questions.some((q) => solved[q.id]))

  return (
    <main>
      <section className="hero">
        <div className="hero-inner">
          <div className="hero-copy">
            <h1>Belajar keamanan jaringan lewat praktik langsung.</h1>
            <p className="lead">
              Baca ringkasannya, ketik perintahnya di terminal simulasi, lalu jawab soal dari hasil yang kamu temukan sendiri. Tanpa VM,
              cukup dari browser.
            </p>
            <Link to={`/${next.id}`} className="btn btn-primary">
              {started ? 'Lanjutkan' : 'Mulai'} modul {next.title}
            </Link>
          </div>

          <div className="hero-term">
            <div className="term-bar">
              <span className="dots" aria-hidden="true">
                <i />
                <i />
                <i />
              </span>
              <span className="term-title">Coba sekarang</span>
            </div>
            <Terminal ref={termRef} startDir={`${EX}/TASK-3`} welcome="Pilih perintah di bawah secara berurutan, atau ketik sendiri." />
            <div className="demo-chips" role="group" aria-label="Contoh perintah">
              {DEMO.map((cmd) => (
                <button key={cmd} type="button" className="chip" onClick={() => termRef.current?.run(cmd)}>
                  {cmd}
                </button>
              ))}
            </div>
          </div>
        </div>
      </section>

      <section className="modules" aria-labelledby="modules-title">
        <h2 id="modules-title">Modul</h2>
        <div className="module-list">
          {MODULES.map((m) => {
            const done = m.tasks.filter((t) => isTaskDone(t, solved)).length
            const percent = Math.round((done / m.tasks.length) * 100)
            return (
              <Link key={m.id} to={`/${m.id}`} className="module-card">
                <div className="module-card-top">
                  <div className="room-icon" aria-hidden="true">
                    {m.letter}
                  </div>
                  <span className="tag">{m.tasks.length} task</span>
                </div>
                <h3>{m.title}</h3>
                <p>{m.cardText}</p>
                <div className="card-progress" role="progressbar" aria-valuemin={0} aria-valuemax={100} aria-valuenow={percent}>
                  <span style={{ width: `${percent}%` }} />
                </div>
                <span className="card-meta">
                  {done} dari {m.tasks.length} task selesai
                </span>
              </Link>
            )
          })}
          <div className="module-card is-soon" aria-disabled="true">
            <div className="module-card-top">
              <div className="room-icon" aria-hidden="true">
                S
              </div>
              <span className="tag">Segera hadir</span>
            </div>
            <h3>Suricata</h3>
            <p>Rule, mode IDS dan IPS, serta membaca eve.json. Modul ini belum tersedia.</p>
          </div>
        </div>
      </section>
    </main>
  )
}
