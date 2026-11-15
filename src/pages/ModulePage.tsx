import { useCallback, useEffect, useRef, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { type Module, isTaskDone } from '../content/modules'
import { resetProgress, useSolved } from '../lib/progress'
import { QuestionBox } from '../components/QuestionBox'
import { Terminal, type TerminalHandle } from '../components/Terminal'
import { TerminalContext } from '../components/TerminalContext'

const WELCOME = `Terminal simulasi TryLearnMe.
Berkas latihan ada di ~/Desktop/Exercise-Files. Ketik help untuk daftar perintah.`

const CheckIcon = ({ done }: { done: boolean }) => (
  <svg className={`check ${done ? 'is-done' : ''}`} viewBox="0 0 20 20" width="18" height="18" aria-hidden="true">
    <circle cx="10" cy="10" r="9" />
    <path d="M5.6 10.4l2.9 2.9 5.9-6.2" />
  </svg>
)

const Chevron = () => (
  <svg className="chevron" viewBox="0 0 20 20" width="16" height="16" aria-hidden="true">
    <path d="M4 7l6 6 6-6" />
  </svg>
)

export function ModulePage({ mod }: { mod: Module }) {
  const solved = useSolved()
  const [params, setParams] = useSearchParams()
  const termRef = useRef<TerminalHandle>(null)
  const lastDir = useRef<string | null>(null)
  const [termOpen, setTermOpen] = useState(false)
  const tasks = mod.tasks

  const totalQ = tasks.reduce((n, t) => n + t.questions.length, 0)
  const solvedQ = tasks.reduce((n, t) => n + t.questions.filter((q) => solved[q.id]).length, 0)
  const percent = Math.round((solvedQ / totalQ) * 100)
  const firstOpen = useRef(tasks.find((t) => !isTaskDone(t, solved))?.id ?? 1)
  const openId = params.has('task') ? Number(params.get('task')) : firstOpen.current
  const openTask = tasks.find((t) => t.id === openId)

  // Saat task dibuka, pindahkan terminal ke folder latihannya.
  useEffect(() => {
    const dir = openTask?.dir
    if (!dir || lastDir.current === dir) return
    lastDir.current = dir
    termRef.current?.run(`cd ~/Desktop/Exercise-Files/${dir}`)
  }, [openTask])

  const runInTerminal = useCallback((cmd: string) => {
    setTermOpen(true)
    termRef.current?.run(cmd)
  }, [])

  const toggle = (id: number) => setParams(id === openId ? { task: '0' } : { task: String(id) }, { replace: true })

  return (
    <TerminalContext.Provider value={runInTerminal}>
      <header className="room-head">
        <div className="room-head-inner">
          <div className="room-icon" aria-hidden="true">
            {mod.letter}
          </div>
          <div>
            <h1>{mod.title}</h1>
            <p>{mod.summary}</p>
          </div>
          <div className="room-actions">
            {mod.cheatsheet && (
              <Link to={mod.cheatsheet} className="btn btn-dark">
                Cheat sheet
              </Link>
            )}
            {solvedQ > 0 && (
              <button
                type="button"
                className="btn btn-dark"
                onClick={() => {
                  if (window.confirm(`Hapus semua progress modul ${mod.title}? Jawaban yang sudah benar akan dikosongkan.`)) resetProgress(mod.prefix)
                }}
              >
                Ulangi dari awal
              </button>
            )}
          </div>
        </div>
      </header>

      <main className="module">
        <div className="module-main">
          <div className="room-progress" role="progressbar" aria-label="Progress modul" aria-valuemin={0} aria-valuemax={100} aria-valuenow={percent}>
            <span className="room-progress-fill" style={{ width: `${percent}%` }} />
            <span className="room-progress-text">{percent}%</span>
          </div>

          <ol className="tasks">
            {tasks.map((task) => {
              const open = task.id === openId
              const done = isTaskDone(task, solved)
              return (
                <li key={task.id} className={`task ${open ? 'is-open' : ''} ${done ? 'is-done' : ''}`}>
                  <button type="button" className="task-head" aria-expanded={open} aria-controls={`task-${task.id}`} onClick={() => toggle(task.id)}>
                    <span className="task-num">Task {task.id}</span>
                    <CheckIcon done={done} />
                    <span className="task-title">{task.title}</span>
                    <Chevron />
                  </button>
                  {open && (
                    <div className="task-body" id={`task-${task.id}`}>
                      {task.dir && (
                        <p className="task-dir">
                          Folder latihan: <code className="inline-code">~/Desktop/Exercise-Files/{task.dir}</code>
                        </p>
                      )}
                      <div className="prose">
                        <task.Body />
                      </div>
                      <section className="questions" aria-label={`Soal task ${task.id}`}>
                        <h3 className="q-heading">
                          <span>Jawab pertanyaan berikut</span>
                        </h3>
                        {task.questions.map((q) => (
                          <QuestionBox key={q.id} q={q} solved={!!solved[q.id]} />
                        ))}
                      </section>
                    </div>
                  )}
                </li>
              )
            })}
          </ol>
        </div>

        <aside className={`term-pane ${termOpen ? 'is-open' : ''}`} aria-label="Terminal simulasi">
          <div className="term-bar">
            <span className="term-title">Terminal simulasi</span>
            <button
              type="button"
              className="ghost-btn"
              onClick={() => {
                lastDir.current = null
                termRef.current?.reset()
                if (openTask?.dir) {
                  lastDir.current = openTask.dir
                  termRef.current?.run(`cd ~/Desktop/Exercise-Files/${openTask.dir}`)
                }
              }}
            >
              Mulai ulang
            </button>
            <button type="button" className="ghost-btn term-close" onClick={() => setTermOpen(false)}>
              Tutup
            </button>
          </div>
          <Terminal ref={termRef} welcome={WELCOME} />
        </aside>

        <button type="button" className="term-fab" onClick={() => setTermOpen(true)}>
          Buka terminal
        </button>
      </main>
    </TerminalContext.Provider>
  )
}
