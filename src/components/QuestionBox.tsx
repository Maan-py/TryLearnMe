import { useState, type FormEvent } from 'react'
import type { Question } from '../content/types'
import { isCorrect, markSolved } from '../lib/progress'

export function QuestionBox({ q, solved }: { q: Question; solved: boolean }) {
  const [value, setValue] = useState('')
  const [wrong, setWrong] = useState(false)
  const [showHint, setShowHint] = useState(false)

  if (!q.answer) {
    return (
      <div className={`question ${solved ? 'is-solved' : ''}`}>
        <p className="q-prompt">{q.prompt}</p>
        <div className="q-row">
          <button type="button" className="btn" disabled={solved} onClick={() => markSolved(q.id)}>
            {solved ? 'Sudah selesai' : 'Tandai selesai'}
          </button>
        </div>
      </div>
    )
  }

  const submit = (e: FormEvent) => {
    e.preventDefault()
    if (isCorrect(value, q.answer!)) {
      setWrong(false)
      markSolved(q.id)
    } else setWrong(true)
  }

  return (
    <form className={`question ${solved ? 'is-solved' : ''}`} onSubmit={submit}>
      <p className="q-prompt">{q.prompt}</p>
      <div className="q-row">
        <input
          className="q-input"
          value={solved ? q.answer[0] : value}
          readOnly={solved}
          onChange={(e) => {
            setValue(e.target.value)
            setWrong(false)
          }}
          placeholder="Ketik jawaban"
          spellCheck={false}
          autoComplete="off"
          aria-label="Jawaban"
          aria-invalid={wrong}
        />
        <button type="submit" className="btn" disabled={solved || !value.trim()}>
          {solved ? 'Jawaban benar' : 'Kirim'}
        </button>
        {q.hint && !solved && (
          <button type="button" className="btn btn-hint" onClick={() => setShowHint((s) => !s)} aria-expanded={showHint}>
            {showHint ? 'Tutup petunjuk' : 'Petunjuk'}
          </button>
        )}
      </div>
      <p className="q-status" role="status">
        {wrong && 'Belum tepat. Periksa lagi keluaran di terminal, lalu coba lagi.'}
      </p>
      {showHint && !solved && <p className="q-hint">{q.hint}</p>}
    </form>
  )
}
