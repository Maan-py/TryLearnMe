import { forwardRef, useEffect, useImperativeHandle, useRef, useState, type KeyboardEvent } from 'react'
import { Shell } from '../terminal/shell'

export interface TerminalHandle {
  run: (cmd: string) => void
  reset: () => void
  focus: () => void
}

interface Entry {
  id: number
  prompt: string
  cmd: string
  text: string
}

const MAX_LINES = 1200
const MAX_ENTRIES = 80

function clip(text: string): string {
  const lines = text.split('\n')
  if (lines.length <= MAX_LINES) return text
  const hidden = lines.length - MAX_LINES
  return [`[${hidden} baris pertama tidak ditampilkan. Persempit dengan | head, | tail, | grep, atau | wc -l]`, ...lines.slice(-MAX_LINES)].join('\n')
}

interface Props {
  startDir?: string
  welcome?: string
}

export const Terminal = forwardRef<TerminalHandle, Props>(function Terminal({ startDir, welcome }, ref) {
  const shellRef = useRef<Shell>()
  if (!shellRef.current) shellRef.current = new Shell(startDir)
  const [entries, setEntries] = useState<Entry[]>([])
  const [input, setInput] = useState('')
  const [, setTick] = useState(0)
  const nextId = useRef(0)
  const histPos = useRef<number | null>(null)
  const draft = useRef('')
  const screenRef = useRef<HTMLDivElement>(null)
  const inputRef = useRef<HTMLInputElement>(null)

  const exec = (cmd: string) => {
    const shell = shellRef.current!
    const prompt = shell.prompt()
    const { text, clear } = shell.run(cmd)
    histPos.current = null
    setEntries((prev) => (clear ? [] : [...prev, { id: nextId.current++, prompt, cmd, text: clip(text) }].slice(-MAX_ENTRIES)))
    setTick((t) => t + 1)
  }

  useImperativeHandle(ref, () => ({
    run: (cmd) => {
      exec(cmd)
      setInput('')
    },
    reset: () => {
      shellRef.current = new Shell(startDir)
      setEntries([])
      setInput('')
    },
    focus: () => inputRef.current?.focus({ preventScroll: true }),
  }))

  useEffect(() => {
    const el = screenRef.current
    if (el) el.scrollTop = el.scrollHeight
  }, [entries])

  const onKey = (e: KeyboardEvent<HTMLInputElement>) => {
    const history = shellRef.current!.ctx.history
    if (e.key === 'Enter') {
      exec(input)
      setInput('')
    } else if (e.key === 'ArrowUp') {
      e.preventDefault()
      if (!history.length) return
      if (histPos.current === null) draft.current = input
      histPos.current = Math.max(0, (histPos.current ?? history.length) - 1)
      setInput(history[histPos.current])
    } else if (e.key === 'ArrowDown') {
      e.preventDefault()
      if (histPos.current === null) return
      histPos.current += 1
      if (histPos.current >= history.length) {
        histPos.current = null
        setInput(draft.current)
      } else setInput(history[histPos.current])
    } else if (e.key === 'Tab') {
      e.preventDefault()
      setInput(shellRef.current!.complete(input))
    } else if (e.key === 'l' && e.ctrlKey) {
      e.preventDefault()
      setEntries([])
    } else if (e.key === 'c' && e.ctrlKey && !window.getSelection()?.toString()) {
      e.preventDefault()
      setInput('')
    }
  }

  return (
    <div
      className="terminal"
      ref={screenRef}
      onClick={() => {
        if (!window.getSelection()?.toString()) inputRef.current?.focus({ preventScroll: true })
      }}
    >
      {welcome && entries.length === 0 && <pre className="t-welcome">{welcome}</pre>}
      {entries.map((e) => (
        <div key={e.id} className="t-entry">
          <div className="t-line">
            <span className="t-prompt">{e.prompt}</span> <span className="t-cmd">{e.cmd}</span>
          </div>
          {e.text && <pre className="t-out">{e.text}</pre>}
        </div>
      ))}
      <label className="t-line t-input">
        <span className="t-prompt">{shellRef.current.prompt()}</span>
        <input
          ref={inputRef}
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={onKey}
          spellCheck={false}
          autoCapitalize="off"
          autoCorrect="off"
          autoComplete="off"
          aria-label="Baris perintah terminal simulasi"
        />
      </label>
    </div>
  )
})
