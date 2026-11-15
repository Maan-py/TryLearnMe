// Progress belajar disimpan di localStorage browser.
import { useSyncExternalStore } from 'react'

const KEY = 'trylearnme:progress:v1'
type Solved = Record<string, true>

let cache: Solved = load()
const listeners = new Set<() => void>()

function load(): Solved {
  try {
    return JSON.parse(localStorage.getItem(KEY) ?? '{}') as Solved
  } catch {
    return {}
  }
}

function save(next: Solved) {
  cache = next
  try {
    localStorage.setItem(KEY, JSON.stringify(next))
  } catch {
    // Mode privat atau penyimpanan penuh: progress tetap jalan selama tab terbuka.
  }
  listeners.forEach((l) => l())
}

export const markSolved = (id: string) => save({ ...cache, [id]: true })
export const resetProgress = (prefix: string) =>
  save(Object.fromEntries(Object.entries(cache).filter(([k]) => !k.startsWith(prefix))) as Solved)

export function useSolved(): Solved {
  return useSyncExternalStore(
    (l) => {
      listeners.add(l)
      return () => listeners.delete(l)
    },
    () => cache,
  )
}

/** Bandingkan jawaban tanpa peduli huruf besar/kecil dan spasi berlebih. */
export function isCorrect(given: string, answers: string[]): boolean {
  const norm = (s: string) => s.trim().toLowerCase().replace(/\s+/g, ' ')
  return answers.some((a) => norm(a) === norm(given))
}
