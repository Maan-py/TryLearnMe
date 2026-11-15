import type { Task } from './types'
import { ZEEK_TASKS } from './zeek'
import { EXERCISE_TASKS } from './exercises'

export interface Module {
  /** Dipakai sebagai alamat halaman: /#/<id> */
  id: string
  title: string
  navTitle: string
  letter: string
  summary: string
  cardText: string
  /** Awalan id soal, dipakai untuk menghapus progress modul ini saja. */
  prefix: string
  tasks: Task[]
  cheatsheet?: string
}

export const MODULES: Module[] = [
  {
    id: 'zeek',
    title: 'Zeek',
    navTitle: 'Zeek',
    letter: 'Z',
    summary: 'Pengenalan pemantauan keamanan jaringan dan deteksi ancaman dengan Zeek, langsung praktik di terminal.',
    cardText: 'Log jaringan, zeek-cut, signature, script, framework, dan package, dengan latihan di terminal.',
    prefix: 'z',
    tasks: ZEEK_TASKS,
    cheatsheet: '/zeek/cheatsheet',
  },
  {
    id: 'zeek-exercises',
    title: 'Latihan Zeek',
    navTitle: 'Latihan Zeek',
    letter: 'L',
    summary: 'Tiga kasus investigasi: DNS yang tidak wajar, phishing, dan eksploitasi Log4J. Buktikan apakah peringatannya benar.',
    cardText: 'Tiga kasus investigasi dengan Zeek: DNS tunneling, phishing, dan Log4Shell.',
    prefix: 'e',
    tasks: EXERCISE_TASKS,
    cheatsheet: '/zeek/cheatsheet',
  },
]

export const getModule = (id: string | undefined) => MODULES.find((m) => m.id === id)

export const isTaskDone = (task: Task, solved: Record<string, true>) => task.questions.every((q) => solved[q.id])
