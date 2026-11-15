import type { FC, ReactNode } from 'react'

export interface Question {
  id: string
  prompt: ReactNode
  /** Kosong = soal "cukup dibaca", ditandai selesai tanpa mengetik jawaban. */
  answer?: string[]
  hint?: ReactNode
}

export interface Task {
  id: number
  title: string
  lead: string
  /** Folder latihan di terminal, relatif terhadap Exercise-Files. */
  dir?: string
  Body: FC
  questions: Question[]
}
