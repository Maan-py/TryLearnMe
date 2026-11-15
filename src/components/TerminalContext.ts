import { createContext, useContext } from 'react'

/** Dipakai blok contoh di materi untuk mengirim perintah ke terminal simulasi. */
export const TerminalContext = createContext<((cmd: string) => void) | null>(null)
export const useRunInTerminal = () => useContext(TerminalContext)
