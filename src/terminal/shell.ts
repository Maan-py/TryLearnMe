// Shell mini: memecah baris perintah, menjalankan pipe (|), ; dan &&, serta redirect sederhana.

import { VFS, HOME, toLines } from './vfs'
import { COMMANDS } from './commands'
import { buildLab } from './lab'

export interface ShellState {
  zeekRunning: boolean
}

export interface Ctx {
  fs: VFS
  cwd: string
  user: string
  history: string[]
  state: ShellState
}

export interface Result {
  out: string[]
  err?: string[]
  clear?: boolean
  fail?: boolean
}

export type Command = (args: string[], stdin: string[] | null, ctx: Ctx) => Result

interface Tok {
  v: string
  quoted: boolean
  op?: boolean
}

const OPS = ['&&', '>>', '|', ';', '>', '<']

function tokenize(line: string): Tok[] {
  const toks: Tok[] = []
  let cur = ''
  let quoted = false
  let has = false
  const push = () => {
    if (has) toks.push({ v: cur, quoted })
    cur = ''
    quoted = false
    has = false
  }
  for (let i = 0; i < line.length; i++) {
    const c = line[i]
    if (c === "'" || c === '"') {
      const end = line.indexOf(c, i + 1)
      const stop = end === -1 ? line.length : end
      cur += line.slice(i + 1, stop)
      quoted = true
      has = true
      i = stop
      continue
    }
    if (c === '\\' && i + 1 < line.length) {
      cur += line[++i]
      has = true
      quoted = true
      continue
    }
    if (c === ' ' || c === '\t') {
      push()
      continue
    }
    const op = OPS.find((o) => line.startsWith(o, i))
    if (op) {
      push()
      toks.push({ v: op, quoted: false, op: true })
      i += op.length - 1
      continue
    }
    cur += c
    has = true
  }
  push()
  return toks
}

function globToRegex(glob: string): RegExp {
  const src = glob.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.')
  return new RegExp(`^${src}$`)
}

export class Shell {
  ctx: Ctx

  constructor(startDir = HOME) {
    this.ctx = { fs: buildLab(), cwd: startDir, user: 'ubuntu', history: [], state: { zeekRunning: false } }
  }

  prompt(): string {
    const { cwd, user } = this.ctx
    const shown = cwd === HOME ? '~' : cwd.startsWith(HOME + '/') ? '~' + cwd.slice(HOME.length) : cwd
    return `${user}@trylearnme:${shown}${user === 'root' ? '#' : '$'}`
  }

  cd(path: string): boolean {
    const abs = this.ctx.fs.resolve(path, this.ctx.cwd)
    const node = this.ctx.fs.get(abs)
    if (node?.type !== 'dir') return false
    this.ctx.cwd = abs
    return true
  }

  private expand(tok: Tok): string[] {
    if (tok.quoted || !/[*?]/.test(tok.v)) return [tok.v]
    const i = tok.v.lastIndexOf('/')
    const dirPart = i === -1 ? '' : tok.v.slice(0, i + 1)
    const dir = this.ctx.fs.get(this.ctx.fs.resolve(dirPart || '.', this.ctx.cwd))
    if (dir?.type !== 'dir') return [tok.v]
    const re = globToRegex(tok.v.slice(i + 1))
    const hits = [...dir.children.keys()].filter((n) => !n.startsWith('.') && re.test(n)).sort()
    return hits.length ? hits.map((n) => dirPart + n) : [tok.v]
  }

  private runStage(toks: Tok[], stdin: string[] | null): Result {
    const { fs, cwd } = this.ctx
    const words: string[] = []
    let outFile: { path: string; append: boolean } | null = null
    for (let i = 0; i < toks.length; i++) {
      const t = toks[i]
      if (t.op && (t.v === '>' || t.v === '>>' || t.v === '<')) {
        const target = toks[++i]
        if (!target) return { out: [], err: ['bash: syntax error near unexpected token `newline\''], fail: true }
        if (t.v === '<') {
          const node = fs.get(fs.resolve(target.v, cwd))
          if (node?.type !== 'file') return { out: [], err: [`bash: ${target.v}: No such file or directory`], fail: true }
          stdin = toLines(fs.read(node))
        } else outFile = { path: fs.resolve(target.v, cwd), append: t.v === '>>' }
        continue
      }
      words.push(...this.expand(t))
    }
    if (!words.length) return { out: stdin ?? [] }

    let [name, ...args] = words
    if (name === 'sudo') {
      if (!args.length) return { out: [], err: ['usage: sudo <perintah>'], fail: true }
      if (args[0] === 'su' || args[0] === '-i' || args[0] === '-s') {
        this.ctx.user = 'root'
        return { out: [] }
      }
      ;[name, ...args] = args
    }
    if (name === 'su') {
      this.ctx.user = 'root'
      return { out: [] }
    }
    if (name === 'exit' || name === 'logout') {
      if (this.ctx.user === 'root') {
        this.ctx.user = 'ubuntu'
        return { out: ['exit'] }
      }
      return { out: ['(Simulator: tidak ada sesi yang perlu ditutup. Pakai `clear` untuk membersihkan layar.)'] }
    }
    if ((name === 'bash' || name === 'sh') && args[0]) [name, ...args] = [args[0].startsWith('./') ? args[0] : './' + args[0], ...args.slice(1)]

    const cmd = COMMANDS[name]
    let res: Result
    if (cmd) res = cmd(args, stdin, this.ctx)
    else if (name.startsWith('./') || name.startsWith('/')) {
      const node = fs.get(fs.resolve(name, cwd))
      if (!node) res = { out: [], err: [`bash: ${name}: No such file or directory`], fail: true }
      else if (name.endsWith('clear-logs.sh')) res = COMMANDS['clear-logs'](args, stdin, this.ctx)
      else res = { out: [], err: [`bash: ${name}: Permission denied`], fail: true }
    } else res = { out: [], err: [`${name}: command not found (ketik \`help\` untuk daftar perintah simulator)`], fail: true }

    if (outFile && !res.fail) {
      const prev = outFile.append ? fs.get(outFile.path) : undefined
      const before = prev?.type === 'file' ? fs.read(prev) : ''
      fs.write(outFile.path, before + res.out.join('\n') + (res.out.length ? '\n' : ''))
      res = { ...res, out: [] }
    }
    return res
  }

  /** Jalankan satu baris perintah, kembalikan teks yang tampil di layar. */
  run(line: string): { text: string; clear: boolean } {
    const trimmed = line.trim()
    if (!trimmed) return { text: '', clear: false }
    this.ctx.history.push(trimmed)
    const toks = tokenize(trimmed)
    const screen: string[] = []
    let clear = false

    // Pecah jadi beberapa pipeline berdasarkan ; dan &&.
    const pipelines: { toks: Tok[]; and: boolean }[] = [{ toks: [], and: false }]
    for (const t of toks) {
      if (t.op && (t.v === ';' || t.v === '&&')) pipelines.push({ toks: [], and: t.v === '&&' })
      else pipelines[pipelines.length - 1].toks.push(t)
    }

    let lastFailed = false
    for (const p of pipelines) {
      if (!p.toks.length) continue
      if (p.and && lastFailed) break
      const stages: Tok[][] = [[]]
      for (const t of p.toks) {
        if (t.op && t.v === '|') stages.push([])
        else stages[stages.length - 1].push(t)
      }
      let stdin: string[] | null = null
      lastFailed = false
      for (const stage of stages) {
        const res = this.runStage(stage, stdin)
        if (res.err) screen.push(...res.err)
        if (res.clear) clear = true
        lastFailed = !!res.fail
        stdin = res.out
      }
      if (stdin) screen.push(...stdin)
    }
    return { text: screen.join('\n'), clear }
  }

  /** Pelengkap otomatis (Tab) untuk nama perintah dan nama berkas. */
  complete(input: string): string {
    const m = input.match(/^(.*?)([^\s|;<>]*)$/)
    if (!m) return input
    const [, head, word] = m
    const isCommand = /(^|[|;]|&&)\s*(sudo\s+)?$/.test(head)
    let options: string[]
    let prefix = ''
    if (isCommand && !word.includes('/')) {
      options = Object.keys(COMMANDS).filter((c) => c !== 'clear-logs')
    } else {
      const i = word.lastIndexOf('/')
      prefix = i === -1 ? '' : word.slice(0, i + 1)
      const dir = this.ctx.fs.get(this.ctx.fs.resolve(prefix || '.', this.ctx.cwd))
      if (dir?.type !== 'dir') return input
      options = [...dir.children.entries()].map(([n, node]) => (node.type === 'dir' ? n + '/' : n))
    }
    const part = word.slice(prefix.length)
    const hits = options.filter((o) => o.startsWith(part))
    if (!hits.length) return input
    let common = hits[0]
    for (const h of hits) while (!h.startsWith(common)) common = common.slice(0, -1)
    const done = hits.length === 1 && !common.endsWith('/') ? common + ' ' : common
    return head + prefix + done
  }
}
