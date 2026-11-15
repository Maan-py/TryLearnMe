// Implementasi perintah-perintah yang tersedia di terminal simulasi.

import type { Command, Ctx, Result } from './shell'
import { type VNode, type FileNode, toLines, basename } from './vfs'
import { zeek, zeekctl, zkg } from './zeek'

const fail = (...err: string[]): Result => ({ out: [], err, fail: true })

function isBinary(node: FileNode) {
  return node.kind !== 'text'
}

/** Baca berkas teks jadi baris-baris; mengembalikan pesan galat bila tidak bisa. */
function readLines(ctx: Ctx, cmd: string, path: string): { lines?: string[]; err?: string } {
  const node = ctx.fs.get(ctx.fs.resolve(path, ctx.cwd))
  if (!node) return { err: `${cmd}: ${path}: No such file or directory` }
  if (node.type === 'dir') return { err: `${cmd}: ${path}: Is a directory` }
  if (isBinary(node)) return { err: `${cmd}: ${path}: berkas biner, isinya tidak ditampilkan di simulator` }
  return { lines: toLines(ctx.fs.read(node)) }
}

/** Gabungkan isi semua berkas, atau pakai stdin bila tidak ada berkas. */
function input(ctx: Ctx, cmd: string, files: string[], stdin: string[] | null): { lines: string[]; err: string[] } {
  if (!files.length) return { lines: stdin ?? [], err: [] }
  const lines: string[] = []
  const err: string[] = []
  for (const f of files) {
    const r = readLines(ctx, cmd, f)
    if (r.err) err.push(r.err)
    else lines.push(...r.lines!)
  }
  return { lines, err }
}

const done = (lines: string[], err: string[]): Result => (err.length ? { out: lines, err, fail: true } : { out: lines })

// ---------- navigasi & berkas ----------

function size(ctx: Ctx, name: string, node: VNode): number {
  if (node.type === 'dir') return 4096
  if (node.kind === 'pcap') return 20000 + ([...name].reduce((a, c) => a + c.charCodeAt(0), 0) % 97) * 9173
  if (node.kind === 'doc') return 323072
  if (node.kind === 'exe') return 2437120
  return ctx.fs.read(node).length
}

const ls: Command = (args, _stdin, ctx) => {
  const flags = args.filter((a) => a.startsWith('-')).join('')
  const targets = args.filter((a) => !a.startsWith('-'))
  const long = flags.includes('l')
  const all = flags.includes('a')
  const out: string[] = []
  const err: string[] = []
  const fmt = (name: string, node: VNode) =>
    long
      ? `${node.type === 'dir' ? 'drwxr-xr-x 2' : node.exec ? '-rwxr-xr-x 1' : '-rw-r--r-- 1'} ubuntu ubuntu ${String(size(ctx, name, node)).padStart(8)} Nov  9 05:55 ${name}`
      : name
  const list = (entries: [string, VNode][]) => {
    const rows = entries.filter(([n]) => all || !n.startsWith('.')).sort(([a], [b]) => a.localeCompare(b)).map(([n, node]) => fmt(n, node))
    if (long) out.push(...rows)
    else if (rows.length) out.push(rows.join('  '))
  }
  const paths = targets.length ? targets : ['.']
  const files: [string, VNode][] = []
  const dirs: [string, VNode][] = []
  for (const p of paths) {
    const node = ctx.fs.get(ctx.fs.resolve(p, ctx.cwd))
    if (!node) err.push(`ls: cannot access '${p}': No such file or directory`)
    else (node.type === 'dir' ? dirs : files).push([p, node])
  }
  if (files.length) list(files)
  for (const [p, node] of dirs) {
    if (paths.length > 1) out.push(...(out.length ? [''] : []), `${p}:`)
    if (node.type === 'dir') list([...node.children.entries()])
  }
  return done(out, err)
}

const cd: Command = (args, _stdin, ctx) => {
  const target = args[0] ?? '~'
  const abs = ctx.fs.resolve(target, ctx.cwd)
  const node = ctx.fs.get(abs)
  if (!node) return fail(`bash: cd: ${target}: No such file or directory`)
  if (node.type !== 'dir') return fail(`bash: cd: ${target}: Not a directory`)
  ctx.cwd = abs
  return { out: [] }
}

const cat: Command = (args, stdin, ctx) => {
  const { lines, err } = input(ctx, 'cat', args.filter((a) => !a.startsWith('-')), stdin)
  return done(lines, err)
}

function countArg(args: string[]): { n: number; fromStart: boolean; files: string[] } {
  let n = 10
  let fromStart = false
  const files: string[] = []
  for (let i = 0; i < args.length; i++) {
    const a = args[i]
    let v: string | null = null
    if (a === '-n') v = args[++i] ?? ''
    else if (/^-n.+/.test(a)) v = a.slice(2)
    else if (/^-\d+$/.test(a)) v = a.slice(1)
    else files.push(a)
    if (v !== null) {
      fromStart = v.startsWith('+')
      n = parseInt(v.replace('+', ''), 10) || 0
    }
  }
  return { n, fromStart, files }
}

const head: Command = (args, stdin, ctx) => {
  const { n, files } = countArg(args)
  const { lines, err } = input(ctx, 'head', files, stdin)
  return done(lines.slice(0, n), err)
}

const tail: Command = (args, stdin, ctx) => {
  const { n, fromStart, files } = countArg(args)
  const { lines, err } = input(ctx, 'tail', files, stdin)
  return done(fromStart ? lines.slice(Math.max(n - 1, 0)) : n === 0 ? [] : lines.slice(-n), err)
}

const rm: Command = (args, _stdin, ctx) => {
  const flags = args.filter((a) => a.startsWith('-')).join('')
  const err: string[] = []
  for (const p of args.filter((a) => !a.startsWith('-'))) {
    const abs = ctx.fs.resolve(p, ctx.cwd)
    const node = ctx.fs.get(abs)
    if (!node) {
      if (!flags.includes('f')) err.push(`rm: cannot remove '${p}': No such file or directory`)
    } else if (node.type === 'dir' && !/[rR]/.test(flags)) err.push(`rm: cannot remove '${p}': Is a directory`)
    else ctx.fs.remove(abs)
  }
  return done([], err)
}

const clearLogs: Command = (_args, _stdin, ctx) => {
  const dir = ctx.fs.get(ctx.cwd)
  if (dir?.type === 'dir') {
    for (const name of [...dir.children.keys()]) if (name.endsWith('.log') || name === 'extract_files') dir.children.delete(name)
  }
  return { out: [] }
}

const FILE_DESC: Record<string, string> = {
  pcap: 'pcap capture file, microsecond ts (little-endian) - version 2.4 (Ethernet, capture length 262144)',
  doc: 'Composite Document File V2 Document, Little Endian, Os: Windows, Version 6.3, Code page: 1252, Template: Normal.dotm, Last Saved By: Administrator, Revision Number: 2, Name of Creating Application: Microsoft Office Word, Create Time/Date: Thu Jun 27 18:24:00 2019, Number of Pages: 1, Security: 0',
  exe: 'PE32 executable (GUI) Intel 80386, for MS Windows',
}

const file: Command = (args, _stdin, ctx) => {
  const out: string[] = []
  const names = args.filter((a) => !a.startsWith('-'))
  const width = Math.max(0, ...names.map((n) => n.length)) + 1
  for (const p of names) {
    const node = ctx.fs.get(ctx.fs.resolve(p, ctx.cwd))
    let desc: string
    if (!node) desc = 'cannot open (No such file or directory)'
    else if (node.type === 'dir') desc = 'directory'
    else if (node.kind !== 'text') desc = FILE_DESC[node.kind]
    else if (p.endsWith('.sh')) desc = 'Bourne-Again shell script, ASCII text executable'
    else {
      const text = ctx.fs.read(node)
      desc = text === '' ? 'empty' : text.includes('\n') ? 'ASCII text' : 'ASCII text, with no line terminators'
    }
    out.push(`${(p + ':').padEnd(width)} ${desc}`)
  }
  return { out }
}

// ---------- pengolah teks ----------

function toRegex(pattern: string, mode: 'basic' | 'extended' | 'fixed'): string {
  const escapeAll = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
  if (mode === 'fixed') return escapeAll(pattern)
  let src = pattern
  if (mode === 'basic') {
    // Pada regex dasar, + ? | ( ) { } bermakna harfiah kecuali diawali backslash.
    src = ''
    for (let i = 0; i < pattern.length; i++) {
      const c = pattern[i]
      if (c === '\\' && '+?|(){}'.includes(pattern[i + 1] ?? '')) src += pattern[++i]
      else if (c === '\\' && i + 1 < pattern.length) src += c + pattern[++i]
      else if ('+?|(){}'.includes(c)) src += '\\' + c
      else src += c
    }
  }
  if (src.startsWith('*')) src = '\\' + src
  try {
    new RegExp(src)
    return src
  } catch {
    return escapeAll(pattern)
  }
}

const grep: Command = (args, stdin, ctx) => {
  let flags = ''
  const patterns: string[] = []
  const rest: string[] = []
  for (let i = 0; i < args.length; i++) {
    const a = args[i]
    if (a.startsWith('-') && a.length > 1 && !/^-\d/.test(a)) {
      const e = a.indexOf('e')
      if (e !== -1) {
        flags += a.slice(1, e)
        patterns.push(a.length > e + 1 ? a.slice(e + 1) : args[++i] ?? '')
      } else flags += a.slice(1)
    } else rest.push(a)
  }
  if (!patterns.length) {
    if (!rest.length) return fail('Usage: grep [OPTION]... PATTERNS [FILE]...')
    patterns.push(rest.shift()!)
  }
  const mode = flags.includes('F') ? 'fixed' : flags.includes('E') ? 'extended' : 'basic'
  let src = patterns.map((p) => toRegex(p, mode)).join('|')
  if (flags.includes('w')) src = `\\b(?:${src})\\b`
  const re = new RegExp(src, flags.includes('i') ? 'i' : '')
  const recursive = /[rR]/.test(flags)
  const invert = flags.includes('v')

  const sources: { label: string; lines: string[] }[] = []
  const err: string[] = []
  const walk = (label: string, node: VNode) => {
    if (node.type === 'dir') {
      for (const [n, child] of [...node.children.entries()].sort(([a], [b]) => a.localeCompare(b))) walk(label === '' ? n : `${label}/${n}`, child)
    } else if (!isBinary(node)) sources.push({ label, lines: toLines(ctx.fs.read(node)) })
  }
  const files = rest.length ? rest : recursive ? [''] : []
  if (!files.length) sources.push({ label: '', lines: stdin ?? [] })
  for (const f of files) {
    const node = ctx.fs.get(ctx.fs.resolve(f || '.', ctx.cwd))
    if (!node) err.push(`grep: ${f}: No such file or directory`)
    else if (node.type === 'dir' && !recursive) err.push(`grep: ${f}: Is a directory`)
    else if (node.type === 'file' && isBinary(node)) continue
    else walk(f.replace(/\/$/, ''), node)
  }
  const showName = !flags.includes('h') && (recursive || rest.length > 1)
  const out: string[] = []
  for (const s of sources) {
    const prefix = showName ? s.label + ':' : ''
    let count = 0
    s.lines.forEach((line, i) => {
      if (re.test(line) === invert) return
      count++
      if (flags.includes('c') || flags.includes('l')) return
      const num = flags.includes('n') ? `${i + 1}:` : ''
      if (flags.includes('o') && !invert) {
        for (const m of line.match(new RegExp(src, flags.includes('i') ? 'gi' : 'g')) ?? []) out.push(prefix + num + m)
      } else out.push(prefix + num + line)
    })
    if (flags.includes('c')) out.push(prefix + count)
    else if (flags.includes('l') && count) out.push(s.label)
  }
  return done(out, err)
}

const sort: Command = (args, stdin, ctx) => {
  let flags = ''
  let key = 0
  let sep: string | null = null
  const files: string[] = []
  for (let i = 0; i < args.length; i++) {
    const a = args[i]
    if (a.startsWith('-k')) key = parseInt(a.length > 2 ? a.slice(2) : args[++i] ?? '1', 10) || 0
    else if (a.startsWith('-t')) sep = a.length > 2 ? a.slice(2) : args[++i] ?? null
    else if (a.startsWith('-') && a.length > 1) flags += a.slice(1)
    else files.push(a)
  }
  const { lines, err } = input(ctx, 'sort', files, stdin)
  const numeric = flags.includes('n')
  const keyOf = (line: string) => {
    if (!key) return line
    const parts = sep ? line.split(sep) : line.trim().split(/\s+/)
    return parts[key - 1] ?? ''
  }
  const num = (s: string) => {
    const v = parseFloat(s)
    return Number.isNaN(v) ? 0 : v
  }
  const fold = flags.includes('f') ? (s: string) => s.toLowerCase() : (s: string) => s
  const plain = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0)
  const byKey = (a: string, b: string) => (numeric ? num(keyOf(a)) - num(keyOf(b)) : plain(fold(keyOf(a)), fold(keyOf(b))))
  let sorted = [...lines].sort((a, b) => byKey(a, b) || plain(a, b))
  if (flags.includes('u')) sorted = sorted.filter((l, i) => i === 0 || byKey(sorted[i - 1], l) !== 0)
  if (flags.includes('r')) sorted.reverse()
  return done(sorted, err)
}

const uniq: Command = (args, stdin, ctx) => {
  const flags = args.filter((a) => a.startsWith('-')).join('')
  const { lines, err } = input(ctx, 'uniq', args.filter((a) => !a.startsWith('-')).slice(0, 1), stdin)
  const same = flags.includes('i') ? (a: string, b: string) => a.toLowerCase() === b.toLowerCase() : (a: string, b: string) => a === b
  const groups: { line: string; n: number }[] = []
  for (const line of lines) {
    const last = groups[groups.length - 1]
    if (last && same(last.line, line)) last.n++
    else groups.push({ line, n: 1 })
  }
  let kept = groups
  if (flags.includes('d')) kept = groups.filter((g) => g.n > 1)
  else if (flags.includes('u')) kept = groups.filter((g) => g.n === 1)
  return done(kept.map((g) => (flags.includes('c') ? `${String(g.n).padStart(7)} ${g.line}` : g.line)), err)
}

const wc: Command = (args, stdin, ctx) => {
  const flags = args.filter((a) => a.startsWith('-')).join('').replace(/-/g, '') || 'lwc'
  const files = args.filter((a) => !a.startsWith('-'))
  const count = (lines: string[]) => {
    const vals: number[] = []
    if (flags.includes('l')) vals.push(lines.length)
    if (flags.includes('w')) vals.push(lines.reduce((a, l) => a + (l.trim() ? l.trim().split(/\s+/).length : 0), 0))
    if (flags.includes('c')) vals.push(lines.reduce((a, l) => a + l.length + 1, 0))
    return vals
  }
  const show = (vals: number[], name?: string) => (vals.length === 1 ? String(vals[0]) : vals.map((v) => String(v).padStart(7)).join('')) + (name ? ` ${name}` : '')
  if (!files.length) return { out: [show(count(stdin ?? []))] }
  const out: string[] = []
  const err: string[] = []
  for (const f of files) {
    const r = readLines(ctx, 'wc', f)
    if (r.err) err.push(r.err)
    else out.push(show(count(r.lines!), f))
  }
  return done(out, err)
}

const nl: Command = (args, stdin, ctx) => {
  const { lines, err } = input(ctx, 'nl', args.filter((a) => !a.startsWith('-')), stdin)
  let n = 0
  return done(lines.map((l) => (l === '' ? '' : `${String(++n).padStart(6)}\t${l}`)), err)
}

function parseRanges(spec: string): (i: number) => boolean {
  const ranges = spec.split(',').map((part) => {
    const m = part.match(/^(\d*)(-?)(\d*)$/)
    if (!m) return [0, 0]
    const from = m[1] ? parseInt(m[1], 10) : 1
    const to = m[2] ? (m[3] ? parseInt(m[3], 10) : Infinity) : from
    return [from, to]
  })
  return (i) => ranges.some(([a, b]) => i >= a && i <= b)
}

const cut: Command = (args, stdin, ctx) => {
  let delim = '\t'
  let fields: string | null = null
  let chars: string | null = null
  const files: string[] = []
  for (let i = 0; i < args.length; i++) {
    const a = args[i]
    if (a.startsWith('-d')) delim = a.length > 2 ? a.slice(2) : args[++i] ?? '\t'
    else if (a.startsWith('-f')) fields = a.length > 2 ? a.slice(2) : args[++i] ?? ''
    else if (a.startsWith('-c')) chars = a.length > 2 ? a.slice(2) : args[++i] ?? ''
    else files.push(a)
  }
  if (fields === null && chars === null) return fail('cut: you must specify a list of bytes, characters, or fields')
  const { lines, err } = input(ctx, 'cut', files, stdin)
  const want = parseRanges((fields ?? chars)!)
  const out = lines.map((line) => {
    if (chars !== null) return [...line].filter((_, i) => want(i + 1)).join('')
    if (!line.includes(delim)) return line
    return line.split(delim).filter((_, i) => want(i + 1)).join(delim)
  })
  return done(out, err)
}

const sed: Command = (args, stdin, ctx) => {
  const quiet = args.includes('-n')
  const rest = args.filter((a) => a !== '-n' && a !== '-e')
  const script = rest[0] ?? ''
  const { lines, err } = input(ctx, 'sed', rest.slice(1), stdin)
  const print = script.match(/^(\d+)(?:,(\d+))?p$/)
  if (print) {
    const from = parseInt(print[1], 10)
    const to = print[2] ? parseInt(print[2], 10) : from
    const picked = lines.slice(from - 1, to)
    return done(quiet ? picked : lines.flatMap((l, i) => (i + 1 >= from && i + 1 <= to ? [l, l] : [l])), err)
  }
  const sub = script.match(/^s(.)(.*?)\1(.*?)\1([gi]*)$/)
  if (sub) {
    const re = new RegExp(toRegex(sub[2], 'basic'), sub[4])
    return done(quiet ? [] : lines.map((l) => l.replace(re, sub[3])), err)
  }
  return fail("sed: simulator hanya mendukung bentuk -n 'Np', -n 'N,Mp', dan 's/a/b/'")
}

// awk mini: [pola] [{ print ... }] dengan NR, NF, $N, /regex/, dan perbandingan sederhana.
function splitTop(s: string, sep: string): string[] {
  const parts: string[] = []
  let cur = ''
  let q = false
  let slash = false
  for (let i = 0; i < s.length; i++) {
    const c = s[i]
    if (c === '"' && !slash) q = !q
    else if (c === '/' && !q) slash = !slash
    if (!q && !slash && s.startsWith(sep, i)) {
      parts.push(cur)
      cur = ''
      i += sep.length - 1
    } else cur += c
  }
  parts.push(cur)
  return parts
}

const awk: Command = (args, stdin, ctx) => {
  let sep: string | null = null
  const rest: string[] = []
  for (let i = 0; i < args.length; i++) {
    const a = args[i]
    if (a.startsWith('-F')) sep = a.length > 2 ? a.slice(2) : args[++i] ?? null
    else rest.push(a)
  }
  const program = rest[0]
  if (program === undefined) return fail("usage: awk [-F pemisah] 'pola { print ... }' [berkas]")
  const m = program.match(/^\s*([^{]*?)\s*(?:\{([\s\S]*)\}\s*)?$/)
  if (!m) return fail('awk: sintaks ini belum didukung simulator')
  const pattern = m[1]
  const action = (m[2] ?? 'print $0').trim().replace(/;$/, '').trim() || 'print $0'
  if (!/^print\b/.test(action)) return fail('awk: simulator hanya mendukung aksi `print`')
  const items = action.slice(5).trim() ? splitTop(action.slice(5).trim(), ',') : ['$0']
  const { lines, err } = input(ctx, 'awk', rest.slice(1), stdin)
  const split = (line: string) => {
    if (sep === null || sep === ' ') return line.trim() ? line.trim().split(/\s+/) : []
    if (sep === '\\t' || sep === 't') return line.split('\t')
    return sep.length === 1 ? line.split(sep) : line.split(new RegExp(sep))
  }
  const out: string[] = []
  let bad = false
  lines.forEach((line, idx) => {
    const f = split(line)
    const atom = (tok: string): string => {
      const t = tok.trim()
      if (t === '$0') return line
      if (t === '$NF') return f[f.length - 1] ?? ''
      if (/^\$\d+$/.test(t)) return f[parseInt(t.slice(1), 10) - 1] ?? ''
      if (t === 'NR') return String(idx + 1)
      if (t === 'NF') return String(f.length)
      if (/^".*"$/.test(t)) return t.slice(1, -1).replace(/\\t/g, '\t')
      if (/^-?\d+(\.\d+)?$/.test(t)) return t
      bad = true
      return ''
    }
    const value = (expr: string) => (expr.match(/"[^"]*"|\$NF|\$\d+|NR|NF|-?\d+(?:\.\d+)?|\S+/g) ?? []).map(atom).join('')
    const cond = (c: string): boolean => {
      const t = c.trim()
      if (!t) return true
      const re = t.match(/^(?:(\$\w+)\s*(!?~)\s*)?\/(.*)\/$/)
      if (re) {
        const hit = new RegExp(re[3]).test(re[1] ? atom(re[1]) : line)
        return re[2] === '!~' ? !hit : hit
      }
      const cmp = t.match(/^(.+?)\s*(==|!=|<=|>=|<|>)\s*(.+)$/)
      if (cmp) {
        const a = value(cmp[1])
        const b = value(cmp[3])
        const numeric = a !== '' && b !== '' && !Number.isNaN(Number(a)) && !Number.isNaN(Number(b))
        const [x, y] = numeric ? [Number(a), Number(b)] : [a, b]
        switch (cmp[2]) {
          case '==': return x === y
          case '!=': return x !== y
          case '<': return x < y
          case '>': return x > y
          case '<=': return x <= y
          default: return x >= y
        }
      }
      const v = value(t)
      return v !== '' && v !== '0'
    }
    const matches = splitTop(pattern, '||').some((or) => splitTop(or, '&&').every(cond))
    if (matches) out.push(items.map(value).join(' '))
  })
  if (bad) return fail('awk: ada bagian program yang belum didukung simulator')
  return done(out, err)
}

const column: Command = (args, stdin, ctx) => {
  let sep: string | null = null
  const files: string[] = []
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '-s') sep = args[++i] ?? null
    else if (!args[i].startsWith('-')) files.push(args[i])
  }
  const { lines, err } = input(ctx, 'column', files, stdin)
  if (!args.includes('-t')) return done(lines, err)
  const rows = lines.map((l) => (sep ? l.split(sep) : l.trim().split(/\s+/)))
  const widths: number[] = []
  for (const r of rows) r.forEach((c, i) => (widths[i] = Math.max(widths[i] ?? 0, c.length)))
  return done(rows.map((r) => r.map((c, i) => (i === r.length - 1 ? c : c.padEnd(widths[i] + 2))).join('')), err)
}

const passthrough = (name: string): Command => (args, stdin, ctx) => {
  const { lines, err } = input(ctx, name, args.filter((a) => !a.startsWith('-')), stdin)
  return done(lines, err)
}

const zeekCut: Command = (args, stdin) => {
  const keepHeader = args.includes('-c') || args.includes('-C')
  const wanted = args.filter((a) => !a.startsWith('-'))
  const out: string[] = []
  let fields: string[] = []
  for (const line of stdin ?? []) {
    if (line.startsWith('#')) {
      if (line.startsWith('#fields')) fields = line.split('\t').slice(1)
      if (keepHeader) {
        if (line.startsWith('#fields') || line.startsWith('#types')) {
          const [tag, ...cols] = line.split('\t')
          out.push([tag, ...(wanted.length ? wanted.map((w) => cols[fields.indexOf(w)] ?? '') : cols)].join('\t'))
        } else out.push(line)
      }
      continue
    }
    const cols = line.split('\t')
    out.push(wanted.length ? wanted.map((w) => cols[fields.indexOf(w)] ?? '').join('\t') : line)
  }
  if (stdin === null) return fail('zeek-cut: tidak ada masukan. Contoh: cat conn.log | zeek-cut uid id.orig_h')
  return { out }
}

// ---------- lain-lain ----------

const HELP = [
  'Perintah yang tersedia di terminal simulasi:',
  '',
  '  Navigasi   ls [-la]  cd  pwd  file  rm  ./clear-logs.sh',
  '  Baca       cat  head  tail  less',
  '  Olah teks  grep  sort  uniq  wc  nl  cut  sed -n  awk  rev  tac  column -t  base64 -d',
  '  Zeek       zeek -C -r <pcap> [-s <sig>] [script...]   zeek -v',
  '             zeek-cut <field...>   zeekctl status|start|stop   zkg list',
  '  Sesi       sudo su  exit  history  clear  help',
  '',
  'Perintah bisa dirangkai dengan pipe, misalnya:',
  '  cat conn.log | zeek-cut id.orig_h | sort | uniq -c | sort -nr',
  '',
  'Tab melengkapi nama berkas, panah atas/bawah membuka riwayat perintah.',
  'Ini simulator: log sudah disiapkan, Zeek tidak benar-benar membaca pcap.',
]

const noEditor: Command = () =>
  fail('Simulator tidak punya editor teks. Berkas signature dan script untuk latihan sudah tersedia di folder ini, lihat dengan `ls` dan `cat`.')
const notHere = (name: string): Command => () => fail(`${name}: tidak tersedia di simulator. Di sini kita fokus mengolah log Zeek.`)

export const COMMANDS: Record<string, Command> = {
  ls, cd, cat, head, tail, rm, file, grep, sort, uniq, wc, nl, cut, sed, awk, column,
  'zeek-cut': zeekCut,
  zeek, zeekctl, zkg,
  'clear-logs': clearLogs,
  less: passthrough('less'),
  more: passthrough('more'),
  egrep: (args, stdin, ctx) => grep(['-E', ...args], stdin, ctx),
  rev: (args, stdin, ctx) => {
    const { lines, err } = input(ctx, 'rev', args, stdin)
    return done(lines.map((l) => [...l].reverse().join('')), err)
  },
  tac: (args, stdin, ctx) => {
    const { lines, err } = input(ctx, 'tac', args, stdin)
    return done([...lines].reverse(), err)
  },
  base64: (args, stdin, ctx) => {
    const decode = args.some((a) => a === '-d' || a === '--decode' || a === '-D')
    const { lines, err } = input(ctx, 'base64', args.filter((a) => !a.startsWith('-')), stdin)
    if (err.length) return done([], err)
    try {
      if (!decode) return { out: [globalThis.btoa(lines.join('\n') + '\n')] }
      const text = lines.map((l) => globalThis.atob(l.trim())).join('')
      return { out: toLines(text) }
    } catch {
      return fail('base64: invalid input')
    }
  },
  pwd: (_a, _s, ctx) => ({ out: [ctx.cwd] }),
  whoami: (_a, _s, ctx) => ({ out: [ctx.user] }),
  hostname: () => ({ out: ['trylearnme'] }),
  echo: (args) => ({ out: [args.join(' ')] }),
  clear: () => ({ out: [], clear: true }),
  history: (_a, _s, ctx) => ({ out: ctx.history.map((h, i) => `${String(i + 1).padStart(5)}  ${h}`) }),
  help: () => ({ out: HELP }),
  man: () => ({ out: HELP }),
  mkdir: (args, _s, ctx) => {
    for (const a of args.filter((x) => !x.startsWith('-'))) ctx.fs.mkdirp(ctx.fs.resolve(a, ctx.cwd))
    return { out: [] }
  },
  nano: noEditor, vim: noEditor, vi: noEditor, pluma: noEditor, gedit: noEditor,
  tcpdump: notHere('tcpdump'), tshark: notHere('tshark'), wireshark: notHere('wireshark'),
}

export { basename }
