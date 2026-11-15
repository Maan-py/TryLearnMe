// Sistem berkas tiruan yang hidup di memori browser.

export type FileKind = 'text' | 'pcap' | 'doc' | 'exe'

export interface FileNode {
  type: 'file'
  content: string | (() => string)
  kind: FileKind
  exec?: boolean
}

export interface DirNode {
  type: 'dir'
  children: Map<string, VNode>
}

export type VNode = FileNode | DirNode

export const HOME = '/home/ubuntu'

export class VFS {
  root: DirNode = { type: 'dir', children: new Map() }

  /** Ubah path relatif/`~` menjadi path absolut yang sudah dirapikan. */
  resolve(path: string, cwd: string): string {
    let p = path
    if (p === '~' || p.startsWith('~/')) p = HOME + p.slice(1)
    if (!p.startsWith('/')) p = cwd + '/' + p
    const out: string[] = []
    for (const part of p.split('/')) {
      if (!part || part === '.') continue
      if (part === '..') out.pop()
      else out.push(part)
    }
    return '/' + out.join('/')
  }

  get(abs: string): VNode | undefined {
    let node: VNode = this.root
    for (const part of abs.split('/')) {
      if (!part) continue
      if (node.type !== 'dir') return undefined
      const next = node.children.get(part)
      if (!next) return undefined
      node = next
    }
    return node
  }

  mkdirp(abs: string): DirNode {
    let node: DirNode = this.root
    for (const part of abs.split('/')) {
      if (!part) continue
      let next = node.children.get(part)
      if (!next) {
        next = { type: 'dir', children: new Map() }
        node.children.set(part, next)
      }
      if (next.type !== 'dir') throw new Error(`${abs}: bukan direktori`)
      node = next
    }
    return node
  }

  write(abs: string, content: string | (() => string), kind: FileKind = 'text', exec = false) {
    const i = abs.lastIndexOf('/')
    const dir = this.mkdirp(abs.slice(0, i) || '/')
    dir.children.set(abs.slice(i + 1), { type: 'file', content, kind, exec })
  }

  remove(abs: string): boolean {
    const i = abs.lastIndexOf('/')
    const dir = this.get(abs.slice(0, i) || '/')
    if (!dir || dir.type !== 'dir') return false
    return dir.children.delete(abs.slice(i + 1))
  }

  /** Isi berkas; konten yang dibuat belakangan (lazy) disimpan setelah dipakai pertama kali. */
  read(node: FileNode): string {
    if (typeof node.content === 'function') node.content = node.content()
    return node.content
  }
}

export function toLines(text: string): string[] {
  if (text === '') return []
  const lines = text.split('\n')
  if (lines[lines.length - 1] === '') lines.pop()
  return lines
}

export function basename(path: string): string {
  const p = path.replace(/\/+$/, '')
  return p.slice(p.lastIndexOf('/') + 1)
}
