// Alat bantu pembuat data log tiruan. Semua acak-nya deterministik (seed tetap),
// supaya isi log dan jawaban soal selalu sama setiap kali website dibuka.

export type Rng = () => number

export function rng(seed: number): Rng {
  let a = seed >>> 0
  return () => {
    a = (a + 0x6d2b79f5) | 0
    let t = Math.imul(a ^ (a >>> 15), 1 | a)
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
  }
}

const B62 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'

export function uid(r: Rng, prefix = 'C'): string {
  let s = prefix
  for (let i = 0; i < 17; i++) s += B62[Math.floor(r() * 62)]
  return s
}

export const int = (r: Rng, min: number, max: number) => min + Math.floor(r() * (max - min + 1))
export const pick = <T>(r: Rng, arr: readonly T[]): T => arr[Math.floor(r() * arr.length)]

export function shuffle<T>(r: Rng, arr: T[]): T[] {
  for (let i = arr.length - 1; i > 0; i--) {
    const j = Math.floor(r() * (i + 1))
    ;[arr[i], arr[j]] = [arr[j], arr[i]]
  }
  return arr
}

export function memo<T>(fn: () => T): () => T {
  let v: T | undefined
  let done = false
  return () => {
    if (!done) {
      v = fn()
      done = true
    }
    return v as T
  }
}

export type Cell = string | number

/** Susun berkas log dengan format TSV asli Zeek (header #fields, #types, dst.). */
export function zlog(path: string, fields: string, types: string, rows: Cell[][], open = '2022-11-09-05-55-48'): string {
  const head = [
    '#separator \\x09',
    '#set_separator\t,',
    '#empty_field\t(empty)',
    '#unset_field\t-',
    `#path\t${path}`,
    `#open\t${open}`,
    '#fields\t' + fields.trim().split(/\s+/).join('\t'),
    '#types\t' + types.trim().split(/\s+/).join('\t'),
  ]
  const body = rows.map((r) => r.join('\t'))
  return [...head, ...body, `#close\t${open}`].join('\n') + '\n'
}

export const ts = (n: number) => n.toFixed(6)

// ---------- conn.log ----------

export interface Conn {
  ts: number
  uid: string
  oh: string
  op: number
  rh: string
  rp: number
  proto: string
  service: string
  dur: string
  ob: Cell
  rb: Cell
  state: string
  hist: string
  opk: number
  rpk: number
}

export const CONN_FIELDS =
  'ts uid id.orig_h id.orig_p id.resp_h id.resp_p proto service duration orig_bytes resp_bytes conn_state local_orig local_resp missed_bytes history orig_pkts orig_ip_bytes resp_pkts resp_ip_bytes tunnel_parents'
export const CONN_TYPES =
  'time string addr port addr port enum string interval count count string bool bool count string count count count count set[string]'

export function connRow(c: Conn): Cell[] {
  const hdr = c.proto === 'tcp' ? 52 : 28
  const oip = c.ob === '-' ? c.opk * hdr : Number(c.ob) + c.opk * hdr
  const rip = c.rb === '-' ? c.rpk * hdr : Number(c.rb) + c.rpk * hdr
  return [ts(c.ts), c.uid, c.oh, c.op, c.rh, c.rp, c.proto, c.service, c.dur, c.ob, c.rb, c.state, '-', '-', 0, c.hist, c.opk, oip, c.rpk, rip, '-']
}

export const connLog = (conns: Conn[], open?: string) => zlog('conn', CONN_FIELDS, CONN_TYPES, conns.map(connRow), open)

// ---------- notice.log & signatures.log ----------

export const NOTICE_FIELDS =
  'ts uid id.orig_h id.orig_p id.resp_h id.resp_p fuid file_mime_type file_desc proto note msg sub src dst p n peer_descr actions email_dest suppress_for remote_location.country_code remote_location.region remote_location.city remote_location.latitude remote_location.longitude'
export const NOTICE_TYPES =
  'time string addr port addr port string string string enum enum string string addr addr port count string set[enum] set[string] interval string string string double double'

export interface Notice {
  ts: number
  uid?: string
  oh?: string
  op?: Cell
  rh?: string
  rp?: Cell
  proto?: string
  note: string
  msg: string
  sub?: string
  src?: string
  dst?: string
  p?: Cell
}

export function noticeLog(rows: Notice[], open?: string): string {
  return zlog(
    'notice',
    NOTICE_FIELDS,
    NOTICE_TYPES,
    rows.map((n) => [
      ts(n.ts), n.uid ?? '-', n.oh ?? '-', n.op ?? '-', n.rh ?? '-', n.rp ?? '-', '-', '-', '-', n.proto ?? '-',
      n.note, n.msg, n.sub ?? '-', n.src ?? '-', n.dst ?? '-', n.p ?? '-', '-', '-', 'Notice::ACTION_LOG', '(empty)',
      '3600.000000', '-', '-', '-', '-', '-',
    ]),
    open,
  )
}

export interface SigHit {
  ts: number
  uid: string
  src: string
  sport: number
  dst: string
  dport: number
  sig: string
  msg: string
  sub: string
}

export function signaturesLog(rows: SigHit[], open?: string): string {
  return zlog(
    'signatures',
    'ts uid src_addr src_port dst_addr dst_port note sig_id event_msg sub_msg sig_count host_count',
    'time string addr port addr port enum string string string count count',
    rows.map((s) => [ts(s.ts), s.uid, s.src, s.sport, s.dst, s.dport, 'Signatures::Sensitive_Signature', s.sig, s.msg, s.sub, '-', '-']),
    open,
  )
}

/** Notice yang ikut dibuat Zeek untuk setiap signature yang cocok. */
export const sigNotice = (s: SigHit): Notice => ({
  ts: s.ts, uid: s.uid, oh: s.src, op: s.sport, rh: s.dst, rp: s.dport, proto: 'tcp',
  note: 'Signatures::Sensitive_Signature', msg: s.msg, sub: s.sub, src: s.src, dst: s.dst, p: s.dport,
})

export const packetFilterLog = (t: number, open?: string) =>
  zlog('packet_filter', 'ts node filter init success', 'time string string bool bool', [[ts(t), 'zeek', 'ip or not ip', 'T', 'T']], open)

export const DNS_FIELDS =
  'ts uid id.orig_h id.orig_p id.resp_h id.resp_p proto trans_id rtt query qclass qclass_name qtype qtype_name rcode rcode_name AA TC RD RA Z answers TTLs rejected'
export const DNS_TYPES =
  'time string addr port addr port enum count interval string count string count string count string bool bool bool bool count vector[string] vector[interval] bool'

export function dnsRow(r: Rng, t: number, oh: string, rh: string, query: string, answer = '-'): Cell[] {
  const ok = query !== '-' && query !== '*'
  return [
    ts(t), uid(r), oh, int(r, 1025, 65000), rh, 53, 'udp', int(r, 1, 65535), ok ? (r() * 0.2).toFixed(6) : '-', query,
    ok ? 1 : '-', ok ? 'C_INTERNET' : '-', ok ? 1 : '-', ok ? 'A' : '-', ok ? 0 : '-', ok ? 'NOERROR' : '-',
    'F', 'F', 'T', ok ? 'T' : 'F', 0, answer, answer === '-' ? '-' : '3600.000000', 'F',
  ]
}

export const DHCP_FIELDS =
  'ts uids client_addr server_addr mac host_name client_fqdn domain requested_addr assigned_addr lease_time client_message server_message msg_types duration'
export const DHCP_TYPES =
  'time set[string] addr addr string string string string addr addr interval string string vector[string] interval'

export function dhcpRow(r: Rng, t: number, client: string, server: string, host: string, domain: string): Cell[] {
  const mac = Array.from({ length: 6 }, () => int(r, 0, 255).toString(16).padStart(2, '0')).join(':')
  return [ts(t), uid(r), client, server, mac, host, '-', domain, '-', client, '3600.000000', '-', '-', 'REQUEST,ACK', (r() * 0.05).toFixed(6)]
}
