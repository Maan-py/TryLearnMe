// Perintah zeek, zeekctl, dan zkg versi simulasi.

import type { Command, Result } from './shell'
import { basename } from './vfs'
import { SCENARIOS, loadedScriptsLog, captureLossLog, statsLog, noticeLog } from './data/scenarios'
import type { Conn } from './data/gen'

const fail = (...err: string[]): Result => ({ out: [], err, fail: true })

/** Nama script -> efek yang ditimbulkannya pada hasil analisis. */
const SCRIPT_FX: Record<string, string> = {
  '101.zeek': '101',
  '102.zeek': '102',
  '103.zeek': '103',
  '201.zeek': '201',
  'dhcp-hostname.zeek': 'dhcphost',
  'hash-demo.zeek': 'hash',
  'hash-all-files.zeek': 'hash',
  'file-extract-demo.zeek': 'extract',
  'extract-all-files.zeek': 'extract',
  'intelligence-demo.zeek': 'intel',
  'sniff-demo.zeek': 'sniffpass',
  'zeek-sniffpass': 'sniffpass',
  'geoip-conn': 'geoip',
  'sumstats-counttable.zeek': 'sumstats',
  'detect-bruteforcing.zeek': 'bruteforce',
  'detection-log4j.zeek': 'log4j',
  local: 'local',
  'local.zeek': 'local',
}

/** Nama yang boleh dipanggil tanpa path (base script dan paket zkg). */
const BARE_NAMES = new Set(['local', 'zeek-sniffpass', 'geoip-conn'])

function connRecord(c: Conn): string {
  return (
    `[id=[orig_h=${c.oh}, orig_p=${c.op}/${c.proto}, resp_h=${c.rh}, resp_p=${c.rp}/${c.proto}], ` +
    `orig=[size=${c.ob === '-' ? 0 : c.ob}, state=1, num_pkts=0, num_bytes_ip=0, flow_label=0, l2_addr=00:16:47:df:e7:c1], ` +
    `resp=[size=0, state=0, num_pkts=0, num_bytes_ip=0, flow_label=0, l2_addr=00:00:0c:9f:f0:79], ` +
    `start_time=${c.ts.toFixed(6)}, duration=0 secs, service={}, history=, uid=${c.uid}, tunnel=<uninitialized>, vlan=121, ` +
    `inner_vlan=<uninitialized>, dpd=<uninitialized>, conn=<uninitialized>, extract_orig=F, extract_resp=F, thresholds=<uninitialized>, ` +
    `dhcp=<uninitialized>, dns=<uninitialized>, ftp=<uninitialized>, http=<uninitialized>, ntp=<uninitialized>, ssh=<uninitialized>, syslog=<uninitialized>]`
  )
}

export const zeek: Command = (args, _stdin, ctx) => {
  if (args.includes('-v') || args.includes('--version')) return { out: ['zeek version 4.2.1'] }
  let pcap: string | null = null
  const sigArgs: string[] = []
  const scriptArgs: string[] = []
  for (let i = 0; i < args.length; i++) {
    const a = args[i]
    if (a.startsWith('-') && a.length > 1) {
      for (const flag of a.slice(1)) {
        if (flag === 'r') pcap = args[++i] ?? ''
        else if (flag === 's') sigArgs.push(args[++i] ?? '')
        else if (flag === 'i') return fail('zeek: simulator tidak bisa menyadap antarmuka jaringan. Pakai mode baca pcap: zeek -C -r <berkas.pcap>')
        else if (flag !== 'C') return fail(`zeek: opsi -${flag} tidak didukung simulator (yang ada: -C, -r, -s, -v)`)
      }
    } else scriptArgs.push(a)
  }
  if (pcap === null) return fail('zeek: tentukan pcap yang dibaca, misalnya: zeek -C -r sample.pcap')

  const { fs, cwd } = ctx
  const pcapNode = fs.get(fs.resolve(pcap, cwd))
  if (!pcapNode || pcapNode.type !== 'file') return fail(`fatal error: problem with trace file ${pcap} (No such file or directory)`)
  const scenario = SCENARIOS[basename(pcap)]
  if (pcapNode.kind !== 'pcap' || !scenario) return fail(`fatal error: problem with trace file ${pcap} (unknown file format)`)

  const sigs = new Set<string>()
  for (const s of sigArgs) {
    if (fs.get(fs.resolve(s, cwd))?.type !== 'file') return fail(`fatal error: can't find signature file ${s}`)
    sigs.add(basename(s))
  }
  const fx = new Set<string>()
  for (const s of scriptArgs) {
    const known = SCRIPT_FX[basename(s)]
    if (!(BARE_NAMES.has(s) && known)) {
      if (!fs.get(fs.resolve(s, cwd))) return fail(`fatal error: can't find ${s}`)
    }
    if (known) fx.add(known)
  }

  const conns = scenario.conns()
  const run = scenario.run(fx, sigs)
  const files = { ...run.files }
  if (run.notices?.length) files['notice.log'] = noticeLog(run.notices)
  if (fx.has('local')) {
    files['loaded_scripts.log'] = loadedScriptsLog()
    files['capture_loss.log'] = captureLossLog(conns[conns.length - 1].ts)
    files['stats.log'] = statsLog(conns[conns.length - 1].ts, conns.length)
  }
  for (const [name, content] of Object.entries(files)) fs.write(`${cwd}/${name}`, content)
  for (const [dir, entries] of Object.entries(run.dirs ?? {})) {
    for (const [name, f] of Object.entries(entries)) fs.write(`${cwd}/${dir}/${name}`, f.content, f.kind)
  }

  const out: string[] = []
  if (fx.has('101')) out.push('Started Zeek!')
  out.push(...run.stdout)
  if (fx.has('102')) out.push(...conns.map(connRecord))
  if (fx.has('103')) {
    for (const c of conns) {
      out.push(
        '###########################################################',
        `New Connection Found! Source Host: ${c.oh} # ${c.op}/${c.proto} --->`,
        `Destination Host: resp: ${c.rh} # ${c.rp}/${c.proto} <---`,
      )
    }
  }
  if (fx.has('101')) out.push('Stopped Zeek!')
  return { out }
}

export const zeekctl: Command = (args, _stdin, ctx) => {
  const sub = args[0]
  if (!sub) {
    return {
      out: [
        '', 'Welcome to ZeekControl 2.4.0', '', 'Type "help" for help.', '',
        '(Simulator: mode interaktif tidak tersedia. Jalankan langsung `zeekctl status`, `zeekctl start`, atau `zeekctl stop`.)',
      ],
    }
  }
  if (!['status', 'start', 'stop', 'deploy'].includes(sub)) return fail(`zeekctl: perintah "${sub}" tidak didukung simulator (yang ada: status, start, stop, deploy)`)
  if (ctx.user !== 'root') return fail('Error: zeekctl butuh hak superuser. Jalankan `sudo su` dulu, atau awali dengan `sudo`.')
  const status = () => [
    'Name         Type       Host          Status    Pid    Started',
    ctx.state.zeekRunning ? 'zeek         standalone localhost     running   2541   09 Nov 05:47:06' : 'zeek         standalone localhost     stopped',
  ]
  if (sub === 'status') return { out: status() }
  if (sub === 'stop') {
    ctx.state.zeekRunning = false
    return { out: ['stopping zeek ...'] }
  }
  ctx.state.zeekRunning = true
  return { out: sub === 'deploy' ? ['checking configurations ...', 'installing ...', 'starting zeek ...'] : ['starting zeek ...'] }
}

const PACKAGES = [
  'zeek/cybera/zeek-sniffpass (installed: master) - Sniffpass will alert on cleartext passwords discovered in HTTP POST requests',
  'zeek/brimsec/geoip-conn (installed: master) - Add geolocation fields to the conn log',
]

export const zkg: Command = (args) => {
  const [sub, target] = args
  switch (sub) {
    case 'list':
      return { out: PACKAGES }
    case 'install':
      if (!target) return fail('usage: zkg install <paket | git_url>')
      return PACKAGES.some((p) => p.includes(basename(target)))
        ? { out: [`package "${target}" sudah terpasang di simulator. Lihat dengan \`zkg list\`.`] }
        : fail(`error: simulator tidak punya akses internet, jadi "${target}" tidak bisa dipasang. Paket latihan sudah terpasang, cek \`zkg list\`.`)
    case 'refresh':
      return { out: ['Refresh package source: zeek', '\tNo membership changes', 'Refresh installed packages', '\tNo new versions'] }
    case 'upgrade':
      return { out: ['All packages already up-to-date.'] }
    case 'remove':
      return fail('Simulator tidak menghapus paket, karena latihan di TASK-9 memerlukannya.')
    default:
      return fail('usage: zkg <list | install | remove | refresh | upgrade>')
  }
}
