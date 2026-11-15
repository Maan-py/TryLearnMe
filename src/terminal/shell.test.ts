import { describe, expect, it } from 'vitest'
import { Shell } from './shell'
import { EX } from './lab'

/** Jalankan beberapa perintah di satu folder task, kembalikan keluaran perintah terakhir. */
function sh(dir: string, ...cmds: string[]): string {
  const shell = new Shell(`${EX}/${dir}`)
  let last = ''
  for (const c of cmds) last = shell.run(c).text
  return last
}

describe('jawaban soal bisa diperoleh dari terminal', () => {
  it('Task 2', () => {
    expect(sh('TASK-2', 'zeek -v')).toBe('zeek version 4.2.1')
    expect(sh('TASK-2', 'zeekctl')).toContain('ZeekControl 2.4.0')
    expect(sh('TASK-2', 'zeek -C -r sample.pcap', 'ls *.log | wc -w')).toBe('8')
    expect(sh('TASK-2', 'sudo su', 'zeekctl start', 'zeekctl status')).toContain('running')
  })

  it('Task 3', () => {
    const z = 'zeek -C -r sample.pcap'
    expect(sh('TASK-3', z, 'cat dhcp.log | zeek-cut host_name')).toBe('Microknoppix')
    expect(sh('TASK-3', z, 'cat dns.log | zeek-cut query | sort | uniq | wc -l')).toBe('2')
    expect(sh('TASK-3', z, 'cat conn.log | zeek-cut duration | sort -n | tail -1')).toBe('332.319364')
    expect(sh('TASK-3', z, 'cat conn.log | zeek-cut duration | sort -nr | head -n 1')).toBe('332.319364')
  })

  it('Task 4', () => {
    expect(sh('TASK-4', "cat access.txt | cut -d ' ' -f 1 | sort | uniq | wc -l")).toBe('5')
    expect(sh('TASK-4', "cat access.txt | cut -d ' ' -f 1 | sort | uniq -c | sort -nr | head -1").trim()).toBe('7 10.0.0.12')
    expect(sh('TASK-4', "cat access.txt | sed -n '11p' | awk '{print $3}'")).toBe('/backup.zip')
    expect(sh('TASK-4', "cat access.txt | awk 'NR == 11 {print $3}'")).toBe('/backup.zip')
    expect(sh('TASK-4', 'grep -c 403 access.txt')).toBe('6')
  })

  it('Task 5', () => {
    const http = 'zeek -C -r http.pcap -s http-password.sig'
    expect(sh('TASK-5/http', http, 'cat signatures.log | zeek-cut src_addr | head -1')).toBe('10.10.57.178')
    expect(sh('TASK-5/http', http, "cat signatures.log | zeek-cut src_port | sed -n '2p'")).toBe('38712')
    expect(sh('TASK-5/http', http, 'cat conn.log | zeek-cut id.orig_p orig_pkts resp_pkts | grep 38706')).toBe('38706\t11\t9')
    expect(sh('TASK-5/http', http, 'cat notice.log | zeek-cut msg | head -1')).toBe('10.10.57.178: Cleartext Password Found!')
    const ftp = 'zeek -C -r ftp.pcap -s ftp-bruteforce.sig'
    expect(sh('TASK-5/ftp', ftp, 'cat notice.log | zeek-cut uid | sort | uniq | wc -l')).toBe('1413')
    expect(sh('TASK-5/ftp', ftp, 'cat notice.log | zeek-cut msg | grep -i brute | wc -l')).toBe('1410')
  })

  it('Task 6', () => {
    expect(sh('TASK-6/smallflow', 'zeek -C -r smallFlows.pcap', 'cat dhcp.log | zeek-cut host_name domain | grep vinlap01')).toBe('vinlap01\tastaro_vineyard')
    expect(sh('TASK-6/smallflow', 'zeek -C -r smallFlows.pcap dhcp-hostname.zeek')).toBe('student01-PC\nvinlap01')
    const big = 'zeek -C -r bigFlows.pcap'
    expect(sh('TASK-6/bigflow', big, 'cat dhcp.log | zeek-cut host_name | sort | uniq | wc -l')).toBe('17')
    expect(sh('TASK-6/bigflow', big, 'cat dhcp.log | zeek-cut domain | sort | uniq')).toBe('jaalam.net')
    expect(sh('TASK-6/bigflow', big, "cat dns.log | zeek-cut query | grep -v -e '*' -e '-' | sort | uniq | wc -l")).toBe('1109')
    expect(sh('TASK-6/bigflow', big, 'cat dns.log | zeek-cut query | sort -u | wc -l')).toBe('1111')
  })

  it('Task 7', () => {
    expect(sh('TASK-7/101', 'zeek -C -r sample.pcap 101.zeek')).toBe('Started Zeek!\nStopped Zeek!')
    expect(sh('TASK-7/101', 'zeek -C -r sample.pcap 103.zeek | grep "New Connection" | wc -l')).toBe('87')
    const z = 'zeek -C -r ftp.pcap -s ftp-admin.sig 201.zeek'
    expect(sh('TASK-7/201', z).split('\n')[0]).toBe('Signature hit! --> #FTP-Admin')
    expect(sh('TASK-7/201', z, 'cat signatures.log | zeek-cut uid | wc -l')).toBe('1401')
    expect(sh('TASK-7/201', z, 'cat signatures.log | zeek-cut sub_msg | grep -i administrator | wc -l')).toBe('731')
    expect(sh('TASK-7/201', 'zeek -C -r ftp.pcap local', 'cat loaded_scripts.log | zeek-cut name | wc -l')).toBe('498')
    expect(sh('TASK-7/202', 'zeek -C -r ftp-brute.pcap /opt/zeek/share/zeek/policy/protocols/ftp/detect-bruteforcing.zeek', 'cat notice.log | zeek-cut note | wc -l')).toBe('2')
  })

  it('Task 8', () => {
    expect(sh('TASK-8', 'zeek -C -r case1.pcap intelligence-demo.zeek', "cat intel.log | zeek-cut seen.where | sed -n '2p'")).toBe('HTTP::IN_HOST_HEADER')
    expect(sh('TASK-8', 'zeek -C -r case1.pcap', 'cat http.log | zeek-cut uri | grep exe')).toBe('/knr.exe')
    expect(sh('TASK-8', 'zeek -C -r case1.pcap hash-demo.zeek', 'cat files.log | zeek-cut mime_type md5 | grep dosexec')).toBe('application/x-dosexec\tcc28e40b46237ab6d5282199ef78c464')
    expect(sh('TASK-8', 'zeek -C -r case1.pcap', 'cat files.log | zeek-cut md5 | sort -u')).toBe('-')
    const ex = 'zeek -C -r case1.pcap file-extract-demo.zeek'
    expect(sh('TASK-8', ex, 'ls extract_files | wc -w')).toBe('3')
    expect(sh('TASK-8', ex, 'cd extract_files', 'cat extract-1561667874.743959-HTTP-Fpgan59p6uvNzLFja')).toBe('Microsoft NCSI')
    expect(sh('TASK-8', ex, 'cd extract_files', 'file * | nl')).toContain('PE32 executable')
    expect(sh('TASK-8', ex, 'file extract_files/* | grep ASCII')).toContain('Fpgan59p6uvNzLFja')
    expect(sh('TASK-8', ex, 'grep -rin CZruIO2cqspVhLuAO9 * | column -t | nl | less -S').split('\n')).toHaveLength(3)
  })

  it('Task 9', () => {
    const sniff = "cat notice.log | zeek-cut msg | sort | uniq -c | sort -nr | head -1"
    expect(sh('TASK-9/cleartext-pass', 'zeek -Cr http.pcap zeek-sniffpass', sniff).trim()).toBe('2 Password found for user BroZeek')
    expect(sh('TASK-9/cleartext-pass', 'zeek -Cr http.pcap sniff-demo.zeek', sniff).trim()).toBe('2 Password found for user BroZeek')
    expect(sh('TASK-9/cleartext-pass', 'zeek -Cr http.pcap /opt/zeek/share/zeek/site/zeek-sniffpass', sniff)).toContain('BroZeek')
    const geo = 'zeek -Cr case2.pcap geoip-conn'
    expect(sh('TASK-9/geoip-conn', geo, "cat conn.log | zeek-cut geo.resp.city id.resp_h | grep -v '^-' | sort | uniq")).toBe('Chicago\t23.77.86.54')
    expect(sh('TASK-9/geoip-conn', 'zeek -Cr case2.pcap sumstats-counttable.zeek | grep "status code" | cut -d , -f 1 | sort -u | wc -l')).toBe('4')
    expect(sh('TASK-9/geoip-conn', 'zkg list')).toContain('zeek-sniffpass')
  })
})

describe('perilaku shell', () => {
  it('pesan galat dan pembersihan log', () => {
    expect(sh('TASK-2', 'zeek -C -r tidakada.pcap')).toContain('No such file')
    expect(sh('TASK-2', 'foo')).toContain('command not found')
    expect(sh('TASK-2', 'zeek -C -r sample.pcap', './clear-logs.sh', 'ls')).toBe('clear-logs.sh  sample.pcap')
    expect(sh('TASK-2', 'cat sample.pcap')).toContain('berkas biner')
  })

  it('cd, pwd, prompt, pelengkap Tab', () => {
    const shell = new Shell()
    expect(shell.prompt()).toBe('ubuntu@trylearnme:~$')
    shell.run('cd Desktop/Exercise-Files/TASK-5/http')
    expect(shell.prompt()).toBe('ubuntu@trylearnme:~/Desktop/Exercise-Files/TASK-5/http$')
    expect(shell.complete('cat http-')).toBe('cat http-password.sig ')
    expect(shell.complete('zeek-')).toBe('zeek-cut ')
    expect(shell.run('cd .. && pwd').text).toBe('/home/ubuntu/Desktop/Exercise-Files/TASK-5')
    expect(shell.run('echo halo > a.txt; cat a.txt').text).toBe('halo')
  })

  it('uniq -c, sort -k, awk, head', () => {
    expect(sh('TASK-4', "awk '$4 == 404 {print $1, $3}' access.txt | head -2")).toBe('10.0.0.23 /robots.txt\n10.0.0.8 /backup.zip')
    expect(sh('TASK-4', "cat access.txt | awk '{print $4}' | sort | uniq -c | sort -k1 -nr | head -1").trim()).toBe('9 200')
    expect(sh('TASK-4', 'cat access.txt | wc -l')).toBe('20')
    expect(sh('TASK-4', "grep -v -e 200 -e 403 access.txt | wc -l")).toBe('5')
  })
})
