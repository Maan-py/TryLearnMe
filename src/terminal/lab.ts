// Isi awal "mesin" latihan: folder Exercise-Files dan sebagian /opt/zeek.

import { VFS, HOME } from './vfs'

export const EX = `${HOME}/Desktop/Exercise-Files`

const CLEAR_LOGS = '#!/bin/bash\n# Hapus semua log hasil Zeek di folder ini.\nrm -rf *.log extract_files\n'

const ACCESS_TXT = `10.0.0.5 GET /index.html 200
10.0.0.8 GET /login 200
10.0.0.5 POST /login 302
10.0.0.12 GET /admin 403
10.0.0.8 GET /index.html 200
10.0.0.23 GET /robots.txt 404
10.0.0.5 GET /dashboard 200
10.0.0.12 GET /admin 403
10.0.0.31 GET /index.html 200
10.0.0.12 POST /admin 403
10.0.0.8 GET /backup.zip 404
10.0.0.12 GET /admin/config 403
10.0.0.5 GET /logout 302
10.0.0.23 GET /index.html 200
10.0.0.12 GET /admin 403
10.0.0.31 GET /about 200
10.0.0.12 GET /.env 404
10.0.0.8 GET /index.html 200
10.0.0.12 GET /admin 403
10.0.0.5 GET /index.html 200
`

export const SIG_HTTP_PASSWORD = `signature http-password {
     ip-proto == tcp
     dst-port == 80
     payload /.*password.*/
     event "Cleartext Password Found!"
}
`

export const SIG_FTP_ADMIN = `signature ftp-admin {
     ip-proto == tcp
     ftp /.*USER.*dmin.*/
     event "FTP Admin Login Attempt!"
}
`

export const SIG_FTP_BRUTE = `signature ftp-username {
    ip-proto == tcp
    ftp /.*USER.*/
    event "FTP Username Input Found!"
}

signature ftp-brute {
    ip-proto == tcp
    payload /.*530.*Login.*incorrect.*/
    event "FTP Brute-force Attempt!"
}
`

export const ZEEK_101 = `event zeek_init()
    {
    print ("Started Zeek!");
    }

event zeek_done()
    {
    print ("Stopped Zeek!");
    }
`

export const ZEEK_102 = `event new_connection(c: connection)
    {
    print c;
    }
`

export const ZEEK_103 = `event new_connection(c: connection)
    {
    print ("###########################################################");
    print fmt ("New Connection Found! Source Host: %s # %s --->", c$id$orig_h, c$id$orig_p);
    print fmt ("Destination Host: resp: %s # %s <---", c$id$resp_h, c$id$resp_p);
    }
`

export const ZEEK_201 = `event signature_match (state: signature_state, msg: string, data: string)
    {
    if (state$sig_id == "ftp-admin")
        {
        print ("Signature hit! --> #FTP-Admin");
        }
    }
`

export const ZEEK_DHCP = `event dhcp_message (c: connection, is_orig: bool, msg: DHCP::Msg, options: DHCP::Options)
    {
    print options$host_name;
    }
`

export const ZEEK_HASH_ALL = `# Enable MD5, SHA1 and SHA256 hashing for all files.

@load base/files/hash
event file_new(f: fa_file)
    {
    Files::add_analyzer(f, Files::ANALYZER_MD5);
    Files::add_analyzer(f, Files::ANALYZER_SHA1);
    Files::add_analyzer(f, Files::ANALYZER_SHA256);
    }
`

export const ZEEK_EXTRACT_ALL = `# Extract all files to disk.

@load base/files/extract
event file_new(f: fa_file)
    {
    Files::add_analyzer(f, Files::ANALYZER_EXTRACT);
    }
`

export const ZEEK_INTEL_DEMO = `# Load intelligence framework!
@load policy/frameworks/intel/seen
@load policy/frameworks/intel/do_notice
redef Intel::read_files += { "/opt/zeek/intel/zeek_intel.txt" };
`

export const INTEL_TXT = '#fields\tindicator\tindicator_type\tmeta.source\tmeta.desc\nsmart-fax.com\tIntel::DOMAIN\tzeek-intel-test\tZeek-Intelligence-Framework-Test\n'

export const ZEEK_SUMSTATS = `# Hitung kode status HTTP per server dengan Summary Statistics framework.
@load base/frameworks/sumstats

event http_reply(c: connection, version: string, code: count, reason: string)
    {
    SumStats::observe("http.status", [$host=c$id$resp_h], [$str=cat(code)]);
    }

event zeek_init()
    {
    local r1 = SumStats::Reducer($stream="http.status", $apply=set(SumStats::UNIQUE, SumStats::SUM));
    SumStats::create([$name="status-count-table", $epoch=1hr, $reducers=set(r1),
        $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) =
            {
            print fmt("Host: %s", key$host);
            # ... lalu cetak "status code: X, count: Y" untuk tiap kode status.
            }]);
    }
`

const DETECT_BRUTE = `##! FTP brute-forcing detector, triggering when too many rejected usernames or
##! failed passwords have occurred from a single address.

@load base/protocols/ftp
@load base/frameworks/sumstats
@load base/utils/time

module FTP;

export {
    redef enum Notice::Type += {
        ## Indicates a host bruteforcing FTP logins by watching for too
        ## many rejected usernames or failed passwords.
        Bruteforcing
    };

    ## How many rejected usernames or passwords are required before being
    ## considered to be bruteforcing.
    const bruteforce_threshold: double = 20 &redef;

    ## The time period in which the threshold needs to be crossed before
    ## being reset.
    const bruteforce_measurement_interval = 15mins &redef;
}
`

export function buildLab(): VFS {
  const fs = new VFS()
  const dir = (path: string, files: Record<string, string>, pcaps: string[] = []) => {
    fs.mkdirp(`${EX}/${path}`)
    fs.write(`${EX}/${path}/clear-logs.sh`, CLEAR_LOGS, 'text', true)
    for (const [name, content] of Object.entries(files)) fs.write(`${EX}/${path}/${name}`, content)
    for (const p of pcaps) fs.write(`${EX}/${path}/${p}`, '', 'pcap')
  }

  for (const d of ['Documents', 'Downloads', 'Music', 'Pictures', 'Public', 'Templates', 'Videos']) fs.mkdirp(`${HOME}/${d}`)
  fs.write(`${EX}/clear-logs.sh`, CLEAR_LOGS, 'text', true)

  dir('TASK-2', {}, ['sample.pcap'])
  dir('TASK-3', {}, ['sample.pcap'])
  dir('TASK-4', { 'access.txt': ACCESS_TXT })
  dir('TASK-5/http', { 'http-password.sig': SIG_HTTP_PASSWORD }, ['http.pcap'])
  dir('TASK-5/ftp', { 'ftp-admin.sig': SIG_FTP_ADMIN, 'ftp-bruteforce.sig': SIG_FTP_BRUTE }, ['ftp.pcap'])
  dir('TASK-6/smallflow', { 'dhcp-hostname.zeek': ZEEK_DHCP }, ['smallFlows.pcap'])
  dir('TASK-6/bigflow', { 'dhcp-hostname.zeek': ZEEK_DHCP }, ['bigFlows.pcap'])
  dir('TASK-7/101', { '101.zeek': ZEEK_101, '102.zeek': ZEEK_102, '103.zeek': ZEEK_103 }, ['sample.pcap'])
  dir('TASK-7/201', { 'ftp-admin.sig': SIG_FTP_ADMIN, '201.zeek': ZEEK_201 }, ['ftp.pcap'])
  dir('TASK-7/202', {}, ['ftp-brute.pcap'])
  dir(
    'TASK-8',
    {
      'hash-demo.zeek': '# Enable MD5, SHA1 and SHA256 hashing for all files.\n@load /opt/zeek/share/zeek/policy/frameworks/files/hash-all-files.zeek\n',
      'file-extract-demo.zeek': '# Extract all files seen in the traffic.\n@load /opt/zeek/share/zeek/policy/frameworks/files/extract-all-files.zeek\n',
      'intelligence-demo.zeek': ZEEK_INTEL_DEMO,
    },
    ['case1.pcap'],
  )
  dir('TASK-9/cleartext-pass', { 'sniff-demo.zeek': '@load /opt/zeek/share/zeek/site/zeek-sniffpass\n' }, ['http.pcap'])
  dir('TASK-9/geoip-conn', { 'sumstats-counttable.zeek': ZEEK_SUMSTATS }, ['case2.pcap'])

  // Modul Latihan Zeek: satu folder per kasus.
  dir('anomalous-dns', {}, ['dns-tunneling.pcap'])
  dir(
    'phishing',
    {
      'hash-demo.zeek': '# Enable MD5, SHA1 and SHA256 hashing for all files.\n@load /opt/zeek/share/zeek/policy/frameworks/files/hash-all-files.zeek\n',
      'file-extract-demo.zeek': '# Extract all files seen in the traffic.\n@load /opt/zeek/share/zeek/policy/frameworks/files/extract-all-files.zeek\n',
    },
    ['phishing.pcap'],
  )
  dir('log4j', { 'detection-log4j.zeek': '# Deteksi percobaan eksploitasi Log4Shell (CVE-2021-44228).\n@load /opt/zeek/share/zeek/site/cve-2021-44228\n' }, [])
  fs.write(`${EX}/log4j/log4shell.pcapng`, '', 'pcap')

  const z = '/opt/zeek/share/zeek'
  fs.write(`${z}/policy/frameworks/files/hash-all-files.zeek`, ZEEK_HASH_ALL)
  fs.write(`${z}/policy/frameworks/files/extract-all-files.zeek`, ZEEK_EXTRACT_ALL)
  fs.write(`${z}/policy/protocols/ftp/detect-bruteforcing.zeek`, DETECT_BRUTE)
  fs.write(`${z}/site/local.zeek`, '##! Local site policy. Customize as appropriate.\n\n@load misc/loaded-scripts\n@load tuning/defaults\n@load misc/capture-loss\n@load misc/stats\n@load frameworks/software/vulnerable\n@load protocols/ftp/software\n@load protocols/ssh/detect-bruteforcing\n')
  fs.write(`${z}/site/zeek-sniffpass/__load__.zeek`, '@load ./sniffpass\n')
  fs.write(`${z}/site/geoip-conn/__load__.zeek`, '@load ./geoip-conn\n')
  fs.mkdirp(`${z}/base/bif/plugins`)
  fs.mkdirp(`${z}/base/protocols`)
  fs.mkdirp(`${z}/base/frameworks`)
  fs.write('/opt/zeek/intel/zeek_intel.txt', INTEL_TXT)
  fs.mkdirp('/opt/zeek/logs')
  return fs
}
