export interface CheatSection {
  title: string
  note?: string
  rows: [cmd: string, desc: string][]
}

export const ZEEK_CHEATSHEET: CheatSection[] = [
  {
    title: 'Menjalankan Zeek',
    rows: [
      ['zeek -v', 'Versi Zeek'],
      ['zeek -C -r sample.pcap', 'Baca pcap, abaikan galat checksum'],
      ['zeek -C -r sample.pcap -s sample.sig', 'Baca pcap dengan berkas signature'],
      ['zeek -C -r sample.pcap script.zeek', 'Baca pcap dengan sebuah script'],
      ['zeek -C -r sample.pcap -s sample.sig script.zeek', 'Signature dan script sekaligus'],
      ['zeek -C -r sample.pcap local', 'Muat semua script di local.zeek'],
      ['./clear-logs.sh', 'Hapus log lama di folder latihan'],
    ],
  },
  {
    title: 'ZeekControl',
    note: 'Butuh hak superuser (sudo su).',
    rows: [
      ['zeekctl status', 'Status layanan Zeek'],
      ['zeekctl start', 'Mulai layanan'],
      ['zeekctl stop', 'Hentikan layanan'],
      ['zeekctl deploy', 'Terapkan konfigurasi dan mulai ulang'],
    ],
  },
  {
    title: 'zeek-cut',
    note: 'Nama kolom diambil dari baris #fields di log.',
    rows: [
      ['cat conn.log | zeek-cut uid id.orig_h id.resp_h', 'Ambil kolom tertentu'],
      ['cat conn.log | zeek-cut -c uid proto', 'Ambil kolom, sertakan header'],
      ['cat dns.log | zeek-cut query | sort | uniq', 'Daftar query DNS unik'],
      ['cat conn.log | zeek-cut duration | sort -n | tail -1', 'Durasi koneksi terlama'],
      ['cat http.log | zeek-cut host uri', 'Host dan alamat yang diminta'],
      ['cat files.log | zeek-cut mime_type md5 sha1', 'Jenis berkas dan hash-nya'],
    ],
  },
  {
    title: 'Pola pipe',
    rows: [
      ['sort | uniq', 'Nilai unik'],
      ['sort | uniq | wc -l', 'Jumlah nilai unik'],
      ['sort | uniq -c | sort -nr', 'Peringkat kemunculan'],
      ['sort -n', 'Urut angka'],
      ['sort -nr | head -n 5', 'Lima angka terbesar'],
      ["grep -v -e '*' -e '-'", 'Buang baris yang memuat * atau -'],
      ['grep -i kata | wc -l', 'Hitung baris yang memuat kata (abaikan huruf besar/kecil)'],
      ["sed -n '10,15p'", 'Baris 10 sampai 15'],
      ["awk 'NR == 11 {print $0}'", 'Baris ke-11'],
      ['nl', 'Nomori baris'],
      ['grep -rin NILAI * | column -t | less -S', 'Cari nilai di semua log, rapikan kolom'],
    ],
  },
  {
    title: 'Log yang sering dibuka',
    rows: [
      ['conn.log', 'Semua koneksi: alamat, port, protokol, durasi, jumlah paket'],
      ['dns.log', 'Query dan jawaban DNS'],
      ['http.log', 'Permintaan HTTP: host, uri, user agent, kode status'],
      ['dhcp.log', 'Pembagian alamat: hostname, domain, MAC'],
      ['ftp.log', 'Sesi FTP: pengguna, perintah, kode balasan'],
      ['files.log', 'Berkas yang lewat: jenis, hash, nama hasil ekstraksi'],
      ['notice.log', 'Pemberitahuan dari script dan signature'],
      ['signatures.log', 'Signature yang cocok'],
      ['intel.log', 'Indikator intelijen yang terlihat'],
      ['loaded_scripts.log', 'Daftar script yang dimuat'],
    ],
  },
  {
    title: 'Filter signature',
    note: 'Bentuk: signature nama { kondisi... event "pesan" }',
    rows: [
      ['ip-proto == tcp', 'Protokol: tcp, udp, icmp, icmp6, ip, ip6'],
      ['src-ip / dst-ip', 'Alamat sumber dan tujuan'],
      ['src-port / dst-port', 'Port sumber dan tujuan'],
      ['payload /.*pola.*/', 'Isi paket cocok dengan regex'],
      ['http-request /.*pola.*/', 'Permintaan HTTP yang sudah diurai'],
      ['http-request-header, http-request-body', 'Header dan isi permintaan HTTP'],
      ['http-reply-header, http-reply-body', 'Header dan isi jawaban HTTP'],
      ['ftp /.*USER.*/', 'Perintah pada sesi FTP'],
      ['same-ip', 'Alamat sumber dan tujuan sama'],
      ['event "Pesan"', 'Pesan saat signature cocok'],
    ],
  },
  {
    title: 'Lokasi penting',
    rows: [
      ['/opt/zeek/logs/', 'Log saat Zeek berjalan sebagai layanan'],
      ['/opt/zeek/share/zeek/base', 'Base script bawaan (jangan diubah)'],
      ['/opt/zeek/share/zeek/site', 'Script buatan pengguna'],
      ['/opt/zeek/share/zeek/site/local.zeek', 'Konfigurasi script untuk mode langsung'],
      ['/opt/zeek/share/zeek/policy', 'Policy script'],
      ['/opt/zeek/share/zeek/policy/protocols/ftp/detect-bruteforcing.zeek', 'Pendeteksi brute-force FTP'],
      ['/opt/zeek/share/zeek/policy/frameworks/files/hash-all-files.zeek', 'Hash semua berkas'],
      ['/opt/zeek/share/zeek/policy/frameworks/files/extract-all-files.zeek', 'Ekstrak semua berkas'],
      ['/opt/zeek/intel/zeek_intel.txt', 'Daftar indikator intelijen'],
    ],
  },
  {
    title: 'Package manager (zkg)',
    rows: [
      ['zkg list', 'Paket terpasang'],
      ['zkg install zeek/cybera/zeek-sniffpass', 'Pasang paket'],
      ['zkg refresh', 'Periksa pembaruan'],
      ['zkg upgrade', 'Perbarui paket'],
      ['zkg remove nama-paket', 'Hapus paket'],
      ['zeek -Cr http.pcap zeek-sniffpass', 'Pakai paket lewat namanya'],
      ['zeek -Cr case2.pcap geoip-conn', 'Tambahkan kolom lokasi ke conn.log'],
    ],
  },
  {
    title: 'Teknik investigasi',
    note: 'Dipakai di modul Latihan Zeek.',
    rows: [
      ["cat dns.log | zeek-cut query | rev | cut -d '.' -f 1-2 | rev | sort | uniq", 'Domain unik (dua bagian terakhir dari tiap nama)'],
      ['cat dns.log | zeek-cut qtype_name | sort | uniq -c', 'Jumlah query per jenis record (A, AAAA, TXT, ...)'],
      ['cat conn.log | zeek-cut id.orig_h | sort | uniq -c | sort -nr', 'Host yang paling banyak membuka koneksi'],
      ['cat http.log | zeek-cut user_agent | sort | uniq -c', 'User agent: sering membuka alat yang dipakai penyerang'],
      ['echo TEKS_BASE64 | base64 -d', 'Uraikan teks base64'],
      ['10[.]6[.]27[.]102, contoh[.]com', 'Format defanged: titik diganti [.] agar tidak bisa diklik'],
    ],
  },
]
