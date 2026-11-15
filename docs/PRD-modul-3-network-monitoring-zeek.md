# PRD: Modul 3, "Network Monitoring with Zeek"

Dokumen ini ditulis untuk AI agent (atau orang) yang akan membangun modul ketiga TryLearnMe tanpa konteks percakapan sebelumnya. Bagian 1 sampai 3 menjelaskan proyeknya, bagian 4 sampai 7 menjelaskan modul yang harus dibuat, bagian 8 sampai 10 menjelaskan pekerjaan teknis dan cara memastikan hasilnya benar.

- PRD induk proyek: [`PRD.md`](PRD.md). Bagian 1 sampai 3 di bawah adalah ringkasannya.
- Status: belum dikerjakan. Belum ada satu baris kode pun untuk modul ini.
- Ditulis: 2026-11-15.
- Pemilik proyek menulis dalam Bahasa Indonesia. Balas dalam Bahasa Indonesia.

## 1. Proyek ini apa

TryLearnMe adalah website belajar keamanan jaringan milik pribadi, dibuat dari screenshot room TryHackMe yang dirangkum ulang dalam Bahasa Indonesia. Tiap modul punya materi, soal dengan pemeriksaan jawaban, progress, dan terminal simulasi di browser.

| Hal | Nilai |
|---|---|
| Lokasi kode | `D:\Code\Cybersecurity\trylearnme\` |
| Lokasi screenshot sumber | `D:\Code\Cybersecurity\Tryhackme\` (satu folder per room) |
| Stack | React 18, Vite 5, TypeScript, react-router-dom v6 (HashRouter), vitest |
| Backend | Tidak ada. Progress di `localStorage` (`trylearnme:progress:v1`) |
| Git | Bukan repo git. Jangan commit atau push kecuali diminta |
| Perintah | `npm run dev`, `npm run build`, `npm test`, `npx tsc --noEmit` |

Modul yang sudah ada:

| Modul | Alamat | Awalan id soal | Sumber |
|---|---|---|---|
| Zeek (10 task) | `/#/zeek` | `z` | `Tryhackme\Zeek\Reference\` |
| Latihan Zeek (5 task) | `/#/zeek-exercises` | `e` | `Tryhackme\Zeek Excercises\` |

### Keputusan yang sudah dibuat pemilik (jangan diubah tanpa bertanya)

1. Materi dirangkum dan ditulis ulang dalam Bahasa Indonesia. Perintah, nama kolom, dan istilah teknis tetap dalam bentuk aslinya.
2. Terminalnya "mesin pipe mini": shell sungguhan di browser yang mengolah log Zeek buatan. Isi log disusun supaya jawaban soal sama dengan room aslinya. Zeek tidak benar-benar membaca pcap.
3. Tampilan mengikuti gaya TryHackMe (navy dan hijau, font Ubuntu, Source Sans 3, Ubuntu Mono). Nama dan logo tetap TryLearnMe, jangan pakai logo TryHackMe. Desain orisinal pertama ditolak pemilik sebagai "jelek banget".
4. Task yang soalnya belum selesai berwarna merah (garis tepi dan tulisan "Task N"). Setelah semua soalnya benar, berubah hijau.
5. Pemilik suka merancang dulu sebelum membangun, dan ingin ditanya kalau ada yang tidak jelas.

### Kendala lingkungan

- Windows 11, Git Bash dan PowerShell. Tidak ada Docker. WSL `kali-linux` punya tshark, tidak punya Zeek.
- Memori laptop sempit. Server pratinjau latar pernah dimatikan sistem. Tanya dulu sebelum menyalakan server latar.
- Menulis berkas TSX lewat heredoc bash pernah gagal karena tanda kutip. Pakai alat tulis berkas biasa.

## 2. Struktur kode

```
src/
  main.tsx                    rute: /, /zeek/cheatsheet, /:moduleId
  styles.css                  seluruh gaya
  content/
    types.ts                  Question, Task
    ui.tsx                    komponen materi: C, H, Code, Term, Table, Note
    modules.ts                daftar modul (MODULES)
    zeek/                     modul 1 (tasksA/B/C.tsx, cheatsheet.ts)
    exercises/index.tsx       modul 2
  pages/                      Home, ModulePage, CheatSheet
  components/                 Layout, Terminal, QuestionBox
  lib/                        progress.ts, theme.ts
  terminal/
    vfs.ts                    sistem berkas di memori, HOME = /home/ubuntu
    shell.ts                  tokenizer, pipe, ; && > >> <, glob, Tab
    commands.ts               ls cd cat head tail grep sort uniq wc cut sed awk ...
    zeek.ts                   zeek, zeekctl, zkg tiruan
    lab.ts                    isi awal sistem berkas (buildLab)
    data/gen.ts               RNG berseed, pembuat baris log format Zeek
    data/scenarios.ts         satu Scenario per pcap, peta SCENARIOS
    shell.test.ts             11 tes
    exercises.test.ts         3 tes
```

Cara kerja `zeek -r <pcap> [script]` saat ini: nama berkas pcap dicari di `SCENARIOS`, nama berkas script dicari di `SCRIPT_FX` (`zeek.ts`), lalu `scenario.run(fx, sigs)` mengembalikan log yang ditulis ke folder kerja. Efek script ditentukan dari **nama berkas**, bukan isinya.

Bentuk data yang dipakai materi:

```ts
interface Question { id: string; prompt: ReactNode; answer?: string[]; hint?: ReactNode }
interface Task { id: number; title: string; lead: string; dir?: string; Body: FC; questions: Question[] }
interface Module { id; title; navTitle; letter; summary; cardText; prefix; tasks; cheatsheet? }
```

`answer` kosong berarti soal "cukup dibaca". `answer` berisi beberapa bentuk jawaban yang semuanya diterima.

## 3. Menambah modul: daftar periksa umum

1. Tulis task di `src/content/<modul>/index.tsx`, contoh pola ada di `src/content/exercises/index.tsx`.
2. Daftarkan di `MODULES` (`src/content/modules.ts`). Halaman depan, navbar, dan rute ikut otomatis.
3. Tambah berkas latihan di `buildLab()` (`src/terminal/lab.ts`).
4. Tambah skenario log di `src/terminal/data/scenarios.ts`.
5. Tambah tes yang membuktikan tiap jawaban bisa diperoleh dari terminal.
6. Jalankan `npx tsc --noEmit`, `npm test`, `npm run build`.

## 4. Modul yang diminta

Sumber: 42 screenshot di `D:\Code\Cybersecurity\Tryhackme\Network Monitoring with Zeek\`, bernama `Task <nomor task>-<urutan>.png`. Room aslinya: TryHackMe "Network Monitoring with Zeek" (90 menit, 8 task).

### Tujuan belajar

Setelah modul ini, pelajar bisa:

- Membaca `conn.log`, `dns.log`, `http.log`, `ssl.log`, dan `files.log` dengan `zeek-cut` dan alat Unix.
- Mengenali beaconing, DNS tunneling, MIME mismatch, dan TLS tanpa SNI di log.
- Mengikuti satu `uid` lintas log untuk menyusun ulang satu sesi jaringan.
- Membaca dan mengubah script Zeek yang memakai Notice framework supaya tidak menghasilkan false positive.

### Usulan identitas modul (belum disetujui pemilik)

| Kolom | Usulan |
|---|---|
| `id` | `network-monitoring` |
| `title` | Pemantauan Jaringan dengan Zeek |
| `navTitle` | Pemantauan Jaringan |
| `letter` | `N` |
| `prefix` | `n` (id soal: `n2-1`, `n2-2`, dst.) |
| `cheatsheet` | `/zeek/cheatsheet` (tambah satu bagian baru, lihat 8.7) |

### Cerita kasus

Aturan Snort dari room sebelumnya sudah menyala di subnet Finance, tetapi Snort hanya melihat kejadian setelah aturannya dipasang. Sensor Zeek di perimeter merekam semuanya sejak awal. Pelajar mengisi celah waktu itu dari log Zeek.

| Peran | Nilai |
|---|---|
| Workstation korban | `WKST-FINANCE-04`, `10.14.22.88` |
| DNS internal | `SRV-DNS-01`, `10.0.0.53` (menjalankan validasi DNSSEC) |
| Zona internal | `nfg.local` (`wiki.nfg.local`, `intranet.nfg.local`) |
| Server C2 | `194.165.16.56`, TCP/443, AS44477 (Stark Industries Solutions) |
| Domain C2 | `update.softpatch-cdn.com` |
| Tujuan exfiltrasi | `185.213.154.201`, TCP/80 |
| Domain exfiltrasi | `backup.corpfiles-sync.com` |
| Sumber unduhan dropper | `185.220.101.45`, host `fileshare.corp-helpdesk.net` |
| Domain tunnel DNS | `exfil-channel.net` |
| Domain DNSSEC (sah) | `dnssec-validation.local` |
| Resolver luar | `1.1.1.1` |

Garis waktu (2025-11-14, UTC):

| Waktu | Epoch | Kejadian |
|---|---|---|
| 02:30:00 | 1763087400 | Baris pertama `conn.log` (DNS biasa) |
| 02:38:00 | 1763087880 | Beacon pertama ke C2 |
| 02:50:00 | 1763088600 | Unduhan `invoice_march.pdf` (sebenarnya executable) |
| 03:14:56 | 1763090096 | Query DNS `backup.corpfiles-sync.com` |
| 03:15:07 | 1763090107 | HTTP POST 5,3 MB ke `185.213.154.201` |
| 03:59:06 | 1763092746.812696 | Beacon terakhir |

## 5. Task, soal, dan jawaban

Jawaban di bawah diambil dari screenshot yang menampilkan "Correct Answer", kecuali yang diberi catatan.

| Task | Judul asli | Soal | Jawaban | Screenshot |
|---|---|---|---|---|
| 1 | Introduction | Baca pengantar (tanpa jawaban) | – | 1-1 s.d. 1-3 |
| 2 | Reading Connection Records with Zeek | Host internal pertama yang dicoba `10.14.22.88` di TCP/445 dengan `conn_state` S0 | `10.14.22.10` | 2-1 s.d. 2-8 |
| 2 | | Timestamp terakhir sesi TCP/443 dari `10.14.22.88` ke `194.165.16.56` | `1763092746.812696` | |
| 3 | DNS Visibility and Tunnelling Detection | Jenis record DNS pada query panjang `exfil-channel.net` | `TXT` (terima juga `txt`) | 3-1 s.d. 3-7 |
| 3 | | Query DNS tepat sebelum POST 03:15 UTC, nama domain lengkap | `backup.corpfiles-sync.com` (lihat catatan) | |
| 3 | | Domain yang di-resolve ke `194.165.16.56` | `update.softpatch-cdn.com` | |
| 4 | HTTP and TLS Protocol Logs | Nilai `uri` di `http.log` untuk POST ke `185.213.154.201` | `/upload/data` | 4-1 s.d. 4-5 |
| 4 | | Jumlah sesi TLS ke `194.165.16.56` dengan `server_name` kosong | `82` | |
| 5 | File Metadata and Hash Correlation | Nilai `filename` untuk berkas dari POST 5,3 MB | `backup_archive.zip` | 5-1 s.d. 5-5 |
| 5 | | MIME type yang dilaporkan Zeek untuk `invoice_march.pdf` | `application/x-dosexec` | |
| 5 | | Nama family pada baris `threat-feed.csv` yang cocok dengan SHA256 `backup_archive.zip` | `CobaltStrikeStager` | |
| 6 | Cross-Log Correlation | Selisih `orig_bytes` (`conn.log`) dan `request_body_len` (`http.log`) untuk koneksi exfiltrasi | `192` | 6-1 s.d. 6-5 |
| 6 | | Jumlah byte body yang dikembalikan responder di `files.log` untuk uid yang sama | `7` | |
| 6 | | Domain yang di-resolve ke `185.213.154.201` | `backup.corpfiles-sync.com` | |
| 7 | Writing a Detection Notice | Jumlah notice dari `dns_notice.zeek` sebelum diubah | `23` | 7-1 s.d. 7-7 |
| 7 | | Jumlah notice setelah `10.0.0.53` dikecualikan | `10` | |
| 8 | Conclusion | Baca penutup (tanpa jawaban) | – | 8-1, 8-2 |

Total 15 soal berjawaban dan 2 soal "cukup dibaca".

Catatan soal Task 3 nomor 2: di screenshot Task 3 jawabannya belum terisi (percobaan pertama ditolak). Nilai `backup.corpfiles-sync.com` diambil dari soal Task 6 nomor 3, yang menanyakan query yang sama dan sudah bertanda benar. Pola isiannya (`______._______________.___`) cocok.

Pencocokan jawaban sebaiknya tidak peka huruf besar-kecil, seperti modul lain.

## 6. Isi materi per task

Rangkum, jangan terjemahkan kata per kata. Yang wajib ada di tiap task:

**Task 1, Pengenalan.** Cerita kasus, tujuan belajar, prasyarat (modul Zeek), dan tata letak berkas lab (lihat 7.1).

**Task 2, conn.log.** `conn.log` sebagai indeks semua koneksi. Header log (`#fields`, `#unset_field -`). Tabel `conn_state`:

| State | Arti | Makna bagi analis |
|---|---|---|
| `S0` | SYN terkirim, tidak dijawab | Port scan, paket dibuang firewall, port tertutup |
| `SF` | Tersambung dan ditutup rapi | Wajar untuk sesi yang selesai |
| `REJ` | Ditolak (RST sebagai jawaban SYN) | Diblokir firewall atau ACL |
| `OTH` | Tidak ada SYN, data di tengah sesi | Tangkapan asimetris, hitungan byte tidak bisa dipercaya |
| `S1` | Tersambung, penutupan tidak terlihat | Mungkin masih aktif, cek `duration` |
| `RSTO` | Pengirim mengirim RST setelah tersambung | Dibatalkan dari sisi klien |

Lalu empat teknik: memeringkat pasangan sumber-tujuan-port (ketemu 82 sesi ke satu IP luar), memeriksa jeda antar-sesi (sekitar 60 detik, `orig_bytes` 308 tiap kali), menghitung scan internal (23 koneksi ke port 445 berstatus S0), dan mencari transfer keluar terbesar (5.348.913 byte).

**Task 3, dns.log.** Kolom penting (`ts`, `id.orig_h`, `query`, `qtype_name`, `rcode_name`, `answers`). Korelasi mundur dari IP ke domain. DNS tunneling: label panjang ber-Base32 ke satu domain tingkat dua yang sama. Pembeda tunnel asli dari query panjang yang sah: sumber, domain tingkat dua, dan jenis record.

| | Tunnel | DNSSEC yang sah |
|---|---|---|
| Sumber | `10.14.22.88` | `10.0.0.53` |
| Domain | `exfil-channel.net` | `dnssec-validation.local` |
| Jenis record | `TXT` | `DS` |

**Task 4, http.log dan ssl.log.** POST dengan body 5,3 MB, header Host berupa IP polos, tanpa User-Agent. `ssl.log`: 82 handshake TLSv12 ke C2 dengan `server_name` kosong (tanpa SNI). MIME dari magic bytes lewat `files.log`.

**Task 5, files.log.** `mime_type` dihitung dari byte pertama berkas, bukan dari header `Content-Type`. Contoh: nama `invoice_march.pdf`, isi `application/x-dosexec` (magic `4D 5A`, "MZ"). ZIP bermagic `50 4B 03 04`. Mencocokkan SHA256 ke `threat-feed.csv`.

**Task 6, korelasi lintas log.** Satu `uid` menghubungkan `conn.log`, `http.log`, dan `files.log`. DNS tidak berbagi uid (sesi UDP terpisah), jadi dikaitkan lewat IP di kolom `answers`. Selisih 192 byte adalah header HTTP. Dua baris `files.log` untuk satu uid: unggahan (`is_orig` T) dan balasan server 7 byte (`is_orig` F).

**Task 7, script notice.** Bahasa script Zeek berbasis event. Bedah `dns_notice.zeek` (isi lengkap di 7.5). Jalankan, lihat false positive dari `10.0.0.53`, tambah dua baris pengecualian, jalankan lagi. Jelaskan `$identifier` (kunci deduplikasi, di sini IP sumber) dan `$suppress_for` (jeda 5 menit sebelum notice yang sama boleh muncul lagi).

**Task 8, Penutup.** Peran tiap log dan lima pelajaran: mulai dari `conn.log`, pakai `dns.log` untuk asal tujuan, `http.log` dan `ssl.log` untuk perilaku klien, `files.log` untuk berkas, lalu ubah logika investigasi menjadi deteksi yang sudah di-tuning.

Room aslinya menyamarkan sebagian nilai di contoh keluaran (`<REDACTED>`, `<COUNT>`) supaya pelajar mencarinya sendiri. Terapkan hal yang sama di teks materi: jangan tulis jawaban soal di paragraf penjelasan task yang sama. Blok `Term` di TryLearnMe menjalankan perintah sungguhan, jadi keluarannya memang akan menampilkan nilainya.

## 7. Spesifikasi data lab

Semua angka di bagian ini harus muncul persis, karena menjadi jawaban soal atau dikutip materi. Kolom dipisah tab.

### 7.1 Tata letak berkas

Room ini bekerja dari home, bukan dari `~/Desktop/Exercise-Files`:

```
/home/ubuntu/
  logs/conn.log  dns.log  http.log  ssl.log  files.log  notice.log
  pcaps/finance-sensor.pcap
  scripts/dns_notice.zeek
  threat-feed.csv
```

Log di `logs/` sudah ada sejak awal, tidak dihasilkan dengan menjalankan `zeek`. Header log memakai `#open 2026-05-04-17-31-44`.

### 7.2 conn.log

| Kelompok | Jumlah | Rincian |
|---|---|---|
| DNS workstation | 196 | `10.14.22.88` → `10.0.0.53:53`, udp, service `dns`, durasi sekitar 0.005, SF |
| Beacon | 82 | `10.14.22.88` → `194.165.16.56:443`, tcp, durasi 0.044000 atau 0.043999, `orig_bytes` 308, `resp_bytes` 419, SF |
| DNS keluar | 15 | `10.0.0.53` → `1.1.1.1:53` |
| Scan SMB | 23 | `10.14.22.88` → host internal port 445, S0. Urutan waktu pertama: `10.14.22.10` |
| Unduhan dropper | 1 | `10.14.22.88` → `185.220.101.45:80` |
| Exfiltrasi | 1 | lihat di bawah |

Baris awal berkas (lima pertama):

```
1763087400.000000  CE0nuI3nDlaV4XL4x8  10.14.22.88  10.0.0.53  53  udp  dns  0.005000  28  54  SF
1763087430.598559  CDq4fC1kEgsWrHHWbd  10.14.22.88  10.0.0.53  53  udp  dns  0.005000  32  62  SF
1763087449.432986  CWO4ZvZ9dq02SQyw4   10.14.22.88  10.0.0.53  53  udp  dns  0.005000  36  70  SF
1763087472.619239  C9A1eg2W7AGrDOJ7Wc  10.14.22.88  10.0.0.53  53  udp  dns  0.005000  32  62  SF
1763087515.047345  CtayFt2fPHBjYhIF59  10.14.22.88  10.0.0.53  53  udp  dns  0.005001  28  54  SF
```

Lima beacon pertama: `1763087880.000000`, `1763087942.388062`, `1763088002.918872`, `1763088062.344944`, `1763088117.959790`. Dua terakhir: `1763092690.911542` dan `1763092746.812696`. Jeda sekitar 60 detik dengan sedikit jitter.

Baris exfiltrasi:

```
1763090107.000000  CmQW1d3iuUHHDgqYe7  10.14.22.88  54891  185.213.154.201  80  tcp  http  2.471327  5348913  110  SF
```

Peringkat `sort | uniq -c | sort -rn | head -5` atas `id.orig_h id.resp_h id.resp_p` harus menghasilkan 196, 82, 15, 1, 1 dalam urutan itu.

### 7.3 dns.log

- Sepuluh baris pertama (kolom `ts id.orig_h query qtype_name rcode_name answers`):

```
1763087400.000000  10.14.22.88  github.com          A   NOERROR  151.101.190.120
1763087430.598559  10.14.22.88  wiki.nfg.local      A   NOERROR  10.14.0.75
1763087449.432986  10.14.22.88  intranet.nfg.local  A   NOERROR  10.14.0.54
1763087472.619239  10.14.22.88  api.github.com      A   NOERROR  151.101.165.151
1763087515.047345  10.14.22.88  github.com          A   NOERROR  151.101.216.30
1763087520.000000  10.0.0.53    ad31fb585692bc49f060f7bd7e8557f4abc17a0c52ae797f4b0557d1.dnssec-validation.local  DS  NOERROR  DS 48 46 ...
1763087541.277349  10.14.22.88  www.microsoft.com   A   NOERROR  151.101.218.74
1763087566.621425  10.14.22.88  github.com          A   NOERROR  151.101.85.159
1763087591.313790  10.14.22.88  wiki.nfg.local      A   NOERROR  10.14.0.13
1763087615.737583  10.14.22.88  api.github.com      A   NOERROR  151.101.35.80
```

- Tepat satu baris yang `answers`-nya `194.165.16.56`: `10.14.22.88  update.softpatch-cdn.com`.
- Tepat satu baris yang `answers`-nya `185.213.154.201`: `1763090096.000000  10.14.22.88  backup.corpfiles-sync.com`.
- 18 query dari `10.14.22.88` yang panjangnya lebih dari 60 karakter, semuanya `<label Base32 huruf kecil>.exfil-channel.net`, jenis `TXT`, tiap query unik. Contoh: `z6s5vtgvxm7vpdfdirfbjuef56w4b7uv2lqguwxhj3vpejguvx.exfil-channel.net`.
- Query DNSSEC dari `10.0.0.53`: label 56 karakter heksadesimal + `.dnssec-validation.local` (total 80 karakter), jenis `DS`, `NOERROR`. Tiga pertama berlabel awal `ad31fb58…`, `89f8d429…`, `2fee0a73…`.
- Tidak ada host lain selain `10.14.22.88` dan `10.0.0.53` yang punya query lebih dari 60 karakter.

### 7.4 http.log, ssl.log, files.log, threat-feed.csv

`http.log` (dua baris; kolom `ts uid id.orig_h id.resp_h method host uri user_agent request_body_len status_code`):

```
1763088600.061000  CdxY4e4OhSKGjp4mDf  10.14.22.88  185.220.101.45   GET   fileshare.corp-helpdesk.net  /downloads/invoice_march.pdf  <ada isinya>  0        200
1763090107.081000  CmQW1d3iuUHHDgqYe7  10.14.22.88  185.213.154.201  POST  185.213.154.201              /upload/data                  -             5348721  200
```

Hanya baris POST yang `user_agent`-nya `-`.

`ssl.log`: 82 baris, satu per beacon, timestamp = timestamp beacon + 0.041 (`1763087880.041000`, `1763087942.429062`, …), `version` `TLSv12`, `server_name` `-`. Tidak ada baris lain ke `194.165.16.56`.

`files.log` (tiga baris; kolom `ts uid source mime_type filename total_bytes sha256`, ditambah `is_orig`):

```
1763088600.062000  CdxY4e4OhSKGjp4mDf  HTTP  application/x-dosexec  invoice_march.pdf   92160    -                 (is_orig F)
1763090107.081000  CmQW1d3iuUHHDgqYe7  HTTP  application/zip        backup_archive.zip  5348721  459b0165d7f2e5577d60cd8c1244daded93f4457ed4a89983e5e36c490402bec  (is_orig T)
1763090109.469327  CmQW1d3iuUHHDgqYe7  HTTP  -                      -                   7        -                 (is_orig F)
```

Room ini memakai kolom bernama `uid` di `files.log` (`zeek-cut uid` berhasil). Pembuat `files.log` yang sudah ada di `scenarios.ts` mungkin memakai `conn_uids`; periksa dulu dan jangan ubah format modul lama.

`threat-feed.csv`: harus memuat baris `459b0165d7f2e5577d60cd8c1244daded93f4457ed4a89983e5e36c490402bec,CobaltStrikeStager,2025-11-10,high`. Urutan kolom: hash, family, tanggal pertama terlihat, tingkat keyakinan.

### 7.5 scripts/dns_notice.zeek (isi persis)

```zeek
@load base/frameworks/notice

module DNSTunnel;

export {
    redef enum Notice::Type += {
        DNS_Exfil_LongQuery
    };
}

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
{
    if ( |query| > 60 )
    {
        NOTICE([$note=DNS_Exfil_LongQuery,
                $conn=c,
                $msg=fmt("Long DNS query (%d chars): %s", |query|, query),
                $identifier=cat(c$id$orig_h),
                $suppress_for=5min]);
    }
}
```

Perubahan yang diminta dari pelajar, di awal isi event:

```zeek
    if ( c$id$orig_h == 10.0.0.53 )
        return;
```

### 7.6 notice.log

| Dijalankan dengan | Jumlah baris | Rincian |
|---|---|---|
| `dns_notice.zeek` | 23 | 13 dari `10.0.0.53`, 10 dari `10.14.22.88` |
| script yang sudah diubah | 10 | semuanya dari `10.14.22.88` |

Kolom `note` berisi `DNSTunnel::DNS_Exfil_LongQuery`, `msg` berisi `Long DNS query (80 chars): <query>` (angka mengikuti panjang query).

Supaya angka ini masuk akal terhadap `dns.log` (ini penalaran penulis PRD, bukan isi screenshot): notice ditahan 5 menit per IP sumber. Atur 13 query DNSSEC panjang berjarak lebih dari 5 menit satu sama lain, dan sebar 18 query tunnel sehingga jatuh ke 10 jendela 5 menit yang berbeda.

`logs/notice.log` yang sudah ada sejak awal isinya tidak tampak di screenshot. Usul: isi dengan hasil script awal (23 baris).

### 7.7 Nilai yang tidak ada di screenshot (boleh dikarang, jaga konsistensi)

- uid selain yang tertulis di atas. uid yang tertulis dibaca dari gambar beresolusi rendah, jadi bisa meleset satu-dua huruf. Ini tidak memengaruhi jawaban, asal uid exfiltrasi sama di `conn.log`, `http.log`, dan `files.log`.
- `user_agent` baris GET, daftar lengkap IP sasaran scan (usul: `10.14.22.10` sampai `10.14.22.32`), baris `conn.log` untuk unduhan dropper, isi lain `threat-feed.csv`, label lengkap query tunnel dan DNSSEC, query DNS biasa selebihnya.

## 8. Pekerjaan teknis

Kemampuan terminal di bawah sudah diperiksa terhadap kode per 2026-11-15.

### 8.1 Perintah dari room yang harus bisa dijalankan

```
head -8 logs/conn.log
zeek-cut ts uid id.orig_h id.resp_h id.resp_p proto service duration orig_bytes resp_bytes conn_state < logs/conn.log | head -5
zeek-cut id.orig_h id.resp_h id.resp_p < logs/conn.log | sort | uniq -c | sort -rn | head -5
zeek-cut id.orig_h id.resp_h id.resp_p conn_state < logs/conn.log | awk -F'\t' '$2=="194.165.16.56" && $3=="443"' | sort -u
zeek-cut id.orig_h id.resp_h id.resp_p conn_state < logs/conn.log | awk -F'\t' '$1=="10.14.22.88" && $3=="445" && $4=="S0"' | wc -l
zeek-cut id.orig_h query answers < logs/dns.log | grep "194.165.16.56"
zeek-cut id.orig_h query < logs/dns.log | awk -F'\t' 'length($2) > 60' | sort | uniq -c | sort -rn | head -10
zeek-cut id.orig_h query < logs/dns.log | awk -F'\t' '$1!="10.0.0.53" && length($2) > 60 {count[$1]++} END {for(h in count) print count[h], h}'
zeek-cut id.orig_h id.resp_h method uri user_agent request_body_len < logs/http.log | awk -F'\t' '$5=="-"'
zeek-cut id.orig_h id.resp_h server_name < logs/ssl.log | awk -F'\t' '$2=="194.165.16.56" && $3=="-" {c++} END{print c+0}'
grep -E "(^#)|(CmQW1d3iuUHHDgqYe7)" logs/files.log | zeek-cut source mime_type filename total_bytes
zeek-cut filename mime_type total_bytes < logs/files.log | awk -F'\t' '$1~/\.(pdf|jpg|png|gif|doc)$/'
HASH=$(grep -E "(^#)|(CmQW1d3iuUHHDgqYe7)" logs/files.log | zeek-cut sha256 filename total_bytes | awk -F'\t' '$2=="backup_archive.zip" {print $1}')
grep "$HASH" threat-feed.csv
mkdir -p /tmp/zeek-task7 && cd /tmp/zeek-task7
zeek -r ~/pcaps/finance-sensor.pcap ~/scripts/dns_notice.zeek
ls -la notice.log
zeek-cut id.orig_h note msg < notice.log | sort -u | head -5
zeek-cut id.orig_h < notice.log | wc -l
rm -f *.log
zeek -r ~/pcaps/finance-sensor.pcap dns_notice_modified.zeek
```

Beberapa perintah di screenshot terpotong di tepi kanan (pola waktu beacon, transfer keluar terbesar). Ujungnya harus direka, misalnya `| sort -t$'\t' -k6 -nr | head -3`, atau diganti bentuk yang lebih sederhana.

### 8.2 Yang belum didukung simulator

| Kebutuhan | Keadaan sekarang | Berkas |
|---|---|---|
| `awk`: fungsi `length()` | Belum ada | `commands.ts` |
| `awk`: aksi selain `print` (`c++`, `count[$1]++`), blok `END`, `for (h in count)` | Hanya `print` | `commands.ts` |
| Shell: variabel (`HASH=...`, `"$HASH"`) dan substitusi `$(...)` | Belum ada. Tanda kutip ganda tidak mengembangkan apa pun | `shell.ts` |
| Shell: `$'\t'` | Belum ada | `shell.ts` |
| Menyunting atau membuat berkas script | `nano`, `vim`, dll. sengaja menolak. Tidak ada `cp` | `commands.ts` |
| `zeek` menilai script dari isinya | Efek ditentukan dari nama berkas (`SCRIPT_FX`) | `zeek.ts` |
| Folder kerja task di luar `Exercise-Files` | `ModulePage` menjalankan `cd ~/Desktop/Exercise-Files/${dir}` | `ModulePage.tsx`, `types.ts` |
| Baris DNS dengan `qtype` selain A | `dnsRow` di `gen.ts` selalu menulis A | `gen.ts` |

Sudah didukung dan tidak perlu diubah: `< berkas`, `&&`, `mkdir -p` (membuat `/tmp` juga), `~` di path, `awk -F'\t'` dengan perbandingan, `&&`, `||`, dan `$1~/regex/`, `sort -u`, `sort -rn`, `uniq -c`, `wc -l`, `zeek -r` tanpa `-C`, konten berkas malas (fungsi) di VFS.

Perlu dicek karena belum dipastikan: `ls -la <berkas>` menampilkan ukuran, `rm -f *.log`, dan `grep -E "(^#)|(uid)"`.

### 8.3 Keputusan yang masih terbuka untuk pemilik

1. **Cara pelajar mengubah script di Task 7.** Usul: `nano <berkas>` membuka penyunting sederhana (kotak teks dengan tombol simpan) di panel terminal, dan `zeek` memeriksa isi script: kalau ada pengecualian untuk `10.0.0.53` sebelum `NOTICE`, hasilnya 10 notice, kalau tidak 23. Pilihan yang lebih murah: sediakan `scripts/dns_notice_modified.zeek` yang sudah jadi dan tambah perintah `cp`, dengan risiko pelajar tidak benar-benar berlatih menyunting.
2. **Identitas modul** di bagian 4 (id, judul, awalan).
3. **Letak berkas lab.** Usul: langsung di `/home/ubuntu` seperti room aslinya supaya perintahnya sama persis. Semua modul berbagi satu sistem berkas, jadi `logs/`, `pcaps/`, dan `scripts/` akan terlihat juga dari modul lain.

Tanyakan ketiganya ke pemilik sebelum membangun.

### 8.4 Skenario dan lab

- Tambah skenario `financeSensor` di `scenarios.ts` dan daftarkan `'finance-sensor.pcap'` di `SCENARIOS`. Pakai RNG berseed dari `gen.ts` supaya isi log selalu sama.
- Di `buildLab()`: tulis enam log ke `~/logs/` dari skenario yang sama, `~/pcaps/finance-sensor.pcap` (jenis `pcap`), `~/scripts/dns_notice.zeek`, dan `~/threat-feed.csv`.
- `zeek -r ~/pcaps/finance-sensor.pcap <script>` menulis `conn.log`, `dns.log`, `http.log`, `ssl.log`, `files.log`, dan `notice.log` ke folder kerja.

### 8.5 Folder kerja task

`Task.dir` sekarang relatif terhadap `Exercise-Files`. Modul ini butuh `~` untuk Task 2 sampai 6. Perluas dengan cara yang tidak mengubah modul lama, misalnya: `dir` yang diawali `~` atau `/` dipakai apa adanya.

### 8.6 Materi

Satu berkas `src/content/network/index.tsx` (pecah kalau terlalu panjang), mengikuti pola `exercises/index.tsx`. Diagram di room (perbandingan browsing biasa dan beacon, tiga jenis query DNS, header vs magic bytes, satu uid untuk empat log, sebelum dan sesudah suppression) cukup diganti tabel atau daftar, tidak perlu gambar.

### 8.7 Cheat sheet

Tambah satu bagian di `src/content/zeek/cheatsheet.ts`: tabel `conn_state`, pola peringkat pasangan koneksi, filter query DNS panjang, filter User-Agent kosong, filter MIME mismatch, dan pivot `uid` dengan `grep -E "(^#)|(<uid>)"`.

## 9. Di luar cakupan

- Modul Suricata (belum ada screenshot).
- Lab Zeek sungguhan di server atau WSL.
- Mengunduh atau menyertakan pcap. `finance-sensor.pcap` cukup berkas kosong berjenis `pcap`.
- Interpreter script Zeek. Cukup pengenalan isi script seperlunya untuk Task 7.
- Mengubah tampilan atau modul yang sudah ada, kecuali perluasan di 8.2 dan 8.5.

## 10. Kriteria selesai

1. Modul muncul di halaman depan dan navbar, terbuka di `/#/network-monitoring` (atau id yang disetujui), dengan 8 task.
2. 15 soal berjawaban menerima jawaban di bagian 5 dan menolak jawaban salah. Progress modul ini bisa dihapus tanpa menyentuh modul lain.
3. Tes baru (`src/terminal/network.test.ts`) membuktikan tiap jawaban bisa diperoleh dari terminal memakai perintah di 8.1, termasuk alur Task 7: 23 notice sebelum diubah dan 10 sesudahnya.
4. 14 tes lama tetap lolos. `npx tsc --noEmit` bersih. `npm run build` berhasil.
5. Blok `Term` di materi berjalan saat tombol "Jalankan" ditekan dan tidak ada yang berakhir dengan pesan "belum didukung simulator".
6. Task merah sebelum selesai dan hijau sesudahnya, sama seperti modul lain.
7. Tampilan dicek di browser pada mode gelap. Tanya pemilik sebelum menyalakan server.
