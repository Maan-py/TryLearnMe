# PRD: TryLearnMe

Dokumen induk proyek. Ditulis supaya AI agent atau orang baru bisa melanjutkan pekerjaan tanpa membaca percakapan sebelumnya. Baca ini dulu, baru PRD modul yang sedang dikerjakan.

- Diperbarui: 2026-11-15
- Pemilik proyek menulis dalam Bahasa Indonesia. Balas dalam Bahasa Indonesia.
- PRD per modul: [`PRD-modul-3-network-monitoring-zeek.md`](PRD-modul-3-network-monitoring-zeek.md)

## 1. Ringkasan

TryLearnMe adalah website belajar keamanan jaringan untuk pemakaian pribadi. Pemiliknya sedang belajar analisis SOC lewat room TryHackMe, memotret layar materinya, lalu meminta materi itu dirangkum menjadi modul di website ini: penjelasan dalam Bahasa Indonesia, soal dengan pemeriksaan jawaban, dan terminal simulasi untuk berlatih.

Yang dicari pemilik: bisa mengulang materi kapan saja dalam bahasanya sendiri, dengan latihan langsung, tanpa harus menyalakan mesin lab TryHackMe.

## 2. Pengguna dan cara pakai

Satu pengguna: pemilik proyek. Dipakai di laptop sendiri lewat `npm run dev`, atau dari hasil build statis. Tidak ada akun, tidak ada server, tidak ada rencana publikasi.

Alur pakai:

1. Buka halaman depan, pilih modul.
2. Buka satu task, baca materinya.
3. Jalankan perintah di terminal di sisi kanan (ketik sendiri atau tekan "Jalankan" pada contoh).
4. Jawab soal. Task berubah dari merah ke hijau saat semua soalnya benar.
5. Buka cheat sheet saat perlu mengingat perintah.

## 3. Keadaan sekarang

| Modul | Alamat | Task | Awalan id soal | Sumber screenshot | Status |
|---|---|---|---|---|---|
| Zeek | `/#/zeek` | 10 | `z` | `Tryhackme\Zeek\Reference\` | Selesai |
| Latihan Zeek | `/#/zeek-exercises` | 5 | `e` | `Tryhackme\Zeek Excercises\` | Selesai |
| Network Monitoring with Zeek | belum ada | 8 | usul `n` | `Tryhackme\Network Monitoring with Zeek\` | PRD ada, belum dibangun |
| Suricata | – | – | – | belum ada screenshot | Ditunda, tampil "Segera hadir" di halaman depan |

Folder screenshot ada di `D:\Code\Cybersecurity\Tryhackme\`. Kode ada di `D:\Code\Cybersecurity\trylearnme\`.

Keadaan pengujian: 14 tes lolos, `tsc` bersih, build berhasil (per 2026-11-15).

Yang belum pernah diperiksa:

- Modul Latihan Zeek belum pernah dilihat di browser.
- Mode terang belum pernah dilihat.
- Warna hijau untuk task selesai belum pernah dilihat.
- Mengetik dan mengklik di browser sungguhan belum diuji. Yang diuji hanya mesin terminalnya lewat tes otomatis.

## 4. Fitur

### 4.1 Halaman

| Halaman | Alamat | Isi |
|---|---|---|
| Depan | `/#/` | Pengantar, terminal contoh, kartu tiap modul dengan progress, kartu Suricata "Segera hadir" |
| Modul | `/#/<id modul>` | Judul, bilah progress persen, daftar task (akordeon, `?task=N`), soal, terminal menempel di kanan |
| Cheat sheet | `/#/zeek/cheatsheet` | 9 bagian perintah Zeek dengan tombol salin |

Di layar sempit, terminal menjadi lembar yang naik dari bawah.

### 4.2 Materi dan soal

- Tiap task punya judul, kalimat pembuka, isi materi, dan daftar soal.
- Soal berjawaban: kotak isian, tombol "Kirim", dan tombol "Petunjuk" (oranye) kalau ada petunjuk. Pembandingan tidak peka huruf besar-kecil dan spasi berlebih. Satu soal boleh punya beberapa bentuk jawaban yang diterima.
- Soal tanpa jawaban ("cukup dibaca"): tombol "Tandai selesai".
- Contoh perintah di materi (komponen `Term`) punya tombol "Jalankan" yang mengirim perintah ke terminal.

### 4.3 Progress

- Disimpan di `localStorage`, kunci `trylearnme:progress:v1`, berbentuk `{ "<id soal>": true }`.
- Id soal diawali awalan modul (`z2-1`, `e3-2`). Menghapus progress satu modul berarti menghapus semua kunci berawalan itu (`startsWith`), jadi awalan modul baru tidak boleh menjadi awalan dari awalan modul lain.
- Task dianggap selesai kalau semua soalnya sudah benar.

### 4.4 Terminal simulasi

Pemilik memilih "mesin pipe mini" daripada keluaran yang dihafal: shell sungguhan yang berjalan di browser dan mengolah berkas log di sistem berkas memori. Yang tiruan hanya Zeek-nya: `zeek -r <pcap>` tidak membaca pcap, melainkan menulis log yang sudah disiapkan untuk pcap bernama itu. Isi log dibuat dengan angka acak berseed tetap, dalam format TSV asli Zeek, dan disusun supaya jawaban soalnya sama dengan room aslinya.

| Kelompok | Yang didukung |
|---|---|
| Shell | pipe `\|`, `;`, `&&`, `>`, `>>`, `<`, glob `*` `?`, Tab, riwayat, `sudo su` |
| Berkas | `ls`, `cd`, `pwd`, `cat`, `head`, `tail`, `less`, `more`, `rm`, `mkdir`, `file` |
| Olah teks | `grep` (-v -i -e -c -n -r -o -E -F -w -l -h), `sort` (-n -r -u -k -t -f), `uniq` (-c -d -u -i), `wc`, `nl`, `cut`, `sed` (-n 'Np', s///), `awk` mini (pola dan `print` saja), `column -t`, `rev`, `tac`, `base64 -d` |
| Zeek | `zeek -C -r <pcap> [-s sig] [script]`, `zeek-cut [-c]`, `zeekctl status\|start\|stop\|deploy` (butuh root), `zkg list`, `./clear-logs.sh` |

Yang sengaja tidak ada: editor teks, `tcpdump`, `tshark`, akses jaringan. Yang belum ada tetapi dibutuhkan modul 3 (variabel shell, `$(...)`, `awk` yang lebih lengkap) dirinci di PRD modul 3 bagian 8.2.

### 4.5 Tampilan

Mengikuti gaya TryHackMe atas permintaan pemilik, dengan nama dan tanda TryLearnMe sendiri.

| Hal | Nilai |
|---|---|
| Latar | navy `#151c2b`, permukaan `#1c2538` dan `#212c42`, garis `#2c3a55` |
| Aksen | hijau `#88cc14` dan `#a3ea2a` |
| Belum selesai | merah `#f0504a` |
| Petunjuk | oranye `#f39c12` |
| Font | Ubuntu (judul), Source Sans 3 (isi), Ubuntu Mono (kode), lewat `@fontsource` |
| Tema | gelap (bawaan) dan terang, tombol di navbar |

Semua warna didefinisikan sebagai variabel di awal `src/styles.css`.

## 5. Keputusan pemilik

Jangan diubah tanpa bertanya.

1. **Bahasa.** Materi dirangkum dan ditulis ulang dalam Bahasa Indonesia. Perintah, nama kolom, dan istilah teknis tetap dalam bentuk aslinya.
2. **Terminal.** Mesin pipe mini seperti di 4.4. Lab sungguhan (Docker dan ttyd di server Ubuntu pemilik lewat Tailscale) pernah dibahas dan ditunda; akses SSH ke server itu belum disiapkan.
3. **Tampilan.** Gaya TryHackMe. Desain orisinal pertama (hijau kebiruan, IBM Plex) ditolak sebagai "jelek banget". Jangan pakai logo TryHackMe.
4. **Warna task.** Belum selesai: garis tepi dan tulisan "Task N" merah. Selesai: hijau.
5. **Pcap.** Hanya pcap publik yang disertakan (`public/pcaps/smallFlows.pcap`). Pcap berisi malware sungguhan tidak diunduh.
6. **Urutan modul.** Mengikuti screenshot yang ditambahkan pemilik. Suricata menunggu screenshot.
7. **Cara kerja.** Rancang dulu, baru bangun. Tanya kalau ada yang tidak jelas.

## 6. Arsitektur

| Hal | Nilai |
|---|---|
| Stack | React 18, Vite 5, TypeScript, react-router-dom v6 (HashRouter), vitest |
| Backend | Tidak ada |
| Build | Statis, `base: './'`, bisa dibuka dari folder mana pun |
| Git | Repo publik `github.com/Maan-py/trylearnme`, cabang `main`. Commit tanpa baris "Co-Authored-By" untuk AI |

```
src/
  main.tsx                    rute: /, /zeek/cheatsheet, /:moduleId
  styles.css                  seluruh gaya dan variabel warna
  content/
    types.ts                  Question, Task
    ui.tsx                    komponen materi: C, H, Code, Term, Table, Note
    modules.ts                daftar modul (MODULES), getModule, isTaskDone
    zeek/                     modul 1: tasksA/B/C.tsx, index.ts, cheatsheet.ts
    exercises/index.tsx       modul 2
  pages/                      Home, ModulePage, CheatSheet
  components/                 Layout, Terminal, QuestionBox, TerminalContext
  lib/                        progress.ts, theme.ts
  terminal/
    vfs.ts                    sistem berkas di memori, HOME = /home/ubuntu
    shell.ts                  tokenizer, pipe, redirect, glob, Tab
    commands.ts               perintah-perintah shell
    zeek.ts                   zeek, zeekctl, zkg tiruan
    lab.ts                    isi awal sistem berkas (buildLab)
    data/gen.ts               RNG berseed, pembuat baris log format Zeek
    data/scenarios.ts         satu Scenario per pcap, peta SCENARIOS
    shell.test.ts             11 tes (modul Zeek)
    exercises.test.ts         3 tes (modul Latihan Zeek)
public/pcaps/smallFlows.pcap  pcap publik untuk diunduh
docs/                         PRD
```

Cara kerja `zeek -r`: nama berkas pcap dicari di `SCENARIOS`, nama berkas script dicari di `SCRIPT_FX` (`zeek.ts`), lalu `scenario.run(fx, sigs)` mengembalikan log yang ditulis ke folder kerja. Efek script ditentukan dari nama berkasnya, bukan isinya.

Semua modul berbagi satu sistem berkas. Folder latihan ada di `~/Desktop/Exercise-Files/<folder>`, dan terminal otomatis pindah ke folder task yang sedang dibuka (`Task.dir`).

## 7. Menambah modul

1. Baca semua screenshot di folder room-nya. Catat tiap soal dan jawabannya.
2. Tulis PRD modul di `docs/` kalau modulnya besar atau butuh kemampuan terminal baru, lalu minta persetujuan pemilik untuk keputusan yang terbuka.
3. Tulis task di `src/content/<modul>/index.tsx`. Pola: `src/content/exercises/index.tsx`.
4. Daftarkan di `MODULES` (`src/content/modules.ts`) dengan awalan id soal yang unik. Halaman depan, navbar, dan rute ikut otomatis.
5. Tambah berkas latihan di `buildLab()` dan skenario log di `scenarios.ts`.
6. Tambah tes yang membuktikan tiap jawaban bisa diperoleh dari terminal dengan perintah yang wajar.
7. Tambah bagian cheat sheet kalau ada teknik baru.
8. Jalankan `npx tsc --noEmit`, `npm test`, `npm run build`.
9. Laporkan ke pemilik apa yang diambil dari screenshot dan apa yang dikarang.

Aturan isi:

- Rangkum, jangan terjemahkan kata per kata.
- Jangan tulis jawaban soal di paragraf materi task yang sama.
- Kalau screenshot tidak memuat suatu nilai, boleh dikarang asal konsisten, dan sebutkan ke pemilik.
- Kalau sebuah soal hanya bisa dijawab di luar simulator (misalnya pencarian hash di VirusTotal), katakan itu di soalnya.

## 8. Kendala lingkungan

- Windows 11, Git Bash dan PowerShell. Tidak ada Docker. Tidak ada python di bash.
- WSL `kali-linux` punya tshark dan tcpdump, tidak punya Zeek.
- Memori laptop sempit. Server pratinjau latar pernah dimatikan sistem. Tanya pemilik sebelum menyalakan server latar.
- Menulis berkas TSX lewat heredoc bash pernah gagal karena tanda kutip. Pakai alat tulis berkas biasa.
- Jangan commit atau push kecuali diminta.
- Data pribadi pemilik dan detail proyek tidak boleh dikirim ke layanan luar.

## 9. Perintah

```
cd D:\Code\Cybersecurity\trylearnme
npm install
npm run dev        http://localhost:5173
npm test           tes mesin terminal dan jawaban soal
npx tsc --noEmit   pemeriksaan tipe
npm run build      hasil statis di dist/
npm run preview    menyajikan dist/ di port 4173
```

## 10. Di luar cakupan

- Akun, login, penyimpanan di server, atau sinkron antar-perangkat.
- Publikasi ke internet.
- Menjalankan Zeek atau membaca pcap sungguhan di browser.
- Menyalin teks atau gambar room TryHackMe apa adanya.

## 11. Rencana

| Urutan | Pekerjaan | Syarat |
|---|---|---|
| 1 | Modul 3, Network Monitoring with Zeek | Tiga keputusan di PRD modul 3 bagian 8.3 dijawab pemilik |
| 2 | Cek tampilan di browser: modul Latihan Zeek, mode terang, keadaan selesai | Izin menyalakan server |
| 3 | Modul Suricata | Screenshot dari pemilik |
| Ditunda | Lab Zeek sungguhan di server Ubuntu lewat Tailscale, atau Zeek di WSL | Permintaan pemilik dan akses SSH |

## 12. Kriteria mutu untuk setiap perubahan

1. Semua tes lolos, `tsc` bersih, build berhasil.
2. Setiap soal berjawaban punya tes yang membuktikan jawabannya bisa didapat dari terminal, atau diberi keterangan bahwa jawabannya dicari di luar simulator.
3. Modul lama tidak berubah perilakunya.
4. Tidak ada contoh perintah di materi yang berakhir dengan pesan "belum didukung simulator".
5. Laporan ke pemilik menyebut dengan jelas apa yang sudah diverifikasi dan apa yang belum.
