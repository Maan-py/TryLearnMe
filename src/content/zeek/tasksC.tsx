import type { Task } from '../types'
import { C, Code, H, Note, Table, Term } from '../ui'
import { INTEL_TXT, ZEEK_HASH_ALL, ZEEK_INTEL_DEMO } from '../../terminal/lab'

export const task8: Task = {
  id: 8,
  title: 'Zeek Scripts: framework',
  lead: 'Memakai framework berkas dan intelijen: hash, ekstraksi berkas, dan pencocokan indikator.',
  dir: 'TASK-8',
  Body: () => (
    <>
      <p>
        Zeek punya lebih dari 15 framework. Kebanyakan dipakai dari dalam script, dengan memuatnya lewat <C>@load</C>. Di task ini kita
        memakai dua yang paling sering berguna saat investigasi: File Analysis dan Intelligence. Semua latihan memakai{' '}
        <C>case1.pcap</C>.
      </p>

      <H>Framework berkas: hash</H>
      <p>
        Script bawaan <C>hash-all-files.zeek</C> menghitung MD5, SHA1, dan SHA256 untuk setiap berkas yang lewat di jaringan. Hash ini bisa
        dicocokkan dengan basis data malware.
      </p>
      <Code title="/opt/zeek/share/zeek/policy/frameworks/files/hash-all-files.zeek">{ZEEK_HASH_ALL}</Code>
      <p>
        Script itu bisa dipanggil lewat path lengkapnya, atau lewat script kecil yang memuatnya (<C>hash-demo.zeek</C>). Hasilnya sama.
      </p>
      <Term title="Mengambil hash berkas">{`
$ cat hash-demo.zeek
$ zeek -C -r case1.pcap hash-demo.zeek
$ cat files.log | zeek-cut mime_type md5 sha1
`}</Term>

      <H>Framework berkas: ekstraksi</H>
      <p>Zeek juga bisa menyimpan berkas yang dikirim lewat jaringan ke disk:</p>
      <Term title="Mengekstrak berkas">{`
$ zeek -C -r case1.pcap file-extract-demo.zeek
$ ls
$ ls extract_files | nl
$ file extract_files/* | nl
`}</Term>
      <p>
        Folder <C>extract_files</C> dibuat otomatis. Nama tiap berkas disusun dari empat bagian: kata <C>extract</C>, waktu (ts), protokol
        sumber, dan ID berkas (fuid). Perintah <C>file</C> menunjukkan jenisnya: satu teks, satu dokumen Word, dan satu program Windows.
      </p>
      <p>
        <C>files.log</C> memuat rincian yang sama beserta UID koneksinya. Dengan UID itu, kita bisa menelusuri berkas <C>.exe</C> ke log
        lain:
      </p>
      <Term title="Mengaitkan temuan">{`
$ cat files.log | zeek-cut fuid conn_uids tx_hosts rx_hosts mime_type extracted | nl
$ grep -rin CZruIO2cqspVhLuAO9 * | column -t | nl | less -S
`}</Term>
      <p>
        UID yang sama muncul di <C>conn.log</C>, <C>files.log</C>, dan <C>http.log</C>. Dari tiga log itu kita tahu siapa mengunduh apa,
        dari mana, dan lewat permintaan HTTP yang mana.
      </p>

      <H>Framework intelijen</H>
      <p>
        Framework ini mencocokkan lalu lintas dengan daftar indikator (domain, IP, hash, dan lainnya), lalu menulis hasilnya ke{' '}
        <C>intel.log</C>. Daftar indikatornya ada di <C>/opt/zeek/intel/zeek_intel.txt</C>.
      </p>
      <ul>
        <li>Berkas indikator harus dipisahkan dengan tab.</li>
        <li>Menambah baris tidak perlu deploy ulang. Menghapus baris perlu deploy ulang Zeek.</li>
      </ul>
      <Code title="/opt/zeek/intel/zeek_intel.txt">{INTEL_TXT}</Code>
      <Code title="intelligence-demo.zeek">{ZEEK_INTEL_DEMO}</Code>
      <Term title="Mencocokkan indikator">{`
$ zeek -C -r case1.pcap intelligence-demo.zeek
$ cat intel.log | zeek-cut uid id.orig_h id.resp_h seen.indicator matched
`}</Term>
      <p>
        Domain <C>smart-fax.com</C> ada di daftar, jadi setiap kemunculannya di lalu lintas tercatat. Kolom <C>seen.where</C> memberi tahu
        di bagian mana indikator itu terlihat.
      </p>
    </>
  ),
  questions: [
    {
      id: 'z8-1',
      prompt: <>Jalankan <C>case1.pcap</C> dengan <C>intelligence-demo.zeek</C> dan periksa <C>intel.log</C>. Pada temuan kedua, di mana indikator itu terlihat?</>,
      answer: ['IN_HOST_HEADER', 'HTTP::IN_HOST_HEADER'],
      hint: <>Lihat kolom <C>seen.where</C>.</>,
    },
    {
      id: 'z8-2',
      prompt: <>Periksa <C>http.log</C>. Apa nama berkas .exe yang diunduh?</>,
      answer: ['knr.exe', '/knr.exe'],
      hint: <>Nama berkas ada di kolom <C>uri</C>.</>,
    },
    {
      id: 'z8-3',
      prompt: <>Jalankan <C>case1.pcap</C> dengan <C>hash-demo.zeek</C> dan periksa <C>files.log</C>. Apa hash MD5 berkas .exe itu?</>,
      answer: ['cc28e40b46237ab6d5282199ef78c464'],
      hint: <>Berkas .exe bertipe <C>application/x-dosexec</C> di kolom <C>mime_type</C>.</>,
    },
    {
      id: 'z8-4',
      prompt: <>Jalankan <C>case1.pcap</C> dengan <C>file-extract-demo.zeek</C>, lalu buka berkas teks di folder <C>extract_files</C>. Apa isinya?</>,
      answer: ['Microsoft NCSI'],
      hint: <>Cari berkas bertipe ASCII text dengan <C>file extract_files/*</C>, lalu <C>cat</C>.</>,
    },
  ],
}

export const task9: Task = {
  id: 9,
  title: 'Zeek Scripts: package',
  lead: 'Memasang dan memakai paket pihak ketiga dengan Zeek Package Manager (zkg).',
  dir: 'TASK-9',
  Body: () => (
    <>
      <p>
        Zeek Package Manager (<C>zkg</C>) memasang script dan plugin buatan komunitas untuk menambah kemampuan Zeek. Alat ini ikut
        terpasang bersama Zeek dan butuh hak root.
      </p>
      <Table
        head={['Perintah', 'Kegunaan']}
        rows={[
          [<C>zkg install package_path</C>, <>Pasang paket, contoh: <C>zkg install zeek/j-gras/zeek-af_packet-plugin</C></>],
          [<C>zkg install git_url</C>, <>Pasang dari Git, contoh: <C>zkg install https://github.com/corelight/ztest</C></>],
          [<C>zkg list</C>, 'Daftar paket terpasang'],
          [<C>zkg remove</C>, 'Hapus paket'],
          [<C>zkg refresh</C>, 'Periksa pembaruan paket terpasang'],
          [<C>zkg upgrade</C>, 'Perbarui paket terpasang'],
        ]}
      />

      <H>Tiga cara memakai paket</H>
      <ol>
        <li>Memanggilnya dari script dengan <C>@load</C> (paling umum).</li>
        <li>Menyebut path paketnya saat menjalankan Zeek.</li>
        <li>Menyebut nama paketnya saja. Cara ini hanya berlaku untuk paket yang dipasang lewat <C>zkg install</C>.</li>
      </ol>

      <H>Paket zeek-sniffpass: kata sandi tanpa enkripsi</H>
      <p>
        Paket ini memberi peringatan bila ada kata sandi terkirim polos lewat HTTP POST. Di Task 5 kita melakukannya dengan signature.
        Sekarang cukup dengan memuat paket.
      </p>
      <Term title="Di folder TASK-9/cleartext-pass">{`
$ cd ~/Desktop/Exercise-Files/TASK-9/cleartext-pass
$ zkg list
$ cat sniff-demo.zeek
$ zeek -Cr http.pcap sniff-demo.zeek
$ zeek -Cr http.pcap /opt/zeek/share/zeek/site/zeek-sniffpass
$ zeek -Cr http.pcap zeek-sniffpass
$ cat notice.log | zeek-cut id.orig_h id.resp_h proto note msg
`}</Term>
      <p>Ketiga cara menghasilkan <C>notice.log</C> yang sama, lengkap dengan nama pengguna yang kata sandinya terlihat.</p>

      <H>Paket geoip-conn: lokasi alamat IP</H>
      <p>
        Paket ini menambahkan kolom lokasi (negara, wilayah, kota, koordinat) ke <C>conn.log</C>. Datanya berasal dari basis data{' '}
        <C>GeoLite2-City.mmdb</C> buatan MaxMind, dan hanya terisi untuk alamat yang ada di basis data itu.
      </p>
      <Term title="Di folder TASK-9/geoip-conn">{`
$ cd ~/Desktop/Exercise-Files/TASK-9/geoip-conn
$ zeek -Cr case2.pcap geoip-conn
$ cat conn.log | zeek-cut uid id.orig_h id.resp_h geo.resp.country_code geo.resp.region geo.resp.city | head -n 5
`}</Term>
      <p>
        Masih banyak paket dan script lain di komunitas Zeek. Kamu bisa memakai yang sudah ada, atau mempelajari bahasa script Zeek dan
        menulis sendiri.
      </p>
      <Note kind="sim">
        Kedua paket sudah terpasang. <C>zkg install</C> untuk paket lain tidak berfungsi karena simulator tidak punya akses internet.
      </Note>
    </>
  ),
  questions: [
    {
      id: 'z9-1',
      prompt: <>Di <C>TASK-9/cleartext-pass</C>, jalankan <C>http.pcap</C> dengan <C>zeek-sniffpass</C> dan periksa <C>notice.log</C>. Nama pengguna mana yang paling banyak terdeteksi?</>,
      answer: ['BroZeek'],
      hint: <>Kolom <C>msg</C>, lalu <C>sort | uniq -c</C>.</>,
    },
    {
      id: 'z9-2',
      prompt: <>Di <C>TASK-9/geoip-conn</C>, jalankan <C>case2.pcap</C> dengan <C>geoip-conn</C> dan periksa <C>conn.log</C>. Kota apa yang teridentifikasi?</>,
      answer: ['Chicago'],
      hint: <>Lihat kolom <C>geo.resp.city</C>.</>,
    },
    {
      id: 'z9-3',
      prompt: 'Alamat IP mana yang terkait dengan kota itu?',
      answer: ['23.77.86.54'],
      hint: <>Tampilkan <C>geo.resp.city</C> berdampingan dengan <C>id.resp_h</C>.</>,
    },
    {
      id: 'z9-4',
      prompt: <>Jalankan <C>case2.pcap</C> dengan <C>sumstats-counttable.zeek</C>. Ada berapa jenis kode status di tangkapan itu?</>,
      answer: ['4'],
      hint: 'Keluaran script muncul langsung di terminal. Hitung kode status yang berbeda.',
    },
  ],
}

export const task10: Task = {
  id: 10,
  title: 'Penutup',
  lead: 'Rangkuman dan langkah berikutnya.',
  Body: () => (
    <>
      <p>Kamu sudah menyelesaikan modul Zeek. Yang sudah dipelajari:</p>
      <ul>
        <li>Beda pemantauan jaringan biasa dan NSM, dan posisi Zeek dibanding Snort.</li>
        <li>Arsitektur Zeek: Event Engine dan Policy Script Interpreter.</li>
        <li>Menjalankan Zeek sebagai layanan dan untuk membaca pcap.</li>
        <li>Membaca log, mengaitkannya lewat UID, dan mengambil kolom dengan <C>zeek-cut</C>.</li>
        <li>Merangkai <C>sort</C>, <C>uniq</C>, <C>grep</C>, dan kawan-kawannya untuk menjawab pertanyaan investigasi.</li>
        <li>Menulis signature, lalu menggabungkannya dengan script.</li>
        <li>Memakai framework berkas dan intelijen, serta paket dari <C>zkg</C>.</li>
      </ul>
      <H>Langkah berikutnya</H>
      <ul>
        <li>Pasang Zeek sungguhan (misalnya di Ubuntu atau lewat Docker) dan ulangi latihan dengan pcap publik.</li>
        <li>Pelajari bahasa script Zeek lebih dalam di docs.zeek.org.</li>
        <li>
          Uji kemampuanmu di modul <a href="#/zeek-exercises">Latihan Zeek</a>: tiga kasus investigasi.
        </li>
        <li>Modul Suricata akan menyusul di TryLearnMe.</li>
      </ul>
      <p>
        Butuh pengingat cepat? Buka <a href="#/zeek/cheatsheet">cheat sheet Zeek</a>.
      </p>
    </>
  ),
  questions: [{ id: 'z10-1', prompt: 'Baca rangkuman di atas.' }],
}
