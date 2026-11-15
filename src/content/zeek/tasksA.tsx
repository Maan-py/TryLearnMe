import type { Task } from '../types'
import { C, Code, H, Note, Table, Term } from '../ui'

export const task1: Task = {
  id: 1,
  title: 'Pengenalan',
  lead: 'Apa itu Zeek dan bagaimana modul ini disusun.',
  Body: () => (
    <>
      <p>
        Zeek (dulu bernama Bro) adalah alat pemantau jaringan yang bersifat pasif: ia mengamati lalu lintas tanpa mengubah atau memblokirnya.
        Hasil pengamatannya ditulis sebagai log yang rapi dan terperinci. Zeek tersedia sebagai proyek open-source dan juga dalam versi
        komersial.
      </p>
      <p>
        Banyak tim keamanan memakai Zeek sebagai Network Security Monitor (NSM) untuk menyelidiki aktivitas mencurigakan. Di luar keamanan,
        Zeek juga dipakai untuk mengukur kinerja dan mencari sumber gangguan jaringan.
      </p>
      <H>Cara belajar di modul ini</H>
      <ul>
        <li>Setiap task berisi ringkasan materi, lalu beberapa soal.</li>
        <li>
          Soal dijawab dengan menyelidiki log di <strong>terminal simulasi</strong>. Berkas latihan ada di{' '}
          <C>~/Desktop/Exercise-Files</C>, satu folder per task.
        </li>
        <li>
          Tombol <strong>Jalankan</strong> pada contoh perintah akan mengirim perintah itu ke terminal.
        </li>
        <li>
          Di setiap folder ada <C>./clear-logs.sh</C> untuk menghapus log lama sebelum mencoba lagi.
        </li>
      </ul>
      <Note kind="sim">
        Terminal di website ini tiruan. Perintah seperti <C>cat</C>, <C>zeek-cut</C>, <C>sort</C>, dan <C>grep</C> benar-benar mengolah
        data, tetapi <C>zeek -r</C> tidak membaca pcap sungguhan: ia memunculkan log yang sudah disiapkan. Ketik <C>help</C> untuk melihat
        perintah yang tersedia.
      </Note>
      <p>Bekal yang membantu: dasar Linux (pindah folder, membaca berkas) dan dasar jaringan (port, protokol, alamat IP).</p>
    </>
  ),
  questions: [{ id: 'z1-1', prompt: 'Baca materi di atas, lalu coba ketik help di terminal.' }],
}

export const task2: Task = {
  id: 2,
  title: 'Network Security Monitoring dan Zeek',
  lead: 'Beda pemantauan jaringan biasa dan NSM, arsitektur Zeek, dan cara menjalankannya.',
  dir: 'TASK-2',
  Body: () => (
    <>
      <H>Dua jenis pemantauan jaringan</H>
      <Table
        head={['', 'Network Monitoring', 'Network Security Monitoring (NSM)']}
        rows={[
          ['Fokus', 'Kesehatan aset TI: ketersediaan, kinerja, konfigurasi', 'Anomali keamanan: host liar, layanan dan port janggal, pola serangan'],
          ['Dipakai oleh', 'Administrator jaringan', 'Analis SOC, incident responder, threat hunter'],
          ['Hasilnya', 'Jaringan lancar dan gangguan cepat ditemukan', 'Ancaman terdeteksi dan bisa diselidiki'],
        ]}
      />
      <p>
        Pemantauan jaringan biasa tidak dirancang untuk menemukan ancaman dari dalam atau celah yang belum dikenal. Itu wilayah NSM, dan di
        sanalah Zeek bekerja.
      </p>

      <H>Zeek dibanding Snort</H>
      <Table
        head={['', 'Zeek', 'Snort']}
        rows={[
          ['Sifat', 'Kerangka NSM dan IDS yang berfokus pada analisis lalu lintas dan peristiwa', 'IDS/IPS yang berfokus pada signature dan paket'],
          ['Kelebihan', 'Log mendalam dan mudah dibaca, bahasa script sendiri, bisa mengaitkan banyak peristiwa, cocok untuk threat hunting', 'Rule mudah ditulis, dukungan komunitas dan Cisco besar'],
          ['Kekurangan', 'Lebih sulit dipelajari, analisis dilakukan di luar Zeek (manual atau otomatis)', 'Sulit mendeteksi ancaman yang rumit'],
          ['Cocok untuk', 'Investigasi mendalam dan deteksi rangkaian peristiwa', 'Mendeteksi dan menghentikan serangan yang sudah dikenal'],
        ]}
      />

      <H>Arsitektur Zeek</H>
      <p>Zeek punya dua lapisan utama:</p>
      <ol>
        <li>
          <strong>Event Engine</strong> memproses paket. Ia memecah lalu lintas menjadi peristiwa netral: alamat sumber dan tujuan, protokol
          yang dikenali, sesi, dan berkas yang lewat. Lapisan ini belum menilai baik atau buruk.
        </li>
        <li>
          <strong>Policy Script Interpreter</strong> menjalankan script Zeek atas peristiwa tadi. Di sinilah makna diberikan: peristiwa
          dikaitkan satu sama lain, lalu ditulis sebagai log atau pemberitahuan.
        </li>
      </ol>
      <Code title="Alur data">{`
Paket jaringan ─► Event Engine ─► Policy Script Interpreter ─► Log (50+ jenis, 7 kategori)
                   (peristiwa)        (script Zeek)          └► Notice (pemberitahuan)
`}</Code>

      <H>Framework</H>
      <p>
        Kemampuan tambahan Zeek dikemas sebagai framework di lapisan script, misalnya Logging, Notice, Input, Intelligence, File Analysis,
        Signature, Summary Statistics, GeoLocation, dan NetControl. Yang selalu terpakai adalah Logging. Beberapa lainnya dibahas di Task 8.
      </p>

      <H>Menjalankan Zeek</H>
      <p>Ada dua cara pakai:</p>
      <ul>
        <li>
          <strong>Sebagai layanan</strong>, untuk memantau lalu lintas langsung. Layanan diatur lewat ZeekControl (<C>zeekctl</C>) dan butuh
          hak superuser. Log tersimpan di <C>/opt/zeek/logs/</C>.
        </li>
        <li>
          <strong>Membaca berkas pcap</strong>, untuk menyelidiki tangkapan lalu lintas. Log ditulis ke folder tempat perintah dijalankan.
        </li>
      </ul>
      <Term title="ZeekControl">{`
$ sudo su
$ zeekctl status
$ zeekctl start
$ zeekctl status
$ zeekctl stop
$ exit
`}</Term>
      <Term title="Membaca pcap">{`
$ zeek -C -r sample.pcap
$ ls -l
`}</Term>
      <Table
        head={['Parameter', 'Arti']}
        rows={[
          [<C>-r</C>, 'Baca dan proses sebuah berkas pcap'],
          [<C>-C</C>, 'Abaikan galat checksum'],
          [<C>-v</C>, 'Tampilkan versi Zeek'],
          [<C>zeekctl</C>, 'Modul ZeekControl'],
        ]}
      />
      <Note kind="sim">
        Mode interaktif <C>zeekctl</C> tidak ada di simulator. Pakai bentuk langsung: <C>zeekctl status</C>, <C>zeekctl start</C>,{' '}
        <C>zeekctl stop</C>.
      </Note>
    </>
  ),
  questions: [
    { id: 'z2-1', prompt: 'Versi Zeek berapa yang terpasang?', answer: ['4.2.1'], hint: <>Jalankan <C>zeek -v</C>.</> },
    { id: 'z2-2', prompt: 'Versi modul ZeekControl berapa?', answer: ['2.4.0'], hint: <>Jalankan <C>zeekctl</C> dan baca sambutannya.</> },
    {
      id: 'z2-3',
      prompt: <>Proses <C>sample.pcap</C> dengan Zeek. Berapa berkas log yang dihasilkan?</>,
      answer: ['8'],
      hint: <>Setelah <C>zeek -C -r sample.pcap</C>, hitung berkas berakhiran <C>.log</C> yang muncul di <C>ls</C>.</>,
    },
  ],
}

export const task3: Task = {
  id: 3,
  title: 'Zeek Logs',
  lead: 'Jenis-jenis log, cara membacanya, dan cara mengambil kolom dengan zeek-cut.',
  dir: 'TASK-3',
  Body: () => (
    <>
      <p>
        Zeek menulis log untuk setiap koneksi yang ia lihat, sampai ke protokol tingkat aplikasi. Ada lebih dari 50 jenis log dalam tujuh
        kategori. Formatnya teks ASCII dengan kolom yang dipisahkan tab, jadi mudah diolah dengan alat baris perintah.
      </p>
      <p>
        Setiap baris log terdiri atas beberapa field. Kunci untuk mengaitkan log yang berbeda adalah <strong>UID</strong>, pengenal unik
        untuk setiap sesi. Koneksi yang sama memakai UID yang sama di <C>conn.log</C>, <C>http.log</C>, <C>files.log</C>, dan lainnya.
      </p>

      <H>Tujuh kategori log</H>
      <Table
        head={['Kategori', 'Isi', 'Contoh berkas']}
        rows={[
          ['Network', 'Log protokol jaringan', 'conn.log, dns.log, dhcp.log, http.log, ftp.log, ssh.log, ssl.log, ntp.log'],
          ['Files', 'Hasil analisis berkas', 'files.log, pe.log, x509.log'],
          ['NetControl', 'Kendali dan aliran jaringan', 'netcontrol.log, openflow.log'],
          ['Detection', 'Deteksi dan indikator', 'notice.log, signatures.log, intel.log, traceroute.log'],
          ['Network Observations', 'Ringkasan yang diamati di jaringan', 'known_hosts.log, known_services.log, software.log'],
          ['Miscellaneous', 'Catatan tambahan: script luar, kejadian aneh', 'weird.log, loaded_scripts.log, dpd.log'],
          ['Zeek Diagnostic', 'Kesehatan Zeek sendiri', 'stats.log, capture_loss.log, packet_filter.log, reporter.log'],
        ]}
      />

      <H>Log mana yang dibuka dulu</H>
      <Table
        head={['Gambaran umum', 'Per protokol', 'Deteksi', 'Pengamatan']}
        rows={[
          ['conn.log', 'http.log', 'notice.log', 'known_hosts.log'],
          ['files.log', 'dns.log', 'signatures.log', 'known_services.log'],
          ['intel.log', 'ftp.log', 'pe.log', 'software.log'],
          ['loaded_scripts.log', 'ssh.log', 'traceroute.log', 'weird.log'],
        ]}
      />
      <ol>
        <li><strong>Gambaran umum:</strong> lihat seluruh koneksi, berkas, dan indikator sekaligus.</li>
        <li><strong>Per protokol:</strong> setelah ada yang mencurigakan, dalami protokolnya.</li>
        <li><strong>Deteksi:</strong> pakai hasil signature dan script untuk menguatkan temuan.</li>
        <li><strong>Pengamatan:</strong> ringkasan host, layanan, dan perangkat lunak membantu menutup celah penyelidikan.</li>
      </ol>
      <p>Tabel ini hanya titik awal. Log yang perlu dibuka selalu bergantung pada kasus dan dugaanmu.</p>

      <H>Membaca log mentah</H>
      <p>
        Bagian atas setiap log berisi header. Dua baris terpenting adalah <C>#fields</C> (nama kolom) dan <C>#types</C> (tipe datanya).
      </p>
      <Term title="Isi conn.log">{`
$ zeek -C -r sample.pcap
$ head -n 10 conn.log
`}</Term>

      <H>zeek-cut</H>
      <p>
        Membaca log mentah cepat melelahkan. <C>zeek-cut</C> mengambil kolom tertentu berdasarkan namanya. Yang dipakai adalah nama di baris{' '}
        <C>#fields</C>, bukan <C>#types</C>.
      </p>
      <Term title="Mengambil kolom">{`
$ cat conn.log | zeek-cut uid proto id.orig_h id.orig_p id.resp_h id.resp_p | head -n 5
`}</Term>
      <p>Hasil <C>zeek-cut</C> bisa langsung diteruskan ke alat lain:</p>
      <Term title="Layanan yang paling sering muncul">{`
$ cat conn.log | zeek-cut service | sort | uniq -c | sort -nr
`}</Term>
    </>
  ),
  questions: [
    {
      id: 'z3-1',
      prompt: <>Proses <C>sample.pcap</C>, lalu periksa <C>dhcp.log</C>. Apa hostname yang tercatat?</>,
      answer: ['Microknoppix'],
      hint: <>Kolomnya bernama <C>host_name</C>.</>,
    },
    {
      id: 'z3-2',
      prompt: <>Periksa <C>dns.log</C>. Ada berapa query DNS yang unik?</>,
      answer: ['2'],
      hint: <>Ambil kolom <C>query</C>, lalu <C>sort | uniq</C>.</>,
    },
    {
      id: 'z3-3',
      prompt: <>Periksa <C>conn.log</C>. Berapa durasi koneksi yang paling lama?</>,
      answer: ['332.319364'],
      hint: <>Ambil kolom <C>duration</C>, urutkan dengan <C>sort -n</C>, lihat baris terakhir.</>,
    },
  ],
}

export const task4: Task = {
  id: 4,
  title: 'CLI Kung-Fu: mengolah log di baris perintah',
  lead: 'Perintah Linux yang paling sering dipakai untuk menyaring, mengurutkan, dan menghitung isi log.',
  dir: 'TASK-4',
  Body: () => (
    <>
      <p>
        Antarmuka grafis enak untuk melihat data, tetapi kewalahan saat datanya sangat besar, dan tidak selalu punya tombol untuk hal yang
        kamu cari. Di baris perintah, kamu merangkai sendiri alat-alat kecil sampai mendapat persis yang dibutuhkan. Kemampuan ini dipakai
        di semua task berikutnya.
      </p>

      <H>Membaca berkas</H>
      <Table
        head={['Perintah', 'Kegunaan']}
        rows={[
          [<C>cat access.txt</C>, 'Tampilkan seluruh isi'],
          [<C>head access.txt</C>, '10 baris pertama (-n 3 untuk 3 baris)'],
          [<C>tail access.txt</C>, '10 baris terakhir'],
          [<C>history</C>, 'Riwayat perintah yang sudah diketik'],
        ]}
      />

      <H>Mencari dan menyaring</H>
      <Table
        head={['Perintah', 'Kegunaan']}
        rows={[
          [<C>cut -f 1</C>, 'Ambil kolom ke-1 (pemisah bawaan: tab)'],
          [<C>cut -d ' ' -f 1</C>, 'Ambil kolom ke-1 dengan pemisah spasi'],
          [<C>cut -c1</C>, 'Ambil karakter ke-1'],
          [<C>grep 'kata'</C>, 'Baris yang mengandung "kata"'],
          [<C>grep -v 'kata'</C>, 'Baris yang tidak mengandung "kata"'],
          [<C>grep -v -e 'a' -e 'b'</C>, 'Buang baris yang mengandung "a" atau "b"'],
          [<C>sort</C>, 'Urutkan menurut abjad'],
          [<C>sort -n</C>, 'Urutkan menurut angka'],
          [<C>sort -nr</C>, 'Urutkan menurut angka, terbesar dulu'],
          [<C>uniq</C>, 'Buang baris kembar yang berurutan'],
          [<C>uniq -c</C>, 'Buang baris kembar dan hitung kemunculannya'],
          [<C>wc -l</C>, 'Hitung jumlah baris'],
          [<C>nl</C>, 'Beri nomor baris'],
          [<C>rev</C>, 'Balik urutan karakter tiap baris'],
        ]}
      />
      <Note kind="warn">
        <C>uniq</C> hanya menggabungkan baris kembar yang <em>bersebelahan</em>. Karena itu hampir selalu didahului <C>sort</C>.
      </Note>

      <H>Lanjutan</H>
      <Table
        head={['Perintah', 'Kegunaan']}
        rows={[
          [<C>sed -n '11p'</C>, 'Cetak baris ke-11'],
          [<C>sed -n '10,15p'</C>, 'Cetak baris 10 sampai 15'],
          [<C>{"awk 'NR < 11 {print $0}'"}</C>, 'Cetak baris sebelum baris ke-11'],
          [<C>{"awk 'NR == 11 {print $0}'"}</C>, 'Cetak baris ke-11'],
          [<C>{"awk '{print $1, $3}'"}</C>, 'Cetak kolom ke-1 dan ke-3'],
          [<C>grep -rin Nilai * | column -t | less -S</C>, 'Cari "Nilai" di semua berkas, rapikan kolomnya'],
          [<C>cat signatures.log | zeek-cut uid src_addr dst_addr</C>, 'Khusus log Zeek: ambil kolom berdasarkan nama'],
        ]}
      />

      <H>Pola yang paling sering dipakai</H>
      <Table
        head={['Rangkaian', 'Hasil']}
        rows={[
          [<C>sort | uniq</C>, 'Daftar nilai unik'],
          [<C>sort | uniq | wc -l</C>, 'Jumlah nilai unik'],
          [<C>sort | uniq -c</C>, 'Nilai unik beserta jumlah kemunculannya'],
          [<C>sort | uniq -c | sort -nr</C>, 'Peringkat: yang paling sering muncul di atas'],
        ]}
      />

      <H>Latihan</H>
      <p>
        Folder <C>TASK-4</C> berisi <C>access.txt</C>, catatan akses web sederhana dengan empat kolom yang dipisahkan spasi: alamat IP,
        metode, path, dan kode status.
      </p>
      <Term title="Coba dulu">{`
$ cat access.txt
$ cat access.txt | cut -d ' ' -f 4 | sort | uniq -c
`}</Term>
    </>
  ),
  questions: [
    {
      id: 'z4-1',
      prompt: <>Di <C>access.txt</C>, ada berapa alamat IP yang unik?</>,
      answer: ['5'],
      hint: <>Ambil kolom pertama dengan <C>cut -d ' ' -f 1</C>, lalu <C>sort | uniq | wc -l</C>.</>,
    },
    {
      id: 'z4-2',
      prompt: 'Alamat IP mana yang paling sering muncul?',
      answer: ['10.0.0.12'],
      hint: <>Pakai pola peringkat: <C>sort | uniq -c | sort -nr</C>.</>,
    },
    {
      id: 'z4-3',
      prompt: 'Path apa yang diminta pada baris ke-11?',
      answer: ['/backup.zip', 'backup.zip'],
      hint: <>Cetak baris ke-11 dengan <C>sed -n '11p'</C>.</>,
    },
  ],
}
