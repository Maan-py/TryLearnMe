import type { Task } from '../types'
import { C, Code, H, Note, Table, Term } from '../ui'
import { SIG_FTP_ADMIN, SIG_FTP_BRUTE, SIG_HTTP_PASSWORD, ZEEK_101, ZEEK_102, ZEEK_103, ZEEK_201, ZEEK_DHCP } from '../../terminal/lab'

export const task5: Task = {
  id: 5,
  title: 'Zeek Signatures',
  lead: 'Menulis aturan pencocokan pola dan membaca hasilnya di signatures.log dan notice.log.',
  dir: 'TASK-5',
  Body: () => (
    <>
      <p>
        Signature di Zeek mencocokkan pola tingkat rendah pada lalu lintas, mirip rule Snort. Bedanya, signature bukan cara deteksi utama
        Zeek. Kekuatan Zeek ada di script yang bisa merangkai banyak peristiwa, dan signature adalah salah satu masukannya.
      </p>

      <H>Tiga bagian signature</H>
      <Table
        head={['Bagian', 'Isi']}
        rows={[
          ['Signature id', 'Nama unik signature'],
          ['Conditions', <><strong>Header:</strong> saring berdasarkan alamat, protokol, dan port. <strong>Content:</strong> saring isi paket berdasarkan nilai atau pola.</>],
          ['Action', <><strong>Bawaan:</strong> tulis ke <C>signatures.log</C> saat cocok. <strong>Tambahan:</strong> picu sebuah script Zeek.</>],
        ]}
      />

      <H>Filter yang sering dipakai</H>
      <Table
        head={['Kelompok', 'Filter']}
        rows={[
          ['Header', <><C>src-ip</C>, <C>dst-ip</C>, <C>src-port</C>, <C>dst-port</C>, <C>ip-proto</C> (tcp, udp, icmp, icmp6, ip, ip6)</>],
          ['Content', <><C>payload</C> (isi paket), <C>http-request</C>, <C>http-request-header</C>, <C>http-request-body</C>, <C>http-reply-header</C>, <C>http-reply-body</C>, <C>ftp</C> (perintah pada sesi FTP)</>],
          ['Context', <><C>same-ip</C>: alamat sumber dan tujuan sama</>],
          ['Action', <><C>event</C>: pesan saat signature cocok</>],
          ['Pembanding', <><C>==</C>, <C>!=</C>, <C>&lt;</C>, <C>&lt;=</C>, <C>&gt;</C>, <C>&gt;=</C></>],
        ]}
      />
      <p>Filter menerima teks, angka, dan regex. Berkas signature berakhiran <C>.sig</C> dan dipakai dengan opsi <C>-s</C>:</p>
      <Code title="Menjalankan Zeek dengan signature">{`zeek -C -r sample.pcap -s sample.sig`}</Code>

      <H>Contoh 1: kata sandi HTTP tanpa enkripsi</H>
      <Code title="http-password.sig">{SIG_HTTP_PASSWORD}</Code>
      <p>
        Regex <C>.*</C> berarti "karakter apa pun, berapa kali pun". Jadi signature ini cocok bila kata <C>password</C> muncul di isi paket
        TCP menuju port 80. Saat cocok, Zeek menulis <C>signatures.log</C> dan <C>notice.log</C>.
      </p>
      <Term title="Di folder TASK-5/http">{`
$ cd ~/Desktop/Exercise-Files/TASK-5/http
$ zeek -C -r http.pcap -s http-password.sig
$ ls
$ cat notice.log | zeek-cut id.orig_h id.resp_h msg
$ cat signatures.log | zeek-cut src_addr dst_addr sig_id event_msg
`}</Term>
      <p>
        Kedua log juga menyimpan potongan isi paket yang memicu signature, di kolom <C>sub_msg</C> (signatures.log) dan <C>sub</C>{' '}
        (notice.log):
      </p>
      <Term>{`
$ cat signatures.log | zeek-cut sub_msg
`}</Term>

      <H>Contoh 2: percobaan login FTP</H>
      <p>
        Filter <C>ftp</C> membaca perintah yang diketik pada sesi FTP. Signature berikut menangkap percobaan login dengan nama pengguna yang
        mengandung "admin":
      </p>
      <Code title="ftp-admin.sig">{SIG_FTP_ADMIN}</Code>
      <Term title="Di folder TASK-5/ftp">{`
$ cd ~/Desktop/Exercise-Files/TASK-5/ftp
$ zeek -C -r ftp.pcap -s ftp-admin.sig
$ cat signatures.log | zeek-cut src_addr dst_addr event_msg sub_msg | sort -r | uniq
`}</Term>
      <p>
        Hasilnya menunjukkan banyak percobaan untuk akun <C>admin</C> dan <C>administrator</C>, tanda kemungkinan brute-force. Namun
        signature ini sempit: hanya untuk satu kasus. Membuat satu signature untuk tiap kasus akan menghasilkan banjir log dan peringatan,
        sehingga anomali yang sebenarnya justru terlewat. Prinsipnya: catat yang masuk akal, bukan semuanya.
      </p>

      <H>Membuatnya lebih umum</H>
      <p>
        Server FTP menjawab login gagal dengan kode <strong>530</strong>. Dengan mencocokkan jawaban itu, kita menangkap semua login gagal,
        siapa pun nama penggunanya. Satu berkas boleh berisi beberapa signature:
      </p>
      <Code title="ftp-bruteforce.sig">{SIG_FTP_BRUTE}</Code>
      <Term>{`
$ zeek -C -r ftp.pcap -s ftp-bruteforce.sig
$ cat notice.log | zeek-cut uid id.orig_h id.resp_h msg sub | sort -r | nl | sed -n '1001,1004p'
`}</Term>
      <p>
        Sekarang ada dua jenis peringatan yang bisa dikaitkan lewat UID: nama pengguna yang dicoba (<C>ftp-username</C>) dan kegagalan
        loginnya (<C>ftp-brute</C>).
      </p>
      <Note>
        Saat masih bernama Bro, Zeek punya script <C>snort2bro</C> untuk mengubah rule Snort menjadi signature. Script itu sudah tidak
        didukung dan tidak lagi disertakan dalam Zeek.
      </Note>
      <Note kind="sim">
        Simulator tidak punya editor teks, jadi ketiga berkas <C>.sig</C> di atas sudah tersedia di foldernya. Lihat isinya dengan{' '}
        <C>cat</C>.
      </Note>
    </>
  ),
  questions: [
    {
      id: 'z5-1',
      prompt: <>Di <C>TASK-5/http</C>, jalankan Zeek pada <C>http.pcap</C> dengan <C>http-password.sig</C>. Apa IP sumber peristiwa pertama?</>,
      answer: ['10.10.57.178'],
      hint: <>Lihat kolom <C>src_addr</C> di <C>signatures.log</C>.</>,
    },
    {
      id: 'z5-2',
      prompt: 'Berapa port sumber peristiwa kedua?',
      answer: ['38712'],
      hint: <>Kolom <C>src_port</C> di <C>signatures.log</C>, baris kedua.</>,
    },
    {
      id: 'z5-3',
      prompt: <>Periksa <C>conn.log</C>. Berapa jumlah paket yang dikirim dan diterima oleh port sumber 38706?</>,
      answer: ['20'],
      hint: <>Jumlahkan <C>orig_pkts</C> dan <C>resp_pkts</C> untuk baris dengan <C>id.orig_p</C> 38706.</>,
    },
    {
      id: 'z5-4',
      prompt: <>Di <C>TASK-5/ftp</C>, jalankan Zeek pada <C>ftp.pcap</C> dengan <C>ftp-bruteforce.sig</C>. Ada berapa peristiwa unik di <C>notice.log</C>?</>,
      answer: ['1413'],
      hint: <>Satu peristiwa = satu UID. Hitung UID yang unik.</>,
    },
    {
      id: 'z5-5',
      prompt: <>Berapa kali signature <C>ftp-brute</C> cocok?</>,
      answer: ['1410'],
      hint: <>Ambil kolom <C>msg</C>, saring dengan <C>grep -i brute</C>, lalu hitung barisnya.</>,
    },
  ],
}

export const task6: Task = {
  id: 6,
  title: 'Zeek Scripts: dasar',
  lead: 'Di mana script disimpan, cara memuatnya, dan mengapa script lebih praktis daripada merangkai alat lain.',
  dir: 'TASK-6',
  Body: () => (
    <>
      <p>
        Zeek punya bahasa script sendiri yang digerakkan oleh peristiwa (<em>event-driven</em>). Kemampuannya setara bahasa pemrograman
        tingkat tinggi, sehingga kita bisa menyelidiki dan mengaitkan peristiwa yang terdeteksi. Script yang menerapkan sebuah kebijakan
        disebut <em>policy script</em>.
      </p>

      <H>Lokasi script</H>
      <Table
        head={['Jenis', 'Lokasi']}
        rows={[
          ['Base script bawaan (jangan diubah)', <C>/opt/zeek/share/zeek/base</C>],
          ['Script buatan atau hasil modifikasi pengguna', <C>/opt/zeek/share/zeek/site</C>],
          ['Policy script', <C>/opt/zeek/share/zeek/policy</C>],
          ['Berkas konfigurasi untuk mode pemantauan langsung', <C>/opt/zeek/share/zeek/site/local.zeek</C>],
        ]}
      />
      <ul>
        <li>Berkas script berakhiran <C>.zeek</C>.</li>
        <li>
          Agar sebuah script selalu dipakai saat memantau lalu lintas langsung, daftarkan di <C>local.zeek</C> dengan{' '}
          <C>@load /path/script</C> atau <C>@load nama-script</C>.
        </li>
        <li>Untuk sekali jalan, cukup sebutkan nama script di akhir perintah, sama seperti signature.</li>
        <li>Zeek berorientasi peristiwa, bukan paket. Script ditulis untuk menangani peristiwa yang kita minati.</li>
      </ul>

      <H>Script dibanding alat lain</H>
      <p>
        Misalkan kita perlu daftar hostname DHCP dari sebuah pcap. Dengan Wireshark, datanya terlihat tetapi sulit diteruskan ke alat lain.
        Dengan <C>tcpdump</C> atau <C>tshark</C> bisa, tetapi rangkaian perintahnya panjang:
      </p>
      <Code title="Cara tcpdump dan tshark (tidak tersedia di simulator)">{`
sudo tcpdump -ntr smallFlows.pcap port 67 or port 68 -e -vv | grep 'Hostname Option' | awk -F: '{print $2}' | sort -nr | uniq | nl

tshark -V -r smallFlows.pcap -Y "udp.port==67 or udp.port==68" -T fields -e dhcp.option.hostname | nl | awk NF
`}</Code>
      <p>Dengan Zeek, cukup script empat baris. Hanya baris ketiga yang kita tulis sendiri, sisanya kerangka baku bahasa script:</p>
      <Code title="dhcp-hostname.zeek">{ZEEK_DHCP}</Code>
      <Term title="Di folder TASK-6/smallflow">{`
$ cd ~/Desktop/Exercise-Files/TASK-6/smallflow
$ zeek -C -r smallFlows.pcap dhcp-hostname.zeek
`}</Term>

      <H>Sumber peristiwa</H>
      <p>
        Peristiwa yang bisa ditangani script berasal dari penganalisis protokol dan fungsi bawaan (<em>built-in function</em>, disingkat
        BIF). Daftarnya bisa dilihat di instalasi Zeek:
      </p>
      <Code title="Lokasi">{`
/opt/zeek/share/zeek/base/bif
/opt/zeek/share/zeek/base/bif/plugins
/opt/zeek/share/zeek/base/protocols
`}</Code>
      <H>Pcap asli untuk dicoba di mesin sendiri</H>
      <p>
        Dua pcap di task ini adalah berkas publik dari proyek Tcpreplay. Kalau kamu punya Zeek, Wireshark, atau tshark sungguhan, kamu
        bisa menganalisis berkas aslinya:
      </p>
      <ul>
        <li>
          <a href={`${import.meta.env.BASE_URL}pcaps/smallFlows.pcap`} download>
            Unduh smallFlows.pcap
          </a>{' '}
          (9 MB, 14.261 paket). Hostname dan domain DHCP di dalamnya sama dengan yang ada di simulator.
        </li>
        <li>
          <a href="https://s3.amazonaws.com/tcpreplay-pcap-files/bigFlows.pcap" target="_blank" rel="noreferrer">
            bigFlows.pcap di server Tcpreplay
          </a>{' '}
          (368 MB, diunduh langsung dari sumbernya).
        </li>
      </ul>
      <Note kind="sim">
        Terminal simulasi tidak membaca berkas unduhan ini. Log di simulator tetap data buatan, jadi angka seperti jumlah query DNS bisa
        berbeda dari hasil Zeek asli.
      </Note>
      <Note>
        Modul ini membahas logika dan cara pakai script, bukan bahasa script-nya secara lengkap. Untuk mendalami bahasanya, Zeek
        menyediakan dokumentasi dan latihan resmi di docs.zeek.org.
      </Note>
    </>
  ),
  questions: [
    {
      id: 'z6-1',
      prompt: <>Di <C>TASK-6/smallflow</C>, proses <C>smallFlows.pcap</C> dan periksa <C>dhcp.log</C>. Apa nilai domain untuk host "vinlap01"?</>,
      answer: ['astaro_vineyard'],
      hint: <>Ambil kolom <C>host_name</C> dan <C>domain</C>.</>,
    },
    {
      id: 'z6-2',
      prompt: <>Di <C>TASK-6/bigflow</C>, proses <C>bigFlows.pcap</C> dan periksa <C>dhcp.log</C>. Ada berapa hostname unik?</>,
      answer: ['17'],
      hint: <>Kolom <C>host_name</C>, lalu <C>sort | uniq | wc -l</C>.</>,
    },
    {
      id: 'z6-3',
      prompt: <>Masih di <C>dhcp.log</C> yang sama, apa nilai domainnya?</>,
      answer: ['jaalam.net'],
    },
    {
      id: 'z6-4',
      prompt: <>Periksa <C>dns.log</C>. Ada berapa query unik?</>,
      answer: ['1109'],
      hint: <>Buang dulu query kosong (<C>-</C>) dan wildcard (<C>*</C>) dengan <C>grep -v -e '*' -e '-'</C>.</>,
    },
  ],
}

export const task7: Task = {
  id: 7,
  title: 'Zeek Scripts: script dan signature',
  lead: 'Menulis script sederhana, menggabungkannya dengan signature, dan memuat script bawaan.',
  dir: 'TASK-7',
  Body: () => (
    <>
      <H>Scripts 101: script pertama</H>
      <p>
        Script berisi operator, tipe, atribut, deklarasi, pernyataan, dan direktif. Dua peristiwa paling sederhana adalah <C>zeek_init</C>{' '}
        dan <C>zeek_done</C>, yang terpicu saat proses Zeek mulai dan selesai. Keduanya tidak punya parameter.
      </p>
      <Code title="101.zeek">{ZEEK_101}</Code>
      <Term title="Di folder TASK-7/101">{`
$ cd ~/Desktop/Exercise-Files/TASK-7/101
$ zeek -C -r sample.pcap 101.zeek
`}</Term>
      <p>Pesan dari script muncul di terminal. Log tetap ditulis ke folder seperti biasa.</p>

      <p>
        Berikutnya, peristiwa <C>new_connection</C> terpicu untuk setiap koneksi baru. Script ini mencetak seluruh data koneksi apa adanya:
      </p>
      <Code title="102.zeek">{ZEEK_102}</Code>
      <Term>{`
$ zeek -C -r sample.pcap 102.zeek | head -n 2
`}</Term>
      <p>
        Keluarannya terlalu padat untuk dibaca. Perhatikan strukturnya: data koneksi tersimpan dalam <C>c</C> (dari <C>c: connection</C>),
        dan di dalamnya ada <C>id</C> dengan field yang sama seperti di log. Kita bisa mengambil bagian tertentu dengan tanda{' '}
        <C>$</C>:
      </p>
      <Code title="103.zeek">{ZEEK_103}</Code>
      <Term>{`
$ zeek -C -r sample.pcap 103.zeek | head -n 6
`}</Term>

      <H>Scripts 201: script bersama signature</H>
      <p>
        Script bisa merujuk signature dan script lain, dan dari sinilah kemampuan mengaitkan peristiwa berasal. Script berikut memakai
        peristiwa <C>signature_match</C> untuk memberi tahu setiap kali signature <C>ftp-admin</C> cocok:
      </p>
      <Code title="201.zeek">{ZEEK_201}</Code>
      <Term title="Di folder TASK-7/201">{`
$ cd ~/Desktop/Exercise-Files/TASK-7/201
$ zeek -C -r ftp.pcap -s ftp-admin.sig 201.zeek | head -n 3
`}</Term>

      <H>Scripts 202: memuat script lokal</H>
      <p>
        Perintah <C>local</C> memuat semua script yang terdaftar di <C>local.zeek</C>. Hasilnya, muncul log tambahan seperti{' '}
        <C>loaded_scripts.log</C>, <C>capture_loss.log</C>, dan <C>stats.log</C>. Script yang tidak menemukan apa-apa tidak menghasilkan
        log.
      </p>
      <Term>{`
$ zeek -C -r ftp.pcap local
$ ls
`}</Term>
      <p>
        Cara lain adalah menyebut path script tertentu. Zeek sudah punya script pendeteksi brute-force FTP, jadi kita bisa membandingkannya
        dengan signature buatan sendiri:
      </p>
      <Term>{`
$ zeek -C -r ftp.pcap /opt/zeek/share/zeek/policy/protocols/ftp/detect-bruteforcing.zeek
$ cat notice.log | zeek-cut ts note msg
`}</Term>
      <p>
        Script bawaan ini merangkum kejadian dalam satu baris: siapa pelakunya, berapa kali gagal, dan dalam waktu berapa lama. Jauh lebih
        ringkas daripada ribuan baris dari signature kita.
      </p>
    </>
  ),
  questions: [
    {
      id: 'z7-1',
      prompt: <>Di <C>TASK-7/101</C>, jalankan <C>sample.pcap</C> dengan <C>103.zeek</C>. Berapa koneksi baru yang terdeteksi di keluaran terminal?</>,
      answer: ['87'],
      hint: <>Teruskan keluarannya ke <C>grep "New Connection" | wc -l</C>.</>,
    },
    {
      id: 'z7-2',
      prompt: <>Di <C>TASK-7/201</C>, jalankan <C>ftp.pcap</C> dengan <C>ftp-admin.sig</C> dan <C>201.zeek</C>. Berapa kali signature cocok menurut <C>signatures.log</C>?</>,
      answer: ['1401'],
      hint: <>Ambil satu kolom dengan <C>zeek-cut</C> agar header tidak ikut terhitung, lalu <C>wc -l</C>.</>,
    },
    {
      id: 'z7-3',
      prompt: <>Di <C>signatures.log</C> itu, berapa kali nama pengguna "administrator" terdeteksi?</>,
      answer: ['731'],
      hint: <>Nama pengguna ada di kolom <C>sub_msg</C>.</>,
    },
    {
      id: 'z7-4',
      prompt: <>Jalankan <C>ftp.pcap</C> dengan semua script lokal, lalu periksa <C>loaded_scripts.log</C>. Berapa script yang dimuat?</>,
      answer: ['498'],
      hint: <>Jalankan dengan <C>local</C>, lalu hitung baris kolom <C>name</C>.</>,
    },
    {
      id: 'z7-5',
      prompt: <>Di <C>TASK-7/202</C>, jalankan <C>ftp-brute.pcap</C> dengan script <C>detect-bruteforcing.zeek</C>. Berapa deteksi brute-force di <C>notice.log</C>?</>,
      answer: ['2'],
      hint: <>Path script-nya: <C>/opt/zeek/share/zeek/policy/protocols/ftp/detect-bruteforcing.zeek</C>.</>,
    },
  ],
}
