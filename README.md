# TryLearnMe

Website belajar keamanan jaringan dengan terminal simulasi. Modul pertama: **Zeek** (10 task). Modul Suricata menyusul.

## Menjalankan

```
npm install
npm run dev      # buka http://localhost:5173
npm run build    # hasil statis di folder dist/
npm test         # uji mesin terminal dan jawaban soal
```

## Struktur

- `src/content/zeek/` : materi dan soal per task, serta cheat sheet
- `src/terminal/` : shell mini (pipe, redirect), perintah (`cat`, `grep`, `sort`, `zeek-cut`, ...), dan `zeek` tiruan
- `src/terminal/data/` : pembuat log tiruan untuk tiap pcap latihan
- `src/pages/`, `src/components/` : halaman dan komponen antarmuka

## Catatan

- Terminalnya simulasi. `zeek -r` tidak membaca pcap sungguhan, tetapi memunculkan log yang sudah disiapkan. Perintah pengolah teks benar-benar memproses log itu.
- Progress belajar disimpan di `localStorage` browser.
