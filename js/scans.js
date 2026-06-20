const SCAN_CATEGORIES = [
  // ═══════════════════════════════════════════
  //  1. HOST DISCOVERY
  // ═══════════════════════════════════════════
  {
    id: "host-discovery",
    label: "Host Discovery",
    icon: "📡",
    scans: [
      {
        id: "ping-sweep",
        name: "Ping Sweep",
        optionsConfig: { noPing: false, ports: false },
        flag: "-sn",
        command: "nmap -sn",
        fungsi: {
          title: "Host Discovery (No Port Scan)",
          description: "Mengirim berbagai probe (ICMP echo, TCP SYN/ACK, ARP) untuk menentukan host mana yang <strong>aktif</strong> di network, tanpa melakukan port scan. Ini adalah langkah pertama dalam reconnaissance — mengetahui target mana yang hidup sebelum scan lebih dalam.",
          howItWorks: [
            "Pada local network: mengirim ARP request (paling reliable)",
            "Pada remote network: mengirim ICMP echo request + TCP SYN ke port 443 + TCP ACK ke port 80",
            "Host yang merespons ditandai sebagai 'up'",
            "Tidak melakukan port scan — hanya discovery"
          ],
          output: "Daftar host yang aktif (up) dengan IP address dan, jika tersedia, hostname serta MAC address (di local network)."
        },
        kapanPakai: {
          kondisi: [
            "Kamu baru memulai reconnaissance dan perlu tahu host mana yang aktif di subnet target",
            "Sebelum menjalankan port scan — tidak perlu scan port pada host yang mati",
            "Mapping topology network untuk memahami scope dan ukuran target",
            "Quick check apakah host tertentu online atau tidak"
          ],
          setelah: "Ini biasanya langkah PERTAMA — dilakukan sebelum scan apapun",
          jikaGagal: [
            "Host tidak merespons ping → coba -Pn untuk skip discovery dan langsung port scan",
            "ICMP diblok firewall → coba TCP ping (-PS443 atau -PA80)",
            "Tidak ada host ditemukan → cek apakah kamu di subnet yang benar, atau coba ARP scan (-PR) untuk local network"
          ]
        },
        skenario: [
          { role: "Pentester", context: "Langkah pertama engagement — mapping semua host aktif di scope yang diberikan client" },
          { role: "Sysadmin", context: "Inventarisasi devices di network — siapa saja yang online di subnet ini" },
          { role: "Blue Team", context: "Deteksi unauthorized devices — apakah ada host baru yang tidak seharusnya ada" },
          { role: "Network Engineer", context: "Troubleshooting connectivity — cek apakah host tertentu reachable dari segment ini" }
        ],
        mitre: {
          tactic: { id: "TA0043", name: "Reconnaissance" },
          technique: { id: "T1595.001", name: "Active Scanning: Scanning IP Blocks" },
          killChain: "Reconnaissance",
          description: "Enumerasi host aktif di network target — langkah awal sebelum port scanning dan service enumeration."
        },
        precautions: [
          { level: "low", text: "Tidak memerlukan root untuk basic ping sweep (tapi ARP scan butuh root)" },
          { level: "critical", text: "WAJIB memiliki written authorization sebelum scanning network manapun" },
          { level: "low", text: "Traffic relatif ringan — tapi scanning subnet besar (/16 atau lebih) bisa memakan waktu" },
          { level: "medium", text: "Beberapa host mungkin tidak merespons ping tapi sebenarnya aktif (firewall memblok ICMP)" }
        ],
        impact: {
          traffic: "Low — beberapa paket per host",
          detection: "Low — ping sweep adalah aktivitas network normal",
          disruption: "Minimal — tidak ada koneksi ke port, hanya probe",
          legal: "Scanning tanpa izin tertulis dapat melanggar hukum"
        }
      },
      {
        id: "tcp-syn-ping",
        name: "TCP SYN Ping",
        optionsConfig: { noPing: false, ports: false },
        flag: "-PS",
        flags: ["-sn", "-PS", "443"],
        command: "nmap -sn -PS443",
        fungsi: {
          title: "TCP SYN Discovery Probe",
          description: "Mengirim paket TCP SYN ke port tertentu (default: 80) untuk menentukan apakah host aktif. Jika host merespons dengan SYN-ACK atau RST, host dianggap <strong>up</strong>. Berguna ketika ICMP ping diblok oleh firewall.",
          howItWorks: [
            "Nmap mengirim paket SYN ke port yang ditentukan (misal: 443)",
            "Host up → merespons SYN-ACK (port open) atau RST (port closed)",
            "Host down → tidak ada response",
            "Biasanya dikombinasikan dengan -sn untuk discovery tanpa port scan"
          ],
          output: "Daftar host aktif — sama seperti ping sweep tapi menggunakan TCP SYN sebagai probe."
        },
        kapanPakai: {
          kondisi: [
            "ICMP ping diblok oleh firewall tapi TCP traffic diizinkan",
            "Ping sweep (-sn) tidak menemukan host yang seharusnya aktif",
            "Target network memblok semua ICMP inbound",
            "Perlu discovery method yang lebih reliable daripada ICMP"
          ],
          setelah: "Ping Sweep (-sn) gagal menemukan host yang expected",
          jikaGagal: [
            "Port SYN juga diblok → coba TCP ACK Ping (-PA) pada port berbeda",
            "Semua TCP diblok → coba UDP Ping (-PU) atau -Pn (skip discovery)",
            "Coba port lain: -PS22,80,443,8080 — mungkin port tertentu tidak difilter"
          ]
        },
        skenario: [
          { role: "Pentester", context: "Discovery di environment yang heavily firewalled — ICMP diblok tapi web traffic diizinkan" },
          { role: "Red Team", context: "Menemukan host di DMZ atau cloud environment yang biasanya memblok ICMP" },
          { role: "Blue Team", context: "Testing apakah host discovery masih mungkin meskipun ICMP sudah diblok" },
          { role: "Network Engineer", context: "Verifikasi reachability ketika ICMP tidak available" }
        ],
        mitre: {
          tactic: { id: "TA0043", name: "Reconnaissance" },
          technique: { id: "T1595.001", name: "Active Scanning: Scanning IP Blocks" },
          killChain: "Reconnaissance",
          description: "Host discovery menggunakan TCP SYN probe — bypass ICMP filtering."
        },
        precautions: [
          { level: "high", text: "Memerlukan root/admin privilege untuk mengirim raw SYN packets" },
          { level: "critical", text: "WAJIB memiliki written authorization" },
          { level: "low", text: "Pilih port yang kemungkinan besar diizinkan (443, 80, 22)" },
          { level: "medium", text: "Tanpa root, Nmap fallback ke connect() syscall yang mungkin kurang efektif" }
        ],
        impact: {
          traffic: "Low — satu paket SYN per port per host",
          detection: "Low — single SYN packet sulit dibedakan dari traffic normal",
          disruption: "Minimal — tidak ada koneksi penuh",
          legal: "Scanning tanpa izin tertulis dapat melanggar hukum"
        }
      },
      {
        id: "tcp-ack-ping",
        name: "TCP ACK Ping",
        optionsConfig: { noPing: false, ports: false },
        flag: "-PA",
        flags: ["-sn", "-PA", "80"],
        command: "nmap -sn -PA80",
        fungsi: {
          title: "TCP ACK Discovery Probe",
          description: "Mengirim paket TCP ACK ke port tertentu (default: 80). Karena ACK dikirim tanpa SYN sebelumnya, host yang aktif akan merespons dengan RST. Teknik ini bisa melewati firewall stateless yang hanya memblok paket SYN.",
          howItWorks: [
            "Nmap mengirim paket ACK (tanpa SYN sebelumnya) ke port target",
            "Host up → merespons RST (karena ACK tidak matching koneksi apapun)",
            "Host down → tidak ada response",
            "Bisa melewati firewall yang hanya blok SYN packets"
          ],
          output: "Daftar host aktif — menggunakan RST response sebagai indikator host hidup."
        },
        kapanPakai: {
          kondisi: [
            "TCP SYN Ping (-PS) diblok oleh firewall yang hanya drop SYN packets",
            "Firewall stateless yang memfilter berdasarkan SYN flag saja",
            "Perlu alternatif discovery method setelah SYN ping gagal",
            "Kombinasi dengan -PS untuk coverage yang lebih baik: -PS443 -PA80"
          ],
          setelah: "TCP SYN Ping (-PS) diblok oleh firewall",
          jikaGagal: [
            "Firewall stateful yang track koneksi → ACK tanpa SYN akan di-drop juga",
            "Coba UDP Ping (-PU) atau kombinasi: -PS443 -PA80 -PE",
            "Jika semua discovery gagal → gunakan -Pn untuk skip dan langsung port scan"
          ]
        },
        skenario: [
          { role: "Pentester", context: "Bypass firewall stateless yang hanya drop SYN — ACK packets bisa lewat" },
          { role: "Red Team", context: "Menemukan host di balik firewall sederhana yang tidak melakukan stateful inspection" },
          { role: "Blue Team", context: "Testing apakah firewall rules cukup ketat — apakah hanya SYN yang diblok atau semua unsolicited TCP" },
          { role: "Security Auditor", context: "Evaluasi efektivitas firewall rules dalam memblok scanning" }
        ],
        mitre: {
          tactic: { id: "TA0043", name: "Reconnaissance" },
          technique: { id: "T1595.001", name: "Active Scanning: Scanning IP Blocks" },
          additionalTactic: { id: "TA0005", name: "Defense Evasion" },
          killChain: "Reconnaissance",
          description: "Host discovery menggunakan ACK probe — bypass firewall stateless."
        },
        precautions: [
          { level: "high", text: "Memerlukan root/admin privilege" },
          { level: "critical", text: "WAJIB memiliki written authorization" },
          { level: "medium", text: "Tidak efektif melawan firewall stateful — hanya bypass stateless" },
          { level: "low", text: "Kombinasikan dengan -PS untuk reliability terbaik" }
        ],
        impact: {
          traffic: "Low — satu paket ACK per port per host",
          detection: "Low — ACK packet tanpa SYN bisa dianggap anomali oleh IDS",
          disruption: "Minimal — tidak ada koneksi",
          legal: "Scanning tanpa izin tertulis dapat melanggar hukum"
        }
      },
      {
        id: "udp-ping",
        name: "UDP Ping",
        flag: "-PU",
        flags: ["-sn", "-PU", "53"],
        command: "nmap -sn -PU53",
        fungsi: {
          title: "UDP Discovery Probe",
          description: "Mengirim paket UDP ke port tertentu (default: 40125, port yang kemungkinan tertutup). Port tertutup merespons dengan ICMP port unreachable — menandakan host <strong>up</strong>. Port terbuka mungkin tidak merespons.",
          howItWorks: [
            "Nmap mengirim paket UDP ke port target (pilih port yang mungkin tertutup)",
            "Port closed → host merespons ICMP port unreachable → host UP",
            "Port open → mungkin tidak ada response (ambigu)",
            "Default port 40125 dipilih karena kemungkinan besar tertutup"
          ],
          output: "Daftar host aktif berdasarkan ICMP unreachable response."
        },
        kapanPakai: {
          kondisi: [
            "Semua TCP discovery methods (SYN dan ACK ping) diblok",
            "Firewall memblok semua TCP inbound tapi UDP tertentu diizinkan",
            "Perlu discovery method alternatif yang berbeda protocol",
            "Network yang memblok TCP tapi DNS (UDP 53) atau SNMP (UDP 161) masih open"
          ],
          setelah: "TCP SYN Ping (-PS) dan TCP ACK Ping (-PA) keduanya gagal",
          jikaGagal: [
            "UDP juga diblok → coba ICMP ping (-PE) atau -Pn (skip discovery)",
            "Rate limiting pada ICMP unreachable → scan jadi sangat lambat, pertimbangkan -Pn",
            "Coba target common UDP ports: -PU53,161,162 yang mungkin open"
          ]
        },
        skenario: [
          { role: "Pentester", context: "Discovery terakhir setelah semua TCP methods gagal — mencoba protocol yang berbeda" },
          { role: "Red Team", context: "Menemukan host yang firewall-nya fokus blok TCP tapi lupa UDP" },
          { role: "Blue Team", context: "Testing apakah UDP ports juga di-cover oleh firewall rules" },
          { role: "Network Engineer", context: "Cek reachability via UDP — misalnya DNS server yang hanya accept UDP" }
        ],
        mitre: {
          tactic: { id: "TA0043", name: "Reconnaissance" },
          technique: { id: "T1595.001", name: "Active Scanning: Scanning IP Blocks" },
          killChain: "Reconnaissance",
          description: "Host discovery via UDP probe — alternatif ketika TCP discovery diblok."
        },
        precautions: [
          { level: "high", text: "Memerlukan root/admin privilege" },
          { level: "critical", text: "WAJIB memiliki written authorization" },
          { level: "medium", text: "Lebih lambat dari TCP discovery karena mengandalkan ICMP unreachable" },
          { level: "medium", text: "Beberapa OS rate-limit ICMP unreachable (Linux: 1/sec) — memperlambat scan" }
        ],
        impact: {
          traffic: "Low — satu paket UDP per port per host",
          detection: "Low-Medium — UDP probes ke port random bisa terlihat anomali",
          disruption: "Minimal — tidak ada koneksi",
          legal: "Scanning tanpa izin tertulis dapat melanggar hukum"
        }
      },
      {
        id: "skip-discovery",
        name: "Skip Host Discovery",
        optionsConfig: { noPing: false },
        flag: "-Pn",
        command: "nmap -Pn",
        fungsi: {
          title: "Treat All Hosts as Online",
          description: "Melewati fase host discovery sepenuhnya — Nmap menganggap semua target host sebagai <strong>aktif</strong> dan langsung melakukan port scan. Berguna ketika host diketahui aktif tapi tidak merespons ping probe.",
          howItWorks: [
            "Nmap melewati semua discovery probes (ICMP, TCP, ARP)",
            "Semua IP di target range dianggap 'up'",
            "Langsung melakukan port scan pada semua target",
            "Trade-off: scan lebih lambat karena mencakup host yang mungkin down"
          ],
          output: "Port scan results untuk semua target IP — termasuk yang mungkin sebenarnya down (hasilnya 'all ports filtered')."
        },
        kapanPakai: {
          kondisi: [
            "Semua discovery methods gagal tapi kamu yakin host tersebut aktif",
            "Firewall memblok semua probe types (ICMP, TCP, UDP)",
            "Kamu sudah tahu host target aktif dan ingin skip discovery untuk hemat waktu",
            "Scanning satu host spesifik yang kamu tahu address-nya"
          ],
          setelah: "Semua discovery methods (-sn, -PS, -PA, -PU, -PE) gagal",
          jikaGagal: [
            "Semua port 'filtered' → host memang down, atau firewall sangat ketat",
            "Scan terlalu lambat → kurangi target range atau gunakan --top-ports",
            "Tidak ada info berguna → host mungkin benar-benar unreachable dari posisi kamu"
          ]
        },
        skenario: [
          { role: "Pentester", context: "Target di balik strict firewall — discovery diblok tapi port scan perlu dilakukan" },
          { role: "Red Team", context: "Known target yang firewall-nya drop semua ICMP dan non-standard TCP" },
          { role: "CTF Player", context: "Quick scan target yang sudah diketahui IP-nya — skip discovery untuk hemat waktu" },
          { role: "Sysadmin", context: "Port scan server sendiri yang ICMP-nya disabled by policy" }
        ],
        mitre: {
          tactic: { id: "TA0007", name: "Discovery" },
          technique: { id: "T1046", name: "Network Service Discovery" },
          killChain: "Reconnaissance",
          description: "Skip host discovery untuk langsung port scan — bypass firewall yang blok semua probes."
        },
        precautions: [
          { level: "low", text: "Tidak memerlukan root untuk basic scan" },
          { level: "critical", text: "WAJIB memiliki written authorization" },
          { level: "medium", text: "Scan jadi lebih lambat karena semua IP di-scan termasuk yang down" },
          { level: "low", text: "Best practice: gunakan bersama -p atau --top-ports untuk limit scope" }
        ],
        impact: {
          traffic: "Medium-High — port scan berjalan ke semua target tanpa filter",
          detection: "Medium — traffic scanning ke host yang sebenarnya down bisa terlihat anomali",
          disruption: "Low — sama seperti port scan biasa",
          legal: "Scanning tanpa izin tertulis dapat melanggar hukum"
        }
      }
    ]
  },

  // ═══════════════════════════════════════════
  //  2. TCP SCANNING
  // ═══════════════════════════════════════════
  {
    id: "tcp-scanning",
    label: "TCP Scanning",
    icon: "⚡",
    scans: [
      {
        id: "tcp-syn",
        name: "TCP SYN Scan",
        flag: "-sS",
        command: "nmap -sS",
        fungsi: {
          title: "Half-Open Scan",
          description: "Mengirim paket SYN ke target port. Jika menerima SYN-ACK, port dianggap <strong>open</strong> — lalu Nmap langsung kirim RST untuk memutus koneksi tanpa menyelesaikan TCP 3-way handshake. Jika menerima RST, port <strong>closed</strong>. Jika tidak ada response, port <strong>filtered</strong>.",
          howItWorks: [
            "Nmap mengirim paket SYN ke port target",
            "Port open → target membalas SYN-ACK → Nmap kirim RST (putus)",
            "Port closed → target membalas RST",
            "Port filtered → tidak ada response (firewall drop paket)"
          ],
          output: "Daftar port dengan status open/closed/filtered, service name berdasarkan port number standar."
        },
        kapanPakai: {
          kondisi: [
            "Kamu sudah tahu host target aktif (dari ping sweep atau -sn) dan perlu tahu port apa saja yang terbuka",
            "TCP Connect scan (-sT) terlalu lambat atau meninggalkan terlalu banyak log di target",
            "UDP scan (-sU) sudah dicoba tapi tidak memberikan informasi yang cukup",
            "Kamu punya akses root/admin dan ingin scan yang lebih cepat dari full connect"
          ],
          setelah: "Host Discovery (-sn) — sudah konfirmasi host aktif",
          jikaGagal: [
            "Banyak port 'filtered' → coba ACK Scan (-sA) untuk mapping firewall rules",
            "Tidak punya root → gunakan TCP Connect (-sT)",
            "IDS mendeteksi → coba FIN/Xmas/Null scan atau tambahkan timing option (-T2)"
          ]
        },
        skenario: [
          { role: "Pentester", context: "Fase awal engagement — mapping attack surface, mencari port terbuka di subnet target setelah scope disepakati" },
          { role: "Red Team", context: "Stealth reconnaissance sebelum exploitation, meminimalkan jejak di log target" },
          { role: "Blue Team", context: "Audit berkala port exposure di server production — memastikan hanya port yang seharusnya terbuka yang benar-benar terbuka" },
          { role: "Compliance", context: "Verifikasi bahwa port yang sudah di-decommission benar-benar tertutup sesuai policy" }
        ],
        mitre: {
          tactic: { id: "TA0007", name: "Discovery" },
          technique: { id: "T1046", name: "Network Service Discovery" },
          killChain: "Reconnaissance",
          description: "Scanning port untuk menemukan service yang berjalan di target, sebagai langkah awal sebelum enumeration lebih lanjut."
        },
        precautions: [
          { level: "high", text: "Memerlukan root/admin privilege — tanpa ini Nmap fallback ke TCP Connect" },
          { level: "critical", text: "WAJIB memiliki written authorization sebelum scanning target manapun" },
          { level: "medium", text: "Dapat memicu alert di IDS/IPS — beberapa sistem mendeteksi pola SYN scan" },
          { level: "low", text: "Pada network yang sangat strict, SYN scan bisa di-rate-limit oleh firewall" }
        ],
        impact: {
          traffic: "Moderate — satu paket SYN per port yang di-scan",
          detection: "Medium — sebagian besar firewall modern mencatat SYN scan di log",
          disruption: "Low — tidak membuat koneksi penuh, risiko gangguan service sangat kecil",
          legal: "Scanning tanpa izin tertulis dapat melanggar hukum (UU ITE di Indonesia, CFAA di US)"
        }
      },
      {
        id: "tcp-connect",
        name: "TCP Connect Scan",
        flag: "-sT",
        command: "nmap -sT",
        fungsi: {
          title: "Full Connection Scan",
          description: "Melakukan TCP 3-way handshake lengkap (SYN → SYN-ACK → ACK) ke setiap port target. Setelah koneksi terbentuk, langsung ditutup. Ini adalah scan paling reliable tapi juga paling mudah terdeteksi karena setiap koneksi tercatat di log aplikasi target.",
          howItWorks: [
            "Nmap melakukan system call connect() ke port target",
            "Port open → handshake berhasil (SYN → SYN-ACK → ACK) → koneksi ditutup",
            "Port closed → target membalas RST",
            "Port filtered → timeout, tidak ada response"
          ],
          output: "Daftar port dengan status open/closed/filtered. Lebih akurat dari SYN scan karena koneksi benar-benar terbentuk."
        },
        kapanPakai: {
          kondisi: [
            "Kamu TIDAK punya root/admin privilege — ini satu-satunya TCP scan yang bisa jalan tanpa root",
            "SYN scan (-sS) gagal atau di-block oleh firewall/IDS",
            "Butuh hasil yang paling reliable dan akurat, tidak peduli soal stealth",
            "Scanning dari environment yang restricted (container, limited user)"
          ],
          setelah: "SYN Scan (-sS) gagal, atau tidak punya privilege untuk SYN scan",
          jikaGagal: [
            "Firewall memblok → coba FIN (-sF), Xmas (-sX), atau Null (-sN) scan",
            "Terlalu lambat → kurangi jumlah port dengan -p atau --top-ports",
            "Terlalu banyak filtered → coba ACK Scan (-sA) untuk analisa firewall"
          ]
        },
        skenario: [
          { role: "Pentester", context: "Scanning dari unprivileged account atau ketika SYN scan tidak tersedia" },
          { role: "Sysadmin", context: "Quick port check dari workstation sendiri tanpa perlu elevated privilege" },
          { role: "Developer", context: "Verifikasi bahwa service yang baru di-deploy listening di port yang benar" },
          { role: "Blue Team", context: "Baseline scan untuk dokumentasi port yang terbuka — reliability lebih penting dari stealth" }
        ],
        mitre: {
          tactic: { id: "TA0007", name: "Discovery" },
          technique: { id: "T1046", name: "Network Service Discovery" },
          killChain: "Reconnaissance",
          description: "Full TCP connection ke port target — lebih mudah dideteksi tapi lebih reliable."
        },
        precautions: [
          { level: "low", text: "Tidak memerlukan root/admin — bisa dijalankan sebagai user biasa" },
          { level: "critical", text: "WAJIB memiliki written authorization sebelum scanning" },
          { level: "high", text: "Setiap koneksi tercatat di application log target — sangat mudah terdeteksi" },
          { level: "medium", text: "Lebih lambat dari SYN scan karena full handshake per port" }
        ],
        impact: {
          traffic: "High — full TCP handshake untuk setiap port",
          detection: "High — setiap koneksi tercatat di log aplikasi dan firewall",
          disruption: "Low — koneksi normal, sangat kecil risiko gangguan service",
          legal: "Scanning tanpa izin tertulis dapat melanggar hukum"
        }
      },
      {
        id: "tcp-ack",
        name: "TCP ACK Scan",
        flag: "-sA",
        command: "nmap -sA",
        fungsi: {
          title: "Firewall Mapping Scan",
          description: "Mengirim paket ACK ke target port. Scan ini <strong>TIDAK bisa menentukan port open atau closed</strong> — tujuannya adalah mendeteksi keberadaan firewall dan mapping rules-nya. Jika menerima RST, port <strong>unfiltered</strong> (firewall tidak memblok). Jika tidak ada response atau ICMP error, port <strong>filtered</strong> (ada firewall).",
          howItWorks: [
            "Nmap mengirim paket ACK (tanpa SYN sebelumnya) ke port target",
            "Unfiltered → target membalas RST (tidak ada firewall yang memblok)",
            "Filtered → tidak ada response (firewall men-drop paket)",
            "Hasilnya: peta port mana yang difilter dan mana yang tidak"
          ],
          output: "Port ditandai sebagai 'unfiltered' atau 'filtered' — BUKAN open/closed. Digunakan untuk memahami firewall rules."
        },
        kapanPakai: {
          kondisi: [
            "SYN atau Connect scan menunjukkan banyak port 'filtered' dan kamu perlu tahu tipe firewall-nya",
            "Kamu ingin mapping firewall rules sebelum mencoba teknik bypass",
            "Perlu menentukan apakah firewall stateful atau stateless",
            "Fase reconnaissance lanjutan setelah port scan awal"
          ],
          setelah: "SYN Scan (-sS) atau Connect Scan (-sT) — sudah tahu ada firewall yang memblok",
          jikaGagal: [
            "Semua port filtered → firewall stateful yang ketat, coba Window Scan (-sW) untuk detail lebih",
            "Semua unfiltered → tidak ada firewall, kembali ke SYN scan untuk cari port open",
            "Perlu bypass → coba FIN/Xmas/Null scan atau fragmentation (-f)"
          ]
        },
        skenario: [
          { role: "Pentester", context: "Fase intelligence gathering — memahami firewall rules sebelum memilih teknik scanning yang tepat" },
          { role: "Red Team", context: "Mapping perimeter defense target untuk merencanakan bypass strategy" },
          { role: "Blue Team", context: "Verifikasi bahwa firewall rules berfungsi sesuai konfigurasi — pastikan port yang seharusnya diblok benar-benar terfilter" },
          { role: "Network Engineer", context: "Troubleshooting firewall rules — cek apakah ACL/rules yang baru diterapkan sudah bekerja" }
        ],
        mitre: {
          tactic: { id: "TA0007", name: "Discovery" },
          technique: { id: "T1046", name: "Network Service Discovery" },
          killChain: "Reconnaissance",
          description: "Mapping firewall rules dan filtering — menentukan attack path yang viable."
        },
        precautions: [
          { level: "high", text: "Memerlukan root/admin privilege" },
          { level: "critical", text: "WAJIB memiliki written authorization" },
          { level: "medium", text: "Tidak memberikan informasi open/closed — jangan salah interpretasi hasilnya" },
          { level: "low", text: "Hasil bergantung pada implementasi TCP stack target OS" }
        ],
        impact: {
          traffic: "Moderate — satu paket ACK per port",
          detection: "Medium — firewall log mencatat unsolicited ACK packets",
          disruption: "Minimal — tidak membuat koneksi, tidak mengganggu service",
          legal: "Scanning tanpa izin tertulis dapat melanggar hukum"
        }
      },
      {
        id: "tcp-fin",
        name: "TCP FIN Scan",
        flag: "-sF",
        command: "nmap -sF",
        fungsi: {
          title: "Stealth FIN Scan",
          description: "Mengirim paket dengan hanya flag FIN aktif, tanpa koneksi sebelumnya. Per RFC 793, port tertutup harus merespons dengan RST, sedangkan port terbuka harus men-drop paket (tidak ada response). Teknik ini bisa melewati firewall stateless yang hanya memblok paket SYN.",
          howItWorks: [
            "Nmap mengirim paket FIN (tanpa SYN/ACK) ke port target",
            "Port closed → target membalas RST (sesuai RFC 793)",
            "Port open → tidak ada response (paket di-drop)",
            "Port filtered → tidak ada response atau ICMP unreachable"
          ],
          output: "Port ditandai open|filtered (tidak bisa dibedakan), closed, atau filtered. Ambiguitas open|filtered adalah kelemahan utama scan ini."
        },
        kapanPakai: {
          kondisi: [
            "SYN scan terdeteksi oleh IDS/IPS dan kamu perlu pendekatan yang lebih stealth",
            "Firewall stateless memblok semua paket SYN inbound",
            "Kamu sudah mencoba SYN dan Connect scan tapi banyak yang diblok",
            "Perlu konfirmasi apakah firewall hanya memeriksa SYN flag atau semua flag"
          ],
          setelah: "SYN Scan (-sS) diblok atau terdeteksi IDS",
          jikaGagal: [
            "Semua port open|filtered → target kemungkinan Windows (tidak ikuti RFC) — kembali ke SYN/Connect",
            "Masih terdeteksi → coba Xmas (-sX) atau Null (-sN) scan",
            "Firewall masih memblok → tambahkan fragmentation (-f) atau decoy (-D)"
          ]
        },
        skenario: [
          { role: "Pentester", context: "Bypassing basic packet-filter firewall yang hanya drop SYN packets" },
          { role: "Red Team", context: "Stealth scanning untuk menghindari deteksi — meminimalkan alert di SOC target" },
          { role: "Blue Team", context: "Testing apakah IDS/IPS bisa mendeteksi non-SYN scan — validasi detection rules" },
          { role: "Security Researcher", context: "Testing TCP stack compliance target terhadap RFC 793" }
        ],
        mitre: {
          tactic: { id: "TA0007", name: "Discovery" },
          technique: { id: "T1046", name: "Network Service Discovery" },
          additionalTactic: { id: "TA0005", name: "Defense Evasion" },
          killChain: "Reconnaissance → Weaponization",
          description: "Scanning port dengan teknik evasion — menghindari deteksi oleh security controls."
        },
        precautions: [
          { level: "high", text: "Memerlukan root/admin privilege" },
          { level: "critical", text: "WAJIB memiliki written authorization" },
          { level: "high", text: "Tidak reliable terhadap Windows — Windows tidak mengikuti RFC 793 (semua port terlihat closed)" },
          { level: "medium", text: "Ambiguitas open|filtered — tidak bisa pastikan port benar-benar open" }
        ],
        impact: {
          traffic: "Low — satu paket kecil per port",
          detection: "Low — banyak IDS lama tidak mendeteksi FIN-only packets",
          disruption: "Minimal — tidak membuat koneksi apapun",
          legal: "Scanning tanpa izin tertulis dapat melanggar hukum"
        }
      },
      {
        id: "tcp-xmas",
        name: "TCP Xmas Scan",
        flag: "-sX",
        command: "nmap -sX",
        fungsi: {
          title: "Xmas Tree Scan",
          description: "Mengirim paket dengan flag FIN, PSH, dan URG aktif secara bersamaan — disebut 'Xmas tree' karena semua flag 'menyala' seperti lampu pohon natal. Logika sama dengan FIN scan: port tertutup respons RST, port terbuka diam.",
          howItWorks: [
            "Nmap mengirim paket dengan flag FIN+PSH+URG aktif",
            "Port closed → target membalas RST",
            "Port open → tidak ada response",
            "Port filtered → tidak ada response atau ICMP unreachable"
          ],
          output: "Sama seperti FIN scan — port ditandai open|filtered, closed, atau filtered."
        },
        kapanPakai: {
          kondisi: [
            "FIN scan (-sF) tidak memberikan hasil yang jelas atau sudah dideteksi",
            "Firewall memblok FIN-only packets tapi mungkin tidak memeriksa kombinasi flag",
            "Variasi teknik stealth — mencoba pattern flag yang berbeda untuk bypass rules",
            "Testing IDS/IPS detection capability terhadap unusual TCP flag combinations"
          ],
          setelah: "FIN Scan (-sF) gagal atau dideteksi",
          jikaGagal: [
            "Sama seperti FIN — tidak reliable di Windows",
            "Coba Null scan (-sN) sebagai variasi terakhir",
            "Jika semua stealth scan gagal → gunakan fragmentation (-f) atau timing (-T2)"
          ]
        },
        skenario: [
          { role: "Pentester", context: "Variasi stealth scan ketika FIN scan sudah dideteksi — menggunakan flag combination yang berbeda" },
          { role: "Red Team", context: "Testing kedalaman detection capability target — apakah SOC mendeteksi unusual flag patterns" },
          { role: "Blue Team", context: "Validasi bahwa IDS signature mencakup Xmas scan pattern — bukan hanya SYN dan FIN" },
          { role: "Security Researcher", context: "Analisis bagaimana berbagai OS dan firewall merespons unusual TCP flag combinations" }
        ],
        mitre: {
          tactic: { id: "TA0007", name: "Discovery" },
          technique: { id: "T1046", name: "Network Service Discovery" },
          additionalTactic: { id: "TA0005", name: "Defense Evasion" },
          killChain: "Reconnaissance → Weaponization",
          description: "Stealth port discovery menggunakan unusual flag combination untuk menghindari detection."
        },
        precautions: [
          { level: "high", text: "Memerlukan root/admin privilege" },
          { level: "critical", text: "WAJIB memiliki written authorization" },
          { level: "high", text: "Tidak reliable terhadap Windows — sama seperti FIN scan" },
          { level: "medium", text: "Beberapa IDS modern sudah punya signature untuk Xmas scan pattern" }
        ],
        impact: {
          traffic: "Low — satu paket kecil per port",
          detection: "Low-Medium — IDS modern mulai mendeteksi Xmas pattern",
          disruption: "Minimal — tidak membuat koneksi",
          legal: "Scanning tanpa izin tertulis dapat melanggar hukum"
        }
      },
      {
        id: "tcp-null",
        name: "TCP Null Scan",
        flag: "-sN",
        command: "nmap -sN",
        fungsi: {
          title: "Null Flag Scan",
          description: "Mengirim paket TCP tanpa flag apapun — header TCP 'kosong'. Ini kebalikan dari Xmas scan. Logika tetap sama per RFC 793: port tertutup respons RST, port terbuka diam.",
          howItWorks: [
            "Nmap mengirim paket TCP tanpa flag (semua flag bits = 0)",
            "Port closed → target membalas RST",
            "Port open → tidak ada response",
            "Port filtered → tidak ada response atau ICMP unreachable"
          ],
          output: "Sama seperti FIN/Xmas — port ditandai open|filtered, closed, atau filtered."
        },
        kapanPakai: {
          kondisi: [
            "FIN (-sF) dan Xmas (-sX) scan sudah dideteksi atau diblok",
            "Perlu variasi terakhir dari stealth TCP scan sebelum beralih ke teknik lain",
            "Testing apakah firewall/IDS memeriksa TCP packets tanpa flag",
            "Firewall hanya memeriksa paket dengan flag tertentu"
          ],
          setelah: "FIN (-sF) dan Xmas (-sX) scan gagal atau terdeteksi",
          jikaGagal: [
            "Semua stealth scan gagal → pertimbangkan fragmentasi (-f), decoy (-D), atau source port spoofing",
            "Target Windows → stealth scan (FIN/Xmas/Null) tidak akan berhasil, kembali ke SYN/Connect",
            "Firewall sangat ketat → pertimbangkan idle scan (-sI) atau pendekatan lain"
          ]
        },
        skenario: [
          { role: "Pentester", context: "Opsi terakhir dalam stealth TCP scan toolkit sebelum eskalasi ke teknik lain" },
          { role: "Red Team", context: "Rotasi teknik scanning — menggunakan variasi yang belum dideteksi" },
          { role: "Blue Team", context: "Testing comprehensive IDS coverage — memastikan semua variasi stealth scan terdeteksi" },
          { role: "Security Researcher", context: "Benchmarking respons berbagai OS terhadap paket tanpa flag — deviation dari RFC 793" }
        ],
        mitre: {
          tactic: { id: "TA0007", name: "Discovery" },
          technique: { id: "T1046", name: "Network Service Discovery" },
          additionalTactic: { id: "TA0005", name: "Defense Evasion" },
          killChain: "Reconnaissance → Weaponization",
          description: "Stealth scan terakhir dalam rangkaian FIN/Xmas/Null — mencoba pattern yang paling unusual."
        },
        precautions: [
          { level: "high", text: "Memerlukan root/admin privilege" },
          { level: "critical", text: "WAJIB memiliki written authorization" },
          { level: "high", text: "Tidak reliable terhadap Windows" },
          { level: "medium", text: "Kemungkinan semua port ditandai open|filtered — hasil sulit diinterpretasi" }
        ],
        impact: {
          traffic: "Minimal — paket terkecil (tanpa flag)",
          detection: "Low — anomali tapi jarang dimonitor secara spesifik",
          disruption: "Minimal — tidak membuat koneksi",
          legal: "Scanning tanpa izin tertulis dapat melanggar hukum"
        }
      },
      {
        id: "tcp-window",
        name: "TCP Window Scan",
        flag: "-sW",
        command: "nmap -sW",
        fungsi: {
          title: "TCP Window Analysis Scan",
          description: "Mirip ACK scan tapi memeriksa TCP Window field dari paket RST yang diterima. Pada beberapa OS, port terbuka mengembalikan window size positif, sedangkan port tertutup mengembalikan window size nol. Ini memberikan informasi lebih dari ACK scan biasa.",
          howItWorks: [
            "Nmap mengirim paket ACK ke port target (sama seperti ACK scan)",
            "Memeriksa RST response — khususnya nilai TCP Window field",
            "Window size > 0 → kemungkinan port open",
            "Window size = 0 → kemungkinan port closed",
            "Tidak ada response → port filtered"
          ],
          output: "Port ditandai open, closed, atau filtered — LEBIH informatif dari ACK scan biasa, tapi akurasi bergantung pada OS target."
        },
        kapanPakai: {
          kondisi: [
            "ACK scan (-sA) menunjukkan banyak port 'unfiltered' tapi kamu perlu tahu mana yang sebenarnya open",
            "Perlu informasi lebih detail dari ACK scan tanpa menggunakan SYN/Connect scan",
            "Target OS diketahui memberikan window size yang berbeda untuk open vs closed ports",
            "Sebagai teknik pelengkap setelah ACK scan untuk analisis lebih dalam"
          ],
          setelah: "ACK Scan (-sA) — perlu detail lebih dari sekedar filtered/unfiltered",
          jikaGagal: [
            "Semua port menunjukkan hasil yang sama → OS target tidak membedakan window size, kembali ke SYN scan",
            "Hasil tidak konsisten → scan ini tidak reliable untuk OS target tersebut",
            "Perlu kepastian → gunakan SYN scan (-sS) dengan timing option yang sesuai"
          ]
        },
        skenario: [
          { role: "Pentester", context: "Analisis lanjutan setelah ACK scan — mencari detail port status di balik firewall" },
          { role: "Red Team", context: "Alternatif untuk mendapatkan info port tanpa SYN scan yang mungkin terdeteksi" },
          { role: "Blue Team", context: "Testing apakah OS server memberikan informasi window size yang bisa dieksploitasi" },
          { role: "Network Analyst", context: "Analisis mendalam TCP stack behavior target untuk fingerprinting" }
        ],
        mitre: {
          tactic: { id: "TA0007", name: "Discovery" },
          technique: { id: "T1046", name: "Network Service Discovery" },
          killChain: "Reconnaissance",
          description: "Analisis TCP window size untuk inferensi status port — teknik pelengkap ACK scan."
        },
        precautions: [
          { level: "high", text: "Memerlukan root/admin privilege" },
          { level: "critical", text: "WAJIB memiliki written authorization" },
          { level: "high", text: "Hasil sangat bergantung pada OS target — tidak semua OS memberikan window size yang berbeda" },
          { level: "medium", text: "Bisa memberikan false positives/negatives — selalu cross-reference dengan scan lain" }
        ],
        impact: {
          traffic: "Moderate — satu paket ACK per port",
          detection: "Medium — mirip ACK scan di log",
          disruption: "Minimal — tidak membuat koneksi",
          legal: "Scanning tanpa izin tertulis dapat melanggar hukum"
        }
      }
    ]
  },

  // ═══════════════════════════════════════════
  //  3. UDP SCANNING
  // ═══════════════════════════════════════════
  {
    id: "udp-scanning",
    label: "UDP Scanning",
    icon: "📦",
    scans: [
      {
        id: "udp-scan",
        name: "UDP Scan",
        flag: "-sU",
        command: "nmap -sU",
        fungsi: {
          title: "UDP Port Scan",
          description: "Mengirim paket UDP ke target port. Karena UDP connectionless, deteksi port status lebih sulit dari TCP. Port tertutup merespons ICMP port unreachable, port terbuka mungkin merespons atau diam, port filtered tidak ada response.",
          howItWorks: [
            "Nmap mengirim paket UDP kosong (atau protocol-specific payload) ke port target",
            "Port closed → ICMP port unreachable (type 3, code 3)",
            "Port open → respons UDP, atau tidak ada response (open|filtered)",
            "Port filtered → ICMP unreachable lainnya, atau tidak ada response",
            "Untuk common ports (DNS 53, SNMP 161), Nmap kirim protocol-specific payload"
          ],
          output: "Port ditandai open, closed, open|filtered, atau filtered. Banyak port akan ditandai open|filtered karena ambiguitas inherent UDP."
        },
        kapanPakai: {
          kondisi: [
            "TCP scan sudah selesai dan kamu perlu cek services yang jalan di UDP (DNS, SNMP, DHCP, TFTP, NTP)",
            "Target mungkin menjalankan UDP-based services yang tidak terdeteksi oleh TCP scan",
            "Pentest requirement mencakup full port assessment termasuk UDP",
            "Mencari services seperti SNMP yang sering misconfigured dan bisa membocorkan informasi"
          ],
          setelah: "TCP Scan (-sS/-sT) — UDP scan melengkapi picture dari TCP scan",
          jikaGagal: [
            "Terlalu lambat → fokus pada top ports: --top-ports 20 atau -p 53,161,162,123,500",
            "Semua open|filtered → kirim protocol-specific probes dengan --version-intensity 0",
            "Rate limited → OS membatasi ICMP response, tambahkan --max-retries 1 atau kurangi parallelism"
          ]
        },
        skenario: [
          { role: "Pentester", context: "Assessment lengkap — UDP services sering terlupakan tapi bisa jadi attack vector (SNMP community strings, DNS zone transfer)" },
          { role: "Red Team", context: "Mencari UDP services yang biasanya kurang di-harden (SNMP, TFTP, NTP amplification)" },
          { role: "Blue Team", context: "Audit UDP exposure — memastikan SNMP community strings tidak default, DNS zone transfer disabled" },
          { role: "Compliance", context: "PCI DSS dan compliance frameworks mengharuskan scanning semua port termasuk UDP" }
        ],
        mitre: {
          tactic: { id: "TA0007", name: "Discovery" },
          technique: { id: "T1046", name: "Network Service Discovery" },
          killChain: "Reconnaissance",
          description: "Discovery UDP services yang sering overlooked — DNS, SNMP, NTP bisa menjadi high-value targets."
        },
        precautions: [
          { level: "high", text: "Memerlukan root/admin privilege" },
          { level: "critical", text: "WAJIB memiliki written authorization" },
          { level: "high", text: "SANGAT LAMBAT — scanning 65535 UDP ports bisa memakan waktu berjam-jam. Gunakan --top-ports atau -p" },
          { level: "medium", text: "Banyak false positives (open|filtered) — perlu version detection (-sV) untuk konfirmasi" }
        ],
        impact: {
          traffic: "Moderate — tapi durasi scan yang panjang berarti total traffic tinggi",
          detection: "Medium — ICMP unreachable responses bisa trigger monitoring",
          disruption: "Low — tapi beberapa UDP services bisa crash jika menerima unexpected data",
          legal: "Scanning tanpa izin tertulis dapat melanggar hukum"
        }
      }
    ]
  },

  // ═══════════════════════════════════════════
  //  4. SERVICE & VERSION DETECTION
  // ═══════════════════════════════════════════
  {
    id: "service-detection",
    label: "Service & Version Detection",
    icon: "🔬",
    scans: [
      {
        id: "version-detection",
        name: "Version Detection",
        flag: "-sV",
        command: "nmap -sV",
        fungsi: {
          title: "Service Version Probing",
          description: "Setelah menemukan port terbuka, Nmap mengirim berbagai probes untuk menentukan <strong>service apa</strong> yang berjalan dan <strong>versi berapa</strong>. Bukan hanya berdasarkan port number (port 80 = HTTP), tapi benar-benar interrogate service untuk mendapatkan banner dan version info.",
          howItWorks: [
            "Nmap membuka koneksi ke port terbuka",
            "Mengirim NULL probe (tunggu banner), lalu protocol-specific probes",
            "Mencocokkan response dengan database signatures (nmap-service-probes)",
            "Mengidentifikasi: service name, version, OS type, hostname, device type"
          ],
          output: "Kolom VERSION di output berisi detail service: misal 'Apache httpd 2.4.52', 'OpenSSH 8.9p1', 'MySQL 5.7.38'."
        },
        kapanPakai: {
          kondisi: [
            "Port scan sudah selesai dan kamu tahu port mana yang open — sekarang perlu tahu SERVICE apa yang jalan",
            "Perlu mengetahui versi spesifik service untuk mencari known vulnerabilities (CVE lookup)",
            "Service berjalan di non-standard port (SSH di port 2222, HTTP di port 8443) — port number saja tidak cukup",
            "Perlu membedakan service yang sharing port number yang sama"
          ],
          setelah: "Port Scan (-sS/-sT) — sudah tahu port mana yang open",
          jikaGagal: [
            "Tidak bisa detect version → tingkatkan intensity: --version-intensity 9 atau --version-all",
            "Service merespons tapi unrecognized → periksa raw output, mungkin custom/proprietary service",
            "Terlalu lambat → kurangi intensity: --version-light (intensity 2) untuk speed"
          ]
        },
        skenario: [
          { role: "Pentester", context: "Post port-scan enumeration — mencari versi yang vulnerable (Apache 2.4.49 = CVE-2021-41773 path traversal)" },
          { role: "Red Team", context: "Identifying targets of opportunity — versi service yang outdated dan punya known exploit" },
          { role: "Blue Team", context: "Inventarisasi versi software yang jalan — identifying end-of-life atau unpatched services" },
          { role: "Vulnerability Manager", context: "Scan berkala untuk mendeteksi services yang perlu di-patch sebelum vulnerability di-exploit" }
        ],
        mitre: {
          tactic: { id: "TA0007", name: "Discovery" },
          technique: { id: "T1046", name: "Network Service Discovery" },
          killChain: "Reconnaissance → Weaponization",
          description: "Identifikasi versi service untuk mencari vulnerabilities — langkah kunci sebelum exploitation."
        },
        precautions: [
          { level: "low", text: "Tidak selalu memerlukan root — tapi beberapa probes membutuhkannya" },
          { level: "critical", text: "WAJIB memiliki written authorization" },
          { level: "high", text: "Membuat koneksi penuh ke service — akan tercatat di application log" },
          { level: "medium", text: "Beberapa probes bisa crash fragile services — jarang tapi possible" }
        ],
        impact: {
          traffic: "Medium-High — multiple probes per open port",
          detection: "High — koneksi dan data exchange tercatat di service log",
          disruption: "Low-Medium — biasanya aman tapi edge case pada legacy systems",
          legal: "Scanning tanpa izin tertulis dapat melanggar hukum"
        }
      },
      {
        id: "aggressive-scan",
        name: "Aggressive Scan",
        flag: "-A",
        command: "nmap -A",
        fungsi: {
          title: "All-in-One Aggressive Scan",
          description: "Kombinasi dari beberapa scan sekaligus: <strong>OS detection (-O)</strong>, <strong>version detection (-sV)</strong>, <strong>default scripts (-sC)</strong>, dan <strong>traceroute (--traceroute)</strong>. Satu command untuk mendapatkan informasi selengkap mungkin.",
          howItWorks: [
            "Menjalankan port scan (default SYN scan jika root)",
            "Version detection: probe setiap open port untuk service & version",
            "OS detection: analisis TCP/IP stack fingerprint",
            "NSE default scripts: menjalankan script kategori 'default' dan 'safe'",
            "Traceroute: mapping network path ke target"
          ],
          output: "Output lengkap: open ports, service versions, OS guess, script results, dan traceroute. Paling informatif tapi juga paling noisy."
        },
        kapanPakai: {
          kondisi: [
            "Kamu ingin informasi selengkap mungkin dalam satu scan — tidak peduli soal stealth",
            "Quick assessment satu host — misalnya CTF challenge atau lab environment",
            "Time-limited engagement dan perlu gather sebanyak mungkin info sekaligus",
            "Environment yang aman untuk noisy scan (lab, authorized testing, server sendiri)"
          ],
          setelah: "Host Discovery (-sn) — biasanya dijalankan pada target yang sudah dikonfirmasi aktif",
          jikaGagal: [
            "Terlalu lambat → jalankan komponen terpisah: -sV dulu, lalu -O, lalu -sC",
            "Terdeteksi/diblok → scan terlalu noisy, gunakan SYN scan dulu baru version detect secara selektif",
            "Script error → jalankan -sC secara terpisah untuk debug output"
          ]
        },
        skenario: [
          { role: "CTF Player", context: "Initial enumeration box target — gather semua info sekaligus untuk cari attack vector" },
          { role: "Pentester", context: "Quick scan single host di lab environment atau staging server" },
          { role: "Student", context: "Belajar Nmap — melihat semua tipe output sekaligus untuk memahami capabilities" },
          { role: "Sysadmin", context: "Full audit satu server — mengetahui semua service, versions, dan potential issues" }
        ],
        mitre: {
          tactic: { id: "TA0007", name: "Discovery" },
          technique: { id: "T1046", name: "Network Service Discovery" },
          killChain: "Reconnaissance → Weaponization",
          description: "Comprehensive target profiling — OS, services, versions, scripts dalam satu pass."
        },
        precautions: [
          { level: "high", text: "Memerlukan root/admin untuk OS detection dan SYN scan" },
          { level: "critical", text: "WAJIB memiliki written authorization" },
          { level: "high", text: "SANGAT NOISY — akan terdeteksi oleh hampir semua IDS/IPS dan firewall" },
          { level: "medium", text: "NSE scripts bisa memicu false positives di security monitoring" }
        ],
        impact: {
          traffic: "Very High — multiple scan types + scripts + traceroute",
          detection: "Very High — pasti terdeteksi oleh monitoring manapun",
          disruption: "Low-Medium — scripts biasanya safe tapi volume traffic bisa significant",
          legal: "Scanning tanpa izin tertulis dapat melanggar hukum"
        }
      }
    ]
  },

  // ═══════════════════════════════════════════
  //  5. OS DETECTION
  // ═══════════════════════════════════════════
  {
    id: "os-detection",
    label: "OS Detection",
    icon: "💻",
    scans: [
      {
        id: "os-detect",
        name: "OS Detection",
        flag: "-O",
        command: "nmap -O",
        fungsi: {
          title: "Operating System Fingerprinting",
          description: "Menganalisis TCP/IP stack implementation target untuk menebak OS yang digunakan. Setiap OS mengimplementasikan TCP/IP stack sedikit berbeda (initial TTL, window size, DF bit, TCP options order) — perbedaan ini menjadi 'fingerprint'.",
          howItWorks: [
            "Nmap mengirim serangkaian TCP dan UDP probes khusus",
            "Menganalisis response: initial TTL, window size, TCP options, IP ID sequence",
            "Mencocokkan fingerprint dengan database nmap-os-db (ribuan OS signatures)",
            "Memberikan OS guess dengan confidence percentage",
            "Memerlukan minimal 1 port open dan 1 port closed untuk hasil terbaik"
          ],
          output: "OS guess dengan confidence level (misal: 'Linux 5.4 - 5.15 (96%)'), device type, network distance."
        },
        kapanPakai: {
          kondisi: [
            "Perlu tahu OS target untuk memilih exploit atau technique yang tepat",
            "Service version detection tidak cukup — perlu OS-level information",
            "Mapping network inventory — mengetahui distribusi OS di network",
            "Memilih payload yang sesuai OS (Linux vs Windows vs embedded device)"
          ],
          setelah: "Port Scan (-sS/-sT) — butuh minimal 1 open + 1 closed port untuk akurasi terbaik",
          jikaGagal: [
            "No match → target mungkin hardened atau OS yang tidak ada di database, coba --osscan-guess",
            "Terlalu banyak kemungkinan → perlu lebih banyak open/closed ports, scan lebih banyak port",
            "Semua port filtered → OS detection butuh direct response dari TCP stack, pastikan ada port yang unfiltered"
          ]
        },
        skenario: [
          { role: "Pentester", context: "Menentukan OS untuk memilih exploit yang tepat — Linux EternalBlue berbeda dari Windows" },
          { role: "Red Team", context: "Profiling target untuk payload selection dan lateral movement strategy" },
          { role: "Blue Team", context: "Inventarisasi OS di network — mendeteksi unauthorized OS atau devices" },
          { role: "Compliance", context: "Verifikasi bahwa hanya approved OS yang jalan di network (policy enforcement)" }
        ],
        mitre: {
          tactic: { id: "TA0007", name: "Discovery" },
          technique: { id: "T1082", name: "System Information Discovery" },
          killChain: "Reconnaissance → Weaponization",
          description: "OS fingerprinting untuk menentukan attack vector yang tepat berdasarkan OS target."
        },
        precautions: [
          { level: "high", text: "Memerlukan root/admin privilege" },
          { level: "critical", text: "WAJIB memiliki written authorization" },
          { level: "medium", text: "Membutuhkan minimal 1 port open dan 1 port closed — scan port dulu" },
          { level: "low", text: "Virtualization dan containerization bisa membuat fingerprint tidak akurat" }
        ],
        impact: {
          traffic: "Moderate — serangkaian specialized probes",
          detection: "Medium — probe patterns bisa dikenali oleh IDS",
          disruption: "Minimal — probes tidak mengganggu service",
          legal: "Scanning tanpa izin tertulis dapat melanggar hukum"
        }
      }
    ]
  },

  // ═══════════════════════════════════════════
  //  6. NSE SCRIPTS
  // ═══════════════════════════════════════════
  {
    id: "nse-scripts",
    label: "NSE Scripts",
    icon: "📜",
    scans: [
      {
        id: "default-scripts",
        name: "Default Scripts",
        flag: "-sC",
        command: "nmap -sC",
        fungsi: {
          title: "Default NSE Script Scan",
          description: "Menjalankan koleksi NSE (Nmap Scripting Engine) scripts yang termasuk kategori <strong>'default'</strong>. Scripts ini dianggap safe, useful, dan tidak terlalu intrusive. Meliputi: banner grabbing, SSL cert info, HTTP title, DNS info, SMB security mode, dll.",
          howItWorks: [
            "Setelah port scan, Nmap menjalankan scripts dari kategori 'default' pada open ports",
            "Setiap script melakukan probe spesifik berdasarkan service yang ditemukan",
            "HTTP ports → http-title, http-server-header, http-robots.txt",
            "SSH ports → ssh-hostkey",
            "SSL/TLS ports → ssl-cert, ssl-date",
            "SMB ports → smb-security-mode, smb-os-discovery"
          ],
          output: "Output tambahan di bawah setiap port: script name dan hasilnya. Misal: http-title menunjukkan title halaman web."
        },
        kapanPakai: {
          kondisi: [
            "Port scan dan version detection sudah selesai — perlu informasi lebih detail dari setiap service",
            "Ingin otomatis extract informasi umum: HTTP titles, SSL certs, SMB info, DNS records",
            "Quick enumeration tanpa harus menjalankan script satu per satu",
            "Fase awal post-scanning enumeration"
          ],
          setelah: "Port Scan + Version Detection (-sV) — tahu service apa yang jalan",
          jikaGagal: [
            "Script timeout → tingkatkan timeout: --script-timeout 60s",
            "Perlu info lebih spesifik → gunakan --script dengan script name tertentu",
            "Terlalu banyak output → filter ke script tertentu: --script http-title,ssl-cert"
          ]
        },
        skenario: [
          { role: "Pentester", context: "Post-scan enumeration — otomatis mengumpulkan HTTP titles, SSL cert info, SMB details" },
          { role: "Red Team", context: "Automated information gathering — mencari low-hanging fruit (default credentials, exposed info)" },
          { role: "Blue Team", context: "Audit apa yang visible dari luar — apakah server leaking informasi sensitif" },
          { role: "CTF Player", context: "Quick enumeration target — default scripts sering memberikan clue yang berguna" }
        ],
        mitre: {
          tactic: { id: "TA0007", name: "Discovery" },
          technique: { id: "T1046", name: "Network Service Discovery" },
          killChain: "Reconnaissance → Weaponization",
          description: "Automated information gathering melalui NSE scripts — extracting service details dan potential vulnerabilities."
        },
        precautions: [
          { level: "low", text: "Tidak selalu memerlukan root — tergantung underlying scan type" },
          { level: "critical", text: "WAJIB memiliki written authorization" },
          { level: "medium", text: "Scripts membuat koneksi dan mengirim data ke services — tercatat di log" },
          { level: "low", text: "Default scripts designed to be safe — tapi tetap bisa trigger IDS" }
        ],
        impact: {
          traffic: "Medium-High — multiple connections dan data exchange per open port",
          detection: "High — script activity sangat visible di service logs",
          disruption: "Low — default scripts designed to be non-intrusive",
          legal: "Scanning tanpa izin tertulis dapat melanggar hukum"
        }
      },
      {
        id: "vuln-scripts",
        name: "Vulnerability Scripts",
        flag: "--script",
        flags: ["--script", "vuln"],
        command: "nmap --script vuln",
        fungsi: {
          title: "Vulnerability Detection Scripts",
          description: "Menjalankan NSE scripts dari kategori <strong>'vuln'</strong> — scripts yang secara khusus memeriksa known vulnerabilities. Termasuk check untuk: Heartbleed, EternalBlue, ShellShock, SlowLoris, dan puluhan CVE lainnya.",
          howItWorks: [
            "Nmap menjalankan semua scripts dalam kategori 'vuln' pada open ports",
            "Setiap script memeriksa vulnerability spesifik berdasarkan service yang ditemukan",
            "HTTP → http-vuln-cve2017-5638 (Struts RCE), http-shellshock",
            "SMB → smb-vuln-ms17-010 (EternalBlue), smb-vuln-ms08-067",
            "SSL → ssl-heartbleed, ssl-poodle, ssl-ccs-injection",
            "Script yang menemukan vulnerability akan melaporkan detail dan CVE number"
          ],
          output: "Daftar vulnerability yang ditemukan dengan CVE number, severity, dan deskripsi. Output VULNERABLE atau NOT VULNERABLE per check."
        },
        kapanPakai: {
          kondisi: [
            "Service versions sudah diidentifikasi dan kamu ingin cek known vulnerabilities",
            "Quick vulnerability assessment sebelum menggunakan dedicated vuln scanner",
            "Mencari low-hanging fruit: known CVEs yang mudah di-exploit",
            "CTF atau lab environment — cek apakah ada vulnerability yang intentionally planted"
          ],
          setelah: "Version Detection (-sV) — perlu tahu service versions untuk vuln check yang akurat",
          jikaGagal: [
            "Script error → beberapa vuln scripts memerlukan specific conditions, coba satu per satu",
            "False positives → cross-reference dengan manual verification atau dedicated scanner",
            "Perlu deeper scan → gunakan dedicated vulnerability scanner (Nessus, OpenVAS) untuk coverage lebih baik"
          ]
        },
        skenario: [
          { role: "Pentester", context: "Quick win identification — mencari known vulnerabilities yang bisa di-exploit langsung" },
          { role: "Red Team", context: "Automated vuln check di awal engagement — prioritaskan target berdasarkan vulnerability" },
          { role: "Blue Team", context: "Proactive vulnerability scanning — mendeteksi known vulnerabilities sebelum attacker" },
          { role: "CTF Player", context: "Enumeration phase — vuln scripts sering menemukan intended vulnerability dalam challenge" }
        ],
        mitre: {
          tactic: { id: "TA0043", name: "Reconnaissance" },
          technique: { id: "T1595.002", name: "Active Scanning: Vulnerability Scanning" },
          killChain: "Reconnaissance → Weaponization",
          description: "Automated vulnerability detection — identifikasi CVE yang bisa menjadi entry point."
        },
        precautions: [
          { level: "high", text: "Memerlukan root/admin untuk beberapa scripts" },
          { level: "critical", text: "WAJIB memiliki written authorization — vuln scanning lebih intrusive dari port scan" },
          { level: "high", text: "Beberapa vuln scripts mengirim exploit-like probes — bisa trigger WAF/IPS" },
          { level: "high", text: "Pada rare cases, beberapa probes bisa crash vulnerable services — selalu test di non-prod dulu" }
        ],
        impact: {
          traffic: "High — multiple exploit-like probes per service",
          detection: "Very High — vuln scanning probes sangat distinctive di IDS/WAF logs",
          disruption: "Medium — beberapa probes bisa mengganggu vulnerable services",
          legal: "Vulnerability scanning memerlukan izin eksplisit — lebih sensitif dari port scan biasa"
        }
      },
      {
        id: "auth-scripts",
        name: "Auth Scripts",
        flag: "--script",
        flags: ["--script", "auth"],
        command: "nmap --script auth",
        fungsi: {
          title: "Authentication Audit Scripts",
          description: "Menjalankan NSE scripts kategori <strong>'auth'</strong> — memeriksa authentication weaknesses: default credentials, anonymous access, null sessions, guest accounts, dan misconfigured authentication pada berbagai services.",
          howItWorks: [
            "Nmap menjalankan scripts auth-related pada setiap open port yang relevan",
            "FTP → ftp-anon (anonymous login allowed?)",
            "SMB → smb-enum-users (list users tanpa auth?), smb-security-mode",
            "MySQL → mysql-empty-password (akun tanpa password?)",
            "MongoDB → mongodb-info (no authentication?)",
            "SNMP → snmp-brute dengan common community strings"
          ],
          output: "Daftar authentication issues per service: anonymous access allowed, accounts tanpa password, default credentials yang masih aktif."
        },
        kapanPakai: {
          kondisi: [
            "Port scan dan version detection sudah selesai — perlu cek apakah services punya auth weaknesses",
            "Mencari quick wins: anonymous FTP, MySQL tanpa password, open MongoDB",
            "Audit konfigurasi authentication sebelum attacker menemukannya",
            "Post-exploitation lateral movement — cek services lain yang mungkin punya weak auth"
          ],
          setelah: "Version Detection (-sV) dan Default Scripts (-sC) — tahu service apa yang jalan",
          jikaGagal: [
            "Script tidak menemukan issues → bukan berarti aman, auth scripts hanya cek common weaknesses",
            "Script timeout → beberapa auth checks memerlukan waktu, tambah --script-timeout",
            "Perlu deeper check → gunakan dedicated tools (Hydra, Medusa) untuk comprehensive auth testing"
          ]
        },
        skenario: [
          { role: "Pentester", context: "Low-hanging fruit hunting — default creds dan anonymous access adalah common findings" },
          { role: "Red Team", context: "Quick credential check sebelum eskalasi ke brute force — avoid unnecessary noise" },
          { role: "Blue Team", context: "Audit berkala — pastikan tidak ada services yang accidentally exposed tanpa auth" },
          { role: "Compliance", context: "CIS benchmark check — verifikasi bahwa default accounts sudah disabled/changed" }
        ],
        mitre: {
          tactic: { id: "TA0006", name: "Credential Access" },
          technique: { id: "T1078.001", name: "Valid Accounts: Default Accounts" },
          killChain: "Reconnaissance → Exploitation",
          description: "Identifikasi authentication weaknesses — default credentials, anonymous access, null sessions."
        },
        precautions: [
          { level: "low", text: "Tidak selalu memerlukan root — tergantung service yang di-test" },
          { level: "critical", text: "WAJIB memiliki written authorization — auth testing bisa dianggap unauthorized access" },
          { level: "high", text: "Beberapa scripts melakukan login attempts — tercatat di auth logs dan bisa trigger lockout" },
          { level: "medium", text: "Successful anonymous/default login bisa memberikan akses — handle dengan hati-hati" }
        ],
        impact: {
          traffic: "Medium — connection + authentication exchange per service",
          detection: "High — failed login attempts sangat visible di auth logs dan SIEM",
          disruption: "Low-Medium — repeated auth attempts bisa trigger account lockout policy",
          legal: "Auth testing tanpa izin = unauthorized access attempt — sangat sensitif secara hukum"
        }
      },
      {
        id: "brute-scripts",
        name: "Brute Force Scripts",
        flag: "--script",
        flags: ["--script", "brute"],
        command: "nmap --script brute",
        fungsi: {
          title: "Brute Force Login Scripts",
          description: "Menjalankan NSE scripts kategori <strong>'brute'</strong> — melakukan brute force login ke services menggunakan wordlist username dan password. Mencoba kombinasi credentials umum untuk menemukan weak passwords.",
          howItWorks: [
            "Nmap menjalankan brute force scripts pada setiap open service yang mendukung authentication",
            "SSH → ssh-brute (brute force SSH login)",
            "FTP → ftp-brute (brute force FTP login)",
            "HTTP → http-brute (brute force HTTP basic auth)",
            "MySQL → mysql-brute, MSSQL → ms-sql-brute",
            "Menggunakan built-in wordlist atau custom list via --script-args"
          ],
          output: "Credentials yang berhasil ditemukan (username:password), serta jumlah attempts dan waktu yang dibutuhkan."
        },
        kapanPakai: {
          kondisi: [
            "Auth scripts tidak menemukan default creds tapi kamu suspect ada weak passwords",
            "Authorized pentest engagement yang secara eksplisit mencakup password testing",
            "CTF challenge yang require credential discovery",
            "Testing password policy enforcement — apakah weak passwords bisa digunakan"
          ],
          setelah: "Auth Scripts (--script auth) — cek default creds dulu sebelum brute force",
          jikaGagal: [
            "Account lockout triggered → stop dan kurangi intensity, gunakan --script-args brute.delay=3",
            "Wordlist terlalu kecil → gunakan custom wordlist: --script-args userdb=users.txt,passdb=pass.txt",
            "Terlalu lambat → fokus pada service tertentu: --script ssh-brute atau ftp-brute saja"
          ]
        },
        skenario: [
          { role: "Pentester", context: "Password strength testing — memvalidasi bahwa password policy diterapkan dengan benar" },
          { role: "Red Team", context: "Credential harvesting untuk initial access atau lateral movement" },
          { role: "Blue Team", context: "Testing account lockout policy — apakah brute force triggers lockout sesuai konfigurasi" },
          { role: "CTF Player", context: "Credential discovery phase — common step dalam CTF challenges" }
        ],
        mitre: {
          tactic: { id: "TA0006", name: "Credential Access" },
          technique: { id: "T1110.001", name: "Brute Force: Password Guessing" },
          killChain: "Weaponization → Exploitation",
          description: "Brute force credentials untuk mendapatkan initial access atau escalate privileges."
        },
        precautions: [
          { level: "critical", text: "WAJIB memiliki written authorization yang SECARA EKSPLISIT mencakup password testing" },
          { level: "high", text: "Bisa trigger account lockout — test di non-production atau pastikan lockout policy dipahami" },
          { level: "high", text: "Setiap login attempt tercatat — sangat noisy di security logs" },
          { level: "high", text: "Bisa dianggap denial-of-service jika menyebabkan mass account lockout" }
        ],
        impact: {
          traffic: "High — ribuan connection attempts per service",
          detection: "Very High — brute force patterns langsung terdeteksi oleh SIEM/IDS",
          disruption: "Medium-High — account lockout, possible service degradation",
          legal: "Brute force tanpa izin eksplisit adalah tindakan ilegal — pastikan scope sangat jelas"
        }
      },
      {
        id: "discovery-scripts",
        name: "Discovery Scripts",
        flag: "--script",
        flags: ["--script", "discovery"],
        command: "nmap --script discovery",
        fungsi: {
          title: "Network & Service Discovery Scripts",
          description: "Menjalankan NSE scripts kategori <strong>'discovery'</strong> — mengumpulkan informasi detail tentang network dan services: DNS enumeration, SNMP community strings, NTP info, LDAP queries, NetBIOS info, dan banyak lagi.",
          howItWorks: [
            "Nmap menjalankan discovery scripts pada open ports yang relevan",
            "DNS → dns-brute (subdomain enumeration), dns-zone-transfer",
            "SNMP → snmp-info, snmp-interfaces, snmp-processes",
            "LDAP → ldap-rootdse, ldap-search",
            "NetBIOS → nbstat (name service info)",
            "NTP → ntp-info, ntp-monlist (amplification check)"
          ],
          output: "Informasi detail per service: DNS records, SNMP system info, LDAP structure, network shares, system processes."
        },
        kapanPakai: {
          kondisi: [
            "Perlu informasi mendalam tentang infrastructure target — bukan hanya port/version tapi detail konfigurasi",
            "DNS enumeration untuk menemukan subdomain dan internal hostnames",
            "SNMP information gathering — sering expose detail system yang sangat berguna",
            "LDAP/AD enumeration untuk memahami domain structure"
          ],
          setelah: "Default Scripts (-sC) — butuh informasi lebih mendalam dari default output",
          jikaGagal: [
            "Script timeout pada slow services → tambah --script-timeout 120s",
            "SNMP community string wrong → specify custom: --script-args snmpcommunity=custom",
            "Terlalu banyak output → jalankan script spesifik: --script dns-brute atau --script snmp-info"
          ]
        },
        skenario: [
          { role: "Pentester", context: "Deep enumeration — DNS zone transfer, SNMP walks, LDAP queries untuk mapping infrastructure" },
          { role: "Red Team", context: "Intelligence gathering — menemukan internal hostnames, network topology, system details via SNMP" },
          { role: "Blue Team", context: "Exposure audit — apakah DNS zone transfer enabled? SNMP community string masih 'public'?" },
          { role: "Network Engineer", context: "Network documentation — otomatis gather info tentang devices dan services di network" }
        ],
        mitre: {
          tactic: { id: "TA0007", name: "Discovery" },
          technique: { id: "T1018", name: "Remote System Discovery" },
          killChain: "Reconnaissance",
          description: "Deep network dan service enumeration — mengumpulkan intelligence untuk planning attack path."
        },
        precautions: [
          { level: "low", text: "Tidak selalu memerlukan root — tergantung script" },
          { level: "critical", text: "WAJIB memiliki written authorization" },
          { level: "medium", text: "DNS brute force bisa generate banyak DNS queries — terdeteksi oleh DNS monitoring" },
          { level: "medium", text: "SNMP walks bisa mengambil informasi sensitif — handle output dengan hati-hati" }
        ],
        impact: {
          traffic: "Medium-High — banyak queries per service terutama DNS brute dan SNMP walk",
          detection: "Medium — DNS brute dan SNMP queries bisa trigger monitoring",
          disruption: "Low — discovery scripts umumnya read-only",
          legal: "Information gathering tanpa izin dapat melanggar hukum"
        }
      },
      {
        id: "exploit-scripts",
        name: "Exploit Scripts",
        flag: "--script",
        flags: ["--script", "exploit"],
        command: "nmap --script exploit",
        fungsi: {
          title: "Exploitation Scripts",
          description: "Menjalankan NSE scripts kategori <strong>'exploit'</strong> — scripts yang benar-benar mencoba <strong>mengeksploitasi</strong> vulnerability, bukan hanya mendeteksinya. Ini langkah lebih agresif dari vuln scripts — bisa menghasilkan shell, read files, atau modify data.",
          howItWorks: [
            "Nmap menjalankan exploit scripts pada services yang vulnerable",
            "HTTP → http-shellshock (execute commands via ShellShock)",
            "SMB → smb-vuln-ms17-010 dengan exploit mode",
            "Scripts mencoba exploitation langsung — bukan hanya detection",
            "Successful exploit bisa memberikan command execution atau data access",
            "Output menunjukkan apakah exploitation berhasil dan hasilnya"
          ],
          output: "Hasil exploitation: command output, file contents, atau confirmation bahwa exploit berhasil. VULNERABLE + exploitation evidence."
        },
        kapanPakai: {
          kondisi: [
            "Vuln scripts sudah mengkonfirmasi ada vulnerability dan kamu perlu prove exploitability",
            "Pentest engagement yang memerlukan proof of exploitation — bukan hanya vulnerability report",
            "Controlled lab/CTF environment untuk learning exploitation techniques",
            "HANYA ketika izin secara eksplisit mencakup exploitation — bukan hanya scanning"
          ],
          setelah: "Vulnerability Scripts (--script vuln) — vulnerability sudah dikonfirmasi",
          jikaGagal: [
            "Exploit gagal tapi vuln detected → vulnerability mungkin sudah di-patch partially, atau exploit conditions tidak terpenuhi",
            "Service crash → ini risiko inherent dari exploitation — harus sudah di-anticipate",
            "Perlu manual exploitation → gunakan Metasploit atau custom exploit untuk more control"
          ]
        },
        skenario: [
          { role: "Pentester", context: "Proof of concept — membuktikan bahwa vulnerability benar-benar exploitable, bukan hanya theoretical" },
          { role: "Red Team", context: "Initial access via automated exploitation — gaining foothold sebelum manual post-exploitation" },
          { role: "Security Researcher", context: "Testing exploit reliability — apakah exploit bisa direproduksi secara consistent" },
          { role: "CTF Player", context: "Automated exploitation — banyak CTF challenges bisa diselesaikan dengan NSE exploit scripts" }
        ],
        mitre: {
          tactic: { id: "TA0001", name: "Initial Access" },
          technique: { id: "T1190", name: "Exploit Public-Facing Application" },
          killChain: "Exploitation",
          description: "Active exploitation — mengeksploitasi vulnerability untuk mendapatkan access atau execute commands."
        },
        precautions: [
          { level: "critical", text: "WAJIB memiliki written authorization yang SECARA EKSPLISIT mengizinkan exploitation" },
          { level: "critical", text: "BISA CRASH SERVICES — jangan jalankan di production tanpa persetujuan dan backup plan" },
          { level: "high", text: "Exploitation attempts tercatat di semua security systems — sangat noisy" },
          { level: "high", text: "Successful exploit = akses ke system — tangani dengan responsible disclosure jika unexpected" }
        ],
        impact: {
          traffic: "High — exploit payloads bisa substantial",
          detection: "Very High — exploit attempts langsung trigger IDS/IPS/WAF alerts",
          disruption: "High — exploitation bisa crash service, corrupt data, atau cause outage",
          legal: "Exploitation tanpa izin eksplisit = unauthorized access — bisa dipidanakan"
        }
      },
      {
        id: "safe-scripts",
        name: "Safe Scripts",
        flag: "--script",
        flags: ["--script", "safe"],
        command: "nmap --script safe",
        fungsi: {
          title: "Non-Intrusive Safe Scripts",
          description: "Menjalankan NSE scripts kategori <strong>'safe'</strong> — scripts yang dirancang untuk <strong>tidak mengganggu</strong> target. Mengumpulkan informasi tanpa risiko crash, lockout, atau service disruption. Ideal untuk scanning di production environment.",
          howItWorks: [
            "Nmap menjalankan scripts yang tagged 'safe' pada open ports",
            "Hanya melakukan passive/read-only operations",
            "HTTP → http-headers, http-favicon-hash, http-methods",
            "SSH → ssh-hostkey, ssh2-enum-algos",
            "SSL → ssl-cert, ssl-date, ssl-known-key",
            "Tidak melakukan login attempts, brute force, atau exploitation"
          ],
          output: "Informasi detail tapi non-intrusive: headers, certificates, supported algorithms, server info — tanpa risiko disruption."
        },
        kapanPakai: {
          kondisi: [
            "Scanning production environment dan tidak boleh mengganggu service sama sekali",
            "Perlu informasi detail tapi risk appetite sangat rendah",
            "Management hanya mengizinkan non-intrusive scanning",
            "Gathering baseline information sebelum meminta approval untuk scan yang lebih agresif"
          ],
          setelah: "Port Scan — bisa langsung setelah port scan tanpa perlu version detection dulu",
          jikaGagal: [
            "Informasi terlalu sedikit → upgrade ke default scripts (-sC) yang sedikit lebih aggressive",
            "Perlu info lebih → jalankan safe + default: --script 'safe and default'",
            "Specific info needed → jalankan script individual yang sudah di-review safety-nya"
          ]
        },
        skenario: [
          { role: "Pentester", context: "Initial recon di production environment — gathering info tanpa risiko disruption" },
          { role: "Blue Team", context: "Regular scanning production servers — compliance tanpa risiko downtime" },
          { role: "Compliance", context: "Audit scanning yang minimal-risk — memenuhi requirement tanpa mengganggu operations" },
          { role: "Sysadmin", context: "Information gathering tentang own infrastructure — safe to run kapan saja" }
        ],
        mitre: {
          tactic: { id: "TA0007", name: "Discovery" },
          technique: { id: "T1046", name: "Network Service Discovery" },
          killChain: "Reconnaissance",
          description: "Non-intrusive information gathering — safe untuk production environment."
        },
        precautions: [
          { level: "low", text: "Tidak memerlukan root untuk kebanyakan safe scripts" },
          { level: "critical", text: "WAJIB memiliki written authorization — meskipun safe, tetap perlu izin" },
          { level: "low", text: "Risiko disruption sangat minimal — designed to be safe" },
          { level: "low", text: "Tetap membuat koneksi ke services — akan ada log entries" }
        ],
        impact: {
          traffic: "Low-Medium — koneksi normal tanpa aggressive probing",
          detection: "Low-Medium — terlihat di logs tapi tidak trigger security alerts",
          disruption: "Minimal — designed to be non-intrusive",
          legal: "Meskipun safe, scanning tanpa izin tetap bisa melanggar hukum"
        }
      },
      {
        id: "http-enum",
        name: "HTTP Enumeration",
        flag: "--script",
        flags: ["--script", "http-enum"],
        command: "nmap --script http-enum",
        fungsi: {
          title: "Web Directory & File Enumeration",
          description: "Menjalankan script <strong>http-enum</strong> — mengenumerasi directories dan files umum di web server: admin panels, backup files, configuration files, CMS paths, database interfaces, dan lainnya.",
          howItWorks: [
            "Nmap mengirim HTTP requests ke daftar common paths dan files",
            "Memeriksa response code: 200 (found), 403 (forbidden but exists), 301/302 (redirect)",
            "Database 1000+ paths: /admin, /phpmyadmin, /wp-admin, /backup, /.git, /robots.txt",
            "Bisa di-extend dengan custom fingerprint file",
            "Mirip dengan tools seperti dirb/dirbuster/gobuster tapi terintegrasi di Nmap"
          ],
          output: "Daftar directories dan files yang ditemukan dengan HTTP status code dan description."
        },
        kapanPakai: {
          kondisi: [
            "Web server ditemukan (port 80/443/8080) dan perlu enumerate content yang tersedia",
            "Mencari admin panels, backup files, exposed configuration, atau hidden directories",
            "Quick web enumeration sebelum menggunakan dedicated tools (gobuster, ffuf)",
            "Checking apakah sensitive files exposed (.git, .env, backup.sql, dll)"
          ],
          setelah: "Port Scan menunjukkan HTTP service open — dan Version Detection (-sV) mengkonfirmasi web server",
          jikaGagal: [
            "WAF blocking requests → coba tambah --script-args http-enum.displayall untuk lihat semua attempts",
            "Terlalu sedikit results → gunakan dedicated tools (gobuster, ffuf) dengan wordlist lebih besar",
            "False positives → verify manual dengan browser atau curl"
          ]
        },
        skenario: [
          { role: "Pentester", context: "Web application assessment — menemukan hidden admin panels, backup files, exposed git repos" },
          { role: "Red Team", context: "Quick web recon — mencari entry points sebelum deep web app testing" },
          { role: "Blue Team", context: "Audit web exposure — memastikan tidak ada sensitive files yang publicly accessible" },
          { role: "Bug Bounty", context: "Initial enumeration — http-enum sering menemukan interesting paths yang bisa di-exploit" }
        ],
        mitre: {
          tactic: { id: "TA0007", name: "Discovery" },
          technique: { id: "T1083", name: "File and Directory Discovery" },
          killChain: "Reconnaissance → Weaponization",
          description: "Web content discovery — menemukan hidden files dan directories yang bisa menjadi attack vector."
        },
        precautions: [
          { level: "low", text: "Tidak memerlukan root — HTTP requests biasa" },
          { level: "critical", text: "WAJIB memiliki written authorization" },
          { level: "medium", text: "1000+ HTTP requests bisa trigger WAF rate limiting atau IP ban" },
          { level: "medium", text: "Web access logs akan mencatat semua requests — sangat visible" }
        ],
        impact: {
          traffic: "Medium-High — 1000+ HTTP requests ke target",
          detection: "High — burst of 404/403 responses sangat visible di web server logs dan WAF",
          disruption: "Low — read-only HTTP requests, tapi high volume bisa affect performance",
          legal: "Web enumeration tanpa izin dapat melanggar hukum"
        }
      },
      {
        id: "smb-enum-shares",
        name: "SMB Share Enumeration",
        flag: "--script",
        flags: ["--script", "smb-enum-shares"],
        command: "nmap --script smb-enum-shares",
        fungsi: {
          title: "SMB/CIFS Network Share Discovery",
          description: "Menjalankan script <strong>smb-enum-shares</strong> — mengenumerasi shared folders di Windows/Samba server. Menampilkan share name, type, comment, dan access permissions (read/write) untuk anonymous dan authenticated users.",
          howItWorks: [
            "Nmap connects ke SMB service (port 445 atau 139)",
            "Mencoba enumerate shares menggunakan null session (anonymous)",
            "Untuk setiap share: mencoba baca dan tulis untuk determine permissions",
            "Menampilkan: share name, type (Disk/Print/IPC), comment, read/write access",
            "Bisa dikombinasikan dengan credentials: --script-args smbuser=admin,smbpass=pass"
          ],
          output: "Daftar network shares dengan permission level: READ, WRITE, atau NO ACCESS. Termasuk default shares (C$, ADMIN$, IPC$)."
        },
        kapanPakai: {
          kondisi: [
            "SMB port (445/139) open dan perlu enumerate shared resources",
            "Mencari sensitive files di network shares yang misconfigured",
            "Windows environment assessment — SMB shares sering overly permissive",
            "Post-exploitation lateral movement — mencari shares yang bisa diakses dengan captured credentials"
          ],
          setelah: "Port Scan menunjukkan SMB open (445/139) — lalu Version Detection mengkonfirmasi Windows/Samba",
          jikaGagal: [
            "Null session diblok → coba dengan captured credentials: --script-args smbuser=user,smbpass=pass",
            "SMB signing required → script mungkin gagal, gunakan tools dedicated (smbclient, CrackMapExec)",
            "Firewall blocking → pastikan port 445 benar-benar accessible"
          ]
        },
        skenario: [
          { role: "Pentester", context: "Windows environment assessment — mencari writable shares, sensitive documents, exposed configurations" },
          { role: "Red Team", context: "Lateral movement recon — shares mana yang bisa diakses untuk pivot atau data exfiltration" },
          { role: "Blue Team", context: "Share permission audit — memastikan hanya authorized users yang punya access" },
          { role: "Compliance", context: "Data exposure check — file shares sering mengandung sensitive data tanpa proper ACL" }
        ],
        mitre: {
          tactic: { id: "TA0007", name: "Discovery" },
          technique: { id: "T1135", name: "Network Share Discovery" },
          killChain: "Reconnaissance → Lateral Movement",
          description: "SMB share enumeration — menemukan shared resources dan permission misconfigurations."
        },
        precautions: [
          { level: "low", text: "Tidak memerlukan root — SMB connection biasa" },
          { level: "critical", text: "WAJIB memiliki written authorization" },
          { level: "high", text: "Share access attempts tercatat di Windows Security Event Log (Event ID 5140, 5145)" },
          { level: "medium", text: "Null session enumeration mungkin diblok di modern Windows — perlu credentials" }
        ],
        impact: {
          traffic: "Low-Medium — SMB protocol exchanges",
          detection: "High — share access attempts langsung visible di Windows Event Logs",
          disruption: "Minimal — read-only enumeration",
          legal: "Accessing network shares tanpa izin = unauthorized access"
        }
      },
      {
        id: "ssl-enum-ciphers",
        name: "SSL/TLS Cipher Audit",
        flag: "--script",
        flags: ["--script", "ssl-enum-ciphers"],
        command: "nmap --script ssl-enum-ciphers -p 443",
        fungsi: {
          title: "SSL/TLS Cipher Suite Enumeration",
          description: "Menjalankan script <strong>ssl-enum-ciphers</strong> — mengenumerasi semua cipher suites yang didukung oleh SSL/TLS service, beserta grading (A-F) untuk setiap cipher. Mengidentifikasi weak ciphers, deprecated protocols, dan misconfiguration.",
          howItWorks: [
            "Nmap melakukan TLS handshake dengan setiap cipher suite yang diketahui",
            "Menentukan cipher mana yang accepted dan mana yang rejected oleh server",
            "Memberikan grade per cipher: A (strong), B (adequate), C (weak), D-F (insecure)",
            "Memeriksa dukungan protocol: SSLv3, TLSv1.0, TLSv1.1, TLSv1.2, TLSv1.3",
            "Overall grade diberikan berdasarkan weakest accepted cipher"
          ],
          output: "Daftar lengkap supported cipher suites per TLS version, dengan grade dan warnings untuk weak/insecure ciphers."
        },
        kapanPakai: {
          kondisi: [
            "HTTPS/SSL service ditemukan dan perlu audit cipher configuration",
            "Compliance requirement (PCI DSS, HIPAA) mengharuskan strong cipher usage",
            "Checking apakah server masih mendukung deprecated protocols (SSLv3, TLSv1.0)",
            "Verifikasi setelah SSL configuration hardening — apakah weak ciphers sudah disabled"
          ],
          setelah: "Port Scan menunjukkan SSL/TLS service (443, 8443, atau port dengan SSL)",
          jikaGagal: [
            "Connection refused → port mungkin bukan SSL, atau menggunakan STARTTLS (gunakan --script ssl-enum-ciphers,ssl-cert)",
            "Terlalu lambat → banyak cipher combinations, bersabar atau limit ke TLS version tertentu",
            "Perlu testing lebih detail → gunakan testssl.sh atau SSLyze untuk analysis mendalam"
          ]
        },
        skenario: [
          { role: "Pentester", context: "SSL/TLS configuration audit — mencari weak ciphers dan deprecated protocols" },
          { role: "Blue Team", context: "Compliance validation — memastikan TLSv1.2+ dan strong ciphers yang aktif" },
          { role: "Compliance", context: "PCI DSS requirement — verifikasi bahwa SSLv3, TLSv1.0, TLSv1.1 sudah disabled" },
          { role: "Sysadmin", context: "Post-hardening verification — konfirmasi bahwa cipher configuration sudah sesuai best practice" }
        ],
        mitre: {
          tactic: { id: "TA0007", name: "Discovery" },
          technique: { id: "T1046", name: "Network Service Discovery" },
          killChain: "Reconnaissance",
          description: "SSL/TLS cipher audit — identifikasi cryptographic weaknesses yang bisa di-exploit (downgrade attacks, BEAST, POODLE)."
        },
        precautions: [
          { level: "low", text: "Tidak memerlukan root — TLS handshake biasa" },
          { level: "critical", text: "WAJIB memiliki written authorization" },
          { level: "low", text: "Non-intrusive — hanya melakukan TLS handshake negotiation" },
          { level: "low", text: "Scan bisa lambat karena banyak cipher combinations — normal behavior" }
        ],
        impact: {
          traffic: "Medium — banyak TLS handshake attempts dengan different ciphers",
          detection: "Low — TLS handshakes terlihat normal, hanya volume yang unusual",
          disruption: "Minimal — hanya handshake, tidak membuat full connection",
          legal: "Cipher enumeration relatif non-intrusive tapi tetap butuh izin"
        }
      }
    ]
  },

  // ═══════════════════════════════════════════
  //  7. FIREWALL / IDS EVASION
  // ═══════════════════════════════════════════
  {
    id: "evasion",
    label: "Firewall / IDS Evasion",
    icon: "🛡️",
    scans: [
      {
        id: "fragment-scan",
        name: "Fragment Packets",
        flag: "-f",
        flags: ["-f", "-sS"],
        command: "nmap -f -sS",
        fungsi: {
          title: "IP Fragmentation Evasion",
          description: "Memecah paket scan menjadi fragmen-fragmen IP kecil (8 bytes per fragment). Banyak packet-filter firewalls dan IDS yang kesulitan memeriksa fragmented packets karena harus reassemble sebelum inspect.",
          howItWorks: [
            "Nmap memecah TCP header menjadi beberapa IP fragments kecil",
            "Setiap fragment berukuran 8 bytes (-f) atau 16 bytes (-ff)",
            "Firewall/IDS harus reassemble fragments sebelum bisa inspect",
            "Banyak device yang tidak reassemble fragments → scan melewati filter"
          ],
          output: "Sama seperti scan type yang digunakan (-sS/-sF/dll) — fragmentation hanya mengubah cara paket dikirim, bukan hasil scan."
        },
        kapanPakai: {
          kondisi: [
            "Firewall atau IDS memblok scan biasa dan kamu perlu bypass",
            "SYN scan terdeteksi/diblok dan FIN/Xmas/Null juga gagal",
            "Perlu technique tambahan di atas stealth scan (kombinasi: -f -sF)",
            "Testing apakah firewall/IDS mampu handle fragmented packets"
          ],
          setelah: "Stealth scans (-sF/-sX/-sN) masih diblok atau terdeteksi",
          jikaGagal: [
            "Modern firewall bisa reassemble fragments → coba --mtu untuk custom fragment size",
            "Coba kombinasi dengan decoy (-D) atau timing (-T2) untuk tambahan evasion",
            "Jika masih gagal → target punya defense-in-depth yang bagus, consider alternate approaches"
          ]
        },
        skenario: [
          { role: "Pentester", context: "Bypassing packet-filter firewall yang tidak reassemble fragments" },
          { role: "Red Team", context: "Layered evasion — fragmentation dikombinasikan dengan stealth scan dan timing" },
          { role: "Blue Team", context: "Testing apakah firewall/IDS bisa mendeteksi scan melalui fragmented packets" },
          { role: "Security Auditor", context: "Evaluasi kemampuan firewall dalam handling IP fragmentation" }
        ],
        mitre: {
          tactic: { id: "TA0005", name: "Defense Evasion" },
          technique: { id: "T1027.013", name: "Obfuscated Files or Information: Encrypted/Encoded File" },
          additionalTactic: { id: "TA0007", name: "Discovery" },
          killChain: "Weaponization → Delivery",
          description: "IP fragmentation untuk menghindari packet inspection oleh firewall dan IDS."
        },
        precautions: [
          { level: "high", text: "Memerlukan root/admin privilege" },
          { level: "critical", text: "WAJIB memiliki written authorization" },
          { level: "medium", text: "Beberapa OS dan network stack tidak handle fragmentation dengan baik — bisa cause issues" },
          { level: "medium", text: "Modern firewalls (Palo Alto, Fortinet, etc.) bisa reassemble fragments — tidak selalu efektif" }
        ],
        impact: {
          traffic: "Higher — lebih banyak paket karena fragmentation (3-4x lebih banyak)",
          detection: "Low-Medium — fragmented packets sendiri bisa jadi anomali yang terdeteksi",
          disruption: "Low — fragments yang reassembled = same as normal scan",
          legal: "Evasion techniques dianggap lebih agresif — pastikan scope izin mencakup ini"
        }
      },
      {
        id: "decoy-scan",
        name: "Decoy Scan",
        flag: "-D",
        flags: ["-D", "RND:5", "-sS"],
        command: "nmap -D RND:5 -sS",
        fungsi: {
          title: "Decoy IP Spoofing",
          description: "Membuat scan terlihat seperti berasal dari beberapa IP address berbeda (decoys) selain IP asli kamu. Target melihat multiple source IPs melakukan scan — sulit menentukan mana scanner yang sebenarnya.",
          howItWorks: [
            "Nmap mengirim paket scan dari IP asli kamu DAN spoofed decoy IPs",
            "Target melihat scan dari banyak IP sekaligus",
            "RND:5 = 5 random decoy IPs yang di-generate otomatis",
            "Bisa juga specify IP tertentu: -D 10.0.0.1,10.0.0.2,ME",
            "ME menandai posisi IP asli kamu dalam urutan decoy"
          ],
          output: "Sama seperti scan biasa — decoy hanya mengubah cara paket dikirim untuk membingungkan target."
        },
        kapanPakai: {
          kondisi: [
            "Kamu ingin menyembunyikan IP asli di antara traffic decoy",
            "IDS mendeteksi scan dari IP kamu — decoy membuat korelasi lebih sulit",
            "Blue team exercise — testing apakah SOC bisa identify real scanner di antara decoys",
            "Kombinasi evasion techniques: fragmentation + decoy + timing"
          ],
          setelah: "Scan biasa terdeteksi dan IP kamu di-flag oleh IDS/firewall",
          jikaGagal: [
            "Decoy IPs yang dead/unreachable → mudah di-filter, pilih decoy yang plausible",
            "Stateful firewall bisa track real connection → decoy SYN tanpa follow-up mudah diidentifikasi",
            "Rate limiting per-IP → decoy tetap terkena rate limit"
          ]
        },
        skenario: [
          { role: "Pentester", context: "Obscuring scan source — membuat log forensics lebih sulit untuk target" },
          { role: "Red Team", context: "Menyembunyikan C2/scanning infrastructure di antara decoy traffic" },
          { role: "Blue Team", context: "Testing kemampuan SIEM dalam mengkorelasi dan identify real attacker dari decoys" },
          { role: "Security Researcher", context: "Testing IDS correlation capability terhadap multi-source scanning patterns" }
        ],
        mitre: {
          tactic: { id: "TA0005", name: "Defense Evasion" },
          technique: { id: "T1665", name: "Hide Infrastructure" },
          additionalTactic: { id: "TA0007", name: "Discovery" },
          killChain: "Weaponization → Delivery",
          description: "Menyembunyikan sumber scan di antara decoy IPs untuk menghindari attribution."
        },
        precautions: [
          { level: "high", text: "Memerlukan root/admin privilege untuk IP spoofing" },
          { level: "critical", text: "WAJIB memiliki written authorization — spoofing bisa affect innocent third parties" },
          { level: "high", text: "Decoy IPs yang spoofed bisa menerima response traffic — jangan gunakan IP milik orang lain" },
          { level: "medium", text: "ISP atau network equipment mungkin drop spoofed packets (egress filtering)" }
        ],
        impact: {
          traffic: "Very High — traffic dikalikan jumlah decoy + 1",
          detection: "Medium — banyak IPs scanning sekaligus itu sendiri anomali",
          disruption: "Low — sama seperti scan biasa per individual scan",
          legal: "IP spoofing tambah layer legal complexity — pastikan scope izin sangat jelas"
        }
      },
      {
        id: "source-port",
        name: "Source Port Spoof",
        flag: "--source-port",
        flags: ["--source-port", "53", "-sS"],
        command: "nmap --source-port 53 -sS",
        fungsi: {
          title: "Source Port Manipulation",
          description: "Menggunakan source port tertentu untuk scan — misalnya port 53 (DNS) atau port 80 (HTTP). Beberapa firewall rules mengizinkan traffic dari 'trusted' source ports, sehingga scan dengan source port DNS/HTTP bisa melewati filter.",
          howItWorks: [
            "Nmap menggunakan source port yang ditentukan untuk semua paket scan",
            "Port 53: firewall mungkin mengizinkan karena dianggap DNS response",
            "Port 80: firewall mungkin mengizinkan karena dianggap HTTP response",
            "Port 88: bisa terlihat seperti Kerberos traffic",
            "Firewall dengan rule 'allow from port 53' akan meloloskan scan"
          ],
          output: "Sama seperti scan biasa — source port hanya mengubah header paket yang dikirim."
        },
        kapanPakai: {
          kondisi: [
            "Firewall rules berdasarkan source port (legacy/misconfigured firewall)",
            "Scan dari source port random diblok tapi 'known' ports diizinkan",
            "Testing apakah firewall rules terlalu permissive terhadap trusted source ports",
            "Kombinasi dengan teknik evasion lain untuk bypass layered defenses"
          ],
          setelah: "Scan biasa diblok oleh firewall — mencoba bypass via trusted source port",
          jikaGagal: [
            "Modern firewall inspect bidirectional traffic → source port spoofing tidak efektif",
            "Stateful firewall track connection state → spoofed source port tanpa matching session di-drop",
            "Coba source port lain (80, 88, 443) atau kombinasi dengan fragmentation"
          ]
        },
        skenario: [
          { role: "Pentester", context: "Exploiting misconfigured firewall rules yang trust traffic berdasarkan source port" },
          { role: "Red Team", context: "Bypassing legacy firewalls yang masih pakai source port-based filtering" },
          { role: "Blue Team", context: "Audit firewall rules — apakah ada rules yang terlalu permissive berdasarkan source port" },
          { role: "Security Auditor", context: "Testing firewall rules compliance — source port-based rules seharusnya sudah deprecated" }
        ],
        mitre: {
          tactic: { id: "TA0005", name: "Defense Evasion" },
          technique: { id: "T1205", name: "Traffic Signaling" },
          additionalTactic: { id: "TA0007", name: "Discovery" },
          killChain: "Delivery",
          description: "Manipulasi source port untuk bypass firewall rules yang filter berdasarkan port."
        },
        precautions: [
          { level: "high", text: "Memerlukan root/admin privilege" },
          { level: "critical", text: "WAJIB memiliki written authorization" },
          { level: "low", text: "Hanya efektif terhadap firewall yang filter berdasarkan source port (legacy)" },
          { level: "low", text: "Modern stateful firewalls tidak terpengaruh oleh teknik ini" }
        ],
        impact: {
          traffic: "Same as normal scan — hanya source port yang berbeda",
          detection: "Low-Medium — DNS traffic ke non-DNS port bisa terlihat anomali",
          disruption: "Minimal — sama seperti scan biasa",
          legal: "Evasion techniques memerlukan izin eksplisit"
        }
      }
    ]
  },

  // ═══════════════════════════════════════════
  //  8. OUTPUT & TIMING
  // ═══════════════════════════════════════════
  {
    id: "output-timing",
    label: "Output & Timing",
    icon: "⏱️",
    scans: [
      {
        id: "timing-templates",
        name: "Timing Templates",
        optionsConfig: { timing: false },
        flag: "-T",
        flags: ["-T4", "-sS"],
        command: "nmap -T4 -sS",
        fungsi: {
          title: "Scan Speed & Stealth Control",
          description: "Mengontrol kecepatan scan dengan template T0-T5. Semakin rendah angka, semakin lambat dan stealth. Semakin tinggi, semakin cepat tapi noisy. Timing mempengaruhi: probe timeout, delay antar probe, parallelism, dan retries.",
          howItWorks: [
            "T0 (Paranoid): 5 menit antar probe — untuk IDS evasion extreme",
            "T1 (Sneaky): 15 detik antar probe — stealth scanning",
            "T2 (Polite): 0.4 detik antar probe — mengurangi network load",
            "T3 (Normal): default — keseimbangan speed dan reliability",
            "T4 (Aggressive): parallelism tinggi — untuk network yang fast dan reliable",
            "T5 (Insane): sacrifice accuracy untuk maximum speed — bisa miss ports"
          ],
          output: "Sama seperti scan biasa — timing hanya mengubah kecepatan, bukan tipe informasi."
        },
        kapanPakai: {
          kondisi: [
            "T0-T1: Perlu menghindari deteksi IDS — scan sangat perlahan di bawah radar",
            "T2: Scanning production network dan tidak ingin mengganggu traffic",
            "T3: Default — cocok untuk kebanyakan situasi",
            "T4: Lab/testing environment, network fast, butuh hasil cepat",
            "T5: CTF dengan time limit, atau scanning localhost"
          ],
          setelah: "Digunakan BERSAMAAN dengan scan type — bukan standalone",
          jikaGagal: [
            "T4-T5 miss ports → turunkan ke T3 atau T2 untuk reliability",
            "T0-T1 terlalu lambat → naikkan ke T2, atau kurangi jumlah port yang di-scan",
            "Bisa fine-tune individual parameter: --min-rate, --max-rate, --max-retries"
          ]
        },
        skenario: [
          { role: "Pentester", context: "T4 untuk internal network assessment — fast scan dengan good reliability" },
          { role: "Red Team", context: "T1-T2 untuk external recon — scan perlahan untuk hindari SOC detection" },
          { role: "Blue Team", context: "T0-T1 simulated slow scan — testing apakah IDS mendeteksi low-and-slow scanning" },
          { role: "CTF Player", context: "T4-T5 untuk speed — time is limited dan detection tidak jadi concern" }
        ],
        mitre: {
          tactic: { id: "TA0005", name: "Defense Evasion" },
          technique: { id: "T1029", name: "Scheduled Transfer" },
          killChain: "Reconnaissance",
          description: "Timing control untuk balance antara speed, stealth, dan accuracy."
        },
        precautions: [
          { level: "low", text: "Tidak memerlukan root — timing applicable ke semua scan types" },
          { level: "low", text: "T0-T1 bisa memakan waktu SANGAT LAMA — plan accordingly" },
          { level: "medium", text: "T4-T5 bisa miss ports atau memberikan false results — jangan untuk critical scans" },
          { level: "low", text: "T5 bisa overwhelm target network — gunakan hanya di controlled environment" }
        ],
        impact: {
          traffic: "Varies: T0 = minimal over long period, T5 = burst of high traffic",
          detection: "T0-T1: Very Low, T2-T3: Medium, T4-T5: High",
          disruption: "T0-T2: Minimal, T3: Low, T4: Low-Medium, T5: Medium (bisa affect network performance)",
          legal: "Timing tidak mengubah legalitas — tetap butuh izin"
        }
      },
      {
        id: "output-normal",
        name: "Normal Output",
        flag: "-oN",
        flags: ["-oN", "scan_result.txt", "-sS"],
        command: "nmap -oN scan_result.txt -sS",
        fungsi: {
          title: "Save Output to Text File",
          description: "Menyimpan output scan ke file text biasa — format yang sama persis seperti yang tampil di terminal. Berguna untuk dokumentasi, reporting, dan review nanti.",
          howItWorks: [
            "Nmap menjalankan scan seperti biasa",
            "Output ditampilkan di terminal DAN disimpan ke file yang ditentukan",
            "Format file sama persis dengan terminal output",
            "File bisa dibaca dengan text editor biasa"
          ],
          output: "File text berisi output scan lengkap — bisa di-review, di-share, atau dimasukkan ke report."
        },
        kapanPakai: {
          kondisi: [
            "Perlu menyimpan hasil scan untuk dokumentasi atau reporting",
            "Scan memakan waktu lama dan kamu tidak ingin kehilangan hasilnya",
            "Perlu membandingkan hasil scan dari waktu berbeda (baseline comparison)",
            "Pentest engagement yang memerlukan evidence dan documentation trail"
          ],
          setelah: "Digunakan BERSAMAAN dengan scan type — bukan standalone",
          jikaGagal: [
            "File permission error → pastikan directory writable",
            "Butuh format parseable → gunakan -oX (XML) atau -oG (greppable) sebagai gantinya",
            "Butuh semua format → gunakan -oA basename untuk generate .nmap, .xml, dan .gnmap sekaligus"
          ]
        },
        skenario: [
          { role: "Pentester", context: "Dokumentasi evidence — menyimpan semua scan results untuk penetration test report" },
          { role: "Blue Team", context: "Baseline documentation — simpan scan results untuk comparison di future scan" },
          { role: "Compliance", context: "Audit trail — menyimpan bukti scanning yang dilakukan sesuai requirement" },
          { role: "Student", context: "Review dan belajar — simpan output untuk dipelajari kembali" }
        ],
        mitre: {
          tactic: { id: "TA0007", name: "Discovery" },
          technique: { id: "T1046", name: "Network Service Discovery" },
          killChain: "Reconnaissance",
          description: "Dokumentasi scan results untuk reporting dan analysis."
        },
        precautions: [
          { level: "low", text: "Tidak ada risiko tambahan — hanya menyimpan output yang sudah dihasilkan" },
          { level: "medium", text: "File output berisi informasi sensitif (target IPs, open ports) — amankan file-nya" },
          { level: "low", text: "Pastikan ada cukup disk space untuk output (scan besar bisa generate file besar)" },
          { level: "low", text: "Gunakan nama file yang descriptive: include tanggal, target, scan type" }
        ],
        impact: {
          traffic: "Same as underlying scan — output format tidak affect network traffic",
          detection: "Same as underlying scan",
          disruption: "Same as underlying scan",
          legal: "Simpan output scan sebagai bukti bahwa scanning dilakukan sesuai scope izin"
        }
      },
      {
        id: "output-xml",
        name: "XML Output",
        flag: "-oX",
        flags: ["-oX", "scan_result.xml", "-sS"],
        command: "nmap -oX scan_result.xml -sS",
        fungsi: {
          title: "Save Output as XML",
          description: "Menyimpan output scan dalam format XML yang structured dan machine-readable. Bisa di-parse oleh tools lain, di-import ke database, atau diolah dengan script. Format standar untuk integrasi dengan security tools.",
          howItWorks: [
            "Nmap menjalankan scan dan menyimpan hasilnya dalam format XML",
            "XML berisi semua data: hosts, ports, services, versions, scripts, OS detection",
            "Bisa di-parse dengan Python (xml.etree), atau tools seperti searchsploit",
            "Compatible dengan Metasploit (db_import), Faraday, dan banyak security tools"
          ],
          output: "File XML berisi structured data dari scan — bisa diolah secara programmatic."
        },
        kapanPakai: {
          kondisi: [
            "Perlu import hasil scan ke tools lain (Metasploit, Faraday, custom scripts)",
            "Automasi reporting — parse XML untuk generate custom reports",
            "Perlu format yang machine-readable untuk processing lebih lanjut",
            "Integrasi dengan security pipeline atau SIEM"
          ],
          setelah: "Digunakan BERSAMAAN dengan scan type — bukan standalone",
          jikaGagal: [
            "XML terlalu complex → gunakan -oG (greppable) untuk quick parsing",
            "Perlu human-readable → gunakan -oN (normal text) sebagai tambahan",
            "Import error ke tools → cek XML validity, Nmap output biasanya valid XML"
          ]
        },
        skenario: [
          { role: "Pentester", context: "Import scan results ke Metasploit untuk exploitation phase — db_import scan.xml" },
          { role: "Automation Engineer", context: "Pipeline scanning — parse XML output untuk automated vulnerability assessment" },
          { role: "Blue Team", context: "SIEM integration — import scan results untuk correlation dan alerting" },
          { role: "Developer", context: "Build custom tools — parse Nmap XML untuk specific analysis needs" }
        ],
        mitre: {
          tactic: { id: "TA0007", name: "Discovery" },
          technique: { id: "T1046", name: "Network Service Discovery" },
          killChain: "Reconnaissance",
          description: "Structured output untuk tool integration dan automated processing."
        },
        precautions: [
          { level: "low", text: "Tidak ada risiko tambahan — hanya format output" },
          { level: "medium", text: "File berisi detail sensitif — protect accordingly" },
          { level: "low", text: "XML files bisa besar untuk scan yang extensive — monitor disk space" },
          { level: "low", text: "Tip: gunakan -oA basename untuk save semua format sekaligus (.nmap, .xml, .gnmap)" }
        ],
        impact: {
          traffic: "Same as underlying scan",
          detection: "Same as underlying scan",
          disruption: "Same as underlying scan",
          legal: "XML output berguna sebagai evidence dalam pentest report"
        }
      }
    ]
  }
];
