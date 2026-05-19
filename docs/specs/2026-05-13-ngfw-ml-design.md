# Next-Generation Firewall: Real-time Threat Detection using Machine Learning

**Spec tarihi:** 2026-05-13
**Ders:** Introduction to Computer Security
**Format çerçevesi:** Mini-NGFW PoC — endüstriyel NGFW'in çekirdek prensibini (akış yakalama → özellik çıkarma → ML sınıflandırma → aksiyon) 4 saldırı sınıfı üzerinde end-to-end gerçekleştirme.

---

## 1. Amaç ve Kapsam

Çalışan bir demo + sunum öncelikli, akademik rapor destekleyici. Hedef:

- Canlı bir lab ortamında atılan saldırıları (Port Scan, DoS, SSH Brute Force) gerçek zamanlıya yakın tespit edip otomatik bloklayan bir sistem.
- Eğitim verisi: **CICIDS2017** (4 sınıf alt kümesi).
- Görsel sunum: tek sayfa web dashboard.

### Kapsam içinde
- Akış-bazlı (flow-based) trafik analizi
- 4 sınıflı sınıflandırma: BENIGN, PORT_SCAN, DOS, BRUTE_FORCE
- iptables üstünden otomatik blok (5 dk TTL)
- Lab izole network (VirtualBox Internal Network) + ikinci NIC ile gerçek internet baseline'ı

### Kapsam dışı (YAGNI)
- TLS/HTTPS içerik analizi (deep packet inspection)
- Zero-day / unknown attack tespiti
- DNS tunneling, DGA, encrypted C2
- IPv6
- Multi-segment / dağıtık ağ
- Kullanıcı kimliği, RBAC, multi-tenant
- Dashboard'da auth, kalıcı DB, mobile responsive

---

## 2. Sistem Mimarisi

```
┌─────────────────────┐        ┌────────────────────────────────────┐
│   Attacker VM       │        │   Firewall + Victim VM             │
│   (Kali Linux)      │        │   (Ubuntu 22.04)                   │
│                     │        │                                    │
│   - nmap            │  NIC1  │   ┌──────────────────────────────┐ │
│   - hydra           │ ─────► │   │  NGFW Engine (Python)        │ │
│   - hping3          │ Internal│  │   1. Sniffer (Scapy)         │ │
│                     │ Network │  │   2. Flow Builder            │ │
└─────────────────────┘        │   │   3. Feature Extractor       │ │
                               │   │   4. RF Classifier           │ │
                               │   │   5. Action Engine (iptables)│ │
                               │   └────────────┬─────────────────┘ │
                               │                │ EventBus           │
                               │   ┌────────────▼─────────────────┐ │
                               │   │  Flask + Socket.IO Dashboard │ │
                               │   └──────────────────────────────┘ │
                               │                                    │
                               │   Victim services: SSH(22), HTTP(80)│
                               │                                    │
                               │   NIC2 ──► NAT ──► gerçek internet │
                               │   (baseline BENIGN trafiği için)   │
                               └────────────────────────────────────┘
```

**Network konfigürasyonu**
- Hypervisor: **VirtualBox**
- NIC1 (her iki VM): VirtualBox Internal Network adı `ngfw-lab` — host ve internet erişimi yok.
- NIC2 (sadece Firewall VM): NAT — gerçek internet sörfü baseline'ı için.

**Beş çekirdek bileşen, tek sorumluluk:**

1. **Sniffer** (`ngfw/sniffer.py`) — Scapy ile NIC'lerden paket yakalar, thread-safe queue'ya basar. Çoklu NIC desteği (`iface=["eth0","eth1"]`), her paket `interface` metadata'sıyla işaretlenir.
2. **Flow Builder** (`ngfw/flow_builder.py`) — Paketleri 5-tuple `(src_ip, dst_ip, src_port, dst_port, proto)` ile akışlara toplar. Akış kapanma tetikleyicileri: FIN/RST, 10 sn idle timeout, 120 sn aktif timeout.
3. **Feature Extractor** (`ngfw/feature_extractor.py`) — Kapanan akıştan 15-boyutlu özellik vektörü üretir (bkz. §4).
4. **Classifier** (`ngfw/classifier.py`) — joblib ile yüklenen Random Forest + StandardScaler. `predict(vector) -> (class, confidence)`.
5. **Action Engine** (`ngfw/action_engine.py`) — `class != BENIGN AND confidence > 0.85` ise kaynak IP için `iptables -A INPUT -s <ip> -j DROP` ekler, TTL listesine yazar; ayrı cleanup thread'i 5 dk sonra kuralı siler.

Bileşenler `EventBus` (basit `queue.Queue` üstü pub/sub) ile gevşek bağlı; Dashboard event bus'a abone olup tarayıcıya WebSocket ile yayar.

**Thread mimarisi (tek process):**
- T1: Sniffer (`scapy.sniff`)
- T2: Flow processor (queue tüketici, akış yönetimi, classifier çağrısı)
- T3: Action cleanup (TTL dolan iptables kurallarını siler)
- Main: Flask + SocketIO

---

## 3. Veri Akışı

```
NIC → Sniffer → packet_queue → Flow Builder
                                    │
                                    │ akış kapandı (FIN/RST | 10s idle | 120s aktif)
                                    ▼
                              Feature Extractor → 15-d vector
                                    │
                                    ▼
                              Classifier → (class, confidence)
                                    │
                       ┌────────────┴────────────┐
                       │ BENIGN                  │ not-BENIGN AND conf>0.85
                       ▼                         ▼
                  log + dashboard          Action Engine
                                                 │
                                                 ▼
                                  iptables -A INPUT -s <src> -j DROP
                                  + dashboard alert
                                  + TTL listesine ekle (5 dk)
```

**Karar parametreleri (config.py'de değiştirilebilir):**

| Parametre | Değer | Gerekçe |
|-----------|-------|---------|
| `FLOW_IDLE_TIMEOUT` | 10 s | CICIDS2017 ile uyumlu |
| `FLOW_ACTIVE_TIMEOUT` | 120 s | CICIDS2017 ile uyumlu; demo için 30 s'ye düşürülebilir |
| `CONFIDENCE_THRESHOLD` | 0.85 | ROC analiziyle seçilecek; FPR-recall dengesi |
| `BLOCK_TTL` | 300 s | Demo'da tekrar gösterim için makul süre |
| `CLEANUP_INTERVAL` | 60 s | TTL kontrol sıklığı |

---

## 4. ML Pipeline

### 4.1 Dataset: CICIDS2017

Kullanılacak 4 sınıf:

| Sınıf | CICIDS2017 etiketleri | Yaklaşık akış sayısı |
|-------|------------------------|------------------------|
| BENIGN | BENIGN | 200K (down-sample) |
| PORT_SCAN | PortScan | 158K |
| DOS | DoS Hulk + DoS SlowHTTPTest | 230K |
| BRUTE_FORCE | FTP-Patator + SSH-Patator | 14K |

BRUTE_FORCE az olduğundan: `class_weight='balanced'` + SMOTE oversample karşılaştırması raporda yer alacak.

### 4.2 Seçilen 15 Özellik

1. flow_duration
2. total_fwd_packets
3. total_bwd_packets
4. total_fwd_bytes
5. total_bwd_bytes
6. fwd_packet_len_mean
7. bwd_packet_len_mean
8. flow_iat_mean
9. syn_flag_count
10. ack_flag_count
11. rst_flag_count
12. avg_packet_size
13. fwd_packets_per_sec
14. bwd_packets_per_sec
15. down_up_ratio (bwd_bytes / fwd_bytes)

Seçim gerekçesi: (a) Scapy ile runtime'da kolayca hesaplanabilir, (b) `mutual_info_classif` skorlarında üst sıralarda, (c) literatürde CICIDS2017 + RF çalışmalarında sık kullanılan minimal set.

### 4.3 Model

```python
RandomForestClassifier(
    n_estimators=100,
    max_depth=20,
    class_weight='balanced',
    n_jobs=-1,
    random_state=42,
)
```

**Neden RF:** tabular veride deep learning'le rekabet eder, feature importance çıkar (raporda açıklayıcılık), inference <1 ms, GPU gerektirmez.

### 4.4 Eğitim (offline, laptop CPU)

`notebooks/01_train_model.ipynb`:
1. CICIDS2017 CSV oku → pandas
2. 4 sınıfa filtrele, label encode
3. 15 özelliği seç, NaN/inf temizle
4. `StandardScaler` fit
5. Stratified 80/20 split
6. `RandomForestClassifier.fit`
7. classification_report + confusion matrix → `docs/report/figures/`
8. `joblib.dump` → `models/rf_model.pkl`, `models/scaler.pkl`

Beklenen: macro F1 ≈ 0.93–0.95 (15 özellikli alt küme; literatürdeki 0.97–0.99 figürleri 70+ özellikle elde ediliyor). BRUTE_FORCE precision'u en düşük (SMOTE/synthetic örneklerin yan etkisi olarak yüksek recall, düşük precision asimetrisi) — raporda §11 Limitasyonlar bölümünde tartışılacak; runtime'da 0.85 güven eşiği false positive'lerin çoğunu süzecek.

### 4.5 Offline FPR (Gerçek Trafik Doğrulaması)

`notebooks/02_real_world_fpr.ipynb`:
- Kendi laptop'umuzdan tcpdump ile 30 dk normal sörf yakala
- Akışlara çevir, 15 özellik çıkar, model üstünde inference
- FPR = (BENIGN olup saldırı denilen akışlar) / (toplam BENIGN akış)
- Hedef: %5'in altında, raporda dürüstçe raporlanır

---

## 5. Demo Senaryosu

5–6 dakikalık canlı sahne, `attacker/run_demo.sh` ile sırayla:

| # | Sahne | Komut | Beklenen | Süre |
|---|-------|-------|----------|------|
| 1 | Gerçek internet baseline | Firefox ile youtube/github/wikipedia | Dashboard'da `[inet]` BENIGN akışları, blok yok | ~60 s |
| 2 | Lab normal trafik | `curl http://victim/`, legit SSH | `[lab]` BENIGN, blok yok | ~30 s |
| 3 | Port Scan | `nmap -sS -p 1-1000 victim` | `[lab]` PORT_SCAN tespit + blok | ~60 s |
| 4 | SSH Brute Force | `hydra -l root -P rockyou.txt ssh://victim` | BRUTE_FORCE tespit + blok | ~60 s |
| 5 | DoS | `hping3 -S --flood -p 80 victim` (rate sınırlı) | DOS tespit + blok | ~60 s |
| 6 | Blok geri alma | Dashboard'dan "Unblock" butonu | iptables kuralı silinir, IP tekrar erişebilir | ~15 s |

**Beklenen tespit gecikmesi:** 5–10 sn (akış 10 sn idle timeout sonrası kapanır). Raporda dürüstçe yer alır.

---

## 6. Dashboard

Tek sayfa, koyu tema. Layout:

- **Header:** Status badge, uptime, "Reset Demo" butonu.
- **Metrics (4 kart):** Total Flows, Benign, Threats, Blocked IPs.
- **Live Flow Stream:** Son 50 akış, auto-scroll, sınıfa göre renk (yeşil/sarı/kırmızı), arayüze göre rozet (`[lab]`/`[inet]`).
- **Threat Breakdown:** Pie chart (sınıf bazında sayım).
- **Blocked IPs:** Aktif blok listesi, sebep, kalan TTL, "Unblock" butonu.
- **Traffic Rate:** Son 60 sn pkts/sec line chart.

**Stack:** Flask + Flask-SocketIO + Vanilla HTML + Tailwind CDN + Chart.js. Build step yok.

**Routes / events:**
- `GET /` → dashboard.html
- `GET /api/status` → JSON özet
- `POST /api/unblock` → `{ip}` → iptables -D + UI güncelle
- SocketIO emit: `flow`, `alert`, `metrics`

**Veri kalıcılığı yok** — restart'ta sayaçlar sıfırlanır (kasıtlı, demo için yeterli).

---

## 7. Proje Yapısı

```
introProjesi/
├── README.md
├── requirements.txt
├── .gitignore
├── ngfw/
│   ├── main.py, sniffer.py, flow_builder.py,
│   ├── feature_extractor.py, classifier.py,
│   ├── action_engine.py, event_bus.py, config.py
│   └── dashboard/
│       ├── app.py
│       ├── templates/dashboard.html
│       └── static/{app.js, style.css}
├── notebooks/
│   ├── 01_train_model.ipynb
│   └── 02_real_world_fpr.ipynb
├── models/
│   ├── rf_model.pkl, scaler.pkl, metrics.json
├── attacker/
│   ├── 01_normal_traffic.sh, 02_port_scan.sh,
│   ├── 03_brute_force.sh, 04_dos_synflood.sh,
│   ├── run_demo.sh, reset_demo.sh
├── tests/
│   ├── test_flow_builder.py
│   ├── test_feature_extractor.py
│   └── test_classifier.py
├── docs/
│   ├── specs/2026-05-13-ngfw-ml-design.md   (BU dosya)
│   ├── report/ (LaTeX, IEEE template)
│   └── presentation/slides.pdf
└── setup/
    ├── firewall_vm_setup.sh
    └── kali_vm_setup.sh
```

---

## 8. Bağımlılıklar

**Python 3.12.x (pin: 3.12.7). Runtime + training, same env:**
```
scapy==2.5.0
flask==3.0.0
flask-socketio==5.3.6
python-socketio==5.10.0
eventlet==0.35.2
joblib==1.3.2
numpy==1.26.4
scikit-learn==1.4.2
pandas==2.2.3
matplotlib==3.8.4
seaborn==0.13.2
imbalanced-learn==0.12.3
jupyter==1.0.0
pytest==8.0.0
```

scikit-learn versiyonu eğitim ve runtime'da **aynı olmak zorunda** (model uyumluluğu).

**Sistem (Ubuntu apt):** iptables, tcpdump, libpcap-dev.

**Sniffer için yetki:** `sudo setcap cap_net_raw,cap_net_admin=eip $(which python3)` (her seferinde sudo şifre sormamak için).

---

## 9. Teslim Çıktıları

| # | Çıktı | Format | Yer |
|---|-------|--------|-----|
| 1 | Çalışan kod | Git repo (lokal + GitHub yedek) | `ngfw/`, `attacker/`, `notebooks/` |
| 2 | Eğitilmiş model | `.pkl` (joblib) | `models/` |
| 3 | Eğitim metrikleri | JSON + PNG figürler | `models/metrics.json`, `docs/report/figures/` |
| 4 | Akademik rapor | PDF (LaTeX, IEEE template) | `docs/report/report.pdf`, ~10–15 sayfa |
| 5 | Sunum slaytları | PDF | `docs/presentation/slides.pdf`, ~12–15 slayt |
| 6 | Demo video yedeği | MP4, ~2 dk | sunumda VM çakılırsa fallback |
| 7 | README | Markdown | klonlayan başkası tek seferde çalıştırabilsin |

### Rapor iskeleti

1. Abstract
2. Introduction
3. Background & Related Work
4. System Design
5. ML Pipeline
6. Implementation
7. Evaluation (7.1 offline CICIDS, 7.2 online lab demo, 7.3 real-world FPR)
8. Limitations & Future Work
9. Conclusion
10. References

---

## 10. Riskler ve Önlemler

| # | Risk | Önlem |
|---|------|-------|
| R1 | Scapy root yetkisi sudo soruyor | `setcap cap_net_raw,cap_net_admin=eip` ile bir kerelik çözüm |
| R2 | scikit-learn versiyon uyumsuzluğu | `requirements.txt` kilit + README'de uyarı |
| R3 | NIC ismi `eth0` değil `enp0s3` | `config.py`'de değişken, otomatik tespit fallback |
| R4 | Aynı IP iki kez block (yarış) | Mutex set + idempotent ekleme |
| R5 | DoS demo'da firewall VM cevap veremez | `hping3` rate sınırlı, `iptables -m limit` koruma |
| R6 | Akış 120 sn aktif timeout'tan önce kapanmaz | Demo için aktif timeout 30 sn'ye indirilebilir |
| R7 | Modern HTTPS BENIGN yanlış sınıflandırılır | Eşik 0.85 + outbound 80/443 whitelist (ilk versiyon) |

---

## 11. Limitasyonlar (Rapora Açıkça Yazılacak)

1. **Domain shift:** CICIDS2017 lab koşullarında üretildi; modern HTTPS/QUIC trafiği eksik temsil ediliyor.
1a. **BRUTE_FORCE precision asimetrisi:** Sınıf eğitim setinde az temsil edildiğinden, dengeleme tekniklerinden sonra model yüksek recall (~0.99) ama daha düşük precision (~0.67) üretir. Runtime'da 0.85 güven eşiği bu false positive'lerin çoğunu süzer; raporda eğitim metriği ile çalışma-zamanı davranışı ayrı tartışılır.
2. **Encrypted payload:** TLS içeriği görmüyoruz; flow metadata yeterli olmayabilir.
3. **Zero-day:** Supervised classification yalnızca eğitilen 4 sınıfı bilir.
4. **Sınırlı sınıf sayısı:** 4 saldırı, gerçek tehdit ortamının küçük bir kesiti.
5. **Adversarial ML:** Saldırgan modeli biliyorsa yavaş scan / payload mutasyonu ile kaçınabilir.
6. **Stateless ML:** Akışlar arası geçmiş ilişkisi modellenmiyor.
7. **Tek host, tek NIC odaklı:** Multi-segment ağ desteklenmiyor.

---

## 12. Etik ve Sorumlu Kullanım

Tüm saldırı simülasyonları izole VirtualBox Internal Network ortamında, kendi kontrolümüzdeki VM'ler üstünde çalıştırılır. nmap, hydra, hping3 hiçbir dış sistemde **izinsiz** kullanılmaz. SSH brute force için kullanılan hesap, kasten zayıf parolayla oluşturulmuş test hesabıdır. Tüm araçlar açık kaynak ve eğitim amaçlıdır.

---

## 13. Onaylanmış Kararlar (Karar Defterinin Özeti)

| Karar | Seçim |
|-------|-------|
| Teslim formatı | Çalışan demo + sunum (rapor ikincil) |
| Demo senaryosu | Canlı saldırı tespiti |
| Dataset | CICIDS2017 |
| Mimari | Python sniffer + Linux iptables |
| Demo ortamı | Tek host, 2 VM (Kali + Ubuntu), VirtualBox |
| Dashboard | Flask + Socket.IO + Chart.js |
| Yaklaşım | A — Random Forest, 4 sınıf, kuralsız |
| Hypervisor | VirtualBox |
| Rapor formatı | LaTeX, IEEE template |
| Repo yönetimi | Lokal git + GitHub yedek |

---

**Spec sonu.**
