# Архитектура tg-ws-proxy-android

## 1. Общая архитектура

Два слоя: **Rust engine** (нативный `.so`) и **Kotlin/Android app** (APK). Связь через **JNA** (Java Native Access).

```mermaid
graph TB
    subgraph "Android Device"
        TG[Telegram App] -->|MTProto :1443| LP[Local Proxy<br/>127.0.0.1:1443]
        
        subgraph "Rust Engine (libtgwsproxy.so)"
            LP --> HC[handle_client]
            HC -->|WSS| DP[Direct WS Pool]
            HC -->|WSS| CF[Cloudflare Proxy]
            HC -->|TCP| TF[TCP Fallback]
            DP -->|kws*.web.telegram.org| TGDC[Telegram DC :443]
            CF -->|kws*.co.uk| TGDC
            TF -->|DC IPs :443| TGDC
        end
        
        subgraph "Kotlin App"
            UI[Jetpack Compose UI<br/>4 tabs] --> PS[ProxyService<br/>Foreground Service]
            PS -->|JNA| NP[NativeProxy.kt]
            NP -->|FFI| RL[Rust lib.rs<br/>StartProxy/StopProxy]
            SS[SettingsStore<br/>DataStore Preferences] --> PS
            AU[AppUpdate<br/>GitHub API] -->|HTTPS| GH[GitHub Releases]
        end
        
        PS -->|Logcat| LM[LogManager<br/>Logcat Parser]
        LM --> UI
        
        BR[BootReceiver] -->|auto-start| PS
        QS[Quick Settings Tile] --> PS
    end

    CF -.->|DoH x4| DNS[Cloudflare/Google/<br/>Quad9/AdGuard DNS]
    CF -.->|GitHub Raw| CFDL[cfproxy-domains.txt]
```

---

## 2. Модули Rust

```mermaid
graph LR
    subgraph "C-FFI Boundary (lib.rs)"
        SP[StartProxy] -->|создаёт| RT[Tokio Runtime<br/>OnceCell]
        SP -->|создаёт| WP[WsPool]
        SP -->|запускает| RP[run_proxy]
        ST[StopProxy] -->|отменяет| CT[CancellationToken]
        ST -->|закрывает| WP
        SC[SetPoolSize] -->|atomic| PS[(POOL_SIZE)]
        SCC[SetCfProxyConfig] -->|RwLock| CFGC[(CFPROXY)]
        SS[SetSecret] -->|RwLock| PSEC[(PROXY_SECRET)]
        GS[GetStats] --> STATS[(STATS)]
    end

    subgraph "Core"
        RP -->|accept loop| HC[handle_client<br/>proxy.rs]
        HC --> BF[do_fallback]
        HC --> BW[bridge_ws]
        HC --> BT[bridge_tcp]
        HC --> CDW[connect_direct_ws]
    end

    subgraph "WebSocket"
        WC[ws_connect] --> WCO[ws_connect_once]
        WCO -->|TLS| TLS[rustls NoVerify]
        WCO -->|WS Upgrade| RWS[RawWebSocket]
        RWS --> SF[read_frame / send / recv]
    end

    subgraph "Cloudflare"
        CF[cfproxy.rs]
        CF -->|decoding| DCD[decode_cf_domain<br/>Caesar cipher]
        CF -->|DoH| DOH[resolve_doh<br/>4 providers + UDP]
        CF -->|429| CD[429 cooldown<br/>exponential backoff]
        CF -->|refresh| TRF[try_refresh_cfproxy_domains<br/>GitHub raw]
        CF -->|cache| CACHE[(filesystem cache)]
    end

    subgraph "Support"
        BAL[balancer.rs] -->|shuffle/assign| DOMAINS[(DC → domain map)]
        CR[crypto.rs] --> TS[TrackedStream<br/>AES-256-CTR cloneable]
        CR --> MS[MsgSplitter<br/>MTProto packet splitter]
        CFG[config.rs] -->|constants + globals| GLOBALS[(static vars)]
    end

    HC -->|pool.get| WP
    HC -->|ws_domains| CDW
    HC --> BF
    BF -->|try CF| CF
    BF -->|fallback| TF[tcp_fallback]
    WP -->|refill| WCO
    CDW --> WCO
    CF -->|cf_connect_domain| WCO
    DCD --> BAL
    TRF --> BAL
    BAL --> CF
    WP --> HW[warmup → refill]
```

---

## 3. Поток данных при подключении клиента

```mermaid
sequenceDiagram
    participant TG as Telegram App
    participant LP as Proxy :1443
    participant HC as handle_client
    participant WS as WS Pool
    participant DW as Direct WSS
    participant CF as Cloudflare
    participant TF as TCP Fallback
    participant DC as Telegram DC

    TG->>LP: TCP connect
    activate LP
    LP->>HC: accept + spawn
    
    HC->>TG: read 64-byte handshake
    HC->>HC: decrypt handshake (AES-256-CTR)
    HC->>HC: parse proto tag + DC + is_media
    HC->>HC: generate relay_init (64 bytes)
    HC->>HC: create cipher streams (clt_dec/clt_enc/tg_enc/tg_dec)
    HC->>HC: create MsgSplitter

    alt DC configured + not blacklisted
        HC->>WS: pool.get(dc, target, domains)
        alt Pool hit
            WS-->>HC: pooled RawWebSocket
        else Pool miss
            WS-->>HC: trigger background refill
            HC->>DW: connect_direct_ws(domains)
            alt Direct WS success
                DW-->>HC: RawWebSocket
                HC->>DW: send(relay_init)
                DW-->>DC: WSS relay_init
                HC->>HC: bridge_ws(client↔ws)
            else Direct WS failed
                HC->>CF: do_fallback → cfproxy_acquire_ws
                alt CF success
                    CF-->>HC: RawWebSocket
                    HC->>CF: send(relay_init)
                    HC->>HC: bridge_ws(client↔ws)
                else CF failed
                    HC->>TF: tcp_fallback(IP, 443)
                    TF->>DC: TCP connect + relay_init
                    HC->>HC: bridge_tcp(client↔DC)
                end
            end
        end
    else DC not configured or blacklisted
        HC->>CF: do_fallback → cfproxy_acquire_ws
        alt CF success
            CF-->>HC: RawWebSocket
            HC->>CF: send(relay_init)
            HC->>HC: bridge_ws
        else CF failed
            HC->>TF: tcp_fallback
            HC->>HC: bridge_tcp
        end
    end
    
    deactivate LP
```

---

## 4. Детальная схема bridge_ws (основной режим)

```mermaid
graph LR
    subgraph "bridge_ws"
        UP[up_task<br/>client → WS] -->|read tcp| RD[TCP Read 64KB]
        RD -->|decrypt| CLD[clt_dec.xor]
        CLD -->|encrypt| TGE[tg_enc.xor]
        TGE -->|split MTProto| SP[MsgSplitter]
        SP -->|send batch| WS_S[WS send/send_batch]
        
        DN[down_task<br/>WS → client] -->|recv| WS_R[WS recv_with_timeout]
        WS_R -->|decrypt| TGD[tg_dec.xor]
        TGD -->|encrypt| CLE[clt_enc.xor]
        CLE -->|write tcp| TW[TCP Write]
        
        PING[ping_task] -->|30s| PP[WS send_ping]
    end
    
    UP -.->|cancel on finish| C{cancel}
    DN -.-> C
    PING -.-> C
```

---

## 5. Алгоритм Cloudflare Proxy

```mermaid
flowchart TD
    START[StartProxy] --> INIT[init_cfproxy_domains]
    INIT --> CHECK_USER{user_domain<br/>set via UI?}
    CHECK_USER -->|yes| USER_DOMAIN[domains = [user_domain]<br/>skip all other sources]
    CHECK_USER -->|no| CACHE{file cache exists?}
    CACHE -->|yes, fresh| CACHE_LOAD[load + merge<br/>with hardcoded defaults]
    CACHE -->|no/expired| GITHUB[spawn async refresh]
    GITHUB --> GIT_FETCH[GET raw.githubusercontent.com/...<br/>cfproxy-domains.txt]
    GIT_FETCH -->|success| GIT_PARSE[parse + normalize]
    GIT_PARSE -->|merge defaults| GIT_MERGE[merge_cfproxy_domains]
    GIT_MERGE --> SAVE[save to file cache]
    GIT_MERGE --> BAL_UPDATE[update Balancer<br/>shuffle + assign per DC]
    GIT_FETCH -->|fail 3x| KEEP_DEFAULTS[keep defaults + cache]
    CACHE_LOAD --> BAL_UPDATE

    BAL_UPDATE --> BAL[Balancer]
    BAL -->|for each DC 1-5,203| DC_ASSIGN[random domain → dc_to_domain]
    
    CONNECT[do_fallback →<br/>cfproxy_acquire_ws] --> ORDERED[balancer.get_domains_for_dc]

    ORDERED --> FIRST[try first domain<br/>try_cfproxy_base_domain]
    FIRST --> CHECK_429{429 cooldown<br/>active?}
    CHECK_429 -->|yes, skip| SKIP[skip domain]
    CHECK_429 -->|no| ACQUIRE_SEM[acquire global semaphore<br/>max 4 concurrent]
    ACQUIRE_SEM --> CONNECT_DOMAIN[cf_connect_domain]

    CONNECT_DOMAIN --> TRY_HOST[ws_connect_once<br/>by hostname]
    TRY_HOST -->|HTTP 429| MARK_COOLDOWN[mark_cfproxy_429_cooldown<br/>exponential backoff]
    TRY_HOST -->|other error| DOH[resolve_doh<br/>4 providers + UDP]
    DOH -->|got IP| TRY_IP[ws_connect_once<br/>by resolved IP]
    TRY_HOST -->|success OK| RETURN_WS[return RawWebSocket]
    TRY_IP -->|success OK| RETURN_WS
    TRY_IP -->|fail| FAIL[return None]

    FIRST -->|fail| PARALLEL[try remaining domains<br/>parallel with semaphore]
    PARALLEL --> RESULT{any success?}
    RESULT -->|yes| UPDATE_BAL[balancer.update_domain_for_dc]
    RESULT -->|no| ALL_FAIL[log warning<br/>return None → TCP fallback]
```

---

## 6. Структура Kotlin-приложения

```mermaid
graph TB
    subgraph "App Entry"
        MA[MainActivity] -->|Compose| MC[MainContent]
        MC -->|4 tabs| CT[ConnectionTab]
        MC -->|4 tabs| ST[SettingsTab]
        MC -->|4 tabs| LT[LogsTab]
        MC -->|4 tabs| IT[InfoTab]
        
        MC -->|update check| AU[AppUpdate.kt<br/>fetchLatestReleaseInfo]
        AU -->|GitHub API| GHR[GitHub Releases/Tags]
        
        MC -->|logs| LM[LogManager<br/>Channel + batch]
        LM -->|logcat --pid| LOGCAT[ProcessBuilder]
        
        MA --> FT[FloatingToolbar<br/>theme/palette controls]
    end

    subgraph "Service Layer"
        PS[ProxyService<br/>Foreground Service]
        PS -->|JNA Thread| NP[NativeProxy]
        NP -->|FFI| RUST[Rust libtgwsproxy.so]
        
        PS -->|intent extras| PC[ProxyController]
        PC -->|read settings| SS[SettingsStore<br/>DataStore Preferences]
        
        PS -->|wakelock| WL[WakeLock<br/>refresh 25min]
        PS -->|notification| NOTIF[Notification<br/>stats + controls]
        PS -->|3s check| WD[Watchdog<br/>port check]
        
        PS -->|START_REDELIVER_INTENT| AUTO_RESTART[System auto-restart<br/>on kill]
    end

    subgraph "System Integration"
        BR[BootReceiver<br/>BOOT_COMPLETED] -->|auto-start| PS
        QS[ProxyTileService<br/>Quick Settings] -->|toggle| PS
        QTP[ProxyTilePreferencesActivity] --> QS
    end

    subgraph "UI Screens"
        CT -->|Start/Stop| PC
        CT -->|Stats| NP
        CT -->|Notification| TG_PROXY[t.me/proxy URL]
        
        ST -->|DC IPs| SS
        ST -->|CF config| SS
        ST -->|Port/Bind| SS
        ST -->|Pool size| SS
        
        LT -->|filtered| LM
        
        IT -->|links| EXT[ExternalLinks<br/>GitHub URLs]
        IT -->|version| AU
        IT -->|donate| EMPTY["""<br/>(not configured)</li>]
    end

    BU[AppBackdrop<br/>decorative orbs] -.-> MC
```

---

## 7. Управление Cloudflare-доменами (Caesar-шифр)

Жёстко закодированные домены в `config.rs` выглядят как `virkgj.com`, но в runtime декодируются.

```mermaid
flowchart LR
    ENC["virkgj.com<br/>(зашифрован)"] --> DECODE[decode_cf_domain]
    DECODE --> COUNT[count letters n=7]
    COUNT --> SHIFT[shift each letter back by n<br/>v→o, i→b, r→k, k→d, g→z, j→c]
    SHIFT --> DEC["obkdzc.co.uk<br/>(расшифрован)"]
```

---

## 8. Система сборки

```mermaid
flowchart TB
    subgraph "Step 1: Rust"
        build_so.bat --> CARGO_NDK[cargo ndk]
        CARGO_NDK --> ARM64["arm64-v8a<br/>libtgwsproxy.so"]
        CARGO_NDK --> ARM32["armeabi-v7a<br/>libtgwsproxy.so"]
        ARM64 --> JNILIBS["app/src/main/jniLibs/"]
        ARM32 --> JNILIBS
    end

    subgraph "Step 2: Android APK"
        build_apk.bat --> GRADLE[gradlew assembleRelease]
        GRADLE --> UNIVERSAL[app-universal-release.apk]
        GRADLE --> V8A[app-arm64-release.apk]
        GRADLE --> V7A[app-arm32-release.apk]
    end

    JNILIBS --> GRADLE

    subgraph "Key Config"
        local.properties -->|sdk.dir| GRADLE
        local.properties -->|keystore| GRADLE
    end
```

---

## 9. Поток данных настроек (UI → Rust)

```mermaid
flowchart LR
    UI[Compose UI] -->|user input| SS[SettingsStore<br/>DataStore]
    SS --> PC[ProxyController]
    PC -->|intent extras| PS[ProxyService]
    PS -->|Thread| NP[NativeProxy<br/>JNA]
    NP -->|StartProxy| RUSTLIB[Rust lib.rs]
    NP -->|SetCfProxyConfig| RUSTLIB
    NP -->|SetPoolSize| RUSTLIB
    NP -->|SetCfProxyCacheDir| RUSTLIB
    NP -->|SetSecret| RUSTLIB
    RUSTLIB -->|GetStats| NP
    RUSTLIB -->|GetSecretWithPrefix| NP
    NP --> PS
    PS -->|StateFlow| UI
```
