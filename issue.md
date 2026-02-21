 ---
  title: "Security: RPC wallet_name allows path traversal and arbitrary file writes"
  labels: ["security", "rpc", "wallet"]
  ---

  ### Summary
  `createwallet`, `restorewallet`, and related RPCs accept arbitrary `wallet_name` strings. They pass the value directly to
  `fsbridge::AbsPathJoin`, which simply concatenates the base path with the supplied name—and silently trusts absolute paths or `../`
  segments. A malicious (or misconfigured) RPC client can therefore cause bitcoind to create/overwrite files anywhere the daemon user can
  write.

  ### Impact
  Remote file clobber or privilege escalation for any authenticated RPC caller (and for unauthenticated callers whenever the RPC port is
  exposed). Attackers can overwrite startup scripts, cron jobs, or wallet backups, potentially gaining code execution or destroying funds.

  ### Evidence
  - `src/wallet/rpc/wallet.cpp:346-420` (`createwallet`) forwards `wallet_name` without sanitization.
  - `src/util/fs.cpp:34-38` shows `AbsPathJoin` returns `base/path` while letting absolute `path` override confinement.
  - `doc/JSON-RPC-interface.md:163-174` already warns that `wallet_name` can be abused for path traversal.

  ### Suggested Mitigation
  Reject absolute paths or `..` segments in RPC handlers before calling `AbsPathJoin`, or resolve to a canonical path and verify it stays
  within `-walletdir`. Consider adding an allowlist regex (e.g., alphanumeric plus `_`/`-`) and documenting the behavior change in release
  notes.

  ---
  title: "Security: REST/RPC connection flood exhausts file descriptors"
  labels: ["security", "rpc", "rest", "DoS"]
  ---

  ### Summary
  The HTTP server that backs both RPC and REST lacks per-client throttling. Documentation notes that “several hundred” concurrent
  connections can exhaust file descriptors and crash the node. Because REST is unauthenticated and shares the same listener, any network-
  adjacent adversary can open many keep-alive sockets to trigger a DoS.

  ### Impact
  Unauthenticated remote crash / service interruption whenever the REST/RPC port is reachable (default 8332). A hostile ISP neighbor or
  botnet can knock nodes offline without touching consensus code.

  ### Evidence
  - `doc/REST-interface.md:1-25` and `doc/JSON-RPC-interface.md:207-216` describe the file-descriptor exhaustion crash.
  - HTTP server implementation (`src/httpserver.cpp`, indirectly) has no rate limiting; REST handlers in `src/rest.cpp` simply service
  requests.

  ### Suggested Mitigation
  Add per-IP connection caps and request rate limits inside the HTTP server, or ship a hardened configuration (e.g., recommended nginx/
  HAProxy front-end). At minimum, document recommended `ulimit -n` settings and default to binding REST to localhost unless explicitly
  enabled.

  ---
  title: "Security: Wallets created unencrypted, metadata always exposed"
  labels: ["security", "wallet"]
  ---

  ### Summary
  New wallets are stored unencrypted unless the operator manually supplies a passphrase. Even after encryption, metadata (transaction
  history, labels) remains plaintext. Malware or filesystem access therefore compromises funds or privacy immediately. The docs warn about
  this, but the software neither enforces encryption nor surfaces health checks.

  ### Impact
  Host compromise or cloud snapshot theft = full key theft for default wallets; even “encrypted” wallets leak metadata that may be sensitive
  for enterprise users.

  ### Evidence
  - `doc/managing-wallets.md:28-99` explains that wallets are unencrypted by default and metadata is never encrypted.
  - `src/wallet/rpc/wallet.cpp` only encrypts when `passphrase` is supplied.

  ### Suggested Mitigation
  Provide a `-requirewalletpassphrase` config, warn loudly (GUI/RPC) when a wallet is unencrypted, and optionally encrypt metadata (or at
  least obscure file contents). Shipping a “wallet posture analyzer” RPC (see innovation issue) would also help.

  ---
  title: "Security: Low-work header streams consume CPU despite anti-DoS checks"
  labels: ["security", "net", "p2p"]
  ---

  ### Summary
  `PeerManagerImpl::ProcessHeadersMessage` validates every received header chain (proof-of-work, continuity, anti-DoS threshold) while
  holding `cs_main`. Attackers can repeatedly send long header chains that barely clear `GetAntiDoSWorkThreshold()`, forcing expensive
  validation and starving legitimate peers despite existing heuristics.

  ### Impact
  Remote peers can tie up CPU and `cs_main`, slowing block/tx propagation and making eclipse attacks easier.

  ### Evidence
  - `src/net_processing.cpp:2620-2810` shows header validation and anti-DoS handling.
  - `GetAntiDoSWorkThreshold` is derived from tip work; staying just above the threshold keeps the node busy.

  ### Suggested Mitigation
  Track CPU/time per peer and disconnect when they repeatedly provide low-value headers, or require additional proof (e.g., checkpoints,
  reputation). Consider performing expensive validation outside `cs_main` or batching work.

  ---
  title: "Security: Transaction package validation causes lock contention DoS"
  labels: ["security", "mempool", "p2p"]
  ---

  ### Summary
  When `m_txdownloadman` queues a package, `ProcessMessage` locks `cs_main` and `m_tx_download_mutex`, then calls `ProcessNewPackage`, which
  iterates the mempool and coins cache. Malicious peers can continuously send malformed packages (child-with-parent topology, cluster-limit
  stress) to keep these global locks held and force cache flushes.

  ### Impact
  Remote peers can degrade relay performance, increase latency, and burn CPU/disk by pinning locks and triggering repeated cache
  maintenance.

  ### Evidence
  - `src/net_processing.cpp:4505-4548` handles `PTX` messages and package validation paths.
  - `src/validation.cpp:1804-1833` shows `ProcessNewPackage` holding `cs_main` while touching the coins view.

  ### Suggested Mitigation
  Rate-limit package validation per peer, move expensive work off `cs_main`, and disconnect/ban peers whose packages fail rapidly for policy
  reasons.

  ---
  title: "Enhancement: Adaptive RPC firewall and telemetry"
  labels: ["enhancement", "rpc", "observability"]
  ---

  ### Summary
  `RPCServerInfo` already tracks active commands, but there’s no built-in telemetry or throttling. Extending this to record per-method
  latency, per-IP call volume, and exposed metrics (e.g., Prometheus endpoint) would let operators detect abusive clients and automatically
  apply backpressure.

  ### Motivation
  Helps mitigate the connection-flood DoS, gives operators visibility into RPC usage, and modernizes node observability.

  ### Proposed Work
  1. Extend `RPCServerInfo` (see `src/rpc/server.cpp:24-96`) to maintain counters/histograms per command and client (IP, auth cookie, etc.).
  2. Expose metrics via a lightweight endpoint or integrate with the existing debug console.
  3. Add policy hooks to limit requests per client or slow down noisy callers.

  ### References
  - Current RPC bookkeeping lives in `src/rpc/server.cpp`.

  ---
  title: "Enhancement: Wallet posture analyzer RPC"
  labels: ["enhancement", "wallet", "security"]
  ---

  ### Summary
  Operators currently have to read `doc/managing-wallets.md` to assess whether wallets are encrypted, backed up, migrated, etc. A dedicated
  RPC (e.g., `analyzewalletsecurity`) could inspect each wallet and return actionable warnings (unencrypted, no recent backups, descriptors
  missing, hardware signer absent).

  ### Motivation
  Improves wallet security posture, helps new operators avoid common pitfalls, and provides machine-readable data for monitoring.

  ### Proposed Work
  1. Implement an RPC in `src/wallet/rpc/wallet.cpp` that reports:
     - Encryption state and passphrase usage.
     - Last backup timestamp/checksum.
     - Descriptor vs legacy status, presence of watchonly/solvable splits.
     - External signer configuration.
  2. Surface recommendations drawn from `doc/managing-wallets.md`.
  3. Optional GUI integration (e.g., warning banner).

  ### References
  - Wallet management guidance: `doc/managing-wallets.md:28-160`.

  ---
  title: "Enhancement: Peer reputation dashboard & alerts"
  labels: ["enhancement", "p2p", "observability"]
  ---

  ### Summary
  Currently, there’s no easy way to see which peers trigger anti-DoS behaviors (invalid headers, package floods, stalls). Instrumenting
  `PeerManagerImpl` to emit structured events and exposing them via an RPC/UI panel would let operators spot eclipse attempts and
  misbehaving peers quickly.

  ### Motivation
  Improves network hygiene, accelerates incident response, and provides data for automated peer management scripts.

  ### Proposed Work
  1. Add hooks in `src/net_processing.cpp` where headers are rejected, packages fail, or stalls occur to log events (peer ID, reason,
  counts).
  2. Store recent events in-memory and expose them via a new RPC (e.g., `getpeeralerts`) and/or GUI panel.
  3. Optionally integrate with `-ban` logic or allow custom automation (webhooks, metrics).

  ### References
  - Headers/DoS logic: `src/net_processing.cpp:2620-2810`.
  - Package handling: `src/net_processing.cpp:4505-4548`.

  ---
  title: "Enhancement: Mempool analytics streaming interface"
  labels: ["enhancement", "mempool", "observability"]
  ---

  ### Summary
  `CTxMemPool` already emits tracepoints (`TRACEPOINT_SEMAPHORE`), but there’s no official, structured feed for fee histograms, cluster
  sizes, or eviction causes. A signed, rate-limited stream (ZMQ or gRPC) would let downstream tools subscribe without polling heavy RPCs.

  ### Motivation
  Reduces RPC load, enables richer fee-estimation and policy research tools, and gives operators insight into mempool health.

  ### Proposed Work
  1. Build on `src/txmempool.cpp:37-189` tracepoints to produce summaries (fee histogram, cluster counts, eviction stats) at regular
  intervals.
  2. Publish via existing ZMQ infrastructure or a new gRPC/WebSocket endpoint with rate limiting.
  3. Provide documentation and sample subscribers.

  ### References
  - Current mempool tracepoints: `src/txmempool.cpp`.

  ---
  title: "Enhancement: Hardened REST gateway/middleware"
  labels: ["enhancement", "rest", "security"]
  ---

  ### Summary
  The REST interface is unauthenticated and directly exposes internal handlers that keep entire responses in memory. Shipping an optional
  front-end (or middleware mode) that enforces API keys, rate limits, pagination, and response size caps would let operators expose REST
  safely without writing their own proxy.

  ### Motivation
  Makes REST usable for exchanges/data providers while preventing trivial DoS, and complements the security fixes above.

  ### Proposed Work
  1. Add a middleware layer in `src/rest.cpp` (or a companion binary) that:
     - Requires API keys/tokens.
     - Applies per-IP quotas and rate limits.
     - Enforces max response sizes/pagination.
     - Provides caching hooks for frequently accessed data.
  2. Provide configuration knobs and documentation on how to enable it.

  ### References
  - REST handlers: `src/rest.cpp:1-200`.
  - Limitations documented in `doc/REST-interface.md:1-25`.
