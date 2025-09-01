import os, json, requests, time, base64

# --------- Config via environment ----------
RPC_HTTP   = os.getenv("RPC_HTTP", "https://api.mainnet-beta.solana.com")
WALLET_LIST= os.getenv("WALLET_LIST", "").strip()   # newline or comma separated
STATE_FILE = os.getenv("STATE_FILE", "state.json")  # per-shard file set by workflow

# Sharding (set by workflow matrix)
SHARD_INDEX = int(os.getenv("SHARD_INDEX", "-1"))
SHARD_TOTAL = int(os.getenv("SHARD_TOTAL", "-1"))

# Tuning knobs (safe defaults)
CONNECT_CHECKS_PER_RUN       = int(os.getenv("CONNECT_CHECKS_PER_RUN", "4"))
HISTORY_PAGES_PER_CONNECTED  = int(os.getenv("HISTORY_PAGES_PER_CONNECTED", "2"))
HISTORY_PAGE_LIMIT           = int(os.getenv("HISTORY_PAGE_LIMIT", "100"))
VERBOSE = os.getenv("VERBOSE", "0") == "1"

# Transfer threshold (new)
MIN_SOL_TRANSFER = float(os.getenv("MIN_SOL_TRANSFER", "1"))  # in SOL; alert only if |ΔSOL| ≥ this

# Alerts (use one or both)
DISCORD_WEBHOOK = os.getenv("DISCORD_WEBHOOK")
TG_TOKEN = os.getenv("TG_TOKEN")
TG_CHAT  = os.getenv("TG_CHAT")

# Program lists (set via repo Variables)
AMM_PROGRAMS_RAW    = os.getenv("AMM_PROGRAMS", "").strip()
SWAP_PROGRAMS_RAW   = os.getenv("SWAP_PROGRAMS", "").strip()
LAUNCH_PROGRAMS_RAW = os.getenv("LAUNCH_PROGRAMS", "").strip()  # e.g., pump.fun
# -------------------------------------------

# Known base programs
SYSTEM_PROGRAM = "11111111111111111111111111111111"
TOKEN_PROGRAMS = {
    "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",  # SPL Token
    "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb",  # Token-2022
}
# Metaplex Token Metadata (mainnet)
METADATA_PROGRAM = "metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s"

def vlog(*args):
    if VERBOSE:
        print(*args)

def parse_list_env(value: str):
    if not value:
        return []
    if "\n" in value:
        return [v.strip() for v in value.splitlines() if v.strip() and not v.strip().startswith("#")]
    return [v.strip() for v in value.split(",") if v.strip() and not v.strip().startswith("#")]

AMM_PROGRAMS     = set(parse_list_env(AMM_PROGRAMS_RAW))
SWAP_PROGRAMS    = set(parse_list_env(SWAP_PROGRAMS_RAW)) or set(parse_list_env(AMM_PROGRAMS_RAW))
LAUNCH_PROGRAMS  = set(parse_list_env(LAUNCH_PROGRAMS_RAW))

# -------------------- RPC helpers --------------------
def rpc(method, params):
    r = requests.post(RPC_HTTP, json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params}, timeout=30)
    r.raise_for_status()
    j = r.json()
    if "result" not in j:
        raise RuntimeError(f"RPC response missing result: {j}")
    return j["result"]

# ---------------- Persistence -----------------------
def load_state():
    try:
        return json.load(open(STATE_FILE, "r"))
    except Exception:
        return {}

def save_state(s):
    with open(STATE_FILE, "w") as f:
        json.dump(s, f)

# ----------------- Alerts ---------------------------
def send_discord(text):
    if not DISCORD_WEBHOOK: return
    try:
        requests.post(DISCORD_WEBHOOK, json={"content": text}, timeout=15)
    except Exception as e:
        print("Discord send error:", e)

def msg_clip(s, limit=3900):  # keep Telegram < 4096
    return s if len(s) <= limit else s[:limit-10] + "…(clipped)"

def send_telegram(text):
    if not (TG_TOKEN and TG_CHAT): return
    try:
        requests.post(f"https://api.telegram.org/bot{TG_TOKEN}/sendMessage",
                      data={"chat_id": TG_CHAT, "text": msg_clip(text)}, timeout=15)
    except Exception as e:
        print("Telegram send error:", e)

def alert(text):
    send_discord(text)
    send_telegram(text)

# ----------------- Decoding helpers -----------------
def account_keys_list(msg):
    keys = msg.get("accountKeys") or []
    if keys and isinstance(keys[0], dict):
        keys = [k.get("pubkey") for k in keys]
    return keys

def get_signers(tx):
    msg = (tx.get("transaction") or {}).get("message") or {}
    header = msg.get("header") or {}
    n = header.get("numRequiredSignatures", 0)
    keys = account_keys_list(msg)
    return set(keys[:n])

def resolve_account(index_or_key, keys):
    if isinstance(index_or_key, int):
        return keys[index_or_key] if 0 <= index_or_key < len(keys) else None
    return index_or_key

def instructions_iter(tx):
    """Yield (program_id, accounts[]) for both top-level and inner instructions."""
    msg = (tx.get("transaction") or {}).get("message") or {}
    keys = account_keys_list(msg)

    # Top-level
    for ix in (msg.get("instructions") or []):
        prog = None
        if "programIdIndex" in ix:
            idx = ix["programIdIndex"]
            prog = keys[idx] if isinstance(idx, int) and idx < len(keys) else None
        if "programId" in ix and ix.get("programId"):
            prog = ix["programId"]
        accs = [resolve_account(a, keys) for a in (ix.get("accounts") or [])]
        yield (prog, accs)

    # Inner
    meta = tx.get("meta") or {}
    for inner in (meta.get("innerInstructions") or []):
        for ix in (inner.get("instructions") or []):
            prog = ix.get("programId")
            if not prog and "programIdIndex" in ix:
                pidx = ix["programIdIndex"]
                prog = keys[pidx] if isinstance(pidx, int) and pidx < len(keys) else None
            accs = [resolve_account(a, keys) for a in (ix.get("accounts") or [])]
            yield (prog, accs)

# ---- Mint creation & supply minting detection ----
def logs_contain_initialize_mint(tx):
    logs = (tx.get("meta") or {}).get("logMessages") or []
    return any(("InitializeMint" in (l or "")) for l in logs)

def logs_contain_mint_to(tx):
    logs = (tx.get("meta") or {}).get("logMessages") or []
    return any(("MintTo" in (l or "")) or ("MintToChecked" in (l or "")) for l in logs)

def extract_mint_candidates(tx):
    """Heuristic: for token-program instructions, first account is often the mint."""
    mints = set()
    for prog, accs in instructions_iter(tx):
        if prog in TOKEN_PROGRAMS and accs:
            mints.add(accs[0])
    return list(mints)

def extract_mint_to_candidates(tx):
    """Heuristic for MintTo/MintToChecked: first account is the mint."""
    return extract_mint_candidates(tx)

# ---- Token metadata (name/symbol) via Metaplex ----
def fetch_token_name_symbol(mint_pubkey):
    try:
        res = rpc("getProgramAccounts", [
            METADATA_PROGRAM,
            {
                "encoding": "base64",
                "filters": [
                    {"memcmp": {"offset": 33, "bytes": mint_pubkey}}
                ]
            }
        ])
        if not res:
            return (None, None)
        data_b64 = res[0]["account"]["data"][0]
        raw = base64.b64decode(data_b64)

        # 1 (key) + 32 (update_authority) + 32 (mint) = 65 bytes, then Rust strings
        off = 65

        def read_str(buf, o):
            ln = int.from_bytes(buf[o:o+4], "little")
            o2 = o + 4
            s = buf[o2:o2+ln].decode("utf-8", "ignore").strip("\x00")
            return s, o2 + ln

        name, off = read_str(raw, off)
        symbol, off = read_str(raw, off)
        name = (name or "").strip()
        symbol = (symbol or "").strip()
        return (name or None, symbol or None)
    except Exception:
        return (None, None)

# ---- LP/Swap/Launch detection ---------------------
def detect_lp_activity(tx):
    hits = []
    for prog, accs in instructions_iter(tx):
        if prog in AMM_PROGRAMS:
            hits.append({"program": prog, "accounts": accs})
    return hits

def detect_swap_activity(tx):
    for prog, _ in instructions_iter(tx):
        if prog in SWAP_PROGRAMS:
            return True
    return False

def detect_launch_activity(tx):
    hits = []
    for prog, accs in instructions_iter(tx):
        if prog in LAUNCH_PROGRAMS:
            hits.append({"program": prog, "accounts": accs})
    return hits

# ---- Balance deltas & counterparties --------------
def token_transfer_deltas_for_wallet(tx, wallet):
    """Return [{mint, owner, delta_ui, decimals}] for this wallet."""
    meta = tx.get("meta") or {}
    pre = meta.get("preTokenBalances") or []
    post = meta.get("postTokenBalances") or []

    def key_of(tb):
        return (tb.get("mint"), tb.get("owner"))

    pre_map = {key_of(tb): tb for tb in pre}
    post_map = {key_of(tb): tb for tb in post}

    deltas = []
    owners = set([k[1] for k in list(pre_map.keys()) + list(post_map.keys())])
    for own in owners:
        if own != wallet:
            continue
        mints = set([m for (m, o) in pre_map.keys() if o == own] + [m for (m, o) in post_map.keys() if o == own])
        for mint in mints:
            pre_amt = (pre_map.get((mint, own)) or {}).get("uiTokenAmount", {}).get("uiAmount", 0.0) or 0.0
            post_amt = (post_map.get((mint, own)) or {}).get("uiTokenAmount", {}).get("uiAmount", 0.0) or 0.0
            dec = ((post_map.get((mint, own)) or {}).get("uiTokenAmount") or {}).get("decimals") \
                or ((pre_map.get((mint, own)) or {}).get("uiTokenAmount") or {}).get("decimals") \
                or 0
            delta = float(post_amt) - float(pre_amt)
            if abs(delta) > 0:
                deltas.append({"mint": mint, "owner": own, "delta_ui": delta, "decimals": dec})
    return deltas

def sol_transfer_counterparties(tx, wallet):
    cps = set()
    for prog, accs in instructions_iter(tx):
        if prog == SYSTEM_PROGRAM and len(accs) >= 2:
            sender, recipient = accs[0], accs[1]
            if sender == wallet and recipient != wallet:
                cps.add(recipient)
            if recipient == wallet and sender != wallet:
                cps.add(sender)
    return cps

def spl_counterparties(tx, wallet):
    meta = tx.get("meta") or {}
    pre = meta.get("preTokenBalances") or []
    post = meta.get("postTokenBalances") or []
    owners = set()
    for tb in pre + post:
        o = tb.get("owner")
        if o and o != wallet:
            owners.add(o)
    return owners

def extract_connected_wallets_from_tx(tx, wallet):
    connected = set()
    for s in get_signers(tx):
        if s != wallet:
            connected.add(s)
    connected |= sol_transfer_counterparties(tx, wallet)
    connected |= spl_counterparties(tx, wallet)
    return connected

def sol_transfer_deltas_for_wallet(tx, wallet):
    meta = tx.get("meta") or {}
    msg = (tx.get("transaction") or {}).get("message") or {}
    keys = account_keys_list(msg)
    if wallet not in keys:
        return None
    idx = keys.index(wallet)
    pre = (meta.get("preBalances") or [])
    post = (meta.get("postBalances") or [])
    if idx >= len(pre) or idx >= len(post):
        return None
    lam_delta = (post[idx] - pre[idx])
    return lam_delta / 1_000_000_000.0

# ---- Quick history scan for connected wallets -----
def find_mints_in_account_history(wallet, pages=2, limit=100):
    """Scan recent history for InitializeMint logs. Returns [{mint, tx, name, symbol}]."""
    before = None
    found = {}
    for _ in range(max(1, pages)):
        params = [wallet, {"limit": limit}]
        if before:
            params[1]["before"] = before
        try:
            sigs = rpc("getSignaturesForAddress", params)
        except Exception as e:
            print(f"[history {wallet}] signatures error:", e)
            break
        if not sigs:
            break
        for s in sigs:
            sig = s["signature"]
            try:
                tx = rpc("getTransaction", [sig, {"encoding": "json", "maxSupportedTransactionVersion": 0}])
            except Exception as e:
                print(f"[history {wallet}] tx error {sig}:", e)
                continue
            if not tx:
                continue
            if logs_contain_initialize_mint(tx):
                for mint in extract_mint_candidates(tx):
                    if mint not in found:
                        name, sym = fetch_token_name_symbol(mint)
                        found[mint] = {"mint": mint, "tx": sig, "name": name, "symbol": sym}
        before = sigs[-1]["signature"]
    return list(found.values())

# ----------------- Main processing -----------------
def process_wallet(wallet, st):
    wallet = wallet.strip()
    if not wallet:
        return st

    # per-wallet state
    wstate = st.get(wallet, {"last_sig": None, "connected": [], "lp_accounts": []})
    last = wstate.get("last_sig")
    known_connected = set(wstate.get("connected") or [])
    known_lp = set(wstate.get("lp_accounts") or [])

    # global caches for connected wallets
    connected_info = st.get("_connected_info", {})        # addr -> {"checked":bool, "mints":[...]}
    pending_checks = st.get("_pending_mint_checks", [])   # queue of addresses to check

    # Fetch latest signatures (large headroom), then process only new ones
    try:
        sigs = rpc("getSignaturesForAddress", [wallet, {"limit": 200}]) or []
    except Exception as e:
        print(f"[{wallet}] signatures error:", e)
        st[wallet] = wstate
        st["_connected_info"] = connected_info
        st["_pending_mint_checks"] = pending_checks
        return st

    vlog(f"[{wallet}] last_sig:", last, "| fetched:", len(sigs))

    new_sigs = []
    for entry in sigs:
        if last and entry["signature"] == last:
            break
        new_sigs.append(entry)
    vlog(f"[{wallet}] new_sigs:", len(new_sigs))

    for s in reversed(new_sigs):  # oldest -> newest
        sig = s["signature"]
        try:
            tx = rpc("getTransaction", [sig, {"encoding": "json", "maxSupportedTransactionVersion": 0}])
        except Exception as e:
            print(f"[{wallet}] tx error for {sig}:", e)
            continue
        if not tx:
            continue

        # 0) LAUNCH (pump.fun etc.)
        launch_hits = detect_launch_activity(tx)
        if launch_hits:
            candidates = set(extract_mint_candidates(tx))
            for hit in launch_hits:
                for a in (hit.get("accounts") or [])[:6]:
                    if a and len(a) >= 32:
                        candidates.add(a)

            resolved_lines = []
            for mint in list(candidates)[:6]:
                name, sym = fetch_token_name_symbol(mint)
                label = f" — {name} ({sym})" if (name or sym) else ""
                resolved_lines.append(f"• {mint}{label}\n  https://solscan.io/token/{mint}")

            lines = [
                "🚀 Launch activity detected",
                f"Wallet: `{wallet}`",
                f"Tx: https://solscan.io/tx/{sig}"
            ]
            if resolved_lines:
                lines.append("Possible token mints:")
                lines += resolved_lines
            alert("\n".join(lines))

        # 1) NEW TOKEN MINT (InitializeMint/InitializeMint2)
        if logs_contain_initialize_mint(tx):
            mints = extract_mint_candidates(tx)
            for mint in mints:
                name, sym = fetch_token_name_symbol(mint)
                name_line = f"\nName: {name} ({sym})" if (name or sym) else ""
                alert("🚨 Token mint detected"
                      f"\nWallet: `{wallet}`"
                      f"\nMint: `{mint}`{name_line}"
                      f"\nToken: https://solscan.io/token/{mint}"
                      f"\nTx: https://solscan.io/tx/{sig}")

        # 1b) SUPPLY MINTING (MintTo / MintToChecked)
        if logs_contain_mint_to(tx):
            mints = extract_mint_to_candidates(tx)
            lines = [f"🪙 Supply minted (MintTo)",
                     f"Wallet: `{wallet}`",
                     f"Tx: https://solscan.io/tx/{sig}"]
            for mint in mints[:6]:
                name, sym = fetch_token_name_symbol(mint)
                label = f" — {name} ({sym})" if (name or sym) else ""
                lines.append(f"• Mint: {mint}{label}\n  Token: https://solscan.io/token/{mint}")
            if len(lines) > 3:
                alert("\n".join(lines))

        # 2) LP-related activity (AMMs)
        lp_hits = detect_lp_activity(tx)
        if lp_hits and wallet in get_signers(tx):
            newly_found = set()
            for hit in lp_hits:
                for a in (hit.get("accounts") or []):
                    if a and len(a) >= 32 and a not in known_lp:
                        newly_found.add(a)
            if newly_found:
                known_lp |= newly_found
                wstate["lp_accounts"] = sorted(known_lp)

            lines = [f"🧪 LP-related activity",
                     f"Wallet: `{wallet}`",
                     f"Tx: https://solscan.io/tx/{sig}"]
            if newly_found:
                sample = list(newly_found)[:5]
                extra = "" if len(newly_found) <= 5 else f" (+{len(newly_found)-5} more)"
                lines.append("New LP/pool addresses:\n" + "\n".join(f"• {x}" for x in sample) + extra)
            alert("\n".join(lines))

        # 3) SWAP detection
        if detect_swap_activity(tx) and wallet in get_signers(tx):
            deltas = token_transfer_deltas_for_wallet(tx, wallet)
            lines = [f"🔄 Swap-related activity",
                     f"Wallet: `{wallet}`",
                     f"Tx: https://solscan.io/tx/{sig}"]
            if deltas:
                for d in deltas[:4]:
                    dir_ = "➕" if d["delta_ui"] > 0 else "➖"
                    lines.append(f"{dir_} {abs(d['delta_ui'])} of {d['mint']}")
                if len(deltas) > 4:
                    lines.append(f"(+{len(deltas)-4} more deltas)")
            alert("\n".join(lines))

        # 4) TRANSFERS summary (SPL + SOL) with SOL threshold
        tok_deltas = token_transfer_deltas_for_wallet(tx, wallet)
        sol_delta  = sol_transfer_deltas_for_wallet(tx, wallet)

        token_trigger = bool(tok_deltas and any(abs(d['delta_ui']) > 0 for d in tok_deltas))
        sol_trigger   = (sol_delta is not None) and (abs(sol_delta) >= MIN_SOL_TRANSFER)

        if token_trigger or sol_trigger:
            lines = [f"💸 Transfer activity",
                     f"Wallet: `{wallet}`",
                     f"Tx: https://solscan.io/tx/{sig}"]
            if sol_trigger:
                arrow = "➕" if sol_delta > 0 else "➖"
                lines.append(f"{arrow} {abs(sol_delta):,.9f} SOL (min {MIN_SOL_TRANSFER} SOL)")
            for d in (tok_deltas or [])[:5]:
                dir_ = "➕" if d["delta_ui"] > 0 else "➖"
                lines.append(f"{dir_} {abs(d['delta_ui'])} of {d['mint']}")
            if tok_deltas and len(tok_deltas) > 5:
                lines.append(f"(+{len(tok_deltas)-5} more token changes)")
            alert("\n".join(lines))

        # 5) CONNECTED WALLETS (discover)
        newly_conn = extract_connected_wallets_from_tx(tx, wallet) - known_connected
        if newly_conn:
            known_connected |= newly_conn
            wstate["connected"] = sorted(known_connected)
            sample = list(newly_conn)[:8]
            extra = "" if len(newly_conn) <= 8 else f" (+{len(newly_conn)-8} more)"
            alert("🕸️ New connected addresses"
                  f"\nWallet: `{wallet}`\n"
                  + "\n".join(f"• {a}" for a in sample) + extra
                  + f"\nTx: https://solscan.io/tx/{sig}")

            # Queue for mint-history checks
            for addr in newly_conn:
                info = connected_info.get(addr) or {}
                if not info.get("checked"):
                    connected_info[addr] = info
                    pending_checks.append(addr)

        # advance last_sig after each processed signature
        wstate["last_sig"] = sig
        st[wallet] = wstate

    # Post-loop: scan a few pending connected wallets for past mints
    checks_done = 0
    i = 0
    while i < len(pending_checks) and checks_done < CONNECT_CHECKS_PER_RUN:
        addr = pending_checks[i]
        info = connected_info.get(addr) or {}
        if info.get("checked"):
            pending_checks.pop(i)
            continue

        try:
            mints = find_mints_in_account_history(addr, pages=HISTORY_PAGES_PER_CONNECTED, limit=HISTORY_PAGE_LIMIT)
            info["checked"] = True
            info["mints"] = mints
            connected_info[addr] = info
            pending_checks.pop(i)
            checks_done += 1

            if mints:
                lines = [f"🧭 Connected wallet mint history",
                         f"Wallet: `{addr}`",
                         f"Found {len(mints)} mint(s) in recent history:"]
                for m in mints[:6]:
                    label = f" — {m['name']} ({m['symbol']})" if (m.get('name') or m.get('symbol')) else ""
                    lines.append(f"• {m['mint']}{label}\n  https://solscan.io/token/{m['mint']}\n  Tx: https://solscan.io/tx/{m['tx']}")
                if len(mints) > 6:
                    lines.append(f"(+{len(mints)-6} more)")
                alert("\n".join(lines))
        except Exception as e:
            print(f"[connected {addr}] history scan error:", e)
            i += 1
            continue

    st["_connected_info"] = connected_info
    st["_pending_mint_checks"] = pending_checks
    return st

# ----------------- Entrypoint -----------------------
def parse_wallets(raw):
    if not raw: return []
    if "\n" in raw:
        wallets = [w.strip() for w in raw.splitlines()]
    else:
        wallets = [w.strip() for w in raw.split(",")]
    return [w for w in wallets if w]

def apply_shard(wallets, idx, total):
    if idx < 0 or total <= 0:  # sharding disabled
        return wallets
    return [w for i, w in enumerate(wallets) if i % total == idx]

def main():
    wallets = parse_wallets(WALLET_LIST)
    if not wallets:
        raise SystemExit("WALLET_LIST is empty. Provide one wallet per line or comma separated.")

    wallets = apply_shard(wallets, SHARD_INDEX, SHARD_TOTAL)
    vlog(f"Shard {SHARD_INDEX}/{SHARD_TOTAL} processing {len(wallets)} wallet(s)")

    st = load_state()
    for w in wallets:
        vlog("Processing wallet:", w)
        st = process_wallet(w, st)
        time.sleep(0.2)  # be gentle on public RPC
    save_state(st)

if __name__ == "__main__":
    main()
