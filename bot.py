import os, json, requests, time, base64

RPC_HTTP = os.getenv("RPC_HTTP", "https://api.mainnet-beta.solana.com")
WALLET_LIST = os.getenv("WALLET_LIST", "").strip()   # newline or comma separated
STATE_FILE = "state.json"

# Alerts (use one or both)
DISCORD_WEBHOOK = os.getenv("DISCORD_WEBHOOK")
TG_TOKEN = os.getenv("TG_TOKEN")
TG_CHAT  = os.getenv("TG_CHAT")

# Programs to flag as LP / Swap related (Raydium/Orca/Meteora/etc) – set via repo Variables.
AMM_PROGRAMS_RAW  = os.getenv("AMM_PROGRAMS", "").strip()
SWAP_PROGRAMS_RAW = os.getenv("SWAP_PROGRAMS", "").strip()

# Known base programs
SYSTEM_PROGRAM = "11111111111111111111111111111111"
TOKEN_PROGRAMS = {
    "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",  # SPL Token
    "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb",  # Token-2022
}
# Metaplex Token Metadata program (fixed address)
METADATA_PROGRAM = "metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s"

def parse_list_env(value: str):
    if not value:
        return []
    if "\n" in value:
        return [v.strip() for v in value.splitlines() if v.strip() and not v.strip().startswith("#")]
    return [v.strip() for v in value.split(",") if v.strip() and not v.strip().startswith("#")]

AMM_PROGRAMS  = set(parse_list_env(AMM_PROGRAMS_RAW))
SWAP_PROGRAMS = set(parse_list_env(SWAP_PROGRAMS_RAW)) or set(parse_list_env(AMM_PROGRAMS_RAW))  # fallback

def rpc(method, params):
    r = requests.post(RPC_HTTP, json={"jsonrpc":"2.0","id":1,"method":method,"params":params}, timeout=25)
    r.raise_for_status()
    j = r.json()
    if "result" not in j:
        raise RuntimeError(f"RPC error: {j}")
    return j["result"]

def load_state():
    try:
        return json.load(open(STATE_FILE, "r"))
    except Exception:
        return {}  # { wallet: { "last_sig": "...", "connected": [...], "lp_accounts":[...] } }

def save_state(s):
    with open(STATE_FILE, "w") as f:
        json.dump(s, f)

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
                prog = keys[pidx] if isinstance(pidx, int) and idx < len(keys) else None
            accs = [resolve_account(a, keys) for a in (ix.get("accounts") or [])]
            yield (prog, accs)

def logs_contain_initialize_mint(tx):
    logs = (tx.get("meta") or {}).get("logMessages") or []
    return any(("InitializeMint" in (l or "")) for l in logs)

def extract_mint_candidates(tx):
    """Heuristic: for token program instructions, first account is often the mint."""
    mints = set()
    for prog, accs in instructions_iter(tx):
        if prog in TOKEN_PROGRAMS and accs:
            mints.add(accs[0])
    return list(mints)

def fetch_token_name_symbol(mint_pubkey):
    """
    Try to read Metaplex metadata (name/symbol) via getProgramAccounts filter where
    offset 33 (1 key + 32 update_authority) equals mint pubkey.
    Returns (name, symbol) or (None, None) if not found/decoding fails.
    """
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

        # Parse: 1 (key) + 32 (update_authority) + 32 (mint) = 65 bytes, then Rust strings
        off = 65

        def read_str(buf, o):
            ln = int.from_bytes(buf[o:o+4], "little")
            o2 = o + 4
            s = buf[o2:o2+ln].decode("utf-8", "ignore").strip("\x00")
            return s, o2 + ln

        name, off = read_str(raw, off)
        symbol, off = read_str(raw, off)
        # uri, off = read_str(raw, off)  # not needed now
        name = name.strip()
        symbol = symbol.strip()
        return (name or None, symbol or None)
    except Exception:
        # Metadata might not exist or be non-standard; that's fine.
        return (None, None)

def detect_lp_activity(tx):
    """Return list of LP-related hits: [{'program': <id>, 'accounts': [...]}, ...]"""
    hits = []
    for prog, accs in instructions_iter(tx):
        if prog in AMM_PROGRAMS:
            hits.append({"program": prog, "accounts": accs})
    return hits

def detect_swap_activity(tx):
    """Return True if any instruction touches a swap program."""
    for prog, _ in instructions_iter(tx):
        if prog in SWAP_PROGRAMS:
            return True
    return False

def token_transfer_deltas_for_wallet(tx, wallet):
    """
    Summarize SPL token balance deltas for 'wallet' using pre/postTokenBalances.
    Returns list of dicts: [{mint, owner, delta_ui, decimals}, ...] where owner==wallet and delta!=0
    """
    meta = tx.get("meta") or {}
    pre = meta.get("preTokenBalances") or []
    post = meta.get("postTokenBalances") or []

    def key_of(tb):
        return (tb.get("mint"), tb.get("owner"))  # owner is the token-account owner

    pre_map = {key_of(tb): tb for tb in pre}
    post_map = {key_of(tb): tb for tb in post}

    deltas = []
    owners = set([k[1] for k in list(pre_map.keys()) + list(post_map.keys())])
    for own in owners:
        if own != wallet:  # focus on changes to THIS wallet's token holdings
            continue
        # collect mints for this owner
        mints = set([m for (m,o) in pre_map.keys() if o==own] + [m for (m,o) in post_map.keys() if o==own])
        for mint in mints:
            pre_amt = (pre_map.get((mint, own)) or {}).get("uiTokenAmount", {}).get("uiAmount", 0.0) or 0.0
            post_amt= (post_map.get((mint, own)) or {}).get("uiTokenAmount", {}).get("uiAmount", 0.0) or 0.0
            dec = ((post_map.get((mint, own)) or {}).get("uiTokenAmount") or {}).get("decimals") \
                  or ((pre_map.get((mint, own)) or {}).get("uiTokenAmount") or {}).get("decimals") \
                  or 0
            delta = float(post_amt) - float(pre_amt)
            if abs(delta) > 0:
                deltas.append({"mint": mint, "owner": own, "delta_ui": delta, "decimals": dec})
    return deltas

def sol_transfer_deltas_for_wallet(tx, wallet):
    """
    Summarize SOL (lamports) delta for 'wallet' via pre/postBalances aligned with accountKeys.
    Returns delta in SOL (float). Positive = received, negative = sent. None if wallet not present.
    """
    meta = tx.get("meta") or {}
    msg = (tx.get("transaction") or {}).get("message") or {}
    keys = account_keys_list(msg)
    if wallet not in keys:
        return None
    idx = keys.index(wallet)
    pre = (meta.get("preBalances")  or [])
    post= (meta.get("postBalances") or [])
    if idx >= len(pre) or idx >= len(post):
        return None
    lam_delta = (post[idx] - pre[idx])
    return lam_delta / 1_000_000_000.0

def process_wallet(wallet, st):
    wallet = wallet.strip()
    if not wallet: return st
    wstate = st.get(wallet, {"last_sig": None, "connected": [], "lp_accounts": []})
    last = wstate.get("last_sig")
    known_connected = set(wstate.get("connected") or [])
    known_lp = set(wstate.get("lp_accounts") or [])

    params = [wallet, {"limit": 50}]
    if last:
        params[1]["until"] = last

    try:
        sigs = rpc("getSignaturesForAddress", params)
    except Exception as e:
        print(f"[{wallet}] signatures error:", e)
        return st

    # Process oldest -> newest so we end on the newest signature
    for s in reversed(sigs):
        sig = s["signature"]
        try:
            tx = rpc("getTransaction", [sig, {"encoding":"json","maxSupportedTransactionVersion":0}])
            if not tx:
                continue

            # 1) MINT alerts (with name/symbol if we can read metadata)
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

            # 2) LP-related activity (AMM programs)
            lp_hits = detect_lp_activity(tx)
            if lp_hits and wallet in get_signers(tx):
                newly_found = set()
                for hit in lp_hits:
                    for a in (hit.get("accounts") or []):
                        if a and len(a) >= 32:  # rough filter for pubkeys
                            if a not in known_lp:
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
                else:
                    sample = []
                    for hit in lp_hits:
                        sample += (hit.get("accounts") or [])
                        if len(sample) >= 5: break
                    if sample:
                        lines.append("Accounts (sample):\n" + "\n".join(f"• {x}" for x in sample[:5]))
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

            # 4) TRANSFERS (SPL token + SOL) for the wallet
            tok_deltas = token_transfer_deltas_for_wallet(tx, wallet)
            sol_delta  = sol_transfer_deltas_for_wallet(tx, wallet)
            if (tok_deltas and any(abs(d['delta_ui']) > 0 for d in tok_deltas)) or (sol_delta and abs(sol_delta) > 0):
                lines = [f"💸 Transfer activity",
                         f"Wallet: `{wallet}`",
                         f"Tx: https://solscan.io/tx/{sig}"]
                if sol_delta and abs(sol_delta) > 0:
                    arrow = "➕" if sol_delta > 0 else "➖"
                    lines.append(f"{arrow} {abs(sol_delta):,.9f} SOL")
                for d in tok_deltas[:5]:
                    dir_ = "➕" if d["delta_ui"] > 0 else "➖"
                    lines.append(f"{dir_} {abs(d['delta_ui'])} of {d['mint']}")
                if len(tok_deltas) > 5:
                    lines.append(f"(+{len(tok_deltas)-5} more token changes)")
                alert("\n".join(lines))

            # 5) Connected addresses (other signers + SOL recipients where wallet sends SOL)
            msg = (tx.get("transaction") or {}).get("message") or {}
            keys = account_keys_list(msg)
            # other signers
            for sgn in get_signers(tx):
                if sgn != wallet and sgn not in known_connected:
                    known_connected.add(sgn)
            # SOL recipients where wallet is sender
            for prog, accs in instructions_iter(tx):
                if prog == SYSTEM_PROGRAM and len(accs) >= 2:
                    sender, recipient = accs[0], accs[1]
                    if sender == wallet and recipient not in known_connected:
                        known_connected.add(recipient)

            newly = set(known_connected) - set(wstate.get("connected") or [])
            if newly:
                wstate["connected"] = sorted(known_connected)
                sample = list(newly)[:6]
                extra = "" if len(newly) <= 6 else f" (+{len(newly)-6} more)"
                alert("🕸️ New connected addresses\n"
                      f"Wallet: `{wallet}`\n"
                      + "\n".join(f"• {a}" for a in sample) + extra
                      + f"\nTx: https://solscan.io/tx/{sig}")

        except Exception as e:
            print(f"[{wallet}] tx error for {sig}:", e)

        wstate["last_sig"] = sig
        st[wallet] = wstate

    return st

def parse_wallets(raw):
    if not raw: return []
    if "\n" in raw:
        wallets = [w.strip() for w in raw.splitlines()]
    else:
        wallets = [w.strip() for w in raw.split(",")]
    return [w for w in wallets if w]

def main():
    wallets = parse_wallets(WALLET_LIST)
    if not wallets:
        raise SystemExit("WALLET_LIST is empty. Provide one wallet per line or comma separated.")

    st = load_state()
    for w in wallets:
        st = process_wallet(w, st)
        time.sleep(0.2)  # be gentle on public RPC
    save_state(st)

if __name__ == "__main__":
    main()
