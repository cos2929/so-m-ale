import os, json, requests, time

RPC_HTTP = os.getenv("RPC_HTTP", "https://api.mainnet-beta.solana.com")
WALLET_LIST = os.getenv("WALLET_LIST", "").strip()  # newline or comma separated
STATE_FILE = "state.json"

# Alerts (use one or both)
DISCORD_WEBHOOK = os.getenv("DISCORD_WEBHOOK")
TG_TOKEN = os.getenv("TG_TOKEN")
TG_CHAT  = os.getenv("TG_CHAT")

# SPL Token programs
TOKEN_PROGRAMS = {
    "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",  # SPL Token
    "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb",  # Token-2022
}

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
        return {}  # { wallet: { "last_sig": "..." } }

def save_state(s):
    with open(STATE_FILE, "w") as f:
        json.dump(s, f)

def send_discord(text):
    if not DISCORD_WEBHOOK: return
    try:
        requests.post(DISCORD_WEBHOOK, json={"content": text}, timeout=15)
    except Exception as e:
        print("Discord send error:", e)

def send_telegram(text):
    if not (TG_TOKEN and TG_CHAT): return
    try:
        requests.post(f"https://api.telegram.org/bot{TG_TOKEN}/sendMessage",
                      data={"chat_id": TG_CHAT, "text": text}, timeout=15)
    except Exception as e:
        print("Telegram send error:", e)

def alert(text):
    send_discord(text)
    send_telegram(text)

def logs_contain_initialize_mint(tx):
    logs = (tx.get("meta") or {}).get("logMessages") or []
    return any(("InitializeMint" in (l or "")) for l in logs)

def extract_mint_candidates(tx):
    """
    Grab likely mint addresses from token-program instructions.
    For InitializeMint/InitializeMint2 the first account is the Mint.
    We scan both top-level and inner instructions.
    """
    mints = set()

    msg = (tx.get("transaction") or {}).get("message") or {}
    keys = msg.get("accountKeys") or []
    # accountKeys can be strings or objects with {"pubkey": "..."}
    if keys and isinstance(keys[0], dict):
        keys = [k.get("pubkey") for k in keys]

    # helper to resolve an account index or string to pubkey
    def resolve(acct):
        if isinstance(acct, int):
            return keys[acct] if 0 <= acct < len(keys) else None
        return acct  # already a pubkey string

    # Top-level instructions
    for ix in (msg.get("instructions") or []):
        idx = ix.get("programIdIndex")
        prog = keys[idx] if isinstance(idx, int) and idx < len(keys) else None
        if prog in TOKEN_PROGRAMS:
            accs = ix.get("accounts") or []
            if accs:
                mint = resolve(accs[0])
                if mint: mints.add(mint)

    # Inner instructions
    meta = tx.get("meta") or {}
    for inner in (meta.get("innerInstructions") or []):
        for ix in (inner.get("instructions") or []):
            # inner can have programIdIndex or programId as string
            prog = ix.get("programId")
            if prog is None and "programIdIndex" in ix:
                pidx = ix["programIdIndex"]
                prog = keys[pidx] if isinstance(pidx, int) and pidx < len(keys) else None
            if prog in TOKEN_PROGRAMS:
                accs = ix.get("accounts") or []
                if accs:
                    mint = resolve(accs[0])
                    if mint: mints.add(mint)

    return list(mints)

def process_wallet(wallet, st):
    wallet = wallet.strip()
    if not wallet: return st
    wstate = st.get(wallet, {"last_sig": None})
    last = wstate.get("last_sig")

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

            if tx and logs_contain_initialize_mint(tx):
                mints = extract_mint_candidates(tx)
                if mints:
                    for mint in mints:
                        # handy links
                        solscan = f"https://solscan.io/token/{mint}"
                        txlink  = f"https://solscan.io/tx/{sig}"
                        alert(f"🚨 New token mint activity\nWallet: `{wallet}`\nMint: `{mint}`\nToken: {solscan}\nTx: {txlink}")
                else:
                    # Fallback alert if we couldn't confidently extract the mint
                    txlink = f"https://solscan.io/tx/{sig}"
                    alert(f"🚨 New token mint activity (mint unknown)\nWallet: `{wallet}`\nTx: {txlink}")

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
        time.sleep(0.2)
    save_state(st)

if __name__ == "__main__":
    main()
