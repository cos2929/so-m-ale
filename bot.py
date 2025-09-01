import os, json, requests, time

RPC_HTTP = os.getenv("RPC_HTTP", "https://api.mainnet-beta.solana.com")
WALLET_LIST = os.getenv("WALLET_LIST", "").strip()  # newline or comma separated
STATE_FILE = "state.json"                           # stores last sig per wallet

# Alerts: enable one or both
DISCORD_WEBHOOK = os.getenv("DISCORD_WEBHOOK")      # Discord channel webhook URL (optional)
TG_TOKEN = os.getenv("TG_TOKEN")                    # Telegram bot token (optional)
TG_CHAT  = os.getenv("TG_CHAT")                     # Telegram chat id (optional)

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

def looks_like_mint_init(tx):
    # Most reliable quick signal is in logs
    logs = (tx.get("meta") or {}).get("logMessages") or []
    if any(("InitializeMint" in (l or "")) for l in logs):  # covers InitializeMint & InitializeMint2
        return True
    # Gentle fallback: if any top-level instruction targets token programs
    msg = (tx.get("transaction") or {}).get("message") or {}
    keys = msg.get("accountKeys") or []
    if keys and isinstance(keys[0], dict):
        keys = [k.get("pubkey") for k in keys]
    for ix in (msg.get("instructions") or []):
        idx = ix.get("programIdIndex")
        if idx is not None and idx < len(keys) and keys[idx] in TOKEN_PROGRAMS:
            return True
    return False

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

    # Older -> newer so last_sig ends up as newest processed
    for s in reversed(sigs):
        sig = s["signature"]
        try:
            tx = rpc("getTransaction", [sig, {"encoding":"json","maxSupportedTransactionVersion":0}])
            if tx and looks_like_mint_init(tx):
                link = f"https://solscan.io/tx/{sig}"
                alert(f"🚨 New token mint activity\nWallet: `{wallet}`\nTx: {link}")
        except Exception as e:
            print(f"[{wallet}] tx error for {sig}:", e)

        wstate["last_sig"] = sig
        st[wallet] = wstate

    return st

def parse_wallets(raw):
    if not raw: return []
    # Accept newline or comma separated
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
        time.sleep(0.2)  # gentle on public RPC
    save_state(st)

if __name__ == "__main__":
    main()
