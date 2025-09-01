import os
import json
import requests
import time
import base64
import logging
from solders.pubkey import Pubkey

# Setup logging
logging.basicConfig(filename='bot.log', level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

# --------- Config via environment ----------
RPC_HTTP = os.getenv("RPC_HTTP", "https://api.mainnet-beta.solana.com")
WALLET_LIST = os.getenv("WALLET_LIST", "").strip()  # newline or comma separated
STATE_FILE = os.getenv("STATE_FILE", "state.json")  # per-shard file
SHARD_INDEX = int(os.getenv("SHARD_INDEX", "-1"))
SHARD_TOTAL = int(os.getenv("SHARD_TOTAL", "-1"))
CONNECT_CHECKS_PER_RUN = int(os.getenv("CONNECT_CHECKS_PER_RUN", "4"))
HISTORY_PAGE_LIMIT = int(os.getenv("HISTORY_PAGE_LIMIT", "100"))
VERBOSE = os.getenv("VERBOSE", "0") == "1"
DISCORD_WEBHOOK = os.getenv("DISCORD_WEBHOOK")
TG_TOKEN = os.getenv("TG_TOKEN")
TG_CHAT = os.getenv("TG_CHAT")
AMM_PROGRAMS_RAW = os.getenv("AMM_PROGRAMS", "").strip()
LAUNCH_PROGRAMS_RAW = os.getenv("LAUNCH_PROGRAMS", "").strip()

# Known programs
TOKEN_PROGRAMS = {
    "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",  # SPL Token
    "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb",  # Token-2022
}
METADATA_PROGRAM = "metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s"

def vlog(*args):
    if VERBOSE:
        print(*args)
        logging.info(' '.join(str(a) for a in args))

def parse_list_env(value: str):
    if not value:
        return []
    if "\n" in value:
        return [v.strip() for v in value.splitlines() if v.strip() and not v.strip().startswith("#")]
    return [v.strip() for v in value.split(",") if v.strip() and not v.strip().startswith("#")]

AMM_PROGRAMS = set(parse_list_env(AMM_PROGRAMS_RAW))
LAUNCH_PROGRAMS = set(parse_list_env(LAUNCH_PROGRAMS_RAW))

# -------------------- RPC helpers --------------------
def rpc(method, params, retries=3):
    for attempt in range(retries):
        try:
            r = requests.post(RPC_HTTP, json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params}, timeout=30)
            if r.status_code == 429:
                sleep = 2 ** attempt
                logging.warning(f"Rate limit hit, retrying after {sleep}s")
                time.sleep(sleep)
                continue
            r.raise_for_status()
            j = r.json()
            if "result" not in j:
                raise RuntimeError(f"RPC response missing result: {j}")
            return j["result"]
        except Exception as e:
            logging.error(f"RPC error (attempt {attempt+1}/{retries}): {e}")
            if attempt == retries - 1:
                raise
            time.sleep(2 ** attempt)

# ---------------- Persistence -----------------------
def load_state():
    try:
        with open(STATE_FILE, "r") as f:
            return json.load(f)
    except Exception:
        logging.info(f"No existing state file {STATE_FILE}, starting fresh")
        return {}

def save_state(s):
    try:
        with open(STATE_FILE, "w") as f:
            json.dump(s, f)
        logging.info(f"Saved state to {STATE_FILE}")
    except Exception as e:
        logging.error(f"Failed to save state: {e}")

# ----------------- Alerts ---------------------------
def send_discord(text, embed=None):
    if not DISCORD_WEBHOOK:
        return
    payload = {"content": text} if not embed else {"embeds": [embed]}
    try:
        requests.post(DISCORD_WEBHOOK, json=payload, timeout=15)
        logging.info("Sent Discord alert")
    except Exception as e:
        logging.error(f"Discord send error: {e}")

def msg_clip(s, limit=3900):  # Telegram < 4096
    return s if len(s) <= limit else s[:limit-10] + "…(clipped)"

def send_telegram(text):
    if not (TG_TOKEN and TG_CHAT):
        return
    try:
        requests.post(f"https://api.telegram.org/bot{TG_TOKEN}/sendMessage",
                      data={"chat_id": TG_CHAT, "text": msg_clip(text)}, timeout=15)
        logging.info("Sent Telegram alert")
    except Exception as e:
        logging.error(f"Telegram send error: {e}")

def alert(text, embed=None):
    send_discord(text, embed)
    send_telegram(text)

def mint_alert(wallet, mint, tx_sig, name, symbol, connected, is_connected_wallet=False, main_wallet=None):
    name_line = f"{name} ({symbol})" if (name or symbol) else "N/A"
    connected_str = "\n".join(f"• {a}" for a in list(connected)[:8]) + (f" (+{len(connected)-8} more)" if len(connected) > 8 else "")
    title = "🔔 Connected Wallet Mint Detected" if is_connected_wallet else "🚨 Token Mint Detected"
    fields = [
        {"name": "Wallet", "value": f"`{wallet}`", "inline": True},
        {"name": "Mint", "value": f"`{mint}`", "inline": True},
        {"name": "Name/Symbol", "value": name_line},
        {"name": "Connected Addresses", "value": connected_str or "None"},
        {"name": "Links", "value": f"[Token](https://solscan.io/token/{mint}) | [Tx](https://solscan.io/tx/{tx_sig})"}
    ]
    if is_connected_wallet and main_wallet:
        fields.insert(0, {"name": "Main Wallet", "value": f"`{main_wallet}`", "inline": True})
    embed = {
        "title": title,
        "fields": fields,
        "color": 0xFF9900 if is_connected_wallet else 0xFF0000
    }
    alert_text = f"Connected wallet {wallet} minted {mint}" if is_connected_wallet else f"Token mint: {wallet} minted {mint}"
    alert(alert_text, embed)

def launch_alert(wallet, tx_sig, candidates, connected, is_connected_wallet=False, main_wallet=None):
    resolved_lines = []
    for mint in list(candidates)[:6]:
        name, sym = fetch_token_name_symbol(mint)
        label = f" — {name} ({sym})" if (name or sym) else ""
        resolved_lines.append(f"• {mint}{label}\n  [Token](https://solscan.io/token/{mint})")
    connected_str = "\n".join(f"• {a}" for a in list(connected)[:8]) + (f" (+{len(connected)-8} more)" if len(connected) > 8 else "")
    title = "🔔 Connected Wallet Launch Detected" if is_connected_wallet else "🚀 Launch Activity Detected"
    fields = [
        {"name": "Wallet", "value": f"`{wallet}`", "inline": True},
        {"name": "Tx", "value": f"[Tx](https://solscan.io/tx/{tx_sig})", "inline": True},
        {"name": "Possible Mints", "value": "\n".join(resolved_lines) or "None"},
        {"name": "Connected Addresses", "value": connected_str or "None"}
    ]
    if is_connected_wallet and main_wallet:
        fields.insert(0, {"name": "Main Wallet", "value": f"`{main_wallet}`", "inline": True})
    embed = {
        "title": title,
        "fields": fields,
        "color": 0x99FF00 if is_connected_wallet else 0x00FF00
    }
    alert_text = f"Connected wallet {wallet} launch activity" if is_connected_wallet else f"Launch activity: {wallet}"
    alert(alert_text, embed)

def lp_alert(wallet, tx_sig, new_accounts, connected):
    sample = list(new_accounts)[:5]
    extra = "" if len(new_accounts) <= 5 else f" (+{len(new_accounts)-5} more)"
    connected_str = "\n".join(f"• {a}" for a in list(connected)[:8]) + (f" (+{len(connected)-8} more)" if len(connected) > 8 else "")
    embed = {
        "title": "🧪 LP-Related Activity",
        "fields": [
            {"name": "Wallet", "value": f"`{wallet}`", "inline": True},
            {"name": "Tx", "value": f"[Tx](https://solscan.io/tx/{tx_sig})", "inline": True},
            {"name": "New LP/Pool Addresses", "value": "\n".join(f"• {x}" for x in sample) + extra},
            {"name": "Connected Addresses", "value": connected_str or "None"}
        ],
        "color": 0x0000FF
    }
    alert(f"LP activity: {wallet}", embed)

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
    msg = (tx.get("transaction") or {}).get("message") or {}
    keys = account_keys_list(msg)
    for ix in (msg.get("instructions") or []):
        prog = None
        if "programIdIndex" in ix:
            idx = ix["programIdIndex"]
            prog = keys[idx] if isinstance(idx, int) and idx < len(keys) else None
        if "programId" in ix and ix.get("programId"):
            prog = ix["programId"]
        accs = [resolve_account(a, keys) for a in (ix.get("accounts") or [])]
        yield (prog, accs)
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
    mints = set()
    for prog, accs in instructions_iter(tx):
        if prog in TOKEN_PROGRAMS and accs:
            mints.add(accs[0])
    return list(mints)

def extract_mint_to_candidates(tx):
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
    except Exception as e:
        logging.error(f"Failed to fetch token metadata for {mint_pubkey}: {e}")
        return (None, None)

# ---- LP/Launch detection ---------------------
def detect_lp_activity(tx):
    hits = []
    for prog, accs in instructions_iter(tx):
        if prog in AMM_PROGRAMS:
            hits.append({"program": prog, "accounts": accs})
    return hits

def detect_launch_activity(tx):
    hits = []
    for prog, accs in instructions_iter(tx):
        if prog in LAUNCH_PROGRAMS:
            hits.append({"program": prog, "accounts": accs})
    return hits

# ---- Connected addresses ---------------------
def extract_connected_wallets_from_tx(tx, wallet):
    connected = set()
    for s in get_signers(tx):
        if s != wallet:
            connected.add(s)
    meta = tx.get("meta") or {}
    pre = meta.get("preTokenBalances") or []
    post = meta.get("postTokenBalances") or []
    for tb in pre + post:
        o = tb.get("owner")
        if o and o != wallet:
            connected.add(o)
    for prog, accs in instructions_iter(tx):
        if prog == "11111111111111111111111111111111" and len(accs) >= 2:  # System Program
            sender, recipient = accs[0], accs[1]
            if sender == wallet and recipient != wallet:
                connected.add(recipient)
            if recipient == wallet and sender != wallet:
                connected.add(sender)
    return connected

# ---- Check connected wallet for mint/launch -----
def check_connected_wallet(wallet, main_wallet, last_sig=None):
    try:
        params = [wallet, {"limit": HISTORY_PAGE_LIMIT}]
        if last_sig:
            params[1]["before"] = last_sig
        sigs = rpc("getSignaturesForAddress", params) or []
    except Exception as e:
        logging.error(f"[connected {wallet}] signatures error: {e}")
        return None, []
    
    new_sigs = []
    for entry in sigs:
        if last_sig and entry["signature"] == last_sig:
            break
        new_sigs.append(entry)
    
    results = []
    latest_sig = new_sigs[0]["signature"] if new_sigs else last_sig
    for s in reversed(new_sigs):
        sig = s["signature"]
        try:
            tx = rpc("getTransaction", [sig, {"encoding": "json", "maxSupportedTransactionVersion": 0}])
        except Exception as e:
            logging.error(f"[connected {wallet}] tx error for {sig}: {e}")
            continue
        if not tx:
            continue
        
        connected = extract_connected_wallets_from_tx(tx, wallet)
        
        # Mint detection
        if logs_contain_initialize_mint(tx):
            mints = extract_mint_candidates(tx)
            for mint in mints:
                name, sym = fetch_token_name_symbol(mint)
                results.append(("mint", mint, sig, name, sym, connected))
        
        # Supply minting
        if logs_contain_mint_to(tx):
            mints = extract_mint_to_candidates(tx)
            for mint in mints:
                name, sym = fetch_token_name_symbol(mint)
                results.append(("mint_to", mint, sig, name, sym, connected))
        
        # Launch detection
        launch_hits = detect_launch_activity(tx)
        if launch_hits:
            candidates = set(extract_mint_candidates(tx))
            for hit in launch_hits:
                for a in (hit.get("accounts") or [])[:6]:
                    if a and len(a) >= 32:
                        candidates.add(a)
            results.append(("launch", None, sig, None, None, connected, candidates))
    
    return latest_sig, results

# ----------------- Main processing -----------------
def is_valid_wallet(address):
    try:
        Pubkey.from_string(address)
        return True
    except:
        logging.warning(f"Invalid wallet address: {address}")
        return False

def process_wallet(wallet, st):
    wallet = wallet.strip()
    if not wallet or not is_valid_wallet(wallet):
        logging.warning(f"Skipping invalid or empty wallet: {wallet}")
        return st

    wstate = st.get(wallet, {"last_sig": None, "lp_accounts": []})
    last = wstate.get("last_sig")
    known_lp = set(wstate.get("lp_accounts") or [])
    connected_wallets = st.get("_connected_wallets", {})
    pending_checks = st.get("_pending_checks", [])

    try:
        sigs = rpc("getSignaturesForAddress", [wallet, {"limit": 200}]) or []
    except Exception as e:
        logging.error(f"[{wallet}] signatures error: {e}")
        st[wallet] = wstate
        st["_connected_wallets"] = connected_wallets
        st["_pending_checks"] = pending_checks
        return st

    vlog(f"[{wallet}] last_sig:", last, "| fetched:", len(sigs))
    new_sigs = []
    for entry in sigs:
        if last and entry["signature"] == last:
            break
        new_sigs.append(entry)
    vlog(f"[{wallet}] new_sigs:", len(new_sigs))

    for s in reversed(new_sigs):
        sig = s["signature"]
        try:
            tx = rpc("getTransaction", [sig, {"encoding": "json", "maxSupportedTransactionVersion": 0}])
        except Exception as e:
            logging.error(f"[{wallet}] tx error for {sig}: {e}")
            continue
        if not tx:
            continue

        connected = extract_connected_wallets_from_tx(tx, wallet)
        for addr in connected:
            if addr not in connected_wallets:
                connected_wallets[addr] = {"last_sig": None, "checked": False}
                pending_checks.append((addr, wallet))

        # 0) LAUNCH
        launch_hits = detect_launch_activity(tx)
        if launch_hits:
            candidates = set(extract_mint_candidates(tx))
            for hit in launch_hits:
                for a in (hit.get("accounts") or [])[:6]:
                    if a and len(a) >= 32:
                        candidates.add(a)
            launch_alert(wallet, sig, candidates, connected)

        # 1) NEW TOKEN MINT
        if logs_contain_initialize_mint(tx):
            mints = extract_mint_candidates(tx)
            for mint in mints:
                name, sym = fetch_token_name_symbol(mint)
                mint_alert(wallet, mint, sig, name, sym, connected)

        # 2) SUPPLY MINTING
        if logs_contain_mint_to(tx):
            mints = extract_mint_to_candidates(tx)
            lines = [f"🪙 Supply minted (MintTo)\nWallet: `{wallet}`\nTx: https://solscan.io/tx/{sig}"]
            for mint in mints[:6]:
                name, sym = fetch_token_name_symbol(mint)
                label = f" — {name} ({sym})" if (name or sym) else ""
                lines.append(f"• Mint: {mint}{label}\n  Token: https://solscan.io/token/{mint})")
            if len(lines) > 3:
                connected_str = "\n".join(f"• {a}" for a in list(connected)[:8]) + (f" (+{len(connected)-8} more)" if len(connected) > 8 else "")
                embed = {
                    "title": "🪙 Supply Minted (MintTo)",
                    "fields": [
                        {"name": "Wallet", "value": f"`{wallet}`", "inline": True},
                        {"name": "Tx", "value": f"[Tx](https://solscan.io/tx/{sig})", "inline": True},
                        {"name": "Mints", "value": "\n".join(lines[1:]) or "None"},
                        {"name": "Connected Addresses", "value": connected_str or "None"}
                    ],
                    "color": 0xFF9900
                }
                alert("\n".join(lines), embed)

        # 3) LP-RELATED ACTIVITY
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
                lp_alert(wallet, sig, newly_found, connected)

        wstate["last_sig"] = sig
        st[wallet] = wstate

    # Check connected wallets
    checks_done = 0
    i = 0
    while i < len(pending_checks) and checks_done < CONNECT_CHECKS_PER_RUN:
        addr, main_wallet = pending_checks[i]
        info = connected_wallets.get(addr, {"last_sig": None, "checked": False})
        if info.get("checked"):
            pending_checks.pop(i)
            continue
        try:
            last_sig, results = check_connected_wallet(addr, main_wallet, info.get("last_sig"))
            for result in results:
                if result[0] == "mint":
                    _, mint, sig, name, sym, connected = result
                    mint_alert(addr, mint, sig, name, sym, connected, is_connected_wallet=True, main_wallet=main_wallet)
                elif result[0] == "mint_to":
                    _, mint, sig, name, sym, connected = result
                    connected_str = "\n".join(f"• {a}" for a in list(connected)[:8]) + (f" (+{len(connected)-8} more)" if len(connected) > 8 else "")
                    lines = [f"🪙 Connected Wallet Supply Minted\nWallet: `{addr}`\nMain Wallet: `{main_wallet}`\nTx: https://solscan.io/tx/{sig}"]
                    label = f" — {name} ({sym})" if (name or sym) else ""
                    lines.append(f"• Mint: {mint}{label}\n  Token: https://solscan.io/token/{mint})")
                    embed = {
                        "title": "🪙 Connected Wallet Supply Minted (MintTo)",
                        "fields": [
                            {"name": "Main Wallet", "value": f"`{main_wallet}`", "inline": True},
                            {"name": "Wallet", "value": f"`{addr}`", "inline": True},
                            {"name": "Tx", "value": f"[Tx](https://solscan.io/tx/{sig})", "inline": True},
                            {"name": "Mint", "value": f"`{mint}`"},
                            {"name": "Connected Addresses", "value": connected_str or "None"}
                        ],
                        "color": 0xFFCC00
                    }
                    alert("\n".join(lines), embed)
                elif result[0] == "launch":
                    _, _, sig, _, _, connected, candidates = result
                    launch_alert(addr, sig, candidates, connected, is_connected_wallet=True, main_wallet=main_wallet)
            info["last_sig"] = last_sig
            info["checked"] = True
            connected_wallets[addr] = info
            pending_checks.pop(i)
            checks_done += 1
        except Exception as e:
            logging.error(f"[connected {addr}] check error: {e}")
            i += 1
            continue

    st["_connected_wallets"] = connected_wallets
    st["_pending_checks"] = pending_checks
    return st

# ----------------- Entrypoint -----------------------
def parse_wallets(raw):
    if not raw:
        return []
    if "\n" in raw:
        wallets = [w.strip() for w in raw.splitlines()]
    else:
        wallets = [w.strip() for w in raw.split(",")]
    return [w for w in wallets if w and is_valid_wallet(w)]

def apply_shard(wallets, idx, total):
    if idx < 0 or total <= 0:
        return wallets
    return [w for i, w in enumerate(wallets) if i % total == idx]

def main():
    wallets = parse_wallets(WALLET_LIST)
    if not wallets:
        logging.error("WALLET_LIST is empty. Provide one wallet per line or comma separated.")
        raise SystemExit("WALLET_LIST is empty")
    wallets = apply_shard(wallets, SHARD_INDEX, SHARD_TOTAL)
    vlog(f"Shard {SHARD_INDEX}/{SHARD_TOTAL} processing {len(wallets)} wallet(s)")
    logging.info(f"Shard {SHARD_INDEX}/{SHARD_TOTAL} processing {len(wallets)} wallet(s)")
    st = load_state()
    for w in wallets:
        vlog("Processing wallet:", w)
        logging.info(f"Processing wallet: {w}")
        st = process_wallet(w, st)
        time.sleep(0.2)
    save_state(st)

if __name__ == "__main__":
    main()
