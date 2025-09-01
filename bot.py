name: solana-multiwallet-alerts

on:
  schedule:
    - cron: "*/1 * * * *"   # runs every minute (UTC)
  workflow_dispatch: {}      # manual "Run workflow" button

permissions:
  contents: write            # needed to push state.json back to the repo

concurrency:
  group: solana-alerts
  cancel-in-progress: true

jobs:
  alerts:
    runs-on: ubuntu-latest

    steps:
      - name: Checkout repo
        uses: actions/checkout@v4
        with:
          persist-credentials: true   # keep GITHUB_TOKEN for push

      - name: Setup Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Install dependencies
        run: pip install "requests>=2.31,<2.33"

      # ✅ SAFE summary for multi-line vars (fixes your error)
      - name: Config summary (safe)
        env:
          WALLET_LIST: ${{ vars.WALLET_LIST }}
          AMM_PROGRAMS: ${{ vars.AMM_PROGRAMS }}
          SWAP_PROGRAMS: ${{ vars.SWAP_PROGRAMS }}
          LAUNCH_PROGRAMS: ${{ vars.LAUNCH_PROGRAMS }}
        run: |
          if [ -n "$WALLET_LIST" ]; then
            echo "Has WALLET_LIST: yes"
            echo "WALLET_LIST entries: $(printf '%s\n' "$WALLET_LIST" | sed '/^\s*$/d;/^\s*#/d' | wc -l)"
          else
            echo "Has WALLET_LIST: no"
          fi

          echo "AMM_PROGRAMS lines:  $(printf '%s\n' "$AMM_PROGRAMS"  | sed '/^\s*$/d;/^\s*#/d' | wc -l)"
          echo "SWAP_PROGRAMS lines: $(printf '%s\n' "$SWAP_PROGRAMS" | sed '/^\s*$/d;/^\s*#/d' | wc -l)"
          echo "LAUNCH_PROGRAMS lines: $(printf '%s\n' "$LAUNCH_PROGRAMS" | sed '/^\s*$/d;/^\s*#/d' | wc -l)"

      - name: Run bot
        env:
          # RPC
          RPC_HTTP: https://api.mainnet-beta.solana.com

          # Inputs (set in Settings → Secrets and variables → Actions)
          WALLET_LIST:  ${{ vars.WALLET_LIST }}     # one wallet per line
          AMM_PROGRAMS: ${{ vars.AMM_PROGRAMS }}    # one program id per line
          SWAP_PROGRAMS: ${{ vars.SWAP_PROGRAMS }}  # one program id per line
          LAUNCH_PROGRAMS: ${{ vars.LAUNCH_PROGRAMS }}

          # Alerts (Discord required; Telegram optional)
          DISCORD_WEBHOOK: ${{ secrets.DISCORD_WEBHOOK }}
          TG_TOKEN: ${{ secrets.TG_TOKEN }}
          TG_CHAT:  ${{ secrets.TG_CHAT }}

          # Connected-wallet scan knobs
          CONNECT_CHECKS_PER_RUN: "4"
          HISTORY_PAGES_PER_CONNECTED: "2"
          HISTORY_PAGE_LIMIT: "100"

          # Verbose logs for troubleshooting (turn to "0" later)
          VERBOSE: "1"
        run: python bot.py

      - name: Prepare Git for pushing state.json
        if: always()
        run: |
          git config --global --add safe.directory "$GITHUB_WORKSPACE"
          BRANCH="${GITHUB_REF_NAME:-$GITHUB_HEAD_REF}"
          git fetch origin "$BRANCH" || true
          git pull --rebase origin "$BRANCH" || true

      - name: Save state back to repo
        if: always()
        run: |
          if [ -f state.json ]; then
            git config user.name  "github-actions[bot]"
            git config user.email "41898282+github-actions[bot]@users.noreply.github.com"
            git add state.json
            git commit -m "chore: update state [skip ci]" || echo "No changes to commit"
            git push || echo "Push failed (branch protection or race); skipping"
          fi
