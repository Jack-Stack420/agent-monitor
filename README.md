# Agent Monitor

A small, self-hosted, read-only dashboard for your [OpenClaw](https://github.com/openclaw) agents. It shows which agents are working, what they did recently, how close you are to your usage limits, and raises alerts when something looks wrong. It runs on the machine that runs OpenClaw: no cloud service, no accounts, and no packages to install beyond Python itself.

Not affiliated with OpenClaw. Provided as-is, without warranty or guaranteed support.

## What it shows

- Which agents are working, recently active, or idle
- The current and last task per agent (optional, see Privacy)
- Usage limits against warn / alarm / critical thresholds, and credit balances
- Token usage and recent history
- Alerts, such as a stale collector, limits nearly reached, or low credits
- A login page protected by an owner password

The dashboard is read-only. It cannot start, stop, or change your agents.

## Requirements

- Linux with systemd user services and cron
- Python 3 (standard library only)
- OpenClaw installed, with the `openclaw` command available

Developed and tested on Ubuntu in a virtual machine. Other setups are untested.

## Install

These steps assume the folder lives at `~/agent-monitor`. If you put it elsewhere, adjust the paths in `agent-monitor-api.service` and `cron-entry.txt`.

1. Create your settings file and data folder:

        cd ~/agent-monitor
        cp config.example.json config.json
        mkdir -p data

2. Point the service and cron files at your home folder:

        sed -i "s|/home/youruser|$HOME|g" agent-monitor-api.service cron-entry.txt

3. Point the collector at your OpenClaw command:

        sed -i "s|--openclaw [^ ]*|--openclaw $(which openclaw)|" cron-entry.txt

4. Set the owner password. You type it in your own terminal (at least 14 characters), and it is stored locally under `data/auth`:

        python3 scripts/set_password.py

5. Start the collector, which runs once a minute from cron:

        (crontab -l 2>/dev/null; cat cron-entry.txt) | crontab -

6. Install and start the dashboard service:

        install -d -m 700 "$HOME/.config/systemd/user"
        install -m 644 agent-monitor-api.service "$HOME/.config/systemd/user/agent-monitor-api.service"
        systemctl --user daemon-reload
        systemctl --user enable --now agent-monitor-api.service

7. Open http://127.0.0.1:8787 in a browser on the same machine and log in. Give the collector a minute or two to gather its first data; until then you may see a "collector stale" tag.

## Viewing it from another device

By default the dashboard listens on `127.0.0.1` only, so it is reachable just from the machine it runs on. To open it from another computer on your home network:

1. In `config.json`, set `bind_address` to the machine's `192.168.x.x` address and add `ADDRESS:PORT` (for example `192.168.1.50:8787`) to `allowed_hosts`. If you change `port`, change the ports in `allowed_hosts` to match.
2. Restart the service: `systemctl --user restart agent-monitor-api.service`
3. Allow your network through the firewall (adjust the subnet to match yours):

        sudo ufw allow from 192.168.1.0/24 to any port 8787 proto tcp

Only `192.168.0.0/16` and `127.0.0.0/8` are accepted as bind addresses. Anything else, including `0.0.0.0`, IPv6, and Tailscale addresses, is rejected on purpose and falls back to `127.0.0.1`.

The dashboard uses plain HTTP. Use it on a network you trust, and never expose its port to the internet.

## Configuration

Settings live in `config.json` (copied from `config.example.json`).

| Setting | Meaning |
|---|---|
| `STORE_TASK_LABELS` | Store task titles so they can be shown. Set to `false` for stricter privacy. |
| `port` | Port the dashboard listens on (default 8787). |
| `stale_after_seconds` | How long without a collection before the collector is marked stale. |
| `thresholds` | Usage percentages for warn, alarm, and critical. Must increase, between 0 and 100. |
| `credit_alert_level` | Raise a credit alert at or below this level. |
| `credits_warn`, `credits_critical` | Credit levels for warning and critical status. |
| `agent_stale_minutes` | Optional stuck-agent alert. Off when `null`. |
| `agents` | Optional per-agent display overrides (see below). |
| `bind_address`, `allowed_hosts` | Network settings (see above). |

Display settings and `lexicon.json` are re-read on every request. Network settings (`port`, `bind_address`, `allowed_hosts`) are read at startup, so restart the service after changing them. The `listeners` and `proxy_allowed_hosts` options are for reverse-proxy setups and are not documented in this release.

### Agents

Agents appear automatically once OpenClaw lists them; no code change or restart is needed. To customize one, add an optional entry to `config.json`:

    "agents": {
      "scout": {
        "display_name": "Scout",
        "accent_color": "#34d399",
        "rank": "Navigator",
        "hidden": false
      }
    }

Every field is optional. Colors must be six-digit hex. `hidden: true` removes the agent from the dashboard.

### Changing the wording

`lexicon.json` holds every status name, heading, and label shown on the dashboard. Edit its values to retheme or translate the dashboard without touching code.

## Privacy and security

- Login is required, and the dashboard is read-only.
- Task labels can contain whatever your agents were asked to do. Set `STORE_TASK_LABELS` to `false` if that is a concern. Free text is sanitized before display, but secrets cannot be reliably detected, so keep them out of task titles.
- Your `config.json` and `data/` folder hold your own settings and activity. They are excluded by `.gitignore`; keep them out of anything you share.

## Tests

    cp config.example.json config.json
    python3 -m unittest discover -p 'test_*.py'

Expect 168 tests with 3 skipped; the skipped ones depend on private data that is not included. The `*.mjs` files are browser-based development checks. They are not needed to run the dashboard and have not been run for this release.

## Known limitations

- Linux only, tested on a single setup.
- Bind addresses are limited to `192.168.x.x` and `127.x.x.x`.
- Plain HTTP only; no built-in HTTPS.

## Credits

Fonts: Chakra Petch and Share Tech Mono, licensed under the SIL Open Font License. License files are in `web/fonts`.

## License

MIT. See `LICENSE`.
