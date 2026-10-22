<p align="center">
  <img src="icons/icon-192.png" width="96" alt="Pane logo">
</p>

<h1 align="center">Pane</h1>

<p align="center">
  Notes, tasks, calendar and links on your own server.<br>
  Plain Markdown files, no database, no dependencies.
</p>

Pane is a self-hosted, installable web app with an Obsidian-like notes editor, a to-do list with reminders, a calendar that can feed your iPhone, a cheat sheet and a link collection. It feels native on iOS, Android and the desktop, and handles Persian and English text line by line, including right-to-left.

Everything is stored as ordinary files in one folder, so you can back it up with `cp`, sync it with Syncthing, or open it in any other editor.

## Features

- **Notes**: Markdown files in folders and multiple vaults. Each line detects Persian or English and switches direction automatically. Smart numbered lists, checkboxes, search, English and Persian spell-check.
- **Open existing folders**: import any folder on the server (for example an Obsidian vault synced by Syncthing) as a vault. Removing it from Pane never deletes your files.
- **Tasks**: due dates, reminders, repeating tasks that reappear when they are due, clear completed with one tap.
- **Calendar**: month, week, day and agenda views, categories, repeats, notifications, Gregorian or Persian calendar, a configurable first weekday, and a feed URL you can subscribe to from iPhone or any calendar app.
- **Links**: save links with previews. Grid, list and compact layouts, grouping by folder or site, tags, favourites.
- **Accounts**: several users on one server, optional two-factor authentication, lock screen.
- **Hot-keys, themes, accent colours and text size**, all in Settings.
- **Everywhere**: use it in a browser, add it to the iPhone/Android home screen, or install the desktop app.

## Quick start

You need a machine that stays on (a home server, a Raspberry Pi, a VPS). Pick one method.

### Docker (recommended)

```bash
git clone https://github.com/spidtzz/pane.git
cd pane
docker compose up -d
```

Open `http://<server-ip>:3000` and create your account. Your data lives in a Docker volume named `pane-data`.

Or run the prebuilt image:

```bash
docker run -d --name pane --restart unless-stopped \
  -p 3000:3000 -v pane-data:/data ghcr.io/spidtzz/pane:latest
```

### Linux service (no Docker)

Requires Node.js 18 or newer.

```bash
git clone https://github.com/spidtzz/pane.git
cd pane
sudo ./install.sh
```

This installs Pane to `/opt/pane`, keeps your data in `/var/lib/pane`, and starts a systemd service called `pane`. Run the script again after `git pull` to update. `sudo ./install.sh uninstall` removes the service and keeps your data.

### Just run it

```bash
git clone https://github.com/spidtzz/pane.git
cd pane
node server.js
```

There is nothing to install. Data goes to `./data`.

## Configuration

All settings are environment variables.

| Variable | Default | What it does |
| --- | --- | --- |
| `PORT` | `3000` | Port to listen on |
| `HOST` | `0.0.0.0` | Address to listen on (use `127.0.0.1` behind a reverse proxy) |
| `DATA` | `./data` | Where accounts and notes are stored |
| `SIGNUP` | `1` | Set to `0` to stop new accounts being created. Do this once you have made yours |
| `VAULT_ROOTS` | unset | Comma-separated folders. If set, only folders inside them can be imported as vaults |

With Docker, put them in a `.env` file (see `.env.example`). With systemd, edit `/etc/systemd/system/pane.service`.

## HTTPS and remote access

Pane serves plain HTTP. If you open it from outside your home network, put it behind HTTPS. Browsers also need HTTPS for notifications and for installing the app on a phone, except on `localhost`.

- [Caddy](deploy/Caddyfile.example): two lines, certificates are automatic.
- [nginx](deploy/nginx.conf.example): remember to forward `X-Forwarded-Proto`, which Pane uses to mark its login cookie `Secure`.
- Tailscale or WireGuard also work well if you only need access from your own devices.

Then set `SIGNUP=0` so strangers cannot create accounts.

## Install on your phone

Open your Pane address in Safari (iPhone) or Chrome (Android), then **Share → Add to Home Screen**. It opens full screen like a native app.

To get the calendar on your iPhone, open the calendar tab, choose **⋯ → Subscribe on iPhone** and follow the link.

## Desktop app

Desktop apps for macOS, Windows and Linux are a small window around your server. They do not contain your notes. Download one from the [Releases page](https://github.com/spidtzz/pane/releases), start it, and enter your server address.

| Platform | File |
| --- | --- |
| macOS | `.dmg` |
| Windows | `.exe` installer or portable |
| Linux | `.AppImage` or `.deb` |

The builds are not code-signed, so the first launch needs one extra step:

- **macOS**: right-click the app, choose **Open**, then confirm. If macOS says the app is damaged, run `xattr -dr com.apple.quarantine /Applications/Pane.app`.
- **Windows**: in the SmartScreen prompt choose **More info → Run anyway**.

Use **Server → Change server…** to connect to a different instance. To build it yourself, see [desktop/README.md](desktop/README.md).

## Troubleshooting

- **"Request failed" when creating an account (Docker)**: the data folder is not writable by the container. This happens if you mounted a host folder such as `./data` that Docker created as root. Fix it with `mkdir -p data && sudo chown -R 1000:1000 data && docker compose restart`, or use the default named volume. `docker logs pane` shows the exact error.

## Backups

You can copy the data folder while Pane runs (`/var/lib/pane` for the systemd install; with Docker run `docker cp pane:/data ./pane-backup`). Notes are plain `.md` files under `users/<name>/vaults/<vault>/notes/`. Accounts, tasks, events and links are small JSON files next to them.

## Security notes

- Passwords are hashed with a salt; sessions use an HTTP-only cookie.
- Turn on two-factor authentication from the profile menu → Settings → Security.
- Pane writes only inside its data folder, plus the notes of any folder you explicitly add as a vault.
- It has no outside dependencies, so there is no supply chain to audit beyond `server.js` and `index.html`.
- Please report security problems privately through GitHub's *Security → Report a vulnerability* instead of a public issue.

## Project layout

```
server.js       the whole server (Node 18+, no dependencies)
index.html      the whole app (HTML, CSS and JavaScript in one file)
dict/           English and Persian spell-check dictionaries
icons/          app icons
desktop/        Electron desktop client
deploy/         systemd unit and reverse-proxy examples
Dockerfile, docker-compose.yml, install.sh
```

## Contributing

Issues and pull requests are welcome. There is no build step: edit `server.js` or `index.html`, run `node server.js`, and reload.

## Credits and licences

Pane is released under the [MIT licence](LICENSE).

- English dictionary from [SCOWL](http://wordlist.sourceforge.net) and Persian dictionary from [Lilak](https://github.com/b00f/lilak), both via [wooorm/dictionaries](https://github.com/wooorm/dictionaries). Their licences are in [dict/LICENSES.txt](dict/LICENSES.txt).
- [Vazirmatn](https://github.com/rastikerdar/vazirmatn) (SIL Open Font License, see [dict/VAZIRMATN-OFL.txt](dict/VAZIRMATN-OFL.txt)) and [Space Grotesk](https://github.com/floriankarsten/space-grotesk) (SIL Open Font License) are embedded in the app.
