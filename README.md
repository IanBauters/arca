# Arca

A self-hosted software vault with an App Store–style interface. Arca keeps the installers, disk images and license keys for software you own, so an older version you paid for stays downloadable even after the vendor stops offering it.

- **Every version, side by side.** Each app holds any number of versions, each with its own files, release date, OS range and notes.
- **Plain folders on disk.** Files land in `library/<App>/<Version>/<file>` with an `_arca.json` next to them. If Arca ever disappears, File Station still shows you everything.
- **Encrypted license keys.** Serials and product keys are stored with AES-256-GCM and only shown when you reveal them.
- **Device compatibility.** Add the machines you still use (say, a Mac Pro 2013 on macOS 12.7.6) and Arca tells you which archived version of each app runs on them.
- **Bit-rot check.** Every file is fingerprinted with SHA-256 on upload. *Settings → Verify all checksums* re-reads the library and flags anything changed or missing.
- **No upload limit.** Files stream straight to disk, so a 60 GB sound library uploads as easily as a 30 MB utility.

## Run it on a Synology NAS (DS724+)

1. In **File Station**, create `docker/arca/data` and a shared folder for the installers, for example `Software/Arca`.
2. Open **Container Manager → Project → Create**. Name it `arca`, pick `/volume1/docker/arca` as the path, choose *Create docker-compose.yml* and paste [`docker-compose.yml`](docker-compose.yml).
3. Change `ARCA_PASSWORD` and the two volume paths, then **Next → Done**.
4. Open `http://<nas-ip>:8085`.

To update later: **Project → arca → Action → Build** (or *Pull* the image and restart).

### Where the image comes from

Pick one in `docker-compose.yml`:

| Option | Line in compose | How it works |
|---|---|---|
| Pre-built image (recommended) | `image: ghcr.io/ianbauters/arca:latest` | Every push to `main` triggers `.github/workflows/docker.yml`, which builds the image for amd64 and arm64 and publishes it to GitHub Container Registry. The NAS only pulls. |
| Build on the NAS | `build: https://github.com/IanBauters/arca.git#main` | Docker clones the repo and builds the Dockerfile on the NAS itself. |

If the repository is private, either make the package public under *GitHub → Packages → arca → Package settings*, or log in once on the NAS over SSH: `docker login ghcr.io -u IanBauters` with a personal access token that has `read:packages`.

## Publish to GitHub

```bash
cd arca
git init -b main
git add .
git commit -m "Arca 1.0"
gh repo create IanBauters/arca --private --source . --push
```

The first push starts the image build; watch it under the repository's **Actions** tab.

## Archiving Mac apps properly

Browsers can't upload a folder, and a `.app` is a folder. Do what Apple's own backup note recommends: select the app in Applications, choose **File → Compress**, and upload the resulting `.zip`. Finder's zip keeps the code signature and, for Mac App Store apps, the purchase receipt inside the bundle. To restore, unzip and drag the app back into Applications.

Arca is for software you own. Keep the purchase details in the license key fields, so you can always show where a copy came from.

## Backups

Back up **both** mounted folders, for example with Hyper Backup:

- `/library` — the installers. Large, rarely changes.
- `/data` — `arca.db` and `secret.key`. Small, but without `secret.key` (or your `ARCA_SECRET`) the stored license keys cannot be decrypted.

*Settings → Export catalog* downloads a JSON overview of every app, version and file (without keys).

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `ARCA_PASSWORD` | *(empty)* | Password for the web interface. If empty, anyone on the network can open Arca. |
| `ARCA_SECRET` | generated into `/data/secret.key` | Encrypts license keys and signs sessions. |
| `PORT` | `8080` | Port inside the container. |
| `DATA_DIR` | `/data` | Database, artwork, secret. |
| `LIBRARY_DIR` | `/library` | Uploaded files. |

Arca is meant for your LAN or a VPN such as Tailscale. Don't forward its port to the internet.

## Develop locally

Requires Node 22.13 or newer (Arca uses the built-in `node:sqlite`, so there are no native dependencies).

```bash
npm install
npm run dev     # http://localhost:8080, password "dev"
```

Opening `public/index.html` directly in a browser runs the interface on example data, without a server.
