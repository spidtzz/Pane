# Pane desktop

An Electron window for a self-hosted Pane server. It stores only the server address and the window size.

## Run from source

```bash
cd desktop
npm install
npm start
```

## Build installers

```bash
npm run dist          # for the system you are on
npm run dist:mac      # .dmg and .zip (build on macOS)
npm run dist:win      # .exe installer and portable (build on Windows)
npm run dist:linux    # .AppImage and .deb
```

Output goes to `desktop/dist/`. GitHub Actions builds all three platforms when you push a tag such as `v1.0.0` (see `.github/workflows/desktop.yml`) and attaches the files to a release.

## How it behaves

- First launch asks for the server address and checks that it is really a Pane server.
- Links to other websites open in your normal browser.
- **Server → Change server…** switches instance; **Server → Open in browser** opens it in your browser.
- Only one window runs at a time.

Builds are unsigned. Signing needs an Apple Developer ID (macOS) and a code-signing certificate (Windows); electron-builder reads the standard `CSC_*` and `APPLE_*` environment variables if you add them to the workflow.
