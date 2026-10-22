// Pane desktop client: a thin window around a Pane server you host yourself.
const { app, BrowserWindow, Menu, shell, ipcMain, dialog, nativeTheme } = require('electron');
const path = require('path');
const fs = require('fs');

const CFG = () => path.join(app.getPath('userData'), 'config.json');
const load = () => { try { return JSON.parse(fs.readFileSync(CFG(), 'utf8')) } catch { return {} } };
const save = o => fs.writeFileSync(CFG(), JSON.stringify({ ...load(), ...o }));

let win;

// Normalise what the user typed: add https:// (http:// for local addresses), drop path and trailing slash.
function normalise(v) {
  v = String(v || '').trim();
  if (!v) return null;
  if (!/^https?:\/\//i.test(v)) v = (/^(localhost|127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|[^./]+(:\d+)?$)/.test(v) ? 'http://' : 'https://') + v;
  try { return new URL(v).origin } catch { return null }
}

// Make sure the address really is a Pane server before saving it.
async function probe(url) {
  const ctl = new AbortController(), t = setTimeout(() => ctl.abort(), 8000);
  try {
    const r = await fetch(url + '/manifest.json', { signal: ctl.signal });
    const j = await r.json();
    return j && j.name === 'Pane' ? null : 'That address answered, but it is not a Pane server.';
  } catch (e) {
    return e.name === 'AbortError' ? 'The server did not answer in time.' : 'Could not reach that address. Check it and your connection.';
  } finally { clearTimeout(t) }
}

function createWindow() {
  const b = load().bounds || {};
  win = new BrowserWindow({
    width: b.width || 1280, height: b.height || 820, x: b.x, y: b.y, minWidth: 380, minHeight: 520,
    title: 'Pane',
    backgroundColor: nativeTheme.shouldUseDarkColors ? '#0d1526' : '#f3f5fa',
    webPreferences: { preload: path.join(__dirname, 'preload.js'), contextIsolation: true, sandbox: true, nodeIntegration: false }
  });
  if (b.max) win.maximize();
  const keep = () => { if (!win.isMinimized() && !win.isMaximized()) save({ bounds: { ...win.getBounds(), max: false } }); else if (win.isMaximized()) save({ bounds: { ...(load().bounds || {}), max: true } }) };
  win.on('resize', keep); win.on('move', keep);

  // Links to other sites open in the normal browser; Pane itself stays in the window.
  const home = () => { try { return new URL(load().url).origin } catch { return null } };
  win.webContents.setWindowOpenHandler(({ url }) => {
    if (/^https?:/i.test(url)) shell.openExternal(url);
    return { action: 'deny' };
  });
  win.webContents.on('will-navigate', (e, url) => {
    if (url.startsWith('file:')) return;
    if (new URL(url).origin !== home()) { e.preventDefault(); if (/^https?:/i.test(url)) shell.openExternal(url) }
  });
  win.webContents.on('did-fail-load', (_e, code, desc, url, main) => {
    if (main && code !== -3 && !url.startsWith('file:')) win.loadFile(path.join(__dirname, 'connect.html'), { query: { err: 'offline', url: load().url } });
  });
  start();
}

function start() {
  const u = load().url;
  if (u) win.loadURL(u); else win.loadFile(path.join(__dirname, 'connect.html'));
}

ipcMain.handle('connect', async (_e, raw) => {
  const url = normalise(raw);
  if (!url) return 'Enter the address of your server, for example notes.example.com.';
  const err = await probe(url);
  if (err) return err;
  save({ url });
  win.loadURL(url);
  return null;
});
ipcMain.handle('current', () => load().url || '');

function menu() {
  const mac = process.platform === 'darwin';
  const t = [
    ...(mac ? [{ role: 'appMenu' }] : []),
    { label: 'Server', submenu: [
      { label: 'Change server…', click: () => win && win.loadFile(path.join(__dirname, 'connect.html')) },
      { label: 'Reload', accelerator: 'CmdOrCtrl+R', click: () => win && win.webContents.reload() },
      { label: 'Open in browser', click: () => { const u = load().url; if (u) shell.openExternal(u) } },
      ...(mac ? [] : [{ type: 'separator' }, { role: 'quit' }])
    ] },
    { role: 'editMenu' }, { role: 'viewMenu' }, { role: 'windowMenu' }
  ];
  Menu.setApplicationMenu(Menu.buildFromTemplate(t));
}

const one = app.requestSingleInstanceLock();
if (!one) app.quit();
else {
  app.on('second-instance', () => { if (win) { if (win.isMinimized()) win.restore(); win.focus() } });
  app.whenReady().then(() => {
    menu(); createWindow();
    app.on('activate', () => { if (!BrowserWindow.getAllWindows().length) createWindow() });
  });
  app.on('window-all-closed', () => { if (process.platform !== 'darwin') app.quit() });
}
