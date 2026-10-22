const { contextBridge, ipcRenderer } = require('electron');
contextBridge.exposeInMainWorld('paneDesktop', {
  connect: v => ipcRenderer.invoke('connect', v),
  current: () => ipcRenderer.invoke('current')
});
