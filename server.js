// Pane server. Run: node server.js  (Node 18+, no dependencies)
// Env: PORT=3000 HOST=0.0.0.0 DATA=./data SIGNUP=0 (disable new accounts)
//      VAULT_ROOTS=/a,/b (optional: if set, only folders inside these can be opened as vaults)
// Data layout: DATA/users/<user>/user.json (account), app/*.json (todos, events, cats, cheat, links: shared by all vaults),
//              vaults/<vault>/**.md (notes only). Folder vaults are any server folder you add; Pane never writes to them except notes.
const http = require('http'), fs = require('fs'), fsp = fs.promises, path = require('path'), crypto = require('crypto'), dns = require('dns').promises, net = require('net');
const PORT = process.env.PORT || 3000, HOST = process.env.HOST || '0.0.0.0', DATA = path.resolve(process.env.DATA || './data'), SIGNUP = process.env.SIGNUP !== '0';
// S: login sessions (token -> {user, expiry}); F: failed-login counters per user; sha: sha256 hex helper.
const S = new Map(), F = {}, sha = s => crypto.createHash('sha256').update(s).digest('hex');
// True for safe names (user and vault names): letters, digits, - and _.
const ok = s => typeof s === 'string' && /^[\w-]{1,32}$/.test(s);
// U: user folder path; vdir: folder that holds a vault (external folder or vaults/<name>).
const U = u => `${DATA}/users/${u}`, vdir = (u, v, d) => d && d.ext && d.ext[v] ? d.ext[v] : `${U(u)}/vaults/${v}`;
// Read and parse a JSON file; null if missing or invalid.
const rj = async f => {
  try {
    return JSON.parse(await fsp.readFile(f, 'utf8'))
  } catch {
    return null
  }
};
// Password hash (scrypt) with a per-user salt.
const hp = (pw, salt) => crypto.scryptSync(String(pw), salt, 32).toString('hex');
// Stable secret token for calendar feed URLs, derived from the password hash.
const tok = (d, v) => sha(d.hash+v).slice(0, 32);
// Base32-encode bytes (for the 2FA setup key).
const b32 = buf => {
  let b = '', o = '';
  for (const x of buf) b += x.toString(2).padStart(8, '0');
  for (let i = 0;i+5 <= b.length;i += 5) o += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'[parseInt(b.slice(i, i+5), 2)];
  return o
};
// Decode a base32 string back to bytes.
const unb = s => {
  let b = '';
  for (const c of s) b += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'.indexOf(c).toString(2).padStart(5, '0');
  return Buffer.from(b.match(/.{8}/g).map(x => parseInt(x, 2)))
};
// 6-digit time-based one-time code (RFC 6238) for a secret at time t.
const totp = (sec, t) => {
  const c = Buffer.alloc(8);
  c.writeBigUInt64BE(BigInt(Math.floor(t/3e4)));
  const h = crypto.createHmac('sha1', unb(sec)).update(c).digest(), o = h[19]&15;
  return String((h.readUInt32BE(o)&0x7fffffff)%1e6).padStart(6, '0')
};
// Accept a 2FA code for the current 30 s window and its neighbours.
const okc = (sec, c) => [-1, 0, 1].some(d => totp(sec, Date.now()+d*3e4) === String(c).trim());
// Turn the internal "2FA" marker into a user-facing message.
const ve = e => e === '2FA' ? 'Enter your 6-digit code.' : e;

// Optional VAULT_ROOTS allow-list; when empty, any server folder can be opened.
const VR = () => (process.env.VAULT_ROOTS || '').split(',').map(x => x.trim()).filter(Boolean), inside = (p, x) => {
  try {
    const q = fs.realpathSync(x);
    return p === q || p.startsWith(q+path.sep)
  } catch {
    return false
  }
};
// Find to-do/calendar data left inside a vault by older versions (migration fallback).
async function legacy(u, d, n) {
  const c = [];
  try {
    for (const e of await fsp.readdir(U(u)+'/vaults', {withFileTypes: true})) if (e.isDirectory()) c.push(`${U(u)}/vaults/${e.name}/${n}.json`)
  } catch {}
  for (const k of Object.keys(d.ext || {})) c.push(`${d.ext[k]}/.pane/${n}.json`);
  for (const f of c) {
    try {
      return await fsp.readFile(f, 'utf8')
    } catch {}
  }
  return null
}
/** All vault names for a user: folders under vaults/ plus registered external folders. */
// All vault names for a user: internal vaults plus registered external folders.
async function vaultList(u, d) {
  const v = (await fsp.readdir(U(u)+'/vaults', {withFileTypes: true})).filter(e => e.isDirectory()).map(e => e.name).filter(n => !(d.ext && d.ext[n]));
  return[...v, ...Object.keys(d.ext || {})]
}
// Check username/password (+ 2FA code) with rate limiting; returns an error string or null.
async function verify(u, pw, code) {
  const d = ok(u) && await rj(U(u)+'/user.json'), f = F[u] || (F[u] = {n: 0, t: 0});
  if (f.n >= 8 && Date.now()-f.t < 6e5) return 'Too many attempts. Try again in a few minutes.';
  if (!d || !crypto.timingSafeEqual(Buffer.from(hp(pw || '', d.salt)), Buffer.from(d.hash))) {
    f.n++;
    f.t = Date.now();
    return 'Wrong username or password.'
  }
  if (d.totp && !okc(d.totp, code)) {
    if (code) {
      f.n++;
      f.t = Date.now();
      return 'Wrong code.'
    }
    return '2FA'
  }
  f.n = 0;
  return null
}

// Read a request body (max 20 MB).
const body = req => new Promise((r, j) => {
  const c = [];
  let n = 0;
  req.on('data', d => {
    n += d.length;
    if (n > 2e7) {
      req.destroy();
      j(0)
    } else c.push(d)
  });
  req.on('end', () => r(Buffer.concat(c).toString()))
});
// App icon: flat vermilion tile with three bold white panes.
const ICON = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><rect width="64" height="64" rx="16" fill="#ff5436"/><g transform="translate(0.0 0.0) scale(1)"><rect x="13" y="12" width="18" height="40" rx="5" fill="#fff"/><rect x="35" y="12" width="16" height="18" rx="5" fill="#fff"/><rect x="35" y="34" width="16" height="18" rx="5" fill="#fff"/></g></svg>';
// Built-in copies of the PNG icons, so the app icon works even if the icons/ folder is missing.
const ICONS = {
  'apple-touch-icon.png': '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',
  'icon-192.png': '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',
  'icon-512.png': 'iVBORw0KGgoAAAANSUhEUgAAAgAAAAIACAIAAAB7GkOtAAAQAElEQVR4nOzdedAcZZ3A8R9JgJAEEgIJcqiwAiL3GblxBWpVFEFhCQiCwoKL4AHIUYjLoq4LKiArHoAlHgjRKkB31VURV+4jASSgAio3gQQSrgRCru1GpbK6IGSmn56Z3+dTU2/lL0v6905/n366Z95hi/aaEADkMywASEkAAJISAICkBAAgKQEASEoAAJISAICkBAAgKQEASEoAAJISAICkBAAgKQEASEoAAJISAICkBAAgKQEASEoAAJISAICkBAAgKQEASEoAAJISAICkBAAgKQEASEoAAJISAICkBAAgKQEASEoAAJISAICkBAAgKQEASEoAAJISAICkBAAgKQEASEoAAJISAICkBAAgKQEASEoAAJISAICkBAAgKQEASEoAAJISAICkBAAgKQEASEoAAJISAICkBAAgKQEASEoAAJISAICkBAAgKQEASEoAAJISAICkBAAgKQEASEoAAJISAICkBAAgKQEASEoAAJISAICkBAAgKQEASEoAAJISAICkBAAgKQEASEoAAJISAICkBAAgKQEASEoAAJISAICkBAAgKQEASEoAAJISAICkBAAgKQEASEoAAJISAICkBAAgKQEASEoAAJISAICkBAAgKQEASEoAAJISAICkBAAgKQEASEoAAJISAICkBAAgKQEASEoAAJISAICkBAAgKQEASEoAAJISAICkBAAgKQEASEoAAJISAICkBKBvjVw+1l4/Vl4lVlolxo7706v696gVoo88/WQ89kjMnBGPTa9/zpwejz4Sv/t1zH4qMlt7g1hltRg7PlYaV/+sJzs+Vn5VtM68BstSi/aaEPSRNdaKLbavX6/fKIYMjYG0cEHcMTWmXFW/Hrg7klhuZGy6dT3ZzbaJFVaMPpJzXgNBAPrE+pvF1m+uzw7jV4tUpj9Un1au/Xn85pYYSNXqfttdYvPtY6MtYwAM/LwGiwD0vHU2iIOOinU3jOR++6v49hfjjltjYCw/Ot55QLz1H2OZZWPwDN68BpEA9LBqt2f/I+pVPy+oVpcXnB33/yH62vDlYvf94x37xfARMdgGY16DSwB6UnVrd+IHYoe3xJAhwV9YuDCu/O+YdE7MmBZ9Z9iw+Ie94l0H9dkufyf6el6DTgB6T7UjfPhJsezw4CXMfTa+9Mm45rLoI2NWio+dlnQ3rx/nlcDQk9dfPegR1Xr/gCPjwI/U60ReWnWIttm53ku59YboC9W9nJO/FGusGTn13bxyEICesdyIOOGMetuHl+/1G8fr3lBvNM+fF73szbvH0f9ef3QjuX6ZVxq2gHrDaq+JYz8Xq782WAIP3hunHRMP3Rc9qFr5HnJs7PzO4AW9PK9kXAH0gM23ixPPqj/zyZJZYUzstFvc97uYdn/0lGrTv5rsVjsGi+vZeeXjIZO2rfrq+PAnY8TIoBPVAfzQKfWFVO9Yaql4/9E+wPH/68F5pSQArar2/Y8/3dm/O0aOqrfReudg7nd4fduTF9Nr80pJANpTrRCP+oxFUDdVN1E+8qn6wLZu6zfHHu8NXlrvzCsr9wDac9BHY0fP/HRbtaW29DIx9cZo0Zrr1Bd2nuV9OXphXom5AmjJru+K3SYGTaiW3tvuEm2p7nAe93mf43sF2p1XbgLQhtFj4z0fDJpz6AkxZmy04oAP1d/kwSvS4rxyE4A27HlgfQeM5lSHd48Do7zXvM5H+ZZEW/NKTwCKG79q7Lpn0LTqIJf/2wkTD4uhA/pXeprWyrzSE4Di9v6nwfz+915THeS9D4mS1tskttopWDLl54UAlGaLoKTqUJdcVO77gaATheeFAJRmi6Ck6lDvd3iUscHmsf7mQSdKzovnCUBBtgjK227XeO3aUcA+hwWdKzYvnicABVUBoLwNm/9j68uNiLU3CLqiwLz4MwEoaLNtgvI2bf6wb75dLL100BWbepuUIwClVIvEdTYKyttgi8a/cczOXhcVmBd/JgClWCS2pTrsm20bzRk2rNn//WyanheLEYBSLBJb1OjBr/asrVi7y5ulFAEowiKxXdW2cnPfzTnB2arbGp0XixGAIsavbpHYppGj6hE0ZPU1g+5qdF4sRgCKWHGloF3NjWDcqkHXecsU4TqrCOeI1o1p7IQyxqmqAY5qEQJQhN/m1jU0ghGj6j9oRdd5yxQhAEX4bW5dQyMw2YY4sEUIQBF+m1vX0AhsVTfEW6YIASjCaaJ145u5DeM81ZDxbpuVIABFDF8uaNeyzYxghD/t2YxlvWVKEACApAQAICkBAEhKAACSEgCApAQAICkBAEhKAACSEgCApAQAICkBAEhKAACSEgCApAQAICkBAEhKAACSEgCApAQAICkBAEhKAACSEgCApAQAICkBAEhKAACSEgCApAQAICkBAEhKAACSEgCApAQAICkBAEhKAACSEgCApAQAICkBAEhKAACSEgCApAQAICkBAEhKAACSEgCApAQAICkBAEhKAACSEgCApAQAICkBAEhKAACSEgCApAQAICkBAEhKAACSEgCApAQAICkBAEhKAACSEgCApAQAOvD4zKAJM6cHzRMA6MDjjwVNcGCLEADogPNUQ1xaFSEA0AEBaMgsB7aEIQEssXnPxZyng65T1iIEADozfVrQdQJQhABAZ5yqmuCoFiEA0Jl77gy6a9ajMcN1VQkCAJ254ZdBd02+IihCAKAzd90WM2cEXaSppQgAdGzKlUG3zJkdt00OihAA6JgVaxfdfE3Mnx8UIQDQsWrFOtunAbrkRjUtRwCgY9WK9ZZrg87Nmxc3XR2UIgDQDd85OxYsCDr0wwvjmTlBKQIA3TB9Wlz+/aAT1e3fi78eFCQA0CWTzo3n5gZL7JLzLf8LEwDokidmxo8mBUtm+kPxw4uCsgQAuqdaw3ocaMl877z6q1UpSwCge6pd7Eu/EbxS9/0+rvhxUJwAQFf95wXxq+uDl2/us/GFk2LhwqA4AYCuWrAgPn983HtX8HJU5/2zPlFfAdAGAYBue2ZO/NtH48nHg7/pm1/wRRotEgBowMwZcerR9eYGL+GHF3nyp10CAM2487b4j5Ntbb+o6/8nvnFm0CoBgMZc/4v47HH1o0H8hat/FmeeGIsWBa0SAGjS5CvihPfVn3LijxYuiPPPjDM/7jufe4EAQMMeujeOOzBuvSF46on45JH1N77RGwQAmvf0k/HpD8dPL47MHrw3jn1v3DYl6BkCAEVUd4PPPTVOOSLjM+/PzI6LvhLHHhCPPhz0kmEBFDP1xjjmPfGm3WLiYTF2fAy8BQviskvju+f4VERvEgAoa9Gi+MV/1Y/BvH2/2OOAWG5kDKobr4hvnRXT7g96lQBAG56bW//xk8suib0PiR3fFiMGKwNTJ8ekr8Ydtwa9TQCgPdXGyNc+F+efEW/YLLbcoX6tsnr0qWfn1N+CN/nKmHJV/bQP/UAAoG3VRvltk+tXVYI11vpTCdbZMIb0wzMajz4SU66sz/vV/3+P9vcbAYBe8sDd9evSb9b/XnHlWH5MrDAmlh9d/xw1OoYOjXY9M7u+aqkW+PXP518+59zPBAB61axH6xc0RgAAkhIAgKQEACApAQBISgAAkhIAgKQEACApAQBISgAAkhIAgKQEACApAQBISgAAkhIAgKQEACApAQBISgAAkhIAgKQEACApAQBISgAAkhIAgKQEACApAQBISgAAkhIAgKQEACApAYAeNmJUjB0XK42PseNjxZVjWNtv2KeeiJnT47EZ9c+ZM4I+JwDQS1Z+VUzYKTbdOlZZvT7pD18uelmVgRkPxx23xk1Xx+03Bf1GAKBtQ4fGuhvFFtvXrzXWij4y9vlLk9dvHLvvH3Nmx6+uiylX1TGoLhToBwIA7Vl+dOxzWOzwlhgxMvpd9Z+wzc71qzJ1clxyfky9MehtAgBtqDb3375vvGO/GD4iBs9GW9avW2+IC86OP/w26FUCAGUts2y8bZ/Y470xcvkYbBtPiI22iusujwu/HNPuD3qPAEApQ4bGzrvHXgfXD/YksdRS9abQhDfF5T+I750Xsx4NesmQAAqotshPOD0OPT7R2f8F1V3uXfeMMybFepsEvUQAoHnjV4tPfa1+uDOzkaPiE2fHjm8NeoYAQMP+br34zNfj1X31fGdDll46jjw5Jh4W9AYBgCZV29+nfDVWGBO84N3vjyP+pf1PNeMmMDRokzfG0Z+JIZZZf2Wnt8WwpePMjwet8qsJzVj11XGUs/+L227X+llYWuW3Exqw3Ig4/vRB+Hxvo/b959h2l6A9AgDdNnRovfZf7TXBS6sujw4/KdZcN2iJAEC3HXxM9ic+X75lh8dxn3OTvC0CAF218YTY9V3By7fyKvH+Y4I2CAB0T7WncdBRwStV3RBeZ4OgOAGA7tl5Dx/4WkLC2QYBgC4ZPiL2OTRYMutuWF8HUJYAQJe8+30xesVgib3ng/WnwyhIAKAbqjuZu00MOjFu1fqP5FCQAEA37H9kLL1M0KE9D/JIaEkCAB0bNiw22zbo3IiR9R8RoxQBgI5tuKVvfeiarXYKShEA6NgE56zu2XQb3xRdjABAx7bcMeiWkaPqKyqKEADozJrrxIorB13kiqoUl1rQmWrLgu5ySEtxBQCdWXfDoLvGrRpjxgbNEwDozJiVgq5zVIsQAOiMU1UTHNUi3AOADgwZGmPHBV0nAEUIAHRghdEx1JuoAeNXC5rndxc6YKHaEDeBixAA6MA4C9VmKGsRAgAdcJ5qiANbhABAJxYFTajurtM8AQBISgAAkhIAgKQEACApAQBISgAAkhIAgKQEACApAQBISgAAkhIAgKQEACApAQBISgAAkhIAgKQEACApAQBISgAAkhIAgKQEACApAQBISgAAkhIAgKQEACApAQBISgAAkhIAgKQEACApAQBISgAAkhIAgKQEACApAQBISgAAkhIAgKQEACApAQBISgAAkhIAgKQEACApAQBISgAAkhIAgKQEACApAQBISgAAkhIAgKQEACApAQBISgAAkhIAgKQEACApAQBISgAAkhIAgKQEACApASji2WeCds1tZgRzng6aMNdbpgQBKGLWY0G7GhrB4ybbDG+ZIgSgCKeJ1jU0AuephnjLFCEARfhtbt2MadEEk21IQ/Pi/xoSFOA00bqGRlDdA5j3XNB13jJFCEARfptb19wIDLcJjmoRAlCE3+bWzRKAvuLmShECUMQDd8dszwu2Z87smP5gNOSeO4PuanReLEYAipg/P265NmjLzdfUI2jIDb8MuqvRebEYASjlRqeJ9jR68G+b7PKuy7xZShGAUqpFzbx5QXnVYb/p6miOy7vuanpeLEYASqm2Ne+aGpR3+5R4Zk40yoq1iwrMiz8TgIJutk5sQ4Hlucu7LnI5VZAAFORuYSsKdNflXRdZJxUkAAU9dG9c/bOgpOqAV4e9gO+eG3Su2Lx4ngCU9Z2zY8GCoIzqUF9wdpRx+01xy3VBJ0rOi+cJQFnTp8Xl3w/Kf/ruWAAABJNJREFUqA51ye8U+9ZZQScKzwsBaMGkc+O5uUHTqoN80TlR0n2/t8W35MrPCwFowRMz40eTgqZVB/nJWVGYLb4l1sq80hOANlxyvs+ONquq7MVfj/Js8S2ZtuaVngC0Yc7sOO/UoDnnfba1DxN9+4vx4D3BK9LivHITgJZc9dO49JtBE6oDe93l0Zaq7qcd6wrvFWh3XrkJQHu+86WY4jtPuu3an9cHtl0P3RtnnRQLFwZ/Uy/MKzEBaM+iRfVpwnZBF919Z3zxX+sD27qbrokLvxy8tN6ZV1YC0CrbBV30xKw49egeesS22tm48ifBi+m1eaUkAG2zXdAV8+fHZ4+Nx6ZHT/nKp+MPvw3+Wm/OKx8B6AHVdsFHJ8b0h4IlM2NaHL1v3HFr9JpqeXviwfHTi4PF9ey88hl68vqrB6176om44sfxd+vFKsbxCk2dHKcc0btryera7qar6z8cv+k2McR6q+fnlYwA9IxqtXjVT2L02HjdG4KX6effjzNOjLnPRo+rNoKqBe/m28WywyOzfplXGkst2mtC0FN23TMO/lgMHRq8hHnz4rzT4vIfRB8Zt2qceGasvmYk1I/zSkAAetIaa8U+h8Yb/z6WWir4C4sWxfW/iEnnxAN3R99ZZtnYbWK884AYuXwk0dfzGnQC0MPWXDcmfiC22C54QbWffuFX4p47o6+NGBXv2C/evm8MHxGDbTDmNbgEoOets0EcdFSsu2Ekd+dtcf7pcdftMTCWHx17H1Lv+A1bOgbP4M1rEAlAn1h/s9h2l9hih1h5lUjl0UdiypVxzWXx65tjIK00vp7sljvE+pvHABj4eQ0WAeg3r10nttw+ttyxflhoUO8QVLvGv/9NTL6yPpXcc1ckUd0VqDKw1Y6xyRv7bGso57wGggD0rWrf4FVr1A+WjF/1+Z+r/enfK6wYfeTJWfV36M+YVn8Orvo54+H6Hw8/EPPnRVpV16vLgsVn+sd/jx0fw4ZFu8xrsAgAQFJtLygAaIkAACQlAABJCQBAUgIAkJQAACQlAABJCQBAUgIAkJQAACQlAABJCQBAUgIAkJQAACQlAABJCQBAUgIAkJQAACQlAABJCQBAUgIAkJQAACQlAABJCQBAUgIAkJQAACQlAABJCQBAUgIAkJQAACQlAABJCQBAUgIAkJQAACQlAABJCQBAUgIAkJQAACQlAABJCQBAUgIAkJQAACQlAABJCQBAUgIAkJQAACQlAABJCQBAUgIAkJQAACQlAABJCQBAUgIAkJQAACQlAABJCQBAUgIAkJQAACQlAABJCQBAUgIAkJQAACQlAABJCQBAUgIAkJQAACQlAABJCQBAUgIAkJQAACQlAABJCQBAUgIAkJQAACQlAABJCQBAUgIAkJQAACQlAABJCQBAUgIAkJQAACQlAABJCQBAUgIAkJQAACQlAABJCQBAUgIAkJQAACQlAABJCQBAUgIAkJQAACQlAABJCQBAUgIAkJQAACQlAABJCQBAUgIAkJQAACQlAABJCQBAUgIAkJQAACQlAABJCQBAUgIAkJQAACQlAABJ/S8AAAD//0TLLsQAAAAGSURBVAMA+jhfVCTk/fMAAAAASUVORK5CYII=',
  'icon-maskable-512.png': 'iVBORw0KGgoAAAANSUhEUgAAAgAAAAIACAIAAAB7GkOtAAAQAElEQVR4nOzdedBdZX3A8V8WAiEkJIEAAYGggAgBAiQxiKgFcYGiQlNZVMRBrba1onbStFrFuo0W6GjdFa1YBEVRq6iAGwJGgRAkLBKgsijBLCQsiRBC3p4LShES8t71fc79fT5z5x3Hv5jfzX2+9zzn3HNGDsyeGQDkMzIASEkAAJISAICkBAAgKQEASEoAAJISAICkBAAgKQEASEoAAJISAICkBAAgKQEASEoAAJISAICkBAAgKQEASEoAAJISAICkBAAgKQEASEoAAJISAICkBAAgKQEASEoAAJISAICkBAAgKQEASEoAAJISAICkBAAgKQEASEoAAJISAICkBAAgKQEASEoAAJISAICkBAAgKQEASEoAAJISAICkBAAgKQEASEoAAJISAICkBAAgKQEASEoAAJISAICkBAAgKQEASEoAAJISAICkBAAgKQEASEoAAJISAICkBAAgKQEASEoAAJISAICkBAAgKQEASEoAAJISAICkBAAgKQEASEoAAJISAICkBAAgKQEASEoAAJISAICkBAAgKQEASEoAAJISAICkBAAgKQEASEoAAJISAICkBAAgKQEASEoAAJISAICkBAAgKQEASEoAAJISAICkBAAgKQEASEoAAJISAICkBAAgKQEASEoAAJISAICkBAAgKQEASEoAAJISAICkBAAgKQEASEoAAJISAICkBAAgKQEASEoAAJISAICkBAAgKQEASEoAAJISAICkBAAgKQEASEoAAJISAICkBAAgKQEASEoAAJISAICkBAAgKQEASEoAAJISAICkBKCv7X9Q7LFPbDkxxo6PLSc0/o4bH2PGRrFW3Rf3rox7Vzzyd2WsXB43LIhf/TL62GajY+YLYspuMa56g7ZsvEGP/o/RY6L3Es4/t2EDs2cG/WTEiNh3Vhx4aMx4XtFr/eBVK9HlP415P4prr4x166I/VOt+9QZVb1P1Zo3aNErWl/PnEQLQR562Sxx5fMw6NDYfii+PPXD/vY1l6DtnxeI7or72nhEvfWVj9a+d/pg/jyMAfWHrbePYN8XBL4nhw6PvPfxw/Pjbce4ZsWJZ1MuU3ePEk2OvA6LW6jt/nkQAaq7aLJ59Urzo6Bi5SaSy5sE4/5z49pcb29bl2+5pcfzfxqxDYtiw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AICk/KAUICkBAEhKAACSEgCApAQAICkBAEhKAACSEgCApAQAICkBAEhKAACSEgCApAQAICkBAEhKAACSEgCApAQAICkBAEhKAACSEgCApAQAICkBAEhKAACSEgCApAQAICkBAEhKAACSEgCApAQAICkBAEhKAACSEgCApAQAICkBAEhKAACSEgCApAQAICkBAEhKAACSEgCApAQAICkBAEhKAACSEgCApAQAICkBAEhKAACSEgCApAQAICkBAEhKAACSEgCApAQAICkBAEhKAACSEgCApAQAICkBAEhKAACSEgCApAQAICkBAEhKAACSEgCApAQAICkBAEhKAACSEgCApAQAICkBAEhKAACSEgCApAQAICkBAEhKAACSEgCApAQAICkBAEhKAACSEgCApAQAICkBAEhKAACSEgCApAQAICkBAEhKAACSEgCApAQAICkBAEhKAACSEgCApAQAICkBAEhKAACSEgCApAQAICkBAEhKAACSEgCApAQAICkBAEhKAACSEgCApAQAICkBAEhKAACSEgCApAQAICkBAEhKAACSEgCApAQAICkBAEhKAACSEgCApAQAICkBAEhKAACSEgCApAQAICkBAEhKAACSEgCApAQAICkBAEhKAACS+j8AAAD//z80TZ0AAAAGSURBVAMAFDzl1ObfpjYAAAAASUVORK5CYII=',
  'favicon-32.png': 'iVBORw0KGgoAAAANSUhEUgAAAEAAAABACAYAAACqaXHeAAAEJklEQVR4nOybW2wNaxTH/2u6z+agznH0UOEBoXUJiaAiXsSTa1PXiLg+ITx6cQuJy6t4kFTEJSIidkrtEi+IJ1TtCA1B3CJEad2Kql2dZX2tXcW+dL5pprNn5pfM7G9mvrWS9d8z33yzZlYIFuB5E4pBtFCao2XJk3ae/P6NroS5AYQ6sCzAXVlOUllVRUfNKVMHnjWmD7p33yTBrpHNXsgK+IMIcgCNjbvpXPW7dD1TCsALR4Vh9lovPbbIZh9kJ+9EiB0wPu2jyN14sg5JBeDiwlyE/ymX5jR4gzOIf1hG0fsffz/whwA8t6gAORyVQ4XwEsz3YHAJRW7cb7/7FwEk+L4wcFX2DocXYX6AuDmFKmJ1iV1G27GpU0Pyz1d4NngFUQHCRnlLrD9oEwB9P2+QHpPhdYimtMb6Y1OteM74PIRzHstWLvxBPahpGEVu1raeAd1ydvooeEVv8F87VIN4xqTe6GnWSjMMP8H8FQ1GvxB68DTfBa8g6qZiD8mpPx26jJMxc7HMkPsPBHpmuII+yxzk1QvgRClw86p9v1b8pUJiJ55fdE0akywZGjJ0LF4NlKxQSloylVMPOHVYHlkOAKZp3286fxltUakGwXxYZeQ4YO5K68ErlI2yHT2+c/ym85eZfBGArQtQshy2UP908dLO85vKX0Y4P9QyGFhlcAFsk8yHHb86thJ7CDr8+x9sk8yHHb+atnoCeIhAAPicQAD4nEAA+BwDbuL9W2ijaesuAZ4+gDaatu4SIHoMWqinwPKj0MFdAlRXAedOwDJlh4A7MejgvkHwyB7ggryUmr0EGDsR+H9A8n61L4HbItjZ48DzJ9DFnXcBFVDpLjhBMA+AzwkEgBtxKisMt90GVW5vyVpgo9wJho5In2pXx1Qf1Vdlkg29UNwlgPNZYZcJ4HhW2G1jgNNZYbhNgCAr7DyBAPA5gQDwOYEA8Dl6M0E72dt0ProkK6y+lrKKnextOh9OZ4UldjkDqAZW0c3eJkiVxXU8K0w16hKwLoBu9jZBqiyu81nhGuIFRZJRwGroMGhI5uxtAitZ3I747Zys8H71mVwJCKfhR5p5hoEGuqQ1EGY9HMcz86JB5yvrJatyBL6DDlMs1tQ6D4jTNlk3wj80gpq2qkaLABStfCWXwX74BdPcq2oFVPPnTLCpfisYt+F1GNfwtm57YrNNgJaSMuPrTOnwHN7lIUzMpstP2y73X54FKHLrBYzmmVAlJZ6D6/CteTqdvv6m/d4/HoYoEqsG5QyRMeEKvALzBVCokMpjj34/lLp0Vokzr2iVrNV76v7IRhivZbUFZVUHJdCkxQSZi6dVGW0od7O8fFiHbCqeNrkU3z7uSlYu2x5LFQ88f+Ic+VkkyyixzBOFVQl9D3QtX+QUV5Wgarkj7QiduhHtqPF3AAAA//9erXYmAAAABklEQVQDALtoaJKJ8CuqAAAAAElFTkSuQmCC'
};
// Send a response with no-store caching.
const send = (res, c, b, t = 'application/json') => {
  res.writeHead(c, {'content-type': t+'; charset=utf-8', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff'});
  res.end(typeof b === 'string' ? b : JSON.stringify(b))
};
// Resolve a request path inside a vault; rejects dot-folders (except .pane), "\" and NULs.
const fp = (base, p) => {
  const x = String(p || '').split('/').filter(Boolean);
  if (!x.length || x.some((s, i) => (s.startsWith('.') && !(i == 0 && s == '.pane')) || s.includes('\0') || s.includes('\\'))) throw 0;
  return path.join(base, ...x)
};
// List files and folders in a vault recursively (path, isDir, mtime, size).
async function walk(b, d = '') {
  let o = [];
  for (const e of await fsp.readdir(path.join(b, d), {withFileTypes: true})) {
    if (e.name.startsWith('.')) continue;
    const p = d ? d+'/'+e.name : e.name, st = await fsp.stat(path.join(b, p));
    o.push({p, d: e.isDirectory(), m: st.mtimeMs, s: st.size});
    if (e.isDirectory()) o = o.concat(await walk(b, p))
  }
  return o
}

// Build an iCalendar (.ics) feed from events, including repeats and alarms.
const ics = (evs, name) => {
  const d = s => (s.replace(/[-:]/g, '')+'00').slice(0, 15), esc = s => String(s || '').replace(/[\\;,]/g, '\\$&').replace(/\n/g, '\\n'), day = s => s.slice(0, 10).replace(/-/g, '');
  const L = ['BEGIN:VCALENDAR', 'VERSION:2.0', 'PRODID:-//Pane//EN', 'CALSCALE:GREGORIAN', 'X-WR-CALNAME:'+esc(name), 'REFRESH-INTERVAL;VALUE=DURATION:PT15M', 'X-PUBLISHED-TTL:PT15M'];
  for (const e of evs) {
    const ee = e.e || e.s;
    L.push('BEGIN:VEVENT', 'UID:'+e.id+'@pane', 'DTSTAMP:'+d(new Date().toISOString())+'Z');
    if (e.ad) {
      const n = new Date(ee.slice(0, 10)+'T00:00:00Z');
      n.setUTCDate(n.getUTCDate()+1);
      L.push('DTSTART;VALUE=DATE:'+day(e.s), 'DTEND;VALUE=DATE:'+day(n.toISOString()))
    } else L.push('DTSTART:'+d(e.s), 'DTEND:'+d(ee));
    L.push('SUMMARY:'+esc(e.t));
    if (e.n) L.push('DESCRIPTION:'+esc(e.n));
    if (e.l) L.push('LOCATION:'+esc(e.l));
    if (e.rep) L.push('RRULE:FREQ='+{d: 'DAILY', w: 'WEEKLY', m: 'MONTHLY', y: 'YEARLY'}[e.rep]+';INTERVAL='+(+e.int || 1));
    if (e.al) L.push('BEGIN:VALARM', 'ACTION:DISPLAY', 'DESCRIPTION:'+esc(e.t), e.al === 'e' ? 'TRIGGER;RELATED=END:PT0S' : 'TRIGGER:'+(e.al === 's0' ? 'PT0S' : '-PT'+e.al.slice(1)+'M'), 'END:VALARM');
    L.push('END:VEVENT')
  }
  L.push('END:VCALENDAR');
  return L.join('\r\n')
};

// True for private/loopback addresses (blocks link previews of internal hosts).
const priv = a => net.isIPv4(a) ? /^(10\.|127\.|0\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(a) : /^(::1|::$|fe80|fc|fd|::ffff)/i.test(a);
// Fetch title, description and image of a URL for the Links module (SSRF-safe, 6 s timeout).
async function preview(u) {
  try {
    let x = new URL(u), r;
    for (let i = 0;i < 4;i++) {
      if (!/^https?:$/.test(x.protocol) || (await dns.lookup(x.hostname, {all: true})).some(a => priv(a.address))) return {};
      r = await fetch(x, {redirect: 'manual', signal: AbortSignal.timeout(6000), headers: {'user-agent': 'Mozilla/5.0 (PanePreview)'}});
      if (r.status > 299 && r.status < 400 && r.headers.get('location')) x = new URL(r.headers.get('location'), x);
      else break
    }
    const h = (await r.text()).slice(0, 3e5);
    const m = n => {
      const a = h.match(new RegExp(`<meta[^>]+(?:property|name)=["']${n}["'][^>]*content=["']([^"']*)["']`, 'i')) || h.match(new RegExp(`<meta[^>]+content=["']([^"']*)["'][^>]*(?:property|name)=["']${n}["']`, 'i'));
      return a && a[1]
    };
    const t = (h.match(/<title[^>]*>([^<]*)/i) || [])[1], img = m('og:image');
    return {t: (m('og:title') || t || '').trim(), d: (m('og:description') || m('description') || '').trim(), i: img ? new URL(img, x).href : '', h: x.hostname}
  } catch {
    return {}
  }
}

http.createServer(async(req, res) => {
  try {
    const u = new URL(req.url, 'http://x'), P = u.pathname, q = u.searchParams, M = req.method;
    if (M === 'GET' && (P === '/' || P === '/index.html')) return send(res, 200, await fsp.readFile(path.join(__dirname, 'index.html'), 'utf8'), 'text/html');
    if (P === '/manifest.json') return send(res, 200, {name: 'Pane', short_name: 'Pane', start_url: '/', scope: '/', display: 'standalone', background_color: '#ff5436', theme_color: '#ff5436', icons: [{src: '/icons/v5/icon-192.png', sizes: '192x192', type: 'image/png', purpose: 'any'}, {src: '/icons/v5/icon-512.png', sizes: '512x512', type: 'image/png', purpose: 'any'}, {src: '/icons/v5/icon-maskable-512.png', sizes: '512x512', type: 'image/png', purpose: 'maskable'}, {src: '/icon.svg', sizes: 'any', type: 'image/svg+xml', purpose: 'any'}]}, 'application/manifest+json');
    {
      const mi = M === 'GET' && /^\/(?:icons\/(?:v\d+\/)?([\w-]+\.png)|(apple-touch-icon(?:-precomposed)?\.png)|favicon\.ico)$/.exec(P);
      if (mi) {
        const n = mi[1] || (mi[2] ? 'apple-touch-icon.png' : 'favicon-32.png');
        let b;
        b = ICONS[n] ? Buffer.from(ICONS[n], 'base64') : null;
        if (!b) try { b = await fsp.readFile(path.join(__dirname, 'icons', n)) } catch {}
        if (!b) return send(res, 404, {error: 'Not found'});
        res.writeHead(200, {'content-type': 'image/png', 'cache-control': 'no-cache', 'x-content-type-options': 'nosniff'});
        return res.end(b)
      }
    }
    if (P === '/icon.svg') return send(res, 200, ICON, 'image/svg+xml');
    if (M === 'GET' && /^\/dict\/(en|fa)\.(aff|dic)$/.test(P)) {
      const b = await fsp.readFile(path.join(__dirname, 'dict', P.slice(6)));
      const gz = /\bgzip\b/.test(req.headers['accept-encoding'] || '');
      res.writeHead(200, Object.assign({'content-type': 'text/plain; charset=utf-8', 'cache-control': 'public, max-age=604800', 'x-content-type-options': 'nosniff', vary: 'accept-encoding'}, gz ? {'content-encoding': 'gzip'} : {}));
      return res.end(gz ? require('zlib').gzipSync(b) : b)
    }
    const fm = P.match(/^\/cal\/([\w-]+)\/(?:([\w-]+)\/)?(\w+)\.ics$/);
    if (fm) {
      const d = ok(fm[1]) && await rj(U(fm[1])+'/user.json');
      if (!d || tok(d, fm[2] || 'all') !== fm[3]) return send(res, 404, 'Not found', 'text/plain');
      let t = null;
      try {
        t = await fsp.readFile(`${U(fm[1])}/app/events.json`, 'utf8')
      } catch {}
      if (t == null) t = await legacy(fm[1], d, 'events');
      let ev = [];
      try {
        ev = JSON.parse(t) || []
      } catch {}
      return send(res, 200, ics(ev, 'Pane'), 'text/calendar')
    }
    if (!P.startsWith('/api/')) return send(res, 404, {error: 'Not found'});
    const ck = Object.fromEntries((req.headers.cookie || '').split(';').map(c => c.trim().split('='))), sec = req.headers['x-forwarded-proto'] === 'https' ? '; Secure' : '';
    const b = M === 'GET' || M === 'DELETE' ? '' : await body(req), J = () => {
      try {
        return JSON.parse(b || '{}')
      } catch {
        return {}
      }
    };
    if (M === 'POST' && P === '/api/register') {
      if (!SIGNUP) return send(res, 403, {error: 'Sign-ups are disabled on this server.'});
      const {user, pw} = J();
      if (!ok(user) || String(pw || '').length < 8) return send(res, 400, {error: 'Username: letters, numbers, - and _. Password: at least 8 characters.'});
      if (fs.existsSync(U(user))) return send(res, 409, {error: 'That username is taken.'});
      const salt = crypto.randomBytes(16).toString('hex');
      await fsp.mkdir(vdir(user, 'Personal')+'/notes', {recursive: true});
      await fsp.writeFile(U(user)+'/user.json', JSON.stringify({salt, hash: hp(pw, salt), totp: null}));
      return send(res, 200, {ok: 1})
    }
    if (M === 'POST' && P === '/api/login') {
      const {user, pw, code, remember} = J(), e = await verify(user, pw, code);
      if (e) return send(res, 401, {error: ve(e), need2fa: e === '2FA'});
      const t = crypto.randomBytes(32).toString('hex');
      S.set(t, {u: user, exp: Date.now()+(remember ? 30*864e5 : 12*36e5)});
      res.setHeader('set-cookie', `s=${t}; HttpOnly; SameSite=Strict; Path=/${remember?'; Max-Age='+30*86400:''}${sec}`);
      return send(res, 200, {ok: 1})
    }
    const s = S.get(ck.s), me = s && s.exp > Date.now() ? s.u : null, ud = me && await rj(U(me)+'/user.json');
    if (!ud) return send(res, 401, {error: 'Sign in required.'});
    if (P === '/api/logout') {
      S.delete(ck.s);
      res.setHeader('set-cookie', 's=; Max-Age=0; Path=/');
      return send(res, 200, {ok: 1})
    }
    if (P === '/api/unlock') {
      const {pw, code} = J(), e = await verify(me, pw, code);
      return e ? send(res, 401, {error: ve(e), need2fa: e === '2FA'}) : send(res, 200, {ok: 1})
    }
    if (P === '/api/me') return send(res, 200, {user: me, display: ud.display || '', avatar: ud.avatar || '', vaults: await vaultList(me, ud), ext: Object.fromEntries(Object.keys(ud.ext || {}).map(k => [k, ud.ext[k]])), totp: !!ud.totp, prefs: ud.prefs || {}});
    if (P === '/api/vault') {
      const n = J().name;
      if (!ok(n)) return send(res, 400, {error: 'Use letters, numbers, - and _.'});
      if (fs.existsSync(vdir(me, n, ud))) return send(res, 409, {error: 'That vault already exists.'});
      await fsp.mkdir(vdir(me, n)+'/notes', {recursive: true});
      return send(res, 200, {ok: 1})
    }
    if (P === '/api/2fa/setup') {
      ud.pending = b32(crypto.randomBytes(10));
      await fsp.writeFile(U(me)+'/user.json', JSON.stringify(ud));
      return send(res, 200, {secret: ud.pending})
    }
    if (P === '/api/2fa/enable') {
      if (!ud.pending || !okc(ud.pending, J().code)) return send(res, 400, {error: 'That code is not right. Try the next one.'});
      ud.totp = ud.pending;
      delete ud.pending;
      await fsp.writeFile(U(me)+'/user.json', JSON.stringify(ud));
      return send(res, 200, {ok: 1})
    }
    if (P === '/api/2fa/off') {
      const {pw, code} = J(), e = await verify(me, pw, code);
      if (e) return send(res, 401, {error: ve(e)});
      ud.totp = null;
      await fsp.writeFile(U(me)+'/user.json', JSON.stringify(ud));
      return send(res, 200, {ok: 1})
    }
    if (P === '/api/profile') {
      const j = J();
      if (j.display !== undefined) ud.display = String(j.display).trim().slice(0, 40);
      if (j.avatar !== undefined) {
        if (!j.avatar) delete ud.avatar;
        else if (typeof j.avatar === 'string' && j.avatar.length < 4e5 && /^data:image\/(jpeg|png|webp);base64,[A-Za-z0-9+\/=]+$/.test(j.avatar)) ud.avatar = j.avatar;
        else return send(res, 400, {error: 'That picture is not supported.'})
      }
      if (j.prefs && typeof j.prefs === 'object') {
        ud.prefs = ud.prefs || {};
        if (j.prefs.ccal === 'g' || j.prefs.ccal === 'p') ud.prefs.ccal = j.prefs.ccal;
        if (Number.isInteger(j.prefs.cws) && j.prefs.cws >= 0 && j.prefs.cws <= 6) ud.prefs.cws = j.prefs.cws
      }
      await fsp.writeFile(U(me)+'/user.json', JSON.stringify(ud));
      return send(res, 200, {display: ud.display || '', avatar: ud.avatar || '', prefs: ud.prefs || {}})
    }
    if (P === '/api/vault/rename') {
      const {name, to} = J();
      if (!ok(to)) return send(res, 400, {error: 'Use letters, numbers, - and _.'});
      const ext = ud.ext && ud.ext[name];
      if (!ext && !(ok(name) && fs.existsSync(vdir(me, name)))) return send(res, 404, {error: 'Vault not found.'});
      if (fs.existsSync(vdir(me, to, ud))) return send(res, 409, {error: 'That name is already used.'});
      if (ext) {
        const e = {};
        for (const k in ud.ext) e[k === name ? to : k] = ud.ext[k];
        ud.ext = e;
        await fsp.writeFile(U(me)+'/user.json', JSON.stringify(ud))
      } else await fsp.rename(vdir(me, name), vdir(me, to));
      return send(res, 200, {ok: 1})
    }
    if (P === '/api/vault/delete') {
      const n = J().name;
      if (ud.ext && ud.ext[n]) return send(res, 400, {error: 'Folder vaults are removed, not deleted.'});
      if (!ok(n) || !fs.existsSync(vdir(me, n))) return send(res, 404, {error: 'Vault not found.'});
      if ((await vaultList(me, ud)).length < 2) return send(res, 400, {error: 'Keep at least one vault.'});
      await fsp.rm(vdir(me, n), {recursive: true, force: true});
      return send(res, 200, {ok: 1})
    }
    const dm = P.match(/^\/api\/data\/(todos|events|cats|cheat|links)$/);
    if (dm) {
      const f = `${U(me)}/app/${dm[1]}.json`;
      if (M === 'GET') {
        let t = null;
        try {
          t = await fsp.readFile(f, 'utf8')
        } catch {}
        if (t == null) t = await legacy(me, ud, dm[1]);
        return t == null ? send(res, 404, {error: 'Not found.'}) : send(res, 200, t, 'text/plain')
      }
      if (M === 'PUT') {
        await fsp.mkdir(path.dirname(f), {recursive: true});
        await fsp.writeFile(f, b);
        return send(res, 200, {ok: 1})
      }
    }
    if (P === '/api/feed') return send(res, 200, {url: `/cal/${me}/${tok(ud,'all')}.ics`});
    if (P === '/api/fs') {
      const roots = VR();
      let p = q.get('path') || roots[0] || require('os').homedir();
      try {
        p = fs.realpathSync(path.resolve(p));
        if (!fs.statSync(p).isDirectory()) throw 0
      } catch {
        return send(res, 400, {error: 'That folder does not exist.'})
      }
      if (roots.length && !roots.some(x => inside(p, x))) return send(res, 403, {error: 'That folder is outside the allowed VAULT_ROOTS.'});
      let ds;
      try {
        ds = (await fsp.readdir(p, {withFileTypes: true})).filter(e => e.isDirectory() && !e.name.startsWith('.')).map(e => e.name).sort((a, b) => a.localeCompare(b))
      } catch {
        return send(res, 403, {error: 'The server cannot read that folder.'})
      }
      const par = path.dirname(p);
      return send(res, 200, {path: p, parent: par !== p ? par : null, sep: path.sep, dirs: ds.map(n => ({n, v: fs.existsSync(path.join(p, n, '.obsidian'))}))})
    }
    if (P === '/api/vault/open') {
      const roots = (process.env.VAULT_ROOTS || '').split(',').map(x => x.trim()).filter(Boolean);
      const j = J();
      let r;
      try {
        r = fs.realpathSync(path.resolve(String(j.path || '')));
        if (!fs.statSync(r).isDirectory()) throw 0;
        fs.accessSync(r, fs.constants.R_OK|fs.constants.W_OK)
      } catch {
        return send(res, 400, {error: 'That folder does not exist or the server cannot read and write it.'})
      }
      if (roots.length && !roots.some(x => {
        try {
          const q = fs.realpathSync(x);
          return r === q || r.startsWith(q+path.sep)
        } catch {
          return false
        }
      })) return send(res, 403, {error: 'That folder is outside the allowed VAULT_ROOTS.'});
      if (r === DATA || r.startsWith(DATA+path.sep)) return send(res, 400, {error: "That is Pane's own data folder."});
      const b = (ok(j.name) ? j.name : (path.basename(r).replace(/[^\w-]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 28) || 'Vault'));
      let n = b, k = 2;
      while (fs.existsSync(vdir(me, n, ud))) n = b.slice(0, 26)+'-'+k++;
      ud.ext = {...(ud.ext || {}), [n]: r};
      await fsp.writeFile(U(me)+'/user.json', JSON.stringify(ud));
      return send(res, 200, {name: n})
    }
    if (P === '/api/vault/close') {
      const n = J().name;
      if (!ud.ext || !ud.ext[n]) return send(res, 400, {error: 'That is not a folder vault.'});
      delete ud.ext[n];
      await fsp.writeFile(U(me)+'/user.json', JSON.stringify(ud));
      return send(res, 200, {ok: 1})
    }
    if (P === '/api/preview') return send(res, 200, await preview(q.get('url') || ''));
    const m2 = P.match(/^\/api\/v\/([\w-]+)\/(tree|f|mv|search|export|feed)$/);
    if (m2) {
      const[, v, op] = m2, base = vdir(me, v, ud);
      if (!fs.existsSync(base)) return send(res, 404, {error: 'Vault not found.'});
      if (op === 'tree') return send(res, 200, (await walk(base)).filter(e => e.d || e.p.endsWith('.md')));
      if (op === 'feed') return send(res, 200, {url: `/cal/${me}/${v}/${tok(ud,v)}.ics`});
      if (op === 'search') {
        const t = (q.get('q') || '').toLowerCase(), o = [];
        for (const e of await walk(base)) if (!e.d && e.p.endsWith('.md') && (await fsp.readFile(fp(base, e.p), 'utf8')).toLowerCase().includes(t)) o.push(e.p);
        return send(res, 200, o)
      }
      if (op === 'export') {
        const f = {};
        for (const e of await walk(base)) if (!e.d && /\.(md|json|txt)$/.test(e.p)) f[e.p] = await fsp.readFile(fp(base, e.p), 'utf8');
        return send(res, 200, {app: 'pane', files: f})
      }
      if (op === 'mv') {
        const to = fp(base, q.get('to'));
        if (fs.existsSync(to)) return send(res, 409, {error: 'An item with that name already exists.'});
        await fsp.mkdir(path.dirname(to), {recursive: true});
        await fsp.rename(fp(base, q.get('from')), to);
        return send(res, 200, {ok: 1})
      }
      const f = fp(base, q.get('p'));
      if (M === 'GET') return send(res, 200, await fsp.readFile(f, 'utf8'), 'text/plain');
      if (M === 'PUT') {
        if ((q.get('p') || '').endsWith('/')) await fsp.mkdir(f, {recursive: true});
        else {
          await fsp.mkdir(path.dirname(f), {recursive: true});
          await fsp.writeFile(f, b);
          const mt = +q.get('mt');
          if (mt > 9e11 && mt < Date.now()+864e5) await fsp.utimes(f, new Date(mt), new Date(mt))
        }
        return send(res, 200, {ok: 1})
      }
      if (M === 'DELETE') {
        await fsp.rm(f, {recursive: true, force: true});
        return send(res, 200, {ok: 1})
      }
    }
    send(res, 404, {error: 'Not found'})
  } catch (e) {
    if (e !== 0 && !(e && e.code === 'ENOENT')) console.error(new Date().toISOString(), req.method, req.url, e && e.stack || e);
    send(res, e === 0 ? 400 : e && e.code === 'ENOENT' ? 404 : 500, {error: e && e.code === 'ENOENT' ? 'Not found.' : 'Request failed.'})
  }
}).listen(PORT, HOST, () => console.log(`Pane running at http://localhost:${PORT}  (data: ${DATA})`));
