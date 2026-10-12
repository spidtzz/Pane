// Pane server. Run: node server.js  (Node 18+, no dependencies)
// Env: PORT=3000 HOST=0.0.0.0 DATA=./data SIGNUP=0 (disable new accounts)
//      VAULT_ROOTS=/a,/b (optional: if set, only folders inside these can be opened as vaults)
// Data layout: DATA/users/<user>/vaults/<vault>/notes/**.md, todos.json, events.json, cheat.json, links.json
const http=require('http'),fs=require('fs'),fsp=fs.promises,path=require('path'),crypto=require('crypto'),dns=require('dns').promises,net=require('net');
const PORT=process.env.PORT||3000,HOST=process.env.HOST||'0.0.0.0',DATA=path.resolve(process.env.DATA||'./data'),SIGNUP=process.env.SIGNUP!=='0';
const S=new Map(),F={},sha=s=>crypto.createHash('sha256').update(s).digest('hex');
const ok=s=>typeof s==='string'&&/^[\w-]{1,32}$/.test(s);
const U=u=>`${DATA}/users/${u}`,vdir=(u,v,d)=>d&&d.ext&&d.ext[v]?d.ext[v]:`${U(u)}/vaults/${v}`;
const rj=async f=>{try{return JSON.parse(await fsp.readFile(f,'utf8'))}catch{return null}};
const hp=(pw,salt)=>crypto.scryptSync(String(pw),salt,32).toString('hex');
const tok=(d,v)=>sha(d.hash+v).slice(0,32);
const b32=buf=>{let b='',o='';for(const x of buf)b+=x.toString(2).padStart(8,'0');for(let i=0;i+5<=b.length;i+=5)o+='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'[parseInt(b.slice(i,i+5),2)];return o};
const unb=s=>{let b='';for(const c of s)b+='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'.indexOf(c).toString(2).padStart(5,'0');return Buffer.from(b.match(/.{8}/g).map(x=>parseInt(x,2)))};
const totp=(sec,t)=>{const c=Buffer.alloc(8);c.writeBigUInt64BE(BigInt(Math.floor(t/3e4)));const h=crypto.createHmac('sha1',unb(sec)).update(c).digest(),o=h[19]&15;return String((h.readUInt32BE(o)&0x7fffffff)%1e6).padStart(6,'0')};
const okc=(sec,c)=>[-1,0,1].some(d=>totp(sec,Date.now()+d*3e4)===String(c).trim());
const ve=e=>e==='2FA'?'Enter your 6-digit code.':e;

async function verify(u,pw,code){
 const d=ok(u)&&await rj(U(u)+'/user.json'),f=F[u]||(F[u]={n:0,t:0});
 if(f.n>=8&&Date.now()-f.t<6e5)return 'Too many attempts. Try again in a few minutes.';
 if(!d||!crypto.timingSafeEqual(Buffer.from(hp(pw||'',d.salt)),Buffer.from(d.hash))){f.n++;f.t=Date.now();return 'Wrong username or password.'}
 if(d.totp&&!okc(d.totp,code)){if(code){f.n++;f.t=Date.now();return 'Wrong code.'}return '2FA'}
 f.n=0;return null}

const body=req=>new Promise((r,j)=>{const c=[];let n=0;req.on('data',d=>{n+=d.length;if(n>2e7){req.destroy();j(0)}else c.push(d)});req.on('end',()=>r(Buffer.concat(c).toString()))});
const send=(res,c,b,t='application/json')=>{res.writeHead(c,{'content-type':t+'; charset=utf-8','cache-control':'no-store','x-content-type-options':'nosniff'});res.end(typeof b==='string'?b:JSON.stringify(b))};
const fp=(base,p)=>{const x=String(p||'').split('/').filter(Boolean);if(!x.length||x.some((s,i)=>(s.startsWith('.')&&!(i==0&&s=='.pane'))||s.includes('\0')||s.includes('\\')))throw 0;return path.join(base,...x)};
async function walk(b,d=''){let o=[];for(const e of await fsp.readdir(path.join(b,d),{withFileTypes:true})){if(e.name.startsWith('.'))continue;const p=d?d+'/'+e.name:e.name,st=await fsp.stat(path.join(b,p));o.push({p,d:e.isDirectory(),m:st.mtimeMs,s:st.size});if(e.isDirectory())o=o.concat(await walk(b,p))}return o}

const ics=(evs,name)=>{
 const d=s=>(s.replace(/[-:]/g,'')+'00').slice(0,15),esc=s=>String(s||'').replace(/[\\;,]/g,'\\$&').replace(/\n/g,'\\n'),day=s=>s.slice(0,10).replace(/-/g,'');
 const L=['BEGIN:VCALENDAR','VERSION:2.0','PRODID:-//Pane//EN','CALSCALE:GREGORIAN','X-WR-CALNAME:'+esc(name),'REFRESH-INTERVAL;VALUE=DURATION:PT15M','X-PUBLISHED-TTL:PT15M'];
 for(const e of evs){const ee=e.e||e.s;L.push('BEGIN:VEVENT','UID:'+e.id+'@pane','DTSTAMP:'+d(new Date().toISOString())+'Z');
  if(e.ad){const n=new Date(ee.slice(0,10)+'T00:00:00Z');n.setUTCDate(n.getUTCDate()+1);L.push('DTSTART;VALUE=DATE:'+day(e.s),'DTEND;VALUE=DATE:'+day(n.toISOString()))}else L.push('DTSTART:'+d(e.s),'DTEND:'+d(ee));
  L.push('SUMMARY:'+esc(e.t));if(e.n)L.push('DESCRIPTION:'+esc(e.n));if(e.l)L.push('LOCATION:'+esc(e.l));
  if(e.rep)L.push('RRULE:FREQ='+{d:'DAILY',w:'WEEKLY',m:'MONTHLY',y:'YEARLY'}[e.rep]+';INTERVAL='+(+e.int||1));
  if(e.al)L.push('BEGIN:VALARM','ACTION:DISPLAY','DESCRIPTION:'+esc(e.t),e.al==='e'?'TRIGGER;RELATED=END:PT0S':'TRIGGER:'+(e.al==='s0'?'PT0S':'-PT'+e.al.slice(1)+'M'),'END:VALARM');
  L.push('END:VEVENT')}
 L.push('END:VCALENDAR');return L.join('\r\n')};

const priv=a=>net.isIPv4(a)?/^(10\.|127\.|0\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(a):/^(::1|::$|fe80|fc|fd|::ffff)/i.test(a);
async function preview(u){try{let x=new URL(u),r;
 for(let i=0;i<4;i++){if(!/^https?:$/.test(x.protocol)||(await dns.lookup(x.hostname,{all:true})).some(a=>priv(a.address)))return{};
  r=await fetch(x,{redirect:'manual',signal:AbortSignal.timeout(6000),headers:{'user-agent':'Mozilla/5.0 (PanePreview)'}});
  if(r.status>299&&r.status<400&&r.headers.get('location'))x=new URL(r.headers.get('location'),x);else break}
 const h=(await r.text()).slice(0,3e5);
 const m=n=>{const a=h.match(new RegExp(`<meta[^>]+(?:property|name)=["']${n}["'][^>]*content=["']([^"']*)["']`,'i'))||h.match(new RegExp(`<meta[^>]+content=["']([^"']*)["'][^>]*(?:property|name)=["']${n}["']`,'i'));return a&&a[1]};
 const t=(h.match(/<title[^>]*>([^<]*)/i)||[])[1],img=m('og:image');
 return{t:(m('og:title')||t||'').trim(),d:(m('og:description')||m('description')||'').trim(),i:img?new URL(img,x).href:'',h:x.hostname}}catch{return{}}}

http.createServer(async(req,res)=>{try{
 const u=new URL(req.url,'http://x'),P=u.pathname,q=u.searchParams,M=req.method;
 if(M==='GET'&&(P==='/'||P==='/index.html'))return send(res,200,await fsp.readFile(path.join(__dirname,'index.html'),'utf8'),'text/html');
 if(P==='/manifest.json')return send(res,200,{name:'Pane',short_name:'Pane',start_url:'/',display:'standalone',background_color:'#0b1220',theme_color:'#0b1220',icons:[{src:'/icon.svg',sizes:'any',type:'image/svg+xml',purpose:'any'}]},'application/manifest+json');
 if(P==='/icon.svg')return send(res,200,'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><rect width="64" height="64" rx="15" fill="#0a84ff"/><rect x="15" y="12" width="34" height="40" rx="8" fill="#fff" fill-opacity=".88"/><path d="M22 24h20M22 32h20M22 40h12" stroke="#0a84ff" stroke-width="3" stroke-linecap="round"/></svg>','image/svg+xml');
 const fm=P.match(/^\/cal\/([\w-]+)\/([\w-]+)\/(\w+)\.ics$/);
 if(fm){const d=ok(fm[1])&&await rj(U(fm[1])+'/user.json');if(!d||tok(d,fm[2])!==fm[3])return send(res,404,'Not found','text/plain');const ex=d.ext&&d.ext[fm[2]];return send(res,200,ics(await rj(`${vdir(fm[1],fm[2],d)}${ex?'/.pane':''}/events.json`)||[],fm[2]),'text/calendar')}
 if(!P.startsWith('/api/'))return send(res,404,{error:'Not found'});
 const ck=Object.fromEntries((req.headers.cookie||'').split(';').map(c=>c.trim().split('='))),sec=req.headers['x-forwarded-proto']==='https'?'; Secure':'';
 const b=M==='GET'||M==='DELETE'?'':await body(req),J=()=>{try{return JSON.parse(b||'{}')}catch{return{}}};

 if(M==='POST'&&P==='/api/register'){
  if(!SIGNUP)return send(res,403,{error:'Sign-ups are disabled on this server.'});
  const{user,pw}=J();if(!ok(user)||String(pw||'').length<8)return send(res,400,{error:'Username: letters, numbers, - and _. Password: at least 8 characters.'});
  if(fs.existsSync(U(user)))return send(res,409,{error:'That username is taken.'});
  const salt=crypto.randomBytes(16).toString('hex');await fsp.mkdir(vdir(user,'Personal')+'/notes',{recursive:true});
  await fsp.writeFile(U(user)+'/user.json',JSON.stringify({salt,hash:hp(pw,salt),totp:null}));return send(res,200,{ok:1})}
 if(M==='POST'&&P==='/api/login'){
  const{user,pw,code,remember}=J(),e=await verify(user,pw,code);
  if(e)return send(res,401,{error:ve(e),need2fa:e==='2FA'});
  const t=crypto.randomBytes(32).toString('hex');S.set(t,{u:user,exp:Date.now()+(remember?30*864e5:12*36e5)});
  res.setHeader('set-cookie',`s=${t}; HttpOnly; SameSite=Strict; Path=/${remember?'; Max-Age='+30*86400:''}${sec}`);return send(res,200,{ok:1})}

 const s=S.get(ck.s),me=s&&s.exp>Date.now()?s.u:null,ud=me&&await rj(U(me)+'/user.json');
 if(!ud)return send(res,401,{error:'Sign in required.'});
 if(P==='/api/logout'){S.delete(ck.s);res.setHeader('set-cookie','s=; Max-Age=0; Path=/');return send(res,200,{ok:1})}
 if(P==='/api/unlock'){const{pw,code}=J(),e=await verify(me,pw,code);return e?send(res,401,{error:ve(e),need2fa:e==='2FA'}):send(res,200,{ok:1})}
 if(P==='/api/me'){const v=(await fsp.readdir(U(me)+'/vaults',{withFileTypes:true})).filter(e=>e.isDirectory()).map(e=>e.name).filter(n=>!(ud.ext&&ud.ext[n])),x=Object.keys(ud.ext||{});return send(res,200,{user:me,vaults:[...v,...x],ext:Object.fromEntries(x.map(k=>[k,ud.ext[k]])),totp:!!ud.totp})}
 if(P==='/api/vault'){const n=J().name;if(!ok(n))return send(res,400,{error:'Use letters, numbers, - and _.'});if(fs.existsSync(vdir(me,n,ud)))return send(res,409,{error:'That vault already exists.'});await fsp.mkdir(vdir(me,n)+'/notes',{recursive:true});return send(res,200,{ok:1})}
 if(P==='/api/2fa/setup'){ud.pending=b32(crypto.randomBytes(10));await fsp.writeFile(U(me)+'/user.json',JSON.stringify(ud));return send(res,200,{secret:ud.pending})}
 if(P==='/api/2fa/enable'){if(!ud.pending||!okc(ud.pending,J().code))return send(res,400,{error:'That code is not right. Try the next one.'});ud.totp=ud.pending;delete ud.pending;await fsp.writeFile(U(me)+'/user.json',JSON.stringify(ud));return send(res,200,{ok:1})}
 if(P==='/api/2fa/off'){const{pw,code}=J(),e=await verify(me,pw,code);if(e)return send(res,401,{error:ve(e)});ud.totp=null;await fsp.writeFile(U(me)+'/user.json',JSON.stringify(ud));return send(res,200,{ok:1})}
 if(P==='/api/vault/open'){const roots=(process.env.VAULT_ROOTS||'').split(',').map(x=>x.trim()).filter(Boolean);
  const j=J();let r;try{r=fs.realpathSync(path.resolve(String(j.path||'')));if(!fs.statSync(r).isDirectory())throw 0;fs.accessSync(r,fs.constants.R_OK|fs.constants.W_OK)}catch{return send(res,400,{error:'That folder does not exist or the server cannot read and write it.'})}
  if(roots.length&&!roots.some(x=>{try{const q=fs.realpathSync(x);return r===q||r.startsWith(q+path.sep)}catch{return false}}))return send(res,403,{error:'That folder is outside the allowed VAULT_ROOTS.'});
  if(r===DATA||r.startsWith(DATA+path.sep))return send(res,400,{error:"That is Pane's own data folder."});
  const b=(ok(j.name)?j.name:(path.basename(r).replace(/[^\w-]+/g,'-').replace(/^-+|-+$/g,'').slice(0,28)||'Vault'));let n=b,k=2;while(fs.existsSync(vdir(me,n,ud)))n=b.slice(0,26)+'-'+k++;
  ud.ext={...(ud.ext||{}),[n]:r};await fsp.writeFile(U(me)+'/user.json',JSON.stringify(ud));return send(res,200,{name:n})}
 if(P==='/api/vault/close'){const n=J().name;if(!ud.ext||!ud.ext[n])return send(res,400,{error:'That is not a folder vault.'});delete ud.ext[n];await fsp.writeFile(U(me)+'/user.json',JSON.stringify(ud));return send(res,200,{ok:1})}
 if(P==='/api/preview')return send(res,200,await preview(q.get('url')||''));

 const m2=P.match(/^\/api\/v\/([\w-]+)\/(tree|f|mv|search|export|feed)$/);
 if(m2){const[,v,op]=m2,base=vdir(me,v,ud);if(!fs.existsSync(base))return send(res,404,{error:'Vault not found.'});
  if(op==='tree')return send(res,200,(await walk(base)).filter(e=>e.d||e.p.endsWith('.md')));
  if(op==='feed')return send(res,200,{url:`/cal/${me}/${v}/${tok(ud,v)}.ics`});
  if(op==='search'){const t=(q.get('q')||'').toLowerCase(),o=[];for(const e of await walk(base))if(!e.d&&e.p.endsWith('.md')&&(await fsp.readFile(fp(base,e.p),'utf8')).toLowerCase().includes(t))o.push(e.p);return send(res,200,o)}
  if(op==='export'){const f={};for(const e of await walk(base))if(!e.d&&/\.(md|json|txt)$/.test(e.p))f[e.p]=await fsp.readFile(fp(base,e.p),'utf8');return send(res,200,{app:'pane',files:f})}
  if(op==='mv'){const to=fp(base,q.get('to'));if(fs.existsSync(to))return send(res,409,{error:'An item with that name already exists.'});await fsp.mkdir(path.dirname(to),{recursive:true});await fsp.rename(fp(base,q.get('from')),to);return send(res,200,{ok:1})}
  const f=fp(base,q.get('p'));
  if(M==='GET')return send(res,200,await fsp.readFile(f,'utf8'),'text/plain');
  if(M==='PUT'){if((q.get('p')||'').endsWith('/'))await fsp.mkdir(f,{recursive:true});else{await fsp.mkdir(path.dirname(f),{recursive:true});await fsp.writeFile(f,b)}return send(res,200,{ok:1})}
  if(M==='DELETE'){await fsp.rm(f,{recursive:true,force:true});return send(res,200,{ok:1})}}
 send(res,404,{error:'Not found'})
}catch(e){send(res,e===0?400:e&&e.code==='ENOENT'?404:500,{error:e&&e.code==='ENOENT'?'Not found.':'Request failed.'})}
}).listen(PORT,HOST,()=>console.log(`Pane running at http://localhost:${PORT}  (data: ${DATA})`));
