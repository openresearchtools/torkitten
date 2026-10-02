'use strict';
const $ = id => document.getElementById(id);
const el = (tag, text, cls) => { const e = document.createElement(tag); if (text !== undefined) e.textContent = text; if (cls) e.className = cls; return e; };
let state, selected = '', edited = false, shared, busy = false, qrData = '', cameraStream, cameraGeneration = 0, cameraTimer;
function message(text, error = false) { $('message').textContent = text; $('message').className = error ? 'error' : ''; }
async function api(path, body) {
  const r = await fetch('/api/' + path, body === undefined ? {} : {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  const data = await r.json(); if (!r.ok) throw new Error(data.error || 'Request failed'); return data;
}
async function work(fn) { if(busy)return;busy=true;document.body.setAttribute('aria-busy','true');try { message('Working…'); await fn(); message('Done'); } catch(e) { message(e.message, true); } finally {busy=false;document.body.removeAttribute('aria-busy')} }
function close(dialog) { dialog.close(); const form = dialog.querySelector('form'); if(form) form.reset(); }
document.querySelectorAll('[data-close]').forEach(b => b.onclick = () => close(b.closest('dialog')));
function open(id) { $(id).showModal(); }
function profile() { if (!selected) throw new Error('Choose a connection first'); return selected; }
function button(text, fn, enabled = true) {const b=el('button',text);b.type='button';b.disabled=!enabled;b.onclick=()=>work(fn);return b;}
function field(label, control) {const l=el('label',label);l.append(control);return l;}
function input(value, type='text') {const x=el('input');x.type=type;if(type==='checkbox')x.checked=value;else x.value=value;return x;}
function select(values, value) {const x=el('select');values.forEach(v=>{const o=el('option',v);o.value=v;x.append(o)});x.value=value;return x;}
function b64(data) {let s='';for(const n of new Uint8Array(data))s+=String.fromCharCode(n);return btoa(s);}
function download(name, encoded) {
  if (window.Native && typeof window.Native.save === 'function') { window.Native.save(name, encoded); return; }
  const data=Uint8Array.from(atob(encoded),c=>c.charCodeAt(0));const url=URL.createObjectURL(new Blob([data],{type:'application/octet-stream'}));
  const a=el('a');a.href=url;a.download=name;document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),60000);
}
async function refresh() {
  state=await api('state'); const previous=selected; $('profiles').replaceChildren(new Option('Choose a connection',''));
  state.profiles.forEach(p=>$('profiles').add(new Option(p.name,p.id)));selected=previous;$('profiles').value=selected;
  const p=state.profiles.find(p=>p.id===selected);$('unlock-open').disabled=!p||!p.locked;$('login-open').disabled=!p||p.locked;$('disconnect').disabled=!p||p.locked;
  $('connection-status').textContent=p?(p.locked?'Unlock this connection with its file password.':p.authenticated?'Connected':p.error||'Log in with Authelia to access shared services.'):'Import an encrypted connection file or scan the desktop QR with your camera.';
  $('host-status').textContent=state.error||(state.host.initialized?state.host.onion:'Create a host identity to share services.');$('enroll-open').disabled=!state.host.initialized;$('revoke').disabled=!state.host.initialized;
  if(!edited) renderHost(); if(p&&p.authenticated) await refreshServices();else $('client-services').replaceChildren();
}
async function refreshServices() {
  if(!selected)return;const data=await api('services?id='+encodeURIComponent(selected));const root=$('client-services');root.replaceChildren();
  for(const service of data.services) {
    const row=el('article',undefined,'service');const title=el('div',undefined,'service-info');title.append(el('span',service.title,'service-title'),el('span',service.reachable?'Available':'Not listening','status'));row.append(title);
    const controls=el('div',undefined,'row-actions');const enabled=input(service.mapped,'checkbox');const port=input(service.port||'','number');port.min=1;port.max=65535;port.placeholder='Auto';port.className='port';port.disabled=service.mapped;
    enabled.onchange=()=>work(async()=>{const n=port.value?Number(port.value):0;await api('map',{id:profile(),service:service.id,enabled:enabled.checked,port:n});await refreshServices();});
    controls.append(field('Route locally',enabled),field('Port',port));if(service.mapped) controls.append(el('span','127.0.0.1:'+service.port,'assigned'));
    ['load','reload','stop'].forEach(action=>controls.append(button(action[0].toUpperCase()+action.slice(1),async()=>{await api('action',{id:profile(),service:service.id,action});await refreshServices();},service.actions.includes(action))));
    row.append(controls);if(service.error)row.append(el('p',service.error,'error-text'));root.append(row);
  }
}
function renderHost() {
  const root=$('host-services');root.replaceChildren();
  for(const s of state.services.services) {
    const actions=s.actions||{};
    const row=el('article',undefined,'service');row.dataset.id=s.id;const grid=el('div',undefined,'edit-grid');
    const title=input(s.title);title.dataset.field='title';grid.append(field('Name',title));
    const endpoint=input(s.endpoint.address);endpoint.dataset.field='address';const network=select(['tcp','unix'],s.endpoint.network);network.dataset.field='network';grid.append(field('Port or socket',endpoint),field('Endpoint type',network));
    const available=input(s.available,'checkbox');available.dataset.field='available';const ssh=input(s.ssh,'checkbox');ssh.dataset.field='ssh';grid.append(field('Available',available),field('SSH access',ssh));
    for(const action of ['load','reload','stop']) {const box=el('textarea');box.value=actions[action]?JSON.stringify(actions[action]):'';box.dataset.action=action;box.placeholder='["/absolute/launcher", "argument"]';const label=field(action[0].toUpperCase()+action.slice(1)+' command',box);label.className='full';grid.append(label)}
    grid.oninput=()=>{edited=true};row.append(grid);const controls=el('div',undefined,'toolbar');['load','reload','stop'].forEach(action=>controls.append(button(action[0].toUpperCase()+action.slice(1),()=>api('host-action',{service:s.id,action}),!!actions[action])));
    controls.append(button('Remove',async()=>{row.remove();edited=true}));row.append(controls);root.append(row);
  }
}
function hostDocument() {
  return {version:2,services:[...$('host-services').children].map(row=>{const get=n=>row.querySelector('[data-field="'+n+'"]');const actions={};row.querySelectorAll('[data-action]').forEach(box=>{if(box.value.trim())actions[box.dataset.action]=JSON.parse(box.value)});
    return {id:row.dataset.id,title:get('title').value,available:get('available').checked,ssh:get('ssh').checked,endpoint:{network:get('network').value,address:get('address').value},actions};})};
}
$('client-tab').onclick=()=>{$('client-view').hidden=false;$('host-view').hidden=true;$('client-tab').setAttribute('aria-pressed','true');$('host-tab').setAttribute('aria-pressed','false')};
$('host-tab').onclick=()=>{$('client-view').hidden=true;$('host-view').hidden=false;$('host-tab').setAttribute('aria-pressed','true');$('client-tab').setAttribute('aria-pressed','false')};
$('profiles').onchange=()=>work(async()=>{selected=$('profiles').value;await refresh()});
for(const name of ['import','unlock','login','identity','enroll'])$(name+'-open').onclick=()=>open(name+'-dialog');
$('disconnect').onclick=()=>work(async()=>{await api('disconnect',{id:profile()});await refresh()});
$('revoke').onclick=()=>work(async()=>{await api('revoke',{});await refresh()});
$('add-service').onclick=()=>{state.services=hostDocument();state.services.services.push({id:'service-'+crypto.getRandomValues(new Uint32Array(1))[0].toString(16),title:'New service',available:false,ssh:false,endpoint:{network:'tcp',address:'127.0.0.1:8080'},actions:{}});renderHost();edited=true};
$('save-services').onclick=()=>work(async()=>{await api('config',{services:hostDocument()});edited=false;await refresh()});
function form(id,fn) {$(id+'-form').onsubmit=e=>{e.preventDefault();const f=e.target;work(async()=>{await fn(new FormData(f));close($(id+'-dialog'));await refresh()})};}
form('import',async d=>{const f=d.get('file');if(!qrData&&(!f.size||f.size>1500000))throw new Error('Scan the desktop QR or choose an encrypted file or QR image smaller than 1.5 MB.');const r=await api(!qrData&&f.type.startsWith('image/')?'import-qr':'import',{name:d.get('name'),password:d.get('password'),data:qrData||b64(await f.arrayBuffer())});selected=r.id});
form('unlock',d=>api('unlock',{id:profile(),password:d.get('password')}));
form('login',async d=>{const consent=await api('login',{id:profile(),username:d.get('username'),password:d.get('password'),totp:d.get('totp')});$('consent-details').textContent='Server: '+consent.gateway+'\nPermissions: '+consent.scopes.join(', ');open('consent-dialog')});
$('consent-accept').onclick=()=>work(async()=>{await api('consent',{id:profile(),accept:true});close($('consent-dialog'));await refresh()});
$('consent-cancel').onclick=()=>work(async()=>{await api('consent',{id:profile(),accept:false});close($('consent-dialog'))});
form('identity',async d=>{const result=await api('identity',{username:d.get('username'),confirm:d.get('confirm')==='on'});$('new-credentials').textContent='Username: '+result.username+'\nPassword: '+result.password;$('totp-image').src='data:image/png;base64,'+result.totp_qr;open('identity-result')});
$('identity-result').addEventListener('close',()=>{$('new-credentials').textContent='';$('totp-image').removeAttribute('src')});
form('enroll',async d=>{shared=await api('enroll',{name:d.get('name'),password:d.get('password')});$('connection-qr').hidden=!shared.qr;if(shared.qr)$('connection-qr').src='data:image/png;base64,'+shared.qr;$('qr-note').textContent=shared.qr_error||'Scan this QR on the other device. Its entire connection setup is encrypted with your file password.';open('enroll-result')});
$('download').onclick=()=>{if(shared)download('torkitten-connection.age',shared.file)};
$('enroll-result').addEventListener('close',()=>{shared=null;$('connection-qr').removeAttribute('src')});
refresh().catch(e=>message(e.message,true));setInterval(()=>{if(!busy&&!document.querySelector('dialog[open]')&&!document.querySelector('input:focus,textarea:focus,select:focus'))refresh().catch(e=>message(e.message,true));},5000);

function stopCamera() {
  cameraGeneration++;clearTimeout(cameraTimer);
  if(cameraStream)cameraStream.getTracks().forEach(track=>track.stop());
  cameraStream=null;$('scan-video').srcObject=null;
}
function clearScanned() {qrData='';$('qr-scanned').textContent='';$('connection-file').required=true;}
$('connection-file').onchange=clearScanned;
$('import-dialog').addEventListener('close',()=>{clearScanned();stopCamera()});
$('scan-dialog').addEventListener('close',stopCamera);
document.addEventListener('visibilitychange',()=>{if(document.hidden&&$('scan-dialog').open)close($('scan-dialog'))});
$('scan-open').onclick=async()=>{
  clearScanned();stopCamera();const generation=cameraGeneration;
  $('scan-status').textContent='Point your camera at the TorKitten connection QR on the desktop.';open('scan-dialog');
  try {
    if(!navigator.mediaDevices?.getUserMedia)throw new Error('Camera access is unavailable in this app build.');
    const stream=await navigator.mediaDevices.getUserMedia({video:{facingMode:{ideal:'environment'},width:{ideal:1920},height:{ideal:1080}},audio:false});
    if(generation!==cameraGeneration){stream.getTracks().forEach(track=>track.stop());return}
    cameraStream=stream;const video=$('scan-video');video.srcObject=stream;await video.play();
    const canvas=document.createElement('canvas'),context=canvas.getContext('2d',{willReadFrequently:true});
    const frame=async()=>{
      if(generation!==cameraGeneration)return;
      try {
        if(video.videoWidth&&video.videoHeight){
          const scale=Math.min(1,1280/Math.max(video.videoWidth,video.videoHeight));canvas.width=Math.round(video.videoWidth*scale);canvas.height=Math.round(video.videoHeight*scale);context.drawImage(video,0,0,canvas.width,canvas.height);
          const blob=await new Promise(resolve=>canvas.toBlob(resolve,'image/jpeg',.92));if(!blob||blob.size>1500000)throw new Error('Camera frame could not be read within the image limit.');
          const result=await api('scan-qr',{data:b64(await blob.arrayBuffer())});
          if(generation!==cameraGeneration)return;
          if(result.found){qrData=result.data;$('connection-file').value='';$('connection-file').required=false;$('qr-scanned').textContent='QR scanned. Enter the connection file password.';close($('scan-dialog'));$('import-form').elements.password.focus();return}
        }
        cameraTimer=setTimeout(frame,350);
      }catch(error){if(generation===cameraGeneration){stopCamera();$('scan-status').textContent=error.message}}
    };
    frame();
  }catch(error){if(generation===cameraGeneration){stopCamera();$('scan-status').textContent=error.message}}
};
