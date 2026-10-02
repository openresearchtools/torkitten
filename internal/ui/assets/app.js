'use strict';
const $=id=>document.getElementById(id);
const el=(tag,text,cls)=>{const e=document.createElement(tag);if(text!==undefined)e.textContent=text;if(cls)e.className=cls;return e};
let state,selected='',edited=false,shared='',busy=false,qrFrame='',cameraStream,cameraGeneration=0,cameraTimer;
function message(text,error=false){$('message').textContent=text;$('message').className=error?'error':'';const d=document.querySelector('dialog[open] .dialog-status');if(d){d.textContent=text;d.className='dialog-status'+(error?' error-text':'')}}
async function api(path,body){const r=await fetch('/api/'+path,body===undefined?{}:{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});const data=await r.json();if(!r.ok)throw new Error(data.error||'Request failed');return data}
async function work(fn){if(busy)return;busy=true;document.body.setAttribute('aria-busy','true');try{message('Working…');await fn();message('')}catch(e){message(e.message,true)}finally{busy=false;document.body.removeAttribute('aria-busy')}}
function close(dialog){dialog.close();const f=dialog.querySelector('form');if(f)f.reset()}
function open(id){const d=$(id);const status=d.querySelector('.dialog-status');if(status)status.textContent='';d.showModal()}
function profile(){if(!selected)throw new Error('Choose a connection first');return selected}
function button(text,fn,enabled=true){const b=el('button',text);b.type='button';b.disabled=!enabled;b.onclick=()=>work(fn);return b}
function field(label,control){const l=el('label',label);l.append(control);return l}
function input(value,type='text'){const x=el('input');x.type=type;if(type==='checkbox')x.checked=value;else x.value=value;return x}
function select(values,value){const x=el('select');values.forEach(v=>x.add(new Option(v,v)));x.value=value;return x}
function b64(data){let s='';for(const n of new Uint8Array(data))s+=String.fromCharCode(n);return btoa(s)}
function showQR(encoded){shared=encoded;$('connection-qr').src='data:image/png;base64,'+encoded;open('qr-dialog')}
function downloadQR(){if(!shared)return;const name='TorKitten-connection.png';if(window.Native&&typeof window.Native.save==='function'){window.Native.save(name,shared);return}const bytes=Uint8Array.from(atob(shared),c=>c.charCodeAt(0));const url=URL.createObjectURL(new Blob([bytes],{type:'image/png'}));const a=el('a');a.href=url;a.download=name;document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),60000)}
async function refresh(){
  const wasAuthenticated=state?.profiles.find(p=>p.id===selected)?.authenticated;state=await api('state');const previous=selected;$('profiles').replaceChildren(new Option('Choose a connection',''));state.profiles.forEach(p=>$('profiles').add(new Option(p.name,p.id)));selected=state.profiles.some(p=>p.id===previous)?previous:'';$('profiles').value=selected;
  const p=state.profiles.find(p=>p.id===selected);$('remove').disabled=!p;$('connection-status').textContent=p?(p.locked?'Select this connection to open it.':p.authenticated?'Connected':p.error||'Sign in to connect.'):'Add a connection by scanning a QR or selecting its image.';
  $('host-status').textContent=state.error||(state.host.enrolled?'Ready to share services.':state.host.initialized?'Complete local two-factor setup, or create a new identity to start again.':'Create an identity to share services.');$('qr-open').disabled=!state.host.enrolled;$('revoke').disabled=!state.host.enrolled;
  if(!edited)renderHost();if(p&&p.authenticated)await refreshServices();else {$('client-services').replaceChildren();if(wasAuthenticated&&p&&!document.querySelector('dialog[open]'))connect()}
}
function connect(){const p=state.profiles.find(p=>p.id===selected);if(p&&!p.authenticated)open(p.locked?'unlock-dialog':'login-dialog')}
async function refreshServices(){
  const id=selected;if(!id)return;const data=await api('services?id='+encodeURIComponent(id));if(selected!==id)return;const root=$('client-services');root.replaceChildren();
  for(const s of data.services){
    const row=el('article',undefined,'service'),title=el('div',undefined,'service-info');title.append(el('span',s.title,'service-title'),el('span',s.reachable?'Ready':s.running?'Starting':'Stopped','status'));row.append(title);
    const controls=el('div',undefined,'row-actions'),enabled=input(s.mapped,'checkbox'),port=input(s.port||'','number');port.min=1;port.max=65535;port.placeholder='Auto';port.className='port';port.disabled=s.mapped;
    enabled.onchange=()=>work(async()=>{try{await api('map',{id,service:s.id,enabled:enabled.checked,port:port.value?Number(port.value):0})}finally{await refreshServices()}});controls.append(field('Route locally',enabled),field('Port',port));if(s.mapped)controls.append(el('span','127.0.0.1:'+s.port,'assigned'));
    if(!s.ssh)for(const action of ['load','reload','stop'])controls.append(button(action[0].toUpperCase()+action.slice(1),async()=>{await api('action',{id,service:s.id,action});await refreshServices()},s.actions.includes(action)));
    row.append(controls);if(s.ssh_command)row.append(el('code',s.ssh_command,'ssh-command'));if(s.error)row.append(el('p',s.error,'error-text'));root.append(row);
  }
}
function renderHost(){
  $('host-ssh').checked=state.services.ssh;const root=$('host-services');root.replaceChildren();
  for(const s of state.services.services){
    const row=el('article',undefined,'service');row.dataset.id=s.id;const grid=el('div',undefined,'edit-grid');
    const controls={title:input(s.title),command:input(s.command||''),network:select(['tcp','unix'],s.endpoint.network),address:input(s.endpoint.address),available:input(s.available,'checkbox')};
    for(const [name,label] of [['title','Name'],['command','Launch command'],['network','Endpoint type'],['address','Port or socket'],['available','Available']]){const control=controls[name];control.dataset.field=name;if(name==='command')control.placeholder='/absolute/path/llama-server --port 5090';const l=field(label,control);if(name==='command')l.className='full';if(name==='available')l.className='check';grid.append(l)}
    grid.oninput=()=>{edited=true};row.append(grid);const actions=el('div',undefined,'toolbar');for(const action of ['load','reload','stop'])actions.append(button(action[0].toUpperCase()+action.slice(1),async()=>{if(edited)throw new Error('Save service changes first.');await api('host-action',{service:s.id,action})}));actions.append(button('Remove',async()=>{row.remove();edited=true}));row.append(actions);root.append(row);
  }
}
function hostDocument(){return{version:2,ssh:$('host-ssh').checked,services:[...$('host-services').children].map(row=>{const get=n=>row.querySelector('[data-field="'+n+'"]');return{id:row.dataset.id,title:get('title').value,command:get('command').value,available:get('available').checked,endpoint:{network:get('network').value,address:get('address').value}}})}}
for(const tab of ['client','host'])$(tab+'-tab').onclick=()=>{for(const item of ['client','host']){$(item+'-view').hidden=item!==tab;$(item+'-tab').setAttribute('aria-pressed',String(item===tab))}};
$('profiles').onchange=()=>work(async()=>{selected=$('profiles').value;await refresh();connect()});
$('import-open').onclick=()=>open('import-dialog');$('identity-open').onclick=()=>open('identity-dialog');
$('remove').onclick=()=>work(async()=>{try{await api('remove',{id:profile()})}finally{await refresh()}});
$('revoke').onclick=()=>work(async()=>{await api('revoke',{});await refresh()});$('qr-open').onclick=()=>work(async()=>showQR((await api('qr',{})).qr));
$('host-ssh').onchange=()=>{edited=true};
$('add-service').onclick=()=>{state.services=hostDocument();state.services.services.push({id:'service-'+crypto.getRandomValues(new Uint32Array(1))[0].toString(16),title:'New service',available:false,command:'',endpoint:{network:'tcp',address:'127.0.0.1:8080'}});renderHost();edited=true};
$('save-services').onclick=()=>work(async()=>{await api('config',{services:hostDocument()});edited=false;await refresh()});
function form(id,fn){$(id+'-form').onsubmit=e=>{e.preventDefault();const d=new FormData(e.target);work(()=>fn(d))}}
form('import',async d=>{const f=d.get('file');if(!qrFrame&&(!f.size||f.size>1500000||!['image/png','image/jpeg'].includes(f.type)))throw new Error('Scan a QR or select a PNG/JPEG image smaller than 1.5 MB.');const r=await api('import-qr',{name:d.get('name'),password:d.get('password'),data:qrFrame||b64(await f.arrayBuffer())});selected=r.id;close($('import-dialog'));await refresh();connect()});
form('unlock',async d=>{await api('unlock',{id:profile(),password:d.get('password')});close($('unlock-dialog'));await refresh();connect()});
form('login',async d=>{const consent=await api('login',{id:profile(),password:d.get('password'),totp:d.get('totp')});close($('login-dialog'));$('consent-details').textContent=consent.gateway;open('consent-dialog')});
$('consent-accept').onclick=()=>work(async()=>{await api('consent',{id:profile(),accept:true});close($('consent-dialog'));await refresh()});$('consent-cancel').onclick=()=>work(async()=>{await api('consent',{id:profile(),accept:false});close($('consent-dialog'))});
form('identity',async d=>{const result=await api('identity',{password:d.get('password'),confirm:d.get('confirm')==='on'});close($('identity-dialog'));$('new-credentials').textContent='Username: '+result.username+'\nPassword: '+result.password;$('totp-image').src='data:image/png;base64,'+result.totp_qr;open('setup-dialog');await refresh()});
form('setup',async d=>{const result=await api('identity-confirm',{totp:d.get('totp')});close($('setup-dialog'));showQR(result.qr);await refresh()});
$('setup-dialog').addEventListener('close',()=>{$('new-credentials').textContent='';$('totp-image').removeAttribute('src')});$('qr-dialog').addEventListener('close',()=>{shared='';$('connection-qr').removeAttribute('src')});$('download').onclick=downloadQR;
for(const b of document.querySelectorAll('[data-close]'))b.onclick=()=>{if(!busy)close(b.closest('dialog'))};for(const d of document.querySelectorAll('dialog'))d.addEventListener('cancel',e=>{e.preventDefault();if(!busy)close(d)});
refresh().then(()=>{if(state.profiles.length===1){selected=state.profiles[0].id;$('profiles').value=selected;connect()}}).catch(e=>message(e.message,true));
async function poll(){try{if(!busy&&!document.querySelector('dialog[open]')&&!document.querySelector('input:focus,textarea:focus,select:focus'))await refresh()}catch(e){message(e.message,true)}finally{setTimeout(poll,5000)}}setTimeout(poll,5000);
function stopCamera(){cameraGeneration++;clearTimeout(cameraTimer);if(cameraStream)cameraStream.getTracks().forEach(track=>track.stop());cameraStream=null;$('scan-video').srcObject=null}
function clearScanned(){qrFrame='';$('qr-scanned').textContent='';$('connection-file').required=true}
$('connection-file').onchange=clearScanned;$('import-dialog').addEventListener('close',()=>{clearScanned();stopCamera()});$('scan-dialog').addEventListener('close',stopCamera);
document.addEventListener('visibilitychange',()=>{if(document.hidden&&$('scan-dialog').open)close($('scan-dialog'))});
$('scan-open').onclick=async()=>{
  clearScanned();stopCamera();const generation=cameraGeneration;$('scan-status').textContent='Point your camera at the TorKitten connection QR.';open('scan-dialog');
  try{
    if(!navigator.mediaDevices?.getUserMedia)throw new Error('Camera access is unavailable in this app build.');const stream=await navigator.mediaDevices.getUserMedia({video:{facingMode:{ideal:'environment'},width:{ideal:1920},height:{ideal:1080}},audio:false});if(generation!==cameraGeneration){stream.getTracks().forEach(track=>track.stop());return}cameraStream=stream;const video=$('scan-video');video.srcObject=stream;await video.play();
    const canvas=document.createElement('canvas'),context=canvas.getContext('2d',{willReadFrequently:true});
    const frame=async()=>{if(generation!==cameraGeneration)return;try{
      if(video.videoWidth&&video.videoHeight){const scale=Math.min(1,1280/Math.max(video.videoWidth,video.videoHeight));canvas.width=Math.round(video.videoWidth*scale);canvas.height=Math.round(video.videoHeight*scale);context.drawImage(video,0,0,canvas.width,canvas.height);const blob=await new Promise(resolve=>canvas.toBlob(resolve,'image/jpeg',.92));if(!blob||blob.size>1500000)throw new Error('Camera frame exceeds the image limit.');const encoded=b64(await blob.arrayBuffer()),result=await api('scan-qr',{data:encoded});if(generation!==cameraGeneration)return;if(result.found){qrFrame=encoded;$('connection-file').value='';$('connection-file').required=false;$('qr-scanned').textContent='QR scanned. Enter its password.';close($('scan-dialog'));$('import-form').elements.password.focus();return}}
      cameraTimer=setTimeout(frame,350);
    }catch(e){if(generation===cameraGeneration){stopCamera();$('scan-status').textContent=e.message}}};frame();
  }catch(e){if(generation===cameraGeneration){stopCamera();$('scan-status').textContent=e.message}}
};
