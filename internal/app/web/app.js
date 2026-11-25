'use strict';
const $ = s => document.querySelector(s);
let profiles = [], detailID = '', detailSnapshot = null, authenticated = false, currentUsername = '';
let selectedID = '', metricsData = null, timer = null, polling = null, generation = 0, exportResult = null, exportRevision = 0;
const requests = new Set(), pollRequests = new Set(), cards = new Map();
const stateNames = {stopped:'已停止',connecting:'连接中',connected:'已连接',reconnecting:'重连中',error:'连接错误',failed:'连接失败',disconnected:'已断开',starting:'启动中',running:'进程运行中',ready:'服务就绪',degraded:'部分异常',stale:'观测未知'};
async function api(path, method = 'GET', body, background = false) {
  const epoch = generation, controller = new AbortController(); requests.add(controller); if(background)pollRequests.add(controller);
  const timeout = setTimeout(()=>controller.abort(),15000);
  if(background && document.hidden)controller.abort();
  try {
    const response = await fetch('/api/' + path, {method, signal:controller.signal, headers:{'Content-Type':'application/json','X-OVPN-Socks':'1'}, body:body === undefined ? undefined : JSON.stringify(body)});
    const data = await response.json().catch(() => ({error:'请求失败，请重试。'}));
    if (epoch !== generation) throw new DOMException('会话已变更', 'AbortError');
    if (!response.ok) { if (response.status === 401 && path !== 'login' && path !== 'account') showLogin(); throw Error(data.error || response.statusText); }
    return data;
  } finally { clearTimeout(timeout); requests.delete(controller); pollRequests.delete(controller); }
}
function notice(message, error = false) { const n = $('#notice'); n.textContent = message; n.className = error ? 'error' : 'success'; n.hidden = false; }
function el(tag, text, className) { const n = document.createElement(tag); if (text !== undefined) n.textContent = text; if (className) n.className = className; return n; }
function button(text, action, cls) { const b = el('button', text, cls); b.type = 'button'; b.addEventListener('click', () => Promise.resolve(action()).catch(e => {if(e.name !== 'AbortError') notice(e.message,true);})); return b; }
const number = n => Number.isFinite(Number(n)) ? Number(n) : 0;
function bytes(n) { n = Math.max(0, number(n)); const units = ['B','KiB','MiB','GiB','TiB']; let i = 0; while(n >= 1024 && i < units.length-1) { n /= 1024; i++; } return n.toLocaleString('zh-CN',{maximumFractionDigits:i ? 1 : 0}) + ' ' + units[i]; }
function duration(n) { n = Math.max(0, Math.floor(number(n)/1000)); if(n >= 86400) return Math.floor(n/86400)+'天 '+Math.floor(n%86400/3600)+'小时'; if(n >= 3600) return Math.floor(n/3600)+'小时 '+Math.floor(n%3600/60)+'分'; return Math.floor(n/60)+'分 '+n%60+'秒'; }
const metric = p => p.status?.metrics || {};
const engine = p => p?.engine || 'openvpn';
const external = p => engine(p) !== 'openvpn';
const engineStatus = p => p?.engine_status || p?.status?.engine_status;
let profilesReceivedAt = 0, freshnessTimer = null;
const fresh = p => {const e=engineStatus(p);return !!e?.fresh && e.process_running === true && number(e.last_telemetry_ms)>0 && performance.now()-profilesReceivedAt<10000;};
const available = p => fresh(p) && engineStatus(p)?.metrics_available === true;
const displayState = p => {if(!external(p))return p.status?.state||'stopped';const e=engineStatus(p);if(!e)return p.status?.state==='stopped'?'stopped':'stale';if(!e.process_running)return ['stopped','failed','reconnecting','error'].includes(p.status?.state)?p.status.state:'stale';return fresh(p)?e.state||'running':'stale';};
const measured = (v,format=String) => v !== null && v !== undefined && Number.isFinite(Number(v)) ? format(Number(v)) : '—';
function evidence(p) {const e=engineStatus(p);return !e ? '尚无运行观测' : !e.process_running ? '进程未运行' : !fresh(p) ? '观测未知 · 等待新鲜遥测' : '观测新鲜 · '+new Date(e.last_telemetry_ms).toLocaleTimeString('zh-CN',{hour12:false});}
function listenerRows(root,p,declaredOnly=false) {
  const declarations=p.listeners||[], runtime=engineStatus(p)?.listeners||[];
  const rows=declaredOnly ? declarations : declarations.map(d=>({...d,...runtime.find(r=>r.id===d.id)})).concat(runtime.filter(r=>!declarations.some(d=>d.id===r.id)));
  root.replaceChildren();
  if(!rows.length){root.append(el('p','暂无监听声明（引擎也可能仅作为客户端）','hint'));return;}
  for(const l of rows.slice(0,256)) {
    const live=!declaredOnly && fresh(p) && l.state==='listening' && !!l.actual_address;
    const row=el('div',undefined,'listener'+(live?' live':'')), scope=l.scope==='remote'?'远端':l.scope==='local'?'本地':'范围未知';
    row.append(el('strong',scope+' · '+String(l.network||'other').toUpperCase()+' · '+(l.kind||'监听')));
    row.append(el('span','声明：'+(l.address||'—')));
    row.append(el('small',live?'正在监听：'+l.actual_address:declaredOnly?'仅配置声明，尚未启动':!fresh(p)?'实际状态未知 · '+evidence(p):({'failed':'监听失败','closed':'已关闭','starting':'启动中','configured':'仅配置声明','unknown':'状态未知'}[l.state]||'尚无实际监听地址')));
    if(l.error)row.append(el('small',l.error));
    if(l.counter_scope || l.connection_scope)row.append(el('small','计数范围：'+[l.counter_scope,l.connection_scope].filter(Boolean).join(' · ')));
    if(!declaredOnly){const ok=fresh(p)&&l.metrics_available===true, noun=l.network==='tcp'?'TCP 连接':l.network==='udp'?'UDP 原生会话 / 请求':'原生流';row.append(el('small','↓ '+(ok?measured(l.download_bytes,bytes):'—')+' · ↑ '+(ok?measured(l.upload_bytes,bytes):'—')+' · 当前'+noun+' '+(ok?measured(l.active_connections):'—')));}
    root.append(row);
  }
}
function setText(node, text) { if(node.textContent !== String(text)) node.textContent = text; }
function metricCells(root, items) {
  if(root.children.length !== items.length) root.replaceChildren(...items.map(() => {const cell=el('div',undefined,'metric');cell.append(el('span',undefined,'metric-label'),el('strong'),el('small'));return cell;}));
  items.forEach(([label,value,note],i) => {const c=root.children[i];setText(c.children[0],label);setText(c.children[1],value);setText(c.children[2],note || '');});
}
function renderSummary() {
  const total = key => profiles.filter(p=>!external(p)).reduce((sum,p)=>sum+number(metric(p)[key]),0);
  const online = profiles.filter(p => ['connected','ready'].includes(displayState(p))).length;
  const dialCount = total('dial_count');
  metricCells($('#summary'),[
    ['在线连接',online+' / '+profiles.length,'已就绪 / 已配置'],
    ['下载 / 上传',bytes(total('download_bytes_per_second'))+'/s', '↑ '+bytes(total('upload_bytes_per_second'))+'/s · 仅 OpenVPN TCP'],
    ['OpenVPN 累计流量',bytes(total('download_bytes')+total('upload_bytes')),'↓ '+bytes(total('download_bytes'))+' · ↑ '+bytes(total('upload_bytes'))],
    ['当前并发',total('active_connections').toLocaleString(),'仅 OpenVPN · SOCKS TCP'],
    ['成功 / 失败',total('requests_succeeded')+' / '+total('requests_failed'),'仅 OpenVPN · SOCKS 请求'],
    ['平均拨号耗时',dialCount ? (total('dial_duration_ms_total')/dialCount).toFixed(1)+' ms' : '—','仅 OpenVPN · TCP 拨号 · '+dialCount+' 次']
  ]);
}
function render() {
  const root = $('#profiles'), ids = new Set(profiles.map(p=>p.id));
  for(const [id,card] of cards) if(!ids.has(id)) {card.remove();cards.delete(id);}
  root.querySelector('.empty')?.remove();
  if(!profiles.length) {const empty=el('div',undefined,'empty');empty.append(el('div','↗','empty-icon'),el('h2','添加你的第一个连接'),el('p','选择 OpenVPN、flyssh 或 gust，查看监听与运行状态。','muted'),button('＋ 新建连接',()=>edit(),'primary'));root.append(empty);}
  for(const p of profiles) {
    let card = cards.get(p.id);
    if(!card) {
      card=el('article',undefined,'card profile-card');
      const top=el('div',undefined,'card-top');top.append(el('h2'),el('span',undefined,'state'));
      card.append(top,el('p',undefined,'endpoint'),el('p',undefined,'muted'),el('div',undefined,'tags'),el('p',undefined,'card-error'),el('p',undefined,'card-traffic'));
      const controls=el('div',undefined,'card-actions');
      controls.append(button('启动',async()=>{const item=profiles.find(x=>x.id===p.id);const running=(item.status?.state||'stopped')!=='stopped';await api('profiles/'+encodeURIComponent(p.id)+'/'+(running?'stop':'start'),'POST',{});await refresh();}),button('路由与日志',()=>openDetails(p.id)),button('编辑',()=>edit(p.id)),button('删除',async()=>{const item=profiles.find(x=>x.id===p.id);if(confirm('删除连接“'+item.name+'”？')){await api('profiles/'+encodeURIComponent(p.id),'DELETE');await refresh();}},'danger'));
      card.append(controls,el('div',undefined,'listener-list'));cards.set(p.id,card);root.append(card);
    }
    const state=displayState(p), m=metric(p), running=(p.status?.state||'stopped')!=='stopped';
    setText(card.children[0].children[0],p.name);setText(card.children[0].children[1],stateNames[state]||state);card.children[0].children[1].className='state '+state;
    setText(card.children[1],external(p)?engine(p)+' · 原生转发':p.listen);setText(card.children[2],external(p)?evidence(p):p.username?'账户 '+p.username:'证书认证');
    setText(card.children[3],(p.auto_reconnect?'自动重连':'手动重连')+(p.has_totp?' · TOTP':''));
    setText(card.children[4],p.status?.error||'');card.children[4].hidden=!p.status?.error;
    setText(card.children[5],'↓ '+bytes(m.download_bytes_per_second)+'/s   ↑ '+bytes(m.upload_bytes_per_second)+'/s · '+number(m.active_connections)+' 并发');
    if(external(p)){setText(card.children[5],available(p)?'↓ '+measured(m.download_bytes_per_second,bytes)+'/s · ↑ '+measured(m.upload_bytes_per_second,bytes)+'/s':'流量 — · '+(fresh(p)?'引擎未提供指标':'等待新鲜观测'));listenerRows(card.children[7],p);}card.children[7].hidden=!external(p);setText(card.children[6].children[1],external(p)?'监听与日志':'路由与日志');
    const toggle=card.children[6].children[0];setText(toggle,running?'停止':'启动');toggle.className=running?'':'primary';
  }
  setText($('#profileCount'),profiles.length);
  const select=$('#metricProfile');
  for(const option of [...select.options]) if(!ids.has(option.value)) option.remove();
  profiles.forEach(p=>{let option=[...select.options].find(o=>o.value===p.id);if(!option){option=el('option');option.value=p.id;select.append(option);}setText(option,p.name);});
  if(!ids.has(selectedID)) {selectedID=profiles[0]?.id||'';metricsData=null;}
  select.value=selectedID;select.disabled=!profiles.length;
  renderSummary();renderMetrics();
}
function renderMetrics() {
  const p=profiles.find(p=>p.id===selectedID), data=metricsData?.profileID===selectedID && performance.now()-metricsData.receivedAt<10000 ? metricsData : null;
  const m=data && data.receivedAt>=profilesReceivedAt ? data.current || (p ? metric(p) : {}) : (p ? metric(p) : {}), runtime=data?.runtime, reconnect=m.reconnect || p?.status?.reconnect || {};
  const state=m.state||p?.status?.state||'stopped';
  setText($('#selectedDownload'),bytes(m.download_bytes_per_second)+'/s');setText($('#selectedUpload'),bytes(m.upload_bytes_per_second)+'/s');
  setText($('#chartStatus'),p ? (stateNames[state]||state)+' · 每 3 秒刷新' : '尚无连接');
  metricCells($('#connectionMetrics'),[
    ['累计在线',p ? duration(m.online_duration_ms) : '—',number(m.connected_since_ms) ? '本次 '+duration(Date.now()-number(m.connected_since_ms)) : '当前未连接'],
    ['峰值并发',p ? number(m.peak_connections) : '—','当前 '+number(m.active_connections)],
    ['最近拨号',number(m.dial_count) ? number(m.dial_duration_ms_last).toFixed(1)+' ms' : '—','平均 '+(number(m.dial_count)?(number(m.dial_duration_ms_total)/number(m.dial_count)).toFixed(1)+' ms':'—')],
    ['重试 / 尝试',p ? number(m.reconnect_count ?? reconnect.retries)+' / '+number(reconnect.attempts) : '—','恢复 '+number(reconnect.reconnects)+' · 中断 '+number(m.disconnect_count)+' · 连续失败 '+number(reconnect.consecutive_failures)+(number(reconnect.next_attempt_ms)>Date.now()?' · '+Math.ceil((reconnect.next_attempt_ms-Date.now())/1000)+'秒后重试':'')]
  ]);
  setText($('#runtimeMetrics'),runtime ? '服务运行 '+duration(runtime.uptime_ms)+'   ·   Go heap '+bytes(runtime.heap_alloc_bytes)+' / '+bytes(runtime.heap_sys_bytes)+' 已申请   ·   Goroutines '+number(runtime.goroutines)+'   ·   GC '+number(runtime.gc_cycles)+' 次' : '运行时指标将在首个采样后显示');
  if(p && external(p)) {
    const ok=available(p), e=engineStatus(p)||{};
    setText($('#selectedDownload'),ok && m.download_bytes_per_second!=null ? measured(m.download_bytes_per_second,bytes)+'/s' : '—');setText($('#selectedUpload'),ok && m.upload_bytes_per_second!=null ? measured(m.upload_bytes_per_second,bytes)+'/s' : '—');
    setText($('#chartStatus'),(stateNames[displayState(p)]||displayState(p))+' · '+evidence(p));
    metricCells($('#connectionMetrics'),[
      ['累计就绪时长',measured(m.online_duration_ms,duration),'按引擎 connected / ready 遥测状态累计'],
      ['当前原生流',ok?measured(m.active_connections):'—','TCP 连接 / UDP 会话等，按监听区分'],
      ['累计 / 失败',ok?measured(e.total_connections)+' / '+measured(e.failed_connections):'—','原生接受流 / 拨号失败，非 SOCKS 请求成功率'],
      ['进程重启',measured(e.restarts),[e.counter_scope,e.connection_scope].filter(Boolean).join(' · ') || '计数范围以引擎观测为准']
    ]);
    drawChart(ok ? (data?.history||[]).filter(x=>x.metrics_available!==false && x.upload_bytes_per_second!=null && x.download_bytes_per_second!=null) : [],p,displayState(p));
    if(!ok)setText($('#chartEmpty'),fresh(p)?'此引擎未提供流量指标':'遥测未更新，当前指标未知');
  } else drawChart(data?.history || [],p,state);
  setText($('#measurementNote'),p && external(p)?'流量为引擎观测的应用字节；原生流可能为 TCP 连接或 UDP 会话 / 请求，不等同于 OpenVPN SOCKS 计数。未知或过期指标显示 —。趋势仅在内存保留 15 分钟、最多 450 点；Go heap 不是进程 RSS。':'流量为 SOCKS TCP payload，不代表线路速率；拨号耗时不是 ping。趋势仅保留最近 15 分钟、最多 450 个采样点，存于内存，不落盘、不主动探测。Go heap 为运行时堆内存，不是进程 RSS。');
}
function drawChart(history,p,state) {
  const end=Date.now(), start=end-900000, samples=history.filter(s=>number(s.timestamp_ms)>=start && number(s.timestamp_ms)<=end).slice(-450);
  const max=Math.max(1,...samples.map(s=>Math.max(number(s.upload_bytes_per_second),number(s.download_bytes_per_second))));
  const x=t=>((t-start)/900000*900).toFixed(2), y=v=>(188-Math.max(0,number(v))/max*164).toFixed(2);
  const path=key=>{let last=0;return samples.map(s=>{const t=number(s.timestamp_ms), command=!last || t-last>10000?'M':'L';last=t;return command+x(t)+','+y(s[key]);}).join(' ');};
  $('#downloadLine').setAttribute('d',path('download_bytes_per_second'));$('#uploadLine').setAttribute('d',path('upload_bytes_per_second'));
  $('#downloadArea').setAttribute('d','');
  const grid=$('#chartGrid');if(!grid.children.length) {for(let i=0;i<3;i++){const line=document.createElementNS('http://www.w3.org/2000/svg','path');line.setAttribute('d','M0 '+(24+i*82)+' H900');grid.append(line);const text=document.createElementNS('http://www.w3.org/2000/svg','text');text.setAttribute('x','5');text.setAttribute('y',String(18+i*82));grid.append(text);}}
  for(let i=0;i<3;i++)setText(grid.children[i*2+1],bytes(max*(1-i/2))+'/s');
  $('#chartEmpty').hidden=samples.length>1;
  setText($('#chartEmpty'),!p?'添加连接后查看实时指标':samples.length===1?'正在积累采样数据…':state==='connected'?'等待首个流量采样…':'连接未在线，暂无近期采样');
}
function schedule() {clearTimeout(timer);if(authenticated && !document.hidden)timer=setTimeout(()=>refresh(),3000);}
async function refresh() {
  if(!authenticated || document.hidden)return;
  if(polling)return polling;
  const epoch=generation;
  const work=(async()=>{
    try {
      const data=await api('profiles?summary=1','GET',undefined,true);if(epoch!==generation || !authenticated)return;profiles=data;profilesReceivedAt=performance.now();clearTimeout(freshnessTimer);freshnessTimer=setTimeout(()=>{if(authenticated){render();renderDetails();}},10050);render();
      const id=selectedID;
      const result=await api(id?'metrics?profile='+encodeURIComponent(id):'metrics','GET',undefined,true);if(epoch!==generation || !authenticated)return;if(id===selectedID){metricsData={...result,profileID:id,receivedAt:performance.now(),history:(result.history||[]).slice(-450)};renderMetrics();}
      if(detailID && $('#details').open)await loadDetails(detailID,true);
      setText($('#syncState'),'已更新 '+new Date().toLocaleTimeString('zh-CN',{hour12:false}));$('#syncState').classList.remove('stale');
    } catch(e) {if(authenticated && epoch===generation && !document.hidden){metricsData=null;renderMetrics();setText($('#syncState'),'暂时离线 · 3 秒后重试');$('#syncState').classList.add('stale');setText($('#chartStatus'),'数据暂未更新');}}
  })();
  polling=work;try{await work;}finally{if(polling===work)polling=null;schedule();}
}
$('#metricProfile').addEventListener('change',()=>{selectedID=$('#metricProfile').value;metricsData=null;renderMetrics();if(polling)polling.finally(()=>refresh());else refresh();});
document.addEventListener('visibilitychange',()=>{clearTimeout(timer);if(document.hidden){for(const c of pollRequests)c.abort();}else if(authenticated){if(polling)polling.finally(()=>refresh());else refresh();}});
async function edit(id) {const epoch=generation, form=$('#profileForm');form.reset();form.elements.id.value='';$('#clearSecrets').hidden=!id;$('#formError').hidden=true;$('#editorTitle').textContent=id?'编辑连接':'新建连接';$('#secretHint').textContent=id?'密码和 seed 留空会保留已保存值；如需删除，请勾选下方清除。':'每次认证自动生成新的验证码，支持带 = 填充的 seed。';if(id){const p=await api('profiles/'+encodeURIComponent(id));for(const key of ['id','name','username','ovpn','listen','totp_mode','engine','arguments','engine_config','config_format','working_directory'])form.elements[key].value=p[key]||'';for(const key of ['auto_reconnect','auto_connect'])form.elements[key].checked=!!p[key];}if(!form.elements.engine.value)form.elements.engine.value='openvpn';updateEngineForm();if(epoch===generation && authenticated)$('#editor').showModal();}
$('#profileForm').addEventListener('submit',async e=>{e.preventDefault();const f=e.target,body={};for(const key of ['id','name','username','password','totp_seed','totp_mode','ovpn','listen','engine','arguments','engine_config','config_format','working_directory'])body[key]=f.elements[key].value;for(const key of ['auto_reconnect','auto_connect','clear_password','clear_totp'])body[key]=f.elements[key].checked;const b=f.querySelector('[type=submit]');b.disabled=true;try{await api('profiles','POST',body);f.reset();$('#editor').close();await refresh();notice('连接已加密保存。');}catch(err){if(err.name!=='AbortError'){$('#formError').textContent=err.message;$('#formError').hidden=false;}}finally{b.disabled=false;}});
$('#file').addEventListener('change',async e=>{const file=e.target.files[0];if(!file)return;if(file.size>3*1024*1024){$('#formError').textContent='配置文件不能超过 3 MiB。';$('#formError').hidden=false;return;}$('#ovpn').value=await file.text();if(!$('#profileForm').elements.name.value)$('#profileForm').elements.name.value=file.name.replace(/\.(ovpn|conf)$/i,'');});
let engineInventory = [];
function renderEngineInventory() {
  let hint=$('#engineInventoryHint');if(!hint){hint=el('p',undefined,'hint');hint.id='engineInventoryHint';hint.setAttribute('role','status');$('#engineType').closest('label').after(hint);}
  const type=$('#engineType').value, item=engineInventory.find(e=>e.engine===type);
  const commit=/^[a-f0-9]{40}$/i.test(item?.commit||'')?item.commit:'', dependency=/^[a-f0-9]{40}$/i.test(item?.dependency_commit||'')?item.dependency_commit:'';
  setText(hint,type==='openvpn'?'内置 OpenVPN 引擎':!item?'引擎安装与版本信息暂不可用':item.available!==true?'服务端未安装此引擎，解析和启动前需安装对应构建':'引擎已安装'+(commit?' · 构建提交 '+commit.slice(0,12):' · 构建版本未提供')+(dependency?' · 依赖提交 '+dependency.slice(0,12):''));
  hint.title=[commit,dependency].filter(Boolean).join('\n');
}
async function loadEngineInventory() {const epoch=generation;try{const data=await api('engines');if(epoch===generation&&authenticated){engineInventory=Array.isArray(data)?data:[];renderEngineInventory();}}catch{if(epoch===generation&&authenticated){engineInventory=[];renderEngineInventory();}}}
function updateEngineForm() {
  renderEngineInventory();
  const f=$('#profileForm'), ext=f.elements.engine.value!=='openvpn';$('#vpnFields').hidden=ext;$('#vpnFields').disabled=ext;$('#engineFields').hidden=!ext;$('#engineFields').disabled=!ext;$('#ovpn').required=!ext;
  f.elements.arguments.placeholder=f.elements.engine.value==='flyssh'?'-N -L 127.0.0.1:8080:127.0.0.1:80 user@host':'-L "tcp://127.0.0.1:8080/127.0.0.1:80"';
  const format=f.elements.config_format;for(const o of format.options)o.disabled=f.elements.engine.value==='flyssh'?o.value!=='ssh':o.value==='ssh';if(!format.value || format.selectedOptions[0]?.disabled)format.value=f.elements.engine.value==='flyssh'?'ssh':'yaml';$('#inspectResult').replaceChildren();
}
$('#engineType').addEventListener('change',updateEngineForm);
$('#engineFields').addEventListener('input',()=>$('#inspectResult').replaceChildren());
$('#engineFile').addEventListener('change',async e=>{try{const file=e.target.files[0];if(!file)return;if(file.size>2*1024*1024)throw Error('引擎配置文件不能超过 2 MiB。');$('#engineConfig').value=await file.text();const f=$('#profileForm');if(!f.elements.name.value)f.elements.name.value=file.name.replace(/\.[^.]+$/,'');if(f.elements.engine.value==='gust')f.elements.config_format.value=/\.json$/i.test(file.name)?'json':'yaml';$('#inspectResult').replaceChildren();}catch(err){$('#formError').textContent=err.message;$('#formError').hidden=false;}});
$('#inspectEngine').addEventListener('click',async()=>{const f=$('#profileForm'), b=$('#inspectEngine'), body={};for(const k of ['engine','arguments','engine_config','config_format','working_directory'])body[k]=f.elements[k].value;const signature=JSON.stringify(body);b.disabled=true;$('#formError').hidden=true;try{const result=await api('engines/inspect','POST',body);const current={};for(const k of Object.keys(body))current[k]=f.elements[k].value;if(signature===JSON.stringify(current)&&$('#editor').open)listenerRows($('#inspectResult'),{listeners:result.listeners},true);}catch(err){if(err.name!=='AbortError'){$('#formError').textContent=err.message;$('#formError').hidden=false;}}finally{b.disabled=false;}});
async function openDetails(id) {detailID=id;detailSnapshot=null;$('#detailTitle').textContent=profiles.find(p=>p.id===id)?.name||'连接详情';$('#routes').textContent='正在加载路由…';$('#dns').textContent='—';$('#logs').textContent='正在加载日志…';$('#details').showModal();await loadDetails(id);}
async function loadDetails(id,background=false) {const snapshot=await api('profiles/'+encodeURIComponent(id)+'/status','GET',undefined,background);if(id!==detailID || !authenticated)return;detailSnapshot=snapshot;renderDetails();}
function renderDetails() {const p=profiles.find(p=>p.id===detailID),s=detailSnapshot;if(!p||!s)return;const state=external(p)?displayState(p):s.state;setText($('#detailTitle'),p.name+' · '+(stateNames[state]||state||'已停止'));setText($('#routes'),s.routes?.length?s.routes.join('\n'):'尚无下发路由');setText($('#dns'),'隧道地址：'+(s.tunnel_ip||'—')+'\nDNS：'+(s.dns?.join(', ')||'未下发（域名访问将拒绝解析）'));$('#vpnDetails').hidden=external(p);$('#engineDetails').hidden=!external(p);if(external(p)){setText($('#engineDetailState'),evidence(p));listenerRows($('#detailListeners'),p);}const logs=$('#logs'),atBottom=logs.scrollHeight-logs.clientHeight-logs.scrollTop<24;setText(logs,s.logs?.join('\n')||'暂无日志');if(atBottom)logs.scrollTop=logs.scrollHeight;}
async function copyText(text) {if(navigator.clipboard && window.isSecureContext){try{await navigator.clipboard.writeText(text);return;}catch{ /* LAN and browser policy fallback below. */ }}const focus=document.activeElement,area=el('textarea');area.value=text;area.className='clipboard-buffer';(document.querySelector('dialog[open]#exportDialog')||document.querySelector('dialog[open]')||document.body).append(area);area.focus();area.select();let copied=false;try{copied=document.execCommand('copy');}finally{area.remove();focus?.focus();}if(!copied)throw Error('浏览器未允许复制，请选择预览内容手动复制。');}
$('#copyRoutes').addEventListener('click',async()=>{try{const nets=(detailSnapshot?.routes||[]).map(r=>r.match(/(?:^|\s)([0-9a-fA-F:.]+\/\d+)(?:\s|$)/)?.[1]).filter(Boolean);if(!nets.length)throw Error('尚无可复制的路由，请先连接 VPN。');await copyText([...new Set(nets)].join('\n'));$('#copyRoutes').textContent='已复制';setTimeout(()=>$('#copyRoutes').textContent='复制网段',1500);}catch(e){notice(e.message,true);}});
function exportHelp() {const f=$('#exportForm');setText($('#exportHelp'),f.elements.format.value==='mihomo'?'将代理与 rules 片段合并到现有 mihomo 配置，检查规则顺序后使用。':'先在 Proxifier 添加下方地址的 SOCKS5 代理，再将结果粘贴到规则 Target Hosts，Action 选择该代理，并保留 Default → Direct。这是官方支持的目标范围文本，不是 .ppx 配置。');}
function invalidateExport() {exportRevision++;exportResult=null;$('#exportContent').value='';$('#copyExport').disabled=true;$('#downloadExport').disabled=true;$('#exportWarnings').textContent='';exportHelp();}
$('#openExport').addEventListener('click',()=>{const p=profiles.find(p=>p.id===detailID);if(!p)return;const f=$('#exportForm');f.reset();f.dataset.profile=p.id;f.elements.host.value=location.hostname.replace(/^\[|\]$/g,'');f.elements.name.value=p.name;const loopback=/^(localhost|127\.[\d.]+|\[::1\]|::1):/i.test(p.listen);setText($('#exportEndpoint'),'SOCKS5 监听 '+p.listen+' · 端口自动取自连接配置。'+(loopback?' 当前仅监听 loopback，只能在代理所在本机使用；局域网访问需修改监听地址。':''));invalidateExport();$('#exportError').hidden=true;$('#exportDialog').showModal();});
$('#exportForm').addEventListener('input',invalidateExport);
$('#exportForm').addEventListener('submit',async e=>{e.preventDefault();const f=e.target,b=f.querySelector('[type=submit]');invalidateExport();const revision=exportRevision;b.disabled=true;$('#exportError').hidden=true;try{const result=await api('profiles/'+encodeURIComponent(f.dataset.profile)+'/export','POST',{format:f.elements.format.value,host:f.elements.host.value.trim(),name:f.elements.name.value.trim()});if(revision!==exportRevision || !$('#exportDialog').open)return;exportResult=result;$('#exportContent').value=result.content;setText($('#exportWarnings'),(result.warnings||[]).join('\n'));$('#copyExport').disabled=false;$('#downloadExport').disabled=false;}catch(err){if(err.name!=='AbortError'){$('#exportError').textContent=err.message;$('#exportError').hidden=false;}}finally{b.disabled=false;}});
$('#copyExport').addEventListener('click',async()=>{if(!exportResult)return;try{await copyText(exportResult.content);$('#copyExport').textContent='已复制';setTimeout(()=>$('#copyExport').textContent='复制配置',1500);}catch(e){$('#exportError').textContent=e.message;$('#exportError').hidden=false;}});
$('#downloadExport').addEventListener('click',()=>{if(!exportResult)return;const url=URL.createObjectURL(new Blob([exportResult.content],{type:exportResult.mime||'text/plain;charset=utf-8'})),a=el('a');a.href=url;a.download=exportResult.filename||'routes.txt';document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);});
$('#closeExport').addEventListener('click',()=>$('#exportDialog').close());$('#exportDialog').addEventListener('close',invalidateExport);
$('#add').addEventListener('click',()=>edit().catch(e=>notice(e.message,true)));for(const id of ['closeEditor','cancelEditor'])$('#'+id).addEventListener('click',()=>{$('#profileForm').reset();$('#editor').close();});$('#closeDetails').addEventListener('click',()=>$('#details').close());$('#details').addEventListener('close',()=>{detailID='';detailSnapshot=null;});$('#editor').addEventListener('close',()=>{$('#profileForm').elements.password.value='';$('#profileForm').elements.totp_seed.value='';});
function showLogin() {generation++;authenticated=false;clearTimeout(timer);for(const c of requests)c.abort();profiles=[];cards.clear();detailID='';detailSnapshot=null;selectedID='';metricsData=null;$('#profiles').replaceChildren();$('#loginPanel').hidden=false;$('#workspace').hidden=true;$('#notice').hidden=true;for(const d of document.querySelectorAll('dialog[open]'))d.close();$('#accountForm').reset();$('#profileForm').reset();}
async function checkAuth() {const a=await api('auth');if(a.authenticated){authenticated=true;engineInventory=[];void loadEngineInventory();currentUsername=a.username;$('#loginPanel').hidden=true;$('#workspace').hidden=false;await refresh();schedule();}else showLogin();}
$('#loginForm').addEventListener('submit',async e=>{e.preventDefault();const f=e.target,b=f.querySelector('button');b.disabled=true;$('#loginError').hidden=true;try{await api('login','POST',{username:f.elements.username.value,password:f.elements.password.value});f.elements.password.value='';await checkAuth();}catch(err){if(err.name!=='AbortError'){$('#loginError').textContent=err.message;$('#loginError').hidden=false;}}finally{b.disabled=false;}});
$('#logoutButton').addEventListener('click',async()=>{showLogin();try{await api('logout','POST',{});}catch(e){$('#loginError').textContent='退出请求失败，请重新登录后重试。';$('#loginError').hidden=false;}});
$('#accountButton').addEventListener('click',()=>{$('#accountForm').reset();$('#accountForm').elements.username.value=currentUsername;$('#accountError').hidden=true;$('#accountDialog').showModal();});$('#closeAccount').addEventListener('click',()=>$('#accountDialog').close());$('#accountDialog').addEventListener('close',()=>$('#accountForm').reset());
$('#accountForm').addEventListener('submit',async e=>{e.preventDefault();const f=e.target,b=f.querySelector('[type=submit]');$('#accountError').hidden=true;if(f.elements.password.value!==f.elements.confirm_password.value){$('#accountError').textContent='两次输入的新密码不一致。';$('#accountError').hidden=false;return;}b.disabled=true;try{await api('account','POST',{current_password:f.elements.current_password.value,username:f.elements.username.value,password:f.elements.password.value});const username=f.elements.username.value;showLogin();$('#loginForm').elements.username.value=username;}catch(err){if(err.name!=='AbortError'){$('#accountError').textContent=err.message;$('#accountError').hidden=false;}}finally{b.disabled=false;}});
checkAuth().catch(e=>{if(e.name!=='AbortError'){$('#loginError').textContent=e.message;$('#loginError').hidden=false;}});
