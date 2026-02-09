/**
 * Admin Panel HTML Templates
 * Collapsible sidebar, redirect URI display, download method settings
 */

export function getAdminLoginHTML(): string {
  return `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Admin Login</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.0/font/bootstrap-icons.css">
<style>body{min-height:100vh;display:flex;align-items:center;background:linear-gradient(135deg,#1a1a2e,#16213e,#0f3460)}.card{border:none;border-radius:12px;box-shadow:0 8px 32px rgba(0,0,0,.3)}</style>
</head><body><div class="container"><div class="row justify-content-center"><div class="col-md-4"><div class="card"><div class="card-body p-4">
<h4 class="text-center mb-4"><i class="bi bi-shield-lock"></i> Admin Login</h4>
<div id="error" class="alert alert-danger d-none"></div>
<form id="f"><div class="mb-3"><label class="form-label">Username</label><input type="text" class="form-control" name="username" required autofocus></div>
<div class="mb-3"><label class="form-label">Password</label><input type="password" class="form-control" name="password" required></div>
<button type="submit" class="btn btn-primary w-100">Sign In</button></form></div></div></div></div></div>
<script>document.getElementById('f').onsubmit=async(e)=>{e.preventDefault();const b=e.target.querySelector('button');b.disabled=true;b.textContent='Signing in...';try{const r=await fetch('/admin/login',{method:'POST',body:new FormData(e.target)});const d=await r.json();if(d.ok)location.reload();else{document.getElementById('error').textContent=d.error||'Login failed';document.getElementById('error').classList.remove('d-none')}}finally{b.disabled=false;b.textContent='Sign In'}};</script></body></html>`;
}

export function getAdminDashboardHTML(origin: string): string {
  const redirectUri = origin + '/google_callback';
  return `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Admin Panel</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.0/font/bootstrap-icons.css">
<style>
:root{--sb-width:240px;--sb-collapsed:60px;--sb-bg:#1a1d21;--sb-hover:rgba(255,255,255,.08)}
*{box-sizing:border-box}body{background:#f0f2f5;margin:0;font-family:system-ui,-apple-system,sans-serif}
.sb{background:var(--sb-bg);min-height:100vh;width:var(--sb-width);position:fixed;top:0;left:0;z-index:100;transition:width .25s ease;overflow:hidden;display:flex;flex-direction:column}
.sb.collapsed{width:var(--sb-collapsed)}
.sb .brand{padding:16px;display:flex;align-items:center;gap:10px;color:#fff;border-bottom:1px solid rgba(255,255,255,.1)}
.sb .brand h5{margin:0;white-space:nowrap;overflow:hidden;transition:opacity .2s}
.sb.collapsed .brand h5,.sb.collapsed .brand small,.sb.collapsed .nav-text,.sb.collapsed .sb-footer .btn span{display:none}
.sb .nav-link{color:#9ca3af;padding:10px 16px;border-radius:8px;margin:2px 8px;display:flex;align-items:center;gap:10px;text-decoration:none;white-space:nowrap;transition:all .15s}
.sb .nav-link:hover,.sb .nav-link.active{color:#fff;background:var(--sb-hover)}
.sb .nav-link i{font-size:18px;width:24px;text-align:center;flex-shrink:0}
.sb-footer{padding:12px 8px;margin-top:auto;border-top:1px solid rgba(255,255,255,.1)}
.sb-footer .btn{width:100%;margin-bottom:6px;display:flex;align-items:center;gap:8px;justify-content:center}
.sb-toggle{position:absolute;top:12px;right:-14px;width:28px;height:28px;border-radius:50%;background:#fff;border:1px solid #ddd;cursor:pointer;display:flex;align-items:center;justify-content:center;z-index:101;box-shadow:0 2px 8px rgba(0,0,0,.15);transition:transform .25s}
.sb.collapsed .sb-toggle{transform:rotate(180deg)}
.main{margin-left:var(--sb-width);padding:24px;min-height:100vh;transition:margin-left .25s ease}
.main.expanded{margin-left:var(--sb-collapsed)}
.card{border:none;border-radius:12px;box-shadow:0 1px 8px rgba(0,0,0,.06)}
.sc{transition:transform .15s}.sc:hover{transform:translateY(-2px)}
.table th{font-weight:600;font-size:.8rem;text-transform:uppercase;color:#6c757d;letter-spacing:.5px}
#tc{position:fixed;top:16px;right:16px;z-index:9999}
@media(max-width:768px){.sb{width:var(--sb-collapsed)}.sb .nav-text,.sb .brand h5,.sb .brand small,.sb-footer .btn span{display:none}.main{margin-left:var(--sb-collapsed)}}
</style>
</head><body>
<div id="tc"></div>

<!-- Sidebar -->
<div class="sb" id="sidebar">
<div class="sb-toggle" onclick="toggleSidebar()"><i class="bi bi-chevron-left" id="sbIcon"></i></div>
<div class="brand"><i class="bi bi-gear-fill" style="font-size:24px"></i><div><h5>Admin</h5><small class="text-muted">Drive Index</small></div></div>
<nav class="nav flex-column mt-2">
<a class="nav-link active" href="#" data-tab="dashboard"><i class="bi bi-speedometer2"></i><span class="nav-text">Dashboard</span></a>
<a class="nav-link" href="#" data-tab="credentials"><i class="bi bi-person-badge"></i><span class="nav-text">Credentials</span></a>
<a class="nav-link" href="#" data-tab="drives"><i class="bi bi-hdd-stack"></i><span class="nav-text">Drives</span></a>
<a class="nav-link" href="#" data-tab="config"><i class="bi bi-sliders"></i><span class="nav-text">Configuration</span></a>
<a class="nav-link" href="#" data-tab="sa"><i class="bi bi-key"></i><span class="nav-text">Service Accounts</span></a>
<a class="nav-link" href="#" data-tab="google-login"><i class="bi bi-google"></i><span class="nav-text">Google Login</span></a>
<a class="nav-link" href="#" data-tab="security"><i class="bi bi-shield-check"></i><span class="nav-text">Security</span></a>
</nav>
<div class="sb-footer">
<a href="/" class="btn btn-outline-light btn-sm" target="_blank"><i class="bi bi-box-arrow-up-right"></i><span>View Site</span></a>
<a href="/admin/logout" class="btn btn-outline-danger btn-sm"><i class="bi bi-box-arrow-left"></i><span>Logout</span></a>
</div>
</div>

<!-- Main Content -->
<div class="main" id="main"></div>

<!-- Drive Modal -->
<div class="modal fade" id="dm" tabindex="-1"><div class="modal-dialog"><div class="modal-content">
<div class="modal-header"><h5 class="modal-title" id="dmt">Add Drive</h5><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div>
<div class="modal-body"><input type="hidden" id="dei">
<div class="mb-3"><label class="form-label">Drive Name</label><input type="text" class="form-control" id="dn" placeholder="My Shared Drive"></div>
<div class="mb-3"><label class="form-label">Drive / Folder ID</label><input type="text" class="form-control font-monospace" id="di" placeholder="0ABCD... or root">
<button class="btn btn-outline-info btn-sm mt-1" onclick="fetchRoot()"><i class="bi bi-arrow-repeat"></i> Fetch Root Info</button>
<small id="fetchResult" class="d-block mt-1 text-muted"></small></div>
<div class="form-check mb-3"><input class="form-check-input" type="checkbox" id="dp"><label class="form-check-label" for="dp">Protect file links</label></div>
</div><div class="modal-footer"><button class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button><button class="btn btn-primary" onclick="saveDrive()">Save</button></div>
</div></div></div>

<!-- Config Modal -->
<div class="modal fade" id="cm" tabindex="-1"><div class="modal-dialog"><div class="modal-content">
<div class="modal-header"><h5 class="modal-title">Add Config Key</h5><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div>
<div class="modal-body"><div class="mb-3"><label class="form-label">Key</label><input type="text" class="form-control font-monospace" id="ck" placeholder="category.key_name"></div>
<div class="mb-3"><label class="form-label">Value</label><input type="text" class="form-control" id="cv"></div></div>
<div class="modal-footer"><button class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button><button class="btn btn-primary" onclick="addCfgKey()">Add</button></div>
</div></div></div>

<!-- SA Modal -->
<div class="modal fade" id="sm" tabindex="-1"><div class="modal-dialog modal-lg"><div class="modal-content">
<div class="modal-header"><h5 class="modal-title">Add Service Account</h5><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div>
<div class="modal-body"><textarea class="form-control font-monospace" id="sj" rows="10" placeholder="Paste service account JSON..."></textarea></div>
<div class="modal-footer"><button class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button><button class="btn btn-primary" onclick="addSA()">Add</button></div>
</div></div></div>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
<script>
const REDIRECT_URI='${redirectUri}';
let AD=[],AC=[],ASA=[];
const $=s=>document.getElementById(s),$$=s=>document.querySelectorAll(s);
const esc=s=>s==null?'':String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');

// Sidebar toggle
function toggleSidebar(){const sb=$('sidebar'),mn=$('main');sb.classList.toggle('collapsed');mn.classList.toggle('expanded');localStorage.setItem('sb_collapsed',sb.classList.contains('collapsed'))}
if(localStorage.getItem('sb_collapsed')==='true'){$('sidebar').classList.add('collapsed');$('main').classList.add('expanded')}

function toast(m,t='success'){const id='t'+Date.now();$('tc').insertAdjacentHTML('beforeend','<div id="'+id+'" class="toast show align-items-center text-bg-'+t+' border-0 mb-2" role="alert"><div class="d-flex"><div class="toast-body">'+m+'</div><button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button></div></div>');setTimeout(()=>{const e=$(id);if(e)e.remove()},3000)}
async function api(p,b){const o=b?{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(b)}:{};const r=await fetch('/admin/api/'+p,o);const d=await r.json();if(d.error)throw new Error(d.error);return d}

const BOOL_KEYS=['auth.enable_login','auth.enable_signup','auth.search_all_drives','auth.enable_cors_file_down','auth.enable_password_file_verify','auth.direct_link_protection','auth.disable_anonymous_download','auth.enable_ip_lock','auth.single_session','ui.logo_image','ui.fixed_header','ui.fixed_footer','ui.hide_footer','ui.credit','ui.display_size','ui.display_time','ui.display_download','ui.disable_player','ui.disable_video_download','ui.allow_selecting_files','ui.second_domain_for_dl','ui.render_head_md','ui.render_readme_md','ui.show_logout_button'];
const SELECT_KEYS={'site.download_mode':['path','id'],'player.player':['videojs','plyr','dplayer','jwplayer'],'ui.theme':['cerulean','cosmo','cyborg','darkly','flatly','journal','litera','lumen','lux','materia','minty','morph','pulse','quartz','sandstone','simplex','sketchy','slate','solar','spacelab','superhero','united','vapor','yeti','zephyr']};

function sc(i,l,v,c){return '<div class="col-md-3"><div class="card sc border-start border-4 border-'+c+'"><div class="card-body py-3"><div class="d-flex align-items-center"><div class="flex-grow-1"><div class="text-muted small">'+l+'</div><div class="h4 mb-0">'+v+'</div></div><i class="bi '+i+' fs-2 text-'+c+'"></i></div></div></div></div>'}

// Tab navigation
document.querySelectorAll('[data-tab]').forEach(a=>{a.addEventListener('click',e=>{e.preventDefault();const t=a.dataset.tab;document.querySelectorAll('.sb .nav-link').forEach(n=>n.classList.remove('active'));a.classList.add('active');loadTab(t)})});

function loadTab(t){$('main').innerHTML='<div class="text-center py-5"><div class="spinner-border"></div></div>';switch(t){case 'dashboard':return loadDash();case 'credentials':return loadCreds();case 'drives':return loadDrives();case 'config':return loadCfg();case 'sa':return loadSA();case 'google-login':return loadGL();case 'security':return loadSec()}}

// ===== Dashboard =====
async function loadDash(){try{const[d,c,s]=await Promise.all([api('drives'),api('config'),api('service-accounts')]);AD=d.drives;AC=c.config;ASA=s.accounts;const gv=k=>(AC.find(x=>x.key===k)||{}).value||'';$('main').innerHTML='<h4 class="mb-4"><i class="bi bi-speedometer2"></i> Dashboard</h4><div class="row g-3 mb-4">'+sc('bi-hdd-stack','Drives',AD.length,'primary')+sc('bi-key','Service Accounts',ASA.length,'warning')+sc('bi-sliders','Config Keys',AC.length,'info')+sc('bi-shield-check','Login',gv('auth.enable_login')==='true'?'Enabled':'Disabled',gv('auth.enable_login')==='true'?'success':'secondary')+'</div><div class="card"><div class="card-header"><h6 class="mb-0">Quick Overview</h6></div><div class="card-body"><div class="row mb-2"><div class="col-md-6"><strong>Site Name:</strong> '+esc(gv('site.name')||'Google Drive Index')+'</div><div class="col-md-6"><strong>Download Mode:</strong> <span class="badge bg-info">'+esc(gv('site.download_mode')||'path')+'</span></div></div><hr><h6>Drives</h6>'+(AD.length?'<div class="list-group list-group-flush">'+AD.map(x=>'<div class="list-group-item d-flex justify-content-between align-items-center"><span><i class="bi bi-hdd me-2"></i>'+esc(x.name)+'</span><code class="small text-muted">'+esc(x.drive_id)+'</code></div>').join('')+'</div>':'<p class="text-muted mb-0">No drives configured yet.</p>')+'</div></div>'}catch(e){$('main').innerHTML='<div class="alert alert-danger">'+esc(e.message)+'</div>'}}

// ===== Credentials =====
async function loadCreds(){try{const d=await api('credentials');const c=d.credentials;$('main').innerHTML='<h4 class="mb-4"><i class="bi bi-person-badge"></i> OAuth Credentials</h4><div class="card"><div class="card-header"><h6 class="mb-0">Google OAuth2 Credentials</h6></div><div class="card-body"><p class="text-muted small mb-3">Credentials are never displayed once saved. Enter new values to update.</p><div class="mb-3"><label class="form-label">Client ID '+(c['auth.client_id']?'<span class="badge bg-success">Set</span>':'<span class="badge bg-danger">Not set</span>')+'</label><input type="text" class="form-control" id="cr-cid" placeholder="Enter client ID"></div><div class="mb-3"><label class="form-label">Client Secret '+(c['auth.client_secret']?'<span class="badge bg-success">Set</span>':'<span class="badge bg-danger">Not set</span>')+'</label><input type="password" class="form-control" id="cr-cs" placeholder="Enter client secret"></div><div class="mb-3"><label class="form-label">Refresh Token '+(c['auth.refresh_token']?'<span class="badge bg-success">Set</span>':'<span class="badge bg-danger">Not set</span>')+'</label><input type="password" class="form-control" id="cr-rt" placeholder="Enter refresh token"></div><button class="btn btn-primary" onclick="saveCreds()"><i class="bi bi-save"></i> Save Credentials</button></div></div>'}catch(e){$('main').innerHTML='<div class="alert alert-danger">'+esc(e.message)+'</div>'}}
async function saveCreds(){const b={};const cid=$('cr-cid').value.trim();if(cid)b.client_id=cid;const cs=$('cr-cs').value.trim();if(cs)b.client_secret=cs;const rt=$('cr-rt').value.trim();if(rt)b.refresh_token=rt;if(!Object.keys(b).length){toast('Enter at least one field','warning');return}try{await api('credentials/save',b);toast('Credentials saved!');loadCreds()}catch(e){toast(e.message,'danger')}}

// ===== Drives =====
async function loadDrives(){try{const d=await api('drives');AD=d.drives;$('main').innerHTML='<div class="d-flex justify-content-between align-items-center mb-4"><h4 class="mb-0"><i class="bi bi-hdd-stack"></i> Drives</h4><button class="btn btn-primary" onclick="showDM()"><i class="bi bi-plus-lg"></i> Add Drive</button></div><div class="card"><div class="card-body p-0"><table class="table table-hover mb-0"><thead><tr><th>#</th><th>Name</th><th>Drive ID</th><th>Protected</th><th>Status</th><th>Actions</th></tr></thead><tbody>'+(AD.length?AD.map((x,i)=>'<tr><td>'+i+'</td><td><strong>'+esc(x.name)+'</strong></td><td><code class="small">'+esc(x.drive_id)+'</code></td><td>'+(x.protect_file_link?'<span class="badge bg-warning">Yes</span>':'<span class="badge bg-secondary">No</span>')+'</td><td>'+(x.enabled?'<span class="badge bg-success">Active</span>':'<span class="badge bg-danger">Off</span>')+'</td><td><button class="btn btn-sm btn-outline-primary me-1" onclick="editDr('+x.id+')"><i class="bi bi-pencil"></i></button><button class="btn btn-sm btn-outline-danger" onclick="delDr('+x.id+')"><i class="bi bi-trash"></i></button></td></tr>').join(''):'<tr><td colspan="6" class="text-center text-muted py-4">No drives configured. Click "Add Drive" to get started.</td></tr>')+'</tbody></table></div></div>'}catch(e){$('main').innerHTML='<div class="alert alert-danger">'+esc(e.message)+'</div>'}}
function showDM(){$('dmt').textContent='Add Drive';$('dei').value='';$('dn').value='';$('di').value='';$('dp').checked=false;$('fetchResult').textContent='';new bootstrap.Modal($('dm')).show()}
function editDr(id){const d=AD.find(x=>x.id===id);if(!d)return;$('dmt').textContent='Edit Drive';$('dei').value=d.id;$('dn').value=d.name;$('di').value=d.drive_id;$('dp').checked=!!d.protect_file_link;$('fetchResult').textContent='';new bootstrap.Modal($('dm')).show()}
async function saveDrive(){const eid=$('dei').value;const b={name:$('dn').value,drive_id:$('di').value,protect_file_link:$('dp').checked};try{if(eid)await api('drives/update',{...b,id:parseInt(eid),enabled:true});else await api('drives/add',b);bootstrap.Modal.getInstance($('dm')).hide();toast(eid?'Drive updated':'Drive added');loadDrives()}catch(e){toast(e.message,'danger')}}
async function delDr(id){if(!confirm('Delete this drive?'))return;try{await api('drives/delete',{id});toast('Drive deleted');loadDrives()}catch(e){toast(e.message,'danger')}}
async function fetchRoot(){const did=$('di').value.trim();if(!did){toast('Enter a drive ID first','warning');return}$('fetchResult').innerHTML='<span class="spinner-border spinner-border-sm"></span> Fetching...';try{const d=await api('drives/fetch-root',{drive_id:did});$('fetchResult').innerHTML='<span class="text-success"><i class="bi bi-check-circle"></i> '+esc(d.name)+' ('+esc(d.root_id)+')</span>';if(d.name&&!$('dn').value)$('dn').value=d.name}catch(e){$('fetchResult').innerHTML='<span class="text-danger"><i class="bi bi-x-circle"></i> '+esc(e.message)+'</span>'}}

// ===== Config =====
async function loadCfg(){try{const d=await api('config');AC=d.config;const grp={};AC.forEach(c=>{const cat=c.key.split('.')[0]||'other';if(!grp[cat])grp[cat]=[];grp[cat].push(c)});$('main').innerHTML='<div class="d-flex justify-content-between align-items-center mb-4"><h4 class="mb-0"><i class="bi bi-sliders"></i> Configuration</h4><div><button class="btn btn-outline-primary btn-sm me-2" onclick="showCM()"><i class="bi bi-plus-lg"></i> Add Key</button><button class="btn btn-primary btn-sm" onclick="saveCfg()"><i class="bi bi-save"></i> Save All</button></div></div>'+Object.keys(grp).sort().map(cat=>'<div class="card mb-3"><div class="card-header d-flex justify-content-between"><h6 class="mb-0 text-capitalize">'+cat+'</h6><span class="badge bg-secondary">'+grp[cat].length+'</span></div><div class="card-body p-0"><table class="table table-sm mb-0"><tbody>'+grp[cat].map(c=>{const isBool=BOOL_KEYS.includes(c.key);const selOpts=SELECT_KEYS[c.key];let input;if(isBool)input='<select class="form-select form-select-sm ci" data-key="'+esc(c.key)+'"><option value="true"'+(c.value==='true'?' selected':'')+'>true</option><option value="false"'+(c.value!=='true'?' selected':'')+'>false</option></select>';else if(selOpts)input='<select class="form-select form-select-sm ci" data-key="'+esc(c.key)+'">'+selOpts.map(o=>'<option value="'+o+'"'+(c.value===o?' selected':'')+'>'+o+'</option>').join('')+'</select>';else input='<input type="text" class="form-control form-control-sm ci" data-key="'+esc(c.key)+'" value="'+esc(c.value)+'">';return '<tr><td style="width:35%"><code class="small">'+esc(c.key)+'</code></td><td>'+input+'</td><td style="width:40px"><button class="btn btn-sm btn-outline-danger" onclick="delCfg(\''+esc(c.key).replace(/'/g,"\\'")+'\')"><i class="bi bi-trash"></i></button></td></tr>'}).join('')+'</tbody></table></div></div>').join('')||'<div class="text-muted text-center py-4">No config keys found.</div>'}catch(e){$('main').innerHTML='<div class="alert alert-danger">'+esc(e.message)+'</div>'}}
function showCM(){$('ck').value='';$('cv').value='';new bootstrap.Modal($('cm')).show()}
async function addCfgKey(){const k=$('ck').value.trim(),v=$('cv').value;if(!k){toast('Key required','warning');return}try{await api('config/set',{key:k,value:v});bootstrap.Modal.getInstance($('cm')).hide();toast('Key added');loadCfg()}catch(e){toast(e.message,'danger')}}
async function delCfg(k){if(!confirm('Delete "'+k+'"?'))return;try{await api('config/delete',{key:k});toast('Deleted');loadCfg()}catch(e){toast(e.message,'danger')}}
async function saveCfg(){const items=[];document.querySelectorAll('.ci').forEach(el=>items.push({key:el.dataset.key,value:el.value}));try{await api('config/bulk',{items});toast('All settings saved!')}catch(e){toast(e.message,'danger')}}

// ===== Service Accounts =====
async function loadSA(){try{const d=await api('service-accounts');ASA=d.accounts;$('main').innerHTML='<div class="d-flex justify-content-between align-items-center mb-4"><h4 class="mb-0"><i class="bi bi-key"></i> Service Accounts</h4><button class="btn btn-primary" onclick="showSM()"><i class="bi bi-plus-lg"></i> Add</button></div><div class="card"><div class="card-body p-0"><table class="table table-hover mb-0"><thead><tr><th>#</th><th>Name</th><th>Status</th><th>Actions</th></tr></thead><tbody>'+(ASA.length?ASA.map((s,i)=>'<tr><td>'+(i+1)+'</td><td>'+esc(s.name)+'</td><td>'+(s.enabled?'<span class="badge bg-success">Active</span>':'<span class="badge bg-danger">Disabled</span>')+'</td><td><button class="btn btn-sm btn-outline-danger" onclick="delSA('+s.id+')"><i class="bi bi-trash"></i></button></td></tr>').join(''):'<tr><td colspan="4" class="text-center text-muted py-4">No service accounts.</td></tr>')+'</tbody></table></div></div>'}catch(e){$('main').innerHTML='<div class="alert alert-danger">'+esc(e.message)+'</div>'}}
function showSM(){$('sj').value='';new bootstrap.Modal($('sm')).show()}
async function addSA(){const j=$('sj').value.trim();if(!j){toast('JSON required','warning');return}try{JSON.parse(j)}catch{toast('Invalid JSON','danger');return}try{await api('service-accounts/add',{json_data:j});bootstrap.Modal.getInstance($('sm')).hide();toast('Service account added');loadSA()}catch(e){toast(e.message,'danger')}}
async function delSA(id){if(!confirm('Delete this service account?'))return;try{await api('service-accounts/delete',{id});toast('Deleted');loadSA()}catch(e){toast(e.message,'danger')}}

// ===== Google Login (with redirect URI) =====
async function loadGL(){try{const d=await api('google-login');
var h='<h4 class="mb-4"><i class="bi bi-google"></i> Google Login</h4>';
h+='<div class="card mb-3"><div class="card-header"><h6 class="mb-0">Redirect URI for Cloud Console</h6></div>';
h+='<div class="card-body"><div class="alert alert-info mb-0"><i class="bi bi-info-circle"></i> Add this <strong>Authorized redirect URI</strong> in Google Cloud Console:<br><br>';
h+='<div class="input-group"><input type="text" class="form-control font-monospace" value="'+REDIRECT_URI+'" readonly id="ruri">';
h+='<button class="btn btn-outline-secondary" onclick="navigator.clipboard.writeText(document.getElementById(\\\'ruri\\\').value);toast(\\\'Copied!\\\')"><i class="bi bi-clipboard"></i></button></div></div></div></div>';
h+='<div class="card"><div class="card-header"><h6 class="mb-0">Google Login Settings</h6></div><div class="card-body">';
h+='<p class="text-muted small">Credentials are never displayed once saved.</p>';
h+='<div class="mb-3"><label class="form-label">Enable Google Login</label><select class="form-select" id="gl-en"><option value="true"'+(d['auth.enable_social_login']?' selected':'')+'>Enabled</option><option value="false"'+(!d['auth.enable_social_login']?' selected':'')+'>Disabled</option></select></div>';
h+='<div class="mb-3"><label class="form-label">Client ID '+(d['google_login.client_id']?'<span class="badge bg-success">Set</span>':'<span class="badge bg-danger">Not set</span>')+'</label><input type="text" class="form-control" id="gl-cid" placeholder="Enter Google Client ID"></div>';
h+='<div class="mb-3"><label class="form-label">Client Secret '+(d['google_login.client_secret']?'<span class="badge bg-success">Set</span>':'<span class="badge bg-danger">Not set</span>')+'</label><input type="password" class="form-control" id="gl-cs" placeholder="Enter Google Client Secret"></div>';
h+='<button class="btn btn-primary" onclick="saveGL()"><i class="bi bi-save"></i> Save</button></div></div>';
$('main').innerHTML=h;
}catch(e){$('main').innerHTML='<div class="alert alert-danger">'+esc(e.message)+'</div>'}}
async function saveGL(){const b={enabled:$('gl-en').value==='true'};const cid=$('gl-cid').value.trim();if(cid)b.client_id=cid;const cs=$('gl-cs').value.trim();if(cs)b.client_secret=cs;try{await api('google-login/save',b);toast('Saved!');loadGL()}catch(e){toast(e.message,'danger')}}

// ===== Security =====
async function loadSec(){try{const d=await api('security');
var h='<h4 class="mb-4"><i class="bi bi-shield-check"></i> Security</h4>';
h+='<div class="card mb-3"><div class="card-header"><h6 class="mb-0">Admin Credentials</h6></div><div class="card-body">';
h+='<div class="row g-3"><div class="col-md-6"><label class="form-label">Username</label><input type="text" class="form-control" id="su" value="'+esc(d['admin.username'])+'"></div>';
h+='<div class="col-md-6"><label class="form-label">New Password '+(d['admin.password_set']?'<span class="badge bg-success">Set</span>':'<span class="badge bg-danger">Not set</span>')+'</label><input type="password" class="form-control" id="sp" placeholder="Enter new password"></div></div>';
h+='<button class="btn btn-primary mt-3" onclick="saveSec()"><i class="bi bi-save"></i> Save</button></div></div>';
h+='<div class="card mb-3"><div class="card-header"><h6 class="mb-0">Blocked Regions / ASNs</h6></div><div class="card-body">';
h+='<div class="mb-3"><label class="form-label">Blocked Regions</label><input type="text" class="form-control" id="sr" value="'+esc(d['security.blocked_regions'])+'" placeholder="CN, RU"></div>';
h+='<div class="mb-3"><label class="form-label">Blocked ASNs</label><input type="text" class="form-control" id="sa2" value="'+esc(d['security.blocked_asn'])+'" placeholder="12345, 67890"></div>';
h+='<button class="btn btn-primary" onclick="saveBlk()"><i class="bi bi-save"></i> Save</button></div></div>';
h+='<div class="card"><div class="card-header"><h6 class="mb-0">Crypto Keys</h6></div><div class="card-body">';
h+='<p>Encryption Key: '+(d['security.crypto_key_set']?'<span class="badge bg-success">Set</span>':'<span class="badge bg-danger">Not set</span>')+' <button class="btn btn-outline-warning btn-sm ms-2" onclick="regenKey(\'crypto\')">Regenerate</button></p>';
h+='<p>HMAC Key: '+(d['security.hmac_key_set']?'<span class="badge bg-success">Set</span>':'<span class="badge bg-danger">Not set</span>')+' <button class="btn btn-outline-warning btn-sm ms-2" onclick="regenKey(\'hmac\')">Regenerate</button></p>';
h+='</div></div>';
$('main').innerHTML=h;
}catch(e){$('main').innerHTML='<div class="alert alert-danger">'+esc(e.message)+'</div>'}}
async function saveSec(){const b={};const u=$('su').value.trim();if(u)b.admin_username=u;const p=$('sp').value;if(p)b.admin_password=p;if(!Object.keys(b).length){toast('Nothing to save','warning');return}try{await api('security/save',b);toast('Saved!');loadSec()}catch(e){toast(e.message,'danger')}}
async function saveBlk(){try{await api('security/save',{blocked_regions:$('sr').value,blocked_asn:$('sa2').value});toast('Saved!')}catch(e){toast(e.message,'danger')}}
async function regenKey(t){if(!confirm('Regenerate '+t+' key?'))return;try{await api('security/regenerate-key',{type:t});toast(t+' key regenerated!');loadSec()}catch(e){toast(e.message,'danger')}}

// Init
loadDash();
</script></body></html>`;
}
