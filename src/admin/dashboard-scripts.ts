/**
 * Admin dashboard JS sections that were too large for inline template
 */

export function getGoogleLoginScript(): string {
  return `
// ===== Google Login (with redirect URI display) =====
async function loadGL(){try{const d=await api('google-login');
$('main').innerHTML='<h4 class="mb-4"><i class="bi bi-google"></i> Google Login</h4>'+
'<div class="card mb-3"><div class="card-header"><h6 class="mb-0">Redirect URI for Google Cloud Console</h6></div>'+
'<div class="card-body"><div class="alert alert-info mb-0"><i class="bi bi-info-circle"></i> Add the following <strong>Authorized redirect URI</strong> in your Google Cloud Console OAuth 2.0 credentials:<br><br>'+
'<div class="input-group"><input type="text" class="form-control font-monospace" value="'+REDIRECT_URI+'" readonly id="ruri">'+
'<button class="btn btn-outline-secondary" onclick="navigator.clipboard.writeText(document.getElementById(\\'ruri\\').value);toast(\\'Copied!\\')"><i class="bi bi-clipboard"></i></button></div></div></div></div>'+
'<div class="card"><div class="card-header"><h6 class="mb-0">Google Login Settings</h6></div><div class="card-body">'+
'<p class="text-muted small">Credentials are never displayed once saved.</p>'+
'<div class="mb-3"><label class="form-label">Enable Google Login</label><select class="form-select" id="gl-en"><option value="true"'+(d['auth.enable_social_login']?' selected':'')+'>Enabled</option><option value="false"'+(!d['auth.enable_social_login']?' selected':'')+'>Disabled</option></select></div>'+
'<div class="mb-3"><label class="form-label">Google Client ID '+(d['google_login.client_id']?'<span class="badge bg-success">Set</span>':'<span class="badge bg-danger">Not set</span>')+'</label><input type="text" class="form-control" id="gl-cid" placeholder="Enter Google Client ID"></div>'+
'<div class="mb-3"><label class="form-label">Google Client Secret '+(d['google_login.client_secret']?'<span class="badge bg-success">Set</span>':'<span class="badge bg-danger">Not set</span>')+'</label><input type="password" class="form-control" id="gl-cs" placeholder="Enter Google Client Secret"></div>'+
'<button class="btn btn-primary" onclick="saveGL()"><i class="bi bi-save"></i> Save</button></div></div>';
}catch(e){$('main').innerHTML='<div class="alert alert-danger">'+esc(e.message)+'</div>'}}
async function saveGL(){const b={enabled:$('gl-en').value==='true'};const cid=$('gl-cid').value.trim();if(cid)b.client_id=cid;const cs=$('gl-cs').value.trim();if(cs)b.client_secret=cs;try{await api('google-login/save',b);toast('Saved!');loadGL()}catch(e){toast(e.message,'danger')}}
`;
}

export function getSecurityScript(): string {
  return `
// ===== Security =====
async function loadSec(){try{const d=await api('security');
$('main').innerHTML='<h4 class="mb-4"><i class="bi bi-shield-check"></i> Security</h4>'+
'<div class="card mb-3"><div class="card-header"><h6 class="mb-0">Admin Credentials</h6></div><div class="card-body">'+
'<div class="row g-3"><div class="col-md-6"><label class="form-label">Username</label><input type="text" class="form-control" id="su" value="'+esc(d['admin.username'])+'"></div>'+
'<div class="col-md-6"><label class="form-label">New Password '+(d['admin.password_set']?'<span class="badge bg-success">Set</span>':'<span class="badge bg-danger">Not set</span>')+'</label><input type="password" class="form-control" id="sp" placeholder="Enter new password"></div></div>'+
'<button class="btn btn-primary mt-3" onclick="saveSec()"><i class="bi bi-save"></i> Save</button></div></div>'+
'<div class="card mb-3"><div class="card-header"><h6 class="mb-0">Blocked Regions / ASNs</h6></div><div class="card-body">'+
'<div class="mb-3"><label class="form-label">Blocked Regions (comma-separated country codes)</label><input type="text" class="form-control" id="sr" value="'+esc(d['security.blocked_regions'])+'" placeholder="e.g. CN, RU"></div>'+
'<div class="mb-3"><label class="form-label">Blocked ASNs (comma-separated)</label><input type="text" class="form-control" id="sa" value="'+esc(d['security.blocked_asn'])+'" placeholder="e.g. 12345, 67890"></div>'+
'<button class="btn btn-primary" onclick="saveBlk()"><i class="bi bi-save"></i> Save</button></div></div>'+
'<div class="card"><div class="card-header"><h6 class="mb-0">Crypto Keys</h6></div><div class="card-body">'+
'<div class="mb-3"><label class="form-label">Encryption Key '+(d['security.crypto_key_set']?'<span class="badge bg-success">Set</span>':'<span class="badge bg-danger">Not set</span>')+'</label><br>'+
'<button class="btn btn-outline-warning btn-sm" onclick="regenKey(\\'crypto\\')"><i class="bi bi-arrow-repeat"></i> Regenerate</button></div>'+
'<div class="mb-3"><label class="form-label">HMAC Key '+(d['security.hmac_key_set']?'<span class="badge bg-success">Set</span>':'<span class="badge bg-danger">Not set</span>')+'</label><br>'+
'<button class="btn btn-outline-warning btn-sm" onclick="regenKey(\\'hmac\\')"><i class="bi bi-arrow-repeat"></i> Regenerate</button></div>'+
'</div></div>';
}catch(e){$('main').innerHTML='<div class="alert alert-danger">'+esc(e.message)+'</div>'}}
async function saveSec(){const b={};const u=$('su').value.trim();if(u)b.admin_username=u;const p=$('sp').value;if(p)b.admin_password=p;if(!Object.keys(b).length){toast('Nothing to save','warning');return}try{await api('security/save',b);toast('Saved!');loadSec()}catch(e){toast(e.message,'danger')}}
async function saveBlk(){try{await api('security/save',{blocked_regions:$('sr').value,blocked_asn:$('sa').value});toast('Saved!')}catch(e){toast(e.message,'danger')}}
async function regenKey(t){if(!confirm('Regenerate '+t+' key? Existing encrypted data may become invalid.'))return;try{await api('security/regenerate-key',{type:t});toast(t+' key regenerated!');loadSec()}catch(e){toast(e.message,'danger')}}

// Init
loadDash();
`;
}