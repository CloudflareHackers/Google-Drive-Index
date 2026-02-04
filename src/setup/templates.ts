/**
 * Setup Wizard HTML Templates
 * All configuration stored in D1 database
 */

const BOOTSTRAP_CSS = 'https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css';
const BOOTSTRAP_JS = 'https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js';

/**
 * Setup login page (password required)
 */
export function getSetupLoginHTML(error?: string): string {
  return `<!DOCTYPE html>
<html><head>
<title>Setup - Google Drive Index</title>
<link href="${BOOTSTRAP_CSS}" rel="stylesheet">
<style>body{background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);min-height:100vh;display:flex;align-items:center}</style>
</head><body>
<div class="container">
<div class="row justify-content-center">
<div class="col-md-5">
<div class="card shadow-lg">
<div class="card-body p-5">
<h3 class="text-center mb-4">🔧 Setup Wizard</h3>
<p class="text-muted text-center mb-4">Enter the setup password from your <code>wrangler.toml</code></p>
${error ? `<div class="alert alert-danger">${error}</div>` : ''}
<form method="POST" action="/setup/login">
<div class="mb-3">
<input type="password" class="form-control form-control-lg" name="password" placeholder="Setup Password" required autofocus>
</div>
<button type="submit" class="btn btn-primary btn-lg w-100">Continue</button>
</form>
</div>
</div>
</div>
</div>
</div>
</body></html>`;
}

/**
 * Main setup wizard
 */
export function getSetupWizardHTML(step: number, data: any = {}): string {
  const steps = ['Database', 'Credentials', 'Drives', 'Settings', 'Complete'];
  
  return `<!DOCTYPE html>
<html><head>
<title>Setup - Step ${step} - Google Drive Index</title>
<link href="${BOOTSTRAP_CSS}" rel="stylesheet">
<style>
body{background:#f8f9fa}
.setup-container{max-width:900px;margin:40px auto}
.step-indicator{display:flex;justify-content:space-between;margin-bottom:30px}
.step{flex:1;text-align:center;padding:10px;border-bottom:3px solid #dee2e6;color:#6c757d}
.step.active{border-color:#0d6efd;color:#0d6efd;font-weight:bold}
.step.done{border-color:#198754;color:#198754}
</style>
</head><body>
<div class="setup-container">
<div class="card shadow">
<div class="card-header bg-primary text-white">
<h4 class="mb-0">🚀 Google Drive Index Setup</h4>
</div>
<div class="card-body p-4">
<div class="step-indicator">
${steps.map((s, i) => `<div class="step ${i + 1 < step ? 'done' : ''} ${i + 1 === step ? 'active' : ''}">${i + 1}. ${s}</div>`).join('')}
</div>
<div id="content">${getStepContent(step)}</div>
<div id="status" class="mt-3"></div>
</div>
</div>
</div>
<script src="${BOOTSTRAP_JS}"></script>
<script>${getStepScript(step)}</script>
</body></html>`;
}

function getStepContent(step: number): string {
  switch (step) {
    case 1:
      return `
<h5>Step 1: Initialize Database</h5>
<p class="text-muted">Create tables in Cloudflare D1 to store your configuration.</p>
<div class="alert alert-info">
<strong>D1 Database</strong> stores all your settings, drives, and credentials securely in Cloudflare's edge database.
</div>
<button class="btn btn-primary btn-lg" onclick="initDB()">Initialize Database</button>`;

    case 2:
      return `
<h5>Step 2: Google Drive Credentials</h5>
<p class="text-muted">Choose OAuth2 or Service Account authentication.</p>

<ul class="nav nav-tabs mb-3" role="tablist">
<li class="nav-item"><a class="nav-link active" data-bs-toggle="tab" href="#oauth">OAuth2 (User Account)</a></li>
<li class="nav-item"><a class="nav-link" data-bs-toggle="tab" href="#sa">Service Account</a></li>
</ul>

<div class="tab-content">
<div class="tab-pane fade show active" id="oauth">
<div class="mb-3"><label class="form-label">Client ID</label>
<input type="text" class="form-control" id="client_id" placeholder="xxx.apps.googleusercontent.com"></div>
<div class="mb-3"><label class="form-label">Client Secret</label>
<input type="text" class="form-control" id="client_secret" placeholder="GOCSPX-xxx"></div>
<div class="mb-3"><label class="form-label">Refresh Token</label>
<input type="text" class="form-control" id="refresh_token" placeholder="1//xxx"></div>
</div>
<div class="tab-pane fade" id="sa">
<div class="mb-3"><label class="form-label">Service Account JSON</label>
<textarea class="form-control" id="service_account_json" rows="8" placeholder='Paste your service account JSON here...'></textarea>
<small class="text-muted">Get from: Google Cloud Console → IAM → Service Accounts → Keys → Create Key (JSON)</small></div>
</div>
</div>

<button class="btn btn-primary btn-lg" onclick="saveCredentials()">Save & Continue</button>`;

    case 3:
      return `
<h5>Step 3: Add Google Drives</h5>
<p class="text-muted">Add your Google Drive folder IDs or Shared Drive IDs.</p>

<div id="drives-list"></div>
<button class="btn btn-outline-secondary mb-3" onclick="addDrive()">+ Add Drive</button>

<div class="alert alert-info">
<strong>How to get Drive ID:</strong><br>
• Open Google Drive folder → Copy ID from URL: <code>drive.google.com/drive/folders/<strong>FOLDER_ID</strong></code><br>
• For My Drive root, use: <code>root</code>
</div>

<button class="btn btn-primary btn-lg" onclick="saveDrives()">Save & Continue</button>`;

    case 4:
      return `
<h5>Step 4: General Settings</h5>

<div class="row">
<div class="col-md-6">
<div class="mb-3"><label class="form-label">Site Name</label>
<input type="text" class="form-control" id="site_name" value="Google Drive Index"></div>

<div class="mb-3"><label class="form-label">Admin Username</label>
<input type="text" class="form-control" id="admin_username" value="admin"></div>

<div class="mb-3"><label class="form-label">Admin Password</label>
<input type="password" class="form-control" id="admin_password" placeholder="Set admin password"></div>
</div>

<div class="col-md-6">
<div class="mb-3"><label class="form-label">Download Mode</label>
<select class="form-select" id="download_mode">
<option value="path">Path-based URLs</option>
<option value="id">ID-based URLs</option>
</select></div>

<div class="mb-3"><label class="form-label">Blocked Regions (comma-separated)</label>
<input type="text" class="form-control" id="blocked_regions" placeholder="e.g., CN,RU"></div>

<div class="mb-3"><label class="form-label">Blocked ASN (comma-separated)</label>
<input type="text" class="form-control" id="blocked_asn" placeholder="e.g., 16509"></div>
</div>
</div>

<div class="form-check mb-3">
<input type="checkbox" class="form-check-input" id="enable_login">
<label class="form-check-label">Enable user login system</label>
</div>

<button class="btn btn-primary btn-lg" onclick="saveSettings()">Save & Complete Setup</button>`;

    case 5:
      return `
<h5>✅ Setup Complete!</h5>
<div class="alert alert-success">
<strong>Congratulations!</strong> Your Google Drive Index is ready to use.
</div>
<p>All configuration is stored in your D1 database. You can modify settings anytime from the admin panel.</p>
<div class="d-flex gap-3">
<a href="/" class="btn btn-primary btn-lg">🏠 Go to Homepage</a>
<a href="/admin" class="btn btn-outline-secondary btn-lg">⚙️ Admin Panel</a>
</div>`;

    default:
      return '<p>Invalid step</p>';
  }
}

function getStepScript(step: number): string {
  const base = `
function showStatus(msg, type='info') {
  document.getElementById('status').innerHTML = '<div class="alert alert-'+type+'">'+msg+'</div>';
}
async function post(url, data) {
  showStatus('Processing...', 'info');
  try {
    const r = await fetch(url, {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(data)});
    const json = await r.json();
    if (!json.success) throw new Error(json.error || 'Unknown error');
    return json;
  } catch(e) {
    showStatus('Error: ' + e.message, 'danger');
    throw e;
  }
}`;

  switch (step) {
    case 1:
      return base + `
async function initDB() {
  await post('/setup/init-db', {});
  showStatus('Database initialized!', 'success');
  setTimeout(() => location.href = '/setup?step=2', 1000);
}`;

    case 2:
      return base + `
async function saveCredentials() {
  await post('/setup/save-credentials', {
    client_id: document.getElementById('client_id').value,
    client_secret: document.getElementById('client_secret').value,
    refresh_token: document.getElementById('refresh_token').value,
    service_account_json: document.getElementById('service_account_json').value
  });
  showStatus('Credentials saved!', 'success');
  setTimeout(() => location.href = '/setup?step=3', 1000);
}`;

    case 3:
      return base + `
let driveCount = 0;
function addDrive() {
  const div = document.createElement('div');
  div.className = 'row mb-2';
  div.id = 'drive-row-' + driveCount;
  div.innerHTML = \`
    <div class="col-5"><input class="form-control" placeholder="Drive/Folder ID" id="drive_id_\${driveCount}"></div>
    <div class="col-5"><input class="form-control" placeholder="Display Name" id="drive_name_\${driveCount}"></div>
    <div class="col-2"><button class="btn btn-outline-danger" onclick="document.getElementById('drive-row-\${driveCount}').remove()">×</button></div>
  \`;
  document.getElementById('drives-list').appendChild(div);
  driveCount++;
}
async function saveDrives() {
  const drives = [];
  document.querySelectorAll('[id^="drive_id_"]').forEach((el, i) => {
    if (el.value) {
      const nameEl = document.getElementById('drive_name_' + el.id.split('_')[2]);
      drives.push({ id: el.value, name: nameEl?.value || 'Drive ' + (i+1) });
    }
  });
  if (drives.length === 0) {
    showStatus('Please add at least one drive', 'warning');
    return;
  }
  await post('/setup/save-drives', { drives });
  showStatus('Drives saved!', 'success');
  setTimeout(() => location.href = '/setup?step=4', 1000);
}
addDrive();`;

    case 4:
      return base + `
async function saveSettings() {
  await post('/setup/save-settings', {
    site_name: document.getElementById('site_name').value,
    admin_username: document.getElementById('admin_username').value,
    admin_password: document.getElementById('admin_password').value,
    download_mode: document.getElementById('download_mode').value,
    blocked_regions: document.getElementById('blocked_regions').value,
    blocked_asn: document.getElementById('blocked_asn').value,
    enable_login: document.getElementById('enable_login').checked
  });
  await post('/setup/complete', {});
  showStatus('Setup complete!', 'success');
  setTimeout(() => location.href = '/setup?step=5', 1000);
}`;

    default:
      return base;
  }
}
