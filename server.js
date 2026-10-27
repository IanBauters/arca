'use strict';
/*
 * Arca — a self-hosted software vault.
 * Keeps installers, disk images and license keys for software you own,
 * so a vendor pulling an old version never locks you out again.
 */
const express = require('express');
const Busboy = require('busboy');
const crypto = require('node:crypto');
const fs = require('node:fs');
const fsp = require('node:fs/promises');
const path = require('node:path');
const { pipeline } = require('node:stream/promises');
const { DatabaseSync } = require('node:sqlite');

const VERSION = '1.1.0';
const PORT = Number(process.env.PORT || 8080);
const DATA_DIR = path.resolve(process.env.DATA_DIR || './data');
const LIBRARY_DIR = path.resolve(process.env.LIBRARY_DIR || './library');
const MEDIA_DIR = path.join(DATA_DIR, 'media');
const TMP_DIR = path.join(LIBRARY_DIR, '.arca-tmp');
const PASSWORD = process.env.ARCA_PASSWORD || '';
// Optional: an existing NAS folder mounted into the container (read-only is fine). Files there are linked, not copied.
const IMPORT_DIR = path.resolve(process.env.IMPORT_DIR || '/import');
const IMPORT_SMB = (process.env.IMPORT_SMB || '').replace(/\/+$/, '');
const importEnabled = () => { try { return fs.statSync(IMPORT_DIR).isDirectory(); } catch { return false; } };

for (const d of [DATA_DIR, LIBRARY_DIR, MEDIA_DIR, TMP_DIR]) {
  try {
    fs.mkdirSync(d, { recursive: true });
    fs.accessSync(d, fs.constants.W_OK);
  } catch (e) {
    const who = typeof process.getuid === 'function' ? `${process.getuid()}:${process.getgid()}` : 'unknown';
    console.error(`[arca] Cannot write to ${d} (${e.code}). Arca runs as uid:gid ${who}.`);
    console.error('[arca] On Synology, give that DSM user Read/Write on the shared folder (Control Panel > Shared Folder > Edit > Permissions),');
    console.error('[arca] or grant it with: synoacltool -add <folder> user:<dsm-user>:allow:rwxpdDaARWcCo:fd--');
    process.exit(1);
  }
}

// ---------- secret (encrypts license keys + signs sessions) ----------
function loadSecret() {
  if (process.env.ARCA_SECRET) return process.env.ARCA_SECRET;
  const f = path.join(DATA_DIR, 'secret.key');
  if (!fs.existsSync(f)) {
    fs.writeFileSync(f, crypto.randomBytes(32).toString('hex'), { mode: 0o600 });
    console.warn(`[arca] Generated ${f}. Back it up: without it, stored license keys cannot be decrypted.`);
  }
  return fs.readFileSync(f, 'utf8').trim();
}
const SECRET = loadSecret();
const ENC_KEY = crypto.scryptSync(SECRET, 'arca-license-keys', 32);
const SIGN_KEY = crypto.scryptSync(SECRET, 'arca-sessions', 32);

function encrypt(text) {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', ENC_KEY, iv);
  const enc = Buffer.concat([c.update(String(text), 'utf8'), c.final()]);
  return ['v1', iv.toString('base64'), c.getAuthTag().toString('base64'), enc.toString('base64')].join(':');
}
function decrypt(blob) {
  const [, iv, tag, data] = String(blob).split(':');
  const d = crypto.createDecipheriv('aes-256-gcm', ENC_KEY, Buffer.from(iv, 'base64'));
  d.setAuthTag(Buffer.from(tag, 'base64'));
  return Buffer.concat([d.update(Buffer.from(data, 'base64')), d.final()]).toString('utf8');
}
function mask(key) {
  const k = String(key);
  const tail = k.replace(/[\s-]/g, '').slice(-4);
  return '•••• •••• •••• ' + tail;
}

// ---------- database ----------
const db = new DatabaseSync(path.join(DATA_DIR, 'arca.db'));
db.exec(`
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS apps (
  id TEXT PRIMARY KEY, name TEXT NOT NULL, developer TEXT DEFAULT '', category TEXT DEFAULT 'Utilities',
  platform TEXT DEFAULT 'macOS', description TEXT DEFAULT '', website TEXT DEFAULT '',
  icon TEXT DEFAULT '', banner TEXT DEFAULT '', featured INTEGER DEFAULT 0, folder TEXT NOT NULL,
  created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS versions (
  id TEXT PRIMARY KEY, app_id TEXT NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
  version TEXT NOT NULL, released TEXT DEFAULT '', min_os TEXT DEFAULT '', max_os TEXT DEFAULT '',
  arch TEXT DEFAULT '', notes TEXT DEFAULT '', created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS files (
  id TEXT PRIMARY KEY, version_id TEXT NOT NULL REFERENCES versions(id) ON DELETE CASCADE,
  app_id TEXT NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
  kind TEXT DEFAULT 'installer', original_name TEXT NOT NULL, rel_path TEXT NOT NULL,
  size INTEGER NOT NULL, sha256 TEXT NOT NULL, uploaded_at TEXT NOT NULL,
  verified_at TEXT DEFAULT '', verify_status TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS licenses (
  id TEXT PRIMARY KEY, app_id TEXT NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
  label TEXT DEFAULT '', key_enc TEXT NOT NULL, key_mask TEXT NOT NULL, registered_to TEXT DEFAULT '',
  email TEXT DEFAULT '', purchased TEXT DEFAULT '', source TEXT DEFAULT '', notes TEXT DEFAULT '',
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS devices (
  id TEXT PRIMARY KEY, name TEXT NOT NULL, model TEXT DEFAULT '', platform TEXT DEFAULT 'macOS',
  os_version TEXT DEFAULT '', arch TEXT DEFAULT '', serial TEXT DEFAULT '', notes TEXT DEFAULT '', created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_versions_app ON versions(app_id);
CREATE INDEX IF NOT EXISTS idx_files_version ON files(version_id);
CREATE INDEX IF NOT EXISTS idx_licenses_app ON licenses(app_id);
`);

// migrations for databases created by earlier versions
if (!db.prepare("SELECT 1 FROM pragma_table_info('files') WHERE name = 'root'").get()) db.exec("ALTER TABLE files ADD COLUMN root TEXT DEFAULT 'library'");
for (const col of ['arch', 'serial']) if (!db.prepare("SELECT 1 FROM pragma_table_info('devices') WHERE name = ?").get(col)) db.exec(`ALTER TABLE devices ADD COLUMN ${col} TEXT DEFAULT ''`);

const q = (sql) => db.prepare(sql);
const now = () => new Date().toISOString();
const uid = () => crypto.randomBytes(9).toString('base64url');

// ---------- helpers ----------
function safeName(s, fallback = 'item') {
  const out = String(s || '').replace(/[\/\\:*?"<>|\x00-\x1f]/g, '-').replace(/^\.+/, '').trim().slice(0, 120);
  return out || fallback;
}
function uniqueFolder(name) {
  let base = safeName(name, 'app'), f = base, i = 2;
  while (q('SELECT 1 FROM apps WHERE folder = ?').get(f) || fs.existsSync(path.join(LIBRARY_DIR, f))) f = `${base} (${i++})`;
  return f;
}
function inside(root, p) {
  const r = path.resolve(root, p);
  if (r !== root && !r.startsWith(root + path.sep)) throw Object.assign(new Error('Bad path'), { status: 400 });
  return r;
}
const rootOf = (f) => f.root === 'import' ? IMPORT_DIR : LIBRARY_DIR;
const absOf = (f) => inside(rootOf(f), f.rel_path);
const isLinked = (f) => f.root === 'import';

// Folder-shaped items macOS treats as a single file (apps, packages, sparse bundles)
const BUNDLE_EXT = /\.(app|pkg|mpkg|sparsebundle|bundle|rtfd|prefPane|plugin|framework)$/i;
const SKIP_NAME = /^(\..*|@eaDir|#recycle|#snapshot|Thumbs\.db|desktop\.ini|Icon\r)$/i;
function kindFor(name) {
  const n = name.toLowerCase();
  if (/\.(iso|dmg|cdr|toast|img|dsk|image|sparseimage|sparsebundle|bin|cue|nrg|vmdk|vdi|ipsw)$/.test(n)) return 'disk-image';
  if (/\.(app|pkg|mpkg|exe|msi|zip|xip|sit|sitx|hqx|tar|gz|tgz|7z|rar)$/.test(n)) return 'installer';
  if (/\.(pdf|rtf|rtfd|txt|md|html?|doc|docx)$/.test(n)) return 'manual';
  if (/\.(jpe?g|png|gif|tiff?|heic|webp|psd)$/.test(n)) return 'artwork';
  return 'other';
}
// Walks a folder; bundles count as one item. Returns [{rel, size, bundle}]
async function walk(absDir, relBase = '') {
  const out = [];
  let entries = [];
  try { entries = await fsp.readdir(absDir, { withFileTypes: true }); } catch { return out; }
  for (const e of entries.sort((a, b) => a.name.localeCompare(b.name))) {
    if (SKIP_NAME.test(e.name)) continue;
    const abs = path.join(absDir, e.name), rel = path.join(relBase, e.name);
    if (e.isDirectory()) {
      if (BUNDLE_EXT.test(e.name)) out.push({ rel, size: await treeSize(abs), bundle: true });
      else out.push(...await walk(abs, rel));
    } else if (e.isFile()) {
      out.push({ rel, size: (await fsp.stat(abs)).size, bundle: false });
    }
  }
  return out;
}
async function treeSize(abs) {
  let total = 0;
  let entries = [];
  try { entries = await fsp.readdir(abs, { withFileTypes: true }); } catch { return 0; }
  for (const e of entries) {
    const p = path.join(abs, e.name);
    if (e.isDirectory()) total += await treeSize(p);
    else if (e.isFile()) total += (await fsp.stat(p)).size;
  }
  return total;
}
// SHA-256 of a file, or of a whole bundle (every path, symlink target and file content, in sorted order)
async function hashPath(abs) {
  const st = await fsp.lstat(abs);
  const h = crypto.createHash('sha256');
  if (!st.isDirectory()) { await pipeline(fs.createReadStream(abs), h); return h.digest('hex'); }
  async function add(dir, rel) {
    const entries = (await fsp.readdir(dir, { withFileTypes: true })).sort((a, b) => a.name.localeCompare(b.name));
    for (const e of entries) {
      const p = path.join(dir, e.name), r = rel ? rel + '/' + e.name : e.name;
      if (e.isSymbolicLink()) h.update(`L ${r} -> ${await fsp.readlink(p)}\0`);
      else if (e.isDirectory()) { h.update(`D ${r}\0`); await add(p, r); }
      else if (e.isFile()) {
        h.update(`F ${r}\0`);
        await new Promise((res, rej) => fs.createReadStream(p).on('data', c => h.update(c)).on('end', res).on('error', rej));
      }
    }
  }
  await add(abs, '');
  return h.digest('hex');
}

function cmpVer(a, b) {
  const pa = String(a).split(/[^\d]+/).filter(Boolean).map(Number);
  const pb = String(b).split(/[^\d]+/).filter(Boolean).map(Number);
  if (!pa.length || !pb.length) return null;
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const x = pa[i] || 0, y = pb[i] || 0;
    if (x !== y) return x < y ? -1 : 1;
  }
  return 0;
}
// Architecture rules for Mac software (Apple: support.apple.com/102527).
// Apple Silicon: needs macOS 11+. Intel 64-bit: native up to macOS 26 (last Intel release), via Rosetta 2 on Apple Silicon
// up to macOS 27. Intel 32-bit: up to macOS 10.14 Mojave. PowerPC: up to 10.6 Snow Leopard (Rosetta 1).
const MAC_ARCH_RULES = {
  'Apple Silicon': { min_os: '11.0' },
  'Intel 64-bit': { max_os: '27' },
  'Intel': { max_os: '27' },
  'Intel 32-bit': { max_os: '10.14.6' },
  'PowerPC': { max_os: '10.6.8' },
};
function archFits(vArch, dArch) {
  if (!vArch || !dArch) return true;
  if (vArch === 'Apple Silicon') return dArch === 'Apple Silicon';
  if (/^Intel/.test(vArch)) return dArch !== 'PowerPC';
  if (vArch === 'x64') return dArch !== 'x86';
  if (vArch === 'ARM') return dArch === 'ARM';
  return true;
}
function compat(version, app, device) {
  if (app.platform !== device.platform) return 'no';
  if (!archFits(version.arch, device.arch)) return 'no';
  if (!device.os_version || (!version.min_os && !version.max_os)) return 'unknown';
  if (version.min_os) { const c = cmpVer(device.os_version, version.min_os); if (c === null) return 'unknown'; if (c < 0) return 'no'; }
  if (version.max_os) {
    // "max 12.7" means any 12.7.x, so compare only as many components as the max specifies
    const depth = String(version.max_os).split(/[^\d]+/).filter(Boolean).length;
    const dev = String(device.os_version).split(/[^\d]+/).filter(Boolean).slice(0, depth).join('.');
    const c = cmpVer(dev, version.max_os); if (c === null) return 'unknown'; if (c > 0) return 'no';
  }
  return 'yes';
}
const pick = (o, keys) => Object.fromEntries(keys.filter(k => o[k] !== undefined).map(k => [k, o[k] == null ? '' : o[k]]));

function hydrateApp(app, { full = false } = {}) {
  const versions = q('SELECT * FROM versions WHERE app_id = ?').all(app.id)
    .sort((a, b) => (cmpVer(b.version, a.version) ?? 0) || b.created_at.localeCompare(a.created_at));
  const files = q('SELECT * FROM files WHERE app_id = ? ORDER BY uploaded_at').all(app.id);
  const out = {
    ...app,
    latest: versions[0]?.version || '',
    version_count: versions.length,
    file_count: files.length,
    total_size: files.reduce((s, f) => s + f.size, 0),
    license_count: q('SELECT COUNT(*) n FROM licenses WHERE app_id = ?').get(app.id).n,
  };
  if (full) {
    out.versions = versions.map(v => ({ ...v, files: files.filter(f => f.version_id === v.id) }));
    out.licenses = q('SELECT id, app_id, label, key_mask, registered_to, email, purchased, source, notes, created_at FROM licenses WHERE app_id = ? ORDER BY created_at').all(app.id);
  }
  return out;
}

// Plain-JSON sidecar next to the files, so the library stays understandable without Arca. Never contains keys.
function writeSidecar(appId) {
  const app = q('SELECT * FROM apps WHERE id = ?').get(appId);
  if (!app) return;
  const full = hydrateApp(app, { full: true });
  const dir = path.join(LIBRARY_DIR, app.folder);
  if (!fs.existsSync(dir)) return;
  const doc = {
    _note: 'Written by Arca. Metadata only; license keys are stored encrypted in the Arca database.',
    name: app.name, developer: app.developer, category: app.category, platform: app.platform,
    description: app.description, website: app.website,
    versions: full.versions.map(v => ({
      version: v.version, released: v.released, min_os: v.min_os, max_os: v.max_os, arch: v.arch, notes: v.notes,
      files: v.files.map(f => ({ name: f.original_name, path: f.rel_path, kind: f.kind, size: f.size, sha256: f.sha256 })),
    })),
  };
  fs.writeFileSync(path.join(dir, '_arca.json'), JSON.stringify(doc, null, 2));
}

// ---------- app ----------
const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '2mb' }));

// auth: a signed, expiring cookie. If ARCA_PASSWORD is unset, Arca runs open (LAN-only use).
const COOKIE = 'arca_session';
const sign = (v) => crypto.createHmac('sha256', SIGN_KEY).update(v).digest('base64url');
function makeSession() { const exp = String(Date.now() + 30 * 864e5); return `${exp}.${sign(exp)}`; }
function validSession(tok) {
  if (!tok) return false;
  const [exp, sig] = tok.split('.');
  if (!exp || !sig) return false;
  const good = sign(exp);
  return sig.length === good.length && crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(good)) && Number(exp) > Date.now();
}
function cookies(req) {
  return Object.fromEntries((req.headers.cookie || '').split(';').map(c => c.trim().split('=')).filter(p => p[0]).map(([k, ...v]) => [k, decodeURIComponent(v.join('='))]));
}
const authed = (req) => !PASSWORD || validSession(cookies(req)[COOKIE]);

app.get('/api/health', (req, res) => res.json({ ok: true, app: 'arca', version: VERSION, auth_required: !!PASSWORD, authenticated: authed(req) }));

app.post('/api/login', async (req, res) => {
  const given = String(req.body?.password || '');
  const ok = PASSWORD && given.length === PASSWORD.length && crypto.timingSafeEqual(Buffer.from(given), Buffer.from(PASSWORD));
  if (!ok) { await new Promise(r => setTimeout(r, 700)); return res.status(401).json({ error: 'Wrong password' }); }
  const secure = req.secure || req.headers['x-forwarded-proto'] === 'https' ? '; Secure' : '';
  res.setHeader('Set-Cookie', `${COOKIE}=${makeSession()}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${30 * 86400}${secure}`);
  res.json({ ok: true });
});
app.post('/api/logout', (req, res) => {
  res.setHeader('Set-Cookie', `${COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0`);
  res.json({ ok: true });
});

app.use(['/api', '/media'], (req, res, next) => authed(req) ? next() : res.status(401).json({ error: 'Not signed in' }));

const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
const need = (row, what = 'Item') => { if (!row) throw Object.assign(new Error(`${what} not found`), { status: 404 }); return row; };

// stats
app.get('/api/stats', wrap(async (req, res) => {
  const n = (t) => q(`SELECT COUNT(*) n FROM ${t}`).get().n;
  const size = q('SELECT COALESCE(SUM(size),0) s FROM files').get().s;
  const bad = q("SELECT COUNT(*) n FROM files WHERE verify_status IN ('mismatch','missing')").get().n;
  const verified = q("SELECT COUNT(*) n FROM files WHERE verify_status = 'ok'").get().n;
  const lastVerify = q("SELECT MAX(verified_at) t FROM files").get().t || '';
  let disk = null;
  try { const s = await fsp.statfs(LIBRARY_DIR); disk = { total: s.blocks * s.bsize, free: s.bavail * s.bsize }; } catch {}
  const recent = q(`SELECT v.id, v.version, v.created_at, a.id app_id, a.name, a.icon, a.category FROM versions v JOIN apps a ON a.id = v.app_id ORDER BY v.created_at DESC LIMIT 6`).all();
  const cats = q('SELECT category, COUNT(*) n FROM apps GROUP BY category').all();
  const pending = q("SELECT COUNT(*) n FROM files WHERE sha256 = ''").get().n;
  res.json({ fingerprinting: { pending, current: hashing.current }, apps: n('apps'), versions: n('versions'), files: n('files'), licenses: n('licenses'), devices: n('devices'), size, bad, verified, last_verify: lastVerify, disk, recent, categories: cats, verify: verifyJob });
}));

// apps
const APP_FIELDS = ['name', 'developer', 'category', 'platform', 'description', 'website', 'featured'];
app.get('/api/apps', (req, res) => {
  let rows = q('SELECT * FROM apps ORDER BY name COLLATE NOCASE').all();
  const { q: term, category, platform } = req.query;
  if (category) rows = rows.filter(a => a.category === category);
  if (platform) rows = rows.filter(a => a.platform === platform);
  if (term) {
    const t = String(term).toLowerCase();
    rows = rows.filter(a => [a.name, a.developer, a.description, a.category].some(x => String(x).toLowerCase().includes(t)));
  }
  res.json(rows.map(a => hydrateApp(a)));
});
app.post('/api/apps', (req, res) => {
  const b = pick(req.body || {}, APP_FIELDS);
  if (!String(b.name || '').trim()) return res.status(400).json({ error: 'Name is required' });
  const id = uid(), t = now(), folder = uniqueFolder(b.name);
  fs.mkdirSync(path.join(LIBRARY_DIR, folder), { recursive: true });
  q(`INSERT INTO apps (id,name,developer,category,platform,description,website,featured,folder,created_at,updated_at)
     VALUES (:id,:name,:developer,:category,:platform,:description,:website,:featured,:folder,:t,:t)`).run({
    id, name: b.name.trim(), developer: b.developer || '', category: b.category || 'Utilities', platform: b.platform || 'macOS',
    description: b.description || '', website: b.website || '', featured: b.featured ? 1 : 0, folder, t,
  });
  writeSidecar(id);
  res.status(201).json(hydrateApp(q('SELECT * FROM apps WHERE id = ?').get(id), { full: true }));
});
app.get('/api/apps/:id', (req, res) => res.json(hydrateApp(need(q('SELECT * FROM apps WHERE id = ?').get(req.params.id), 'App'), { full: true })));
app.put('/api/apps/:id', (req, res) => {
  const a = need(q('SELECT * FROM apps WHERE id = ?').get(req.params.id), 'App');
  const b = { ...a, ...pick(req.body || {}, APP_FIELDS) };
  if (b.featured) q('UPDATE apps SET featured = 0').run();
  q(`UPDATE apps SET name=:name, developer=:developer, category=:category, platform=:platform, description=:description,
     website=:website, featured=:featured, updated_at=:t WHERE id=:id`).run({ ...pick(b, APP_FIELDS), featured: b.featured ? 1 : 0, id: a.id, t: now() });
  writeSidecar(a.id);
  res.json(hydrateApp(q('SELECT * FROM apps WHERE id = ?').get(a.id), { full: true }));
});
app.delete('/api/apps/:id', wrap(async (req, res) => {
  const a = need(q('SELECT * FROM apps WHERE id = ?').get(req.params.id), 'App');
  for (const f of q('SELECT * FROM files WHERE app_id = ?').all(a.id)) if (!isLinked(f)) await fsp.rm(absOf(f), { force: true });
  await fsp.rm(path.join(LIBRARY_DIR, a.folder, '_arca.json'), { force: true });
  await removeEmptyDirs(path.join(LIBRARY_DIR, a.folder));
  for (const m of [a.icon, a.banner]) if (m) await fsp.rm(path.join(MEDIA_DIR, m), { force: true });
  q('DELETE FROM apps WHERE id = ?').run(a.id);
  res.json({ ok: true });
}));
async function removeEmptyDirs(dir) {
  try {
    for (const e of await fsp.readdir(dir, { withFileTypes: true })) if (e.isDirectory()) await removeEmptyDirs(path.join(dir, e.name));
    if (!(await fsp.readdir(dir)).length) await fsp.rmdir(dir);
  } catch {}
}

// app artwork (icon / banner)
app.post('/api/apps/:id/:slot(icon|banner)', (req, res, next) => {
  const a = q('SELECT * FROM apps WHERE id = ?').get(req.params.id);
  if (!a) return res.status(404).json({ error: 'App not found' });
  const bb = Busboy({ headers: req.headers, limits: { files: 1, fileSize: 15 * 1024 * 1024 } });
  let saved = null, tooBig = false, writes = [];
  bb.on('file', (_f, stream, info) => {
    const ext = ({ 'image/png': '.png', 'image/jpeg': '.jpg', 'image/webp': '.webp', 'image/gif': '.gif', 'image/svg+xml': '.svg' })[info.mimeType];
    if (!ext) { stream.resume(); return; }
    const name = `${a.id}-${req.params.slot}-${Date.now()}${ext}`;
    stream.on('limit', () => { tooBig = true; });
    writes.push(pipeline(stream, fs.createWriteStream(path.join(MEDIA_DIR, name))).then(() => { saved = name; }));
  });
  bb.on('close', async () => {
    try {
      await Promise.all(writes);
      if (tooBig) { if (saved) await fsp.rm(path.join(MEDIA_DIR, saved), { force: true }); return res.status(413).json({ error: 'Image too large (15 MB max)' }); }
      if (!saved) return res.status(400).json({ error: 'Upload a PNG, JPEG, WebP, GIF or SVG image' });
      if (a[req.params.slot]) await fsp.rm(path.join(MEDIA_DIR, a[req.params.slot]), { force: true });
      q(`UPDATE apps SET ${req.params.slot} = ?, updated_at = ? WHERE id = ?`).run(saved, now(), a.id);
      res.json(hydrateApp(q('SELECT * FROM apps WHERE id = ?').get(a.id), { full: true }));
    } catch (e) { next(e); }
  });
  req.pipe(bb);
});
app.use('/media', express.static(MEDIA_DIR, { maxAge: '7d', fallthrough: false }));

// versions
const VER_FIELDS = ['version', 'released', 'min_os', 'max_os', 'arch', 'notes'];
app.post('/api/apps/:id/versions', (req, res) => {
  const a = need(q('SELECT * FROM apps WHERE id = ?').get(req.params.id), 'App');
  const b = pick(req.body || {}, VER_FIELDS);
  if (!String(b.version || '').trim()) return res.status(400).json({ error: 'Version number is required' });
  const rule = a.platform === 'macOS' ? MAC_ARCH_RULES[b.arch] : null;
  if (rule) { if (!b.min_os && rule.min_os) b.min_os = rule.min_os; if (!b.max_os && rule.max_os) b.max_os = rule.max_os; }
  const id = uid();
  q(`INSERT INTO versions (id,app_id,version,released,min_os,max_os,arch,notes,created_at)
     VALUES (:id,:app,:version,:released,:min_os,:max_os,:arch,:notes,:t)`).run({
    id, app: a.id, version: b.version.trim(), released: b.released || '', min_os: b.min_os || '', max_os: b.max_os || '', arch: b.arch || '', notes: b.notes || '', t: now(),
  });
  q('UPDATE apps SET updated_at = ? WHERE id = ?').run(now(), a.id);
  writeSidecar(a.id);
  res.status(201).json(q('SELECT * FROM versions WHERE id = ?').get(id));
});
app.put('/api/versions/:id', (req, res) => {
  const v = need(q('SELECT * FROM versions WHERE id = ?').get(req.params.id), 'Version');
  const b = { ...v, ...pick(req.body || {}, VER_FIELDS) };
  q('UPDATE versions SET version=:version, released=:released, min_os=:min_os, max_os=:max_os, arch=:arch, notes=:notes WHERE id=:id').run({ ...pick(b, VER_FIELDS), id: v.id });
  writeSidecar(v.app_id);
  res.json(q('SELECT * FROM versions WHERE id = ?').get(v.id));
});
app.delete('/api/versions/:id', wrap(async (req, res) => {
  const v = need(q('SELECT * FROM versions WHERE id = ?').get(req.params.id), 'Version');
  for (const f of q('SELECT * FROM files WHERE version_id = ?').all(v.id)) if (!isLinked(f)) await fsp.rm(absOf(f), { force: true });
  q('DELETE FROM versions WHERE id = ?').run(v.id);
  const a = q('SELECT folder FROM apps WHERE id = ?').get(v.app_id);
  await removeEmptyDirs(path.join(LIBRARY_DIR, a.folder, safeName(v.version, 'version')));
  writeSidecar(v.app_id);
  res.json({ ok: true });
}));

// file upload: streamed straight to disk, hashed on the way in. No size limit.
app.post('/api/versions/:id/files', (req, res, next) => {
  const v = q('SELECT * FROM versions WHERE id = ?').get(req.params.id);
  if (!v) return res.status(404).json({ error: 'Version not found' });
  const a = q('SELECT * FROM apps WHERE id = ?').get(v.app_id);
  const relDir = path.join(a.folder, safeName(v.version, 'version'));
  const absDir = inside(LIBRARY_DIR, relDir);
  fs.mkdirSync(absDir, { recursive: true });

  const bb = Busboy({ headers: req.headers, preservePath: false });
  const fields = { kind: 'auto' };
  const jobs = [];
  let aborted = false;
  bb.on('field', (k, val) => { fields[k] = val; });
  bb.on('file', (_f, stream, info) => {
    const orig = safeName(path.basename(info.filename || 'file'), 'file');
    const kind = ['installer', 'disk-image', 'update', 'manual', 'artwork', 'other'].includes(fields.kind) ? fields.kind : kindFor(orig);
    const tmp = path.join(TMP_DIR, uid());
    const hash = crypto.createHash('sha256');
    let size = 0;
    stream.on('data', (c) => { hash.update(c); size += c.length; });
    jobs.push(pipeline(stream, fs.createWriteStream(tmp)).then(async () => {
      let name = orig, i = 2;
      const ext = path.extname(orig), stem = orig.slice(0, orig.length - ext.length);
      while (fs.existsSync(path.join(absDir, name))) name = `${stem} (${i++})${ext}`;
      await fsp.rename(tmp, path.join(absDir, name));
      const id = uid(), t = now();
      q(`INSERT INTO files (id,version_id,app_id,kind,original_name,rel_path,size,sha256,uploaded_at,verified_at,verify_status)
         VALUES (?,?,?,?,?,?,?,?,?,?,?)`).run(id, v.id, a.id, kind, orig, path.join(relDir, name), size, hash.digest('hex'), t, t, 'ok');
      return q('SELECT * FROM files WHERE id = ?').get(id);
    }).catch(async (e) => { await fsp.rm(tmp, { force: true }); throw e; }));
  });
  req.on('aborted', () => { aborted = true; });
  bb.on('close', async () => {
    try {
      const saved = await Promise.all(jobs);
      if (aborted) return;
      q('UPDATE apps SET updated_at = ? WHERE id = ?').run(now(), a.id);
      writeSidecar(a.id);
      res.status(201).json(saved);
    } catch (e) { next(e); }
  });
  bb.on('error', next);
  req.pipe(bb);
});
app.get('/api/files/:id/download', (req, res) => {
  const f = need(q('SELECT * FROM files WHERE id = ?').get(req.params.id), 'File');
  if (fs.existsSync(absOf(f)) && fs.statSync(absOf(f)).isDirectory()) {
    return res.status(409).json({ error: `${f.original_name} is a bundle (a folder). Open it on the NAS through Finder instead.` });
  }
  res.download(absOf(f), path.basename(f.original_name), { dotfiles: 'allow' }, (err) => {
    if (err && !res.headersSent) res.status(404).json({ error: 'File missing on disk' });
  });
});
app.put('/api/files/:id', (req, res) => {
  const f = need(q('SELECT * FROM files WHERE id = ?').get(req.params.id), 'File');
  if (req.body?.kind) q('UPDATE files SET kind = ? WHERE id = ?').run(req.body.kind, f.id);
  writeSidecar(f.app_id);
  res.json(q('SELECT * FROM files WHERE id = ?').get(f.id));
});
app.delete('/api/files/:id', wrap(async (req, res) => {
  const f = need(q('SELECT * FROM files WHERE id = ?').get(req.params.id), 'File');
  if (!isLinked(f)) await fsp.rm(absOf(f), { force: true });
  q('DELETE FROM files WHERE id = ?').run(f.id);
  writeSidecar(f.app_id);
  res.json({ ok: true });
}));

// licenses (keys encrypted at rest, only revealed on explicit request)
const LIC_FIELDS = ['label', 'registered_to', 'email', 'purchased', 'source', 'notes'];
const licOut = (id) => q('SELECT l.id, l.app_id, l.label, l.key_mask, l.registered_to, l.email, l.purchased, l.source, l.notes, l.created_at, a.name app_name, a.icon app_icon, a.category app_category FROM licenses l JOIN apps a ON a.id = l.app_id WHERE l.id = ?').get(id);
app.get('/api/licenses', (req, res) => {
  res.json(q('SELECT l.id, l.app_id, l.label, l.key_mask, l.registered_to, l.email, l.purchased, l.source, l.notes, l.created_at, a.name app_name, a.icon app_icon, a.category app_category FROM licenses l JOIN apps a ON a.id = l.app_id ORDER BY a.name COLLATE NOCASE, l.created_at').all());
});
app.post('/api/apps/:id/licenses', (req, res) => {
  const a = need(q('SELECT * FROM apps WHERE id = ?').get(req.params.id), 'App');
  const key = String(req.body?.key || '').trim();
  if (!key) return res.status(400).json({ error: 'License key is required' });
  const b = pick(req.body, LIC_FIELDS), id = uid();
  q(`INSERT INTO licenses (id,app_id,label,key_enc,key_mask,registered_to,email,purchased,source,notes,created_at)
     VALUES (:id,:app,:label,:enc,:mask,:registered_to,:email,:purchased,:source,:notes,:t)`).run({
    id, app: a.id, enc: encrypt(key), mask: mask(key), t: now(),
    label: b.label || '', registered_to: b.registered_to || '', email: b.email || '', purchased: b.purchased || '', source: b.source || '', notes: b.notes || '',
  });
  res.status(201).json(licOut(id));
});
app.put('/api/licenses/:id', (req, res) => {
  const l = need(q('SELECT * FROM licenses WHERE id = ?').get(req.params.id), 'License');
  const b = { ...l, ...pick(req.body || {}, LIC_FIELDS) };
  const key = String(req.body?.key || '').trim();
  q(`UPDATE licenses SET label=:label, registered_to=:registered_to, email=:email, purchased=:purchased, source=:source, notes=:notes,
     key_enc=:enc, key_mask=:mask WHERE id=:id`).run({ ...pick(b, LIC_FIELDS), enc: key ? encrypt(key) : l.key_enc, mask: key ? mask(key) : l.key_mask, id: l.id });
  res.json(licOut(l.id));
});
app.get('/api/licenses/:id/reveal', (req, res) => {
  const l = need(q('SELECT key_enc FROM licenses WHERE id = ?').get(req.params.id), 'License');
  try { res.set('Cache-Control', 'no-store').json({ key: decrypt(l.key_enc) }); }
  catch { res.status(500).json({ error: 'Could not decrypt. Was ARCA_SECRET or secret.key changed?' }); }
});
app.delete('/api/licenses/:id', (req, res) => { q('DELETE FROM licenses WHERE id = ?').run(req.params.id); res.json({ ok: true }); });

// devices + compatibility
const DEV_FIELDS = ['name', 'model', 'serial', 'platform', 'os_version', 'arch', 'notes'];
app.get('/api/devices', (req, res) => res.json(q('SELECT * FROM devices ORDER BY name COLLATE NOCASE').all()));
app.post('/api/devices', (req, res) => {
  const b = pick(req.body || {}, DEV_FIELDS);
  if (!String(b.name || '').trim()) return res.status(400).json({ error: 'Name is required' });
  const id = uid();
  q('INSERT INTO devices (id,name,model,serial,platform,os_version,arch,notes,created_at) VALUES (:id,:name,:model,:serial,:platform,:os_version,:arch,:notes,:t)').run({
    id, name: b.name.trim(), model: b.model || '', serial: String(b.serial || '').trim().toUpperCase(), platform: b.platform || 'macOS', os_version: b.os_version || '', arch: b.arch || '', notes: b.notes || '', t: now(),
  });
  res.status(201).json(q('SELECT * FROM devices WHERE id = ?').get(id));
});
app.put('/api/devices/:id', (req, res) => {
  const d = need(q('SELECT * FROM devices WHERE id = ?').get(req.params.id), 'Device');
  const b = { ...d, ...pick(req.body || {}, DEV_FIELDS) };
  q('UPDATE devices SET name=:name, model=:model, serial=:serial, platform=:platform, os_version=:os_version, arch=:arch, notes=:notes WHERE id=:id').run({ ...pick(b, DEV_FIELDS), serial: String(b.serial || '').trim().toUpperCase(), id: d.id });
  res.json(q('SELECT * FROM devices WHERE id = ?').get(d.id));
});
app.delete('/api/devices/:id', (req, res) => { q('DELETE FROM devices WHERE id = ?').run(req.params.id); res.json({ ok: true }); });
app.get('/api/devices/:id/compatible', (req, res) => {
  const d = need(q('SELECT * FROM devices WHERE id = ?').get(req.params.id), 'Device');
  const out = q("SELECT * FROM apps WHERE category <> 'Operating Systems' ORDER BY name COLLATE NOCASE").all().map(a => {
    const h = hydrateApp(a, { full: true });
    const versions = h.versions.map(v => ({ id: v.id, version: v.version, min_os: v.min_os, max_os: v.max_os, file_count: v.files.length, compat: compat(v, a, d) }));
    const best = versions.find(v => v.compat === 'yes');
    return { id: a.id, name: a.name, icon: a.icon, category: a.category, platform: a.platform, best: best?.version || '', status: best ? 'yes' : versions.some(v => v.compat === 'unknown') ? 'unknown' : 'no', versions };
  }).filter(a => a.platform === d.platform);
  res.json({ device: d, apps: out });
});

// Background fingerprinting for linked files (they can be many gigabytes, so this never blocks a request)
const hashQueue = [];
let hashing = { current: '', done: 0 };
async function runHashQueue() {
  if (hashing.running) return;
  hashing.running = true;
  while (hashQueue.length) {
    const id = hashQueue.shift();
    const f = q('SELECT * FROM files WHERE id = ?').get(id);
    if (!f) continue;
    hashing.current = f.original_name;
    try { q("UPDATE files SET sha256 = ?, verify_status = 'ok', verified_at = ? WHERE id = ?").run(await hashPath(absOf(f)), now(), f.id); }
    catch { q("UPDATE files SET verify_status = 'missing', verified_at = ? WHERE id = ?").run(now(), f.id); }
    hashing.done++;
  }
  hashing = { current: '', done: 0, running: false };
}
function queueHash(ids) { hashQueue.push(...ids); runHashQueue(); }

// integrity check: re-hash every file to catch bit rot or missing files
let verifyJob = { running: false, done: 0, total: 0, bad: [], started_at: '', finished_at: '' };
app.get('/api/verify', (req, res) => res.json(verifyJob));
app.post('/api/verify', (req, res) => {
  if (verifyJob.running) return res.json(verifyJob);
  const all = q('SELECT f.*, a.name app_name FROM files f JOIN apps a ON a.id = f.app_id').all();
  verifyJob = { running: true, done: 0, total: all.length, bad: [], started_at: now(), finished_at: '' };
  (async () => {
    for (const f of all) {
      let status = 'ok';
      try {
        const digest = await hashPath(absOf(f));
        if (!f.sha256) q('UPDATE files SET sha256 = ? WHERE id = ?').run(digest, f.id);
        else if (digest !== f.sha256) status = 'mismatch';
      } catch { status = 'missing'; }
      q('UPDATE files SET verify_status = ?, verified_at = ? WHERE id = ?').run(status, now(), f.id);
      if (status !== 'ok') verifyJob.bad.push({ id: f.id, app: f.app_name, name: f.original_name, status });
      verifyJob.done++;
    }
    verifyJob.running = false;
    verifyJob.finished_at = now();
  })();
  res.json(verifyJob);
});

// ---------- import from an existing NAS folder (files are linked in place, never copied or changed) ----------
app.get('/api/import/browse', wrap(async (req, res) => {
  if (!importEnabled()) return res.json({ enabled: false, entries: [] });
  const rel = String(req.query.path || '').replace(/^\/+/, '');
  const abs = inside(IMPORT_DIR, rel);
  const linked = new Set(q("SELECT rel_path FROM files WHERE root = 'import'").all().map(r => r.rel_path));
  const entries = [];
  for (const e of (await fsp.readdir(abs, { withFileTypes: true })).sort((a, b) => a.name.localeCompare(b.name, undefined, { numeric: true }))) {
    if (SKIP_NAME.test(e.name)) continue;
    const r = path.join(rel, e.name), p = path.join(abs, e.name);
    if (e.isDirectory() && !BUNDLE_EXT.test(e.name)) {
      const items = await walk(p, r);
      entries.push({ name: e.name, path: r, type: 'folder', size: items.reduce((t, i) => t + i.size, 0), files: items.length, imported: items.length > 0 && items.every(i => linked.has(i.rel)) });
    } else if (e.isDirectory() || e.isFile()) {
      const bundle = e.isDirectory();
      entries.push({ name: e.name, path: r, type: bundle ? 'bundle' : 'file', size: bundle ? await treeSize(p) : (await fsp.stat(p)).size, files: 1, imported: linked.has(r) });
    }
  }
  res.json({ enabled: true, path: rel, entries });
}));

app.post('/api/import', wrap(async (req, res) => {
  if (!importEnabled()) return res.status(400).json({ error: 'No import folder is mounted. Add a volume at /import in docker-compose.yml.' });
  const items = Array.isArray(req.body?.items) ? req.body.items : [];
  const summary = { apps: 0, versions: 0, files: 0, skipped: 0 };
  const queued = [], touched = new Set();
  for (const it of items) {
    const name = String(it.name || '').trim(), version = String(it.version || '').trim() || '1.0';
    if (!name || !it.path) continue;
    const abs = inside(IMPORT_DIR, String(it.path));
    const st = await fsp.stat(abs);
    // app: reuse one with the same name, so several folders can become versions of one entry
    let a = q('SELECT * FROM apps WHERE name = ? COLLATE NOCASE').get(name);
    if (!a) {
      const id = uid(), t = now(), folder = uniqueFolder(name);
      fs.mkdirSync(path.join(LIBRARY_DIR, folder), { recursive: true });
      q(`INSERT INTO apps (id,name,developer,category,platform,description,website,featured,folder,created_at,updated_at)
         VALUES (?,?,?,?,?,?,?,0,?,?,?)`).run(id, name, it.developer || '', it.category || 'Utilities', it.platform || 'macOS', it.description || '', '', folder, t, t);
      a = q('SELECT * FROM apps WHERE id = ?').get(id); summary.apps++;
    }
    let v = q('SELECT * FROM versions WHERE app_id = ? AND version = ?').get(a.id, version);
    if (!v) {
      const id = uid();
      q(`INSERT INTO versions (id,app_id,version,released,min_os,max_os,arch,notes,created_at) VALUES (?,?,?,?,?,?,?,?,?)`)
        .run(id, a.id, version, '', it.min_os || '', it.max_os || '', it.arch || '', it.notes || '', now());
      v = q('SELECT * FROM versions WHERE id = ?').get(id); summary.versions++;
    }
    const list = st.isDirectory() && !BUNDLE_EXT.test(abs)
      ? (await walk(abs, String(it.path))).map(x => ({ ...x, display: path.relative(String(it.path), x.rel) }))
      : [{ rel: String(it.path), size: st.isDirectory() ? await treeSize(abs) : st.size, bundle: st.isDirectory(), display: path.basename(String(it.path)) }];
    for (const x of list) {
      if (q("SELECT 1 FROM files WHERE root = 'import' AND rel_path = ?").get(x.rel)) { summary.skipped++; continue; }
      const id = uid(), t = now();
      q(`INSERT INTO files (id,version_id,app_id,kind,original_name,rel_path,size,sha256,uploaded_at,verified_at,verify_status,root)
         VALUES (?,?,?,?,?,?,?,'',?,'','pending','import')`).run(id, v.id, a.id, kindFor(x.display), x.display, x.rel, x.size, t);
      queued.push(id); summary.files++;
    }
    q('UPDATE apps SET updated_at = ? WHERE id = ?').run(now(), a.id);
    touched.add(a.id);
  }
  touched.forEach(writeSidecar);
  queueHash(queued);
  res.json(summary);
}));

// catalog export (no keys)
app.get('/api/export', (req, res) => {
  const apps = q('SELECT * FROM apps ORDER BY name COLLATE NOCASE').all().map(a => {
    const h = hydrateApp(a, { full: true });
    h.licenses = h.licenses.map(({ key_mask, ...l }) => l);
    return h;
  });
  res.set('Content-Disposition', `attachment; filename="arca-catalog-${now().slice(0, 10)}.json"`)
    .json({ exported_at: now(), arca: VERSION, apps, devices: q('SELECT * FROM devices').all() });
});

app.get('/api/settings', (req, res) => res.json({ import_dir: importEnabled() ? IMPORT_DIR : '', import_smb: IMPORT_SMB, version: VERSION, data_dir: DATA_DIR, library_dir: LIBRARY_DIR, auth_required: !!PASSWORD, secret_from_env: !!process.env.ARCA_SECRET }));

app.use('/api', (req, res) => res.status(404).json({ error: 'Not found' }));
// The page is authored as a fragment (it doubles as the hosted preview), so wrap it in a full document here.
const PAGE = '<!doctype html><html lang="en"><head><meta charset="utf-8"></head><body>\n' + fs.readFileSync(path.join(__dirname, 'public', 'index.html'), 'utf8') + '\n</body></html>';
app.get(['/', '/index.html'], (req, res) => res.type('html').set('Cache-Control', 'no-cache').send(PAGE));
app.use(express.static(path.join(__dirname, 'public'), { index: false }));

app.use((err, req, res, _next) => {
  if (err.status !== 404) console.error('[arca]', err);
  if (!res.headersSent) res.status(err.status || 500).json({ error: err.message || 'Server error' });
});

// resume fingerprinting interrupted by a restart
queueHash(q("SELECT id FROM files WHERE sha256 = ''").all().map(r => r.id));

// clear abandoned partial uploads on start
for (const f of fs.readdirSync(TMP_DIR)) fs.rmSync(path.join(TMP_DIR, f), { force: true });

const server = app.listen(PORT, () => {
  console.log(`[arca] v${VERSION} on :${PORT}  data=${DATA_DIR}  library=${LIBRARY_DIR}${importEnabled() ? '  import=' + IMPORT_DIR : ''}`);
  if (!PASSWORD) console.warn('[arca] ARCA_PASSWORD is not set — anyone on your network can open Arca.');
});
server.requestTimeout = 0;   // multi-GB uploads would otherwise be cut off after 5 minutes
server.headersTimeout = 120000;
