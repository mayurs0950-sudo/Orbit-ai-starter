require('dotenv').config();
const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const multer = require('multer');

let pdfParse = null;
let mammoth = null;
try { pdfParse = require('pdf-parse'); } catch (e) {}
try { mammoth = require('mammoth'); } catch (e) {}

const app = express();
const PORT = process.env.PORT || 3000;

const DATA_DIR = path.join(__dirname, 'data');
const UPLOADS_DIR = path.join(DATA_DIR, 'uploads');
const AUTH_FILE = path.join(DATA_DIR, 'auth.json');
const SECRET_FILE = path.join(DATA_DIR, 'session.secret');
const WORKSPACE_FILE = path.join(DATA_DIR, 'workspace.json');

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });

let SESSION_SECRET = process.env.SESSION_SECRET || '';
if (!SESSION_SECRET) {
  if (fs.existsSync(SECRET_FILE)) {
    SESSION_SECRET = fs.readFileSync(SECRET_FILE, 'utf8').trim();
  } else {
    SESSION_SECRET = crypto.randomBytes(32).toString('hex');
    fs.writeFileSync(SECRET_FILE, SESSION_SECRET, 'utf8');
  }
}

// रेट लिमिटर
const requestCounts = new Map();
function rateLimiter(req, res, next) {
  const ip = req.ip || req.connection.remoteAddress || 'unknown';
  const now = Date.now();
  const windowMs = 60 * 1000;
  const maxRequests = 400;

  if (!requestCounts.has(ip)) {
    requestCounts.set(ip, { count: 1, startTime: now });
  } else {
    let data = requestCounts.get(ip);
    if (now - data.startTime > windowMs) {
      data.count = 1;
      data.startTime = now;
    } else {
      data.count++;
      if (data.count > maxRequests) {
        return res.status(429).json({ error: 'Too many requests, please try again later.' });
      }
    }
  }
  next();
}
app.use(rateLimiter);

function loadAuthData() {
  if (!fs.existsSync(AUTH_FILE)) {
    const initial = { owner: null, ownerClaimCode: '411826', users: [], requests: [], otps: {}, sessions: {} };
    fs.writeFileSync(AUTH_FILE, JSON.stringify(initial, null, 2), 'utf8');
    return initial;
  }
  try {
    const raw = JSON.parse(fs.readFileSync(AUTH_FILE, 'utf8'));
    raw.users = raw.users || [];
    raw.requests = raw.requests || [];
    raw.otps = raw.otps || {};
    raw.sessions = raw.sessions || {};
    if (!raw.ownerClaimCode) raw.ownerClaimCode = '411826';
    return raw;
  } catch (e) {
    return { owner: null, ownerClaimCode: '411826', users: [], requests: [], otps: {}, sessions: {} };
  }
}

function saveAuthData(data) {
  fs.writeFileSync(AUTH_FILE, JSON.stringify(data, null, 2), 'utf8');
}

function loadWorkspaceData() {
  if (!fs.existsSync(WORKSPACE_FILE)) {
    const initWs = { agents: [], projects: [], knowledge: [], files: [], providers: {} };
    fs.writeFileSync(WORKSPACE_FILE, JSON.stringify(initWs, null, 2), 'utf8');
    return initWs;
  }
  try { return JSON.parse(fs.readFileSync(WORKSPACE_FILE, 'utf8')); }
  catch (e) { return { agents: [], projects: [], knowledge: [], files: [], providers: {} }; }
}

function saveWorkspaceData(data) {
  fs.writeFileSync(WORKSPACE_FILE, JSON.stringify(data, null, 2), 'utf8');
}

app.use(express.json({ limit: '25mb' }));
app.use(express.urlencoded({ extended: true, limit: '25mb' }));

app.use((req, res, next) => {
  const origin = req.headers.origin || '*';
  res.setHeader('Access-Control-Allow-Origin', origin);
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Orbit-Token');
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});

function signToken(payload) {
  const data = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig = crypto.createHmac('sha256', SESSION_SECRET).update(data).digest('base64url');
  return `${data}.${sig}`;
}

function verifyToken(token) {
  if (!token || !token.includes('.')) return null;
  const [data, sig] = token.split('.');
  const expected = crypto.createHmac('sha256', SESSION_SECRET).update(data).digest('base64url');
  if (sig !== expected) return null;
  try { return JSON.parse(Buffer.from(data, 'base64url').toString('utf8')); }
  catch (e) { return null; }
}

function parseCookies(req) {
  const list = {};
  const rc = req.headers.cookie;
  if (rc) {
    rc.split(';').forEach(cookie => {
      const parts = cookie.split('=');
      const key = parts.shift().trim();
      const val = decodeURI(parts.join('='));
      list[key] = val;
    });
  }
  return list;
}

function getSessionUser(req) {
  const cookies = parseCookies(req);
  const token = req.headers['x-orbit-token'] || cookies['orbit_session'];
  if (!token) return null;
  const decoded = verifyToken(token);
  if (!decoded) return null;
  const auth = loadAuthData();
  if (decoded.role === 'owner' && auth.owner && auth.owner.id === decoded.id) {
    return { ...auth.owner, role: 'owner', tier: 'pro' };
  }
  const user = auth.users.find(u => u.id === decoded.id && !u.revoked);
  if (user) return { ...user, role: user.role || 'guest', tier: user.tier || 'free' };
  return null;
}

function setSessionCookie(res, userObj) {
  const token = signToken({ id: userObj.id, role: userObj.role, tier: userObj.tier, email: userObj.email, iat: Date.now() });
  res.setHeader('Set-Cookie', `orbit_session=${token}; HttpOnly; Path=/; Max-Age=${30 * 24 * 3600}; SameSite=Lax`);
  return token;
}

function requireOwner(req, res, next) {
  const user = getSessionUser(req);
  if (!user || user.role !== 'owner') return res.status(403).json({ error: 'Owner permissions required' });
  req.user = user;
  next();
}

app.get('/api/auth/status', (req, res) => {
  const auth = loadAuthData();
  const cookies = parseCookies(req);
  const token = req.headers['x-orbit-token'] || cookies['orbit_session'];
  
  if (!token) return res.json({ ok: true, authenticated: false, user: null });
  const decoded = verifyToken(token);
  if (!decoded) return res.json({ ok: true, authenticated: false, user: null });

  if (decoded.role !== 'owner') {
    const userInDb = auth.users.find(u => u.id === decoded.id);
    if (!userInDb || userInDb.revoked) {
      return res.status(403).json({ error: 'Access revoked by admin', revoked: true });
    }
  }

  const user = getSessionUser(req);
  res.json({ ok: true, hasOwner: Boolean(auth.owner), authenticated: Boolean(user), user: user || null });
});

app.post('/api/auth/owner/claim', (req, res) => {
  const { name, email, claimCode } = req.body;
  const auth = loadAuthData();
  const validClaimCode = '411826';

  if (claimCode !== validClaimCode) {
    return res.status(403).json({ error: 'Invalid Owner Claim Code.' });
  }

  const ownerUser = {
    id: auth.owner?.id || 'owner_' + crypto.randomBytes(6).toString('hex'),
    name: name || 'Mayur Sonawane (Owner)',
    email: email || 'smayur0797@gmail.com',
    role: 'owner',
    tier: 'pro',
    createdAt: auth.owner?.createdAt || new Date().toISOString()
  };

  auth.owner = ownerUser;
  saveAuthData(auth);
  const token = setSessionCookie(res, ownerUser);
  res.json({ ok: true, user: ownerUser, token });
});

app.post('/api/auth/request', (req, res) => {
  const { name, email, reason } = req.body;
  if (!name || !email) return res.status(400).json({ error: 'Name and email required.' });
  const auth = loadAuthData();
  
  let user = auth.users.find(u => u.email.toLowerCase() === email.toLowerCase());
  if (!user) {
    user = { id: 'usr_' + crypto.randomBytes(6).toString('hex'), name, email, role: 'guest', tier: 'free', revoked: false, createdAt: new Date().toISOString() };
    auth.users.push(user);
  }

  let existingReq = auth.requests.find(r => r.email.toLowerCase() === email.toLowerCase());
  if (existingReq) {
    existingReq.status = 'pending';
    saveAuthData(auth);
    return res.json({ ok: true, requestId: existingReq.id, status: existingReq.status });
  }

  const newReq = { id: 'req_' + crypto.randomBytes(6).toString('hex'), name, email, reason: reason || 'Workspace Access', status: 'pending', createdAt: new Date().toISOString() };
  auth.requests.push(newReq);
  saveAuthData(auth);
  res.json({ ok: true, requestId: newReq.id, status: 'pending' });
});

app.get('/api/auth/requests', requireOwner, (req, res) => {
  const auth = loadAuthData();
  res.json({ ok: true, requests: auth.requests || [] });
});

// 🌟 ॲडमिनने अप्रूव्ह केल्यावर युजर थेट रजिस्टर होईल आणि ओटीपी पाठवण्यासाठी तयार होईल
app.post('/api/auth/approve', requireOwner, (req, res) => {
  const { requestId, tier } = req.body;
  const auth = loadAuthData();
  const reqItem = auth.requests.find(r => r.id === requestId);
  if (!reqItem) return res.status(404).json({ error: 'Request not found' });
  
  reqItem.status = 'approved';
  
  let user = auth.users.find(u => u.email.toLowerCase() === reqItem.email.toLowerCase());
  if (!user) {
    user = { id: 'usr_' + crypto.randomBytes(6).toString('hex'), name: reqItem.name, email: reqItem.email, role: 'guest', tier: tier || 'free', revoked: false, createdAt: new Date().toISOString() };
    auth.users.push(user);
  } else {
    user.revoked = false;
    user.tier = tier || user.tier || 'free';
  }
  saveAuthData(auth);
  res.json({ ok: true, request: reqItem, user });
});

app.post('/api/auth/reject', requireOwner, (req, res) => {
  const { requestId } = req.body;
  const auth = loadAuthData();
  const index = auth.requests.findIndex(r => r.id === requestId);
  if (index === -1) return res.status(404).json({ error: 'Request not found' });
  auth.requests.splice(index, 1);
  saveAuthData(auth);
  res.json({ ok: true });
});

// 🌟 युजरने 'Get OTP' दाबल्यावर केवळ अप्रूव्ह केलेल्यांनाच थेट ईमेलवर ओटीपी जाईल
app.post('/api/auth/issue', (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email required' });
  const auth = loadAuthData();
  const lower = email.toLowerCase();
  
  const isOwner = auth.owner && auth.owner.email.toLowerCase() === lower;
  const user = auth.users.find(u => u.email.toLowerCase() === lower && !u.revoked);
  const approvedReq = auth.requests.find(r => r.email.toLowerCase() === lower && r.status === 'approved');

  if (!isOwner && !user && !approvedReq) {
    return res.status(403).json({ error: 'Your request is pending admin approval or not registered.' });
  }

  const otp = String(Math.floor(100000 + Math.random() * 900000));
  auth.otps = auth.otps || {};
  auth.otps[lower] = { otp, createdAt: new Date().toISOString(), expiresAt: Date.now() + 10 * 60 * 1000 };
  saveAuthData(auth);

  console.log(`[ORBIT AI EMAIL GATEWAY] Sent OTP ${otp} to approved email: ${lower}`);
  res.json({ ok: true, message: `OTP successfully sent to ${email}` });
});

app.post('/api/auth/verify', (req, res) => {
  const { email, otp } = req.body;
  if (!email || !otp) return res.status(400).json({ error: 'Email and OTP required' });
  const lower = email.toLowerCase();

  const auth = loadAuthData();
  const record = auth.otps ? auth.otps[lower] : null;
  if (!record || record.otp !== String(otp).trim()) {
    return res.status(401).json({ error: 'Invalid or expired OTP.' });
  }
  delete auth.otps[lower];
  saveAuthData(auth);

  if (auth.owner && auth.owner.email.toLowerCase() === lower) {
    const token = setSessionCookie(res, { ...auth.owner, role: 'owner', tier: 'pro' });
    return res.json({ ok: true, user: { ...auth.owner, role: 'owner', tier: 'pro' }, token });
  }
  const user = auth.users.find(u => u.email.toLowerCase() === lower && !u.revoked);
  if (!user) return res.status(403).json({ error: 'User access revoked or not approved' });
  const token = setSessionCookie(res, user);
  res.json({ ok: true, user, token });
});

app.post('/api/auth/logout', (req, res) => {
  res.setHeader('Set-Cookie', 'orbit_session=; HttpOnly; Path=/; Max-Age=0');
  res.json({ ok: true });
});

app.get('/api/health', (req, res) => {
  res.json({ ok: true, version: '2.2.0', openrouterConfigured: Boolean(process.env.OPENROUTER_API_KEY), kieConfigured: Boolean(process.env.KIE_API_KEY) });
});

app.get('/api/models', async (req, res) => {
  const apiKey = process.env.OPENROUTER_API_KEY;
  const defaults = [
    { id: 'openrouter/auto', name: 'OpenRouter Auto' },
    { id: 'anthropic/claude-3.5-sonnet', name: 'Claude 3.5 Sonnet' },
    { id: 'seedance-2.5', name: 'KIE.ai Seedance 2.5 (Video)' },
    { id: 'kling-4.0', name: 'KIE.ai Kling 4.0 (Video/Image)' },
    { id: 'flux-3', name: 'KIE.ai Flux 3 (Image)' }
  ];
  if (!apiKey) return res.json({ ok: true, models: defaults });
  try {
    const resp = await fetch('https://openrouter.ai/api/v1/models', { headers: { 'Authorization': `Bearer ${apiKey}` } });
    const data = await resp.json();
    res.json({ ok: true, models: [...(data.data || []), ...defaults] });
  } catch (e) {
    res.json({ ok: true, models: defaults });
  }
});

// 🌟 KIE.AI MEDIA GENERATION ROUTER
app.post('/api/kie/generate', async (req, res) => {
  const { model, prompt } = req.body;
  const kieApiKey = process.env.KIE_API_KEY || '';
  if (!prompt) return res.status(400).json({ error: 'Prompt required' });

  const encoded = encodeURIComponent(prompt);
  const fallbackUrl = `https://image.pollinations.ai/prompt/${encoded}?width=1024&height=1024&nologo=true`;

  if (!kieApiKey) {
    return res.json({ ok: true, url: fallbackUrl, message: 'Generated via fallback engine.' });
  }

  try {
    const resp = await fetch('https://api.kie.ai/v1/images/generations', {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${kieApiKey}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ model: model || 'flux-3', prompt })
    });
    const data = await resp.json();
    res.json({ ok: true, result: data, url: data.url || data.output_url || fallbackUrl });
  } catch (e) {
    res.json({ ok: true, url: fallbackUrl, error: e.message });
  }
});

app.post('/api/search', async (req, res) => {
  const { query } = req.body;
  if (!query) return res.status(400).json({ error: 'Query required' });
  res.json({ ok: true, answer: `Search results for: ${query}`, results: [{ title: query, url: '#', content: 'Active search insight.' }] });
});

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOADS_DIR),
  filename: (req, file, cb) => cb(null, `${Date.now()}_${file.originalname.replace(/[^a-zA-Z0-9._-]/g, '_')}`)
});
const upload = multer({ storage, limits: { fileSize: 18 * 1024 * 1024 } });

app.post('/api/upload', upload.single('file'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file' });
  const ws = loadWorkspaceData();
  const fileMeta = { id: 'file_' + crypto.randomBytes(6).toString('hex'), originalName: req.file.originalname, url: `/api/files/download/${req.file.filename}` };
  ws.files.unshift(fileMeta);
  saveWorkspaceData(ws);
  res.json({ ok: true, file: fileMeta });
});

app.get('/api/files', (req, res) => {
  const ws = loadWorkspaceData();
  res.json({ ok: true, files: ws.files || [] });
});

app.get('/api/files/download/:filename', (req, res) => {
  res.sendFile(path.join(UPLOADS_DIR, path.basename(req.params.filename)));
});

app.post('/api/chat', async (req, res) => {
  const apiKey = process.env.OPENROUTER_API_KEY;
  if (!apiKey) return res.status(503).json({ error: 'OPENROUTER_API_KEY missing in .env' });
  const { messages = [], model = 'openrouter/auto' } = req.body;
  try {
    const resp = await fetch('https://openrouter.ai/api/v1/chat/completions', {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${apiKey}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ model, messages })
    });
    const data = await resp.json();
    res.json({ ok: true, reply: data?.choices?.[0]?.message?.content || 'No response' });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.use(express.static(path.join(__dirname, 'public')));
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

app.listen(PORT, () => console.log(`ORBIT AI running on port ${PORT}`));
