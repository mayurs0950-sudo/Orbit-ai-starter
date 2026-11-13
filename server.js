
'use strict';

require('dotenv').config();

const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const multer = require('multer');

let pdfParse = null;
let mammoth = null;

try {
  pdfParse = require('pdf-parse');
} catch (e) {
  console.log('PDF parser not installed');
}

try {
  mammoth = require('mammoth');
} catch (e) {
  console.log('Mammoth not installed');
}

const app = express();
const PORT = process.env.PORT || 3000;

// =====================================================
// ORBIT AI — DIRECTORIES
// =====================================================

const DATA_DIR = path.join(__dirname, 'data');
const UPLOADS_DIR = path.join(DATA_DIR, 'uploads');
const PUBLIC_DIR = path.join(__dirname, 'public');

const AUTH_FILE = path.join(DATA_DIR, 'auth.json');
const SECRET_FILE = path.join(DATA_DIR, 'session.secret');
const WORKSPACE_FILE = path.join(DATA_DIR, 'workspace.json');
const INDEX_FILE = path.join(PUBLIC_DIR, 'index.html');

for (const dir of [DATA_DIR, UPLOADS_DIR]) {
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
}

// =====================================================
// SESSION SECRET
// =====================================================

let SESSION_SECRET = process.env.SESSION_SECRET || '';

if (!SESSION_SECRET) {
  if (fs.existsSync(SECRET_FILE)) {
    SESSION_SECRET = fs.readFileSync(SECRET_FILE, 'utf8').trim();
  } else {
    SESSION_SECRET = crypto.randomBytes(32).toString('hex');
    fs.writeFileSync(SECRET_FILE, SESSION_SECRET, 'utf8');
  }
}

// =====================================================
// RATE LIMITING
// =====================================================

const requestCounts = new Map();
const otpStore = new Map();

function rateLimiter(req, res, next) {
  const ip = req.ip || req.socket.remoteAddress || 'unknown';
  const now = Date.now();
  const windowMs = 15 * 60 * 1000;
  const maxRequests = 100;

  let data = requestCounts.get(ip);

  if (!data || now - data.startTime > windowMs) {
    requestCounts.set(ip, {
      count: 1,
      startTime: now
    });
    return next();
  }

  data.count++;

  if (data.count > maxRequests) {
    return res.status(429).json({
      ok: false,
      error: 'Too many requests. Please try again later.'
    });
  }

  next();
}

app.use(rateLimiter);

// =====================================================
// OTP VERIFICATION
// =====================================================

function verifyOtpForEmail(email, enteredOtp) {
  const record = otpStore.get(email);

  if (!record) {
    return {
      success: false,
      message: 'OTP not requested or expired.'
    };
  }

  if (Date.now() > record.expiresAt) {
    otpStore.delete(email);

    return {
      success: false,
      message: 'OTP expired. Request a new OTP.'
    };
  }

  if (record.attempts >= 3) {
    otpStore.delete(email);

    return {
      success: false,
      message: 'Maximum attempts exceeded.'
    };
  }

  if (record.otp !== enteredOtp) {
    record.attempts++;

    return {
      success: false,
      message: `Invalid OTP. ${3 - record.attempts} attempts remaining.`
    };
  }

  otpStore.delete(email);

  return { success: true };
}

// =====================================================
// AUTH DATABASE
// =====================================================

function loadAuthData() {
  if (!fs.existsSync(AUTH_FILE)) {
    const initial = {
      owner: null,
      ownerClaimCode: process.env.OWNER_CLAIM_CODE || '411826',
      users: [],
      requests: [],
      otps: {},
      sessions: {}
    };

    saveAuthData(initial);
    return initial;
  }

  try {
    const raw = JSON.parse(fs.readFileSync(AUTH_FILE, 'utf8'));

    raw.users = raw.users || [];
    raw.requests = raw.requests || [];
    raw.otps = raw.otps || {};
    raw.sessions = raw.sessions || {};

    if (!raw.ownerClaimCode) {
      raw.ownerClaimCode = process.env.OWNER_CLAIM_CODE || '411826';
    }

    return raw;
  } catch (error) {
    console.error('Auth database error:', error.message);

    return {
      owner: null,
      ownerClaimCode: process.env.OWNER_CLAIM_CODE || '411826',
      users: [],
      requests: [],
      otps: {},
      sessions: {}
    };
  }
}

function saveAuthData(data) {
  fs.writeFileSync(
    AUTH_FILE,
    JSON.stringify(data, null, 2),
    'utf8'
  );
}

// =====================================================
// WORKSPACE DATABASE
// =====================================================

function loadWorkspaceData() {
  if (!fs.existsSync(WORKSPACE_FILE)) {
    const initial = {
      agents: [],
      projects: [],
      knowledge: [],
      files: [],
      providers: {}
    };

    saveWorkspaceData(initial);
    return initial;
  }

  try {
    return JSON.parse(
      fs.readFileSync(WORKSPACE_FILE, 'utf8')
    );
  } catch (error) {
    console.error('Workspace database error:', error.message);

    return {
      agents: [],
      projects: [],
      knowledge: [],
      files: [],
      providers: {}
    };
  }
}

function saveWorkspaceData(data) {
  fs.writeFileSync(
    WORKSPACE_FILE,
    JSON.stringify(data, null, 2),
    'utf8'
  );
}

// =====================================================
// BODY PARSING
// =====================================================

app.use(express.json({ limit: '25mb' }));
app.use(express.urlencoded({
  extended: true,
  limit: '25mb'
}));

// =====================================================
// CORS
// =====================================================

app.use((req, res, next) => {
  const allowedOrigins = (process.env.ALLOWED_ORIGINS || '')
    .split(',')
    .map(origin => origin.trim())
    .filter(Boolean);

  const origin = req.headers.origin;

  if (
    !origin ||
    allowedOrigins.includes(origin) ||
    (process.env.NODE_ENV !== 'production' && allowedOrigins.length === 0)
  ) {
    res.setHeader('Access-Control-Allow-Origin', origin || '*');

    if (origin && allowedOrigins.length > 0) {
      res.setHeader('Vary', 'Origin');
    }

    res.setHeader('Access-Control-Allow-Credentials', 'true');
  }

  res.setHeader(
    'Access-Control-Allow-Methods',
    'GET,POST,PUT,DELETE,OPTIONS'
  );

  res.setHeader(
    'Access-Control-Allow-Headers',
    'Content-Type, Authorization, X-Orbit-Token'
  );

  if (req.method === 'OPTIONS') {
    return res.sendStatus(204);
  }

  next();
});

// =====================================================
// TOKEN SYSTEM
// =====================================================

function signToken(payload) {
  const data = Buffer.from(
    JSON.stringify(payload)
  ).toString('base64url');

  const signature = crypto
    .createHmac('sha256', SESSION_SECRET)
    .update(data)
    .digest('base64url');

  return `${data}.${signature}`;
}

function verifyToken(token) {
  if (!token || typeof token !== 'string') {
    return null;
  }

  const parts = token.split('.');

  if (parts.length !== 2) {
    return null;
  }

  const [data, signature] = parts;

  const expected = crypto
    .createHmac('sha256', SESSION_SECRET)
    .update(data)
    .digest('base64url');

  const suppliedBuffer = Buffer.from(signature);
  const expectedBuffer = Buffer.from(expected);

  if (
    suppliedBuffer.length !== expectedBuffer.length ||
    !crypto.timingSafeEqual(suppliedBuffer, expectedBuffer)
  ) {
    return null;
  }

  try {
    const payload = JSON.parse(
      Buffer.from(data, 'base64url').toString('utf8')
    );

    if (
      !payload.iat ||
      Date.now() - payload.iat > 30 * 24 * 60 * 60 * 1000
    ) {
      return null;
    }

    return payload;
  } catch (error) {
    return null;
  }
}

// =====================================================
// COOKIE SYSTEM
// =====================================================

function parseCookies(req) {
  const cookies = {};
  const cookieHeader = req.headers.cookie;

  if (!cookieHeader) return cookies;

  cookieHeader.split(';').forEach(cookie => {
    const parts = cookie.split('=');
    const key = parts.shift().trim();

    cookies[key] = decodeURIComponent(
      parts.join('=')
    );
  });

  return cookies;
}

function getSessionUser(req) {
  const cookies = parseCookies(req);

  const token =
    req.headers['x-orbit-token'] ||
    cookies.orbit_session;

  if (!token) return null;

  const decoded = verifyToken(token);

  if (!decoded) return null;

  const auth = loadAuthData();

  if (
    decoded.role === 'owner' &&
    auth.owner &&
    auth.owner.id === decoded.id
  ) {
    return {
      ...auth.owner,
      role: 'owner',
      tier: 'pro'
    };
  }

  const user = auth.users.find(
    item => item.id === decoded.id && !item.revoked
  );

  if (!user) return null;

  return {
    ...user,
    role: user.role || 'guest',
    tier: user.tier || 'free'
  };
}

function setSessionCookie(res, user) {
  const token = signToken({
    id: user.id,
    role: user.role,
    tier: user.tier,
    email: user.email,
    iat: Date.now()
  });

  const secure = process.env.NODE_ENV === 'production'
    ? 'Secure; '
    : '';

  res.setHeader(
    'Set-Cookie',
    `orbit_session=${token}; HttpOnly; Path=/; Max-Age=2592000; SameSite=Lax; ${secure}`
  );

  return token;
}

// =====================================================
// AUTH MIDDLEWARE
// =====================================================

function requireOwner(req, res, next) {
  const user = getSessionUser(req);

  if (!user || user.role !== 'owner') {
    return res.status(403).json({
      ok: false,
      error: 'Owner permissions required.'
    });
  }

  req.user = user;
  next();
}

function requireAuth(req, res, next) {
  const user = getSessionUser(req);

  if (!user) {
    return res.status(401).json({
      ok: false,
      error: 'Authentication required.'
    });
  }

  req.user = user;
  next();
}

// =====================================================
// AUTH STATUS
// =====================================================

app.get('/api/auth/status', (req, res) => {
  const auth = loadAuthData();
  const user = getSessionUser(req);

  res.json({
    ok: true,
    hasOwner: Boolean(auth.owner),
    authenticated: Boolean(user),
    user: user || null
  });
});

// =====================================================
// OWNER CLAIM
// =====================================================

app.post('/api/auth/owner/claim', (req, res) => {
  const { name, email, claimCode } = req.body;
  const auth = loadAuthData();

  if (!name || !email || !claimCode) {
    return res.status(400).json({
      error: 'Name, email and claim code required.'
    });
  }

  const validCode = auth.ownerClaimCode;

  const provided = Buffer.from(String(claimCode));
  const expected = Buffer.from(String(validCode));

  if (
    provided.length !== expected.length ||
    !crypto.timingSafeEqual(provided, expected)
  ) {
    return res.status(403).json({
      error: 'Invalid Owner Claim Code.'
    });
  }

  if (
    auth.owner &&
    auth.owner.email.toLowerCase() !== email.toLowerCase()
  ) {
    return res.status(403).json({
      error: 'Owner is already registered.'
    });
  }

  const owner = {
    id: auth.owner?.id ||
      'owner_' + crypto.randomBytes(6).toString('hex'),
    name,
    email: email.toLowerCase(),
    role: 'owner',
    tier: 'pro',
    createdAt: auth.owner?.createdAt ||
      new Date().toISOString()
  };

  auth.owner = owner;
  saveAuthData(auth);

  const token = setSessionCookie(res, owner);

  res.json({
    ok: true,
    user: owner,
    token
  });
});

// =====================================================
// ACCESS REQUEST
// =====================================================

app.post('/api/auth/request', (req, res) => {
  const { name, email, reason } = req.body;

  if (!name || !email) {
    return res.status(400).json({
      error: 'Name and email required.'
    });
  }

  const auth = loadAuthData();
  const lower = email.toLowerCase();

  let user = auth.users.find(
    item => item.email.toLowerCase() === lower
  );

  if (!user) {
    user = {
      id: 'usr_' + crypto.randomBytes(6).toString('hex'),
      name,
      email: lower,
      role: 'guest',
      tier: 'free',
      revoked: false,
      createdAt: new Date().toISOString()
    };

    auth.users.push(user);
  }

  let existing = auth.requests.find(
    item => item.email.toLowerCase() === lower &&
      item.status === 'pending'
  );

  if (existing) {
    return res.json({
      ok: true,
      requestId: existing.id,
      status: existing.status
    });
  }

  const newRequest = {
    id: 'req_' + crypto.randomBytes(6).toString('hex'),
    name,
    email: lower,
    reason: reason || 'Workspace Access',
    status: 'pending',
    createdAt: new Date().toISOString()
  };

  auth.requests.push(newRequest);
  saveAuthData(auth);

  res.json({
    ok: true,
    requestId: newRequest.id,
    status: 'pending'
  });
});

// =====================================================
// OWNER REQUEST MANAGEMENT
// =====================================================

app.get('/api/auth/requests', requireOwner, (req, res) => {
  const auth = loadAuthData();

  res.json({
    ok: true,
    requests: auth.requests
  });
});

app.post('/api/auth/approve', requireOwner, (req, res) => {
  const { requestId, tier } = req.body;
  const auth = loadAuthData();

  const request = auth.requests.find(
    item => item.id === requestId
  );

  if (!request) {
    return res.status(404).json({
      error: 'Request not found.'
    });
  }

  request.status = 'approved';

  let user = auth.users.find(
    item => item.email.toLowerCase() ===
      request.email.toLowerCase()
  );

  if (!user) {
    user = {
      id: 'usr_' + crypto.randomBytes(6).toString('hex'),
      name: request.name,
      email: request.email,
      role: 'guest',
      tier: tier === 'pro' ? 'pro' : 'free',
      revoked: false,
      createdAt: new Date().toISOString()
    };

    auth.users.push(user);
  } else {
    user.revoked = false;
    user.tier = tier === 'pro' ? 'pro' : 'free';
  }

  saveAuthData(auth);

  res.json({
    ok: true,
    request,
    user
  });
});

app.post('/api/auth/reject', requireOwner, (req, res) => {
  const { requestId } = req.body;
  const auth = loadAuthData();

  const request = auth.requests.find(
    item => item.id === requestId
  );

  if (!request) {
    return res.status(404).json({
      error: 'Request not found.'
    });
  }

  request.status = 'rejected';

  const user = auth.users.find(
    item => item.email.toLowerCase() ===
      request.email.toLowerCase()
  );

  if (user) user.revoked = true;

  saveAuthData(auth);

  res.json({
    ok: true,
    request
  });
});

// =====================================================
// OTP ISSUE
// =====================================================

app.post('/api/auth/issue', (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({
      error: 'Email required.'
    });
  }

  const auth = loadAuthData();
  const lower = email.toLowerCase();

  const isOwner = auth.owner &&
    auth.owner.email.toLowerCase() === lower;

  const user = auth.users.find(
    item => item.email.toLowerCase() === lower &&
      !item.revoked
  );

  if (!isOwner && !user) {
    return res.status(403).json({
      error: 'Email not found or access not approved.'
    });
  }

  const otp = String(
    crypto.randomInt(100000, 1000000)
  );

  otpStore.set(lower, {
    otp,
    expiresAt: Date.now() + 5 * 60 * 1000,
    attempts: 0
  });

  const response = {
    ok: true,
    message: 'OTP generated.'
  };

  // Development mode only
  if (process.env.NODE_ENV !== 'production') {
    response.devOtp = otp;
  }

  res.json(response);
});

// =====================================================
// OTP VERIFY
// =====================================================

app.post('/api/auth/verify', (req, res) => {
  const { email, otp } = req.body;

  if (!email || !otp) {
    return res.status(400).json({
      error: 'Email and OTP required.'
    });
  }

  const lower = email.toLowerCase();

  const result = verifyOtpForEmail(
    lower,
    String(otp).trim()
  );

  if (!result.success) {
    return res.status(401).json({
      error: result.message
    });
  }

  const auth = loadAuthData();

  if (
    auth.owner &&
    auth.owner.email.toLowerCase() === lower
  ) {
    const owner = {
      ...auth.owner,
      role: 'owner',
      tier: 'pro'
    };

    const token = setSessionCookie(res, owner);

    return res.json({
      ok: true,
      user: owner,
      token
    });
  }

  const user = auth.users.find(
    item => item.email.toLowerCase() === lower &&
      !item.revoked
  );

  if (!user) {
    return res.status(403).json({
      error: 'User access revoked or not approved.'
    });
  }

  const token = setSessionCookie(res, user);

  res.json({
    ok: true,
    user,
    token
  });
});

// =====================================================
// USER MANAGEMENT
// =====================================================

app.get('/api/auth/users', requireOwner, (req, res) => {
  const auth = loadAuthData();

  res.json({
    ok: true,
    users: auth.users,
    owner: auth.owner
  });
});

app.post('/api/auth/users/tier', requireOwner, (req, res) => {
  const { userId, tier } = req.body;
  const auth = loadAuthData();

  const user = auth.users.find(
    item => item.id === userId
  );

  if (!user) {
    return res.status(404).json({
      error: 'User not found.'
    });
  }

  user.tier = tier === 'pro' ? 'pro' : 'free';

  saveAuthData(auth);

  res.json({
    ok: true,
    user
  });
});

app.post('/api/auth/users/revoke', requireOwner, (req, res) => {
  const { userId, revoked } = req.body;
  const auth = loadAuthData();

  const user = auth.users.find(
    item => item.id === userId
  );

  if (!user) {
    return res.status(404).json({
      error: 'User not found.'
    });
  }

  user.revoked = Boolean(revoked);

  saveAuthData(auth);

  res.json({
    ok: true,
    user
  });
});

// =====================================================
// LOGOUT
// =====================================================

app.post('/api/auth/logout', (req, res) => {
  res.setHeader(
    'Set-Cookie',
    'orbit_session=; HttpOnly; Path=/; Max-Age=0; SameSite=Lax'
  );

  res.json({ ok: true });
});

// =====================================================
// HEALTH CHECK
// =====================================================

app.get('/api/health', (req, res) => {
  res.json({
    ok: true,
    name: 'ORBIT AI',
    version: '2.1.0',
    status: 'running',
    openrouterConfigured: Boolean(
      process.env.OPENROUTER_API_KEY
    ),
    frontendAvailable: fs.existsSync(INDEX_FILE)
  });
});

// =====================================================
// OPENROUTER MODELS
// =====================================================

app.get('/api/models', async (req, res) => {
  const apiKey = process.env.OPENROUTER_API_KEY;

  const defaults = [
    {
      id: 'openrouter/auto',
      name: 'OpenRouter Auto'
    },
    {
      id: 'anthropic/claude-3.5-sonnet',
      name: 'Claude 3.5 Sonnet'
    }
  ];

  if (!apiKey) {
    return res.json({
      ok: true,
      models: defaults
    });
  }

  try {
    const response = await fetch(
      'https://openrouter.ai/api/v1/models',
      {
        headers: {
          Authorization: `Bearer ${apiKey}`
        },
        signal: AbortSignal.timeout(20000)
      }
    );

    if (!response.ok) {
      throw new Error(`OpenRouter error: ${response.status}`);
    }

    const data = await response.json();

    res.json({
      ok: true,
      models: data.data || defaults
    });

  } catch (error) {
    console.error('Models error:', error.message);

    res.json({
      ok: true,
      models: defaults,
      warning: 'Using default models.'
    });
  }
});

// =====================================================
