const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = Number(process.env.PORT || 3000);
const HOST = process.env.HOST || '0.0.0.0';
const DATA_DIR = path.join(__dirname, 'data');
const DATA_FILE = path.join(DATA_DIR, 'db.json');
const PUBLIC_DIR = path.join(__dirname, 'public');

fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(DATA_FILE)) {
  fs.writeFileSync(DATA_FILE, JSON.stringify({ users: [], sessions: [], friendRequests: [], friendships: [] }, null, 2));
}

function loadDB() {
  try { return JSON.parse(fs.readFileSync(DATA_FILE, 'utf8')); }
  catch { return { users: [], sessions: [], friendRequests: [], friendships: [] }; }
}
function saveDB(db) { fs.writeFileSync(DATA_FILE, JSON.stringify(db, null, 2)); }
function id() { return crypto.randomBytes(18).toString('hex'); }
function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return { salt, hash };
}
function verifyPassword(password, salt, hash) {
  const check = crypto.scryptSync(password, salt, 64).toString('hex');
  return crypto.timingSafeEqual(Buffer.from(check, 'hex'), Buffer.from(hash, 'hex'));
}
function parseCookies(req) {
  const out = {};
  String(req.headers.cookie || '').split(';').forEach(part => {
    const idx = part.indexOf('=');
    if (idx > -1) out[part.slice(0, idx).trim()] = decodeURIComponent(part.slice(idx + 1).trim());
  });
  return out;
}
function json(res, code, payload) {
  const body = JSON.stringify(payload);
  res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
  res.end(body);
}
function redirect(res, location) { res.writeHead(302, { Location: location }); res.end(); }
function readBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => { body += chunk; if (body.length > 1e6) req.destroy(); });
    req.on('end', () => { try { resolve(body ? JSON.parse(body) : {}); } catch (e) { reject(e); } });
    req.on('error', reject);
  });
}
function cleanUsername(v) { return String(v || '').trim().toLowerCase(); }
function publicUser(u) { return { id: u.id, username: u.username, displayName: u.displayName, gender: u.gender || 'unspecified', joinedAt: u.joinedAt, lastSeen: u.lastSeen || null }; }
function getCurrentUser(db, req) {
  const sid = parseCookies(req).storybots_session;
  if (!sid) return null;
  const session = db.sessions.find(s => s.id === sid && s.expiresAt > Date.now());
  if (!session) return null;
  const user = db.users.find(u => u.id === session.userId);
  if (!user) return null;
  user.lastSeen = Date.now();
  return user;
}
function isFriends(db, a, b) {
  return db.friendships.some(f => (f.a === a && f.b === b) || (f.a === b && f.b === a));
}
function friendList(db, me) {
  return db.friendships.flatMap(f => {
    const otherId = f.a === me.id ? f.b : f.b === me.id ? f.a : null;
    if (!otherId) return [];
    const u = db.users.find(x => x.id === otherId);
    return u ? [publicUser(u)] : [];
  });
}
function pendingRequests(db, me) {
  return db.friendRequests.filter(r => r.to === me.id && r.status === 'pending').map(r => {
    const from = db.users.find(u => u.id === r.from);
    return { ...r, from: from ? publicUser(from) : null };
  });
}
function outgoing(db, me) { return db.friendRequests.filter(r => r.from === me.id && r.status === 'pending').map(r => { const to=db.users.find(u=>u.id===r.to); return { ...r, to: to ? publicUser(to) : null }; }); }

function serveStatic(req, res) {
  let reqPath = decodeURIComponent(new URL(req.url, `http://${req.headers.host || 'localhost'}`).pathname);
  if (reqPath === '/') reqPath = '/index.html';
  const safePath = path.normalize(reqPath).replace(/^([.][.][\\/])+/, '');
  const file = path.join(PUBLIC_DIR, safePath);
  if (!file.startsWith(PUBLIC_DIR)) return json(res, 403, { error: 'Forbidden' });
  fs.readFile(file, (err, data) => {
    if (err) return json(res, 404, { error: 'Not found' });
    const ext = path.extname(file);
    const mime = { '.html':'text/html; charset=utf-8', '.js':'text/javascript; charset=utf-8', '.css':'text/css; charset=utf-8', '.svg':'image/svg+xml', '.json':'application/json' }[ext] || 'application/octet-stream';
    res.writeHead(200, { 'Content-Type': mime, 'Cache-Control': 'no-cache' });
    res.end(data);
  });
}

async function handleAPI(req, res) {
  const db = loadDB();
  const u = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const pathname = u.pathname;
  const current = getCurrentUser(db, req);

  if (pathname === '/api/register' && req.method === 'POST') {
    const b = await readBody(req);
    const username = cleanUsername(b.username);
    const displayName = String(b.displayName || b.username || '').trim().slice(0, 40);
    const password = String(b.password || '');
    if (!/^[a-z0-9_]{3,20}$/.test(username)) return json(res, 400, { error:'El usuario debe tener 3–20 caracteres: letras, números o _.' });
    if (password.length < 6) return json(res, 400, { error:'La contraseña debe tener al menos 6 caracteres.' });
    if (db.users.some(x => x.username === username)) return json(res, 409, { error:'Ese nombre de usuario ya existe.' });
    const pw = hashPassword(password);
    const user = { id:id(), username, displayName:displayName || username, gender:String(b.gender || 'unspecified'), ...pw, joinedAt:Date.now(), lastSeen:Date.now() };
    db.users.push(user);
    const sid = id();
    db.sessions.push({ id:sid, userId:user.id, expiresAt:Date.now()+1000*60*60*24*30 });
    saveDB(db);
    res.setHeader('Set-Cookie', `storybots_session=${encodeURIComponent(sid)}; HttpOnly; SameSite=Lax; Path=/; Max-Age=2592000`);
    return json(res, 201, { user: publicUser(user) });
  }

  if (pathname === '/api/login' && req.method === 'POST') {
    const b = await readBody(req); const username = cleanUsername(b.username); const password=String(b.password||'');
    const user=db.users.find(x=>x.username===username);
    if(!user || !verifyPassword(password,user.salt,user.hash)) return json(res,401,{error:'Usuario o contraseña incorrectos.'});
    user.lastSeen=Date.now(); const sid=id(); db.sessions=db.sessions.filter(s=>s.userId!==user.id || s.expiresAt>Date.now()); db.sessions.push({id:sid,userId:user.id,expiresAt:Date.now()+1000*60*60*24*30}); saveDB(db);
    res.setHeader('Set-Cookie', `storybots_session=${encodeURIComponent(sid)}; HttpOnly; SameSite=Lax; Path=/; Max-Age=2592000`);
    return json(res,200,{user:publicUser(user)});
  }
  if (pathname === '/api/logout' && req.method === 'POST') {
    const sid=parseCookies(req).storybots_session; db.sessions=db.sessions.filter(s=>s.id!==sid); saveDB(db);
    res.setHeader('Set-Cookie','storybots_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0'); return json(res,200,{ok:true});
  }
  if (!current) return json(res,401,{error:'Inicia sesión para continuar.'});

  if (pathname === '/api/me' && req.method === 'GET') return json(res,200,{user:publicUser(current)});
  if (pathname === '/api/friends' && req.method === 'GET') return json(res,200,{friends:friendList(db,current), incoming:pendingRequests(db,current), outgoing:outgoing(db,current)});

  if (pathname === '/api/users/search' && req.method === 'GET') {
    const q=cleanUsername(u.searchParams.get('q'));
    const users=db.users.filter(x=>x.username.includes(q) && x.id!==current.id && !isFriends(db,current.id,x.id)).slice(0,12).map(publicUser);
    return json(res,200,{users});
  }

  if (pathname === '/api/friends/request' && req.method === 'POST') {
    const b=await readBody(req); const username=cleanUsername(b.username); const target=db.users.find(x=>x.username===username);
    if(!target) return json(res,404,{error:'No encontré ese usuario.'});
    if(target.id===current.id) return json(res,400,{error:'No puedes agregarte a ti mismo.'});
    if(isFriends(db,current.id,target.id)) return json(res,409,{error:'Ya son amigos.'});
    const reverse=db.friendRequests.find(r=>r.from===target.id && r.to===current.id && r.status==='pending');
    if(reverse) { reverse.status='accepted'; db.friendships.push({id:id(),a:current.id,b:target.id,createdAt:Date.now()}); saveDB(db); return json(res,200,{autoAccepted:true}); }
    const duplicate=db.friendRequests.find(r=>r.from===current.id && r.to===target.id && r.status==='pending');
    if(duplicate) return json(res,409,{error:'Ya enviaste una solicitud a esa persona.'});
    db.friendRequests.push({id:id(),from:current.id,to:target.id,status:'pending',createdAt:Date.now()}); saveDB(db); return json(res,201,{ok:true});
  }

  if (pathname === '/api/friends/respond' && req.method === 'POST') {
    const b=await readBody(req); const request=db.friendRequests.find(r=>r.id===b.requestId && r.to===current.id && r.status==='pending');
    if(!request) return json(res,404,{error:'Solicitud no encontrada.'});
    if(b.action==='accept') { request.status='accepted'; db.friendships.push({id:id(),a:request.from,b:request.to,createdAt:Date.now()}); }
    else request.status='declined';
    saveDB(db); return json(res,200,{ok:true});
  }
  if (pathname.startsWith('/api/friends/') && req.method==='DELETE') {
    const username=cleanUsername(pathname.split('/').pop()); const target=db.users.find(x=>x.username===username);
    if(!target) return json(res,404,{error:'Usuario no encontrado.'});
    db.friendships=db.friendships.filter(f=>!((f.a===current.id&&f.b===target.id)||(f.a===target.id&&f.b===current.id))); saveDB(db); return json(res,200,{ok:true});
  }

  return json(res,404,{error:'Ruta no encontrada.'});
}

const server=http.createServer(async (req,res)=>{
  try {
    if (req.url.startsWith('/api/')) return await handleAPI(req,res);
    return serveStatic(req,res);
  } catch (e) { console.error(e); if(!res.headersSent) json(res,500,{error:'Error interno del servidor.'}); }
});
server.listen(PORT,HOST,()=>console.log(`StoryBots Online: http://${HOST === '0.0.0.0' ? 'localhost' : HOST}:${PORT}`));
