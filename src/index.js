// קופסת המתכונים — recipe-box social network
// Cloudflare Worker + D1 + R2. Hebrew RTL. Free tier only.

const enc = new TextEncoder();

function uid() {
  const b = new Uint8Array(16);
  crypto.getRandomValues(b);
  return [...b].map(x => x.toString(16).padStart(2, '0')).join('');
}
function token() {
  const b = new Uint8Array(32);
  crypto.getRandomValues(b);
  return [...b].map(x => x.toString(16).padStart(2, '0')).join('');
}
async function hashPass(password, saltHex) {
  const salt = new Uint8Array(saltHex.match(/.{2}/g).map(h => parseInt(h, 16)));
  const key = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' }, key, 256);
  return [...new Uint8Array(bits)].map(x => x.toString(16).padStart(2, '0')).join('');
}
function newSalt() {
  const b = new Uint8Array(16);
  crypto.getRandomValues(b);
  return [...b].map(x => x.toString(16).padStart(2, '0')).join('');
}
function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', ...headers },
  });
}
function esc(s) {
  return String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

async function currentUser(request, env) {
  const cookie = request.headers.get('Cookie') || '';
  const m = cookie.match(/(?:^|;\s*)matkon_session=([a-f0-9]{64})/);
  if (!m) return null;
  const row = await env.DB.prepare(
    `SELECT u.id, u.name, u.role FROM sessions s JOIN users u ON u.id = s.user_id
     WHERE s.token = ? AND s.expires_at > datetime('now')`
  ).bind(m[1]).first();
  return row || null;
}
function sessionCookie(t) {
  return `matkon_session=${t}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=2592000`;
}

const MAX_PHOTO = 5 * 1024 * 1024;
const OK_TYPES = { 'image/jpeg': 'jpg', 'image/png': 'png', 'image/webp': 'webp' };

async function savePhoto(file, env) {
  if (!file || typeof file === 'string') return { error: 'חסרה תמונה' };
  const ext = OK_TYPES[file.type];
  if (!ext) return { error: 'סוג קובץ לא נתמך (רק JPG, PNG או WebP)' };
  if (file.size > MAX_PHOTO) return { error: 'התמונה גדולה מדי (עד 5MB)' };
  const key = `${uid()}.${ext}`;
  await env.PHOTOS.put(key, await file.arrayBuffer(), { metadata: { ct: file.type } });
  return { key };
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const p = url.pathname;
    const method = request.method;

    try {
      // ---------- API ----------
      if (p === '/api/signup' && method === 'POST') {
        const { name, password, role } = await request.json().catch(() => ({}));
        if (!name || !String(name).trim()) return json({ error: 'צריך שם' }, 400);
        if (!password || String(password).length < 4) return json({ error: 'סיסמה קצרה מדי (לפחות 4 תווים)' }, 400);
        if (!['creator', 'responder'].includes(role)) return json({ error: 'צריך לבחור תפקיד' }, 400);
        const salt = newSalt();
        const hash = await hashPass(String(password), salt);
        const id = uid();
        try {
          await env.DB.prepare(
            `INSERT INTO users (id, name, pass_hash, salt, role, created_at) VALUES (?,?,?,?,?,datetime('now'))`
          ).bind(id, String(name).trim().slice(0, 40), hash, salt, role).run();
        } catch (e) {
          return json({ error: 'שגיאה ביצירת המשתמש' }, 500);
        }
        const t = token();
        await env.DB.prepare(
          `INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?,?,datetime('now'),datetime('now','+30 days'))`
        ).bind(t, id).run();
        return json({ ok: true, user: { id, name: String(name).trim(), role } }, 200, { 'Set-Cookie': sessionCookie(t) });
      }

      if (p === '/api/login' && method === 'POST') {
        const { name, password } = await request.json().catch(() => ({}));
        const user = await env.DB.prepare(`SELECT * FROM users WHERE name = ?`).bind(String(name || '').trim()).first();
        if (!user) return json({ error: 'שם או סיסמה שגויים' }, 401);
        const hash = await hashPass(String(password || ''), user.salt);
        if (hash !== user.pass_hash) return json({ error: 'שם או סיסמה שגויים' }, 401);
        const t = token();
        await env.DB.prepare(
          `INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?,?,datetime('now'),datetime('now','+30 days'))`
        ).bind(t, user.id).run();
        return json({ ok: true, user: { id: user.id, name: user.name, role: user.role } }, 200, { 'Set-Cookie': sessionCookie(t) });
      }

      if (p === '/api/logout' && method === 'POST') {
        const cookie = request.headers.get('Cookie') || '';
        const m = cookie.match(/(?:^|;\s*)matkon_session=([a-f0-9]{64})/);
        if (m) await env.DB.prepare(`DELETE FROM sessions WHERE token = ?`).bind(m[1]).run();
        return json({ ok: true }, 200, { 'Set-Cookie': 'matkon_session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0' });
      }

      if (p === '/api/me' && method === 'GET') {
        const u = await currentUser(request, env);
        return json({ user: u });
      }

      if (p === '/api/recipes' && method === 'GET') {
        const rows = await env.DB.prepare(
          `SELECT r.id, r.title, r.photo_key, r.created_at, u.name AS creator_name,
                  (SELECT COUNT(*) FROM responses x WHERE x.recipe_id = r.id) AS response_count
           FROM recipes r JOIN users u ON u.id = r.user_id
           ORDER BY r.created_at DESC LIMIT 100`
        ).all();
        return json({ recipes: rows.results || [] });
      }

      if (p === '/api/recipes' && method === 'POST') {
        const u = await currentUser(request, env);
        if (!u) return json({ error: 'צריך להתחבר' }, 401);
        if (u.role !== 'creator') return json({ error: 'רק יוצרים יכולים להעלות מתכון' }, 403);
        const form = await request.formData();
        const title = String(form.get('title') || '').trim().slice(0, 120);
        const ingredients = String(form.get('ingredients') || '').trim().slice(0, 4000);
        const instructions = String(form.get('instructions') || '').trim().slice(0, 8000);
        if (!title) return json({ error: 'צריך שם למתכון' }, 400);
        if (!ingredients) return json({ error: 'צריך רשימת מרכיבים' }, 400);
        if (!instructions) return json({ error: 'צריך הוראות הכנה' }, 400);
        const saved = await savePhoto(form.get('photo'), env);
        if (saved.error) return json({ error: saved.error }, 400);
        const id = uid();
        await env.DB.prepare(
          `INSERT INTO recipes (id, user_id, title, ingredients, instructions, photo_key, created_at)
           VALUES (?,?,?,?,?,?,datetime('now'))`
        ).bind(id, u.id, title, ingredients, instructions, saved.key).run();
        return json({ ok: true, id });
      }

      const rm = p.match(/^\/api\/recipes\/([a-f0-9]{32})(\/responses)?$/);
      if (rm && method === 'GET' && !rm[2]) {
        const r = await env.DB.prepare(
          `SELECT r.*, u.name AS creator_name FROM recipes r JOIN users u ON u.id = r.user_id WHERE r.id = ?`
        ).bind(rm[1]).first();
        if (!r) return json({ error: 'מתכון לא נמצא' }, 404);
        const resp = await env.DB.prepare(
          `SELECT x.id, x.photo_key, x.created_at, u.name AS responder_name
           FROM responses x JOIN users u ON u.id = x.user_id
           WHERE x.recipe_id = ? ORDER BY x.created_at DESC`
        ).bind(rm[1]).all();
        return json({
          recipe: { id: r.id, title: r.title, ingredients: r.ingredients, instructions: r.instructions, photo_key: r.photo_key, created_at: r.created_at, creator_name: r.creator_name },
          responses: resp.results || [],
        });
      }

      if (rm && rm[2] && method === 'POST') {
        const u = await currentUser(request, env);
        if (!u) return json({ error: 'צריך להתחבר' }, 401);
        if (u.role !== 'responder') return json({ error: 'רק מגיבים יכולים להעלות תמונת הכנה' }, 403);
        const r = await env.DB.prepare(`SELECT id FROM recipes WHERE id = ?`).bind(rm[1]).first();
        if (!r) return json({ error: 'מתכון לא נמצא' }, 404);
        const form = await request.formData();
        const saved = await savePhoto(form.get('photo'), env);
        if (saved.error) return json({ error: saved.error }, 400);
        const id = uid();
        await env.DB.prepare(
          `INSERT INTO responses (id, recipe_id, user_id, photo_key, created_at) VALUES (?,?,?,?,datetime('now'))`
        ).bind(id, rm[1], u.id, saved.key).run();
        return json({ ok: true, id });
      }

      // ---------- Images from R2 ----------
      const im = p.match(/^\/img\/([a-f0-9]{32}\.(?:jpg|png|webp))$/);
      if (im && method === 'GET') {
        const { value, metadata } = await env.PHOTOS.getWithMetadata(im[1], 'arrayBuffer');
        if (!value) return new Response('not found', { status: 404 });
        return new Response(value, {
          headers: {
            'Content-Type': (metadata && metadata.ct) || 'image/jpeg',
            'Cache-Control': 'public, max-age=31536000, immutable',
          },
        });
      }

      // ---------- Frontend ----------
      if (method === 'GET') {
        return new Response(HTML, { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
      }
      return json({ error: 'not found' }, 404);
    } catch (e) {
      return json({ error: 'שגיאת שרת: ' + (e && e.message ? e.message : 'unknown') }, 500);
    }
  },
};

const HTML = "<!DOCTYPE html>\n<html lang=\"he\" dir=\"rtl\">\n<head>\n<meta charset=\"utf-8\">\n<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n<title>קופסת המתכונים — בישלת, צילמת, שיתפת</title>\n<link rel=\"preconnect\" href=\"https://fonts.googleapis.com\">\n<link rel=\"preconnect\" href=\"https://fonts.gstatic.com\" crossorigin>\n<link href=\"https://fonts.googleapis.com/css2?family=Secular+One&family=Heebo:wght@400;500;700&display=swap\" rel=\"stylesheet\">\n<style>\n:root{\n  --paper:#f4ecdc; --paper2:#efe4cd; --card:#fffdf6; --ink:#2e2620; --ink-soft:#6d5f52;\n  --terra:#c0532b; --terra-deep:#9c3f1f; --green:#46614a; --blue-line:#b8cfe0; --red-line:#e0a493;\n  --tape:rgba(240,214,140,.85);\n}\n*{box-sizing:border-box;margin:0;padding:0}\nbody{\n  font-family:'Heebo',sans-serif;color:var(--ink);background:var(--paper);\n  background-image:\n    radial-gradient(ellipse at 20% 10%, rgba(255,255,255,.5), transparent 60%),\n    repeating-linear-gradient(0deg, transparent 0 34px, rgba(120,90,60,.045) 34px 35px);\n  min-height:100vh;\n}\nh1,h2,h3,.brand,.btn,.stamp{font-family:'Secular One','Heebo',sans-serif}\na{color:var(--terra-deep)}\nheader{\n  display:flex;align-items:center;justify-content:space-between;gap:12px;\n  padding:18px clamp(16px,5vw,48px);border-bottom:3px solid var(--ink);\n  background:linear-gradient(180deg,var(--paper2),var(--paper));\n  position:sticky;top:0;z-index:10;\n}\n.brand{font-size:clamp(22px,4vw,32px);display:flex;align-items:center;gap:10px;cursor:pointer}\n.brand .box{font-size:.85em}\n.tagline{font-size:12px;color:var(--ink-soft);margin-top:2px}\n.stamp{\n  display:inline-block;background:var(--terra);color:#fff;padding:4px 12px;border-radius:4px;\n  transform:rotate(-3deg);font-size:13px;box-shadow:2px 2px 0 rgba(0,0,0,.18);\n}\nnav{display:flex;gap:10px;align-items:center;flex-wrap:wrap}\n.btn{\n  border:2px solid var(--ink);background:var(--card);color:var(--ink);padding:8px 18px;\n  border-radius:6px;cursor:pointer;font-size:15px;box-shadow:3px 3px 0 var(--ink);\n  transition:transform .08s, box-shadow .08s;text-decoration:none;display:inline-block;\n}\n.btn:hover{transform:translate(-1px,-1px);box-shadow:4px 4px 0 var(--ink)}\n.btn:active{transform:translate(2px,2px);box-shadow:1px 1px 0 var(--ink)}\n.btn.primary{background:var(--terra);color:#fff;border-color:var(--terra-deep);box-shadow:3px 3px 0 var(--terra-deep)}\n.btn.ghost{background:transparent;box-shadow:none;border-color:transparent;text-decoration:underline}\nmain{max-width:1060px;margin:0 auto;padding:28px clamp(14px,4vw,40px) 80px}\n/* ---- feed: recipe cards in the box ---- */\n.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(250px,1fr));gap:34px 26px;margin-top:26px}\n.rcard{\n  background:var(--card);border:1.5px solid #d8cdb4;border-radius:3px;padding:14px 16px 18px;\n  box-shadow:4px 6px 14px rgba(80,60,30,.16);position:relative;cursor:pointer;\n  background-image:repeating-linear-gradient(0deg, transparent 0 27px, var(--blue-line) 27px 28px);\n  transition:transform .15s;\n}\n.rcard::before{ /* red margin line */\n  content:\"\";position:absolute;top:0;bottom:0;right:34px;width:1.5px;background:var(--red-line);opacity:.7;\n}\n.rcard:nth-child(odd){transform:rotate(-1.1deg)}\n.rcard:nth-child(even){transform:rotate(.9deg)}\n.rcard:hover{transform:rotate(0) scale(1.02);z-index:2}\n.rcard .photo{\n  margin:6px 0 12px;position:relative;transform:rotate(-1.5deg);\n}\n.rcard:nth-child(even) .photo{transform:rotate(1.4deg)}\n.rcard .photo img{width:100%;aspect-ratio:4/3;object-fit:cover;display:block;border:5px solid #fff;box-shadow:2px 3px 8px rgba(0,0,0,.25)}\n.rcard .photo::after{ /* washi tape */\n  content:\"\";position:absolute;top:-11px;right:50%;transform:translateX(50%) rotate(-2deg);\n  width:78px;height:22px;background:var(--tape);box-shadow:0 1px 2px rgba(0,0,0,.15);\n  clip-path:polygon(2% 0,98% 4%,100% 96%,0 100%);\n}\n.rcard h3{font-size:20px;line-height:28px;min-height:28px}\n.rcard .by{font-size:13px;color:var(--ink-soft);line-height:28px}\n.rcard .meta{display:flex;justify-content:space-between;align-items:center;margin-top:8px;line-height:28px}\n.rcard .count{\n  background:var(--green);color:#fff;font-size:12px;padding:2px 10px;border-radius:20px;font-weight:700;\n}\n.empty{\n  text-align:center;padding:70px 20px;border:2px dashed #c9b892;border-radius:12px;margin-top:30px;\n  background:rgba(255,253,246,.5);\n}\n.empty h2{font-size:26px;margin-bottom:10px}\n/* ---- recipe detail ---- */\n.detail{display:grid;grid-template-columns:1.05fr .95fr;gap:34px;margin-top:24px}\n@media(max-width:820px){.detail{grid-template-columns:1fr}}\n.polaroid{\n  background:#fff;padding:14px 14px 46px;box-shadow:5px 8px 20px rgba(80,60,30,.25);\n  transform:rotate(-1.6deg);position:relative;\n}\n.polaroid::after{\n  content:\"\";position:absolute;top:-12px;right:50%;transform:translateX(50%) rotate(2deg);\n  width:110px;height:26px;background:var(--tape);box-shadow:0 1px 3px rgba(0,0,0,.2);\n}\n.polaroid img{width:100%;display:block}\n.recipe-sheet{\n  background:var(--card);border:1.5px solid #d8cdb4;padding:22px 26px;border-radius:3px;\n  box-shadow:4px 6px 14px rgba(80,60,30,.16);position:relative;\n  background-image:repeating-linear-gradient(0deg, transparent 0 27px, var(--blue-line) 27px 28px);\n}\n.recipe-sheet::before{content:\"\";position:absolute;top:0;bottom:0;right:40px;width:1.5px;background:var(--red-line);opacity:.7}\n.recipe-sheet h2{font-size:30px;line-height:28px;margin-bottom:6px}\n.recipe-sheet h4{color:var(--terra-deep);font-family:'Secular One';margin:16px 0 4px;font-size:17px}\n.recipe-sheet .txt{white-space:pre-wrap;line-height:28px;font-size:15px}\n.responses{margin-top:44px}\n.responses h3{font-size:24px;display:flex;align-items:center;gap:12px}\n.rgrid{display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:22px;margin-top:18px}\n.rshot{\n  background:#fff;padding:9px 9px 30px;box-shadow:3px 5px 12px rgba(80,60,30,.22);position:relative;\n}\n.rshot:nth-child(odd){transform:rotate(-1.4deg)}\n.rshot:nth-child(even){transform:rotate(1.2deg)}\n.rshot img{width:100%;aspect-ratio:1;object-fit:cover;display:block}\n.rshot figcaption{font-size:12px;color:var(--ink-soft);margin-top:7px;text-align:center}\n/* ---- forms ---- */\n.panel{\n  max-width:480px;margin:40px auto;background:var(--card);border:1.5px solid #d8cdb4;border-radius:4px;\n  padding:30px 30px 34px;box-shadow:5px 7px 18px rgba(80,60,30,.18);position:relative;\n}\n.panel::before{\n  content:\"\";position:absolute;top:-13px;right:50%;transform:translateX(50%) rotate(-2deg);\n  width:120px;height:26px;background:var(--tape);box-shadow:0 1px 3px rgba(0,0,0,.18);\n}\n.panel h2{font-size:26px;margin-bottom:16px;text-align:center}\nlabel{display:block;font-weight:700;font-size:14px;margin:14px 0 5px}\ninput[type=text],input[type=password],textarea{\n  width:100%;padding:9px 12px;border:1.5px solid #c9b892;border-radius:5px;background:#fffef9;\n  font-family:'Heebo';font-size:15px;color:var(--ink);\n}\ntextarea{resize:vertical;min-height:90px}\ninput[type=file]{width:100%;font-size:13px;margin-top:4px}\n.roles{display:flex;gap:10px;margin-top:6px}\n.role-chip{\n  flex:1;border:2px solid var(--ink);border-radius:8px;padding:12px 8px;text-align:center;cursor:pointer;\n  background:#fffef9;transition:all .1s;\n}\n.role-chip.sel{background:var(--terra);color:#fff;border-color:var(--terra-deep);box-shadow:2px 2px 0 var(--terra-deep)}\n.role-chip .big{font-family:'Secular One';font-size:17px}\n.role-chip .small{font-size:12px;opacity:.85}\n.err{background:#fbe3dc;border:1.5px solid var(--terra);color:var(--terra-deep);padding:9px 12px;border-radius:6px;margin-top:12px;font-size:14px}\n.ok{background:#e4efe2;border:1.5px solid var(--green);color:var(--green);padding:9px 12px;border-radius:6px;margin-top:12px;font-size:14px}\n.panel .btn{width:100%;margin-top:20px}\n.switchline{text-align:center;margin-top:16px;font-size:14px;color:var(--ink-soft)}\n.me-badge{font-size:13px;color:var(--ink-soft)}\n.me-badge b{color:var(--ink)}\n.hero{\n  text-align:center;padding:34px 16px 8px;\n}\n.hero h1{font-size:clamp(30px,6vw,52px);line-height:1.15}\n.hero p{color:var(--ink-soft);margin-top:10px;font-size:16px}\n.hidden{display:none!important}\n.spin{display:inline-block;width:16px;height:16px;border:2px solid #fff;border-top-color:transparent;border-radius:50%;animation:sp .7s linear infinite;vertical-align:middle}\n@keyframes sp{to{transform:rotate(360deg)}}\nfooter{text-align:center;color:var(--ink-soft);font-size:12px;padding:30px;border-top:1.5px dashed #c9b892}\n@media(max-width:640px){\n  header{padding:14px 14px}\n  .brand{font-size:20px}\n  .btn{padding:7px 12px;font-size:14px}\n}\n</style>\n</head>\n<body>\n<header>\n  <div>\n    <div class=\"brand\" onclick=\"go('feed')\">🗃️ <span>קופסת המתכונים</span></div>\n    <div class=\"tagline\">יוצרים מעלים מתכון · מגיבים מעלים תמונה של מה שהכינו</div>\n  </div>\n  <nav id=\"nav\"></nav>\n</header>\n<main id=\"app\"></main>\n<footer>קופסת המתכונים · נבנה באהבה ובחינם · גרסה ראשונה</footer>\n<script>\nlet ME = null;\nconst $ = s => document.querySelector(s);\nconst app = $('#app');\n\nasync function api(path, opts = {}) {\n  const res = await fetch(path, opts);\n  const data = await res.json().catch(() => ({}));\n  if (!res.ok) throw new Error(data.error || 'שגיאה');\n  return data;\n}\nfunction esc(s){return String(s??'').replace(/[&<>\"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;',\"'\":'&#39;'}[c]))}\nfunction imgUrl(k){return '/img/'+k}\n\n// downscale photo client-side before upload (keeps storage tiny on free tier)\nfunction shrink(file, max=1600){\n  return new Promise((resolve,reject)=>{\n    const img = new Image();\n    img.onload = () => {\n      const scale = Math.min(1, max/Math.max(img.width,img.height));\n      if(scale===1 && file.size < 2*1024*1024){ resolve(file); return; }\n      const c = document.createElement('canvas');\n      c.width = Math.round(img.width*scale); c.height = Math.round(img.height*scale);\n      c.getContext('2d').drawImage(img,0,0,c.width,c.height);\n      c.toBlob(b=>{\n        if(!b) return reject(new Error('בעיה בעיבוד התמונה'));\n        resolve(new File([b],'photo.jpg',{type:'image/jpeg'}));\n      },'image/jpeg',0.85);\n    };\n    img.onerror = ()=>reject(new Error('הקובץ אינו תמונה תקינה'));\n    img.src = URL.createObjectURL(file);\n  });\n}\n\nfunction renderNav(){\n  const nav = $('#nav');\n  if(!ME){\n    nav.innerHTML = `<button class=\"btn primary\" onclick=\"go('auth')\">כניסה / הרשמה</button>`;\n  } else {\n    const roleName = ME.role==='creator' ? 'יוצר/ת' : 'מגיב/ה';\n    nav.innerHTML = `\n      <span class=\"me-badge\">שלום, <b>${esc(ME.name)}</b> (${roleName})</span>\n      ${ME.role==='creator' ? `<button class=\"btn primary\" onclick=\"go('new')\">+ מתכון חדש</button>` : ''}\n      <button class=\"btn ghost\" onclick=\"logout()\">יציאה</button>`;\n  }\n}\n\nasync function go(view, arg){\n  renderNav();\n  if(view==='feed') return renderFeed();\n  if(view==='auth') return renderAuth();\n  if(view==='new') return renderNew();\n  if(view==='recipe') return renderRecipe(arg);\n}\n\nasync function renderFeed(){\n  app.innerHTML = `<div class=\"hero\"><h1>כל מתכון הוא קלף בקופסה</h1>\n    <p>יוצרים מעלים קלף מתכון עם תמונה והוראות. מגיבים מכינים בבית — ומדביקים תמונה של מה שיצא.</p>\n    ${!ME?`<div style=\"margin-top:18px\"><button class=\"btn primary\" onclick=\"go('auth')\">הצטרפו לקופסה</button></div>`:''}\n  </div><div id=\"feed\"><div class=\"empty\">טוען קלפים…</div></div>`;\n  const {recipes} = await api('/api/recipes');\n  const feed = $('#feed');\n  if(!recipes.length){\n    feed.innerHTML = `<div class=\"empty\"><h2>הקופסה עוד ריקה</h2><p>המתכון הראשון מחכה ליוצר הראשון.</p></div>`;\n    return;\n  }\n  feed.innerHTML = `<div class=\"grid\">` + recipes.map(r=>`\n    <article class=\"rcard\" onclick=\"go('recipe','${r.id}')\">\n      <div class=\"photo\"><img loading=\"lazy\" src=\"${imgUrl(r.photo_key)}\" alt=\"${esc(r.title)}\"></div>\n      <h3>${esc(r.title)}</h3>\n      <div class=\"by\">מאת ${esc(r.creator_name)}</div>\n      <div class=\"meta\">\n        <span class=\"count\">${r.response_count} הכינו</span>\n        <span style=\"font-size:12px;color:var(--ink-soft)\">${new Date(r.created_at+'Z').toLocaleDateString('he-IL')}</span>\n      </div>\n    </article>`).join('') + `</div>`;\n}\n\nfunction renderAuth(mode='signup'){\n  app.innerHTML = `\n  <div class=\"panel\">\n    <h2>${mode==='signup'?'פתיחת קלף אישי':'כניסה לקופסה'}</h2>\n    ${mode==='signup' ? `\n    <label>מי את/ה בקופסה?</label>\n    <div class=\"roles\">\n      <div class=\"role-chip ${window._role==='creator'?'sel':''}\" id=\"chip-creator\" onclick=\"pickRole('creator')\">\n        <div class=\"big\">🧑‍🍳 יוצר/ת</div><div class=\"small\">מעלה מתכונים עם הוראות</div>\n      </div>\n      <div class=\"role-chip ${window._role==='responder'?'sel':''}\" id=\"chip-responder\" onclick=\"pickRole('responder')\">\n        <div class=\"big\">🍳 מגיב/ה</div><div class=\"small\">מכין/ה ומעלה תמונה</div>\n      </div>\n    </div>` : ''}\n    <label>שם</label>\n    <input type=\"text\" id=\"f-name\" maxlength=\"40\" placeholder=\"השם שיופיע על הקלפים שלך\">\n    <label>סיסמה</label>\n    <input type=\"password\" id=\"f-pass\" placeholder=\"לפחות 4 תווים\">\n    <div id=\"auth-msg\"></div>\n    <button class=\"btn primary\" id=\"auth-btn\" onclick=\"doAuth('${mode}')\">${mode==='signup'?'צרו לי קלף':'כניסה'}</button>\n    <div class=\"switchline\">\n      ${mode==='signup'\n        ? `יש לך כבר קלף? <a href=\"#\" onclick=\"renderAuth('login');return false\">כניסה</a>`\n        : `חדשים כאן? <a href=\"#\" onclick=\"renderAuth('signup');return false\">הרשמה</a>`}\n    </div>\n  </div>`;\n  if(!window._role) pickRole('creator');\n}\nfunction pickRole(r){\n  window._role = r;\n  document.querySelectorAll('.role-chip').forEach(c=>c.classList.remove('sel'));\n  const chip = $('#chip-'+r); if(chip) chip.classList.add('sel');\n}\nasync function doAuth(mode){\n  const msg = $('#auth-msg'); msg.innerHTML='';\n  const btn = $('#auth-btn'); btn.disabled = true; btn.innerHTML = '<span class=\"spin\"></span>';\n  try{\n    const body = {name: $('#f-name').value.trim(), password: $('#f-pass').value};\n    if(mode==='signup') body.role = window._role || 'creator';\n    const data = await api('/api/'+mode, {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(body)});\n    ME = data.user;\n    go('feed');\n  }catch(e){\n    msg.innerHTML = `<div class=\"err\">${esc(e.message)}</div>`;\n    btn.disabled = false; btn.textContent = mode==='signup'?'צרו לי קלף':'כניסה';\n  }\n}\nasync function logout(){\n  await api('/api/logout',{method:'POST'});\n  ME = null; go('feed');\n}\n\nfunction renderNew(){\n  if(!ME || ME.role!=='creator'){ return renderAuth('login'); }\n  app.innerHTML = `\n  <div class=\"panel\" style=\"max-width:560px\">\n    <h2>קלף מתכון חדש</h2>\n    <label>שם המתכון</label>\n    <input type=\"text\" id=\"n-title\" maxlength=\"120\" placeholder=\"למשל: עוגת התפוחים של סבתא\">\n    <label>תמונה של המנ&#1492;</label>\n    <input type=\"file\" id=\"n-photo\" accept=\"image/jpeg,image/png,image/webp\">\n    <label>מרכיבים</label>\n    <textarea id=\"n-ing\" rows=\"5\" placeholder=\"שורה לכל מרכיב…\"></textarea>\n    <label>הוראות הכנה</label>\n    <textarea id=\"n-ins\" rows=\"8\" placeholder=\"שלב אחר שלב…\"></textarea>\n    <div id=\"new-msg\"></div>\n    <button class=\"btn primary\" id=\"new-btn\" onclick=\"doNew()\">לתוך הקופסה</button>\n  </div>`;\n}\nasync function doNew(){\n  const msg = $('#new-msg'); msg.innerHTML='';\n  const btn = $('#new-btn'); btn.disabled=true; btn.innerHTML='<span class=\"spin\"></span> מעלה…';\n  try{\n    const f = $('#n-photo').files[0];\n    if(!f) throw new Error('צריך תמונה של המנה');\n    const photo = await shrink(f);\n    const fd = new FormData();\n    fd.append('title', $('#n-title').value.trim());\n    fd.append('ingredients', $('#n-ing').value.trim());\n    fd.append('instructions', $('#n-ins').value.trim());\n    fd.append('photo', photo);\n    const data = await api('/api/recipes', {method:'POST', body:fd});\n    go('recipe', data.id);\n  }catch(e){\n    msg.innerHTML = `<div class=\"err\">${esc(e.message)}</div>`;\n    btn.disabled=false; btn.textContent='לתוך הקופסה';\n  }\n}\n\nasync function renderRecipe(id){\n  app.innerHTML = `<div class=\"empty\">שולף את הקלף…</div>`;\n  let data;\n  try{ data = await api('/api/recipes/'+id); }\n  catch(e){ app.innerHTML = `<div class=\"empty\"><h2>הקלף הלך לאיבוד</h2><p><a href=\"#\" onclick=\"go('feed');return false\">חזרה לקופסה</a></p></div>`; return; }\n  const r = data.recipe;\n  app.innerHTML = `\n  <div style=\"margin-top:6px\"><a href=\"#\" onclick=\"go('feed');return false\">→ חזרה לקופסה</a></div>\n  <div class=\"detail\">\n    <div class=\"polaroid\"><img src=\"${imgUrl(r.photo_key)}\" alt=\"${esc(r.title)}\"></div>\n    <div class=\"recipe-sheet\">\n      <span class=\"stamp\">קלף מתכון</span>\n      <h2>${esc(r.title)}</h2>\n      <div style=\"color:var(--ink-soft);font-size:14px\">מאת ${esc(r.creator_name)} · ${new Date(r.created_at+'Z').toLocaleDateString('he-IL')}</div>\n      <h4>מרכיבים</h4>\n      <div class=\"txt\">${esc(r.ingredients)}</div>\n      <h4>הוראות הכנה</h4>\n      <div class=\"txt\">${esc(r.instructions)}</div>\n    </div>\n  </div>\n  <section class=\"responses\">\n    <h3>🍽️ הכינו את זה בבית <span style=\"font-size:14px;color:var(--ink-soft);font-family:'Heebo'\">(${data.responses.length})</span></h3>\n    ${ME && ME.role==='responder' ? `\n      <div class=\"panel\" style=\"max-width:420px;margin:20px 0;text-align:right\">\n        <h2 style=\"font-size:19px\">הכנתם? הדביקו תמונה</h2>\n        <p style=\"font-size:13px;color:var(--ink-soft)\">תמונה בלבד — התמונה שלכם מספרת את הסיפור.</p>\n        <input type=\"file\" id=\"r-photo\" accept=\"image/jpeg,image/png,image/webp\">\n        <div id=\"r-msg\"></div>\n        <button class=\"btn primary\" id=\"r-btn\" onclick=\"doRespond('${r.id}')\">הדבקה לקלף</button>\n      </div>` : (!ME ? `<p style=\"margin-top:10px\"><a href=\"#\" onclick=\"go('auth');return false\">התחברו כמגיבים</a> כדי להדביק תמונה של מה שהכנתם.</p>` : '')}\n    <div class=\"rgrid\" id=\"rgrid\">\n      ${data.responses.map(x=>`\n        <figure class=\"rshot\"><img loading=\"lazy\" src=\"${imgUrl(x.photo_key)}\">\n        <figcaption>${esc(x.responder_name)} הכין/ה · ${new Date(x.created_at+'Z').toLocaleDateString('he-IL')}</figcaption></figure>`).join('') || '<p style=\"color:var(--ink-soft)\">עוד אף אחד לא הדביק תמונה. מי ראשון?</p>'}\n    </div>\n  </section>`;\n}\nasync function doRespond(id){\n  const msg = $('#r-msg'); msg.innerHTML='';\n  const btn = $('#r-btn'); btn.disabled=true; btn.innerHTML='<span class=\"spin\"></span> מדביק…';\n  try{\n    const f = $('#r-photo').files[0];\n    if(!f) throw new Error('צריך תמונה');\n    const photo = await shrink(f);\n    const fd = new FormData();\n    fd.append('photo', photo);\n    await api('/api/recipes/'+id+'/responses', {method:'POST', body:fd});\n    renderRecipe(id);\n  }catch(e){\n    msg.innerHTML = `<div class=\"err\">${esc(e.message)}</div>`;\n    btn.disabled=false; btn.textContent='הדבקה לקלף';\n  }\n}\n\n(async ()=>{\n  try{ const d = await api('/api/me'); ME = d.user; }catch(e){}\n  go('feed');\n})();\n</script>\n</body>\n</html>\n";
