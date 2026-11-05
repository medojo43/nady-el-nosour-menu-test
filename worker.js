const COOKIE = "nosour_admin";
const encoder = new TextEncoder();

function json(data, status=200, headers={}) {
  return new Response(JSON.stringify(data), {status, headers:{"content-type":"application/json; charset=utf-8", ...headers}});
}
function cookieValue(request, name) {
  const raw = request.headers.get("Cookie") || "";
  const part = raw.split(";").map(x=>x.trim()).find(x=>x.startsWith(name+"="));
  return part ? decodeURIComponent(part.slice(name.length+1)) : "";
}
async function sign(value, secret) {
  const key = await crypto.subtle.importKey("raw", encoder.encode(secret), {name:"HMAC",hash:"SHA-256"}, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, encoder.encode(value));
  return btoa(String.fromCharCode(...new Uint8Array(sig))).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/g,"");
}
async function validSession(request, env) {
  if (!env.ADMIN_PASSWORD) return false;
  const token = cookieValue(request, COOKIE);
  const [expires, sig] = token.split(".");
  if (!expires || !sig || Number(expires) < Date.now()) return false;
  return (await sign(expires, env.ADMIN_PASSWORD)) === sig;
}
async function requireAdmin(request, env) {
  return await validSession(request, env) ? null : json({error:"غير مصرح"},401);
}
function cleanNumber(v) { if (v === "" || v === null || v === undefined) return null; const n=Number(v); return Number.isFinite(n) ? n : null; }
async function handleApi(request, env, url) {
  if (url.pathname === "/api/menu" && request.method === "GET") {
    const {results=[]} = await env.DB.prepare("SELECT id, section, category, item, civilian_price, member_price, sort_order, notes FROM menu_items ORDER BY id").all();
    return json({items:results});
  }
  if (url.pathname === "/api/admin/login" && request.method === "POST") {
    const body = await request.json().catch(()=>({}));
    if (!env.ADMIN_PASSWORD) return json({error:"لم يتم ضبط كلمة مرور الإدارة"},500);
    if (String(body.password || "") !== env.ADMIN_PASSWORD) return json({error:"كلمة المرور غير صحيحة"},401);
    const expires=String(Date.now()+12*60*60*1000);
    const sig=await sign(expires,env.ADMIN_PASSWORD);
    return json({ok:true},200,{"set-cookie":`${COOKIE}=${encodeURIComponent(expires+'.'+sig)}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=43200`});
  }
  if (url.pathname === "/api/admin/logout" && request.method === "POST") {
    return json({ok:true},200,{"set-cookie":`${COOKIE}=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0`});
  }
  if (url.pathname.startsWith("/api/admin/")) {
    const denied=await requireAdmin(request,env); if (denied) return denied;
    if (url.pathname === "/api/admin/items" && request.method === "GET") {
      const {results=[]}=await env.DB.prepare("SELECT * FROM menu_items ORDER BY id").all();
      return json({items:results});
    }
    if (url.pathname === "/api/admin/items" && request.method === "POST") {
      const b=await request.json();
      if (!b.section || !b.item) return json({error:"القسم واسم الصنف مطلوبان"},400);
      const r=await env.DB.prepare("INSERT INTO menu_items(section,category,item,civilian_price,member_price,sort_order,notes) VALUES(?,?,?,?,?,?,?)")
        .bind(String(b.section),String(b.category||""),String(b.item),cleanNumber(b.civilian_price),cleanNumber(b.member_price),String(b.sort_order||""),String(b.notes||"")).run();
      return json({ok:true,id:r.meta.last_row_id});
    }
    const match=url.pathname.match(/^\/api\/admin\/items\/(\d+)$/);
    if (match && request.method === "PUT") {
      const b=await request.json();
      if (!b.section || !b.item) return json({error:"القسم واسم الصنف مطلوبان"},400);
      await env.DB.prepare("UPDATE menu_items SET section=?,category=?,item=?,civilian_price=?,member_price=?,sort_order=?,notes=? WHERE id=?")
        .bind(String(b.section),String(b.category||""),String(b.item),cleanNumber(b.civilian_price),cleanNumber(b.member_price),String(b.sort_order||""),String(b.notes||""),Number(match[1])).run();
      return json({ok:true});
    }
    if (match && request.method === "DELETE") {
      await env.DB.prepare("DELETE FROM menu_items WHERE id=?").bind(Number(match[1])).run();
      return json({ok:true});
    }
  }
  return json({error:"غير موجود"},404);
}
export default {
  async fetch(request, env) {
    const url=new URL(request.url);
    if (url.pathname.startsWith("/api/")) {
      try { return await handleApi(request,env,url); }
      catch(e) { return json({error:"حدث خطأ في الخادم",detail:String(e?.message||e)},500); }
    }
    return env.ASSETS.fetch(request);
  }
};
