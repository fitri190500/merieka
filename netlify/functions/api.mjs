import { getStore } from "@netlify/blobs";
import crypto from "node:crypto";

export const config = { path: "/api/*" };
const J = (o, s = 200) => new Response(JSON.stringify(o), { status: s, headers: { "content-type": "application/json" } });
const E = () => getStore({ name: "entries", consistency: "strong" });
const P = () => getStore({ name: "photos", consistency: "strong" });
const S = () => getStore({ name: "meta", consistency: "strong" });
const sha = (s) => crypto.createHash("sha256").update(s).digest();
const same = (a, b) => crypto.timingSafeEqual(sha(a), sha(b));
const secret = () => process.env.AUTH_SECRET || "";
const sign = (b) => crypto.createHmac("sha256", secret()).update(b).digest("base64url");
function makeToken() { const b = Buffer.from(JSON.stringify({ exp: Date.now() + 864e5 })).toString("base64url"); return b + "." + sign(b); }
function isAdmin(req) {
  const t = (req.headers.get("authorization") || "").replace("Bearer ", "");
  const [b, s] = t.split("."); if (!b || !s || !secret() || !same(s, sign(b))) return false;
  try { return JSON.parse(Buffer.from(b, "base64url")).exp > Date.now(); } catch { return false; }
}
async function allEntries() {
  const { blobs } = await E().list();
  const rows = await Promise.all(blobs.map((b) => E().get(b.key, { type: "json" })));
  return rows.filter(Boolean).sort((a, b) => b.created_at - a.created_at);
}
async function settings() { return (await S().get("settings", { type: "json" })) || { is_open: true, close_at: null }; }
const isClosed = (s) => !s.is_open || (s.close_at && Date.now() > s.close_at);

export default async (req) => {
  const u = new URL(req.url), p = u.pathname.replace(/^\/api\//, "").split("/"), m = req.method;

  if (p[0] === "settings" && m === "GET") { const s = await settings(); return J({ closed: !!isClosed(s), is_open: s.is_open, close_at: s.close_at }); }

  if (p[0] === "wall" && m === "GET") {
    return J((await allEntries()).filter((e) => !e.hidden).slice(0, 30).map(({ name, message, created_at }) => ({ name, message, created_at })));
  }

  if (p[0] === "login" && m === "POST") {
    const b = await req.json().catch(() => ({}));
    const ok = process.env.ADMIN_EMAIL && process.env.ADMIN_PASSWORD && same(String(b.email || ""), process.env.ADMIN_EMAIL) && same(String(b.password || ""), process.env.ADMIN_PASSWORD);
    if (!ok) { await new Promise((r) => setTimeout(r, 1000)); return J({ error: "salah" }, 401); }
    return J({ token: makeToken() });
  }

  if (p[0] === "entries" && m === "POST") {
    if (isClosed(await settings())) return J({ error: "ditutup" }, 403);
    const ip = req.headers.get("x-nf-client-connection-ip") || "x", key = "rl-" + sha(ip).toString("hex").slice(0, 24);
    const hits = ((await S().get(key, { type: "json" })) || []).filter((t) => Date.now() - t < 36e5);
    if (hits.length >= 3) return J({ error: "Batas 3 kiriman per jam tercapai." }, 429);
    const b = await req.json().catch(() => null); if (!b) return J({ error: "bad" }, 400);
    const name = String(b.name || "").trim().slice(0, 80), message = String(b.message || "").trim().slice(0, 300);
    if (!name || !message) return J({ error: "Nama dan ucapan wajib." }, 400);
    const day = ["23 Januari", "24 Januari", "Kedua hari"].includes(b.day_attending) ? b.day_attending : "Kedua hari";
    const gc = Math.min(5, Math.max(1, parseInt(b.guest_count))) || null;
    const id = crypto.randomUUID(); let photo = false;
    if (b.photo) {
      const buf = Buffer.from(String(b.photo).replace(/^data:image\/jpeg;base64,/, ""), "base64");
      if (buf.length > 3e6 || buf[0] !== 0xff || buf[1] !== 0xd8) return J({ error: "Foto tidak valid." }, 400);
      await P().set(id, buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.length)); photo = true;
    }
    await E().setJSON(id, { id, name, day_attending: day, guest_count: gc, message, photo, hidden: false, created_at: Date.now(), checked_in_at: null, checked_out_at: null });
    hits.push(Date.now()); await S().setJSON(key, hits);
    return J({ ok: true });
  }

  if (p[0] === "admin") {
    if (!isAdmin(req)) return J({ error: "unauthorized" }, 401);
    if (p[1] === "entries" && !p[2] && m === "GET") return J(await allEntries());
    if (p[1] === "photo" && p[2] && m === "GET") {
      const d = await P().get(p[2], { type: "arrayBuffer" }); if (!d) return J({ error: "none" }, 404);
      return new Response(d, { headers: { "content-type": "image/jpeg" } });
    }
    if (p[1] === "entries" && p[2] && m === "PATCH") {
      const e = await E().get(p[2], { type: "json" }); if (!e) return J({ error: "none" }, 404);
      const b = await req.json().catch(() => ({})); if (typeof b.hidden === "boolean") e.hidden = b.hidden;
      await E().setJSON(p[2], e); return J(e);
    }
    if (p[1] === "entries" && p[2] && m === "DELETE") { await E().delete(p[2]); await P().delete(p[2]); return J({ ok: true }); }
    if (p[1] === "settings" && m === "PUT") {
      const b = await req.json().catch(() => ({}));
      await S().setJSON("settings", { is_open: !!b.is_open, close_at: b.close_at ? Number(b.close_at) : null }); return J({ ok: true });
    }
  }
  return J({ error: "not found" }, 404);
};
