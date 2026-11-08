const PROJECT_ID = "medienscoutswebseite";
const FIREBASE_API_KEY = "AIzaSyAheWnI7RFPl9h0C0rGy_6-l5liyNsMKzc";
const ALLOWED = new Set(["DE", "AT", "CH"]);

const COUNTRY_NAMES = {
  DE: "Deutschland",
  AT: "Österreich",
  CH: "Schweiz",
  US: "USA",
  GB: "Vereinigtes Königreich",
  NL: "Niederlande",
  FR: "Frankreich",
  BE: "Belgien",
  PL: "Polen",
  TR: "Türkei",
  XX: "Unbekannt"
};

const json = (data, status = 200) => new Response(JSON.stringify(data), {
  status,
  headers: {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store, private",
    "X-Content-Type-Options": "nosniff"
  }
});

function requestIp(request) {
  return request.headers.get("CF-Connecting-IP") || "unknown";
}

function countryInfo(request) {
  const code = (request.headers.get("CF-IPCountry") || "XX").toUpperCase();
  return {
    code,
    name: COUNTRY_NAMES[code] || code,
    decision: ALLOWED.has(code) ? (code === "AT" ? "review" : "allowed") : "blocked"
  };
}

async function upsertIp(env, request, eventType, decisionOverride) {
  if (!env.SECURITY_DB) throw new Error("D1-Bindung SECURITY_DB fehlt");
  const ip = requestIp(request);
  if (ip === "unknown") return;
  // Datenschutz: nicht mehr benötigte IP-Einträge nach 90 Tagen entfernen.
  await env.SECURITY_DB.prepare("DELETE FROM ip_addresses WHERE last_seen < datetime('now', '-90 days')").run();
  const country = countryInfo(request);
  const decision = decisionOverride || country.decision;
  const now = new Date().toISOString();
  await env.SECURITY_DB.prepare(`
    INSERT INTO ip_addresses
      (ip_address, country_code, country_name, first_seen, last_seen, check_count, last_event_type, decision)
    VALUES (?, ?, ?, ?, ?, 1, ?, ?)
    ON CONFLICT(ip_address) DO UPDATE SET
      country_code = excluded.country_code,
      country_name = excluded.country_name,
      last_seen = excluded.last_seen,
      check_count = ip_addresses.check_count + 1,
      last_event_type = excluded.last_event_type,
      decision = excluded.decision
  `).bind(ip, country.code, country.name, now, now, eventType, decision).run();
}

async function verifyFirebaseUser(request) {
  const auth = request.headers.get("Authorization") || "";
  const match = auth.match(/^Bearer\s+(.+)$/i);
  if (!match) return null;
  const idToken = match[1];

  const lookup = await fetch(
    `https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=${FIREBASE_API_KEY}`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ idToken })
    }
  );
  if (!lookup.ok) return null;
  const account = await lookup.json();
  const user = account.users?.[0];
  if (!user?.localId) return null;

  const docUrl = `https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents/users/${encodeURIComponent(user.localId)}`;
  const profileResponse = await fetch(docUrl, {
    headers: { Authorization: `Bearer ${idToken}` }
  });
  if (!profileResponse.ok) return null;
  const profile = await profileResponse.json();
  const role = profile.fields?.role?.stringValue || "Schüler";
  return { uid: user.localId, role };
}

export async function onRequestGet({ request, env }) {
  const url = new URL(request.url);

  if (url.searchParams.get("list") === "1") {
    const user = await verifyFirebaseUser(request);
    if (!user || user.role !== "Admin") return json({ error: "Nicht autorisiert" }, 403);
    if (!env.SECURITY_DB) return json({ error: "D1-Datenbankbindung fehlt" }, 503);
    const result = await env.SECURITY_DB.prepare(`
      SELECT ip_address, country_code, country_name, first_seen, last_seen,
             check_count, last_event_type, decision
      FROM ip_addresses
      ORDER BY last_seen DESC
      LIMIT 1000
    `).all();
    return json({ items: result.results || [] });
  }

  const country = countryInfo(request);
  // Österreich darf sich anmelden, wird aber im Admin-Terminal als Prüfhinweis markiert.
  // Andere Länder werden vor dem Firebase-Login blockiert.
  if (country.decision === "blocked") {
    try { await upsertIp(env, request, "suspicious_access", "blocked"); }
    catch (error) { console.error("Blockierter Zugriff konnte nicht gespeichert werden:", error); }
    return json({
      country: country.code,
      countryName: country.name,
      allowed: false,
      blocked: true,
      status: "blocked",
      enforcement: "enabled",
      checkedAt: new Date().toISOString()
    }, 403);
  }

  if (country.decision === "review") {
    try { await upsertIp(env, request, "suspicious_access", "review"); }
    catch (error) { console.error("Prüfhinweis konnte nicht gespeichert werden:", error); }
  }

  return json({
    country: country.code,
    countryName: country.name,
    allowed: true,
    blocked: false,
    status: country.decision,
    enforcement: "enabled",
    checkedAt: new Date().toISOString()
  });
}

export async function onRequestPost({ request, env }) {
  const user = await verifyFirebaseUser(request);
  if (!user) return json({ error: "Ungültige oder abgelaufene Anmeldung" }, 401);

  const country = countryInfo(request);
  if (country.decision === "blocked") {
    try { await upsertIp(env, request, "suspicious_access", "blocked"); } catch (_) {}
    return json({ error: "Anmeldung aus diesem Land ist nicht erlaubt" }, 403);
  }

  try {
    await upsertIp(env, request, "login", country.decision);
    return json({ ok: true, status: country.decision });
  } catch (error) {
    console.error("IP-Protokollierung fehlgeschlagen:", error);
    return json({ error: "Sicherheitsprotokoll konnte nicht gespeichert werden" }, 503);
  }
}
