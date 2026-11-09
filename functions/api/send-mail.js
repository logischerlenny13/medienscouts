const PROJECT_ID = "medienscoutswebseite";
const FIREBASE_API_KEY = "AIzaSyAheWnI7RFPl9h0C0rGy_6-l5liyNsMKzc";

const json = (data, status = 200) => new Response(JSON.stringify(data), {
  status,
  headers: {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store, private",
    "X-Content-Type-Options": "nosniff"
  }
});

async function verifyAdmin(request) {
  const match = (request.headers.get("Authorization") || "").match(/^Bearer\s+(.+)$/i);
  if (!match) return null;

  const lookup = await fetch(
    `https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=${FIREBASE_API_KEY}`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ idToken: match[1] })
    }
  );

  if (!lookup.ok) return null;

  const account = (await lookup.json()).users?.[0];
  if (!account?.localId) return null;

  const profileUrl =
    `https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents/users/${encodeURIComponent(account.localId)}`;
  const profileResponse = await fetch(profileUrl, {
    headers: { Authorization: `Bearer ${match[1]}` }
  });

  if (!profileResponse.ok) return null;

  const profile = await profileResponse.json();
  const role = profile.fields?.role?.stringValue || "Schüler";
  if (role !== "Admin") return null;

  return { uid: account.localId };
}

export async function onRequestPost({ request, env }) {
  if (!env.MAIL_WEBAPP_URL || !env.MAIL_API_SECRET) {
    return json({ success: false, error: "Mailserver ist nicht vollständig konfiguriert." }, 503);
  }

  const endpoint = String(env.MAIL_WEBAPP_URL);
  if (!endpoint.startsWith("https://script.google.com/macros/s/") || !endpoint.endsWith("/exec")) {
    return json({ success: false, error: "Die Mailserver-URL ist ungültig." }, 503);
  }

  let adminUser;
  try {
    adminUser = await verifyAdmin(request);
  } catch (error) {
    console.error("Admin-Prüfung fehlgeschlagen:", error);
    return json({ success: false, error: "Anmeldung konnte nicht geprüft werden." }, 503);
  }

  if (!adminUser) {
    return json({ success: false, error: "Nur angemeldete Admins dürfen E-Mails versenden." }, 403);
  }

  let data;
  try {
    const raw = await request.text();
    if (raw.length > 30000) return json({ success: false, error: "Anfrage ist zu groß." }, 413);
    data = JSON.parse(raw);
  } catch {
    return json({ success: false, error: "Ungültige Anfrage." }, 400);
  }

  const to = String(data.to || "").trim();
  const subject = String(data.subject || "").trim();
  const message = String(data.message || "").trim();
  const htmlBody = String(data.htmlBody || "").trim();

  if (!/^[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+$/.test(to) || to.length > 254) {
    return json({ success: false, error: "Empfänger-Adresse ist ungültig." }, 400);
  }
  if (!subject || subject.length > 200 || /[\r\n]/.test(subject)) {
    return json({ success: false, error: "Betreff ist ungültig." }, 400);
  }
  if (!message || message.length > 10000 || htmlBody.length > 20000) {
    return json({ success: false, error: "Nachricht fehlt oder ist zu lang." }, 400);
  }

  try {
    const upstream = await fetch(endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        secret: env.MAIL_API_SECRET,
        to,
        subject,
        message,
        htmlBody
      }),
      redirect: "follow"
    });

    const resultText = await upstream.text();
    let result;
    try {
      result = JSON.parse(resultText);
    } catch {
      console.error("Mailserver lieferte keine gültige JSON-Antwort. HTTP:", upstream.status);
      return json({ success: false, error: "Mailserver hat keine gültige Antwort geliefert." }, 502);
    }

    if (!upstream.ok || result.success !== true) {
      console.error("Mailserver meldete einen Versandfehler. HTTP:", upstream.status);
      return json({ success: false, error: "Google konnte die E-Mail nicht versenden." }, 502);
    }

    return json({ success: true });
  } catch (error) {
    console.error("Mailserver nicht erreichbar:", error);
    return json({ success: false, error: "Mailserver ist momentan nicht erreichbar." }, 502);
  }
}
