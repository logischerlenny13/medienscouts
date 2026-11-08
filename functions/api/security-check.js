/**
 * Cloudflare Pages Function: serverseitige Erkennung von IP-Herkunftsland.
 *
 * Aufruf: GET /api/security-check
 *
 * Diese erste Stufe ERFASST NICHTS dauerhaft und blockiert noch keine Besucher.
 * Sie liefert nur die vom Cloudflare-Rand ermittelten Daten für einen Funktionstest.
 * Die spätere Admin-Protokollierung und Sperrlogik benötigt eine geschützte,
 * serverseitige Speicherung sowie eine verifizierte Firebase-Identität.
 */
export async function onRequestGet({ request }) {
  const country = (request.headers.get("CF-IPCountry") || "XX").toUpperCase();
  const ip = request.headers.get("CF-Connecting-IP") || null;

  const allowedCountries = new Set(["DE", "AT", "CH"]);
  const knownCountry = country !== "XX" && country !== "T1";
  const allowed = knownCountry && allowedCountries.has(country);

  return new Response(
    JSON.stringify({
      country,
      ip,
      countryName:
        country === "DE" ? "Deutschland" :
        country === "AT" ? "Österreich" :
        country === "CH" ? "Schweiz" :
        country === "XX" ? "Unbekannt" :
        country,
      allowed,
      status: allowed ? "allowed" : "review",
      enforcement: "disabled",
      checkedAt: new Date().toISOString()
    }),
    {
      status: 200,
      headers: {
        "Content-Type": "application/json; charset=utf-8",
        "Cache-Control": "no-store, private",
        "X-Content-Type-Options": "nosniff"
      }
    }
  );
}
