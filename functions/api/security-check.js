/**
 * Cloudflare Pages Function: serverseitige Erkennung des IP-Herkunftslandes.
 *
 * Aufruf: GET /api/security-check
 *
 * Diese Teststufe speichert keine Besucherdaten und blockiert niemanden.
 * Die rohe IP-Adresse wird bewusst weder zurückgegeben noch protokolliert.
 * Eine Zuordnung zu Accounts und ein Admin-Protokoll kommen erst mit
 * serverseitiger Firebase-Token-Prüfung und geschützter Speicherung hinzu.
 */
export async function onRequestGet({ request }) {
  const country = (request.headers.get("CF-IPCountry") || "XX").toUpperCase();

  const allowedCountries = new Set(["DE", "AT", "CH"]);
  const knownCountry = country !== "XX" && country !== "T1";
  const allowed = knownCountry && allowedCountries.has(country);

  const countryNames = {
    DE: "Deutschland",
    AT: "Österreich",
    CH: "Schweiz",
    XX: "Unbekannt"
  };

  return new Response(
    JSON.stringify({
      country,
      countryName: countryNames[country] || country,
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
