const PROJECT_ID = "medienscoutswebseite";
const FIREBASE_API_KEY = "AIzaSyAheWnI7RFPl9h0C0rGy_6-l5liyNsMKzc";
const ALLOWED = new Set(["DE", "AT", "CH"]);
const COUNTRY_NAMES = {DE:"Deutschland",AT:"Österreich",CH:"Schweiz",US:"USA",GB:"Vereinigtes Königreich",NL:"Niederlande",FR:"Frankreich",BE:"Belgien",PL:"Polen",TR:"Türkei",XX:"Unbekannt"};
const json=(data,status=200)=>new Response(JSON.stringify(data),{status,headers:{"Content-Type":"application/json; charset=utf-8","Cache-Control":"no-store, private","X-Content-Type-Options":"nosniff"}});
const requestIp=r=>r.headers.get("CF-Connecting-IP")||"unknown";
const countryInfo=r=>{const code=(r.headers.get("CF-IPCountry")||"XX").toUpperCase();return{code,name:COUNTRY_NAMES[code]||code,decision:ALLOWED.has(code)?(code==="AT"?"review":"allowed"):"blocked"}};
async function verifyFirebaseUser(request){
 const m=(request.headers.get("Authorization")||"").match(/^Bearer\s+(.+)$/i);if(!m)return null;
 const lookup=await fetch(`https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=${FIREBASE_API_KEY}`,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({idToken:m[1]})});
 if(!lookup.ok)return null;const user=(await lookup.json()).users?.[0];if(!user?.localId)return null;
 const url=`https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents/users/${encodeURIComponent(user.localId)}`;
 const pr=await fetch(url,{headers:{Authorization:`Bearer ${m[1]}`}});if(!pr.ok)return null;const p=await pr.json();
 return{uid:user.localId,email:user.email||"",name:p.fields?.name?.stringValue||user.displayName||user.email||"Unbekannt",role:p.fields?.role?.stringValue||"Schüler"};
}
async function upsertLegacy(env,r,event,decision){
 const ip=requestIp(r);if(ip==="unknown")return;await env.SECURITY_DB.prepare("DELETE FROM ip_addresses WHERE julianday(last_seen) < julianday('now', '-90 days')").run();
 const c=countryInfo(r),now=new Date().toISOString();
 await env.SECURITY_DB.prepare(`INSERT INTO ip_addresses(ip_address,country_code,country_name,first_seen,last_seen,check_count,last_event_type,decision) VALUES(?,?,?,?,?,1,?,?) ON CONFLICT(ip_address) DO UPDATE SET country_code=excluded.country_code,country_name=excluded.country_name,last_seen=excluded.last_seen,check_count=ip_addresses.check_count+1,last_event_type=excluded.last_event_type,decision=excluded.decision`).bind(ip,c.code,c.name,now,now,event,decision||c.decision).run();
}
async function getIpOverride(env,ip){try{return (await env.SECURITY_DB.prepare("SELECT decision FROM security_ip_overrides WHERE ip_address=?").bind(ip).first())?.decision||null}catch{return null}}
async function isDeviceBlocked(env,id){if(!id)return false;try{return !!(await env.SECURITY_DB.prepare("SELECT device_id FROM security_devices WHERE device_id=? AND blocked=1").bind(id).first())}catch{return false}}
async function logEvent(env,r,user,event,decision,deviceId){
 const ip=requestIp(r),c=countryInfo(r),now=new Date().toISOString();
 try{
  await env.SECURITY_DB.prepare("INSERT INTO security_events(ip_address,country_code,country_name,uid,email,account_name,event_type,decision,device_id,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)").bind(ip,c.code,c.name,user?.uid||null,user?.email||null,user?.name||null,event,decision,deviceId||null,now).run();
 }catch(e){console.warn("Neue Sicherheitstabellen fehlen; nutze bisheriges IP-Protokoll.",e);await upsertLegacy(env,r,event,decision)}
}
async function admin(request){const u=await verifyFirebaseUser(request);return u?.role==="Admin"?u:null}
export async function onRequestGet({request,env}){
 const url=new URL(request.url),ip=requestIp(request);
 if(url.searchParams.get("list")==="1"){
  const u=await admin(request);if(!u)return json({error:"Nicht autorisiert"},403);
  try{
   const events=await env.SECURITY_DB.prepare("SELECT id,ip_address,country_code,country_name,uid,email,account_name,event_type,decision,device_id,created_at FROM security_events ORDER BY created_at DESC LIMIT 500").all();
   const ips=await env.SECURITY_DB.prepare("SELECT ip_address,decision,updated_at FROM security_ip_overrides").all();
   const accounts=await env.SECURITY_DB.prepare("SELECT uid,email,account_name,reason,updated_at FROM security_account_blocks").all();
   const devices=await env.SECURITY_DB.prepare("SELECT device_id,reason,updated_at FROM security_devices WHERE blocked=1").all();
   return json({items:events.results||[],overrides:ips.results||[],blockedAccounts:accounts.results||[],blockedDevices:devices.results||[]});
  }catch(e){
   const old=await env.SECURITY_DB.prepare("SELECT ip_address,country_code,country_name,first_seen,last_seen,check_count,last_event_type,decision FROM ip_addresses ORDER BY last_seen DESC").all();
   return json({items:(old.results||[]).map(x=>({...x,created_at:x.last_seen,event_type:x.last_event_type,account_name:"Noch keine Account-Zuordnung"})),setupRequired:true});
  }
 }
 const deviceId=url.searchParams.get("deviceId")||"";
 const override=await getIpOverride(env,ip),c=countryInfo(request);
 if(override==="blocked"||await isDeviceBlocked(env,deviceId))return json({country:c.code,countryName:c.name,allowed:false,blocked:true,status:"blocked",enforcement:"enabled"},403);
 if(override==="allowed")return json({country:c.code,countryName:c.name,allowed:true,blocked:false,status:"allowed",manualOverride:true});
 if(c.decision==="blocked"){
  try{await logEvent(env,request,null,"suspicious_access","blocked",deviceId)}catch(e){console.error(e)}
  return json({country:c.code,countryName:c.name,allowed:false,blocked:true,status:"blocked",enforcement:"enabled"},403);
 }
 try{await logEvent(env,request,null,"anonymous_visit",c.decision,deviceId)}catch(e){console.error(e)}
 return json({country:c.code,countryName:c.name,allowed:true,blocked:false,status:c.decision,enforcement:"enabled"});
}
export async function onRequestPost({request,env}){
 const body=await request.json().catch(()=>({})),deviceId=String(body.deviceId||"").slice(0,100),eventType=body.action?"admin_action":"login";
 const user=await verifyFirebaseUser(request);if(!user)return json({error:"Ungültige oder abgelaufene Anmeldung"},401);
 if(body.action){
  const actor=await admin(request);if(!actor)return json({error:"Nur Admins dürfen Sicherheitsmaßnahmen ändern"},403);
  const ip=String(body.ip||""),uid=String(body.uid||""),did=String(body.targetDeviceId||"");
  try{
   if(body.action==="allow_ip"||body.action==="block_ip"){
    if(!ip||ip.length>64)return json({error:"Ungültige IP-Adresse"},400);
    await env.SECURITY_DB.prepare("INSERT INTO security_ip_overrides(ip_address,decision,updated_at,updated_by) VALUES(?,?,?,?) ON CONFLICT(ip_address) DO UPDATE SET decision=excluded.decision,updated_at=excluded.updated_at,updated_by=excluded.updated_by").bind(ip,body.action==="allow_ip"?"allowed":"blocked",new Date().toISOString(),actor.uid).run();
   }else if(body.action==="unban_ip"){
    await env.SECURITY_DB.prepare("DELETE FROM security_ip_overrides WHERE ip_address=?").bind(ip).run();
   }else if(body.action==="block_account"){
    if(!uid)return json({error:"Account-ID fehlt"},400);
    await env.SECURITY_DB.prepare("INSERT INTO security_account_blocks(uid,email,account_name,reason,updated_at,updated_by) VALUES(?,?,?,?,?,?) ON CONFLICT(uid) DO UPDATE SET email=excluded.email,account_name=excluded.account_name,reason=excluded.reason,updated_at=excluded.updated_at,updated_by=excluded.updated_by").bind(uid,String(body.email||""),String(body.accountName||""),String(body.reason||"Durch Admin gesperrt"),new Date().toISOString(),actor.uid).run();
   }else if(body.action==="unban_account"){
    await env.SECURITY_DB.prepare("DELETE FROM security_account_blocks WHERE uid=?").bind(uid).run();
   }else if(body.action==="block_device"){
    if(!did)return json({error:"Gerätekennung fehlt"},400);
    await env.SECURITY_DB.prepare("INSERT INTO security_devices(device_id,reason,blocked,updated_at,updated_by) VALUES(?,?,1,?,?) ON CONFLICT(device_id) DO UPDATE SET reason=excluded.reason,blocked=1,updated_at=excluded.updated_at,updated_by=excluded.updated_by").bind(did,String(body.reason||"Anonymer Zugriff gesperrt"),new Date().toISOString(),actor.uid).run();
   }else if(body.action==="unban_device"){
    if(!did)return json({error:"Gerätekennung fehlt"},400);
    await env.SECURITY_DB.prepare("DELETE FROM security_devices WHERE device_id=?").bind(did).run();
   }else return json({error:"Unbekannte Aktion"},400);
   return json({ok:true});
  }catch(e){console.error("Sicherheitsaktion fehlgeschlagen:",e);return json({error:"Datenbanktabellen fehlen noch oder Aktion fehlgeschlagen: "+e.message},503)}
 }
 const ip=requestIp(request),override=await getIpOverride(env,ip),c=countryInfo(request);
 if(override==="blocked"||await isDeviceBlocked(env,deviceId))return json({error:"Dieser Zugriff ist gesperrt."},403);
 if(c.decision==="blocked"&&override!=="allowed")return json({error:"Anmeldung aus diesem Land ist nicht erlaubt"},403);
 try{
  const blocked=await env.SECURITY_DB.prepare("SELECT uid FROM security_account_blocks WHERE uid=?").bind(user.uid).first();
  if(blocked)return json({error:"Dieser Account wurde durch die Administration gesperrt."},403);
 }catch{}
 await logEvent(env,request,user,"login",override==="allowed"?"allowed":c.decision,deviceId);
 return json({ok:true,status:override==="allowed"?"allowed":c.decision});
}
