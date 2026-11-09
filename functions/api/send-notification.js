const PROJECT_ID = "medienscoutswebseite";
const FIREBASE_API_KEY = "AIzaSyAheWnI7RFPl9h0C0rGy_6-l5liyNsMKzc";
const json = (data, status=200) => new Response(JSON.stringify(data), {status,headers:{"Content-Type":"application/json; charset=utf-8","Cache-Control":"no-store, private","X-Content-Type-Options":"nosniff"}});
const decodeValue = v => {
  if (!v) return null;
  if (v.stringValue !== undefined) return v.stringValue;
  if (v.booleanValue !== undefined) return v.booleanValue;
  if (v.integerValue !== undefined) return Number(v.integerValue);
  if (v.doubleValue !== undefined) return Number(v.doubleValue);
  if (v.nullValue !== undefined) return null;
  if (v.arrayValue) return (v.arrayValue.values||[]).map(decodeValue);
  if (v.mapValue) return Object.fromEntries(Object.entries(v.mapValue.fields||{}).map(([k,x])=>[k,decodeValue(x)]));
  return null;
};
const decodeDoc = d => Object.fromEntries(Object.entries(d.fields||{}).map(([k,v])=>[k,decodeValue(v)]));
const escapeHtml = s => String(s??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const fill = (s, values, html=false) => String(s||"").replace(/\{(student|platform|class|motivation)\}/g,(_,k)=>html?escapeHtml(values[k]||""):String(values[k]||""));
async function readDoc(path, token) {
  const r=await fetch(`https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents/${path}`,{headers:{Authorization:`Bearer ${token}`}});
  if(!r.ok) return null;
  return decodeDoc(await r.json());
}
export async function onRequestPost({request,env}) {
  if(!env.MAIL_WEBAPP_URL||!env.MAIL_API_SECRET) return json({success:false,error:"Mailserver ist nicht vollständig konfiguriert."},503);
  const endpoint=String(env.MAIL_WEBAPP_URL);
  if(!endpoint.startsWith("https://script.google.com/macros/s/")||!endpoint.endsWith("/exec")) return json({success:false,error:"Die Mailserver-URL ist ungültig."},503);
  const match=(request.headers.get("Authorization")||"").match(/^Bearer\s+(.+)$/i);
  if(!match) return json({success:false,error:"Anmeldung erforderlich."},401);
  let data;
  try { const raw=await request.text(); if(raw.length>3000)return json({success:false,error:"Anfrage zu groß."},413); data=JSON.parse(raw); }
  catch { return json({success:false,error:"Ungültige Anfrage."},400); }
  const {type,id}=data||{};
  if(!["passwordReset","application"].includes(type)||typeof id!=="string"||!/^[A-Za-z0-9_-]{1,150}$/.test(id)) return json({success:false,error:"Ungültiger Benachrichtigungstyp oder Eintrag."},400);
  try {
    const authRes=await fetch(`https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=${FIREBASE_API_KEY}`,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({idToken:match[1]})});
    if(!authRes.ok) return json({success:false,error:"Anmeldung ist abgelaufen."},401);
    const uid=(await authRes.json()).users?.[0]?.localId;
    if(!uid) return json({success:false,error:"Account konnte nicht geprüft werden."},401);
    const collection=type==="passwordReset"?"tickets":"applications";
    const record=await readDoc(`${collection}/${encodeURIComponent(id)}`,match[1]);
    if(!record||record.uid!==uid) return json({success:false,error:"Eintrag nicht gefunden oder gehört nicht zu diesem Account."},403);
    if(type==="passwordReset"&&record.passwordReset!==true) return json({success:false,error:"Das ist keine Passwort-Zurücksetzung."},400);
    const settings=await readDoc("settings/main",match[1]);
    const template=type==="passwordReset"
      ? (settings?.mailTemplates?.passwordResetByPlatform?.[record.passwordPlatform] || settings?.mailTemplates?.passwordReset)
      : settings?.mailTemplates?.application;
    if(!template?.to||!template?.subject||!template?.body||!template?.html) return json({success:false,error:"Die E-Mail-Vorlage ist noch nicht vollständig eingerichtet."},503);
    const to=String(template.to).trim();
    if(!/^[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+$/.test(to)||to.length>254) return json({success:false,error:"Die Empfängeradresse in den Einstellungen ist ungültig."},503);
    const values={
      student:String(record.name||record.userName||"Schüler"),
      platform:String(record.passwordPlatform||""),
      class:String(record.klass||""),
      motivation:String(record.motivation||"")
    };
    const subject=fill(template.subject,values).replace(/[\r\n]/g," ").slice(0,200);
    const message=fill(template.body,values).slice(0,10000);
    const htmlBody=fill(template.html,values,true).slice(0,20000);
    const upstream=await fetch(endpoint,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({secret:env.MAIL_API_SECRET,to,subject,message,htmlBody,requestId:type+":"+id}),redirect:"follow"});
    const result=await upstream.json().catch(()=>null);
    if(!upstream.ok||result?.success!==true) return json({success:false,error:"Google konnte die E-Mail nicht versenden."},502);
    return json({success:true});
  } catch(error) {
    console.error("Automatische Benachrichtigung fehlgeschlagen:",error);
    return json({success:false,error:"Benachrichtigung konnte momentan nicht versendet werden."},502);
  }
}