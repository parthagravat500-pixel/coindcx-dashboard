import {DatabaseSync} from "node:sqlite";
import {mkdirSync} from "node:fs";
import {join} from "node:path";
import {randomBytes,createCipheriv,createDecipheriv} from "node:crypto";
export class Store{
 constructor(directory,key){
  mkdirSync(directory,{recursive:true,mode:0o700});this.key=key;this.db=new DatabaseSync(join(directory,"dcx-pilot.sqlite"));
  this.db.exec("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA busy_timeout=5000; CREATE TABLE IF NOT EXISTS kv(key TEXT PRIMARY KEY,value TEXT NOT NULL); CREATE TABLE IF NOT EXISTS intents(id TEXT PRIMARY KEY,state TEXT NOT NULL,payload TEXT NOT NULL); CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY AUTOINCREMENT,time INTEGER NOT NULL,event TEXT NOT NULL);");
 }
 get(key,fallback=null){const r=this.db.prepare("SELECT value FROM kv WHERE key=?").get(key);return r?JSON.parse(r.value):fallback;}
 set(key,value){this.db.prepare("INSERT INTO kv(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value").run(key,JSON.stringify(value));}
 audit(value){this.db.prepare("INSERT INTO audit(time,event) VALUES(?,?)").run(Date.now(),JSON.stringify(value));}
 put(intent){this.db.prepare("INSERT INTO intents(id,state,payload) VALUES(?,?,?) ON CONFLICT(id) DO UPDATE SET state=excluded.state,payload=excluded.payload").run(intent.id,intent.state,JSON.stringify(intent));this.audit({intent:intent.id,state:intent.state});}
 unresolved(){return this.db.prepare("SELECT payload FROM intents WHERE state NOT IN ('CLOSED','REJECTED','NO_FILL')").all().map(x=>JSON.parse(x.payload));}
 encrypt(value){if(!/^[a-f0-9]{64}$/i.test(this.key||""))throw Error("Encryption key is not configured");const iv=randomBytes(12),c=createCipheriv("aes-256-gcm",Buffer.from(this.key,"hex"),iv),data=Buffer.concat([c.update(JSON.stringify(value),"utf8"),c.final()]);return {iv:iv.toString("hex"),data:data.toString("hex"),tag:c.getAuthTag().toString("hex")};}
 decrypt(value){const d=createDecipheriv("aes-256-gcm",Buffer.from(this.key,"hex"),Buffer.from(value.iv,"hex"));d.setAuthTag(Buffer.from(value.tag,"hex"));return JSON.parse(Buffer.concat([d.update(Buffer.from(value.data,"hex")),d.final()]).toString("utf8"));}
 credentials(){const x=this.get("credentials");return x?this.decrypt(x):null;}
 close(){this.db.close();}
}
