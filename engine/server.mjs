import http from "node:http";
import {timingSafeEqual} from "node:crypto";
import {Store} from "./store.mjs";
import {CoinDCX,ProtectedExecution} from "./execution.mjs";
import {initialState,advancePaper,event,closePaper,liveGates} from "../lib/paper.ts";
import {marketSnapshot,candles,instrument} from "../lib/exchange.ts";
import {fetchNews} from "../lib/news.ts";
import {fetchOnline} from "../lib/online.ts";
import {validSettings} from "../lib/strategy.ts";
import {runBacktest} from "../lib/backtest.ts";
const token=process.env.ENGINE_TOKEN||"";
if(token.length<32)throw Error("ENGINE_TOKEN must have at least 32 characters");
if(!/^[a-f0-9]{64}$/i.test(process.env.APP_ENCRYPTION_KEY||""))throw Error("APP_ENCRYPTION_KEY must be a 64-character hexadecimal key");
const directory=process.env.DATA_DIR||"./data";
if(process.env.RENDER&&process.env.PERSISTENT_STORAGE!=="true")throw Error("Production worker requires verified persistent storage");
const store=new Store(directory,process.env.APP_ENCRYPTION_KEY);
let state=store.get("desk",initialState()),busy=false,stopping=false;
state.worker={connected:true,lastHeartbeat:Date.now(),continuous:process.env.ALWAYS_ON==="true"&&process.env.PERSISTENT_STORAGE==="true",message:process.env.ALWAYS_ON==="true"?"Server worker configured for continuous paper observation":"Development worker; continuous hosting has not been verified"};
// Only this process may write this account. Holding a separate SQLite write transaction
// prevents a second worker on the same disk from taking leadership.
import {DatabaseSync} from "node:sqlite";
const leader=new DatabaseSync(directory+"/leader.sqlite");
leader.exec("PRAGMA busy_timeout=0; CREATE TABLE IF NOT EXISTS leader(id INTEGER PRIMARY KEY); BEGIN EXCLUSIVE;");
event(state.portfolio,"SYSTEM","Worker started. Durable paper state restored; real-money execution remains locked.");
function save(){state.version++;store.set("desk",state);}
function authorize(req){const candidate=Buffer.from(req.headers.authorization||""),expected=Buffer.from("Bearer "+token);return candidate.length===expected.length&&timingSafeEqual(candidate,expected);}
function send(res,status,data){res.writeHead(status,{"Content-Type":"application/json","Cache-Control":"no-store","X-Content-Type-Options":"nosniff"});res.end(JSON.stringify(data));}
function safeState(){return {state,gates:liveGates(state),liveExecution:{enabled:false,reason:"Exchange verification and independent strategy qualification remain pending"}};}
async function scan(){
 if(busy||stopping)return;busy=true;state.portfolio.lastAttempt=Date.now();
 try{
  const held=state.portfolio.trades.filter(t=>t.status==="OPEN").map(t=>t.pair);
  const rotate=!state.markets.length||Date.now()-(state.universeSelectedAt||0)>86400000;
  const refreshNews=Date.now()-state.newsHealth.checkedAt>60000;
  const refreshOnline=!state.online||Date.now()-state.online.checkedAt>10*60000;
  // Settle source requests independently: a market failure must not suppress news
  // updates, and no abandoned promise may become an unhandled rejection.
  const [markets,news,online]=await Promise.allSettled([marketSnapshot(state.markets,held,rotate),refreshNews?fetchNews(state.news):Promise.resolve(null),refreshOnline?fetchOnline(state.online):Promise.resolve(null)]);
  if(news.status==="fulfilled"&&news.value){state.news=news.value.items;state.newsHealth=news.value.health;}
  if(online.status==="fulfilled"&&online.value)state.online=online.value;
  if(markets.status==="rejected")throw markets.reason;
  state.markets=markets.value;if(rotate)state.universeSelectedAt=Date.now();state.marketError=null;
  advancePaper(state);
  if(refreshNews)console.log("context_scan",JSON.stringify({version:"context-v1",news:state.newsHealth.sources,newsReady:state.newsHealth.ok,searchSources:state.online?.searchSources.filter(s=>s.ok).length||0,sentimentReady:state.online?.sentimentHealth.ok||false,assessed:state.markets.length,coverage:state.markets.map(m=>m.assessment?.coverage),running:state.settings.running}));
 }catch(error){state.marketError="Market data is unavailable or stale; new entries are blocked.";event(state.portfolio,"DATA",state.marketError);console.error("scan_failed",error instanceof Error?error.name:"Error");}
 finally{state.worker.lastHeartbeat=Date.now();save();busy=false;}
}
async function command(body){
 const action=body.action;
 if(action==="enable-live")throw Error("Live execution is locked: independent strategy evidence and exchange protection verification are still required.");
 if(action==="scan"){await scan();return safeState();}
 if(busy)throw Error("The engine is updating; try again shortly.");
 busy=true;
 try{
  if(action==="start"){if(state.portfolio.halted)throw Error(state.portfolio.halted);state.settings.running=true;event(state.portfolio,"SYSTEM","Continuous paper execution enabled");}
  else if(action==="pause"){state.settings.running=false;event(state.portfolio,"SYSTEM","New paper entries paused; position supervision continues");}
  else if(action==="settings"){const next=validSettings({...state.settings,...body.settings});next.running=state.settings.running;if(next.paperCapital!==state.settings.paperCapital){if(state.portfolio.trades.length)throw Error("Paper capital cannot change after the first trade");const p=initialState().portfolio;p.initial=p.balance=p.peak=p.dayStart=p.weekStart=next.paperCapital;p.equityCurve=[{time:Date.now(),equity:next.paperCapital}];state.portfolio=p;}state.settings=next;event(state.portfolio,"SETTINGS","Risk limits updated");}
  else if(action==="connect"){const key=String(body.key||"").trim(),secret=String(body.secret||"").trim();if(key.length<16||secret.length<16||key.length>256||secret.length>512)throw Error("Invalid API credentials");const api=new CoinDCX(key,secret);await api.positions();store.set("credentials",store.encrypt({key,secret}));state.connection={configured:true,verified:true,message:"Read-only futures access verified. Real orders remain disabled."};event(state.portfolio,"ACCOUNT","Futures account verified");}
  else if(action==="disconnect"){if(store.unresolved().length)throw Error("Resolve exchange order intents before removing credentials");store.set("credentials",null);state.connection={configured:false,verified:false,message:"Credentials removed"};}
  else if(action==="close"){const t=state.portfolio.trades.find(t=>t.id===body.id&&t.status==="OPEN");if(!t)throw Error("Open paper position not found");state.markets=await marketSnapshot(state.markets,state.portfolio.trades.filter(t=>t.status==="OPEN").map(t=>t.pair),false);const m=state.markets.find(m=>m.pair===t.pair);if(!m||Date.now()-m.updatedAt>15000)throw Error("Fresh execution quote unavailable");closePaper(state,t,(t.side==="LONG"?m.bid:m.ask)*(1+(t.side==="LONG"?-1:1)*state.settings.slippageBps/10000),"Manual paper exit");}
  else if(action==="backtest"){const pair=String(body.pair||"");if(!state.markets.some(m=>m.pair===pair))throw Error("Select a current universe member");const [bars,inst]=await Promise.all([candles(pair,1500),instrument(pair)]);state.backtest=runBacktest(pair,bars,state.settings,inst);event(state.portfolio,"RESEARCH","Recent-data diagnostic completed",pair);}
  else throw Error("Unknown action");
  save();return safeState();
 }finally{busy=false;}
}
const server=http.createServer(async(req,res)=>{
 const path=new URL(req.url,"http://localhost").pathname;
 if(path==="/healthz"){send(res,Date.now()-(state.worker.lastHeartbeat||0)<180000?200:503,{ok:!stopping,mode:"PAPER",lastHeartbeat:state.worker.lastHeartbeat});return;}
 if(!authorize(req)){send(res,401,{error:"Authentication required"});return;}
 if(path==="/v1/state"&&req.method==="GET"){send(res,200,safeState());return;}
 if(path==="/v1/action"&&req.method==="POST"){try{let raw="";for await(const chunk of req){raw+=chunk;if(Buffer.byteLength(raw)>16384)throw Error("Request too large");}send(res,200,await command(JSON.parse(raw)));}catch(error){send(res,409,{error:error instanceof Error?error.message:"Action failed"});}return;}
 if(path==="/v1/export"&&req.method==="GET"){send(res,200,{state,unresolved:store.unresolved()});return;}
 send(res,404,{error:"Not found"});
});
server.requestTimeout=15000;server.headersTimeout=10000;
server.listen(Number(process.env.PORT)||10000,"0.0.0.0",()=>{console.log("DCX Pilot worker listening; real orders disabled");if(process.env.DISABLE_SCAN!=="true")scan();});
const timer=setInterval(()=>{if(process.env.DISABLE_SCAN!=="true")scan();},15000);
const recovery=setInterval(async()=>{if(busy||stopping)return;const intents=store.unresolved();if(!intents.length)return;const credentials=store.credentials();if(!credentials){state.portfolio.halted="Unresolved exchange intent without credentials";save();return;}busy=true;try{const adapter=new ProtectedExecution(new CoinDCX(credentials.key,credentials.secret),store,{allowLive:false});for(const intent of intents){if(["EXIT_PENDING","EXIT_UNKNOWN"].includes(intent.state))await adapter.emergencyExit(intent);else await adapter.reconcile(intent);}}catch{state.portfolio.halted="Exchange reconciliation requires review";state.settings.running=false;save();}finally{busy=false;}},5000);
async function shutdown(){stopping=true;clearInterval(timer);clearInterval(recovery);event(state.portfolio,"SYSTEM","Worker stopping; paper run preference preserved for restart");server.close();const deadline=Date.now()+15000;while(busy&&Date.now()<deadline)await new Promise(resolve=>setTimeout(resolve,50));save();leader.close();store.close();process.exit(0);}
process.on("SIGTERM",shutdown);process.on("SIGINT",shutdown);
