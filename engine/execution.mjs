import {createHmac,randomUUID} from "node:crypto";
const BASE="https://api.coindcx.com/exchange/v1/derivatives/futures";
const ALLOWED=new Set(["positions","orders","orders/create","orders/cancel","positions/create_tpsl","positions/exit"]);
export class CoinDCX {
 constructor(key,secret,transport=fetch){this.key=key;this.secret=secret;this.transport=transport;}
 async request(path,data={},timeout=6000){
  if(!ALLOWED.has(path))throw Error("Operation is outside the trading adapter");
  const body=JSON.stringify({timestamp:Date.now(),...data});
  const signature=createHmac("sha256",this.secret).update(body).digest("hex");
  let response;try{response=await this.transport(BASE+"/"+path,{method:"POST",headers:{"Content-Type":"application/json","X-AUTH-APIKEY":this.key,"X-AUTH-SIGNATURE":signature},body,signal:AbortSignal.timeout(timeout)});}catch{throw Error("OUTCOME_UNKNOWN");}
  if(!response.ok)throw Error("Exchange returned "+response.status);return response.json();
 }
 async positions(){const all=[];for(let page=1;page<=10;page++){const rows=await this.request("positions",{page:String(page),size:"100",margin_currency_short_name:["USDT"]});if(!Array.isArray(rows))throw Error("Invalid position response");all.push(...rows);if(rows.length<100)return all;}throw Error("Position pagination limit exceeded");}
 async orders(){const all=[];for(let page=1;page<=10;page++){const rows=await this.request("orders",{status:"open,filled,partially_filled,partially_cancelled,cancelled,rejected,untriggered",page:String(page),size:"100",margin_currency_short_name:["USDT"]});if(!Array.isArray(rows))throw Error("Invalid order response");all.push(...rows);if(rows.length<100)return all;}throw Error("Order pagination limit exceeded");}
}
export function protectionAccepted(result){return !!result?.stop_loss?.id&&result.stop_loss.success!==false&&result.stop_loss.status==="untriggered"&&!!result?.take_profit?.id&&result.take_profit.success!==false&&result.take_profit.status==="untriggered";}
export class ProtectedExecution {
 constructor(exchange,journal,{allowLive=false}={}){this.exchange=exchange;this.journal=journal;this.allowLive=allowLive;this.busy=false;}
 async enter(plan){
  if(!this.allowLive)throw Error("Live execution is disabled");
  if(this.busy)throw Error("Execution writer is busy");
  if(!plan.validated||!plan.pair||!["LONG","SHORT"].includes(plan.side)||![plan.entry,plan.stop,plan.target,plan.quantity,plan.leverage,plan.risk,plan.allocation].every(Number.isFinite)||plan.quantity<=0||plan.entry<=0||plan.stop<=0||plan.target<=0||plan.leverage<1||plan.leverage>3||plan.risk<=0||plan.risk>plan.allocation*.005||Date.now()-plan.quoteAt>5000)throw Error("Invalid or expired trade plan");
  if(plan.side==="LONG"&&!(plan.stop<plan.entry&&plan.target>plan.entry)||plan.side==="SHORT"&&!(plan.stop>plan.entry&&plan.target<plan.entry))throw Error("Invalid stop or target");
  if(this.journal.unresolved().length)throw Error("Unresolved intent blocks new exposure");
  this.busy=true;let intent;
  try{
   const before=await this.exchange.positions();
   // Initial live allocation deliberately admits one position and no manual exposure.
   if(before.some(p=>Math.abs(Number(p.active_pos))>0))throw Error("Existing account exposure blocks initial live entries");
   intent={id:randomUUID(),createdAt:Date.now(),state:"SUBMITTING",plan,orderId:null,positionId:null};this.journal.put(intent);
   let created;try{created=await this.exchange.request("orders/create",{order:{side:plan.side==="LONG"?"buy":"sell",pair:plan.pair,order_type:"limit_order",price:plan.entry,stop_price:null,total_quantity:plan.quantity,leverage:plan.leverage,notification:"no_notification",time_in_force:"immediate_or_cancel",margin_currency_short_name:"USDT",position_margin_type:"isolated"}});}catch(error){intent.state="UNKNOWN";intent.error=String(error.message);this.journal.put(intent);throw Error("Entry outcome unknown; no resubmission permitted");}
   const order=Array.isArray(created)?created[0]:created;if(!order?.id){intent.state="UNKNOWN";this.journal.put(intent);throw Error("Order acknowledgement incomplete");}
   intent.orderId=order.id;intent.state="ACKNOWLEDGED";this.journal.put(intent);
   await this.reconcile(intent);
   return intent;
  }finally{this.busy=false;}
 }
 async reconcile(intent){
  if(["CLOSED","REJECTED","NO_FILL"].includes(intent.state))return intent;
  let positions,orders;try{[positions,orders]=await Promise.all([this.exchange.positions(),this.exchange.orders()]);}catch{intent.state="RECONCILE_REQUIRED";this.journal.put(intent);throw Error("Exchange state unavailable; new exposure halted");}
  if(!intent.orderId){intent.state="UNKNOWN";this.journal.put(intent);throw Error("Unknown submission needs reconciliation; it will not be retried");}
  const order=orders.find(o=>o.id===intent.orderId),position=positions.find(p=>p.pair===intent.plan.pair&&Math.abs(Number(p.active_pos))>0);
  if(!order&&!intent.positionId){intent.state="RECONCILE_REQUIRED";this.journal.put(intent);throw Error("Entry order not found in exchange history");}
  if(!position){if(intent.positionId){intent.state="CLOSED";}else if(order&&["cancelled","rejected","partially_cancelled"].includes(order.status)&&Number(order.total_quantity)-Number(order.remaining_quantity)-Number(order.cancelled_quantity||0)<=0){intent.state=order.status==="rejected"?"REJECTED":"NO_FILL";}else intent.state="AWAITING_FILL";this.journal.put(intent);return intent;}
  // An unlinked position cannot be assumed to belong to this engine.
  if(!intent.positionId&&(!order||!(Number(order.avg_price)>0))){intent.state="RECONCILE_REQUIRED";this.journal.put(intent);throw Error("Position ownership cannot be established");}
  intent.positionId=position.id;intent.filledQuantity=Math.abs(Number(position.active_pos));this.journal.put(intent);
  if(Number(order?.remaining_quantity)>0){try{await this.exchange.request("orders/cancel",{id:intent.orderId});}catch{intent.state="RECONCILE_REQUIRED";this.journal.put(intent);}}
  if(position.position_margin_type&&position.position_margin_type.toLowerCase()!=="isolated"){await this.emergencyExit(intent);throw Error("Unexpected margin mode; close requested");}
  const long=intent.plan.side==="LONG",price=Number(position.avg_price||order?.avg_price),liq=Number(position.liquidation_price);
  if(!Number.isFinite(price)||intent.filledQuantity>intent.plan.quantity+1e-10||(long?Number(position.active_pos)<0:Number(position.active_pos)>0)||(liq>0&&(long?liq>=intent.plan.stop:liq<=intent.plan.stop))){await this.emergencyExit(intent);throw Error("Fill or liquidation guard failed; close requested");}
  const stopOk=Math.abs(Number(position.stop_loss_trigger)-intent.plan.stop)<1e-8,targetOk=Math.abs(Number(position.take_profit_trigger)-intent.plan.target)<1e-8;
  if(stopOk&&targetOk){intent.state="PROTECTED";this.journal.put(intent);return intent;}
  try{
   const result=await this.exchange.request("positions/create_tpsl",{id:position.id,take_profit:{stop_price:String(intent.plan.target),order_type:"take_profit_market"},stop_loss:{stop_price:String(intent.plan.stop),order_type:"stop_market"}},4000);
   if(!protectionAccepted(result))throw Error("Partial protection failure");
   intent.stopOrderId=result.stop_loss.id;intent.targetOrderId=result.take_profit.id;
   const check=(await this.exchange.positions()).find(p=>p.id===position.id);
   if(check&&Math.abs(Number(check.active_pos))>0&&Math.abs(Number(check.stop_loss_trigger)-intent.plan.stop)<1e-8&&Math.abs(Number(check.take_profit_trigger)-intent.plan.target)<1e-8)intent.state="PROTECTED";
   else if(check&&Number(check.active_pos)===0)intent.state="CLOSED";else throw Error("Protection verification failed");
   this.journal.put(intent);return intent;
  }catch{await this.emergencyExit(intent);throw Error("Protective orders not verified; emergency exit requested");}
 }
 async emergencyExit(intent){
  if(!intent.positionId){intent.state="RECONCILE_REQUIRED";this.journal.put(intent);return;}
  intent.state="EXIT_PENDING";this.journal.put(intent);
  // Keep existing protection in place; never cancel all exits ahead of closing.
  try{await this.exchange.request("positions/exit",{id:intent.positionId},4000);const positions=await this.exchange.positions();const p=positions.find(p=>p.id===intent.positionId);if(p&&Number(p.active_pos)===0||!p)intent.state="CLOSED";else intent.state="EXIT_PENDING";}catch{intent.state="EXIT_UNKNOWN";}
  this.journal.put(intent);
 }
}
