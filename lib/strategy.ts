import type {Candle,Signal,Settings,Instrument,Market,Trade} from "./types";
export const DEFAULT_SETTINGS:Settings={paperCapital:1000,riskPct:.25,dailyLimitPct:2,weeklyLimitPct:5,drawdownLimitPct:8,leverage:2,maxPositions:2,maxSpreadBps:12,slippageBps:5,feeBps:7.5,newsGuard:true,running:true};
export function ema(values:number[],period:number){let e=values[0]||0;const k=2/(period+1);for(const v of values.slice(1))e=v*k+e*(1-k);return e;}
export function atr(c:Candle[],period=14){const a=c.slice(-(period+1));if(a.length<period+1)return 0;return a.slice(1).reduce((s,v,i)=>s+Math.max(v.high-v.low,Math.abs(v.high-a[i].close),Math.abs(v.low-a[i].close)),0)/period;}
export function aggregate(c:Candle[],minutes:number){const buckets=new Map<number,Candle>();const width=minutes*60000;for(const v of c){const t=Math.floor(v.time/width)*width;const old=buckets.get(t);if(old){old.high=Math.max(old.high,v.high);old.low=Math.min(old.low,v.low);old.close=v.close;old.volume+=v.volume;}else buckets.set(t,{...v,time:t});}return [...buckets.values()].filter(x=>x.time+width<=((c.at(-1)?.time||0)+60000));}
export function signal(candles:Candle[],now=Date.now()):Signal{
 const c=candles.filter(x=>x.time+60000<=now).sort((a,b)=>a.time-b.time);
 const wait=(reason:string,regime="Unknown"):Signal=>({action:"WAIT",strategy:"Observation",regime,reason,barTime:c.at(-1)?.time});
 if(c.length<210)return wait("Collecting at least 210 closed one-minute candles");
 for(let i=c.length-210;i<c.length-1;i++)if(c[i+1].time-c[i].time!==60000)return wait("Candle gap detected; entries paused");
 const last=c.at(-1)!;if(now-(last.time+60000)>90000)return wait("Candle history is stale");
 const close=c.map(x=>x.close),e20=ema(close.slice(-80),20),e50=ema(close.slice(-180),50),v=atr(c),five=aggregate(c,5);if(five.length<40||v<=0)return wait("Higher-timeframe history incomplete");
 const fast=ema(five.map(x=>x.close).slice(-40),10),slow=ema(five.map(x=>x.close).slice(-40),30),trend=Math.abs(fast-slow)/v;
 const regime=trend>.9?(fast>slow?"Uptrend":"Downtrend"):"Range";
 const avgVol=c.slice(-21,-1).reduce((s,x)=>s+x.volume,0)/20,participation=avgVol>0?last.volume/avgVol:0;
 const prior=c.slice(-21,-1),high=Math.max(...prior.map(x=>x.high)),low=Math.min(...prior.map(x=>x.low));
 const make=(action:"LONG"|"SHORT",strategy:string,reason:string,stopDistance:number):Signal=>{const d=action==="LONG"?1:-1;return {action,strategy,regime,reason,entry:last.close,stop:last.close-d*stopDistance,target:last.close+d*stopDistance*1.8,atr:v,barTime:last.time,strength:Math.min(100,Math.round(40+Math.min(trend,3)*10+Math.min(participation,3)*10))};};
 if(v/last.close>.025)return wait("Extreme one-minute volatility",regime);
 if(last.close>high&&fast>slow&&participation>1.5)return make("LONG","Volume breakout","Closed above the prior 20-bar high with stronger volume",v*1.8);
 if(last.close<low&&fast<slow&&participation>1.5)return make("SHORT","Volume breakout","Closed below the prior 20-bar low with stronger volume",v*1.8);
 const previous=c.at(-2)!;
 if(regime==="Uptrend"&&e20>e50&&previous.low<=e20&&last.close>e20&&last.close>previous.close&&participation>.8)return make("LONG","Trend pullback","Uptrend pullback recovered above its short moving average",v*1.6);
 if(regime==="Downtrend"&&e20<e50&&previous.high>=e20&&last.close<e20&&last.close<previous.close&&participation>.8)return make("SHORT","Trend pullback","Downtrend bounce rejected below its short moving average",v*1.6);
 if(regime==="Range"&&last.close<e20-v*1.8&&last.close>previous.close)return make("LONG","Range reversion","Range edge showed a closed-candle recovery",v*1.5);
 if(regime==="Range"&&last.close>e20+v*1.8&&last.close<previous.close)return make("SHORT","Range reversion","Range edge showed a closed-candle rejection",v*1.5);
 return wait("No complete setup; waiting for price and volume confirmation",regime);
}
export function sizeTrade(equity:number,entry:number,stop:number,inst:Instrument,s:Settings,freeMargin:number){
 if(![equity,entry,stop,inst.step,inst.contractValue,freeMargin].every(Number.isFinite)||equity<=0||entry<=0||stop<=0||inst.step<=0||inst.contractValue<=0||s.riskPct<=0||s.riskPct>.5||s.leverage>3)return {quantity:0,risk:0,reason:"Invalid sizing inputs or risk limit"};
 const distance=Math.abs(entry-stop),fee=Math.max(inst.feeRate,s.feeBps/10000),cost=entry*(2*fee+2*s.slippageBps/10000+.001);
 if(distance<=entry*.0001)return {quantity:0,risk:0,reason:"Stop distance too small"};
 const riskPer=inst.contractValue*(distance+cost),budget=equity*s.riskPct/100;
 let q=Math.floor(Math.min(budget/riskPer,freeMargin*.8*s.leverage/(entry*inst.contractValue),inst.maxQuantity)/inst.step+1e-10)*inst.step;
 q=Number(q.toFixed(12));const notional=q*entry*inst.contractValue;
 if(q<inst.minimum||notional<inst.minNotional)return {quantity:0,risk:0,reason:"Minimum order size exceeds the risk budget"};
 if(q*riskPer>budget+1e-8)return {quantity:0,risk:0,reason:"Rounded quantity exceeds risk budget"};
 return {quantity:q,risk:q*riskPer,reason:"Risk and contract limits passed"};
}
export function exitPrice(t:Trade,c:Candle,slippageBps:number){const long=t.side==="LONG",sl=long?c.low<=t.stop:c.high>=t.stop,tp=long?c.high>=t.target:c.low<=t.target;const slip=slippageBps/10000;
 if(sl)return {price:(long?Math.min(t.stop,c.open):Math.max(t.stop,c.open))*(long?1-slip:1+slip),reason:tp?"Stop first (ambiguous candle)":"Stop loss"};
 if(tp)return {price:t.target*(long?1-slip:1+slip),reason:"Take profit"};
 if(c.time-t.openedAt>=90*60000)return {price:c.close*(long?1-slip:1+slip),reason:"Time exit"};return null;
}
export function utcDayKeys(now:number){const local=new Date(now+19800000),day=local.toISOString().slice(0,10);const weekDate=new Date(local);weekDate.setUTCDate(local.getUTCDate()-((local.getUTCDay()+6)%7));return {day,week:weekDate.toISOString().slice(0,10)};}
export function markPnl(t:Trade,price:number){return (price-t.entry)*t.quantity*(t.side==="LONG"?1:-1);}
export function validSettings(value:Partial<Settings>):Settings{const s={...DEFAULT_SETTINGS,...value};for(const k of ["paperCapital","riskPct","dailyLimitPct","weeklyLimitPct","drawdownLimitPct","leverage","maxPositions","maxSpreadBps","slippageBps","feeBps"] as const)if(!Number.isFinite(s[k]))throw Error("Every risk field must be a number");if(s.paperCapital<10||s.paperCapital>10000000||s.riskPct<=0||s.riskPct>.5||s.dailyLimitPct<=0||s.dailyLimitPct>2||s.weeklyLimitPct<=0||s.weeklyLimitPct>5||s.drawdownLimitPct<=0||s.drawdownLimitPct>8||![1,2,3].includes(s.leverage)||![1,2].includes(s.maxPositions)||s.maxSpreadBps<1||s.maxSpreadBps>30||s.slippageBps<1||s.slippageBps>100||s.feeBps<1||s.feeBps>100||typeof s.running!=="boolean"||typeof s.newsGuard!=="boolean")throw Error("Settings exceed permitted risk limits");return s;}
