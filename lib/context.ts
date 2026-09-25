import type {Assessment,DeskState,Market,NewsItem,Signal} from "./types";
import {atr} from "./strategy.ts";

function recent(at:number,now:number,window:number){return Number.isFinite(at)&&at<=now&&now-at<window;}
function relevant(n:NewsItem,symbol:string){return n.assets.includes(symbol)||(n.assets.length===0&&((n.verified&&n.topic==="MACRO")||/\b(?:crypto(?:currency)?|cryptocurrencies|exchange)\b/i.test(n.title)));}
function supported(items:NewsItem[]){return items.some(n=>n.verified)||new Set(items.map(n=>n.source)).size>=2;}

export function assessMarket(m:Market,state:DeskState,now=Date.now()):{signal:Signal;assessment:Assessment}{
 const base=m.technicalSignal||m.signal,online=state.online;
 const newsReady=state.newsHealth.ok&&recent(state.newsHealth.checkedAt,now,5*60000);
 const searchReady=!!online?.searchSources.some(s=>s.ok&&recent(s.checkedAt,now,30*60000));
 const sentimentReady=!!online?.sentiment&&online.sentimentHealth.ok&&recent(online.sentiment.checkedAt,now,2*3600000)&&recent(online.sentiment.publishedAt,now,48*3600000);
 const sentiment=sentimentReady?online!.sentiment!.value:null;
 const activeFeeds=state.newsHealth.feeds?new Set(state.newsHealth.feeds.filter(f=>f.ok).map(f=>f.name)):null;
 // Identical headlines do not count twice toward agreement, including syndication.
 const relevantNews=[...new Map(state.news.filter(n=>recent(n.publishedAt,now,2*3600000)&&recent(n.seenAt,now,2*3600000)&&(!activeFeeds||activeFeeds.has(n.source))&&relevant(n,m.symbol)).map(n=>[n.title.toLowerCase().replace(/[^a-z0-9]/g,""),n])).values()];
 const positive=relevantNews.filter(n=>!n.uncertain&&n.tone==="POSITIVE"),negative=relevantNews.filter(n=>!n.uncertain&&n.tone==="NEGATIVE");
 const bullish=supported(positive),bearish=supported(negative);
 const bias=bullish&&bearish?"MIXED":bullish?"POSITIVE":bearish?"NEGATIVE":"NEUTRAL";
 const goodRegions=new Set((online?.searchSources||[]).filter(s=>s.ok&&recent(s.checkedAt,now,30*60000)).map(s=>s.name.split(" ").at(-1)));
 const searchMatches=(online?.searches||[]).filter(x=>goodRegions.has(x.region)&&x.assets.includes(m.symbol)&&recent(x.publishedAt,now,24*3600000));
 const bars=m.history.filter(c=>c.time+60000<=now).sort((a,b)=>a.time-b.time),last=bars.at(-1),prior=bars.slice(-21,-1),average=prior.reduce((a,b)=>a+b.volume,0)/Math.max(1,prior.length);
 const volumeRatio=last&&prior.length===20&&average>0?last.volume/average:null;
 const mediaMentions=relevantNews.filter(n=>recent(n.publishedAt,now,3600000)).length;
 const a:Assessment={version:"context-v1",at:now,coverage:!newsReady||!searchReady?"BLOCKED":sentimentReady?"READY":"PARTIAL",technical:base.action+": "+base.reason,newsBias:bias,newsSources:new Set(relevantNews.map(n=>n.source)).size,headlines:relevantNews.slice(0,6).map(({title,url,source,publishedAt})=>({title,url,source,publishedAt})),searchMatches,mediaMentions,volumeRatio,sentiment,reasons:[],action:base.action};
 let chosen:Signal={...base};
 const wait=(reason:string)=>{a.reasons.push(reason);chosen={action:"WAIT",strategy:"Market + news + attention",regime:base.regime,barTime:base.barTime,reason};};
 if(!recent(m.updatedAt,now,15000))wait("Quote is stale; waiting for fresh execution data");
 else if(!newsReady)wait("News coverage is incomplete or stale; new entries wait");
 else if(!searchReady)wait("Online search coverage is unavailable or stale; new entries wait");
 else {
  const shock=relevantNews.some(n=>!n.uncertain&&n.severity==="HIGH"&&recent(n.publishedAt,now,30*60000)&&(n.verified||n.topic==="SECURITY"));
  if(state.settings.newsGuard&&shock)wait("Recent security or macro event; new entries paused while conditions settle");
  else if(bias==="MIXED")wait("News sources point in conflicting directions");
  else if((base.action==="LONG"&&bearish)||(base.action==="SHORT"&&bullish))wait("News direction conflicts with the price setup");
  else {
   const momentum=last&&bars.length>=6?last.close/bars.at(-6)!.close-1:0;
   const direction=momentum>0?"LONG":"SHORT";
   const attention=searchMatches.length>0||(mediaMentions>=3&&a.newsSources>=2);
   const alignedNews=(direction==="LONG"&&bullish)||(direction==="SHORT"&&bearish);
   // Context may create a candidate only after the baseline has passed its candle,
   // gap, freshness and volatility checks. It never overrides a data rejection.
   if(base.action==="WAIT"&&base.reason.startsWith("No complete setup")&&last&&recent(last.time+60000,now,90000)&&volumeRatio!==null&&volumeRatio>=1.5&&Math.abs(momentum)>=.001&&attention&&alignedNews){
    const distance=atr(bars)*1.8,sign=direction==="LONG"?1:-1;
    const candleConfirms=sign*(last.close-last.open)>0;
    if(distance>0&&candleConfirms){chosen={action:direction,strategy:"News and attention confirmation",regime:base.regime,barTime:last.time,entry:last.close,stop:last.close-sign*distance,target:last.close+sign*distance*1.8,atr:distance/1.8,reason:"Price and volume confirm reported news direction with elevated search or media attention"};a.reasons.push("Context created a paper candidate after price and volume confirmation");}
   }
   if(chosen.action!=="WAIT"){
    if(sentiment!==null&&((sentiment>=80&&chosen.action==="LONG")||(sentiment<=20&&chosen.action==="SHORT"))&&!alignedNews)wait("Extreme crowd sentiment; waiting for supporting news before following the move");
    else if((chosen.action==="LONG"&&m.funding>.001)||(chosen.action==="SHORT"&&m.funding<-.001))wait("Funding suggests a crowded position; entry deferred");
    else {a.reasons.push(chosen.reason);a.reasons.push(bullish||bearish?"Reported news direction: "+bias.toLowerCase():"No corroborated directional news in the recent source sample");a.reasons.push(searchMatches.length?"Coin appears in regional Google trending searches":"No matching coin in the regional trending-search sample");if(sentiment===null)a.reasons.push("Daily sentiment unavailable; no sentiment inference used");chosen.reason=a.reasons.join(". ");}
   }else if(!a.reasons.length)a.reasons.push(base.reason);
  }
 }
 a.action=chosen.action;
 return {signal:chosen,assessment:a};
}

export function applyMarketContext(state:DeskState,now=Date.now()){
 for(const m of state.markets){m.technicalSignal=m.technicalSignal||m.signal;const v=assessMarket(m,state,now);m.signal=v.signal;m.assessment=v.assessment;}
}
