import type {OnlineContext,SearchTrend,SourceStatus} from "./types";
import {publicText,tag} from "./news.ts";
import {assetsIn} from "./subjects.ts";
export const SEARCH_FEEDS=[{region:"US",url:"https://trends.google.com/trending/rss?geo=US"},{region:"IN",url:"https://trends.google.com/trending/rss?geo=IN"}];
export const SENTIMENT_URL="https://api.alternative.me/fng/?limit=1";
export function parseSearchTrends(xml:string,region:string,now=Date.now()):SearchTrend[]{if(!/<rss/i.test(xml))throw Error("Invalid search feed");return (xml.match(/<item[\s>][\s\S]*?<\/item>/gi)||[]).slice(0,100).map(x=>{const query=tag(x,"title").slice(0,200);return {query,region,url:"https://trends.google.com/trending?geo="+region,publishedAt:Date.parse(tag(x,"pubDate")),assets:assetsIn(query),traffic:tag(x,"ht:approx_traffic").slice(0,30)};}).filter(x=>x.assets.length&&Number.isFinite(x.publishedAt)&&x.publishedAt<=now&&now-x.publishedAt<48*3600000);}
export function parseSentiment(raw:any,now=Date.now()){const d=raw?.data?.[0],value=Number(d?.value),publishedAt=Number(d?.timestamp)*1000;if(!d||!Number.isFinite(value)||value<0||value>100||!Number.isFinite(publishedAt)||publishedAt>now||now-publishedAt>48*3600000)throw Error("Stale or invalid sentiment");return {value,label:String(d.value_classification||"").slice(0,40),publishedAt,checkedAt:now};}
export async function fetchOnline(previous?:OnlineContext):Promise<OnlineContext>{
 const now=Date.now();
 const searchPromise=Promise.all(SEARCH_FEEDS.map(async f=>{
  const name="Google Trends "+f.region;
  try{return {items:parseSearchTrends(await publicText(f.url,"application/rss+xml"),f.region,now),health:{name,url:f.url,ok:true,checkedAt:now,message:"Regional trending searches checked"} as SourceStatus};}
  catch{return {items:previous?.searches.filter(x=>x.region===f.region)||[],health:{name,url:f.url,ok:false,checkedAt:now,message:"Search feed unavailable"} as SourceStatus};}
 }));
 const sentimentPromise=(async()=>{
  const health:SourceStatus={name:"Alternative.me",url:"https://alternative.me/crypto/fear-and-greed-index/",ok:false,checkedAt:now,message:"Sentiment unavailable"};
  try{return {value:parseSentiment(JSON.parse(await publicText(SENTIMENT_URL,"application/json")),now),health:{...health,ok:true,message:"Daily Bitcoin sentiment; not a coin-specific prediction"}};}
  catch{return {value:previous?.sentiment||null,health};}
 })();
 const [searches,sentiment]=await Promise.all([searchPromise,sentimentPromise]);
 return {checkedAt:now,searches:searches.flatMap(x=>x.items),searchSources:searches.map(x=>x.health),sentiment:sentiment.value,sentimentHealth:sentiment.health};
}
