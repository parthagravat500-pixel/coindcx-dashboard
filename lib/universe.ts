// Explicit cryptocurrency admission keeps metals, equities, indices and newly
// listed instruments out until their underlying asset has been reviewed.
const cryptoAssets=new Set([
 "BTC","ETH","BNB","XRP","SOL","DOGE","ADA","TRX","LINK","AVAX",
 "SUI","TON","BCH","LTC","DOT","XLM","HBAR","NEAR","UNI","APT",
 "ETC","FIL","ATOM","AAVE","ZEC","XMR","ICP","ARB","OP","INJ",
 "TIA","ALGO","VET","TAO","RENDER","FET"
]);
export function isEligibleCryptoPair(pair:string){
 return /^B-[A-Z0-9]+_USDT$/.test(pair)&&cryptoAssets.has(pair.slice(2,-5));
}
