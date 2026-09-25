// Specific names avoid interpreting everyday words such as "near" as tokens.
const aliases:Record<string,string>={BTC:"bitcoin|btc",ETH:"ethereum|ether|eth",SOL:"solana|sol",BNB:"bnb|binance coin",XRP:"xrp",DOGE:"dogecoin|doge",ADA:"cardano|ada",TRX:"tron|trx",LINK:"chainlink",AVAX:"avalanche|avax",SUI:"sui",TON:"toncoin",BCH:"bitcoin cash|bch",LTC:"litecoin|ltc",DOT:"polkadot",XLM:"stellar|xlm",HBAR:"hedera|hbar",NEAR:"near protocol",UNI:"uniswap",APT:"aptos|apt",ETC:"ethereum classic|etc coin",FIL:"filecoin|fil",ATOM:"cosmos|atom token",AAVE:"aave",ZEC:"zcash|zec",XMR:"monero|xmr",ICP:"internet computer|icp",ARB:"arbitrum|arb",OP:"optimism network|op token",INJ:"injective|inj",TIA:"celestia|tia",ALGO:"algorand|algo",VET:"vechain|vet",TAO:"bittensor|tao",RENDER:"render network|render token",FET:"fetch\\.ai|fet"};
export function assetsIn(text:string){return Object.entries(aliases).filter(([,pattern])=>new RegExp("\\b(?:"+pattern+")\\b","i").test(text)).map(([symbol])=>symbol).filter(s=>!(s==="BTC"&&/bitcoin cash/i.test(text)&&!/\bbtc\b/i.test(text))&&!(s==="ETH"&&/ethereum classic/i.test(text)&&!/\beth\b/i.test(text)));}
export function headlineContext(title:string){
 const uncertain=/\?|\b(?:may|might|could|rumou?r|unconfirmed|alleged|prediction|predicts?|expects?|forecast|denies?|denied|not|no|fake|debunked|if)\b/i.test(title);
 const security=/\b(?:hack(?:ed)?|exploit(?:ed)?|breach|outage|halt(?:s|ed)?|bankrupt(?:cy)?|insolven\w*|depeg\w*)\b/i.test(title);
 const macro=/\b(?:federal funds|interest rates?|fomc|rate cut|rate hike|inflation|cpi|payrolls)\b/i.test(title);
 const flow=/\b(?:inflows?|outflows?|buy(?:s|ing)?|bought|sell(?:s|ing)?|sold)\b/i.test(title);
 const adoption=/\b(?:approv\w*|reject\w*|adopt\w*|launch\w*|ban(?:s|ned)?|delist\w*)\b/i.test(title);
 const positive=/\b(?:inflows?|approv(?:es?|ed|al)|adopt(?:s|ed|ion)|bought|buys|launch(?:es|ed)?)\b/i.test(title);
 const negative=security||/\b(?:outflows?|reject(?:s|ed|ion)|sold|sells|ban(?:s|ned)?|delist(?:s|ed|ing)?)\b/i.test(title);
 return {uncertain,tone:(!uncertain&&positive!==negative?(positive?"POSITIVE":"NEGATIVE"):"NEUTRAL") as "POSITIVE"|"NEGATIVE"|"NEUTRAL",topic:(security?"SECURITY":macro?"MACRO":flow?"FLOW":adoption?"ADOPTION":"OTHER") as "SECURITY"|"MACRO"|"FLOW"|"ADOPTION"|"OTHER",severity:(security||macro?"HIGH":"NORMAL") as "HIGH"|"NORMAL"};
}
