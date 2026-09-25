import http from 'node:http';
import {readFileSync,statSync} from 'node:fs';
import {resolve} from 'node:path';

export function mountedAt(mountInfo, directory) {
  const target=resolve(directory);
  if(target==='/') return false;
  return mountInfo.split('\n').some(line=>{
    const fields=line.split(' ');
    return fields.length>6 && fields[4].replace(/\\([0-7]{3})/g,(_,n)=>String.fromCharCode(parseInt(n,8)))===target;
  });
}

function persistentDiskIsMounted(directory) {
  try {return statSync(directory).isDirectory() && mountedAt(readFileSync('/proc/self/mountinfo','utf8'),directory);}
  catch {return false;}
}

export async function launch() {
  const directory=process.env.DATA_DIR||'/var/data';
  if(process.env.RENDER && !persistentDiskIsMounted(directory)) {
    // Provisioning mode cannot import the engine, create orders, or accept account credentials.
    const server=http.createServer((req,res)=>{
      const health=req.url==='/'||req.url==='/healthz';
      res.writeHead(health?200:409,{'Content-Type':'application/json','Cache-Control':'no-store'});
      res.end(JSON.stringify({ok:health,ready:false,mode:'SETUP',tradingEnabled:false,message:'Persistent disk is not attached. Continuous paper operation has not started.'}));
    });
    server.listen(Number(process.env.PORT)||10000,'0.0.0.0',()=>console.log('DCX Pilot setup service listening; persistent disk pending; no trading'));
    process.on('SIGTERM',()=>server.close(()=>process.exit(0)));
    process.on('SIGINT',()=>server.close(()=>process.exit(0)));
    return;
  }
  if(process.env.RENDER) process.env.PERSISTENT_STORAGE='true';
  await import('./server.mjs');
}

if(process.argv[1] && import.meta.url===new URL('file://'+resolve(process.argv[1])).href) await launch();
