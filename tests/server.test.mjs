import test from 'node:test';
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {once} from 'node:events';
import {mkdtemp,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import net from 'node:net';
import {randomBytes} from 'node:crypto';

test('worker authenticates, persists settings across restart, exports no credentials, and rejects live entry', {timeout:20000}, async()=>{
 const directory=await mkdtemp(join(tmpdir(),'dcx-worker-test-'));
 const socket=net.createServer();socket.listen(0,'127.0.0.1');await once(socket,'listening');const port=socket.address().port;await new Promise(r=>socket.close(r));
 const token=randomBytes(32).toString('hex'), encryption=randomBytes(32).toString('hex');let child;
 const launch=async()=>{
  child=spawn(process.execPath,['--experimental-strip-types','engine/server.mjs'],{cwd:new URL('..',import.meta.url),env:{...process.env,PORT:String(port),DATA_DIR:directory,ENGINE_TOKEN:token,APP_ENCRYPTION_KEY:encryption,DISABLE_SCAN:'true',PERSISTENT_STORAGE:'true',ALWAYS_ON:'true'},stdio:['ignore','pipe','pipe']});
  await new Promise((resolve,reject)=>{const timer=setTimeout(()=>reject(Error('Worker did not start')),6000);child.stdout.on('data',b=>{if(b.toString().includes('listening')){clearTimeout(timer);resolve();}});child.once('exit',code=>{clearTimeout(timer);reject(Error('Worker exited '+code));});});
 };
 const stop=async()=>{if(child&&child.exitCode===null){const ended=once(child,'exit');child.kill('SIGTERM');await ended;}};
 const call=(path,body,auth=true)=>fetch('http://127.0.0.1:'+port+path,{method:body?'POST':'GET',headers:{...(auth?{Authorization:'Bearer '+token}:{}),'Content-Type':'application/json'},body:body?JSON.stringify(body):undefined});
 try{
  await launch();
  assert.equal((await call('/healthz',null,false)).status,200);
  assert.equal((await call('/v1/state',null,false)).status,401);
  let r=await call('/v1/action',{action:'settings',settings:{riskPct:.1,paperCapital:750}});assert.equal(r.status,200);assert.equal((await r.json()).state.portfolio.balance,750);
  r=await call('/v1/action',{action:'start'});assert.equal((await r.json()).state.settings.running,true);
  await stop();await launch();
  const restored=await(await call('/v1/state')).json();assert.equal(restored.state.settings.riskPct,.1);assert.equal(restored.state.settings.running,true);assert.equal(restored.state.portfolio.balance,750);assert.equal(restored.liveExecution.enabled,false);
  assert.equal((await call('/v1/action',{action:'enable-live'})).status,409);
  assert.equal((await call('/v1/action',{action:'settings',settings:{riskPct:10}})).status,409);
  const exported=await(await call('/v1/export')).text();assert.ok(!exported.includes(token));assert.ok(!exported.includes(encryption));assert.ok(!exported.includes('secret'));
  const paused=await(await call('/v1/action',{action:'pause'})).json();assert.equal(paused.state.settings.running,false);
 }finally{await stop();await rm(directory,{recursive:true,force:true});}
});
