import test from 'node:test';
import assert from 'node:assert/strict';
import {mountedAt} from '../engine/launch.mjs';
import {spawn} from 'node:child_process';
import {once} from 'node:events';
import net from 'node:net';

test('a directory name alone does not establish persistent storage',()=>{
  assert.equal(mountedAt('1 0 0:1 / / rw - overlay overlay rw','/var/data'),false);
  assert.equal(mountedAt('1 0 0:1 / / rw - overlay overlay rw','/'),false);
});
test('persistent startup requires the exact mounted data path',()=>{
  const mounted='1 0 0:1 / / rw - overlay overlay rw\n42 1 8:1 / /var/data rw - ext4 /dev/disk rw';
  assert.equal(mountedAt(mounted,'/var/data'),true);
  assert.equal(mountedAt(mounted,'/var/dat'),false);
  assert.equal(mountedAt(mounted,'/var/data/child'),false);
});

test('setup hosting cannot start the engine or accept trading actions', {timeout:10000}, async()=>{
  const socket=net.createServer();socket.listen(0,'127.0.0.1');await once(socket,'listening');const port=socket.address().port;await new Promise(r=>socket.close(r));
  const child=spawn(process.execPath,['--experimental-strip-types','engine/launch.mjs'],{cwd:new URL('..',import.meta.url),env:{...process.env,RENDER:'true',PORT:String(port),DATA_DIR:'/tmp/dcx-not-a-persistent-mount'},stdio:['ignore','pipe','pipe']});
  try {
    await new Promise((resolve,reject)=>{const timer=setTimeout(()=>reject(Error('Setup server did not start')),5000);child.stdout.on('data',b=>{if(b.toString().includes('setup service listening')){clearTimeout(timer);resolve();}});child.once('exit',c=>{clearTimeout(timer);reject(Error('Setup exited '+c));});});
    const health=await(await fetch('http://127.0.0.1:'+port+'/healthz')).json();assert.equal(health.mode,'SETUP');assert.equal(health.ready,false);assert.equal(health.tradingEnabled,false);
    const action=await fetch('http://127.0.0.1:'+port+'/v1/action',{method:'POST',body:JSON.stringify({action:'start'})});assert.equal(action.status,409);
  } finally {if(child.exitCode===null){const ended=once(child,'exit');child.kill('SIGTERM');await ended;}}
});
