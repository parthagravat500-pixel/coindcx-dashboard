// DOM-unit smoke test, not a browser or a visual layout test.
'use strict';
const fs=require('fs'),vm=require('vm'),assert=require('assert');
class Node {
 constructor(tag='div'){this.tagName=tag;this.children=[];this.value='';this.textContent='';this.dataset={};this.style={};}
 append(...items){this.children.push(...items);}
 appendChild(item){this.append(item);return item;}
 replaceChildren(...items){this.children=items;}
 setAttribute(k,v){this[k]=v;}
 addEventListener(){}
 querySelectorAll(){return [];}
 showModal(){this.open=true;}
 close(){this.open=false;}
 get innerHTML(){throw Error('HTML injection is not permitted in this smoke test');}
 set innerHTML(value){throw Error('HTML injection is not permitted: '+value);}
}
const html=fs.readFileSync('index.html','utf8'),nodes=new Map([...html.matchAll(/id="([^"]+)"/g)].map(m=>[m[1],new Node()]));
const document={getElementById:id=>{if(!nodes.has(id))throw Error('Missing DOM id '+id);return nodes.get(id);},createElement:tag=>new Node(tag),createTextNode:text=>String(text),querySelectorAll:()=>[]};
const state=JSON.parse(fs.readFileSync(0,'utf8'));
const context=vm.createContext({document,URL,Date,console,setInterval:()=>{},confirm:()=>false,fetch:async()=>({ok:true,json:async()=>state})});
vm.runInContext(fs.readFileSync('ui.js','utf8'),context);
setImmediate(()=>{
 assert.equal(nodes.get('message').textContent,'');
 assert.match(nodes.get('privateAIStatus').textContent,/Disabled|Paused/);
 state.research.ai_enabled=true;state.research.identity_ready=true;state.paused=false;
 state.research.ai_reviews=[{run:'1',revision:'a'.repeat(40),state:'reviewed',started:1,updated:2,url:'https://github.com/example/repo/actions/runs/1',result:{model:'test',calibration_passed:true,limitation:'Unverified',reviews:[{file:'app.py',line:1,status:'Unverified',analysis:'<img src=x onerror=alert(1)>'}]}}];
 vm.runInContext('renderResearchStatus();openPrivateAI()',context);
 assert.match(nodes.get('privateAIStatus').textContent,/Review received/);
 assert(nodes.get('detail').open);
 state.program_queue.rows=[{name:'<script>unsafe</script>',policy:'https://hackerone.com/example',status:'Skipped: permission needed',approved_urls:0}];
 state.program_queue.attempts=[{name:'Fixture',outcome:'no_observation',started:1,observations:0}];
 vm.runInContext('openProgramQueue()',context);
 assert(nodes.get('openProgramQueue').onclick);
 assert(nodes.get('detail').open);
 console.log('Dashboard DOM smoke test passed: valid IDs, initial render, private review rendering, text-only analysis.');
});
