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
 state.research.ai_reviews[0].triage_summary={pending:0,dismissed:1};
 state.research.ai_reviews[0].result.reviews[0].triage={decision:'dismissed',reason:'<script>private review</script>',evidence:'Test evidence only',reviewed:1};
 vm.runInContext('renderResearchStatus();openPrivateAI()',context);
 assert.match(nodes.get('privateAIStatus').textContent,/0 awaiting validation · 1 dismissed/);
 vm.runInContext('openAIHypothesisReview(state.research.ai_reviews[0],0,state.research.ai_reviews[0].result.reviews[0])',context);
 assert(nodes.get('detail').open);
 state.gitlab={configured:true,enabled:0,expires:Date.now()/1000+3600,retry_available:true,result:{evidence:[]}};
 vm.runInContext('openGitlab()',context);
 assert(nodes.get('detailContent').children.some(n=>n.textContent==='Retry saved connection'));
 state.program_queue.rows=[{name:'<script>unsafe</script>',policy:'https://hackerone.com/example',status:'Skipped: permission needed',approved_urls:0}];
 state.program_queue.attempts=[{name:'Fixture',outcome:'no_observation',started:1,observations:0}];
 vm.runInContext('openProgramQueue()',context);
 assert(nodes.get('openProgramQueue').onclick);
 assert(nodes.get('detail').open);
 const listed=(name,category,rank)=>({name,url:'https://example.com/'+name,source:'fixture',maximum:100,currency:'USD',available:true,stale:false,stage:'queue',details:{requirements:[],scope_count:1},readiness:{category,rank,label:name+' readiness',explanation:'Fixture coverage only',sources:[],configured:category==='configured',active:category==='configured'}});
 state.workflow.programs=[listed('Firmware','specialist',3),listed('Configured','configured',0),listed('NeedsReview','unknown',2)];
 nodes.get('currency').value='all';nodes.get('readiness').value='all';
 vm.runInContext('currentStage="queue";renderWorklist()',context);
 assert.equal(vm.runInContext('workflowRows("queue")[0].data.name',context),'Configured');
 nodes.get('readiness').value='specialist';nodes.get('readiness').onchange();
 assert.equal(nodes.get('listCount').textContent,'1 item');
 vm.runInContext('openProgram(state.workflow.programs[0]);openAccess()',context);
 const descendants=n=>[n,...(n.children||[]).filter(x=>x&&typeof x==='object').flatMap(descendants)];
 state.gitlab={configured:true,connected:true,enabled:1,expires:Date.now()/1000+3600,project:'fixture-a/private-a',result:{evidence:[]},peer:{configured:false}};
 vm.runInContext('openGitlab()',context);
 const peerForm=descendants(nodes.get('detailContent')).find(n=>n['aria-label']==='Connect second GitLab account');
 assert(peerForm);
 assert.equal(descendants(peerForm).filter(n=>n.type==='password'&&n.required).length,1);
 assert(descendants(peerForm).some(n=>n.textContent==='Connect second account'));
 vm.runInContext('openAccess()',context);
 const mode=descendants(nodes.get('detailContent')).find(n=>n.tagName==='select'&&n.children.some(o=>o.value==='two_account'));
 assert(mode);mode.value='two_account';mode.onchange();
 assert.equal(descendants(nodes.get('detailContent')).find(n=>n.tagName==='fieldset').hidden,false);
 assert.equal(descendants(nodes.get('detailContent')).filter(n=>n.type==='password'&&n.required).length,2);
 assert(nodes.get('openMethods').onclick);nodes.get('openMethods').onclick();
 assert.equal(nodes.get('detailContent').children[0].textContent,'Testing methods and actual coverage');
 console.log('Dashboard DOM smoke test passed: valid IDs, initial render, private review rendering, text-only analysis.');
});
