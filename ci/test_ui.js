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
const requests=[];
const context=vm.createContext({document,URL,URLSearchParams,location:{hash:''},Date,console,setInterval:()=>{},confirm:()=>false,fetch:async(path,options={})=>{requests.push({path,method:options.method||'GET'});return {ok:true,json:async()=>state};}});
vm.runInContext(fs.readFileSync('ui.js','utf8'),context);
setImmediate(async()=>{
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
 state.workflow.policy_evidence={unavailable_entries:0,records:[{program:'Unlisted fixture',checked_at:'2026-09-26T00:00:00Z',scope_complete:true,in_scope_assets:['public.example.com'],excluded_assets:['private.example.com'],scope_conditions:[],exclusions:[],unresolved:['Permission unverified'],accounts:'Owned test accounts only',automation:'Manual validation required',explicit_requests_per_second:null,note:'<img src=x onerror=alert(1)>',sources:['https://example.com/policy']}]};
 vm.runInContext('renderPolicyEvidence()',context);
 assert.match(nodes.get('policyEvidenceStatus').textContent,/1 saved policy reviews/);
 assert(descendants(nodes.get('policyEvidenceList')).some(n=>n.textContent==='Unlisted fixture'),'Evidence must be visible without a matching directory card.');
 nodes.get('policyEvidenceList').children[0].onclick();
 assert(descendants(nodes.get('detailContent')).some(n=>n.textContent==='public.example.com'));
 assert(descendants(nodes.get('detailContent')).some(n=>n.textContent==='Owned test accounts only'));
 assert(descendants(nodes.get('detailContent')).some(n=>n.textContent==='Not stated / unknown'));
 assert(descendants(nodes.get('detailContent')).some(n=>n.textContent==='<img src=x onerror=alert(1)>'),'Untrusted policy text must remain text.');
 assert(!descendants(nodes.get('detailContent')).some(n=>n.tagName==='form'),'Viewing evidence must not create an activation form.');
 state.workflow.policy_evidence.records[0].research_plan={selected:true,status:'needs_user',updated_at:'2026-09-26T06:00:00Z',summary:'Account step pending',goal:'Owned fixture only',completed:['Local preparation'],user_actions:['Secure sign-in needed'],blockers:['No owned session'],planned_checks:['Not run'],validation:'Synthetic fixtures only',result:'No live finding'};
 vm.runInContext('renderResearchFocus()',context);
 assert.equal(nodes.get('researchFocusCard').hidden,false);
 assert.match(nodes.get('researchFocusSummary').textContent,/Waiting for your account step/);
 assert(descendants(nodes.get('researchFocusActions')).some(n=>n.textContent==='Secure sign-in needed'));
 nodes.get('openResearchFocus').onclick();
 assert(descendants(nodes.get('detailContent')).some(n=>n.textContent==='No live finding'));
 assert(!descendants(nodes.get('detailContent')).some(n=>n.tagName==='form'),'Research preparation must stay read-only.');
 state.workflow.policy_evidence.records[0].research_plan.connection={status:'provider_approval_required',summary:'<script>Connection requires approval</script>',manual_alternative:'Manual browser review is separate.',checked_at:'2026-09-26T07:00:00Z',requirements:['Provider approval is not verified.'],sources:['https://example.com/docs'],connected:false};
 vm.runInContext('renderResearchFocus()',context);
 assert.equal(nodes.get('researchFocusConnection').hidden,false);
 assert.match(nodes.get('researchFocusConnection').textContent,/needs provider approval/);
 nodes.get('openResearchFocus').onclick();
 assert(descendants(nodes.get('detailContent')).some(n=>n.textContent==='<script>Connection requires approval</script>'));
 assert(descendants(nodes.get('detailContent')).some(n=>n.textContent==='Manual browser review is separate.'));
 assert(!descendants(nodes.get('detailContent')).some(n=>n.tagName==='form'),'Connection notes must not collect credentials or activate tests.');
 nodes.get('openPolicyReviews').onclick();
 assert.equal(nodes.get('detailContent').children[0].textContent,'Program policy reviews');
 state.workflow.policy_evidence={unavailable_entries:1,records:[]};
 vm.runInContext('renderPolicyEvidence();openPolicyReviews()',context);
 assert.match(nodes.get('policyEvidenceStatus').textContent,/Some evidence could not be loaded/);
 assert.equal(nodes.get('policyEvidenceList').children.length,0);
 assert.equal(nodes.get('researchFocusCard').hidden,true);
 assert(requests.every(r=>r.method==='GET'),'Reading policy evidence must never submit a request.');
 const oldQueue=state.program_queue,oldPrograms=state.workflow.programs,oldEvidence=state.workflow.policy_evidence;
 state.workflow.programs=Array.from({length:304},(_,i)=>listed('Fixture '+i,'unknown',2));
 state.workflow.policy_evidence={records:Array.from({length:9},()=>({program:'Reviewed fixture'})),unavailable_entries:0};
 state.program_queue={paused:false,healthy:true,saved_targets:0,eligible_targets:0,due_targets:0,completed:1,confirmed_payable:0};
 vm.runInContext('renderProgressSummary()',context);
 assert.equal(nodes.get('reviewedPolicyCount').textContent,9);
 assert.equal(nodes.get('limitedCheckCount').textContent,1);
 assert.equal(nodes.get('confirmedBugCount').textContent,0);
 assert.match(nodes.get('directorySummary').textContent,/304 programs listed/);
 assert.match(nodes.get('nextTitle').textContent,/No websites approved/);
 assert.match(nodes.get('plainSummary').textContent,/No confirmed bounty bug yet/);
 state.program_queue={...state.program_queue,saved_targets:3,expired_targets:1,disabled_targets:1,directory_blocked_targets:1};
 vm.runInContext('renderProgressSummary()',context);
 assert.match(nodes.get('nextTitle').textContent,/checks are blocked/);
 assert.match(nodes.get('nextText').textContent,/1 permissions expired/);
 state.program_queue={...state.program_queue,eligible_targets:1,next_due:Math.floor(Date.now()/1000)+3600};
 vm.runInContext('renderProgressSummary()',context);
 assert.match(nodes.get('nextTitle').textContent,/Waiting for the next scheduled check/);
 state.program_queue.healthy=false;vm.runInContext('renderProgressSummary()',context);
 assert.match(nodes.get('nextTitle').textContent,/worker needs attention/);
 state.program_queue.paused=true;vm.runInContext('renderProgressSummary()',context);
 assert.match(nodes.get('nextTitle').textContent,/checks are paused/);
 state.program_queue=undefined;vm.runInContext('renderProgressSummary()',context);
 assert.equal(nodes.get('limitedCheckCount').textContent,'—');
 assert.equal(nodes.get('confirmedBugCount').textContent,'—');
 assert.match(nodes.get('nextTitle').textContent,/status is unavailable/);
 assert.match(nodes.get('status').textContent,/Status unavailable/);
 state.program_queue=oldQueue;state.workflow.programs=oldPrograms;state.workflow.policy_evidence=oldEvidence;
 state.gitlab={configured:true,connected:true,enabled:1,expires:Date.now()/1000+3600,project:'fixture-a/private-a',result:{evidence:[]},peer:{configured:false}};
 vm.runInContext('openGitlab()',context);
 const peerForm=descendants(nodes.get('detailContent')).find(n=>n['aria-label']==='Connect second GitLab account');
 assert(peerForm);
 assert.equal(descendants(peerForm).filter(n=>n.type==='password'&&n.required).length,1);
 assert(descendants(peerForm).some(n=>n.textContent==='Connect second account'));
 const marker='scopeguard_'+'a'.repeat(32),setupHash='#gitlab-peer?project=fixture-b%2Fprivate-b&marker='+marker;
 context.location.hash=setupHash;
 vm.runInContext('openGitlabSetupFromLink()',context);
 assert.equal(nodes.get('detailContent').children[0].textContent,'Finish your GitLab connection');
 const setupForm=descendants(nodes.get('detailContent')).find(n=>n['aria-label']==='Connect second GitLab account');
 assert(descendants(setupForm).some(n=>n.value==='https://gitlab.com/fixture-b/private-b'));
 assert(descendants(setupForm).some(n=>n.value===marker));
 assert.equal(descendants(setupForm).find(n=>n.type==='password').value,'');
 assert(!descendants(setupForm).find(n=>n.type==='checkbox').checked);
 assert.match(descendants(setupForm).find(n=>n.tagName==='textarea').value,/fixture-a\/private-a and fixture-b\/private-b/);
 assert(requests.every(r=>r.method==='GET'),'Opening a setup link must never submit a connection.');
 vm.runInContext('openGitlabSetupFromLink()',context);
 assert(descendants(nodes.get('detailContent')).includes(setupForm),'Refresh must not replace an in-progress setup form.');
 for(const badHash of [setupHash+'&token=secret',setupHash+'&project=other%2Fproject',setupHash.replace('fixture-b%2Fprivate-b','https%3A%2F%2Fevil.example%2Fx'),setupHash.replace(marker,'wrong')]){
  assert.equal(vm.runInContext('parseGitlabSetupLink('+JSON.stringify(badHash)+')',context),null);
 }
 state.gitlab.peer={configured:true,project:'saved/peer',expires:Date.now()/1000+3600,result:{evidence:[]}};
 vm.runInContext('gitlabSetupOpened=false;gitlabSetupDraft=null;openGitlabSetupFromLink()',context);
 assert.equal(nodes.get('detailContent').children[0].textContent,'Your private GitLab project');
 assert(!descendants(nodes.get('detailContent')).some(n=>n.value==='https://gitlab.com/fixture-b/private-b'),'A setup link must not override an existing connection.');
 state.gitlab.peer={configured:true,connected:false,enabled:0,project:'fixture-b/private-b',expires:Date.now()/1000+3600,result:{evidence:[{step:'Verify account B read-only token',status:401}]}};
 vm.runInContext('gitlabSetupOpened=false;gitlabSetupDraft=null;openGitlabSetupFromLink()',context);
 assert.equal(nodes.get('detailContent').children[0].textContent,'Finish your GitLab connection');
 assert(descendants(nodes.get('detailContent')).some(n=>n.value===marker),'A failed connection to the same project can use its prepared details.');
 assert(descendants(nodes.get('detailContent')).some(n=>String(n.textContent).includes('second account token (HTTP 401)')));
 assert.equal(descendants(nodes.get('detailContent')).find(n=>n.type==='password').value,'');
 assert(!descendants(nodes.get('detailContent')).find(n=>n.type==='checkbox').checked);
 state.gitlab.peer.connected=true;state.gitlab.peer.enabled=1;
 vm.runInContext('gitlabSetupOpened=false;gitlabSetupDraft=null;openGitlabSetupFromLink()',context);
 assert.equal(nodes.get('detailContent').children[0].textContent,'Your private GitLab project');
 assert(!descendants(nodes.get('detailContent')).some(n=>n.value===marker),'An active connection must ignore prepared replacement details.');
 assert(requests.every(r=>r.method==='GET'),'Repair links must not submit or restart a check.');
 vm.runInContext('openAccess()',context);
 const mode=descendants(nodes.get('detailContent')).find(n=>n.tagName==='select'&&n.children.some(o=>o.value==='two_account'));
 assert(mode);mode.value='two_account';mode.onchange();
 assert.equal(descendants(nodes.get('detailContent')).find(n=>n.tagName==='fieldset').hidden,false);
 assert.equal(descendants(nodes.get('detailContent')).filter(n=>n.type==='password'&&n.required).length,2);
 assert(nodes.get('openMethods').onclick);nodes.get('openMethods').onclick();
 assert.equal(nodes.get('detailContent').children[0].textContent,'Testing methods and actual coverage');
 context.fetch=async()=>({ok:false});
 await assert.rejects(vm.runInContext('refresh()',context),/Connection or login failed/);
 assert.match(nodes.get('summaryUpdated').textContent,/last successful update/);
 assert.match(nodes.get('status').textContent,/Connection needs attention/);
 console.log('Dashboard DOM smoke test passed: truthful progress, queue blockers, stale data, valid IDs and text-only policy/review rendering.');
});
