'use strict';
let state;
const $ = id => document.getElementById(id);
function el(tag, text, cls) { const n = document.createElement(tag); if(text !== undefined) n.textContent = text; if(cls) n.className = cls; return n; }
function button(text, action) { const b = el('button', text, 'secondary'); b.onclick = async () => {b.disabled=true;try{await action();}catch(e){$('message').textContent=e.message;}finally{b.disabled=false;}};return b; }
async function change(path, data) {
  const r = await fetch(path, {method:'POST', headers:{'Content-Type':'application/json','X-CSRF-Token':state.csrf}, body:JSON.stringify(data)});
  const result = await r.json(); if(!r.ok) throw Error(result.error || 'Request failed'); $('message').textContent = ''; await refresh();
}
function renderLegacy() {
  $('status').textContent = state.paused ? '● Checks paused' : '● Checks enabled';
  $('pause').textContent = state.paused ? 'Resume website checks' : 'Pause website checks';
  $('targetCount').textContent = state.targets.length;
  $('findingCount').textContent = state.findings.length;
  $('acceptedCount').textContent = state.findings.filter(f=>f.feedback==='accepted').length;
  const supervisor=state.supervisor || {};
  $('supervisorRules').textContent=supervisor.rules_status || 'Loading review status';
  $('supervisorAI').textContent='AI: '+(supervisor.ai_status || 'Not connected');
  $('supervisorDelivery').textContent=state.reporting?.connected?'HackerOne connected. Only independently validated reports can be sent.':'Reporting account not connected. Open Finish setup.';
  $('supervisorRepeat').textContent=supervisor.repeat_policy || '';
  $('supervisorLimit').textContent=supervisor.limitation || '';
  $('targets').replaceChildren();
  if(!state.targets.length) $('targets').append(el('p','No targets yet. Add one using its written program scope.','empty'));
  state.targets.forEach(t=>{
    const card=el('article',undefined,'item'); card.append(el('strong',t.name),el('small',t.url));
    const expired=t.expires*1000<Date.now(); card.append(el('span',expired?'Authorization expired':t.enabled?'Approved':'Disabled','tag'));
    card.append(el('small',t.state),el('small','Review by '+new Date(t.expires*1000).toLocaleString()+' · Every '+t.interval/3600+' hours'));
    const policy=el('a','Read program policy');policy.href=t.policy;policy.target='_blank';policy.rel='noopener noreferrer';card.append(policy,el('br'));
    card.append(button(t.enabled?'Disable target':'Enable target',()=>change('/api/target-state',{id:t.id,enabled:!t.enabled})));
    card.append(button('Renew approval 24h',async()=>{if(confirm('Have you re-read the current policy and confirmed this exact URL, automated checks, exclusions and rate limits are still permitted?')) await change('/api/renew',{id:t.id,reviewed:true});}));
    $('targets').append(card);
  });
  $('findings').replaceChildren();
  if(!state.findings.length) $('findings').append(el('p','No observations yet. An empty queue does not mean a website is secure.','empty'));
  state.findings.forEach(f=>{
    const card=el('article',undefined,'item'); card.append(el('span','INFORMATIONAL · IMPACT UNVERIFIED','tag'),el('strong',f.title));
    card.append(el('small',state.targets.find(t=>t.id===f.target)?.url||''));
    card.append(el('small',JSON.parse(f.evidence).note),el('small','Review priority '+f.review_priority+' · Last observed '+new Date(f.last_seen*1000).toLocaleString()));
    if(f.supervisor){
      const review=f.supervisor;
      card.append(el('strong',review.status),el('small','Repeat observations: '+review.repeat_count+'/3'),el('small',review.reason));
      if(!review.current_observation)card.append(el('small','Not seen in the latest successful check.'));
      card.append(el('small','Reporting channel: '+review.channel.name));
      if(review.ai_review)card.append(el('small','AI advisory ('+review.ai_review.status+'): '+review.ai_review.note));
    }
    const select=el('select');select.setAttribute('aria-label','Review outcome for '+f.title);
    ['unreviewed','validated','accepted','duplicate','false_positive','ineligible'].forEach(v=>{const option=el('option',v.replaceAll('_',' '));option.value=v;option.selected=f.feedback===v;select.append(option);});
    select.onchange=()=>change('/api/feedback',{id:f.id,feedback:select.value}).catch(e=>$('message').textContent=e.message);
    card.append(select);const link=el('a','Download draft evidence report');link.href='/report/'+f.id;link.download='scopeguard-'+f.id+'.md';card.append(link);$('findings').append(card);
  });
  $('events').replaceChildren(...state.events.map(e=>el('div',new Date(e.at*1000).toLocaleString()+' · '+e.message)));
}
async function refresh(){const r=await fetch('/api/state');if(!r.ok)throw Error('Connection or login failed. Refresh to sign in.');state=await r.json();render();}
$('pause').onclick=()=>{if(state)change('/api/pause',{paused:!state.paused}).catch(e=>$('message').textContent=e.message);};
$('targetForm').onsubmit=async e=>{e.preventDefault();const form=e.target;const f=new FormData(form);const b=form.querySelector('button');b.disabled=true;try{await change('/api/targets',{name:f.get('name'),url:f.get('url'),policy:f.get('policy'),rules:f.get('rules'),interval:Number(f.get('hours'))*3600,expires:Math.floor(Date.now()/1000)+Number(f.get('days'))*86400-5,authorized:f.has('authorized'),automation_allowed:f.has('automation_allowed'),cors:f.has('cors')});form.reset();}catch(err){$('message').textContent=err.message;}finally{b.disabled=false;}};
refresh().catch(e=>$('message').textContent=e.message);


let currentStage='queue', visibleLimit=40;
const stages=[
  ['queue','Found websites','Your priority shortlist first, then highest published rewards compared in US dollars. These are possible maximum rewards, not expected earnings. New websites still need permission checks.'],
  ['review','Checking','Websites with permission and a scheduled check. They are checked at set times, not all at once.'],
  ['supervisor','Double-checking','Possible issues being checked again. They are not confirmed bugs yet.'],
  ['results','Results','Completed reviews. Open a result to see whether it still needs more proof.'],
  ['sent','Sent reports','Reports with a submission receipt. A receipt does not mean a bounty has been approved.']
];
function safeLink(text,url){const a=el('a',text);try{const u=new URL(url);if(u.protocol!=='https:')return el('span',text);a.href=u.href;a.target='_blank';a.rel='noopener noreferrer';return a;}catch{return el('span',text);}}
function money(p){if(p.maximum===null||!p.currency)return 'Reward not shown';return new Intl.NumberFormat('en-US',{style:'currency',currency:p.currency,maximumFractionDigits:0}).format(p.maximum)+' '+p.currency+' possible';}
function date(at){return at?new Date(at*1000).toLocaleString():'Not yet';}
function workflowRows(stage){const w=state.workflow||{programs:[],submissions:[]};const p=w.programs.filter(p=>p.stage!=='dismissed');
 if(stage==='queue')return p.sort((a,b)=>Number(b.stage==='review'&&b.available)-Number(a.stage==='review'&&a.available)).map(p=>({kind:'program',data:p}));
 if(stage==='review')return (gitlabActive()?[{kind:'gitlab',data:state.gitlab}]:[]).concat(state.targets.filter(t=>t.enabled&&t.expires*1000>Date.now()).map(t=>({kind:'target',data:t})).concat(capitalActive()?[{kind:'capital',data:{...state.capital_demo,name:'Capital.com demo watchlist'}}]:[]));
 if(stage==='supervisor')return state.findings.filter(f=>f.feedback==='unreviewed'&&(f.supervisor?.repeat_count||0)<3).map(f=>({kind:'finding',data:f}));
 if(stage==='results')return (state.gitlab?.checked&&state.gitlab?.result?.evidence?.length?[{kind:'gitlab',data:state.gitlab}]:[]).concat(state.findings.filter(f=>f.feedback!=='unreviewed'||(f.supervisor?.repeat_count||0)>=3).map(f=>({kind:'finding',data:f})).concat(state.capital_demo?.checked?[{kind:'capital',data:{...state.capital_demo,name:'Capital.com demo test result'}}]:[]));
 return w.submissions.map(s=>({kind:'submission',data:s}));
}
function modal(title){$('detailContent').replaceChildren(el('h2',title));if(!$('detail').open)$('detail').showModal();return $('detailContent');}
function facts(root,pairs){const dl=el('dl',undefined,'facts');pairs.forEach(([k,v])=>{dl.append(el('dt',k),el('dd',String(v)));});root.append(dl);}
function openProgram(p){const root=modal(p.name);root.append(el('span',money(p),'reward'),el('p','Listed by '+p.source+' · reward and availability need confirmation in the official policy.','muted'));
 facts(root,[['Directory status',!p.available?'Unavailable or removed':p.stale?'Cached / needs refresh':'Listed as open'],['Last directory observation',date(p.last_seen)],['Requirements',p.details.requirements.join('; ')||'Read the current program terms'],['Listed scope entries',p.details.scope_count],['Scan permission','Not verified. No target is created from this listing.']]);
 root.append(safeLink('Open official program policy ↗',p.url),el('br'),safeLink('View discovery source ↗',p.source_url));
 root.append(el('h3','What happens next'),el('p','Verify eligible web assets, exclusions, permitted automation and reporting route. A high maximum reward may apply to work this scanner cannot perform.'));
 if(p.policy_review){root.append(el('h3','Permission review'),el('p',p.policy_review.note),el('small','Reviewed '+p.policy_review.reviewed_on+'; check current terms before testing.'));p.policy_review.sources.forEach(u=>root.append(safeLink('Official source ↗',u),el('br')));}
 if(p.local_review)root.append(el('h3','Automatic review · local rules'),el('p',p.local_review.note));
 if(p.ai_note)root.append(el('h3','Earlier AI advisory'),el('p',p.ai_note));
 const actions=el('div',undefined,'controls');actions.append(button(p.stage==='review'?'Remove from shortlist':'Shortlist this company',async()=>{await change('/api/program-stage',{id:p.id,stage:p.stage==='review'?'queue':'review'});$('detail').close();}));
 actions.append(button('Hide this company',async()=>{await change('/api/program-stage',{id:p.id,stage:'dismissed'});$('detail').close();}));root.append(actions);
}
function openTarget(t){const root=modal(t.name);facts(root,[['Exact URL',t.url],['Current status',t.state],['Schedule','Every '+(t.interval<3600?t.interval/60+' minutes':t.interval/3600+' hours')],['Scope review expires',date(t.expires)],['Checks',!t.enabled?'Disabled':t.expires*1000<Date.now()?'Blocked: authorization expired':state.paused?'Scheduler paused':'Enabled']]);root.append(el('h3','Recorded authorization'),el('p',t.rules),safeLink('Read official policy ↗',t.policy));root.append(button(t.enabled?'Disable target':'Enable target',async()=>{await change('/api/target-state',{id:t.id,enabled:!t.enabled});$('detail').close();}));}
function openFinding(f){const root=modal(f.title),r=f.supervisor;root.append(el('span',r?.status||'Impact unproven','tag'));facts(root,[['Website',state.targets.find(t=>t.id===f.target)?.url||'Unknown'],['Observations',(r?.repeat_count||0)+'/3'],['Last observed',date(f.last_seen)],['Feedback',f.feedback],['Submission ready','No — security impact has not been demonstrated']]);root.append(el('p',r?.reason||f.impact),el('h3','Evidence'),el('p',JSON.parse(f.evidence).note));
 if(r){root.append(el('h3','Reporting route'),el('p',r.channel.name));if(r.channel.url)root.append(safeLink('Open reporting policy ↗',r.channel.url));if(r.ai_review)root.append(el('p','AI advisory: '+r.ai_review.note));}
 renderCasework(root,f);
 const a=el('a','Download evidence draft');a.href='/report/'+f.id;a.download='scopeguard-'+f.id+'.md';root.append(el('br'),a);
 const details=el('details');details.append(el('summary','Record a report already submitted'));const form=el('form');const info=el('p','Use only if you already submitted this finding through an accepted channel. This records your reference; it does not send or validate a report.','muted');const receipt=el('input');receipt.required=true;receipt.minLength=8;receipt.maxLength=1000;receipt.placeholder='Report ID, receipt or confirmation reference';receipt.setAttribute('aria-label','Submission receipt');const channel=el('select');['portal','email'].forEach(v=>{const o=el('option',v==='portal'?'Reporting portal':'Email');o.value=v;channel.append(o);});channel.setAttribute('aria-label','Actual submission channel');const label=el('label',undefined,'check'),check=el('input');check.type='checkbox';check.required=true;label.append(check,document.createTextNode('I actually submitted this report and have a receipt.'));const submit=el('button','Save submission record');submit.type='submit';form.append(info,channel,receipt,label,submit);form.onsubmit=async e=>{e.preventDefault();submit.disabled=true;try{await change('/api/submissions/record',{finding:f.id,channel:channel.value,receipt:receipt.value,actually_submitted:check.checked});$('detail').close();}catch(err){info.textContent=err.message;}finally{submit.disabled=false;}};details.append(form);root.append(details);
}
function renderCasework(root,f){
 const c=f.casework;if(!c)return;
 root.append(el('h3','Evidence review'),el('span',c.label,'tag'),el('p',c.explanation));
 const blockers=el('ul');c.blockers.forEach(t=>blockers.append(el('li',t)));root.append(blockers);
 root.append(el('h3','What would strengthen this finding?'));
 const questions=el('ul');c.questions.forEach(t=>questions.append(el('li',t)));root.append(questions);
 root.append(el('p',c.duplicate_status,'muted'));
 const details=el('details');details.append(el('summary',`Evidence notebook · ${c.completed_sections}/${c.total_sections} sections filled`));
 details.append(el('p','For an authorized researcher to record evidence. Use only your own test data. Remove passwords, tokens and personal details. Filling this form does not confirm a bug or send a report.','muted'));
 const form=el('form'),inputs={};
 Object.entries(c.fields).forEach(([key,title])=>{const label=el('label',title),input=el('textarea');input.rows=3;input.maxLength=1500;input.value=c.notes[key]||'';input.placeholder=key==='remediation'?c.suggested_fix:'Not recorded yet';label.append(input);form.append(label);inputs[key]=input;});
 const submit=el('button','Save evidence notes');submit.type='submit';const status=el('p');status.setAttribute('role','status');form.append(submit,status);
 form.onsubmit=async e=>{e.preventDefault();submit.disabled=true;try{await change('/api/evidence',{finding:f.id,notes:Object.fromEntries(Object.entries(inputs).map(([key,input])=>[key,input.value]))});openFinding(state.findings.find(x=>x.id===f.id));}catch(err){status.textContent=err.message;}finally{submit.disabled=false;}};
 details.append(form);root.append(details,el('h3','Suggested fix'),el('p',c.suggested_fix));
 c.sources.forEach(u=>root.append(safeLink('Report guidance ↗',u),el('br')));
}
function openSubmission(s){const f=state.findings.find(f=>f.id===s.finding),root=modal(f?.title||'Submission record');facts(root,[['Channel',s.channel],['Receipt / reference',s.receipt],['Recorded at',date(s.at)],['Evidence source',s.origin==='hackerone_receipt'?'HackerOne returned this report ID. Acceptance and payment are not yet confirmed.':'User-recorded receipt; delivery and bounty acceptance are not independently verified']]);}
function renderWorklist(){const stage=stages.find(s=>s[0]===currentStage);$('stageTitle').textContent=stage[1];$('stageHelp').textContent=stage[2];$('stageEyebrow').textContent='YOUR PROGRESS';$('currencyLabel').hidden=currentStage!=='queue';const query=$('search').value.toLowerCase();let rows=workflowRows(currentStage).filter(r=>JSON.stringify(r.data).toLowerCase().includes(query));const currency=$('currency').value;
 if(['queue','review'].includes(currentStage)&&currency!=='all')rows=rows.filter(r=>r.kind!=='program'||(currency==='unknown'?r.data.maximum===null:r.data.currency===currency));
 $('listCount').textContent=rows.length+(rows.length===1?' item':' items');$('worklist').replaceChildren();let group='';
 if(currentStage==='queue')$('worklist').append(el('p',state.workflow.reward_exchange?.date?'Currency comparison uses ECB rates dated '+state.workflow.reward_exchange.date+'. Original rewards are shown below.':'Exchange rates are loading. USD rewards appear first; other currencies are listed separately until rates are available.','muted'));
 if(!rows.length)$('worklist').append(el('p',currentStage==='sent'?'No reports have been sent.':currentStage==='results'?'No completed reviews yet. Possible issues are in Double-checking.':'No matching items in this stage.','empty'));
 rows.slice(0,visibleLimit).forEach(row=>{const p=row.data;const heading=p.stage==='review'&&p.available?'Priority shortlist · setup needed':p.reward_group;if(row.kind==='program'&&group!==heading){group=heading;$('worklist').append(el('h3',group,'group-title'));}
 const card=el('button',undefined,'work-card');card.type='button';const left=el('div'),right=el('div',undefined,'work-meta');
 if(row.kind==='program'){left.append(el('strong',p.name),el('small',p.source+' · '+(!p.available?'Unavailable — do not test':p.stale?'Cached listing — verify':'Permission not checked')));if(p.stage==='review')left.append(el('small','Priority · setup needed before testing'));right.append(el('span',money(p),'reward'));if(p.reward_usd!=null&&p.currency!=='USD')right.append(el('small','≈ '+new Intl.NumberFormat('en-US',{style:'currency',currency:'USD',maximumFractionDigits:0}).format(p.reward_usd)+' USD'));card.onclick=()=>openProgram(p);}
 else if(row.kind==='target'){left.append(el('strong',p.name),el('small',p.url));right.append(el('span',!p.enabled?'Disabled':p.expires*1000<Date.now()?'Scope expired':state.paused?'Paused':p.state||'Waiting','tag'),el('small','Next check: '+date(p.due)));card.onclick=()=>openTarget(p);}
 else if(row.kind==='gitlab'){left.append(el('strong','GitLab · '+p.project),el('small','Private project description test'));right.append(el('span',state.paused&&p.enabled?'Paused':p.status,'tag'),el('small','Last check: '+date(p.checked)));card.onclick=openGitlab;}
 else if(row.kind==='capital'){left.append(el('strong',p.name),el('small','Your demo account · watchlist access only'));right.append(el('span',state.paused?'Paused':p.status,'tag'),el('small',currentStage==='results'?'Last check: '+date(p.checked):'Next check: '+date(p.due)));card.onclick=openCapital;}
 else if(row.kind==='finding'){left.append(el('strong',p.title),el('small',state.targets.find(t=>t.id===p.target)?.name||''));right.append(el('span',(p.supervisor?.repeat_count||0)+'/3 checks','tag'),el('small',p.casework?.label||'Not a confirmed bug'));card.onclick=()=>openFinding(p);}
 else {left.append(el('strong',state.findings.find(f=>f.id===p.finding)?.title||'Submitted report'),el('small',p.receipt));right.append(el('span',p.channel==='email'?'Email · recorded':'Portal · recorded','tag'));card.onclick=()=>openSubmission(p);}
 card.append(left,right,el('span','↗','arrow'));$('worklist').append(card);});$('showMore').hidden=rows.length<=visibleLimit;
}
function render(){renderLegacy();const w=state.workflow;if(!w)return;$('stages').replaceChildren(...stages.map(([id,label],i)=>{const b=el('button',undefined,'stage'+(id===currentStage?' active':''));b.type='button';b.setAttribute('aria-pressed',String(id===currentStage));b.append(el('span',['⌕','◷','✓','▤','↗'][i],'step-no'),el('b',workflowRows(id).length),el('span',label));b.onclick=()=>{currentStage=id;visibleLimit=40;render();};return b;}));$('discoveryPause').textContent=w.enabled?'Pause discovery':'Resume discovery';$('discoveryStatus').textContent=(w.enabled?'Directory discovery active':'Directory discovery paused')+' · Every '+w.interval_minutes+' minutes · Scan permissions remain separate';$('discoveryAI').textContent=w.ai_status;$('sources').replaceChildren(...w.sources.map(s=>{const a=el('article',undefined,'item');a.append(el('strong',s.id),el('small',s.status),el('small','Last successful sync: '+date(s.last_success)+' · Next attempt: '+date(s.due)));return a;}));renderWorklist();renderSimpleStatus();}
$('search').oninput=()=>{visibleLimit=40;renderWorklist();};$('currency').onchange=()=>{visibleLimit=40;renderWorklist();};$('showMore').onclick=()=>{visibleLimit+=40;renderWorklist();};$('closeDetail').onclick=()=>$('detail').close();$('detail').addEventListener('click',e=>{if(e.target===$('detail'))$('detail').close();});$('discoveryPause').onclick=()=>change('/api/discovery/pause',{enabled:!state.workflow.enabled}).catch(e=>$('message').textContent=e.message);$('discoveryRefresh').onclick=()=>change('/api/discovery/refresh',{}).catch(e=>$('message').textContent=e.message);
setInterval(()=>refresh().catch(e=>$('message').textContent=e.message),15000);

function capitalActive(){const c=state.capital_demo;return !!(c?.enabled&&c.expires*1000>Date.now());}
function gitlabActive(){const g=state.gitlab;return !!(g?.configured&&g.enabled&&g.expires*1000>Date.now());}
function renderSimpleStatus(){
 const g=state.gitlab||{};
 $('gitlabSummary').textContent=g.configured?((g.expires*1000<=Date.now()?'Permission expired':state.paused&&g.enabled?'Paused':g.status)+' · '+g.runs+' completed checks · '+(gitlabActive()&&!state.paused?'Next check: '+date(g.due):'Open setup for details.')):'Your private project is not connected. Add a read-only token and synthetic test text. No repository files are needed.';
 $('openGitlab').textContent=g.configured?'View GitLab test and setup':'Finish GitLab setup';
 $('capitalCard').hidden=!state.capital_demo?.connected;

 const cap=state.capital_demo; if(cap){$('capitalSummary').textContent=capitalActive()?(state.paused?'Paused. ':cap.status+'. ')+cap.runs+' runs · next check '+date(cap.due):cap.connected?(cap.expires*1000<=Date.now()?'Permission expired. Reconnect after reviewing current rules.':cap.status):'Ready for setup. Connect your own demo account to test its watchlist login boundary.';$('openCapital').textContent=cap.connected?'View demo test and setup':'Connect demo account';}
 const ac=state.access_checks||[];$("accessSummary").textContent=ac.length?`${ac.filter(p=>p.enabled&&p.expires*1000>Date.now()).length} active tests · ${ac.filter(p=>p.result.reproduced).length} reproduced marker exposures. Tap to see evidence and setup issues.`:"Not connected yet. Needs a permitted private JSON endpoint and synthetic test data you own. Checks whether that data is exposed without login.";
 const v=state.validation;if(v)$("validationSummary").textContent=`${v.completed} completed runs · ${v.status}. Tests your ScopeGuard login and request protection every ${v.interval_minutes} minutes. Other websites are not included.`;
 const bg=state.background;
 if(bg){
  $('backgroundState').textContent=bg.status;
  $('backgroundDetails').textContent=`${bg.pending} items waiting · ${bg.completed} local reviews completed · Last worker check-in: ${date(bg.heartbeat)}. Last reviewed: ${bg.last_task}.`;
  $('backgroundNext').textContent=state.paused?'Background reviews and website checks are paused.':`Next website check: ${bg.next_website_check?date(bg.next_website_check):gitlabActive()?'GitLab: '+date(state.gitlab.due):capitalActive()?'Demo test: '+date(state.capital_demo.due):'No approved websites available'}. Directory update: ${bg.directory_enabled?date(bg.next_directory_update):'Paused'}. The worker looks for changed data every 10 seconds.`;
 }

 const w=state.workflow,active=workflowRows('review').length;
 const running=w.enabled||!state.paused;
 $('masterPause').textContent=running?'Pause everything':'Resume';
 $('status').textContent=w.enabled?(state.paused||!active?'● Finding websites':'● Running'):(!state.paused&&active?'● Checking websites':'● Paused');
 if(bg&&!state.paused)$('status').textContent=state.targets.some(t=>t.state==='Checking')?'● Checking website':!bg.healthy?'● Check worker':bg.pending?'● Reviews queued':'● Waiting · online';
 $('plainSummary').textContent=running?`${w.programs.filter(p=>p.stage!=='dismissed').length} companies found. ${active} websites ${state.paused?'paused':'have scheduled checks'}.`:'Everything is paused. Your saved progress is safe.';
 $('nextTitle').textContent='Local reviews · no API fees';
 $('nextText').textContent='Every listed company and finding is assessed with rules. Basic checks cannot prove a bounty-worthy bug. Hosting is billed separately.';
 $('connectAI').textContent='Review settings';
 $('openSetup').textContent='Setup status';
}
function setup(){
 const root=modal('Your setup');
 root.append(el('p','Free local reviews are active. OpenAI requests are disabled.','muted'));
 const list=el('div',undefined,'setup-list');
 [['✓','Find companies','Public directories update every 15 minutes.'],['✓','Review every company','Local rules assess reward uncertainty and missing permissions. No daily review quota.'],['✓','Check approved websites','Checks run on the server at their approved intervals, even when your phone is off.'],['✓','Review findings','Local rules check repeated observations and missing evidence. These are not AI reviews.'],[state.reporting?.connected?'✓':'1','Reporting account',state.reporting?.connected?'HackerOne connected. No confirmed bug is ready to send.':'Connect HackerOne when ready.']].forEach(([icon,title,note])=>{const item=el('article',undefined,'setup-item');item.append(el('span',icon,'setup-icon'));const info=el('div');info.append(el('strong',title),el('small',note));item.append(info);list.append(item);});
 root.append(list,el('p','No AI API charges. Your existing hosting charge remains. Reports still require independently validated evidence.','muted'));
 root.append(button(state.reporting?.connected?'Reporting account settings':'Connect reporting account',reportSetup));
}
$('connectAI').onclick=setup;$('openSetup').onclick=setup;
$('detail').addEventListener('close',()=>{$('detail').querySelectorAll('input[type="password"]').forEach(i=>i.value='');});
$('masterPause').onclick=async()=>{const b=$('masterPause');b.disabled=true;const pause=state.workflow.enabled||!state.paused;try{await change('/api/all-pause',{paused:pause});}catch(e){$('message').textContent=e.message;}finally{b.disabled=false;}};

function reportSetup(){
 const root=modal('Connect your reporting account');
 root.append(el('p','GitHub reports go through HackerOne. RoboForm uses its own support portal; it cannot use this connection.','muted'));
 if(state.reporting?.connected){root.append(el('strong','HackerOne is connected'),el('p','At most one verified report is attempted per day. If delivery is uncertain, the app stops rather than sending a duplicate.'));(state.reporting.attempts||[]).forEach(a=>root.append(el('p',a.status+': '+a.note)));root.append(button('Disconnect reporting',async()=>{await change('/api/reporting/disconnect',{});reportSetup();}));return;}
 root.append(safeLink('Open HackerOne API setup instructions ↗','https://api.hackerone.com/getting-started-hacker-api/'),el('p','Create an API token in your own HackerOne account. Enter its API username and token below.','muted'));
 const form=el('form');form.autocomplete='off';const nameLabel=el('label','API username'),name=el('input');name.required=true;name.autocomplete='off';name.maxLength=150;nameLabel.append(name);
 const tokenLabel=el('label','Private API token'),token=el('input');token.type='password';token.required=true;token.autocomplete='new-password';token.maxLength=500;tokenLabel.append(token);
 const permission=el('label',undefined,'check'),check=el('input');check.type='checkbox';check.required=true;permission.append(check,document.createTextNode('Allow ScopeGuard to submit independently validated reports through my HackerOne account.'));
 const result=el('p');result.setAttribute('role','status');const submit=el('button','Connect HackerOne');submit.type='submit';form.append(nameLabel,tokenLabel,permission,el('p','Credentials stay private on this server. Connecting does not submit the current unproven finding.','muted'),submit,result);
 form.onsubmit=async e=>{e.preventDefault();submit.disabled=true;submit.textContent='Checking account…';const secret=token.value.trim();token.value='';try{await change('/api/reporting/connect',{username:name.value.trim(),token:secret,authorize_delivery:check.checked});reportSetup();}catch(err){result.textContent=err.message;submit.disabled=false;submit.textContent='Connect HackerOne';}};root.append(form);
}

function openCodeAudits(){
 const root=modal('Your code security');
 root.append(el('p','Python only. Seven pattern checks and limited input-flow tracing run locally. Findings need human review; a clean result does not prove security. ScopeGuard files are rechecked automatically when code changes.','muted'));
 for(const audit of state.source_audits||[]){const box=el('details');box.append(el('summary',audit.name+' · '+audit.result.total_findings+' patterns to review'),el('small','Checked '+date(audit.checked)));
 if(!audit.result.total_findings)box.append(el('p','No covered patterns detected. Other vulnerabilities may still exist.'));
 for(const finding of audit.result.findings){box.append(el('h3','Line '+finding.line+': '+finding.title),el('p',finding.remediation));if(finding.trace_lines)box.append(el('p','Possible input path: lines '+finding.trace_lines.join(' → ')),el('p',finding.flow_status));}
 box.append(el('p',audit.result.limitation,'muted'));root.append(box);}
 const form=el('form'),label=el('label','Audit a Python file you own'),file=el('input');file.type='file';file.accept='.py';file.required=true;label.append(file);
 const permission=el('label',undefined,'check'),owned=el('input');owned.type='checkbox';owned.required=true;permission.append(owned,document.createTextNode('I own this code or have permission to audit it.'));
 const help=el('p','Remove credentials and personal data first. The file is sent only to your ScopeGuard server. Results and a file fingerprint are saved; source text is not saved. Maximum 128 KB.','muted'),submit=el('button','Check file'),status=el('p');submit.type='submit';status.setAttribute('role','status');
 form.append(label,permission,help,submit,status);form.onsubmit=async e=>{e.preventDefault();const chosen=file.files[0];if(!chosen||chosen.size>128000){status.textContent='Choose a Python file up to 128 KB.';return;}submit.disabled=true;try{await change('/api/source-audit',{name:chosen.name,source:await chosen.text(),owned:owned.checked});openCodeAudits();}catch(err){status.textContent=err.message;}finally{submit.disabled=false;}};root.append(form);
}
$('openCodeAudit').onclick=openCodeAudits;

function openDependencies(){
 const root=modal('Known vulnerability monitor');
 root.append(el('p','Checks exact software package versions against OSV advisories every day. No software is installed or executed. An advisory match does not prove that your app is exploitable or eligible for a bounty.','muted'));
 for(const p of state.dependency_projects||[]){const box=el('details');box.append(el('summary',p.name+' · '+p.result.length+' packages with matches'),el('p',p.status),el('p',p.package_count+' exact versions · '+p.skipped+' unsupported entries skipped'),el('small','Last completed: '+date(p.checked)+' · Next check: '+date(p.due)));
 if(p.checked&&!p.result.length)box.append(el('p','No advisory matches in the covered versions at the last completed check. This is not a security guarantee.'));
 for(const match of p.result){box.append(el('h3',match.name+' '+match.version+' ('+match.ecosystem+')'));for(const id of match.advisories)box.append(safeLink(id+' ↗','https://osv.dev/vulnerability/'+encodeURIComponent(id)),el('br'));}
 const remove=el('button','Stop and remove project','secondary');remove.onclick=async()=>{try{await change('/api/dependencies/delete',{project:p.name});openDependencies();}catch(e){remove.textContent=e.message;}};box.append(remove);root.append(box);}
 if(!(state.dependency_projects||[]).length)root.append(el('p','No dependency projects connected yet. Add a file below to start daily monitoring.'));
 const form=el('form'),nameLabel=el('label','Project name'),name=el('input');name.required=true;name.maxLength=80;nameLabel.append(name);
 const label=el('label','Dependency file'),file=el('input');file.type='file';file.accept='.txt,.json';file.required=true;label.append(file);
 const consent=el('label',undefined,'check'),check=el('input');check.type='checkbox';check.required=true;consent.append(check,document.createTextNode('I own this project or have permission. Send its package names and versions to OSV for daily checks.'));
 const status=el('p');status.setAttribute('role','status');const submit=el('button','Start daily checks');submit.type='submit';
 form.append(nameLabel,label,el('p','Supported: requirements.txt with exact versions, or package-lock.json version 2/3. Maximum 500 KB and 500 versions. Private packages may reveal their names to OSV; remove them first. Original file contents are not retained. Upload the new file when versions change.','muted'),consent,submit,status);
 form.onsubmit=async e=>{e.preventDefault();const f=file.files[0];if(!f||f.size>500000){status.textContent='Choose a supported file up to 500 KB.';return;}submit.disabled=true;try{await change('/api/dependencies',{project:name.value,filename:f.name,source:await f.text(),owned:check.checked,share_packages:check.checked});openDependencies();}catch(err){status.textContent=err.message;}finally{submit.disabled=false;}};root.append(form);
}
$('openDependencies').onclick=openDependencies;

function openValidation(){
 const root=modal('Live security validation'),v=state.validation;
 root.append(el('p','Automatic checks of your own ScopeGuard application. These use its local server connection, not third-party websites. Actual HTTP statuses and response fingerprints are retained; passwords and response bodies are not.','muted'));
 if(!v)return;
 root.append(el('p',v.status),el('small','Last started: '+date(v.last_started)+' · Next scheduled: '+date(v.due)));
 const run=el('button','Run checks now'),message=el('p');message.setAttribute('role','status');run.disabled=state.paused;
 run.onclick=async()=>{run.disabled=true;try{await change('/api/validation/run',{});openValidation();}catch(e){message.textContent=e.message;run.disabled=false;}};root.append(run,message);
 for(const entry of v.runs){const box=el('details');box.append(el('summary',date(entry.at)+' · '+entry.result.status));
 for(const check of entry.result.checks){box.append(el('h3',(check.passed?'Passed: ':'Investigate: ')+check.title),el('p',check.method+' '+check.path+' · expected '+check.expected_status+' · received '+check.actual_status),el('small','Response fingerprint: '+check.response_sha256));}
 box.append(el('p',entry.result.impact||'No completed impact assessment.'),el('p',entry.result.limitation||'This run did not complete.','muted'));root.append(box);}
 if(!v.runs.length)root.append(el('p','Waiting for the first run. The worker checks for queued work every 30 seconds.'));
}
$('openValidation').onclick=openValidation;

function openAccess(){
 const root=modal('Private data access tests');
 root.append(el('p','Tests one exact approved JSON API URL using your own test account and a unique marker in your own private test data. It sends up to four GET requests every 15 minutes. No crawling, object-ID guessing or account changes. A reproduced marker exposure still needs intended-access and impact review.','muted'));
 for(const profile of state.access_checks||[]){const target=state.targets.find(t=>t.id===profile.target),box=el('details');box.append(el('summary',(target?.name||'Target '+profile.target)+' · '+profile.status),el('p',target?.url||''),el('small','Last checked: '+date(profile.checked)+' · Scope expires: '+date(profile.expires)));
 for(const proof of profile.result.evidence||[])box.append(el('p',proof.step+': HTTP '+proof.status+' · test marker '+(proof.marker_present?'present':'absent')+' · '+proof.bytes+' bytes'),el('small','Response fingerprint: '+proof.sha256));
 if(profile.result.impact)box.append(el('p',profile.result.impact));
 for(const step of profile.result.reproduction||[])box.append(el('p',step));
 if(profile.result.remediation)box.append(el('p','Suggested fix: '+profile.result.remediation));
 box.append(el('p','Severity requires impact review. Nothing has been submitted.','muted'));
 const remove=el('button','Stop and remove saved credentials','secondary');remove.onclick=async()=>{try{await change('/api/access-check/remove',{target:profile.target});openAccess();}catch(e){remove.textContent=e.message;}};box.append(remove);root.append(box);}
 root.append(el('h3','Connect a private test endpoint'),el('p','First add its exact URL in Settings & details → Advanced target management. Use a URL containing only your own synthetic test record. A public home page is not suitable.'));
 const form=el('form'),targetLabel=el('label','Approved exact API URL'),select=el('select');select.required=true;const empty=el('option','Choose a URL');empty.value='';select.append(empty);
 state.targets.filter(t=>t.enabled&&t.expires*1000>Date.now()).forEach(t=>{const option=el('option',t.url);option.value=t.id;select.append(option);});targetLabel.append(select);
 const markerLabel=el('label','Unique marker saved in your private test record'),marker=el('input');marker.required=true;marker.minLength=24;marker.maxLength=160;marker.autocomplete='off';markerLabel.append(marker);
 const generate=el('button','Generate a test marker','secondary');generate.type='button';generate.onclick=()=>{const b=new Uint8Array(16);crypto.getRandomValues(b);marker.value='scopeguard_'+Array.from(b,x=>x.toString(16).padStart(2,'0')).join('');};
 const authLabel=el('label','Authorization value for your test account'),auth=el('input');auth.type='password';auth.autocomplete='off';auth.required=true;auth.placeholder='Bearer … or Basic …';auth.maxLength=4096;authLabel.append(auth);
 const rulesLabel=el('label','Program permission for this exact test'),rules=el('textarea');rules.required=true;rules.minLength=30;rules.maxLength=8000;rules.rows=3;rules.placeholder='Record the current policy allowing authenticated and anonymous GET comparisons at this rate.';rulesLabel.append(rules);
 const confirm=el('label',undefined,'check'),check=el('input');check.type='checkbox';check.required=true;confirm.append(check,document.createTextNode('I have permission for this read-only test. The record and account are mine, the marker is synthetic, and the response should require login.'));
 const status=el('p');status.setAttribute('role','status');const submit=el('button','Connect and start checks');submit.type='submit';
 form.append(targetLabel,markerLabel,generate,el('p','Save the generated marker inside your private test record before connecting. Do not put it in the URL. Responses must be JSON and no larger than 64 KB.','muted'),authLabel,el('p','Credentials stay in a private file on your server and go only to this exact HTTPS host. They are never shown in results. Do not send passwords or tokens in chat.','muted'),rulesLabel,confirm,submit,status);
 form.onsubmit=async e=>{e.preventDefault();submit.disabled=true;try{await change('/api/access-check',{target:Number(select.value),marker:marker.value,authorization:auth.value,rules:rules.value,permission:check.checked,own_data:check.checked,read_only:check.checked,private_expected:check.checked});auth.value='';openAccess();}catch(err){status.textContent=err.message;}finally{submit.disabled=false;}};root.append(form);
}
$('openAccess').onclick=openAccess;

function openCapital(){
 const root=modal('Connect Capital.com demo');const c=state.capital_demo||{};
 root.append(el('p','This tests whether your private demo watchlist can be read without logging in. It uses a demo account, creates one empty test watchlist and checks every 15 minutes. Login sessions renew automatically. This covers one access-control test, not the entire bounty program.'));
 root.append(safeLink('Read Capital.com bounty rules ↗','https://app.intigriti.com/programs/capitalcom/capitalcom/detail'),el('br'),safeLink('Open Capital.com demo account setup ↗','https://capital.com/'),el('br'),safeLink('Official API setup instructions ↗','https://open-api.capital.com/'));
 root.append(el('h3','One-time account setup'));
 const steps=el('ol');['Create your own Capital.com demo account if it is available to you. Use your real country and account details. No deposit is needed for this connector.','Enable two-factor authentication in Capital.com.','In Settings → API integrations, generate a key and its separate API password. Enter them below; do not share them in chat.','Join the Capital.com program through Intigriti for reporting. Your HackerOne connection does not submit to Intigriti.'].forEach(t=>steps.append(el('li',t)));root.append(steps);
 root.append(el('p','The connector contacts only the demo server. Its allowed requests are login, reading watchlists and creating an empty test watchlist. It cannot place orders, move funds or change balances. Review permission again after seven days.','muted'));
 if(c.connected){facts(root,[['Status',c.expires*1000<=Date.now()?'Permission expired':state.paused&&c.enabled?'Paused':c.status],['Runs',c.runs],['Last checked',date(c.checked)],['Next check',c.enabled?date(c.due):'Stopped'],['Permission expires',date(c.expires)],['Reporting','Manual Intigriti submission only; no report sent']]);
 for(const e of c.result?.evidence||[])root.append(el('p',e.step+': HTTP '+e.status+' · synthetic marker '+(e.marker_present?'present':'absent')));
 if(c.result?.reproduced)root.append(el('p','The test marker appeared without login twice. Testing stopped. This still requires manual review of intended privacy and impact; it is not a confirmed critical bug.'));
 root.append(button('Disconnect and remove credentials',async()=>{await change('/api/capital-demo/disconnect',{});openCapital();}));}
 const form=el('form'),inputs={};
 [['identifier','Demo account email','email'],['api_key','Capital.com API key','password'],['password','Separate API key password','password']].forEach(([key,title,type])=>{const label=el('label',title),input=el('input');input.type=type;input.required=true;input.autocomplete='off';input.maxLength=512;label.append(input);form.append(label);inputs[key]=input;});
 const label=el('label',undefined,'check'),check=el('input');check.type='checkbox';check.required=true;label.append(check,document.createTextNode('This demo account belongs to me. I have checked current program rules and am permitted to test this demo API, create one empty synthetic watchlist and compare logged-in and anonymous access at this rate.'));
 const note=el('p');note.setAttribute('role','status');const submit=el('button','Connect demo test');submit.type='submit';form.append(label,submit,note);
 form.onsubmit=async e=>{e.preventDefault();submit.disabled=true;try{await change('/api/capital-demo/connect',{...Object.fromEntries(Object.entries(inputs).map(([k,v])=>[k,v.value])),permission:check.checked,demo_only:check.checked,own_account:check.checked,create_watchlist:check.checked});Object.values(inputs).forEach(i=>i.value='');openCapital();}catch(err){note.textContent=err.message;}finally{submit.disabled=false;}};root.append(form);
}
$('openCapital').onclick=openCapital;

function openGitlab(){
 const root=modal('Your private GitLab project'),g=state.gitlab||{};
 root.append(el('p','This checks whether synthetic text in your private project description is exposed without login. It does not need a README or any code files.'));
 root.append(el('p','GitLab recommends a local lab for most research. Use this GitLab.com test only when current rules permit the production comparison, with your HackerOne email alias account. It covers one access boundary; it cannot guarantee a bounty.','muted'),safeLink('Read GitLab program rules ↗','https://hackerone.com/gitlab'));
 if(g.configured||g.checked){facts(root,[['Connection',g.connected?'Verified on last completed run':g.configured?'Saved; not yet verified':'Disconnected'],['Status',g.expires*1000<=Date.now()?'Permission expired':g.status],['Completed checks',g.runs],['Last checked',date(g.checked)],['Next check',gitlabActive()?(state.paused?'Paused':date(g.due)):'Stopped'],['Permission review due',date(g.expires)]]);
 for(const e of g.result?.evidence||[])root.append(el('p',e.step+': HTTP '+e.status),el('small','Response fingerprint: '+e.sha256));
 if(g.result?.limitation)root.append(el('p',g.result.limitation,'muted'));
 if(g.configured)root.append(button('Disconnect and remove saved token',async()=>{await change('/api/gitlab/disconnect',{});openGitlab();}));}
 const steps=el('ol');['Keep your own test project Private. In its Settings → General, save the generated text below in Project description.','Create a GitLab personal access token named ScopeGuard. Set a short expiry and select only read_api. This can read projects your account can access, so use your dedicated test account.','Paste the token into this form, confirm the exact test is permitted, and connect. It checks the token and your project role before comparing access.'].forEach(t=>steps.append(el('li',t)));root.append(steps,safeLink('GitLab token setup instructions ↗','https://docs.gitlab.com/user/profile/personal_access_tokens/'));
 const form=el('form');const inputs={};
 for(const [key,label,type] of [['project','Your GitLab project link','text'],['marker','Test text to save in the project description','text'],['token','Private GitLab token — read_api only','password']]){const l=el('label',label),i=el('input');i.type=type;i.required=true;i.autocomplete='off';i.maxLength=key==='marker'?43:512;l.append(i);inputs[key]=i;form.append(l);}
 inputs.project.value='https://gitlab.com/'+(g.project||'babe500-security-lab/scopeguard-test');
 const gen=el('button','Generate test text','secondary');gen.type='button';gen.onclick=()=>{const b=crypto.getRandomValues(new Uint8Array(16));inputs.marker.value='scopeguard_'+Array.from(b,x=>x.toString(16).padStart(2,'0')).join('');};form.append(gen,el('p','Copy the generated text into your private project description, then return here. Keep this setup form open.','muted'));
 const rl=el('label','Why is this exact GitLab.com test permitted?'),rules=el('textarea');rules.required=true;rules.minLength=30;rules.maxLength=4000;rules.placeholder='Record the current policy permission and why this needs production architecture instead of a local lab.';rl.append(rules);form.append(rl);
 const label=el('label',undefined,'check'),check=el('input');check.type='checkbox';check.required=true;label.append(check,document.createTextNode('I own this private test project and use my HackerOne alias account. I checked the current rules and have permission for this read-only comparison, up to five requests every 15 minutes. The description contains synthetic test data only.'));
 const submit=el('button','Connect and verify'),note=el('p');note.setAttribute('role','status');form.append(label,el('p','The token stays in a restricted server file and is sent only to gitlab.com. Checks stop on errors, uncertain results, or suspected exposure. Review permission after seven days. Nothing is automatically reported.','muted'),submit,note);
 form.onsubmit=async e=>{e.preventDefault();submit.disabled=true;try{await change('/api/gitlab/connect',{project:inputs.project.value,token:inputs.token.value,marker:inputs.marker.value,rules:rules.value,own_project:check.checked,policy_permission:check.checked,read_only:check.checked});inputs.token.value='';openGitlab();}catch(err){note.textContent=err.message;}finally{submit.disabled=false;}};root.append(form);
}
$('openGitlab').onclick=openGitlab;

function openProjectAudits(){
 const root=modal('Project research');
 root.append(el('p','Follows external input between Python functions and files. Code is parsed, never executed. ScopeGuard reviews its own code after updates; you can also upload an authorized Python project.','muted'));
 const audits=state.project_audits||[];
 if(!audits.length)root.append(el('p','No project analysis has completed yet.'));
 for(const a of audits){const box=el('details');box.open=true;const r=a.result;
 box.append(el('summary',a.name+' · '+r.total_findings+' leads · 0 confirmed bugs'),el('small','Reviewed '+date(a.checked)),el('p',r.files_analyzed+' Python files · '+r.functions_analyzed+' top-level functions'));
 if(r.syntax_skipped.length)box.append(el('p','Could not parse: '+r.syntax_skipped.join(', ')));
 if(r.bounded_or_truncated)box.append(el('p','Coverage is incomplete: a depth, work or output limit was reached.'));
 if(!r.findings.length)box.append(el('p','No input-to-operation paths found by the covered checks. This does not establish that the project is secure.'));
 for(const f of r.findings){const detail=el('details');detail.append(el('summary',f.title+' — '+f.file+':'+f.line));const steps=el('ol');f.trace.forEach(t=>steps.append(el('li',t.file+':'+t.line+' — '+t.role)));detail.append(steps,el('p',f.next_step),el('p','Evidence status: static hypothesis. No runtime impact demonstrated.','muted'));box.append(detail);}
 box.append(el('p',r.limitation,'muted'));
 box.append(button('Download review evidence',()=>{const blob=new Blob([JSON.stringify(a,null,2)],{type:'application/json'});const url=URL.createObjectURL(blob);const link=el('a');link.href=url;link.download='scopeguard-project-review.json';link.click();setTimeout(()=>URL.revokeObjectURL(url),1000);}));root.append(box);}
 const form=el('form'),label=el('label','Review your Python project ZIP'),file=el('input');file.type='file';file.accept='.zip';file.required=true;label.append(file);
 const permission=el('label',undefined,'check'),owned=el('input');owned.type='checkbox';owned.required=true;permission.append(owned,document.createTextNode('I own this code or have permission to review it.'));
 const note=el('p','Remove credentials before uploading. Up to 80 Python files, 128 KB each, 2 MB total. The ZIP goes only to this server. Source code is not saved; evidence paths and fingerprints are saved. No websites are scanned.','muted');
 const submit=el('button','Review project'),status=el('p');status.setAttribute('role','status');form.append(label,permission,note,submit,status);
 form.onsubmit=async e=>{e.preventDefault();const f=file.files[0];if(!f||f.size>2000000){status.textContent='Choose a ZIP up to 2 MB.';return;}submit.disabled=true;status.textContent='Reviewing project…';try{const encoded=await new Promise((resolve,reject)=>{const reader=new FileReader();reader.onload=()=>resolve(String(reader.result).split(',')[1]);reader.onerror=reject;reader.readAsDataURL(f);});await change('/api/project-audit',{name:f.name,archive:encoded,owned:owned.checked});openProjectAudits();}catch(err){status.textContent=err.message;}finally{submit.disabled=false;}};root.append(form);
}
$('openProjectAudit').onclick=openProjectAudits;
