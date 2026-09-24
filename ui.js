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
  ['queue','Found websites','Companies with bounty programs. Higher rewards appear first within each currency. Permission must be checked before testing a new website.'],
  ['review','Checking','Websites with permission and a scheduled check. They are checked at set times, not all at once.'],
  ['supervisor','Double-checking','Possible issues being checked again. They are not confirmed bugs yet.'],
  ['results','Results','Completed reviews. Open a result to see whether it still needs more proof.'],
  ['sent','Sent reports','Reports with a submission receipt. A receipt does not mean a bounty has been approved.']
];
function safeLink(text,url){const a=el('a',text);try{const u=new URL(url);if(u.protocol!=='https:')return el('span',text);a.href=u.href;a.target='_blank';a.rel='noopener noreferrer';return a;}catch{return el('span',text);}}
function money(p){if(p.maximum===null||!p.currency)return 'Reward not shown';return new Intl.NumberFormat('en-US',{style:'currency',currency:p.currency,maximumFractionDigits:0}).format(p.maximum)+' '+p.currency+' possible';}
function date(at){return at?new Date(at*1000).toLocaleString():'Not yet';}
function workflowRows(stage){const w=state.workflow||{programs:[],submissions:[]};const p=w.programs.filter(p=>p.stage!=='dismissed');
 if(stage==='queue')return p.map(p=>({kind:'program',data:p}));
 if(stage==='review')return state.targets.filter(t=>t.enabled&&t.expires*1000>Date.now()).map(t=>({kind:'target',data:t}));
 if(stage==='supervisor')return state.findings.filter(f=>f.feedback==='unreviewed'&&(f.supervisor?.repeat_count||0)<3).map(f=>({kind:'finding',data:f}));
 if(stage==='results')return state.findings.filter(f=>f.feedback!=='unreviewed'||(f.supervisor?.repeat_count||0)>=3).map(f=>({kind:'finding',data:f}));
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
function openTarget(t){const root=modal(t.name);facts(root,[['Exact URL',t.url],['Current status',t.state],['Schedule','Every '+t.interval/3600+' hours'],['Scope review expires',date(t.expires)],['Checks',!t.enabled?'Disabled':t.expires*1000<Date.now()?'Blocked: authorization expired':state.paused?'Scheduler paused':'Enabled']]);root.append(el('h3','Recorded authorization'),el('p',t.rules),safeLink('Read official policy ↗',t.policy));root.append(button(t.enabled?'Disable target':'Enable target',async()=>{await change('/api/target-state',{id:t.id,enabled:!t.enabled});$('detail').close();}));}
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
function renderWorklist(){const stage=stages.find(s=>s[0]===currentStage);$('stageTitle').textContent=stage[1];$('stageHelp').textContent=stage[2];$('stageEyebrow').textContent='YOUR PROGRESS';$('currencyLabel').hidden=!['queue','review'].includes(currentStage);const query=$('search').value.toLowerCase();let rows=workflowRows(currentStage).filter(r=>JSON.stringify(r.data).toLowerCase().includes(query));const currency=$('currency').value;
 if(['queue','review'].includes(currentStage)&&currency!=='all')rows=rows.filter(r=>r.kind!=='program'||(currency==='unknown'?r.data.maximum===null:r.data.currency===currency));
 $('listCount').textContent=rows.length+(rows.length===1?' item':' items');$('worklist').replaceChildren();let group='';
 if(!rows.length)$('worklist').append(el('p',currentStage==='sent'?'No reports have been sent.':currentStage==='results'?'No completed reviews yet. Possible issues are in Double-checking.':'No matching items in this stage.','empty'));
 rows.slice(0,visibleLimit).forEach(row=>{const p=row.data;if(row.kind==='program'&&currency==='all'&&group!==(p.maximum===null?'Unknown reward':p.currency)){group=p.maximum===null?'Unknown reward':p.currency;$('worklist').append(el('h3',group==='Unknown reward'?group:group+' · highest reported rewards first','group-title'));}
 const card=el('button',undefined,'work-card');card.type='button';const left=el('div'),right=el('div',undefined,'work-meta');
 if(row.kind==='program'){left.append(el('strong',p.name),el('small',p.source+' · '+(!p.available?'Unavailable — do not test':p.stale?'Cached listing — verify':'Permission not checked')));right.append(el('span',money(p),'reward'));card.onclick=()=>openProgram(p);}
 else if(row.kind==='target'){left.append(el('strong',p.name),el('small',p.url));right.append(el('span',!p.enabled?'Disabled':p.expires*1000<Date.now()?'Scope expired':'Checks scheduled','tag'));card.onclick=()=>openTarget(p);}
 else if(row.kind==='finding'){left.append(el('strong',p.title),el('small',state.targets.find(t=>t.id===p.target)?.name||''));right.append(el('span',(p.supervisor?.repeat_count||0)+'/3 checks','tag'),el('small',p.casework?.label||'Not a confirmed bug'));card.onclick=()=>openFinding(p);}
 else {left.append(el('strong',state.findings.find(f=>f.id===p.finding)?.title||'Submitted report'),el('small',p.receipt));right.append(el('span',p.channel==='email'?'Email · recorded':'Portal · recorded','tag'));card.onclick=()=>openSubmission(p);}
 card.append(left,right,el('span','↗','arrow'));$('worklist').append(card);});$('showMore').hidden=rows.length<=visibleLimit;
}
function render(){renderLegacy();const w=state.workflow;if(!w)return;$('stages').replaceChildren(...stages.map(([id,label],i)=>{const b=el('button',undefined,'stage'+(id===currentStage?' active':''));b.type='button';b.setAttribute('aria-pressed',String(id===currentStage));b.append(el('span',['⌕','◷','✓','▤','↗'][i],'step-no'),el('b',workflowRows(id).length),el('span',label));b.onclick=()=>{currentStage=id;visibleLimit=40;render();};return b;}));$('discoveryPause').textContent=w.enabled?'Pause discovery':'Resume discovery';$('discoveryStatus').textContent=(w.enabled?'Directory discovery active':'Directory discovery paused')+' · Every '+w.interval_hours+' hours · Scan permissions remain separate';$('discoveryAI').textContent=w.ai_status;$('sources').replaceChildren(...w.sources.map(s=>{const a=el('article',undefined,'item');a.append(el('strong',s.id),el('small',s.status),el('small','Last successful sync: '+date(s.last_success)+' · Next attempt: '+date(s.due)));return a;}));renderWorklist();renderSimpleStatus();}
$('search').oninput=()=>{visibleLimit=40;renderWorklist();};$('currency').onchange=()=>{visibleLimit=40;renderWorklist();};$('showMore').onclick=()=>{visibleLimit+=40;renderWorklist();};$('closeDetail').onclick=()=>$('detail').close();$('detail').addEventListener('click',e=>{if(e.target===$('detail'))$('detail').close();});$('discoveryPause').onclick=()=>change('/api/discovery/pause',{enabled:!state.workflow.enabled}).catch(e=>$('message').textContent=e.message);$('discoveryRefresh').onclick=()=>change('/api/discovery/refresh',{}).catch(e=>$('message').textContent=e.message);
setInterval(()=>refresh().catch(e=>$('message').textContent=e.message),15000);

function renderSimpleStatus(){
 const w=state.workflow,active=state.targets.filter(t=>t.enabled&&t.expires*1000>Date.now()).length;
 const running=w.enabled||!state.paused;
 $('masterPause').textContent=running?'Pause everything':'Resume';
 $('status').textContent=w.enabled?(state.paused||!active?'● Finding websites':'● Running'):(!state.paused&&active?'● Checking websites':'● Paused');
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
 [['✓','Find companies','Public directories update every 6 hours.'],['✓','Review every company','Local rules assess reward uncertainty and missing permissions. No daily review quota.'],['✓','Check approved websites','Checks run on the server at their approved intervals, even when your phone is off.'],['✓','Review findings','Local rules check repeated observations and missing evidence. These are not AI reviews.'],[state.reporting?.connected?'✓':'1','Reporting account',state.reporting?.connected?'HackerOne connected. No confirmed bug is ready to send.':'Connect HackerOne when ready.']].forEach(([icon,title,note])=>{const item=el('article',undefined,'setup-item');item.append(el('span',icon,'setup-icon'));const info=el('div');info.append(el('strong',title),el('small',note));item.append(info);list.append(item);});
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
