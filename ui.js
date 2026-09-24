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
  $('status').textContent = state.paused ? '● Scheduler paused' : '● Scheduler running';
  $('pause').textContent = state.paused ? 'Resume approved checks' : 'Pause all checks';
  $('targetCount').textContent = state.targets.length;
  $('findingCount').textContent = state.findings.length;
  $('acceptedCount').textContent = state.findings.filter(f=>f.feedback==='accepted').length;
  const supervisor=state.supervisor || {};
  $('supervisorRules').textContent=supervisor.rules_status || 'Loading review status';
  $('supervisorAI').textContent='AI: '+(supervisor.ai_status || 'Not connected');
  $('supervisorDelivery').textContent=supervisor.delivery_status || '';
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
  ['queue','Websites in queue','Discovered paid programs. Rewards are reported directory amounts, not verified payouts. Ranked highest first within each currency; unknown amounts come last.'],
  ['review','Under review','Shortlisted programs and saved targets. Discovery does not authorize scanning. Approved targets retain their existing schedules.'],
  ['supervisor','Supervisor review','Findings gathering up to three spaced observations. Repeating a warning does not establish security impact.'],
  ['results','Results','Completed observation reviews and recorded feedback. Held results are not confirmed vulnerabilities or bounty-ready reports.'],
  ['sent','Submitted / emailed','Actual submission records only. Automatic delivery is not connected. Programs may require a portal instead of email.']
];
function safeLink(text,url){const a=el('a',text);try{const u=new URL(url);if(u.protocol!=='https:')return el('span',text);a.href=u.href;a.target='_blank';a.rel='noopener noreferrer';return a;}catch{return el('span',text);}}
function money(p){if(p.maximum===null||!p.currency)return 'Reward amount not published';return new Intl.NumberFormat('en-US',{style:'currency',currency:p.currency,maximumFractionDigits:0}).format(p.maximum)+' '+p.currency+' maximum';}
function date(at){return at?new Date(at*1000).toLocaleString():'Not yet';}
function workflowRows(stage){const w=state.workflow||{programs:[],submissions:[]};const p=w.programs.filter(p=>p.stage!=='dismissed');
 if(stage==='queue')return p.filter(p=>p.stage==='queue').map(p=>({kind:'program',data:p}));
 if(stage==='review')return [...p.filter(p=>p.stage==='review').map(p=>({kind:'program',data:p})),...state.targets.map(t=>({kind:'target',data:t}))];
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
 if(p.ai_note)root.append(el('h3','AI advisory'),el('p',p.ai_note));
 const actions=el('div',undefined,'controls');actions.append(button(p.stage==='review'?'Return to queue':'Move to scope review',async()=>{await change('/api/program-stage',{id:p.id,stage:p.stage==='review'?'queue':'review'});$('detail').close();}));
 actions.append(button('Dismiss from queue',async()=>{await change('/api/program-stage',{id:p.id,stage:'dismissed'});$('detail').close();}));root.append(actions);
}
function openTarget(t){const root=modal(t.name);facts(root,[['Exact URL',t.url],['Current status',t.state],['Schedule','Every '+t.interval/3600+' hours'],['Scope review expires',date(t.expires)],['Checks',!t.enabled?'Disabled':t.expires*1000<Date.now()?'Blocked: authorization expired':state.paused?'Scheduler paused':'Enabled']]);root.append(el('h3','Recorded authorization'),el('p',t.rules),safeLink('Read official policy ↗',t.policy));root.append(button(t.enabled?'Disable target':'Enable target',async()=>{await change('/api/target-state',{id:t.id,enabled:!t.enabled});$('detail').close();}));}
function openFinding(f){const root=modal(f.title),r=f.supervisor;root.append(el('span',r?.status||'Impact unproven','tag'));facts(root,[['Website',state.targets.find(t=>t.id===f.target)?.url||'Unknown'],['Observations',(r?.repeat_count||0)+'/3'],['Last observed',date(f.last_seen)],['Feedback',f.feedback],['Submission ready','No — security impact has not been demonstrated']]);root.append(el('p',r?.reason||f.impact),el('h3','Evidence'),el('p',JSON.parse(f.evidence).note));
 if(r){root.append(el('h3','Reporting route'),el('p',r.channel.name));if(r.channel.url)root.append(safeLink('Open reporting policy ↗',r.channel.url));if(r.ai_review)root.append(el('p','AI advisory: '+r.ai_review.note));}
 const a=el('a','Download evidence draft');a.href='/report/'+f.id;a.download='scopeguard-'+f.id+'.md';root.append(el('br'),a);
 const details=el('details');details.append(el('summary','Record a report already submitted'));const form=el('form');const info=el('p','Use only if you already submitted this finding through an accepted channel. This records your reference; it does not send or validate a report.','muted');const receipt=el('input');receipt.required=true;receipt.minLength=8;receipt.maxLength=1000;receipt.placeholder='Report ID, receipt or confirmation reference';receipt.setAttribute('aria-label','Submission receipt');const channel=el('select');['portal','email'].forEach(v=>{const o=el('option',v==='portal'?'Reporting portal':'Email');o.value=v;channel.append(o);});channel.setAttribute('aria-label','Actual submission channel');const label=el('label',undefined,'check'),check=el('input');check.type='checkbox';check.required=true;label.append(check,document.createTextNode('I actually submitted this report and have a receipt.'));const submit=el('button','Save submission record');submit.type='submit';form.append(info,channel,receipt,label,submit);form.onsubmit=async e=>{e.preventDefault();submit.disabled=true;try{await change('/api/submissions/record',{finding:f.id,channel:channel.value,receipt:receipt.value,actually_submitted:check.checked});$('detail').close();}catch(err){info.textContent=err.message;}finally{submit.disabled=false;}};details.append(form);root.append(details);
}
function openSubmission(s){const f=state.findings.find(f=>f.id===s.finding),root=modal(f?.title||'Submission record');facts(root,[['Channel',s.channel],['Receipt / reference',s.receipt],['Recorded at',date(s.at)],['Evidence source','User-recorded receipt; delivery and bounty acceptance are not independently verified']]);}
function renderWorklist(){const stage=stages.find(s=>s[0]===currentStage);$('stageTitle').textContent=stage[1];$('stageHelp').textContent=stage[2];$('stageEyebrow').textContent=currentStage==='queue'?'PROGRAM INTAKE':'RESEARCH PIPELINE';$('currencyLabel').hidden=!['queue','review'].includes(currentStage);const query=$('search').value.toLowerCase();let rows=workflowRows(currentStage).filter(r=>JSON.stringify(r.data).toLowerCase().includes(query));const currency=$('currency').value;
 if(['queue','review'].includes(currentStage)&&currency!=='all')rows=rows.filter(r=>r.kind!=='program'||(currency==='unknown'?r.data.maximum===null:r.data.currency===currency));
 $('listCount').textContent=rows.length+' items';$('worklist').replaceChildren();let group='';
 if(!rows.length)$('worklist').append(el('p',currentStage==='sent'?'No reports submitted or emailed.':currentStage==='results'?'No completed reviews yet. Findings with fewer than three observations are in Supervisor review.':'No matching items in this stage.','empty'));
 rows.slice(0,visibleLimit).forEach(row=>{const p=row.data;if(row.kind==='program'&&currency==='all'&&group!==(p.maximum===null?'Unknown reward':p.currency)){group=p.maximum===null?'Unknown reward':p.currency;$('worklist').append(el('h3',group==='Unknown reward'?group:group+' · highest reported rewards first','group-title'));}
 const card=el('button',undefined,'work-card');card.type='button';const left=el('div'),right=el('div',undefined,'work-meta');
 if(row.kind==='program'){left.append(el('strong',p.name),el('small',p.source+' · '+(!p.available?'Unavailable — do not test':p.stale?'Cached listing — verify':'Scope review needed')));right.append(el('span',money(p),'reward'));card.onclick=()=>openProgram(p);}
 else if(row.kind==='target'){left.append(el('strong',p.name),el('small',p.url));right.append(el('span',!p.enabled?'Disabled':p.expires*1000<Date.now()?'Scope expired':'Scheduled checks','tag'));card.onclick=()=>openTarget(p);}
 else if(row.kind==='finding'){left.append(el('strong',p.title),el('small',state.targets.find(t=>t.id===p.target)?.name||''));right.append(el('span',(p.supervisor?.repeat_count||0)+'/3 observations','tag'),el('small','Held · impact unproven'));card.onclick=()=>openFinding(p);}
 else {left.append(el('strong',state.findings.find(f=>f.id===p.finding)?.title||'Submitted report'),el('small',p.receipt));right.append(el('span',p.channel==='email'?'Email · recorded':'Portal · recorded','tag'));card.onclick=()=>openSubmission(p);}
 card.append(left,right,el('span','↗','arrow'));$('worklist').append(card);});$('showMore').hidden=rows.length<=visibleLimit;
}
function render(){renderLegacy();const w=state.workflow;if(!w)return;$('stages').replaceChildren(...stages.map(([id,label],i)=>{const b=el('button',undefined,'stage'+(id===currentStage?' active':''));b.type='button';b.setAttribute('aria-pressed',String(id===currentStage));b.append(el('span','0'+(i+1),'step-no'),el('b',workflowRows(id).length),el('span',label));b.onclick=()=>{currentStage=id;visibleLimit=40;render();};return b;}));$('discoveryPause').textContent=w.enabled?'Pause discovery':'Resume discovery';$('discoveryStatus').textContent=(w.enabled?'Directory discovery active':'Directory discovery paused')+' · Every '+w.interval_hours+' hours · Scan permissions remain separate';$('discoveryAI').textContent=w.ai_status;$('sources').replaceChildren(...w.sources.map(s=>{const a=el('article',undefined,'item');a.append(el('strong',s.id),el('small',s.status),el('small','Last successful sync: '+date(s.last_success)+' · Next attempt: '+date(s.due)));return a;}));renderWorklist();}
$('search').oninput=()=>{visibleLimit=40;renderWorklist();};$('currency').onchange=()=>{visibleLimit=40;renderWorklist();};$('showMore').onclick=()=>{visibleLimit+=40;renderWorklist();};$('closeDetail').onclick=()=>$('detail').close();$('detail').addEventListener('click',e=>{if(e.target===$('detail'))$('detail').close();});$('discoveryPause').onclick=()=>change('/api/discovery/pause',{enabled:!state.workflow.enabled}).catch(e=>$('message').textContent=e.message);$('discoveryRefresh').onclick=()=>change('/api/discovery/refresh',{}).catch(e=>$('message').textContent=e.message);
setInterval(()=>refresh().catch(e=>$('message').textContent=e.message),15000);
