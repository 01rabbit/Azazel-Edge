/* Offline study harness only; no runtime telemetry, networking or truth labels. */
(function () {
    'use strict';
    function capture(assignment, start, end, answers, plan) {
        if (!Number.isFinite(start) || !Number.isFinite(end) || end < start) throw Error('Invalid elapsed clock');
        var elapsed=(end-start)/1000, timeout=elapsed>=plan.task_horizon_seconds;
        var options=plan.task_cards[assignment.case].options.map(function(o){return o.id;});
        if (!Array.isArray(answers) || answers.length>10 || new Set(answers).size!==answers.length || answers.some(function(a){return options.indexOf(a)<0;})) throw Error('Invalid answer choices');
        return {assignment_id:assignment.id,consented:true,elapsed_seconds:timeout?plan.task_horizon_seconds:elapsed,timed_out:timeout,
            answer_ids:timeout?[]:answers,render_sha256:plan.render_sha256[assignment.arm],snapshot_sha256:assignment.snapshot_sha256,
            rubric_sha256:plan.rubric_sha256};
    }
    if(typeof module!=='undefined'&&module.exports)module.exports={capture:capture};
    if(typeof document==='undefined')return;
    var plan=null,digest=null,assignments=[],captures=[],active=null,started=0,participant=null;
    function $(id){return document.getElementById(id);}
    function status(message){$('status').textContent=message;}
    $('plan').addEventListener('change',async function(){
        plan=null;digest=null;captures=[];assignments=[];participant=null;active=null;$('start').disabled=true;$('finish').disabled=true;$('export').disabled=true;$('task').hidden=true;
        try{
            var file=this.files[0];if(!file||file.size>8*1024*1024)throw Error('Invalid bounded plan file');
            var input=JSON.parse(await file.text());
            if(input.schema_version!=='azazel-operator-collector-input/v1'||typeof input.plan_canonical_json!=='string'||!/^[0-9a-f]{64}$/.test(input.plan_sha256))throw Error('Prepare plan with the offline CLI');
            var bytes=new TextEncoder().encode(input.plan_canonical_json),hash=Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',bytes))).map(function(b){return b.toString(16).padStart(2,'0');}).join('');
            if(hash!==input.plan_sha256)throw Error('Plan digest mismatch');
            var parsed=JSON.parse(input.plan_canonical_json);
            if(parsed.schema_version!=='azazel-operator-study/v1'||!Array.isArray(parsed.assignments)||parsed.assignments.length>8000||!(parsed.task_horizon_seconds>=1&&parsed.task_horizon_seconds<=3600)||!parsed.task_cards)throw Error('Invalid prepared plan');
            plan=parsed;digest=hash;$('start').disabled=false;status('Prepared plan loaded. Confirm consent and fixture before starting.');
        }catch(e){status('Plan unavailable: '+e.message);}
    });
    $('start').addEventListener('click',function(){
        if(!plan||!$('consent').checked||!$('fixture').checked){status('Consent and assigned fixture confirmation are required.');return;}
        var id=$('participant').value;
        if(!/^p-[0-9a-f]{16}$/.test(id)||participant&&participant!==id){status('Use one planned anonymous participant ID per export.');return;}
        participant=id;
        assignments=plan.assignments.filter(function(a){return a.participant===id;}).sort(function(a,b){return a.case.localeCompare(b.case)||a.order-b.order;});
        active=assignments.find(function(a){return !captures.some(function(c){return c.assignment_id===a.id;});});
        if(!active){status('No remaining assignment for this participant. Export captures.');return;}
        var card=plan.task_cards[active.case];if(!card||typeof card.prompt!=='string'||card.prompt.length>500||!Array.isArray(card.options)||card.options.length>10){status('Invalid task card');active=null;return;}
        $('title').textContent=active.id+' · '+active.arm+' · order '+active.order;
        $('prompt').textContent=card.prompt;$('options').textContent='';
        card.options.forEach(function(o){var label=document.createElement('label'),choice=document.createElement('input');choice.type='checkbox';choice.value=o.id;label.appendChild(choice);label.appendChild(document.createTextNode(' '+String(o.label).slice(0,200)));$('options').appendChild(label);});
        $('task').hidden=false;$('start').disabled=true;$('finish').disabled=false;$('plan').disabled=true;$('participant').disabled=true;started=performance.now();
        status('Task started. Common deadline '+plan.task_horizon_seconds+' seconds.');
    });
    $('finish').addEventListener('click',function(){
        if(!active||!$('consent').checked){status('Capture unavailable: task inactive or consent withdrawn.');return;}
        try{
            var answers=Array.from($('options').querySelectorAll('input:checked')).map(function(n){return n.value;});
            captures.push(capture(active,started,performance.now(),answers,plan));active=null;
            $('finish').disabled=true;$('start').disabled=false;$('export').disabled=false;$('fixture').checked=false;
            $('progress').textContent=captures.length+' / '+assignments.length+' unscored captures';status('Captured locally. Load/confirm the next assigned fixture separately.');
        }catch(e){status('Capture unavailable: '+e.message);}
    });
    $('export').addEventListener('click',function(){
        if(!$('consent').checked||active){status('Export requires current consent and a finished task.');return;}
        var body={schema_version:'azazel-operator-capture/v1',source:'offline_browser_task_collector',plan_sha256:digest,captures:captures};
        var url=URL.createObjectURL(new Blob([JSON.stringify(body,null,2)],{type:'application/json'})),a=document.createElement('a');a.href=url;a.download='anonymous-operator-captures.json';a.click();setTimeout(function(){URL.revokeObjectURL(url);},1000);
    });
})();
