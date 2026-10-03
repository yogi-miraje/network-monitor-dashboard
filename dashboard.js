"use strict";
(() => {
  const $ = id => document.getElementById(id);
  const canvas = $("chart"), ctx = canvas.getContext("2d");
  const range = $("window");
  let data = null, eventLimit = 50, requestId = 0, lastStatus = "", hover = null;
  const colors = {green:"#5dd6a5",red:"#ff777f",amber:"#eebc68",grid:"#27313b",text:"#94a3b1",gray:"#8e9aa6"};
  const time = (ts, seconds = false) => new Date(ts * 1000).toLocaleTimeString([], {hour:"numeric",minute:"2-digit",...(seconds ? {second:"2-digit"} : {})});
  const date = ts => new Date(ts * 1000).toLocaleDateString([], {month:"short",day:"numeric"});
  const duration = seconds => {seconds=Math.max(0,Math.round(seconds));if(seconds<60)return `${seconds}s`;if(seconds<3600)return `${Math.floor(seconds/60)}m ${seconds%60}s`;if(seconds<86400)return `${Math.floor(seconds/3600)}h ${Math.floor(seconds%3600/60)}m`;return `${Math.floor(seconds/86400)}d ${Math.floor(seconds%86400/3600)}h`;};
  const el = (tag, text, cls) => {const node=document.createElement(tag);if(text!==undefined)node.textContent=text;if(cls)node.className=cls;return node;};

  function stopped() {
    $("status-dot").className="status-dot waiting";
    $("connection-title").textContent="Monitor is stopped";
    $("connection-detail").textContent=`Double-click Start.command to start monitoring, then open ${location.host||"localhost:8787"} in Chrome.`;
    $("latency").textContent="—";
    $("packet-loss").replaceChildren();$("loss-note").textContent="Monitor stopped — no current packet-loss reading";
    $("check-status").textContent="Waiting for the local monitor";
    $("chart-empty").hidden=Boolean(data?.points?.length);
    $("chart-empty").firstElementChild.textContent="Start the monitor to begin collecting data";
    $("events-empty").querySelector("h3").textContent="Waiting for the monitor";
    $("events-empty").querySelector("p").textContent="Saved events will load when the monitor is running.";
  }

  function render(next) {
    data=next;
    const latest=data.latest;
    const fresh=latest && data.now-latest.ts<4;
    const state=fresh?latest.state:"waiting";
    $("status-dot").className=`status-dot ${state}`;
    const titles={online:"Connected",offline:"Connection check failed",dns:"DNS problem",blocked:"Monitoring blocked",waiting:"Waiting for a check"};
    $("connection-title").textContent=titles[state];
    $("connection-detail").textContent=fresh?(state==="online"?"Your internet connection is responding.":latest.detail):"The monitor is running. Waiting for a fresh connection check.";
    $("latency").replaceChildren(latest?.latency!=null&&fresh?document.createTextNode(`${Math.round(latest.latency)}`):document.createTextNode("—"));
    if(latest?.latency!=null&&fresh)$("latency").append(el("span","ms","unit"));
    $("uptime").textContent=data.uptime==null?"—":`${data.uptime.toFixed(1)}%`;
    $("uptime-window").textContent=`· ${{300:"5 min",900:"15 min",3600:"1 hr",86400:"24 hr"}[data.window]}`;
    $("drops").textContent=String(data.drop_count);
    $("event-count").textContent=String(data.event_count);
    $("since").textContent=`Monitoring since ${date(data.first_seen)}, ${time(data.first_seen)}`;
    $("check-status").replaceChildren(el("span","","live-dot"),document.createTextNode(state==="blocked"?"Checks blocked":fresh?"Checks every second":"Waiting for a fresh check"));
    $("check-status").firstChild.style.background=state==="offline"?colors.red:state==="dns"?colors.amber:state==="blocked"||state==="waiting"?colors.gray:colors.green;
    $("chart-empty").hidden=data.points.length>0;
    if(!data.points.length)$("chart-empty").firstElementChild.textContent="The graph begins with your first connection check";
    if(state!==lastStatus){$("announcement").textContent=titles[state];lastStatus=state;}
    const loss=$("packet-loss");loss.replaceChildren();
    for(const target of data.packet_loss?.targets??[]){
      const item=el("span",undefined,"loss-target");
      item.append(document.createTextNode(`${target.name} `),el("strong",target.percent==null?"—":`${target.percent.toFixed(1)}%`));
      item.title=`${target.lost} unanswered / ${target.sent} measured pings; ${target.unknown} unavailable checks. Missing or blocked checks are excluded.`;
      loss.append(item);
    }
    $("loss-note").textContent=data.packet_loss?.fresh?"Unanswered pings · every 2 seconds · loss or filtering":"Waiting for fresh ping measurements";
    renderEvents();draw();
  }

  function renderEvents() {
    const body=$("events-body");body.replaceChildren();
    $("events-table").hidden=!data.events.length;
    $("events-empty").hidden=Boolean(data.events.length);
    $("events-empty").querySelector("h3").textContent="No check failures recorded";
    $("events-empty").querySelector("p").textContent="Failed checks and monitoring gaps appear here. Causes need supporting evidence.";
    for(const event of data.events){
      const row=el("tr");
      const started=el("td",time(event.start,true));started.append(el("span",date(event.start),"event-date"));
      const span=duration((event.end??data.now)-event.start);
      const elapsed=el("td",`${event.end_known===0?"≥ ":event.kind==="offline"?"≈ ":""}${span}`);
      if(event.kind==="offline")elapsed.title="Approximate sampled failure interval, not a measured full internet outage duration.";
      if(event.end_known===0)elapsed.title="At least this long; recovery time is unknown because monitoring stopped.";
      const what=el("td");const reason=el("div",undefined,"event-reason");reason.append(el("i","",`event-mark ${event.kind}`),document.createTextNode(event.reason));
      what.append(reason,el("p",event.detail,"event-detail"));
      const status=el("td");const label=event.kind==="pause"?"Monitoring gap":event.end_known===0?"Recovery unknown":event.end==null?"Ongoing":"Recovered";
      const badge=event.kind==="pause"||event.end_known===0?"neutral":event.end==null?(event.kind==="dns"?"warning":"active"):"";
      status.append(el("span",label,`badge ${badge}`));row.append(started,elapsed,what,status);body.append(row);
    }
    $("load-more").hidden=data.events.length>=data.event_count;
    $("load-more").textContent=`Show older events (${data.event_count-data.events.length} more)`;
  }

  function geometry() {
    const rect=canvas.getBoundingClientRect(), width=Math.max(1,rect.width), height=Math.max(1,rect.height);
    const left=51,right=17,top=22,bottom=36;
    const end=data?.now??Date.now()/1000, start=end-Number(range.value);
    const maxLatency=Math.max(0,...(data?.points??[]).map(p=>p.smooth??0));
    const ymax=Math.max(100,Math.ceil(maxLatency/50)*50);
    return {width,height,left,right,top,bottom,start,end,ymax,x:ts=>left+(ts-start)/(end-start)*(width-left-right),y:ms=>height-bottom-ms/ymax*(height-top-bottom)};
  }

  function draw() {
    const g=geometry(),dpr=window.devicePixelRatio||1;
    canvas.width=Math.round(g.width*dpr);canvas.height=Math.round(g.height*dpr);ctx.setTransform(dpr,0,0,dpr,0,0);
    ctx.clearRect(0,0,g.width,g.height);ctx.font="12px -apple-system, BlinkMacSystemFont, sans-serif";
    ctx.textBaseline="middle";
    for(let n=0;n<=4;n++){const value=g.ymax*n/4,y=g.y(value);ctx.strokeStyle=colors.grid;ctx.lineWidth=1;ctx.beginPath();ctx.moveTo(g.left,y);ctx.lineTo(g.width-g.right,y);ctx.stroke();ctx.fillStyle=colors.text;ctx.textAlign="right";ctx.fillText(String(Math.round(value)),g.left-11,y);}
    ctx.fillStyle=colors.text;ctx.textAlign="left";ctx.fillText("ms",g.left-27,8);
    for(let n=0;n<=4;n++){const ts=g.start+(g.end-g.start)*n/4,x=g.x(ts);ctx.textAlign=n===0?"left":n===4?"right":"center";ctx.fillText(time(ts),x,g.height-13);}
    if(!data)return;
    ctx.save();ctx.beginPath();ctx.rect(g.left,g.top,g.width-g.left-g.right,g.height-g.top-g.bottom);ctx.clip();
    for(const band of data.bands){const x1=g.x(Math.max(g.start,band.start)),x2=g.x(Math.min(g.end,band.end??g.end));const w=Math.max(3,x2-x1);ctx.fillStyle=band.kind==="pause"?"#8e9aa613":band.kind==="dns"?"#eebc6815":"#ff777f19";ctx.fillRect(x1,g.top,w,g.height-g.top-g.bottom);ctx.fillStyle=band.kind==="pause"?"#8e9aa66b":band.kind==="dns"?colors.amber:colors.red;ctx.fillRect(x1,g.height-g.bottom-4,w,4);}
    const segments=[];let segment=[];let previous=null;
    for(const point of data.points){
      const broken=point.state==="offline"||point.state==="blocked"||point.smooth==null||(previous&&point.ts-previous.ts>data.step*2.5);
      if(broken&&segment.length){segments.push(segment);segment=[];}
      if(point.smooth!=null&&point.state!=="offline"&&point.state!=="blocked")segment.push(point);
      previous=point;
    }
    if(segment.length)segments.push(segment);
    const gradient=ctx.createLinearGradient(0,g.top,0,g.height-g.bottom);gradient.addColorStop(0,"#5dd6a529");gradient.addColorStop(1,"#5dd6a500");
    for(const part of segments){
      const first=part[0],last=part[part.length-1];
      ctx.beginPath();ctx.moveTo(g.x(first.ts),g.height-g.bottom);for(const p of part)ctx.lineTo(g.x(p.ts),g.y(p.smooth));ctx.lineTo(g.x(last.ts),g.height-g.bottom);ctx.closePath();ctx.fillStyle=gradient;ctx.fill();
      ctx.beginPath();part.forEach((p,i)=>i?ctx.lineTo(g.x(p.ts),g.y(p.smooth)):ctx.moveTo(g.x(p.ts),g.y(p.smooth)));ctx.strokeStyle=colors.green;ctx.lineWidth=1.75;ctx.lineJoin="round";ctx.stroke();
      ctx.beginPath();ctx.arc(g.x(last.ts),g.y(last.smooth),3.5,0,Math.PI*2);ctx.fillStyle=colors.green;ctx.fill();
    }
    if(hover){const x=g.x(hover.ts);ctx.strokeStyle="#94a3b175";ctx.lineWidth=1;ctx.setLineDash([3,4]);ctx.beginPath();ctx.moveTo(x,g.top);ctx.lineTo(x,g.height-g.bottom);ctx.stroke();ctx.setLineDash([]);}
    ctx.restore();
    const sampled=data.points.length;
    canvas.setAttribute("aria-label",`10-second median response time over ${range.selectedOptions[0].text.toLowerCase()}. ${sampled} graph points. ${data.bands.filter(e=>e.kind==="offline").length} check failures in view. Current response time ${data.latest?.latency==null?"unavailable":Math.round(data.latest.latency)+" milliseconds"}.`);
  }

  canvas.addEventListener("pointermove",event=>{
    if(!data?.points.length)return;
    const rect=canvas.getBoundingClientRect(),g=geometry(),px=event.clientX-rect.left;
    const ts=g.start+(px-g.left)/(g.width-g.left-g.right)*(g.end-g.start);
    let nearest=data.points[0];for(const point of data.points)if(Math.abs(point.ts-ts)<Math.abs(nearest.ts-ts))nearest=point;
    if(Math.abs(nearest.ts-ts)>Math.max(data.step*2,Number(range.value)/90)){$("tooltip").hidden=true;hover=null;draw();return;}
    hover=nearest;const tip=$("tooltip");const issue=data.bands.find(e=>nearest.ts>=e.start&&nearest.ts<=(e.end??data.now));
    tip.replaceChildren(el("small",`${date(nearest.ts)} · ${time(nearest.ts,true)}`),document.createTextNode(issue?.reason??(nearest.smooth==null?"No response":`${Math.round(nearest.smooth)} ms · 10-second median`)));
    tip.hidden=false;tip.style.left=`${Math.max(0,Math.min(g.width-tip.offsetWidth,px+12))}px`;tip.style.top=`${Math.max(0,event.clientY-rect.top-55)}px`;draw();
  });
  canvas.addEventListener("pointerleave",()=>{hover=null;$("tooltip").hidden=true;draw();});

  async function refresh() {
    if(location.protocol==="file:"){stopped();draw();return;}
    const id=++requestId;
    try{
      const response=await fetch(`/api/state?window=${range.value}&events=${eventLimit}`,{cache:"no-store",signal:AbortSignal.timeout(3500)});
      if(!response.ok)throw new Error("Monitor unavailable");const next=await response.json();
      if(next.service!=="local-network-monitor")throw new Error("Wrong server");
      if(id===requestId)render(next);
    }catch(error){if(id===requestId)stopped();}
  }
  range.addEventListener("change",()=>{hover=null;$("tooltip").hidden=true;refresh();});
  $("load-more").addEventListener("click",()=>{eventLimit+=100;refresh();});
  new ResizeObserver(()=>draw()).observe($("chart-wrap"));
  document.addEventListener("visibilitychange",()=>{if(!document.hidden)refresh();});
  // A test-only fixture is inserted in a separate verification page, never in the live dashboard.
  if(window.__NETWORK_MONITOR_VERIFICATION__){render(window.__NETWORK_MONITOR_VERIFICATION__);$("check-status").textContent="Verification data · not live";range.addEventListener("change",()=>{data.window=Number(range.value);render(data);$("check-status").textContent="Verification data · not live";});}
  else{refresh();setInterval(refresh,1000);}
})();
