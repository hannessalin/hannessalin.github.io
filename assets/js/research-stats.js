fetch('/assets/data/research-stats.json',{cache:'no-store'})
.then(r=>{if(!r.ok)throw new Error();return r.json()})
.then(d=>{
  const set=(id,v)=>{const e=document.getElementById(id);if(e&&v!==undefined&&v!==null)e.textContent=v};
  set('citations',d.citations); set('h-index',d.h_index); set('i10-index',d.i10_index);
  set('publication-count',d.publications || 32);
  const u=document.getElementById('scholar-updated');
  if(u)u.textContent=(d.source==='sample'?'Preview data · ':'Google Scholar · ')+'updated '+d.updated;
}).catch(()=>{const u=document.getElementById('scholar-updated');if(u)u.textContent='Research metrics temporarily unavailable';});
