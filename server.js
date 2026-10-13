const http=require('http'),fs=require('fs'),path=require('path'),crypto=require('crypto');
const PORT=process.env.PORT||3000,DIR=process.env.DATA_DIR||path.join(__dirname,'data'),FILE=path.join(DIR,'santa.json');
fs.mkdirSync(DIR,{recursive:true});
let db;try{db=JSON.parse(fs.readFileSync(FILE,'utf8'))}catch(e){db={users:[],items:[],claims:[],draw:null,sessions:{}}}
const save=()=>{const t=FILE+'.tmp';fs.writeFileSync(t,JSON.stringify(db));fs.renameSync(t,FILE)};
const id=()=>crypto.randomBytes(6).toString('hex');
const hash=(pw,salt=crypto.randomBytes(8).toString('hex'))=>salt+':'+crypto.scryptSync(pw,salt,32).toString('hex');
const check=(pw,h)=>{const a=Buffer.from(hash(pw,h.split(':')[0])),b=Buffer.from(h);return a.length===b.length&&crypto.timingSafeEqual(a,b)};
const str=(v,n)=>typeof v==='string'?v.trim().slice(0,n):'';
const nameOf=i=>(db.users.find(u=>u.id===i)||{}).name||'?';
if(!db.users.length){const pw=process.env.ADMIN_PASSWORD||crypto.randomBytes(5).toString('hex');
  db.users.push({id:id(),name:process.env.ADMIN_NAME||'Admin',pw:hash(pw),admin:true});save();
  if(!process.env.ADMIN_PASSWORD)console.log('First-run admin password:',pw)}
function stateFor(u){
  const mine=db.items.filter(i=>i.owner===u.id).map(({id,title,note,link})=>({id,title,note,link}));
  const people=((db.draw&&db.draw[u.id])||[]).map(r=>({id:r,name:nameOf(r),
    items:db.items.filter(i=>i.owner===r).map(i=>{const c=db.claims.find(c=>c.itemId===i.id);
      return{id:i.id,title:i.title,note:i.note,link:i.link,claim:c?(c.by===u.id?'me':'other'):null,claimId:c&&c.by===u.id?c.id:null}}),
    extras:db.claims.filter(c=>c.owner===r&&!c.itemId).map(c=>({id:c.id,text:c.text,mine:c.by===u.id}))}));
  return{me:{id:u.id,name:u.name,admin:u.admin},items:mine,people,drawDone:!!db.draw,
    users:u.admin?db.users.map(x=>({id:x.id,name:x.name,admin:x.admin})):undefined};
}
function body(req){return new Promise((ok,no)=>{let d='',n=0;req.on('data',c=>{n+=c.length;if(n>1e5){no(new Error('big'));req.destroy()}else d+=c});
  req.on('end',()=>{try{ok(d?JSON.parse(d):{})}catch(e){no(e)}});req.on('error',no)})}
const send=(res,c,o)=>{res.writeHead(c,{'Content-Type':'application/json','Cache-Control':'no-store'});res.end(JSON.stringify(o))};
const tries={};
http.createServer(async(req,res)=>{
  const p=new URL(req.url,'http://x').pathname,m=req.method;
  if(!p.startsWith('/api/')){
    if(p==='/health'){res.writeHead(200);return res.end('ok')}
    return fs.readFile(path.join(__dirname,'index.html'),(e,d)=>{
      if(e){res.writeHead(500);return res.end('index.html missing')}
      res.writeHead(200,{'Content-Type':'text/html; charset=utf-8','Cache-Control':'no-store'});res.end(d)})}
  try{
    const b=(m==='GET'||m==='DELETE')?{}:await body(req),rt=p.slice(5);
    if(rt==='login'&&m==='POST'){
      const ip=(req.headers['x-forwarded-for']||req.socket.remoteAddress||'').split(',')[0].trim(),now=Date.now();
      let t=tries[ip];if(!t||now-t.t>6e4)t=tries[ip]={n:0,t:now};
      if(t.n>=8)return send(res,429,{error:'Too many tries. Wait a minute.'});
      const u=db.users.find(x=>x.name.toLowerCase()===str(b.name,50).toLowerCase());
      if(!u||!check(str(b.password,100),u.pw)){t.n++;return send(res,401,{error:'Wrong name or password.'})}
      for(const k in db.sessions)if(db.sessions[k].exp<now)delete db.sessions[k];
      const tok=crypto.randomBytes(24).toString('hex');db.sessions[tok]={uid:u.id,exp:now+30*864e5};save();
      return send(res,200,{token:tok})}
    const tok=(req.headers.authorization||'').replace('Bearer ','');const s=db.sessions[tok];
    const me=s&&s.exp>Date.now()&&db.users.find(x=>x.id===s.uid);
    if(!me)return send(res,401,{error:'Please sign in.'});
    const mine=()=>(db.draw&&db.draw[me.id])||[];let r;
    if(rt==='logout'&&m==='POST'){delete db.sessions[tok];save();return send(res,200,{})}
    if(rt==='state'&&m==='GET')return send(res,200,stateFor(me));
    if(rt==='item'&&m==='POST'){const title=str(b.title,100);if(!title)return send(res,400,{error:'Add a title.'});
      db.items.push({id:id(),owner:me.id,title,note:str(b.note,200),link:str(b.link,300)});save();return send(res,200,{})}
    if(r=rt.match(/^item\/(\w+)$/)){if(m!=='DELETE')return send(res,405,{});
      const it=db.items.find(i=>i.id===r[1]&&i.owner===me.id);if(!it)return send(res,404,{error:'Not found.'});
      db.claims.forEach(c=>{if(c.itemId===it.id){c.itemId=null;c.text=it.title}});
      db.items=db.items.filter(i=>i!==it);save();return send(res,200,{})}
    if(rt==='claim'&&m==='POST'){const it=db.items.find(i=>i.id===b.itemId);
      if(!it||!mine().includes(it.owner))return send(res,403,{error:'Not your person.'});
      if(db.claims.some(c=>c.itemId===it.id))return send(res,409,{error:'Someone already bought that one.'});
      db.claims.push({id:id(),owner:it.owner,itemId:it.id,text:'',by:me.id});save();return send(res,200,{})}
    if(rt==='extra'&&m==='POST'){const text=str(b.text,100);
      if(!text||!mine().includes(b.owner))return send(res,400,{error:'Check the details.'});
      db.claims.push({id:id(),owner:b.owner,itemId:null,text,by:me.id});save();return send(res,200,{})}
    if(r=rt.match(/^claim\/(\w+)$/)){if(m!=='DELETE')return send(res,405,{});
      db.claims=db.claims.filter(c=>!(c.id===r[1]&&c.by===me.id));save();return send(res,200,{})}
    if(rt==='user'&&m==='POST'){if(!me.admin)return send(res,403,{error:'Admin only.'});
      const name=str(b.name,50),pw=str(b.password,100);if(!name||pw.length<4)return send(res,400,{error:'Name needed, password at least 4 characters.'});
      const ex=db.users.find(x=>x.name.toLowerCase()===name.toLowerCase());
      if(ex)ex.pw=hash(pw);else db.users.push({id:id(),name,pw:hash(pw),admin:false});save();
      return send(res,200,{})}
    if(rt==='draw'&&m==='POST'){if(!me.admin)return send(res,403,{error:'Admin only.'});
      if(db.users.length<3)return send(res,400,{error:'Add at least 3 people first.'});
      const ids=db.users.map(u=>u.id);for(let i=ids.length-1;i>0;i--){const j=crypto.randomInt(i+1);[ids[i],ids[j]]=[ids[j],ids[i]]}
      const d={};ids.forEach((x,i)=>d[x]=[ids[(i+1)%ids.length],ids[(i+2)%ids.length]]);db.draw=d;db.claims=[];save();return send(res,200,{})}
    send(res,404,{error:'Not found.'});
  }catch(e){send(res,400,{error:'Bad request.'})}
}).listen(PORT,'0.0.0.0',()=>console.log('Secret Santa on port',PORT));
