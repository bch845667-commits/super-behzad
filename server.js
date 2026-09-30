require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Database = require('better-sqlite3');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const JWT_SECRET = process.env.JWT_SECRET;
let ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const SMS_API_KEY = process.env.SMS_API_KEY || '';
const SMS_FROM = process.env.SMS_FROM || '';
const SMS_API_URL = process.env.SMS_API_URL || 'https://edge.ippanel.com/v1/api/send';
if (!JWT_SECRET || !ADMIN_PASSWORD) {
  console.error('Set JWT_SECRET and ADMIN_PASSWORD environment variables before starting.');
  process.exit(1);
}
const db = new Database(process.env.DB_FILE || path.join(__dirname,'store.db'));
db.pragma('journal_mode = WAL');
db.exec(`
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS products (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, category TEXT NOT NULL DEFAULT '', price INTEGER NOT NULL CHECK(price>=0), discount INTEGER NOT NULL DEFAULT 0 CHECK(discount BETWEEN 0 AND 90), stock INTEGER NOT NULL DEFAULT 999 CHECK(stock>=0), active INTEGER NOT NULL DEFAULT 1, created_at TEXT DEFAULT CURRENT_TIMESTAMP);

CREATE TABLE IF NOT EXISTS customers (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, phone TEXT NOT NULL, address TEXT NOT NULL DEFAULT '', vip INTEGER NOT NULL DEFAULT 0, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS orders (id TEXT PRIMARY KEY, customer_id INTEGER, status TEXT NOT NULL DEFAULT 'pending', subtotal INTEGER NOT NULL, discount INTEGER NOT NULL DEFAULT 0, total INTEGER NOT NULL, items_json TEXT NOT NULL, created_at TEXT DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY(customer_id) REFERENCES customers(id));
CREATE TABLE IF NOT EXISTS coupons (code TEXT PRIMARY KEY, percent INTEGER NOT NULL CHECK(percent BETWEEN 1 AND 90), active INTEGER NOT NULL DEFAULT 1, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS bundles (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, items_json TEXT NOT NULL, price INTEGER NOT NULL CHECK(price>=0), active INTEGER NOT NULL DEFAULT 1);
CREATE TABLE IF NOT EXISTS wheel_entries (id INTEGER PRIMARY KEY AUTOINCREMENT, phone TEXT NOT NULL UNIQUE, code TEXT NOT NULL UNIQUE, percent INTEGER NOT NULL, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS payments (id INTEGER PRIMARY KEY AUTOINCREMENT, order_id TEXT NOT NULL, provider TEXT NOT NULL, authority TEXT, ref_id TEXT, amount INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'initiated', created_at TEXT DEFAULT CURRENT_TIMESTAMP, verified_at TEXT);
`);
try { db.exec('ALTER TABLE products ADD COLUMN stock INTEGER NOT NULL DEFAULT 999'); } catch (e) { if (!String(e.message).includes('duplicate column')) throw e; }
try { db.exec("ALTER TABLE orders ADD COLUMN payment_status TEXT NOT NULL DEFAULT 'unpaid'"); } catch (e) { if (!String(e.message).includes('duplicate column')) throw e; }
const PAYMENT_PROVIDER = String(process.env.PAYMENT_PROVIDER || 'zarinpal').toLowerCase();
const ZARINPAL_MERCHANT_ID = String(process.env.ZARINPAL_MERCHANT_ID || '').trim();
const PAYMENT_CALLBACK_URL = String(process.env.PAYMENT_CALLBACK_URL || '').trim();
const ZARINPAL_SANDBOX = String(process.env.ZARINPAL_SANDBOX || 'false').toLowerCase() === 'true';
function zarinBase(){ return ZARINPAL_SANDBOX ? 'https://sandbox.zarinpal.com/pg/v4/payment' : 'https://api.zarinpal.com/pg/v4/payment'; }
function zarinStart(authority){ return ZARINPAL_SANDBOX ? `https://sandbox.zarinpal.com/pg/StartPay/${authority}` : `https://www.zarinpal.com/pg/StartPay/${authority}`; }
app.use(helmet({contentSecurityPolicy:false}));
app.use(express.json({limit:'100kb'}));
app.use(rateLimit({windowMs:15*60*1000,limit:250,standardHeaders:true,legacyHeaders:false}));
app.use(express.static(path.join(__dirname,'public')));

function auth(req,res,next){
  const token=(req.headers.authorization||'').replace(/^Bearer\s+/i,'');
  try { req.admin=jwt.verify(token,JWT_SECRET); next(); }
  catch { res.status(401).json({error:'ابتدا وارد مدیریت شوید.'}); }
}
const q=(sql)=>db.prepare(sql);
app.get('/api/health',(req,res)=>res.json({ok:true,database:'SQLite connected'}));
app.post('/api/admin/login',async(req,res)=>{
  const password=String(req.body?.password||'');
  const savedHash=q("SELECT value FROM settings WHERE key='adminPasswordHash'").get()?.value;
  const ok=savedHash ? await bcrypt.compare(password,savedHash) : password===ADMIN_PASSWORD;
  if(!ok) return res.status(401).json({error:'رمز مدیریت نادرست است.'});
  res.json({token:jwt.sign({role:'admin'},JWT_SECRET,{expiresIn:'8h'})});
});
app.get('/api/products',(req,res)=>res.json(q('SELECT id,name,category,price,discount,stock FROM products WHERE active=1 ORDER BY id DESC').all()));
app.get('/api/settings',(req,res)=>{ const rows=q("SELECT key,value FROM settings WHERE key IN ('storeName','address','phone','cardNumber')").all(); res.json(rows.reduce((a,x)=>(a[x.key]=x.value,a),{})); });
app.post('/api/admin/products/import',auth,(req,res)=>{
  const rows=req.body?.products;
  if(!Array.isArray(rows)||!rows.length||rows.length>1000) return res.status(400).json({error:'فهرست کالاها معتبر نیست.'});
  const count=q('SELECT COUNT(*) n FROM products').get().n;
  if(count>0) return res.status(409).json({error:'دیتابیس خالی نیست؛ واردکردن اولیه فقط یک بار مجاز است.'});
  const insert=q('INSERT INTO products(name,category,price,discount,stock) VALUES(?,?,?,?,?)');
  const tx=db.transaction(items=>{for(const p of items){const name=String(p.name||'').trim(),category=String(p.category||'متفرقه'),price=Number(p.price),discount=Number(p.discount||0);if(!name||!Number.isInteger(price)||price<0||!Number.isInteger(discount)||discount<0||discount>90) throw new Error('یکی از کالاها معتبر نیست.');insert.run(name,category,price,discount,Number.isInteger(Number(p.stock))&&Number(p.stock)>=0?Number(p.stock):999);}});
  try{tx(rows);res.status(201).json({ok:true,count:rows.length});}catch(e){res.status(400).json({error:e.message||'ورود کالاها انجام نشد.'});}
});
app.post('/api/admin/products',auth,(req,res)=>{
  const {name,category='',price,discount=0,stock=999}=req.body||{};
  if(!String(name||'').trim()||!Number.isInteger(Number(price))||Number(price)<0||!Number.isInteger(Number(discount))||discount<0||discount>90||!Number.isInteger(Number(stock))||Number(stock)<0) return res.status(400).json({error:'اطلاعات کالا معتبر نیست.'});
  const info=q('INSERT INTO products(name,category,price,discount,stock) VALUES(?,?,?,?,?)').run(name.trim(),category,Number(price),Number(discount),Number(stock));
  res.status(201).json(q('SELECT * FROM products WHERE id=?').get(info.lastInsertRowid));
});
app.patch('/api/admin/products/:id',auth,(req,res)=>{
  const {name,category,price,discount,stock,active}=req.body||{};
  const old=q('SELECT * FROM products WHERE id=?').get(req.params.id);
  if(!old) return res.status(404).json({error:'کالا پیدا نشد.'});
  const p=price===undefined?old.price:Number(price), d=discount===undefined?old.discount:Number(discount), s=stock===undefined?old.stock:Number(stock);
  if (!Number.isInteger(s)||s<0) return res.status(400).json({error:'موجودی معتبر نیست.'});
  if(!Number.isInteger(p)||p<0||!Number.isInteger(d)||d<0||d>90) return res.status(400).json({error:'قیمت یا تخفیف معتبر نیست.'});
  q('UPDATE products SET name=?,category=?,price=?,discount=?,stock=?,active=? WHERE id=?').run(name??old.name,category??old.category,p,d,s,active===undefined?old.active:(active?1:0),req.params.id);
  res.json(q('SELECT * FROM products WHERE id=?').get(req.params.id));
});
app.get('/api/admin/orders',auth,(req,res)=>res.json(q(`SELECT o.*,c.name customer_name,c.phone,c.address FROM orders o LEFT JOIN customers c ON c.id=o.customer_id ORDER BY o.created_at DESC LIMIT 300`).all()));
app.patch('/api/admin/orders/:id',auth,(req,res)=>{
  const allowed=['pending','confirmed','preparing','sent','completed','cancelled'];
  if(!allowed.includes(req.body?.status)) return res.status(400).json({error:'وضعیت سفارش نامعتبر است.'});
  const info=q('UPDATE orders SET status=? WHERE id=?').run(req.body.status,req.params.id);
  if(!info.changes) return res.status(404).json({error:'سفارش پیدا نشد.'});
  res.json({ok:true});
});
app.post('/api/orders',(req,res)=>{
  const {name,phone,address,items,coupon}=req.body||{};
  if(!String(name||'').trim()||!/^09\d{9}$/.test(String(phone||''))||!String(address||'').trim()||!Array.isArray(items)||!items.length) return res.status(400).json({error:'نام، موبایل، آدرس و اقلام سفارش را کامل کنید.'});
  let subtotal=0,clean=[];
  const get=q('SELECT id,name,price,discount,stock FROM products WHERE id=? AND active=1');
  for(const row of items){
    const p=get.get(Number(row.productId)),qty=Number(row.quantity);
    if(!p||!Number.isInteger(qty)||qty<1||qty>99) return res.status(400).json({error:'یکی از کالاها یا تعداد آن معتبر نیست.'});
    if(p.stock < qty) return res.status(409).json({error:`موجودی «${p.name}» کافی نیست. موجودی: ${p.stock}`});
    const unit=Math.round(p.price*(100-p.discount)/100);
    subtotal+=unit*qty; clean.push({productId:p.id,name:p.name,unitPrice:unit,quantity:qty});
  }
  let discount=0;
  if(coupon){const c=q('SELECT percent FROM coupons WHERE code=? AND active=1').get(String(coupon).trim().toUpperCase());if(c) discount=Math.round(subtotal*c.percent/100);}
  const total=Math.max(0,subtotal-discount);
  const customer=q('INSERT INTO customers(name,phone,address) VALUES(?,?,?)').run(name.trim(),phone,address.trim());
  const id=crypto.randomUUID();
  const tx=db.transaction(()=>{
    q('INSERT INTO orders(id,customer_id,subtotal,discount,total,items_json) VALUES(?,?,?,?,?,?)').run(id,customer.lastInsertRowid,subtotal,discount,total,JSON.stringify(clean));
    const dec=q('UPDATE products SET stock=stock-? WHERE id=? AND stock>=?');
    for(const x of clean){ const r=dec.run(x.quantity,x.productId,x.quantity); if(!r.changes) throw new Error('موجودی یکی از کالاها در لحظه ثبت سفارش کافی نبود.'); }
  });
  try { tx(); } catch(e) { q('DELETE FROM customers WHERE id=?').run(customer.lastInsertRowid); return res.status(409).json({error:e.message}); }
  res.status(201).json({orderId:id,subtotal,discount,total,status:'pending'});
});
app.post('/api/payments/zarinpal/request',async(req,res)=>{
  if(PAYMENT_PROVIDER!=='zarinpal') return res.status(400).json({error:'درگاه پرداخت تنظیم نشده است.'});
  if(!ZARINPAL_MERCHANT_ID) return res.status(503).json({error:'Merchant ID زرین‌پال هنوز در تنظیمات سرور وارد نشده است.'});
  if(!PAYMENT_CALLBACK_URL) return res.status(503).json({error:'آدرس Callback پرداخت هنوز تنظیم نشده است.'});
  const orderId=String(req.body?.orderId||'');
  const order=q('SELECT id,total,payment_status,status FROM orders WHERE id=?').get(orderId);
  if(!order) return res.status(404).json({error:'سفارش پیدا نشد.'});
  if(order.payment_status==='paid') return res.status(409).json({error:'این سفارش قبلاً پرداخت شده است.'});
  const amountRial=Math.max(1000,Math.round(Number(order.total)*10));
  try {
    const r=await fetch(`${zarinBase()}/request.json`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({merchant_id:ZARINPAL_MERCHANT_ID,amount:amountRial,description:`پرداخت سفارش سوپر بهزاد ${order.id}`,callback_url:PAYMENT_CALLBACK_URL})});
    const data=await r.json();
    const authority=data?.data?.authority;
    if(!authority) return res.status(502).json({error:'زرین‌پال درخواست پرداخت را نپذیرفت.',details:data?.errors||data});
    q('INSERT INTO payments(order_id,provider,authority,amount,status) VALUES(?,?,?,?,?)').run(order.id,'zarinpal',authority,amountRial,'initiated');
    res.json({ok:true,authority,paymentUrl:zarinStart(authority)});
  } catch(e) { res.status(502).json({error:'ارتباط با درگاه پرداخت برقرار نشد.',details:e.message}); }
});
app.get('/api/payments/zarinpal/callback',async(req,res)=>{
  const authority=String(req.query.Authority||'');
  const status=String(req.query.Status||'');
  const payment=q('SELECT * FROM payments WHERE authority=? ORDER BY id DESC LIMIT 1').get(authority);
  if(!payment) return res.status(404).send('پرداخت پیدا نشد.');
  if(status!=='OK') { q('UPDATE payments SET status=? WHERE id=?').run('cancelled',payment.id); return res.send('<meta charset=\"utf-8\"><h2>پرداخت لغو شد</h2><p>می‌توانید دوباره از فروشگاه اقدام کنید.</p>'); }
  try {
    const r=await fetch(`${zarinBase()}/verify.json`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({merchant_id:ZARINPAL_MERCHANT_ID,amount:payment.amount,authority})});
    const data=await r.json();
    const code=Number(data?.data?.code);
    if(code===100 || code===101) {
      const ref=String(data?.data?.ref_id||'');
      q('UPDATE payments SET status=?,ref_id=?,verified_at=CURRENT_TIMESTAMP WHERE id=?').run('paid',ref,payment.id);
      q("UPDATE orders SET payment_status='paid',status=CASE WHEN status='pending' THEN 'confirmed' ELSE status END WHERE id=?").run(payment.order_id);
      return res.send(`<meta charset=\"utf-8\"><meta http-equiv=\"refresh\" content=\"0;url=/\"><h2>پرداخت با موفقیت انجام شد</h2><p>کد پیگیری: ${ref||'ثبت شد'}</p>`);
    }
    q('UPDATE payments SET status=? WHERE id=?').run('failed',payment.id);
    res.status(400).send('<meta charset=\"utf-8\"><h2>تأیید پرداخت ناموفق بود</h2><p>وضعیت سفارش را در مدیریت بررسی کنید.</p>');
  } catch(e) { res.status(502).send('<meta charset=\"utf-8\"><h2>خطا در تأیید پرداخت</h2>'); }
});
app.get('/api/payments/:orderId',auth,(req,res)=>{ res.json(q('SELECT id,order_id,provider,authority,ref_id,amount,status,created_at,verified_at FROM payments WHERE order_id=? ORDER BY id DESC').all(req.params.orderId)); });
app.post('/api/admin/coupons',auth,(req,res)=>{
  const code=String(req.body?.code||'').trim().toUpperCase(),percent=Number(req.body?.percent);
  if(!/^[A-Z0-9_-]{3,32}$/.test(code)||!Number.isInteger(percent)||percent<1||percent>90) return res.status(400).json({error:'کد یا درصد نامعتبر است.'});
  q('INSERT INTO coupons(code,percent) VALUES(?,?) ON CONFLICT(code) DO UPDATE SET percent=excluded.percent,active=1').run(code,percent);
  res.status(201).json({code,percent});
});
app.get('/api/coupons/:code',(req,res)=>{
  const c=q('SELECT code,percent FROM coupons WHERE code=? AND active=1').get(String(req.params.code).toUpperCase());
  if(!c) return res.status(404).json({error:'کد معتبر نیست.'}); res.json(c);
});
app.post('/api/admin/bundles',auth,(req,res)=>{
  const {name,items,price}=req.body||{};
  if(!String(name||'').trim()||!Array.isArray(items)||!items.length||!Number.isInteger(Number(price))||Number(price)<0) return res.status(400).json({error:'اطلاعات پک معتبر نیست.'});
  const info=q('INSERT INTO bundles(name,items_json,price) VALUES(?,?,?)').run(name,JSON.stringify(items),Number(price));
  res.status(201).json({id:info.lastInsertRowid,name,items,price:Number(price)});
});
app.get('/api/bundles',(req,res)=>res.json(q('SELECT id,name,items_json,price FROM bundles WHERE active=1').all().map(x=>({...x,items:JSON.parse(x.items_json)}))));
app.post('/api/wheel/spin',(req,res)=>{
  const phone=String(req.body?.phone||'');
  if(!/^09\d{9}$/.test(phone)) return res.status(400).json({error:'شماره موبایل معتبر نیست.'});
  const opts=[5,10,15,20],percent=opts[crypto.randomInt(opts.length)],code='LUCKY'+percent+crypto.randomInt(1000,9999);
  try {db.transaction(()=>{q('INSERT INTO wheel_entries(phone,code,percent) VALUES(?,?,?)').run(phone,code,percent);q('INSERT INTO coupons(code,percent) VALUES(?,?)').run(code,percent);})(); }
  catch {return res.status(409).json({error:'این شماره قبلاً در گردونه شرکت کرده است.'});}
  res.json({code,percent});
});
app.post('/api/vip/join',(req,res)=>{
  const phone=String(req.body?.phone||''),name=String(req.body?.name||'مشتری');
  if(!/^09\d{9}$/.test(phone)) return res.status(400).json({error:'شماره موبایل معتبر نیست.'});
  const old=q('SELECT id FROM customers WHERE phone=? ORDER BY id DESC LIMIT 1').get(phone);
  if(old) q('UPDATE customers SET vip=1,name=? WHERE id=?').run(name,old.id); else q('INSERT INTO customers(name,phone,vip) VALUES(?,?,1)').run(name,phone);
  res.json({ok:true,message:'درخواست عضویت VIP ثبت شد.'});
});
app.post('/api/admin/sms/marketing',auth,async(req,res)=>{
  const message=String(req.body?.message||'').trim().slice(0,500);
  const audience=String(req.body?.audience||'all');
  if(!message) return res.status(400).json({error:'متن پیامک خالی است.'});
  if(!SMS_API_KEY || !SMS_FROM) return res.status(503).json({error:'سرویس پیامک هنوز تنظیم نشده است. SMS_API_KEY و SMS_FROM را در .env وارد کنید.'});
  const where=audience==='vip'?' WHERE vip=1':'';
  const customers=q(`SELECT DISTINCT phone FROM customers WHERE phone IS NOT NULL AND phone<>''${where}`).all();
  const recipients=customers.map(x=>String(x.phone).replace(/^0/,'+98')).filter(x=>/^\+989\d{9}$/.test(x));
  if(!recipients.length) return res.status(400).json({error:'شماره مشتری برای ارسال پیدا نشد.'});
  const r=await fetch(SMS_API_URL,{method:'POST',headers:{'Content-Type':'application/json','Authorization':SMS_API_KEY},body:JSON.stringify({sending_type:'webservice',from_number:SMS_FROM,message,params:{recipients}})});
  const data=await r.json().catch(()=>({}));
  if(!r.ok || data?.meta?.status===false) return res.status(502).json({error:data?.meta?.message||'ارسال پیامک ناموفق بود.'});
  res.json({ok:true,count:recipients.length,message:`پیامک برای ${recipients.length} مشتری ارسال شد.`});
});

app.get('/api/admin/settings',auth,(req,res)=>{
  res.json(q("SELECT key,value FROM settings WHERE key IN ('storeName','address','phone','cardNumber')").all().reduce((a,x)=>(a[x.key]=x.value,a),{}));
});
app.put('/api/admin/settings',auth,(req,res)=>{
  const allowed=['storeName','address','phone','cardNumber'];
  const put=q('INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value');
  for(const k of allowed) if(req.body?.[k]!==undefined) put.run(k,String(req.body[k]));
  res.json({ok:true});
});
app.get('/api/admin/stats',auth,(req,res)=>{
  const today=q("SELECT COALESCE(SUM(total),0) total, COUNT(*) count FROM orders WHERE date(created_at,'localtime')=date('now','localtime') AND status!='cancelled'").get();
  const all=q("SELECT COALESCE(SUM(total),0) total, COUNT(*) count FROM orders WHERE status!='cancelled'").get();
  const low=q('SELECT id,name,stock FROM products WHERE active=1 AND stock<=5 ORDER BY stock ASC,name LIMIT 30').all();
  const top=q(`SELECT json_extract(j.value,'$.name') name, SUM(json_extract(j.value,'$.quantity')) quantity FROM orders o, json_each(o.items_json) j WHERE o.status!='cancelled' GROUP BY name ORDER BY quantity DESC LIMIT 10`).all();
  res.json({today,all,low,top});
});
app.post('/api/admin/password',auth,async(req,res)=>{
  const pw=String(req.body?.password||'');
  if(pw.length<8) return res.status(400).json({error:'رمز جدید باید حداقل ۸ کاراکتر باشد.'});
  const hash=await bcrypt.hash(pw,12);
  q("INSERT INTO settings(key,value) VALUES('adminPasswordHash',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value").run(hash);
  ADMIN_PASSWORD=pw;
  res.json({ok:true,message:'رمز مدیریت ذخیره شد و بعد از راه‌اندازی مجدد سرور هم باقی می‌ماند.'});
});
app.listen(PORT,()=>console.log(`Super Behzad listening on port ${PORT}`));
