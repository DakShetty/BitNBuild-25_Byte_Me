/* NourishNet backend (demo-ready)
   Run: cd backend && npm install && node server.js
*/

require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const http = require('http');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');

const app = express();
const server = http.createServer(app);
const { Server } = require('socket.io');
const io = new Server(server, { cors: { origin: "*" } });

app.use(cors());
app.use(bodyParser.json());

const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET || 'demo_jwt_secret';

// Postgres connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL || 'postgresql://postgres:postgres@localhost:5432/nourishnet'
});
async function q(text, params) {
  const c = await pool.connect();
  try { return await c.query(text, params); } finally { c.release(); }
}

// Basic init (run on start)
async function initDb() {
  await q(`CREATE TABLE IF NOT EXISTS vendors (
    id SERIAL PRIMARY KEY, name TEXT, email TEXT UNIQUE, password_hash TEXT,
    address TEXT, lat DOUBLE PRECISION, lon DOUBLE PRECISION, menu JSONB DEFAULT '[]', created_at TIMESTAMP DEFAULT now()
  );`);
  await q(`CREATE TABLE IF NOT EXISTS customers (
    id SERIAL PRIMARY KEY, name TEXT, email TEXT UNIQUE, password_hash TEXT,
    address TEXT, lat DOUBLE PRECISION, lon DOUBLE PRECISION, created_at TIMESTAMP DEFAULT now()
  );`);
  await q(`CREATE TABLE IF NOT EXISTS orders (
    id SERIAL PRIMARY KEY, customer_id INTEGER REFERENCES customers(id), vendor_id INTEGER REFERENCES vendors(id),
    items JSONB, customization JSONB, status TEXT DEFAULT 'pending', eta TIMESTAMP, driver_id TEXT, created_at TIMESTAMP DEFAULT now()
  );`);
  await q(`CREATE TABLE IF NOT EXISTS subscriptions (
    id SERIAL PRIMARY KEY, customer_id INTEGER REFERENCES customers(id), vendor_id INTEGER REFERENCES vendors(id),
    cadence TEXT, start_date DATE, end_date DATE, active BOOLEAN DEFAULT true, plan JSONB, created_at TIMESTAMP DEFAULT now()
  );`);
  await q(`CREATE TABLE IF NOT EXISTS drivers (
    id TEXT PRIMARY KEY, name TEXT, phone TEXT, lat DOUBLE PRECISION, lon DOUBLE PRECISION, available BOOLEAN DEFAULT true, created_at TIMESTAMP DEFAULT now()
  );`);
}
initDb().catch(console.error);

// Auth helpers (simple)
async function hashPass(p){ return await bcrypt.hash(p, 10); }
async function cmpPass(p, h){ return await bcrypt.compare(p,h); }
function genToken(payload){ return jwt.sign(payload, JWT_SECRET, { expiresIn: '12h' }); }
function authMiddleware(req,res,next){
  const a = req.headers.authorization;
  if(!a) return res.status(401).json({error:'Missing auth header'});
  const token = a.split(' ')[1];
  try{ req.user = jwt.verify(token, JWT_SECRET); next(); } catch(e){ return res.status(401).json({error:'Invalid token'}); }
}

// --- AUTH endpoints (vendor & customer) ---
app.post('/auth/vendor/register', async (req,res)=>{
  const {name,email,password,address,lat,lon} = req.body;
  if(!email||!password) return res.status(400).json({error:'email+password required'});
  try{
    const hp = await hashPass(password);
    const r = await q('INSERT INTO vendors (name,email,password_hash,address,lat,lon) VALUES ($1,$2,$3,$4,$5,$6) RETURNING id,name,email', [name,email,hp,address,lat,lon]);
    const user = r.rows[0];
    const token = genToken({id:user.id,type:'vendor'});
    res.json({user,token});
  }catch(e){
    console.error(e); res.status(500).json({error:'server error'});
  }
});

app.post('/auth/vendor/login', async (req,res)=>{
  const {email,password} = req.body;
  if(!email||!password) return res.status(400).json({error:'email+password required'});
  try{
    const r = await q('SELECT * FROM vendors WHERE email=$1', [email]);
    const v = r.rows[0];
    if(!v) return res.status(401).json({error:'invalid credentials'});
    const ok = await cmpPass(password, v.password_hash);
    if(!ok) return res.status(401).json({error:'invalid credentials'});
    const token = genToken({id:v.id,type:'vendor'});
    res.json({user:{id:v.id,name:v.name,email:v.email},token});
  }catch(e){ console.error(e); res.status(500).json({error:'server error'}); }
});

app.post('/auth/customer/register', async (req,res)=>{
  const {name,email,password,address,lat,lon} = req.body;
  if(!email||!password) return res.status(400).json({error:'email+password required'});
  try{
    const hp = await hashPass(password);
    const r = await q('INSERT INTO customers (name,email,password_hash,address,lat,lon) VALUES ($1,$2,$3,$4,$5,$6) RETURNING id,name,email', [name,email,hp,address,lat,lon]);
    const user = r.rows[0];
    const token = genToken({id:user.id,type:'customer'});
    res.json({user,token});
  }catch(e){ console.error(e); res.status(500).json({error:'server error'}); }
});

app.post('/auth/customer/login', async (req,res)=>{
  const {email,password} = req.body;
  if(!email||!password) return res.status(400).json({error:'email+password required'});
  try{
    const r = await q('SELECT * FROM customers WHERE email=$1', [email]);
    const c = r.rows[0];
    if(!c) return res.status(401).json({error:'invalid credentials'});
    const ok = await cmpPass(password, c.password_hash);
    if(!ok) return res.status(401).json({error:'invalid credentials'});
    const token = genToken({id:c.id,type:'customer'});
    res.json({user:{id:c.id,name:c.name,email:c.email},token});
  }catch(e){ console.error(e); res.status(500).json({error:'server error'}); }
});

// --- Vendor routes: menu, view subscribers/orders, assign driver, publish daily menu ---
app.post('/vendor/:vendorId/menu', authMiddleware, async (req,res)=>{
  if(req.user.type !== 'vendor' || req.user.id !== parseInt(req.params.vendorId)) return res.status(403).json({error:'forbidden'});
  const {menu} = req.body;
  try{
    await q('UPDATE vendors SET menu=$1 WHERE id=$2', [menu, req.user.id]);
    res.json({ok:true});
  }catch(e){ console.error(e); res.status(500).json({error:'server error'}); }
});

app.get('/vendor/:vendorId/orders', authMiddleware, async (req,res)=>{
  if(req.user.type !== 'vendor' || req.user.id !== parseInt(req.params.vendorId)) return res.status(403).json({error:'forbidden'});
  const r = await q('SELECT o.*, c.name as customer_name FROM orders o JOIN customers c ON o.customer_id=c.id WHERE o.vendor_id=$1 ORDER BY o.created_at DESC', [req.user.id]);
  res.json({orders: r.rows});
});

// assign driver to route + compute optimized route
app.post('/vendor/:vendorId/dispatch', authMiddleware, async (req,res)=>{
  if(req.user.type !== 'vendor' || req.user.id !== parseInt(req.params.vendorId)) return res.status(403).json({error:'forbidden'});
  // request contains driver_id (string) and order_ids: [1,2,3]
  const {driver_id, order_ids} = req.body;
  if(!driver_id || !Array.isArray(order_ids) || order_ids.length===0) return res.status(400).json({error:'driver_id + order_ids required'});
  try{
    // fetch order locations
    const sql = 'SELECT o.id, o.customer_id, c.address, c.lat, c.lon FROM orders o JOIN customers c ON o.customer_id=c.id WHERE o.id = ANY($1::int[])';
    const r = await q(sql, [order_ids]);
    const stops = r.rows.map(row => ({ id: row.id, customer_id: row.customer_id, lat: parseFloat(row.lat), lon: parseFloat(row.lon) }));
    // simple greedy nearest-neighbour TSP starting from driver (or vendor center) - demo only
    // get driver location; if not found use vendor lat/lon
    const drv = (await q('SELECT * FROM drivers WHERE id=$1', [driver_id])).rows[0];
    let start = drv ? {lat:drv.lat||stops[0]?.lat, lon:drv.lon||stops[0]?.lon} : stops[0];
    // nearest neighbor
    const route = [];
    const remaining = stops.slice();
    let cur = start;
    while(remaining.length){
      let bestIdx = 0;
      let bestDist = distance(cur, remaining[0]);
      for(let i=1;i<remaining.length;i++){
        const d = distance(cur, remaining[i]);
        if(d < bestDist){ bestDist = d; bestIdx = i; }
      }
      const next = remaining.splice(bestIdx,1)[0];
      route.push(next);
      cur = {lat: next.lat, lon: next.lon};
    }
    // save driver assignment & driver_id in orders
    for(const o of order_ids){
      await q('UPDATE orders SET driver_id=$1, status=$2 WHERE id=$3', [driver_id, 'dispatched', o]);
    }
    // send route to driver via socket and to vendor UI
    io.to(`driver-${driver_id}`).emit('route-assigned', {driver_id, route});
    io.to(`vendor-${req.user.id}`).emit('route-assigned', {driver_id, route});
    res.json({ok:true, route});
  }catch(e){ console.error(e); res.status(500).json({error:'server error'}); }
});

// small haversine-ish distance (approx) for greedy routing (not for production)
function distance(a,b){
  if(!a||!b) return 1e9;
  const R = 6371; // km
  const toRad = x => x * Math.PI / 180;
  const dLat = toRad(b.lat - a.lat);
  const dLon = toRad(b.lon - a.lon);
  const lat1 = toRad(a.lat);
  const lat2 = toRad(b.lat);
  const A = Math.sin(dLat/2)*Math.sin(dLat/2) + Math.cos(lat1)*Math.cos(lat2)*Math.sin(dLon/2)*Math.sin(dLon/2);
  const c = 2 * Math.atan2(Math.sqrt(A), Math.sqrt(1-A));
  return R * c;
}

// --- Orders (customer) ---
app.post('/customer/order', authMiddleware, async (req,res)=>{
  if(req.user.type !== 'customer') return res.status(403).json({error:'forbidden'});
  const customer_id = req.user.id;
  const {vendor_id, items, customization} = req.body;
  if(!vendor_id || !items) return res.status(400).json({error:'vendor + items required'});
  const eta = new Date(Date.now() + (30 + Math.floor(Math.random()*30)) * 60000); // 30-60 min demo
  try{
    const r = await q('INSERT INTO orders (customer_id, vendor_id, items, customization, eta) VALUES ($1,$2,$3,$4,$5) RETURNING *',
                      [customer_id, vendor_id, items, customization || {}, eta]);
    const order = r.rows[0];
    // emit to vendor room and optionally to assigned driver
    io.to(`vendor-${vendor_id}`).emit('new-order', order);
    res.json({order});
  }catch(e){ console.error(e); res.status(500).json({error:'server error'}); }
});

app.get('/customer/orders', authMiddleware, async (req,res)=>{
  if(req.user.type !== 'customer') return res.status(403).json({error:'forbidden'});
  const r = await q('SELECT o.*, v.name as vendor_name FROM orders o JOIN vendors v ON o.vendor_id=v.id WHERE o.customer_id=$1 ORDER BY o.created_at DESC', [req.user.id]);
  res.json({orders:r.rows});
});

// --- Subscriptions endpoints (demo, flexible) ---
app.post('/subscriptions', authMiddleware, async (req,res)=>{
  // create subscription: body {vendor_id, cadence: 'daily'|'weekly'|'monthly', plan: {...}, start_date}
  if(req.user.type !== 'customer') return res.status(403).json({error:'forbidden'});
  const {vendor_id, cadence, start_date, plan} = req.body;
  try{
    const r = await q('INSERT INTO subscriptions (customer_id, vendor_id, cadence, start_date, plan, active) VALUES ($1,$2,$3,$4,$5,$6) RETURNING *',
                      [req.user.id, vendor_id, cadence, start_date || new Date(), plan || {}, true]);
    res.json({subscription: r.rows[0]});
  }catch(e){ console.error(e); res.status(500).json({error:'server error'}); }
});

app.post('/subscriptions/:id/pause', authMiddleware, async (req,res)=>{
  if(req.user.type !== 'customer') return res.status(403).json({error:'forbidden'});
  const id = parseInt(req.params.id);
  try{
    await q('UPDATE subscriptions SET active=false WHERE id=$1 AND customer_id=$2', [id, req.user.id]);
    res.json({ok:true});
  }catch(e){ console.error(e); res.status(500).json({error:'server error'}); }
});

app.post('/subscriptions/:id/resume', authMiddleware, async (req,res)=>{
  if(req.user.type !== 'customer') return res.status(403).json({error:'forbidden'});
  const id = parseInt(req.params.id);
  try{
    await q('UPDATE subscriptions SET active=true WHERE id=$1 AND customer_id=$2', [id, req.user.id]);
    res.json({ok:true});
  }catch(e){ console.error(e); res.status(500).json({error:'server error'}); }
});

// --- Drivers: create / update location (drivers can be real devices sending location) ---
app.post('/drivers', async (req,res)=>{
  const {id,name,phone,lat,lon} = req.body;
  const driverId = id || uuidv4();
  try{
    await q('INSERT INTO drivers (id,name,phone,lat,lon,available) VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (id) DO UPDATE SET name=EXCLUDED.name, phone=EXCLUDED.phone, lat=EXCLUDED.lat, lon=EXCLUDED.lon, available=EXCLUDED.available',
          [driverId, name, phone, lat || null, lon || null, true]);
    res.json({driver_id: driverId});
  }catch(e){ console.error(e); res.status(500).json({error:'server error'}); }
});

// driver updates its position
app.post('/drivers/:driverId/position', async (req,res)=>{
  const driverId = req.params.driverId;
  const {lat, lon} = req.body;
  try{
    await q('UPDATE drivers SET lat=$1, lon=$2 WHERE id=$3', [lat, lon, driverId]);
    // broadcast to consumers / vendor who are interested
    io.to(`driver-${driverId}`).emit('position', {driverId, lat, lon});
    // If driver has assigned orders, broadcast new ETA approx (demo)
    const assigned = (await q('SELECT * FROM orders WHERE driver_id=$1 AND status IN ($2,$3,$4)', [driverId,'dispatched','preparing','onway'])).rows;
    for(const o of assigned){
      io.to(`customer-${o.customer_id}`).emit('order-position', {orderId:o.id, lat, lon, eta: o.eta});
    }
    res.json({ok:true});
  }catch(e){ console.error(e); res.status(500).json({error:'server error'}); }
});

// --- Socket.IO handling ---
io.on('connection', socket => {
  console.log('socket connected', socket.id);
  socket.on('join', room => {
    socket.join(room);
    console.log('joined', room);
  });
  // driver socket can emit position updates
  socket.on('driver-position', data => {
    if(data && data.driverId && data.lat && data.lon){
      io.to(`vendor-${data.vendorId}`).emit('driver-position', data);
      io.to(`customer-${data.customerId}`).emit('driver-position', data);
    }
  });
});

// Start server
server.listen(PORT, ()=> console.log(`NourishNet backend running on ${PORT}`));
