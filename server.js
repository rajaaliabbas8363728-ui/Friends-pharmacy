require("dotenv").config();
const express = require("express");
const session = require("express-session");
const SQLiteStore = require("connect-sqlite3")(session);
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const path = require("path");
const fs = require("fs");

const app = express();
const PORT = Number(process.env.PORT || 3000);
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || "Treviamet50@500";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "";
const SESSION_SECRET = process.env.SESSION_SECRET || "";
const WHATSAPP_NUMBER = (process.env.WHATSAPP_NUMBER || "923486864297").replace(/\D/g, "");

if (process.env.NODE_ENV === "production") {
  if (ADMIN_PASSWORD.length < 14 || ADMIN_PASSWORD.includes("CHANGE_THIS") ||
      SESSION_SECRET.length < 32 || SESSION_SECRET.includes("CHANGE_THIS")) {
    console.error("Production requires a strong ADMIN_PASSWORD (14+ chars) and SESSION_SECRET (32+ chars).");
    process.exit(1);
  }
  app.set("trust proxy", 1);
}

const dataDir = path.join(__dirname, "data");
fs.mkdirSync(dataDir, { recursive: true });
const sqlite3 = require("better-sqlite3");
const db = new sqlite3(path.join(dataDir, "pharmacy.sqlite"));
db.pragma("journal_mode = WAL");
db.exec(`CREATE TABLE IF NOT EXISTS products (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  description TEXT DEFAULT '',
  category TEXT DEFAULT 'General',
  price REAL NOT NULL CHECK(price >= 0),
  image_url TEXT DEFAULT '',
  available INTEGER NOT NULL DEFAULT 1
)`);
if (db.prepare("SELECT COUNT(*) n FROM products").get().n === 0) {
  const ins = db.prepare("INSERT INTO products(name,description,category,price,image_url,available) VALUES(?,?,?,?,?,1)");
  [
    ["Digital Thermometer", "Everyday health essential.", "Health essentials", 450, ""],
    ["Hand Sanitizer 100ml", "Hand hygiene gel, 100ml.", "Personal care", 180, ""],
    ["First Aid Bandages", "Assorted adhesive bandages.", "First aid", 120, ""]
  ].forEach(p => ins.run(...p));
}

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com", "data:"],
      imgSrc: ["'self'", "data:", "https:", "http:"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      connectSrc: ["'self'"],
      objectSrc: ["'none'"]
    }
  }
}));
app.use(express.json({limit:"100kb"}));
app.use(express.urlencoded({extended:false, limit:"20kb"}));
app.use(session({
  store: new SQLiteStore({db:"sessions.sqlite", dir:dataDir}),
  name: "friendspharmacy.sid",
  secret: SESSION_SECRET || "local-development-secret-only-change-before-deploy",
  resave:false,
  saveUninitialized:false,
  cookie:{httpOnly:true, sameSite:"lax", secure:process.env.NODE_ENV==="production", maxAge:8*60*60*1000}
}));
app.use(express.static(path.join(__dirname,"public")));

const loginLimiter = rateLimit({windowMs:15*60*1000, limit:8, standardHeaders:true, legacyHeaders:false});
const adminLimiter = rateLimit({windowMs:60*1000, limit:60, standardHeaders:true, legacyHeaders:false});
const clean = (v,max=500) => String(v ?? "").trim().slice(0,max);
function isAdmin(req,res,next) {
  if (req.session && req.session.isAdmin === true) return next();
  return res.status(401).json({error:"Admin login required."});
}
function validateProduct(body) {
  const name=clean(body.name,100), description=clean(body.description,500);
  const category=clean(body.category,60)||"General", image_url=clean(body.image_url,1000);
  const price=Number(body.price);
  const available=(body.available===false || body.available===0 || body.available==="0")?0:1;
  if (!name || !Number.isFinite(price) || price<0 || price>100000000) return null;
  if (image_url && !/^https?:\\/\\//i.test(image_url)) return null;
  return {name,description,category,image_url,price,available};
}

app.get("/api/config",(req,res)=>res.json({whatsappNumber:WHATSAPP_NUMBER}));
app.get("/api/products",(req,res)=>res.json(db.prepare("SELECT id,name,description,category,price,image_url,available FROM products ORDER BY id DESC").all()));
app.get("/api/admin/session",(req,res)=>res.json({authenticated:!!(req.session && req.session.isAdmin===true)}));
app.post("/api/admin/login",loginLimiter,(req,res)=>{
  const username=clean(req.body.username,100), password=String(req.body.password||"");
  if (!ADMIN_PASSWORD || username!==ADMIN_USERNAME || password!==ADMIN_PASSWORD) {
    return res.status(401).json({error:"Username or password is incorrect."});
  }
  req.session.regenerate(err=>{
    if(err) return res.status(500).json({error:"Could not start secure session."});
    req.session.isAdmin=true;
    req.session.save(err2=>{
      if(err2) return res.status(500).json({error:"Could not save admin session."});
      res.json({ok:true});
    });
  });
});
app.post("/api/admin/logout",isAdmin,(req,res)=>req.session.destroy(()=>{
  res.clearCookie("friendspharmacy.sid",{httpOnly:true,sameSite:"lax",secure:process.env.NODE_ENV==="production"});
  res.json({ok:true});
}));
app.use("/api/admin",adminLimiter);
app.post("/api/admin/products",isAdmin,(req,res)=>{
  const p=validateProduct(req.body);
  if(!p) return res.status(400).json({error:"Enter a product name and valid price. Image must be an http(s) URL."});
  const result=db.prepare("INSERT INTO products(name,description,category,price,image_url,available) VALUES(@name,@description,@category,@price,@image_url,@available)").run(p);
  res.status(201).json({id:Number(result.lastInsertRowid),...p});
});
app.put("/api/admin/products/:id",isAdmin,(req,res)=>{
  const id=Number(req.params.id), p=validateProduct(req.body);
  if(!Number.isInteger(id)||id<1||!p) return res.status(400).json({error:"Invalid product details."});
  const result=db.prepare("UPDATE products SET name=@name,description=@description,category=@category,price=@price,image_url=@image_url,available=@available WHERE id=@id").run({...p,id});
  if(!result.changes) return res.status(404).json({error:"Product not found."});
  res.json({id,...p});
});
app.delete("/api/admin/products/:id",isAdmin,(req,res)=>{
  const id=Number(req.params.id);
  if(!Number.isInteger(id)||id<1) return res.status(400).json({error:"Invalid product ID."});
  const result=db.prepare("DELETE FROM products WHERE id=?").run(id);
  if(!result.changes) return res.status(404).json({error:"Product not found."});
  res.json({ok:true});
});
app.get("/admin",(req,res)=>res.sendFile(path.join(__dirname,"public","admin.html")));
app.get("*",(req,res)=>res.sendFile(path.join(__dirname,"public","index.html")));
app.listen(PORT,()=>console.log(`Friends Pharmacy running on http://localhost:${PORT}`));
