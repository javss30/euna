// server.js
import express from "express";
import fs from "fs";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";

const app = express();
app.use(express.json());

const DATA_FILE = "./athletes.json";
const SECRET_KEY = "mysecretkey"; // change to env variable in production

// Load data from file or initialize empty
let athletes = [];
if (fs.existsSync(DATA_FILE)) {
  athletes = JSON.parse(fs.readFileSync(DATA_FILE));
}

// Save data to file
function saveData() {
  fs.writeFileSync(DATA_FILE, JSON.stringify(athletes, null, 2));
}

// ================= AUTH ROUTES =================

// Register athlete
app.post("/register", async (req, res) => {
  const { username, password, name, age, sport } = req.body;

  if (!username || !password) {
    return res.status(400).json({ message: "Username and password required" });
  }

  const existing = athletes.find(a => a.username === username);
  if (existing) {
    return res.status(400).json({ message: "Username already exists" });
  }

  const hashedPassword = await bcrypt.hash(password, 10);

  const newAthlete = {
    id: Date.now(),
    username,
    password: hashedPassword,
    name,
    age,
    sport
  };

  athletes.push(newAthlete);
  saveData();

  res.json({ message: "Athlete registered successfully" });
});

// Login athlete
app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  const athlete = athletes.find(a => a.username === username);

  if (!athlete) return res.status(400).json({ message: "User not found" });

  const valid = await bcrypt.compare(password, athlete.password);
  if (!valid) return res.status(401).json({ message: "Invalid password" });

  const token = jwt.sign({ id: athlete.id }, SECRET_KEY, { expiresIn: "1h" });
  res.json({ token });
});

// Middleware to check auth
function authenticate(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ message: "No token provided" });

  const token = authHeader.split(" ")[1];
  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) return res.status(403).json({ message: "Invalid token" });
    req.user = user;
    next();
  });
}

// ================= ATHLETE ROUTES =================

// Get all athletes
app.get("/athletes", authenticate, (req, res) => {
  res.json(athletes);
});

// ✅ Get specific athlete by ID
app.get("/athlete/:id", authenticate, (req, res) => {
  const id = parseInt(req.params.id);
  const athlete = athletes.find(a => a.id === id);

  if (!athlete) {
    return res.status(404).json({ message: "Athlete not found" });
  }

  res.json(athlete);
});

// ✅ Update athlete info (with password hashing if changed)
app.put("/athletes/:id", authenticate, async (req, res) => {
  const id = parseInt(req.params.id);
  const athlete = athletes.find(a => a.id === id);

  if (!athlete) return res.status(404).json({ message: "Athlete not found" });

  // If password is being updated, hash it before saving
  if (req.body.password) {
    req.body.password = await bcrypt.hash(req.body.password, 10);
  }

  Object.assign(athlete, req.body);
  saveData();

  res.json({ message: "Athlete updated", athlete });
});

// Delete athlete
app.delete("/athletes/:id", authenticate, (req, res) => {
  const id = parseInt(req.params.id);
  const index = athletes.findIndex(a => a.id === id);

  if (index === -1) return res.status(404).json({ message: "Athlete not found" });

  athletes.splice(index, 1);
  saveData();

  res.json({ message: "Athlete deleted" });
});

// ================= START SERVER =================
const PORT = 3000;
app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
