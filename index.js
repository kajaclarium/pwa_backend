import express from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { createClient } from "@supabase/supabase-js";
import dotenv from "dotenv";
import cors from "cors";
dotenv.config();

const app = express();


const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY,
  {
    auth: { autoRefreshToken: false, persistSession: false },
  }
);


const allowedOrigins = [
  "http://localhost:5173",
  "https://kajaclarium.github.io"
];

app.set("trust proxy", 1);

app.use(cors({
  origin: (origin, callback) => {
    // allow server-to-server / Postman
    if (!origin) return callback(null, true);

    if (allowedOrigins.includes(origin)) {
      return callback(null, true);
    }

    return callback(new Error("CORS not allowed"));
  },
  credentials: true,
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"]
}));

// // Optional: Handle preflight requests explicitly
// app.options("/*", cors({
//   origin: allowedOrigins,
//   credentials: true,
//   methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
//   allowedHeaders: ["Content-Type", "Authorization"]
// }));

app.use(express.json());


const JWT_SECRET = process.env.JWT_SECRET || "YOUR_SECRET_KEY"; // Use environment variable

/* ---------------------------------------
      AUTHENTICATION MIDDLEWARE
---------------------------------------- */
function auth(req, res, next) {
  const header = req.headers.authorization;

  if (!header) return res.status(401).json({ message: "No token" });

  const token = header.split(" ")[1];

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (err) {
    return res.status(401).json({ message: "Invalid token" });
  }
}

/* ---------------------------------------
      REGISTER ROUTE
---------------------------------------- */
app.post("/auth/register", async (req, res) => {
  const { email, password, username } = req.body;


  // Insert Supabase Auth user
  const { data: authUser, error } = await supabase.auth.admin.createUser({
    email,
    password: password,
    email_confirm: true,
  });

  if (error) return res.status(400).json({ message: error.message });

  // Insert into profiles table with default role = "user"
  await supabase.from("profiles").insert({
    id: authUser.user.id,
    email,
    username,
    role: "user",
  });

  res.json({ message: "User registered" });
});

/* ---------------------------------------
      LOGIN ROUTE
---------------------------------------- */
app.post("/auth/login", async (req, res) => {
  const { email, password } = req.body;

  const result = await supabase.auth.signInWithPassword({
    email,
    password,
    email_confirm: true,
  });

  if (result.error || !result.data?.user) {
    return res.status(401).json({ message: "Invalid credentials" });
  }

  const supabaseUser = result.data.user;



  // Fetch profile
  const { data: profile, error: profileError } = await supabase
    .from("profiles")
    .select("*")
    .eq("id", supabaseUser.id)
    .single();

  if (profileError || !profile) {
    return res.status(500).json({ message: "Profile not found" });
  }

  // Generate your JWT
  const token = jwt.sign(
    {
      id: profile.id,
      email: profile.email,
      role: profile.role
    },
    JWT_SECRET,
    { expiresIn: "7d" }
  );

  res.json({
    token,
    user: {
      id: profile.id,
      email: profile.email,
      username: profile.username,
      role: profile.role
    }
  });
});


/* ---------------------------------------
      PROTECTED ROUTE: PROFILE
---------------------------------------- */
app.get("/auth/me", auth, async (req, res) => {
  const { data, error } = await supabase
    .from("profiles")
    .select("*")
    .eq("id", req.user.id)
    .single();

  if (error || !data) {
    return res.status(500).json({ message: "Profile not found" });
  }

  res.json({ user: data });
});

/* ---------------------------------------
      ADMIN ROUTE: VIEW ALL USERS
---------------------------------------- */
app.get("/admin/all-users", auth, async (req, res) => {
  if (req.user.role !== "admin") {
    return res.status(403).json({ message: "Not allowed" });
  }

  const { data, error } = await supabase.from("profiles").select("*");

  if (error || !data) {
    return res.status(500).json({ message: "Error fetching users" });
  }

  res.json(data);
});

/* ---------------------------------------
      ADMIN: CREATE USER
---------------------------------------- */
app.post("/admin/create-user", auth, async (req, res) => {
  // Only admin can create users
  if (req.user.role !== "admin") {
    return res.status(403).json({ message: "Not allowed" });
  }

  const { email, password, username, role } = req.body;

  if (!email || !password || !username || !role) {
    return res.status(400).json({ message: "All fields required" });
  }

  // 1️⃣ Create in Supabase Auth
  const { data: authUser, error: authError } = await supabase.auth.admin.createUser({
    email,
    password,
    email_confirm: true,
  });

  if (authError) return res.status(400).json({ message: authError.message });

  // 2️⃣ Insert into profiles table
  const { error: profileError } = await supabase.from("profiles").insert({
    id: authUser.user.id,
    email,
    username,
    role, // admin or user
  });

  if (profileError) {
    return res.status(500).json({ message: "Profile insert failed" });
  }

  return res.json({ message: "User created successfully" });
});

/* ---------------------------------------
      ADMIN: UPDATE USER
---------------------------------------- */
app.put("/admin/update-user/:id", auth, async (req, res) => {
  // Only admin access
  if (req.user.role !== "admin") {
    return res.status(403).json({ message: "Not allowed" });
  }

  const { id } = req.params;
  const { email, username, role } = req.body;

  // 1️⃣ Update profile table
  const { error: updateError } = await supabase
    .from("profiles")
    .update({ email, username, role })
    .eq("id", id);

  if (updateError) {
    return res.status(400).json({ message: updateError.message });
  }

  // 2️⃣ If email changed, update Supabase Auth
  if (email) {
    const { error: authUpdateError } = await supabase.auth.admin.updateUserById(
      id,
      { email }
    );

    if (authUpdateError) {
      return res.status(400).json({ message: authUpdateError.message });
    }
  }

  return res.json({ message: "User updated successfully" });
});


/* ---------------------------------------
      SERVER START
---------------------------------------- */
// app.listen(5000, () => console.log("API running on port 5000"));

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
  console.log(`API running on port ${PORT}`);
});

