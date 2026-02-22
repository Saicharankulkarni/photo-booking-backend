const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");

const app = express();

/* ===============================
   🔥 MIDDLEWARE
================================ */
app.use(cors()); // Fix CORS error
app.use(express.json());

/* ===============================
   🌍 ROOT ROUTE
================================ */
app.get("/", (req, res) => {
  res.send("🚀 Photo Booking API is running...");
});

/* ===============================
   🔥 DATABASE CONNECTION
================================ */
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("MongoDB Connected 🚀"))
  .catch(err => console.log(err));

const JWT_SECRET = process.env.JWT_SECRET;

/* ===============================
   👤 USER SCHEMA
================================ */
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true }
}, { timestamps: true });

const User = mongoose.model("User", userSchema);

/* ===============================
   📦 BOOKING SCHEMA
================================ */
const bookingSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  name: { type: String, required: true },
  event: { type: String, required: true },
  date: { type: String, required: true }
}, { timestamps: true });

const Booking = mongoose.model("Booking", bookingSchema);

/* ===============================
   🔐 AUTH MIDDLEWARE
================================ */
const authMiddleware = (req, res, next) => {
  const authHeader = req.header("Authorization");

  if (!authHeader) {
    return res.status(401).json({ message: "No token provided" });
  }

  try {
    const token = authHeader.split(" ")[1];
    const verified = jwt.verify(token, JWT_SECRET);
    req.user = verified;
    next();
  } catch (err) {
    res.status(400).json({ message: "Invalid token" });
  }
};

/* ===============================
   📝 SIGNUP
================================ */
app.post("/signup", async (req, res) => {
  try {
    const { email, password } = req.body;

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: "User already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new User({ email, password: hashedPassword });
    await newUser.save();

    res.status(201).json({ message: "User registered successfully!" });

  } catch (err) {
    res.status(500).json({ message: "Signup error" });
  }
});

/* ===============================
   🔑 LOGIN
================================ */
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: "Invalid credentials" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ message: "Invalid credentials" });

    const token = jwt.sign({ userId: user._id }, JWT_SECRET, {
      expiresIn: "1h"
    });

    res.json({ message: "Login successful", token });

  } catch (err) {
    res.status(500).json({ message: "Login error" });
  }
});

/* ===============================
   🟢 CREATE BOOKING
================================ */
app.post("/book", authMiddleware, async (req, res) => {
  const { name, event, date } = req.body;

  const booking = new Booking({
    user: req.user.userId,
    name,
    event,
    date
  });

  await booking.save();
  res.json({ message: "Booking created", booking });
});

/* ===============================
   🔵 GET BOOKINGS
================================ */
app.get("/bookings", authMiddleware, async (req, res) => {
  const bookings = await Booking.find({ user: req.user.userId });
  res.json(bookings);
});

/* ===============================
   🚀 SERVER
================================ */
const PORT = process.env.PORT || 3001;

app.listen(PORT, () => {
  console.log("Server running 🚀");
});