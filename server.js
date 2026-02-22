const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();

/* ===============================
   🔥 MIDDLEWARE
================================ */
app.use(express.json());

/* ===============================
   🌍 ROOT ROUTE (Fix Cannot GET /)
================================ */
app.get("/", (req, res) => {
  res.send("🚀 Photo Booking API is running...");
});

/* ===============================
   🔥 MONGODB CONNECTION
================================ */
mongoose.connect("mongodb+srv://admin:9398718707@cluster0.afwzmes.mongodb.net/photoBookingDB")
.then(() => console.log("MongoDB Connected 🚀"))
.catch(err => console.log(err));

/* ===============================
   🔐 JWT SECRET
================================ */
const JWT_SECRET = "supersecretkey";

/* ===============================
   👤 USER SCHEMA
================================ */
const userSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    unique: true
  },
  password: {
    type: String,
    required: true
  }
}, { timestamps: true });

const User = mongoose.model("User", userSchema);

/* ===============================
   📦 BOOKING SCHEMA (USER LINKED)
================================ */
const bookingSchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true
  },
  name: {
    type: String,
    required: true,
    trim: true
  },
  event: {
    type: String,
    required: true,
    trim: true
  },
  date: {
    type: String,
    required: true
  }
}, { timestamps: true });

const Booking = mongoose.model("Booking", bookingSchema);

/* ===============================
   🔐 AUTH MIDDLEWARE
================================ */
const authMiddleware = (req, res, next) => {
  const authHeader = req.header("Authorization");

  if (!authHeader) {
    return res.status(401).json({ message: "Access denied. No token provided." });
  }

  try {
    const token = authHeader.split(" ")[1]; // Remove "Bearer"

    if (!token) {
      return res.status(401).json({ message: "Invalid token format" });
    }

    const verified = jwt.verify(token, JWT_SECRET);
    req.user = verified;
    next();

  } catch (error) {
    res.status(400).json({ message: "Invalid token" });
  }
};

/* ===============================
   📝 SIGNUP
================================ */
app.post("/signup", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: "Email and password required" });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: "User already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new User({
      email,
      password: hashedPassword
    });

    await newUser.save();

    res.status(201).json({ message: "User registered successfully!" });

  } catch (error) {
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
    if (!user) {
      return res.status(400).json({ message: "Invalid credentials" });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: "Invalid credentials" });
    }

    const token = jwt.sign(
      { userId: user._id },
      JWT_SECRET,
      { expiresIn: "1h" }
    );

    res.json({
      message: "Login successful!",
      token
    });

  } catch (error) {
    res.status(500).json({ message: "Login error" });
  }
});

/* ===============================
   🟢 CREATE BOOKING
================================ */
app.post("/book", authMiddleware, async (req, res) => {
  try {
    const { name, event, date } = req.body;

    if (!name || !event || !date) {
      return res.status(400).json({ message: "All fields are required" });
    }

    const newBooking = new Booking({
      user: req.user.userId,
      name,
      event,
      date
    });

    await newBooking.save();

    res.status(201).json({
      message: "Booking created successfully!",
      booking: newBooking
    });

  } catch (error) {
    res.status(500).json({ message: "Error creating booking" });
  }
});

/* ===============================
   🔵 GET BOOKINGS (ONLY OWNER)
================================ */
app.get("/bookings", authMiddleware, async (req, res) => {
  try {
    const bookings = await Booking.find({
      user: req.user.userId
    });

    res.json(bookings);

  } catch (error) {
    res.status(500).json({ message: "Error fetching bookings" });
  }
});

/* ===============================
   🟡 UPDATE BOOKING (ONLY OWNER)
================================ */
app.put("/bookings/:id", authMiddleware, async (req, res) => {
  try {
    const booking = await Booking.findOne({
      _id: req.params.id,
      user: req.user.userId
    });

    if (!booking) {
      return res.status(404).json({ message: "Booking not found or not authorized" });
    }

    booking.name = req.body.name;
    booking.event = req.body.event;
    booking.date = req.body.date;

    await booking.save();

    res.json({
      message: "Booking updated successfully!",
      booking
    });

  } catch (error) {
    res.status(500).json({ message: "Error updating booking" });
  }
});

/* ===============================
   🔴 DELETE BOOKING (ONLY OWNER)
================================ */
app.delete("/bookings/:id", authMiddleware, async (req, res) => {
  try {
    const deletedBooking = await Booking.findOneAndDelete({
      _id: req.params.id,
      user: req.user.userId
    });

    if (!deletedBooking) {
      return res.status(404).json({ message: "Booking not found or not authorized" });
    }

    res.json({ message: "Booking deleted successfully!" });

  } catch (error) {
    res.status(500).json({ message: "Error deleting booking" });
  }
});

/* ===============================
   🚀 SERVER
================================ */
app.listen(3001, () => {
  console.log("Server running on port 3001 🚀");
});