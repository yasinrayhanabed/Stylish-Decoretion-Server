const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const multer = require("multer");
require("dotenv").config();
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const path = require("path");
const fs = require("fs");

const app = express();
const port = process.env.PORT || 5000;

// ===== Multer setup for image upload =====
const uploadDir = path.join(__dirname, "uploads");
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir);

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    const name = Date.now() + "-" + Math.round(Math.random() * 1e9) + ext;
    cb(null, name);
  },
});
const upload = multer({ storage });


if (!process.env.DB_USER || !process.env.DB_PASS || !process.env.DB_NAME) {
  console.warn("WARNING: Missing DB credentials (DB_USER, DB_PASS, DB_NAME) in .env");
}
if (!process.env.JWT_SECRET) {
  console.warn("WARNING: Missing JWT_SECRET in .env — generate a long random string for security");
}

// Middleware
app.use(cors());
app.use(express.json());
app.use("/uploads", express.static(uploadDir)); // serve uploaded images

// MongoDB Connection (Atlas)
const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.xdad6f7.mongodb.net/?retryWrites=true&w=majority`;
const client = new MongoClient(uri, {
  serverApi: { version: ServerApiVersion.v1, strict: true, deprecationErrors: true },
});

let usersCollection, servicesCollection, bookingsCollection;

async function run() {
  try {
    await client.connect();
    console.log("Connected to MongoDB");

    const db = client.db(process.env.DB_NAME || "style-decor");
    usersCollection = db.collection("users");
    servicesCollection = db.collection("services");
    bookingsCollection = db.collection("bookings");

    // ===== AUTH =====
    app.post("/api/auth/register", async (req, res) => {
      try {
        const { name, email, password } = req.body;
        if (!name || !email || !password)
          return res.status(400).json({ message: "Name, email and password are required" });

        const exists = await usersCollection.findOne({ email });
        if (exists) return res.status(400).json({ message: "User already exists" });

        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = { name, email, password: hashedPassword, role: "user", createdAt: new Date() };
        const result = await usersCollection.insertOne(newUser);

        const insertedUser = await usersCollection.findOne(
          { _id: result.insertedId },
          { projection: { password: 0 } }
        );

        const token = jwt.sign(
          { id: insertedUser._id.toString(), email: insertedUser.email, role: insertedUser.role, name: insertedUser.name },
          process.env.JWT_SECRET,
          { expiresIn: "7d" }
        );

        res.status(201).json({ token, user: insertedUser });
      } catch (err) {
        console.error("Register error:", err);
        res.status(500).json({ message: "Registration failed" });
      }
    });

    app.post("/api/auth/login", async (req, res) => {
      try {
        const { email, password } = req.body;
        if (!email || !password) return res.status(400).json({ message: "Email and password required" });

        const user = await usersCollection.findOne({ email });
        if (!user) return res.status(404).json({ message: "User not found" });

        if (!user.password) return res.status(400).json({ message: "Please login with Google" });

        const match = await bcrypt.compare(password, user.password || "");
        if (!match) return res.status(400).json({ message: "Invalid credentials" });

        const safeUser = { ...user };
        delete safeUser.password;

        const token = jwt.sign(
          { id: user._id.toString(), email: user.email, role: user.role, name: user.name },
          process.env.JWT_SECRET,
          { expiresIn: "7d" }
        );

        res.json({ token, user: safeUser });
      } catch (err) {
        console.error("Login error:", err);
        res.status(500).json({ message: "Login failed" });
      }
    });

    app.post("/api/auth/google-login", async (req, res) => {
      try {
        const { name, email, photo, uid } = req.body;
        if (!email) return res.status(400).json({ message: "Invalid Google user data" });

        let user = await usersCollection.findOne({ email });

        if (!user) {
          const randomSeed = uid || Math.random().toString(36).slice(2, 10);
          const tempPasswordHash = await bcrypt.hash(randomSeed, 10);
          const doc = { name: name || "Google User", email, password: tempPasswordHash, role: "user", googleId: uid || null, photo: photo || null, createdAt: new Date() };
          const insertRes = await usersCollection.insertOne(doc);
          user = await usersCollection.findOne({ _id: insertRes.insertedId }, { projection: { password: 0 } });
        } else {
          user = { ...user };
          delete user.password;
        }

        const token = jwt.sign(
          { id: user._id.toString(), email: user.email, role: user.role, name: user.name },
          process.env.JWT_SECRET,
          { expiresIn: "7d" }
        );

        res.json({ token, user });
      } catch (err) {
        console.error("Google login error:", err);
        res.status(500).json({ message: "Google login failed" });
      }
    });

    // ===== Middleware =====
    const verifyToken = (req, res, next) => {
      const authHeader = req.headers.authorization || req.headers.Authorization;
      if (!authHeader) return res.status(401).json({ message: "Unauthorized" });

      const token = authHeader.split(" ")[1] || authHeader;
      if (!token) return res.status(401).json({ message: "Unauthorized" });

      try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded;
        next();
      } catch (err) {
        console.error("JWT verify error:", err);
        return res.status(403).json({ message: "Invalid token" });
      }
    };

    const requireRole = (allowedRoles = []) => (req, res, next) => {
      if (!req.user) return res.status(401).json({ message: "Unauthorized" });
      if (!allowedRoles.includes(req.user.role)) return res.status(403).json({ message: "Forbidden" });
      next();
    };

    // ===== SERVICES =====
    app.get("/api/services", async (req, res) => {
      try {
        const q = {};
        const { search, category, sort } = req.query;
        if (search) q.$or = [
          { service_name: { $regex: search, $options: "i" } },
          { description: { $regex: search, $options: "i" } },
          { category: { $regex: search, $options: "i" } },
        ];
        if (category) q.category = category;

        let cursor = servicesCollection.find(q);
        if (sort === "cost_asc") cursor = cursor.sort({ cost: 1 });
        if (sort === "cost_desc") cursor = cursor.sort({ cost: -1 });

        const services = await cursor.toArray();
        res.json(services);
      } catch (err) {
        console.error("Get services error:", err);
        res.status(500).json({ message: "Failed to fetch services" });
      }
    });

    app.get("/api/services/:id", async (req, res) => {
      try {
        const id = req.params.id;
        if (!ObjectId.isValid(id)) return res.status(400).json({ message: "Invalid id" });
        const service = await servicesCollection.findOne({ _id: new ObjectId(id) });
        if (!service) return res.status(404).json({ message: "Service not found" });
        res.json(service);
      } catch (err) {
        console.error("Get service error:", err);
        res.status(500).json({ message: "Failed to fetch service" });
      }
    });

    // ===== Add service with photo =====
    app.post("/api/services", verifyToken, requireRole(["admin"]), upload.single("photo"), async (req, res) => {
      try {
        const doc = req.body;
        if (req.file) doc.images = [ `/uploads/${req.file.filename}` ]
        doc.createdAt = new Date();
        doc.createdBy = req.user.id;
        const result = await servicesCollection.insertOne(doc);
        res.status(201).json({ success: true, serviceId: result.insertedId });
      } catch (err) {
        console.error("Create service error:", err);
        res.status(500).json({ message: "Failed to create service" });
      }
    });

    app.put("/api/services/:id", verifyToken, requireRole(["admin"]), async (req, res) => {
      try {
        const id = req.params.id;
        if (!ObjectId.isValid(id)) return res.status(400).json({ message: "Invalid id" });
        const data = req.body;
        const result = await servicesCollection.updateOne({ _id: new ObjectId(id) }, { $set: data });
        res.json({ success: result.modifiedCount > 0 });
      } catch (err) {
        console.error("Update service error:", err);
        res.status(500).json({ message: "Failed to update service" });
      }
    });

    app.delete("/api/services/:id", verifyToken, requireRole(["admin"]), async (req, res) => {
      try {
        const id = req.params.id;
        if (!ObjectId.isValid(id)) return res.status(400).json({ message: "Invalid id" });
        const result = await servicesCollection.deleteOne({ _id: new ObjectId(id) });
        res.json({ success: result.deletedCount > 0 });
      } catch (err) {
        console.error("Delete service error:", err);
        res.status(500).json({ message: "Failed to delete service" });
      }
    });

    // ===== BOOKINGS =====
    app.post("/api/bookings", verifyToken, async (req, res) => {
      try {
        const booking = { ...req.body, userId: req.user.id, userEmail: req.user.email, status: "Assigned", paymentStatus: "pending", createdAt: new Date() };
        const result = await bookingsCollection.insertOne(booking);
        res.status(201).json({ success: true, bookingId: result.insertedId });
      } catch (err) {
        console.error("Create booking error:", err);
        res.status(500).json({ message: "Failed to create booking" });
      }
    });

    app.get("/api/bookings/my", verifyToken, async (req, res) => {
      try {
        const bookings = await bookingsCollection.find({ userId: req.user.id }).toArray();
        res.json(bookings);
      } catch (err) {
        console.error("Get user bookings error:", err);
        res.status(500).json({ message: "Failed to fetch bookings" });
      }
    });

    app.get("/api/bookings/my/:userId", verifyToken, async (req, res) => {
      try {
        const { userId } = req.params;
        if (req.user.id !== userId && req.user.role !== "admin" && req.user.role !== "decorator") return res.status(403).json({ message: "Forbidden" });
        const bookings = await bookingsCollection.find({ userId }).toArray();
        res.json(bookings);
      } catch (err) {
        console.error("Get user bookings by id error:", err);
        res.status(500).json({ message: "Failed to fetch user bookings" });
      }
    });

    app.get("/api/bookings", verifyToken, requireRole(["admin"]), async (req, res) => {
      try {
        const bookings = await bookingsCollection.find().toArray();
        res.json(bookings);
      } catch (err) {
        console.error("Get bookings error:", err);
        res.status(500).json({ message: "Failed to fetch bookings" });
      }
    });

    app.put("/api/bookings/:id", verifyToken, async (req, res) => {
      try {
        const id = req.params.id;
        const data = req.body;
        if (!["admin", "decorator"].includes(req.user.role)) return res.status(403).json({ message: "Forbidden" });
        const result = await bookingsCollection.updateOne({ _id: new ObjectId(id) }, { $set: data });
        res.json({ success: result.modifiedCount > 0 });
      } catch (err) {
        console.error("Update booking error:", err);
        res.status(500).json({ message: "Failed to update booking" });
      }
    });

    app.delete("/api/bookings/:id", verifyToken, async (req, res) => {
      try {
        const id = req.params.id;
        const booking = await bookingsCollection.findOne({ _id: new ObjectId(id) });
        if (!booking) return res.status(404).json({ message: "Booking not found" });
        if (booking.userId !== req.user.id && req.user.role !== "admin") return res.status(403).json({ message: "Forbidden" });
        const result = await bookingsCollection.deleteOne({ _id: new ObjectId(id) });
        res.json({ success: result.deletedCount > 0 });
      } catch (err) {
        console.error("Delete booking error:", err);
        res.status(500).json({ message: "Failed to delete booking" });
      }
    });

    // ===== DECORATORS =====
    app.get("/api/decorators", verifyToken, requireRole(["admin"]), async (req, res) => {
      try {
        const decorators = await usersCollection.find({ role: "decorator" }).project({ password: 0 }).toArray();
        res.json(decorators);
      } catch (err) {
        console.error("Get decorators error:", err);
        res.status(500).json({ message: "Failed to fetch decorators" });
      }
    });

    app.put("/api/decorators/:id", verifyToken, requireRole(["admin"]), async (req, res) => {
      try {
        const id = req.params.id;
        const result = await usersCollection.updateOne({ _id: new ObjectId(id) }, { $set: { role: "decorator" } });
        res.json({ success: result.modifiedCount > 0 });
      } catch (err) {
        console.error("Make decorator error:", err);
        res.status(500).json({ message: "Failed to update user role" });
      }
    });

    app.get("/api/me", verifyToken, async (req, res) => {
      try {
        const user = await usersCollection.findOne({ _id: new ObjectId(req.user.id) }, { projection: { password: 0 } });
        if (!user) return res.status(404).json({ message: "User not found" });
        res.json(user);
      } catch (err) {
        console.error("Get me error:", err);
        res.status(500).json({ message: "Failed to fetch user" });
      }
    });

    // ===== DEFAULT =====
    app.get("/", (req, res) => res.send("StyleDecor Backend Running"));

  } finally {
   
  }
}

run().catch((err) => console.error("Fatal error starting server:", err));

app.listen(port, () => console.log(`Server running on port ${port}`));
