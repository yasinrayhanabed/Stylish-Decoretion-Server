// index.js
const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
require("dotenv").config();
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");

const app = express();
const port = process.env.PORT || 5000;

// Middleware
app.use(cors());
app.use(express.json());

// MongoDB Connection
const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.xdad6f7.mongodb.net/?retryWrites=true&w=majority`;
const client = new MongoClient(uri, {
  serverApi: { version: ServerApiVersion.v1, strict: true, deprecationErrors: true },
});

let usersCollection, servicesCollection, bookingsCollection;

async function run() {
  try {
    await client.connect();
    console.log("Connected to MongoDB");

    const db = client.db("styledb");
    usersCollection = db.collection("users");
    servicesCollection = db.collection("services");
    bookingsCollection = db.collection("bookings");

    // ===== AUTH =====
    app.post("/api/auth/register", async (req, res) => {
      try {
        const { name, email, password } = req.body;
        if (!name || !email || !password) {
          return res.status(400).json({ message: "Name, email and password are required" });
        }

        const exists = await usersCollection.findOne({ email });
        if (exists) return res.status(400).json({ message: "User already exists" });

        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = {
          name,
          email,
          password: hashedPassword,
          role: "user",
          createdAt: new Date(),
        };

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
          const doc = {
            name: name || "Google User",
            email,
            password: "",
            role: "user",
            googleId: uid || null,
            photo: photo || null,
            createdAt: new Date(),
          };
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

    // ===== MIDDLEWARE =====
    const verifyToken = (req, res, next) => {
      const authHeader = req.headers.authorization;
      if (!authHeader) return res.status(401).json({ message: "Unauthorized" });

      const token = authHeader.split(" ")[1];
      if (!token) return res.status(401).json({ message: "Unauthorized" });

      try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded;
        next();
      } catch (err) {
        return res.status(403).json({ message: "Invalid token" });
      }
    };

    // ===== SERVICES =====
    app.get("/api/services", async (req, res) => {
      try {
        const services = await servicesCollection.find({}).toArray();
        res.json(services);
      } catch (err) {
        console.error("Get services error:", err);
        res.status(500).json({ message: "Failed to fetch services" });
      }
    });

    app.get("/api/services/:id", async (req, res) => {
      try {
        const service = await servicesCollection.findOne({ _id: new ObjectId(req.params.id) });
        res.json(service);
      } catch (err) {
        console.error(err);
        res.status(500).json({ message: "Failed to fetch service" });
      }
    });

    app.post("/api/services", verifyToken, async (req, res) => {
      try {
        if (req.user.role !== "admin") return res.status(403).json({ message: "Forbidden" });
        const result = await servicesCollection.insertOne(req.body);
        res.status(201).json({ success: true, serviceId: result.insertedId });
      } catch (err) {
        console.error("Create service error:", err);
        res.status(500).json({ message: "Failed to create service" });
      }
    });

    app.put("/api/services/:id", verifyToken, async (req, res) => {
      try {
        if (req.user.role !== "admin") return res.status(403).json({ message: "Forbidden" });
        const result = await servicesCollection.updateOne({ _id: new ObjectId(req.params.id) }, { $set: req.body });
        res.json({ success: result.modifiedCount > 0 });
      } catch (err) {
        console.error("Update service error:", err);
        res.status(500).json({ message: "Failed to update service" });
      }
    });

    app.delete("/api/services/:id", verifyToken, async (req, res) => {
      try {
        if (req.user.role !== "admin") return res.status(403).json({ message: "Forbidden" });
        const result = await servicesCollection.deleteOne({ _id: new ObjectId(req.params.id) });
        res.json({ success: result.deletedCount > 0 });
      } catch (err) {
        console.error("Delete service error:", err);
        res.status(500).json({ message: "Failed to delete service" });
      }
    });

    // ===== BOOKINGS =====
    app.post("/api/bookings", verifyToken, async (req, res) => {
      try {
        const booking = { ...req.body, userId: req.user.id, userEmail: req.user.email, status: "Assigned", paymentStatus: "Pending", createdAt: new Date() };
        const result = await bookingsCollection.insertOne(booking);
        res.status(201).json({ success: true, bookingId: result.insertedId });
      } catch (err) {
        console.error("Create booking error:", err);
        res.status(500).json({ message: "Failed to create booking" });
      }
    });

    app.get("/api/bookings/user", verifyToken, async (req, res) => {
      try {
        const bookings = await bookingsCollection.find({ userEmail: req.user.email }).toArray();
        res.json(bookings);
      } catch (err) {
        console.error("Get user bookings error:", err);
        res.status(500).json({ message: "Failed to fetch bookings" });
      }
    });

    app.get("/api/bookings", verifyToken, async (req, res) => {
      try {
        if (req.user.role !== "admin") return res.status(403).json({ message: "Forbidden" });
        const bookings = await bookingsCollection.find({}).toArray();
        res.json(bookings);
      } catch (err) {
        console.error("Get bookings error:", err);
        res.status(500).json({ message: "Failed to fetch bookings" });
      }
    });

    app.put("/api/bookings/:id", verifyToken, async (req, res) => {
      try {
        if (!["admin", "decorator"].includes(req.user.role)) return res.status(403).json({ message: "Forbidden" });
        const result = await bookingsCollection.updateOne({ _id: new ObjectId(req.params.id) }, { $set: req.body });
        res.json({ success: result.modifiedCount > 0 });
      } catch (err) {
        console.error("Update booking error:", err);
        res.status(500).json({ message: "Failed to update booking" });
      }
    });

    app.delete("/api/bookings/:id", verifyToken, async (req, res) => {
      try {
        if (req.user.role !== "admin") return res.status(403).json({ message: "Forbidden" });
        const result = await bookingsCollection.deleteOne({ _id: new ObjectId(req.params.id) });
        res.json({ success: result.deletedCount > 0 });
      } catch (err) {
        console.error("Delete booking error:", err);
        res.status(500).json({ message: "Failed to delete booking" });
      }
    });

    // ===== DECORATORS =====
    app.get("/api/decorators", verifyToken, async (req, res) => {
      try {
        if (req.user.role !== "admin") return res.status(403).json({ message: "Forbidden" });
        const decorators = await usersCollection.find({ role: "decorator" }).toArray();
        res.json(decorators);
      } catch (err) {
        console.error("Get decorators error:", err);
        res.status(500).json({ message: "Failed to fetch decorators" });
      }
    });

    app.put("/api/decorators/:id", verifyToken, async (req, res) => {
      try {
        if (req.user.role !== "admin") return res.status(403).json({ message: "Forbidden" });
        const result = await usersCollection.updateOne({ _id: new ObjectId(req.params.id) }, { $set: { role: "decorator" } });
        res.json({ success: result.modifiedCount > 0 });
      } catch (err) {
        console.error("Make decorator error:", err);
        res.status(500).json({ message: "Failed to update user role" });
      }
    });

    // ===== DEFAULT =====
    app.get("/", (req, res) => res.send("StyleDecor Backend Running"));
  } finally {
    // client stays connected
  }
}

run().catch(console.dir);

app.listen(port, () => console.log(`Server running on port ${port}`));
