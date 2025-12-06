// index.js
const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
require("dotenv").config();
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");

const app = express();
const port = process.env.PORT || 5000;

// Middleware
app.use(cors());
app.use(express.json());

// MongoDB Connection
const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.xdad6f7.mongodb.net/?appName=Cluster0`;
const client = new MongoClient(uri, {
  serverApi: { version: ServerApiVersion.v1, strict: true, deprecationErrors: true },
});

async function run() {
  try {
    await client.connect();
    console.log("Connected to MongoDB");

    const db = client.db("styledb");
    const usersCollection = db.collection("users");
    const servicesCollection = db.collection("services");
    const bookingsCollection = db.collection("bookings");

    // ===== AUTH =====

    // Register
    app.post("/api/register", async (req, res) => {
      try {
        const { name, email, password, role } = req.body;
        const hashedPassword = await bcrypt.hash(password, 10);

        const exists = await usersCollection.findOne({ email });
        if (exists) return res.status(400).send({ message: "User already exists" });

        const result = await usersCollection.insertOne({
          name,
          email,
          password: hashedPassword,
          role: role || "user",
        });

        res.status(201).send({ success: true, userId: result.insertedId });
      } catch (err) {
        console.error(err);
        res.status(500).send({ success: false });
      }
    });

    // Login
    app.post("/api/login", async (req, res) => {
      try {
        const { email, password } = req.body;
        const user = await usersCollection.findOne({ email });
        if (!user) return res.status(404).send({ message: "User not found" });

        const match = await bcrypt.compare(password, user.password);
        if (!match) return res.status(400).send({ message: "Invalid credentials" });

        const token = jwt.sign({ id: user._id, role: user.role, email: user.email }, process.env.JWT_SECRET, { expiresIn: "7d" });

        res.send({ token, user: { name: user.name, email: user.email, role: user.role } });
      } catch (err) {
        console.error(err);
        res.status(500).send({ success: false });
      }
    });

    // Middleware: Verify JWT
    const verifyToken = (req, res, next) => {
      const authHeader = req.headers.authorization;
      if (!authHeader) return res.status(401).send({ message: "Unauthorized" });

      const token = authHeader.split(" ")[1];
      jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) return res.status(403).send({ message: "Forbidden" });
        req.user = decoded;
        next();
      });
    };

    // ===== SERVICES =====

    // Get all services
    app.get("/api/services", async (req, res) => {
      try {
        const services = await servicesCollection.find({}).toArray();
        res.send(services);
      } catch (err) {
        console.error(err);
        res.status(500).send({ message: "Failed to fetch services" });
      }
    });

    // Create new service (Admin)
    app.post("/api/services", verifyToken, async (req, res) => {
      try {
        if (req.user.role !== "admin") return res.status(403).send({ message: "Forbidden" });
        const service = req.body;
        const result = await servicesCollection.insertOne(service);
        res.status(201).send({ success: true, serviceId: result.insertedId });
      } catch (err) {
        console.error(err);
        res.status(500).send({ success: false });
      }
    });

    // Update service
    app.put("/api/services/:id", verifyToken, async (req, res) => {
      try {
        if (req.user.role !== "admin") return res.status(403).send({ message: "Forbidden" });
        const id = req.params.id;
        const data = req.body;
        const result = await servicesCollection.updateOne({ _id: new ObjectId(id) }, { $set: data });
        res.send({ success: result.modifiedCount > 0 });
      } catch (err) {
        console.error(err);
        res.status(500).send({ success: false });
      }
    });

    // Delete service
    app.delete("/api/services/:id", verifyToken, async (req, res) => {
      try {
        if (req.user.role !== "admin") return res.status(403).send({ message: "Forbidden" });
        const id = req.params.id;
        const result = await servicesCollection.deleteOne({ _id: new ObjectId(id) });
        res.send({ success: result.deletedCount > 0 });
      } catch (err) {
        console.error(err);
        res.status(500).send({ success: false });
      }
    });

    // ===== BOOKINGS =====

    // Create booking
    app.post("/api/bookings", verifyToken, async (req, res) => {
      try {
        const booking = { ...req.body, userEmail: req.user.email, status: "Assigned" };
        const result = await bookingsCollection.insertOne(booking);
        res.status(201).send({ success: true, bookingId: result.insertedId });
      } catch (err) {
        console.error(err);
        res.status(500).send({ success: false });
      }
    });

    // Get user's bookings
    app.get("/api/bookings/user", verifyToken, async (req, res) => {
      try {
        const bookings = await bookingsCollection.find({ userEmail: req.user.email }).toArray();
        res.send(bookings);
      } catch (err) {
        console.error(err);
        res.status(500).send({ success: false });
      }
    });

    // Update booking status (Admin / Decorator)
    app.put("/api/bookings/:id", verifyToken, async (req, res) => {
      try {
        const id = req.params.id;
        const { status } = req.body;
        if (!["admin", "decorator"].includes(req.user.role)) return res.status(403).send({ message: "Forbidden" });
        const result = await bookingsCollection.updateOne({ _id: new ObjectId(id) }, { $set: { status } });
        res.send({ success: result.modifiedCount > 0 });
      } catch (err) {
        console.error(err);
        res.status(500).send({ success: false });
      }
    });

    // Delete booking (Admin)
    app.delete("/api/bookings/:id", verifyToken, async (req, res) => {
      try {
        if (req.user.role !== "admin") return res.status(403).send({ message: "Forbidden" });
        const id = req.params.id;
        const result = await bookingsCollection.deleteOne({ _id: new ObjectId(id) });
        res.send({ success: result.deletedCount > 0 });
      } catch (err) {
        console.error(err);
        res.status(500).send({ success: false });
      }
    });

    // ===== DECORATORS =====
    // Get all decorators
    app.get("/api/decorators", verifyToken, async (req, res) => {
      try {
        if (req.user.role !== "admin") return res.status(403).send({ message: "Forbidden" });
        const decorators = await usersCollection.find({ role: "decorator" }).toArray();
        res.send(decorators);
      } catch (err) {
        console.error(err);
        res.status(500).send({ success: false });
      }
    });

    // Make user a decorator
    app.put("/api/decorators/:id", verifyToken, async (req, res) => {
      try {
        if (req.user.role !== "admin") return res.status(403).send({ message: "Forbidden" });
        const id = req.params.id;
        const result = await usersCollection.updateOne({ _id: new ObjectId(id) }, { $set: { role: "decorator" } });
        res.send({ success: result.modifiedCount > 0 });
      } catch (err) {
        console.error(err);
        res.status(500).send({ success: false });
      }
    });

    // ===== DEFAULT ROUTE =====
    app.get("/", (req, res) => res.send("StyleDecor Backend Running"));

  } finally {
    // Nothing here
  }
}

run().catch(console.dir);

app.listen(port, () => console.log(`Server running on port ${port}`));
