const express = require("express");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());

const users = [];

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString("hex");
  const hash = crypto
    .pbkdf2Sync(password, salt, 100000, 64, "sha512")
    .toString("hex");
  return `${salt}:${hash}`;
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

app.post("/api/signup", (req, res) => {
  const { username, email, password } = req.body;

  if (!username || !email || !password) {
    return res.status(400).json({
      message: "username, email, and password are required",
    });
  }

  if (typeof username !== "string" || username.trim().length < 3) {
    return res.status(400).json({
      message: "username must be at least 3 characters",
    });
  }

  if (typeof password !== "string" || password.length < 6) {
    return res.status(400).json({
      message: "password must be at least 6 characters",
    });
  }

  if (typeof email !== "string" || !isValidEmail(email)) {
    return res.status(400).json({
      message: "email is not valid",
    });
  }

  const normalizedUsername = username.trim();
  const normalizedEmail = email.trim().toLowerCase();

  const usernameExists = users.some(
    (user) => user.username.toLowerCase() === normalizedUsername.toLowerCase()
  );
  if (usernameExists) {
    return res.status(409).json({ message: "username already exists" });
  }

  const emailExists = users.some((user) => user.email === normalizedEmail);
  if (emailExists) {
    return res.status(409).json({ message: "email already exists" });
  }

  const newUser = {
    id: users.length + 1,
    username: normalizedUsername,
    email: normalizedEmail,
    passwordHash: hashPassword(password),
    createdAt: new Date().toISOString(),
  };

  users.push(newUser);

  return res.status(201).json({
    message: "signup successful",
    user: {
      id: newUser.id,
      username: newUser.username,
      email: newUser.email,
      createdAt: newUser.createdAt,
    },
  });
});

app.get("/", (req, res) => {
  res.json({ message: "Signup API is running" });
});

app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
