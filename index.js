require("dotenv").config();
const mysql = require("mysql2/promise");
const express = require("express");
const path = require("path");
const crypto = require("crypto");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.static("public"));

const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
});

const KEY_PREFIX = "An4n_R4is_";
const JWT_SECRET = process.env.JWT_SECRET;

app.get("/generate-apikey", async (req, res) => {
  try {
    const randomToken = crypto.randomBytes(16).toString("hex");
    const newApiKey = KEY_PREFIX + randomToken;
    const sql =
      "INSERT INTO api_keys (api_key, expires_at) VALUES (?, NOW() + INTERVAL 30 DAY)";
    await pool.query(sql, [newApiKey]);
    console.log("Key baru dibuat (berlaku 30 hari):", newApiKey);
    res.json({ apiKey: newApiKey });
  } catch (error) {
    console.error("Error saat generate key:", error);
    res.status(500).json({ error: "Gagal membuat API key" });
  }
});

app.post("/api/register", async (req, res) => {
  const { firstname, lastname, email, apiKey } = req.body;
  if (!firstname || !lastname || !email || !apiKey) {
    return res.status(400).json({
      error: "Semua field (firstname, lastname, email, apiKey) dibutuhkan.",
    });
  }

  let connection;
  try {
    connection = await pool.getConnection();
    await connection.beginTransaction();

    const [keyRows] = await connection.query(
      "SELECT * FROM api_keys WHERE api_key = ? AND user_id IS NULL",
      [apiKey]
    );

    if (keyRows.length === 0) {
      await connection.rollback();
      return res.status(404).json({
        error: "API Key tidak valid, sudah digunakan, atau tidak ditemukan.",
      });
    }

    const userSql =
      "INSERT INTO users_apikey (firstname, lastname, email, start_date) VALUES (?, ?, ?, CURDATE())";
    const [userResult] = await connection.query(userSql, [
      firstname,
      lastname,
      email,
    ]);
    const newUserId = userResult.insertId;

    const apiKeyId = keyRows[0].id;
    const updateKeySql = "UPDATE api_keys SET user_id = ? WHERE id = ?";
    await connection.query(updateKeySql, [newUserId, apiKeyId]);

    await connection.commit();

    res.status(201).json({
      message: "User berhasil dibuat dan API Key terhubung!",
      user: { id: newUserId, firstname, lastname, email },
      apiKey: apiKey,
    });
  } catch (error) {
    if (connection) await connection.rollback();
    if (error.code === "ER_DUP_ENTRY") {
      res.status(409).json({ error: "Email sudah terdaftar." });
    } else {
      console.error("Error saat registrasi:", error);
      res.status(500).json({ error: "Gagal mendaftar user" });
    }
  } finally {
    if (connection) connection.release();
  }
});