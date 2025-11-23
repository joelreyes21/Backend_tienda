// server.js - Backend tienda (auth + productos)

require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const multer = require('multer');

const app = express();

// Config
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'secreto_super_seguro';

// Middlewares
app.use(cors());
app.use(express.json());

// ------- Configuración de subida de imágenes (productos) -------
const uploadDir = path.join(__dirname, 'uploads');

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    const base = path.basename(file.originalname, ext);
    const unique = Date.now();
    cb(null, base.replace(/\s+/g, '_') + '_' + unique + ext);
  }
});

const upload = multer({ storage });

// Servir imágenes
app.use('/uploads', express.static(uploadDir));

// Pool MySQL (Render → Hostinger)
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10
});

// ---------- Helper: crear token ----------
function createToken(user) {
  return jwt.sign(
    { id: user.id, email: user.email },
    JWT_SECRET,
    { expiresIn: '7d' }
  );
}

// ---------- Middleware auth ----------
function authMiddleware(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ ok: false, error: 'No token' });

  const token = auth.split(' ')[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ ok: false, error: 'Token inválido' });
  }
}

// ---------- Rutas básicas ----------
app.get('/api/ping', (req, res) => {
  res.json({ ok: true, message: 'Backend vivo 🔥' });
});

app.get('/api/test-db', async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT 1 + 1 AS resultado');
    res.json({ ok: true, resultado: rows[0].resultado });
  } catch (err) {
    res.status(500).json({
      ok: false,
      error: err.message,
      code: err.code
    });
  }
});

// ---------- AUTH: REGISTER ----------
app.post('/api/register', async (req, res) => {
  try {
    const { nombre, apellido, email, password } = req.body;

    if (!email || !password)
      return res.status(400).json({ ok: false, error: 'Email y password son obligatorios' });

    const [exist] = await pool.query('SELECT id FROM users WHERE email = ?', [email]);
    if (exist.length > 0)
      return res.status(409).json({ ok: false, error: 'Ese email ya está registrado' });

    const hash = bcrypt.hashSync(password, bcrypt.genSaltSync(10));

    const [result] = await pool.query(
      'INSERT INTO users (nombre, apellido, email, password_hash, role_id) VALUES (?, ?, ?, ?, (SELECT id FROM roles WHERE nombre = "user"))',
      [nombre || null, apellido || null, email, hash]
    );

    const user = { id: result.insertId, email };
    const token = createToken(user);

    res.json({
      ok: true,
      token,
      user: {
        id: user.id,
        nombre,
        apellido,
        email,
        role: 'user'
      }
    });

  } catch (err) {
    res.status(500).json({ ok: false, error: 'Error en el servidor' });
  }
});

// ---------- AUTH: LOGIN ----------
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password)
      return res.status(400).json({ ok: false, error: 'Email y password son obligatorios' });

    const [rows] = await pool.query(
      `SELECT u.id, u.nombre, u.apellido, u.email, u.password_hash, r.nombre AS role
       FROM users u
       LEFT JOIN roles r ON r.id = u.role_id
       WHERE u.email = ?`,
      [email]
    );

    if (rows.length === 0)
      return res.status(401).json({ ok: false, error: 'Credenciales inválidas' });

    const user = rows[0];
    const match = bcrypt.compareSync(password, user.password_hash);

    if (!match)
      return res.status(401).json({ ok: false, error: 'Credenciales inválidas' });

    const token = createToken(user);

    res.json({
      ok: true,
      token,
      user: {
        id: user.id,
        nombre: user.nombre,
        apellido: user.apellido,
        email: user.email,
        role: user.role
      }
    });

  } catch (err) {
    res.status(500).json({ ok: false, error: 'Error en el servidor' });
  }
});

// ----------------------------------------------------------
// ------------------------ PRODUCTS ------------------------
// ----------------------------------------------------------

// GET productos
app.get('/api/products', async (req, res) => {
  try {
    const [rows] = await pool.query(`
      SELECT 
        id,
        nombre,
        descripcion,
        price,
        stock,
        categoria,
        tallas,
        codigo,
        CASE
          WHEN imagen IS NOT NULL AND imagen != '' THEN imagen
          ELSE image_url
        END AS imagen
      FROM products
      ORDER BY created_at DESC
    `);

    res.json({ ok: true, products: rows });

  } catch (err) {
    res.status(500).json({ ok: false, error: 'Error en el servidor' });
  }
});

// GET producto por ID
app.get('/api/products/:id', async (req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT * FROM products WHERE id = ?`,
      [req.params.id]
    );

    if (rows.length === 0)
      return res.status(404).json({ ok: false, error: 'Producto no encontrado' });

    res.json({ ok: true, product: rows[0] });

  } catch (err) {
    res.status(500).json({ ok: false, error: 'Error en el servidor' });
  }
});

// POST crear producto
app.post('/api/products', upload.single('imagen'), async (req, res) => {
  try {
    const {
      nombre,
      codigo,
      categoria,
      tallas,
      precio,
      costo,
      stock,
      descripcion
    } = req.body;

    if (!nombre || !precio) {
      return res.status(400).json({
        ok: false,
        error: 'Nombre y precio son obligatorios'
      });
    }

    const imagenFinal = req.file ? `/uploads/${req.file.filename}` : null;

    const [result] = await pool.query(
      `INSERT INTO products
      (nombre, codigo, categoria, tallas, price, costo, stock, descripcion, imagen)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        nombre,
        codigo || null,
        categoria || null,
        tallas || null,
        parseFloat(precio),
        costo ? parseFloat(costo) : null,
        stock ? parseInt(stock) : 0,
        descripcion || null,
        imagenFinal
      ]
    );

    const [rows] = await pool.query(
      `SELECT * FROM products WHERE id = ?`,
      [result.insertId]
    );

    res.status(201).json({
      ok: true,
      product: rows[0]
    });

  } catch (err) {
    res.status(500).json({ ok: false, error: 'Error en el servidor' });
  }
});

// PUT actualizar producto
app.put('/api/products/:id', upload.single("imagen"), async (req, res) => {
  try {
    const {
      nombre,
      codigo,
      categoria,
      tallas,
      precio,
      costo,
      stock,
      descripcion
    } = req.body;

    let imagenFinal = null;
    if (req.file) {
      imagenFinal = `/uploads/${req.file.filename}`;
    }

    const sql = `
      UPDATE products SET
        nombre = ?,
        codigo = ?,
        categoria = ?,
        tallas = ?,
        price = ?,
        costo = ?,
        stock = ?,
        descripcion = ?
        ${imagenFinal ? ", imagen = ?" : ""}
      WHERE id = ?
    `;

    const params = [
      nombre,
      codigo,
      categoria,
      tallas,
      precio,
      costo,
      stock,
      descripcion
    ];

    if (imagenFinal) params.push(imagenFinal);
    params.push(req.params.id);

    await pool.query(sql, params);

    res.json({ ok: true, message: "Producto actualizado" });

  } catch (err) {
    res.status(500).json({ ok: false, error: "Error en el servidor" });
  }
});

// DELETE producto
app.delete('/api/products/:id', async (req, res) => {
  try {
    await pool.query(
      `DELETE FROM products WHERE id = ?`,
      [req.params.id]
    );

    res.json({ ok: true, message: "Producto eliminado" });

  } catch (err) {
    res.status(500).json({ ok: false, error: "Error en el servidor" });
  }
});

// ---------- USUARIOS ----------
app.get('/api/usuarios', async (req, res) => {
  try {
    const [rows] = await pool.query(`
      SELECT 
        u.id,
        u.nombre,
        u.apellido,
        u.email,
        r.nombre AS rol,
        u.created_at
      FROM users u
      LEFT JOIN roles r ON r.id = u.role_id
      ORDER BY u.id DESC
    `);

    res.json(rows);

  } catch (err) {
    res.status(500).json({ ok: false, error: "Error obteniendo usuarios" });
  }
});

app.delete("/api/usuarios/:id", async (req, res) => {
  try {
    await pool.query(
      `DELETE FROM users WHERE id = ?`,
      [req.params.id]
    );
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: "Error eliminando usuario" });
  }
});

app.put("/api/usuarios/:id/rol", async (req, res) => {
  try {
    const { rol } = req.body;
    const nuevoID = rol === "admin" ? 1 : 2;

    await pool.query(
      `UPDATE users SET role_id = ? WHERE id = ?`,
      [nuevoID, req.params.id]
    );

    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: "Error cambiando rol" });
  }
});

// ---------- CONTACTO ----------
app.post("/api/contacto", async (req, res) => {
  try {
    const { nombre, email, mensaje } = req.body;

    await pool.query(
      `INSERT INTO contacto (nombre, email, mensaje)
       VALUES (?, ?, ?)`,
      [nombre, email, mensaje]
    );

    res.json({ ok: true });

  } catch (err) {
    res.status(500).json({ ok: false });
  }
});

app.get("/api/contacto", async (req, res) => {
  try {
    const [rows] = await pool.query(`
      SELECT *
      FROM contacto
      ORDER BY created_at DESC
    `);

    res.json({ ok: true, mensajes: rows });

  } catch (err) {
    res.status(500).json({ ok: false, error: "Error al obtener mensajes" });
  }
});

app.delete("/api/contacto/:id", async (req, res) => {
  try {
    await pool.query(`DELETE FROM contacto WHERE id = ?`, [req.params.id]);
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ ok: false });
  }
});

// ----------------------------------------------------------
app.listen(PORT, () => {
  console.log(`✅ Server escuchando en puerto ${PORT}`);
});
