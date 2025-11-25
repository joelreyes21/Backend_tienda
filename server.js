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
const PORT = process.env.PORT || 8080;
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
  res.json({ ok: true, message: 'Backend vivo' });
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

// GET productoss
app.get('/api/products', async (req, res) => {
  try {
    // 1. Obtener productos
    const [products] = await pool.query(`
      SELECT 
        id,
        nombre,
        descripcion,
        price,
        stock,
        categoria,
        codigo,
        CASE
          WHEN imagen IS NOT NULL AND imagen != '' THEN imagen
          ELSE image_url
        END AS imagen
      FROM products
      ORDER BY created_at DESC
    `);

    // 2. Obtener tallas desde product_sizes
    const [sizes] = await pool.query(`
      SELECT product_id, talla, cantidad
      FROM product_sizes
    `);

    // 3. Mapear tallas a cada producto
    const productosFinal = products.map(p => {
      const tallasDelProducto = sizes
        .filter(s => s.product_id === p.id)
        .map(s => s.talla);

      return {
        ...p,
        tallas: tallasDelProducto
      };
    });

    res.json({ ok: true, products: productosFinal });

  } catch (err) {
    console.error("Error /api/products:", err);
    res.status(500).json({ ok: false, error: "Error en el servidor" });
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
  const conn = await pool.getConnection();
  await conn.beginTransaction();

  try {
    const {
      nombre,
      codigo,
      categoria,
      tallas,
      precio,
      costo,
      stock,
      descripcion,
      cantidadesJSON
    } = req.body;

    if (!nombre || !precio) {
      return res.status(400).json({
        ok: false,
        error: 'Nombre y precio son obligatorios'
      });
    }

    const imagenFinal = req.file ? `/uploads/${req.file.filename}` : null;

    // ------------------------
    // INSERTAR PRODUCTO
    // ------------------------
    const [result] = await conn.query(
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

    const newProductId = result.insertId;

    // ------------------------
    // INSERTAR TALLAS EN product_sizes
    // ------------------------
    if (cantidadesJSON) {
      try {
        const cantidades = JSON.parse(cantidadesJSON);

        for (const talla in cantidades) {
          const cantidad = cantidades[talla];

          await conn.query(
            `INSERT INTO product_sizes (product_id, talla, cantidad)
             VALUES (?, ?, ?)`,
            [newProductId, talla, cantidad]
          );
        }
      } catch (err) {
        console.error("❌ Error guardando tallas:", err);
      }
    }

    await conn.commit();

    const [rows] = await conn.query(
      `SELECT * FROM products WHERE id = ?`,
      [newProductId]
    );

    res.status(201).json({
      ok: true,
      product: rows[0]
    });

  } catch (err) {
    await conn.rollback();
    console.error("❌ Error POST /api/products:", err);
    res.status(500).json({ ok: false, error: 'Error en el servidor' });
  } finally {
    conn.release();
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
// ---------- LISTAR USUARIOS (ADMIN) ----------
app.get("/api/usuarios", async (req, res) => {
  try {
    const [rows] = await pool.query(`
      SELECT 
        u.id,
        u.nombre,
        u.apellido,
        u.email,
        r.nombre AS rol
      FROM users u
      LEFT JOIN roles r ON r.id = u.role_id
      ORDER BY u.id DESC
    `);

    res.json(rows); // la tabla espera un array directo
  } catch (err) {
    console.error("Error GET /api/usuarios", err);
    res.status(500).json({ error: "Error cargando usuarios" });
  }
});

// ----------------------------------------------------------
// --------------------- FINALIZAR COMPRA --------------------
// ----------------------------------------------------------

// ----------------------------------------------------------
// --------------------- FINALIZAR COMPRA --------------------
// ----------------------------------------------------------

app.post("/api/orders", async (req, res) => {
  const conn = await pool.getConnection();
  await conn.beginTransaction();

  try {
    // YA NO USAMOS userId
    const items = req.body.items;
    const total = req.body.total;

    if (!items || !items.length) {
      return res.status(400).json({ ok: false, error: "Carrito vacío" });
    }

    // 1️⃣ Crear la orden SIN user_id
    const [orderResult] = await conn.query(
      `INSERT INTO orders (total)
       VALUES (?)`,
      [total]
    );

    const orderId = orderResult.insertId;

    // 2️⃣ Procesar productos del carrito
    for (const item of items) {
      const { id: productId, cantidad, talla } = item;

      if (!talla) throw new Error("Falta seleccionar talla en un producto");

      const [stockRows] = await conn.query(
        `SELECT cantidad FROM product_sizes WHERE product_id = ? AND talla = ?`,
        [productId, talla]
      );

      if (stockRows.length === 0)
        throw new Error(`No existe la talla ${talla} para el producto ${productId}`);

      if (stockRows[0].cantidad < cantidad)
        throw new Error(`Stock insuficiente para talla ${talla} del producto ${productId}`);

      await conn.query(
        `UPDATE product_sizes SET cantidad = cantidad - ?
         WHERE product_id = ? AND talla = ?`,
        [cantidad, productId, talla]
      );

      await conn.query(
        `INSERT INTO order_items (order_id, product_id, cantidad, talla)
         VALUES (?, ?, ?, ?)`,
        [orderId, productId, cantidad, talla]
      );
    }

    await conn.commit();

    res.json({
      ok: true,
      message: "Orden creada con éxito",
      orderId
    });

  } catch (err) {
    await conn.rollback();
    console.error("❌ Error en /api/orders:", err);
    res.status(500).json({ ok: false, error: err.message });
  } finally {
    conn.release();
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

app.get("/api/direcciones/:userId", async (req, res) => {
    try {
        const { userId } = req.params;

        const [rows] = await pool.query(
            `SELECT id, departamento, ciudad, direccion, created_at
             FROM direcciones
             WHERE user_id = ?
             ORDER BY created_at DESC`,
            [userId]
        );

        res.json({ ok: true, direcciones: rows });

    } catch (err) {
        console.error("Error GET /api/direcciones:", err);
        res.status(500).json({ ok: false, error: "Error interno del servidor" });
    }
});

app.post("/api/direcciones", async (req, res) => {
    try {
        const { userId, departamento, ciudad, direccion } = req.body;

        if (!userId || !departamento || !ciudad || !direccion) {
            return res.status(400).json({ ok: false, error: "Datos incompletos" });
        }

        await pool.query(
            `INSERT INTO direcciones (user_id, departamento, ciudad, direccion)
             VALUES (?, ?, ?, ?)`,
            [userId, departamento, ciudad, direccion]
        );

        res.json({ ok: true, message: "Dirección guardada" });

    } catch (err) {
        console.error("Error POST /direcciones:", err);
        res.status(500).json({ ok: false, error: "Error al guardar dirección" });
    }
});


app.get("/api/direcciones/:userId", async (req, res) => {
    try {
        const { userId } = req.params;

        const [rows] = await pool.query(
            `SELECT id, departamento, ciudad, direccion, created_at
             FROM direcciones
             WHERE user_id = ?
             ORDER BY created_at DESC`,
            [userId]
        );

        res.json({ ok: true, direcciones: rows });

    } catch (err) {
        console.error("Error GET /direcciones:", err);
        res.status(500).json({ ok: false, error: "Error al obtener direcciones" });
    }
});


app.post("/api/direcciones", async (req, res) => {
    try {
        const { userId, departamento, ciudad, direccion } = req.body;

        if (!userId || !departamento || !ciudad || !direccion) {
            return res.status(400).json({ ok: false, error: "Datos incompletos" });
        }

        await pool.query(
            `INSERT INTO direcciones (user_id, departamento, ciudad, direccion)
             VALUES (?, ?, ?, ?)`,
            [userId, departamento, ciudad, direccion]
        );

        res.json({ ok: true });

    } catch (err) {
        console.error("Error POST /direcciones:", err);
        res.status(500).json({ ok: false, error: "Error al guardar dirección" });
    }
});

// 🔥 EDITAR DIRECCIÓN
app.put("/api/direcciones/:id", async (req, res) => {
    try {
        const { id } = req.params;
        const { departamento, ciudad, direccion } = req.body;

        if (!departamento || !ciudad || !direccion) {
            return res.status(400).json({ ok: false, error: "Datos incompletos" });
        }

        await pool.query(
            `UPDATE direcciones
             SET departamento = ?, ciudad = ?, direccion = ?
             WHERE id = ?`,
            [departamento, ciudad, direccion, id]
        );

        res.json({ ok: true, message: "Dirección actualizada" });

    } catch (err) {
        console.error("Error PUT /direcciones:", err);
        res.status(500).json({ ok: false, error: "Error al actualizar dirección" });
    }
});


// 🔥 ELIMINAR DIRECCIÓN
app.delete("/api/direcciones/:id", async (req, res) => {
    try {
        const { id } = req.params;

        await pool.query(`DELETE FROM direcciones WHERE id = ?`, [id]);

        res.json({ ok: true, message: "Dirección eliminada" });

    } catch (err) {
        console.error("Error DELETE /direcciones:", err);
        res.status(500).json({ ok: false, error: "Error al eliminar dirección" });
    }
});



// ----------------------------------------------------------
app.listen(PORT, () => {
  console.log(`✅ Server escuchando en puerto ${PORT}`);
});