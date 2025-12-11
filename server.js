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

app.get('/api/products', async (req, res) => {
  try {
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

app.post("/api/orders", async (req, res) => {
  const conn = await pool.getConnection();
  await conn.beginTransaction();

  try {
    // 🔥 Recibir items, total y user_id desde el frontend
    const { items, total, user_id, factura } = req.body;


    if (!items || !items.length) {
      return res.status(400).json({ ok: false, error: "Carrito vacío" });
    }

    // 1️⃣ Crear la orden CON user_id
    const [orderResult] = await conn.query(
      `INSERT INTO orders (total, user_id, factura)
       VALUES (?, ?, ?)`,
      [total, user_id, factura || "no"]
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

      // Obtener precio real del producto
      const [[productRow]] = await conn.query(
        `SELECT price FROM products WHERE id = ?`,
        [productId]
      );
      
      // Insertar item con precio incluido
      await conn.query(
        `INSERT INTO order_items (order_id, product_id, cantidad, talla, precio)
         VALUES (?, ?, ?, ?, ?)`,
        [orderId, productId, cantidad, talla, productRow.price]
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

// --------------------- FACTURA PDF ---------------------

const PDFDocument = require("pdfkit");

app.get("/api/orders/:id/factura", async (req, res) => {
  const orderId = req.params.id;

  try {
    const [rows] = await pool.query(`
      SELECT o.id, o.total, o.factura, o.created_at,
             u.nombre, u.email 
      FROM orders o
      JOIN users u ON u.id = o.user_id
      WHERE o.id = ?
    `, [orderId]);

    if (rows.length === 0)
      return res.status(404).json({ ok: false, error: "Pedido no encontrado" });

    const pedido = rows[0];

    const [items] = await pool.query(`
      SELECT p.nombre, oi.cantidad, oi.talla, oi.precio
      FROM order_items oi
      JOIN products p ON p.id = oi.product_id
      WHERE oi.order_id = ?
    `, [orderId]);

    const doc = new PDFDocument({ margin: 50 });

    res.setHeader("Content-Type", "application/pdf");
    res.setHeader("Content-Disposition", `inline; filename=factura_${orderId}.pdf`);

    doc.pipe(res);

    // ---------- ENCABEZADO ----------
    doc
      .fontSize(28)
      .font("Helvetica-Bold")
      .text("K&L LEGACY", { align: "center" })
      .moveDown(0.5);

    doc
      .fontSize(12)
      .font("Helvetica")
      .text("Tienda Oficial - Moda & Exclusividad", { align: "center" })
      .moveDown(1);

    doc
      .moveTo(50, doc.y)
      .lineTo(550, doc.y)
      .stroke()
      .moveDown(1);

    // ---------- DATOS DEL CLIENTE ----------
    doc.fontSize(14).font("Helvetica-Bold").text("Factura", { underline: true }).moveDown(0.5);

    doc.font("Helvetica").fontSize(12)
      .text(`Pedido: #${orderId}`)
      .text(`Fecha: ${new Date(pedido.created_at).toLocaleDateString()}`)
      .text(`Cliente: ${pedido.nombre}`)
      .text(`Email: ${pedido.email}`)
      .text(`Factura solicitada: ${pedido.factura}`)
      .moveDown(1);

    // ---------- TABLA DE PRODUCTOS ----------
    doc.fontSize(14).font("Helvetica-Bold").text("Detalle de productos").moveDown(0.5);

    // Encabezado tabla
    doc.fontSize(12).font("Helvetica-Bold");
    doc.text("Producto", 50, doc.y);
    doc.text("Talla", 260, doc.y);
    doc.text("Cant.", 330, doc.y);
    doc.text("Precio", 400, doc.y);
    doc.text("Total", 480, doc.y);
    doc.moveDown(0.5);

    doc.moveTo(50, doc.y).lineTo(550, doc.y).stroke().moveDown(0.5);

    doc.font("Helvetica");

    items.forEach(i => {
      const totalLinea = (i.precio * i.cantidad).toFixed(2);

      doc.text(i.nombre, 50, doc.y);
      doc.text(i.talla, 260, doc.y);
      doc.text(i.cantidad, 330, doc.y);
      doc.text(`$${i.precio}`, 400, doc.y);
      doc.text(`$${totalLinea}`, 480, doc.y);
      doc.moveDown(0.3);
    });

    doc.moveDown(1);

    // ---------- TOTAL ----------
    doc.fontSize(16).font("Helvetica-Bold");
    doc.text(`TOTAL A PAGAR: $${pedido.total}`, { align: "right" });

    doc.moveDown(2);

    // ---------- FOOTER ----------
    doc.fontSize(12).font("Helvetica-Oblique");
    doc.text("Gracias por comprar en K&L Legacy 💛", { align: "center" });
    doc.text("Esperamos que vuelvas pronto.", { align: "center" });

    doc.end();

  } catch (err) {
    console.error(err);
    res.status(500).json({ ok: false, error: "Error generando factura" });
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

// 🔥 HISTORIAL POR USUARIO
app.get("/api/orders/user/:userId", async (req, res) => {
  const userId = req.params.userId;

  try {
    const [orders] = await pool.query(`
      SELECT id, total, created_at, factura, estado
      FROM orders
      WHERE user_id = ?
      ORDER BY created_at DESC
    `, [userId]);

    res.json({ ok: true, orders });

  } catch (err) {
    console.error("Error GET /api/orders/user/:userId", err);
    res.status(500).json({ ok: false, error: err.message });
  }
});


// --------------------- ENDPOINTS PEDIDOS ADMIN ---------------------

// 1️⃣ Listar todos los pedidos
// GET todos los pedidos con cliente y productos
app.get("/api/orders", async (req, res) => {
  try {
    // Traer pedidos con info del cliente
    const [orders] = await pool.query(`
      SELECT o.id, o.total, o.created_at, o.factura, o.estado, u.nombre AS cliente, u.email AS cliente_email
      FROM orders o
      LEFT JOIN users u ON o.user_id = u.id
      ORDER BY o.created_at DESC
    `);

    // Traer productos de cada pedido
    for (let order of orders) {
      const [items] = await pool.query(`
        SELECT oi.cantidad, oi.precio, oi.talla, p.nombre AS producto
        FROM order_items oi
        JOIN products p ON p.id = oi.product_id
        WHERE oi.order_id = ?
      `, [order.id]);

      order.items = items; // agregar array de productos al pedido
      order.notas = "Para llevar"; // aquí puedes traer notas si lo guardas en DB
    }

    res.json({ ok: true, orders });

  } catch (err) {
    console.error("Error GET /api/orders", err);
    res.status(500).json({ ok: false, error: err.message });
  }
});


// 2️⃣ Detalle de un pedido
app.get("/api/orders/:id", async (req, res) => {
  const orderId = req.params.id;

  try {
    const [items] = await pool.query(`
      SELECT 
        oi.cantidad,
        oi.talla,
        oi.precio,
        p.nombre AS producto
      FROM order_items oi
      JOIN products p ON p.id = oi.product_id
      WHERE oi.order_id = ?
    `, [orderId]);

    res.json({ ok: true, items });

  } catch (err) {
    console.error("Error GET /api/orders/:id", err);
    res.status(500).json({ ok: false, error: err.message });
  }
});



// 3️⃣ Cambiar estado de un pedido
app.put("/api/orders/:id", async (req, res) => {
  const orderId = req.params.id;
  const { estado } = req.body;
  try {
    await pool.query(`UPDATE orders SET estado = ? WHERE id = ?`, [estado, orderId]);
    res.json({ ok: true, message: "Estado actualizado" });
  } catch (err) {
    console.error("Error PUT /api/orders/:id", err);
    res.status(500).json({ ok: false, error: err.message });
  }
});


app.listen(PORT, () => {
  console.log(`✅ Server escuchando en puerto ${PORT}`);
});