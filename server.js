import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import Database from 'better-sqlite3';
import Anthropic from '@anthropic-ai/sdk';
import { fileURLToPath } from 'url';
import { dirname } from 'path';
import os from 'os';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'mobinel-secret-key-2025';

// Initialize database (CÓDIGO CORREGIDO PARA RENDER)
const dbPath = process.env.NODE_ENV === 'production' ? `${os.tmpdir()}/mobinel.db` : 'mobinel.db';
const db = new Database(dbPath);

// Initialize Anthropic client
const anthropic = new Anthropic({
  apiKey: process.env.ANTHROPIC_API_KEY || '',
});

// Middleware
app.use(cors({
  origin: ['http://localhost:3000', 'https://mobinel-app.vercel.app', 'https://mobinel-app-*.vercel.app'],
  credentials: true
}));
app.use(express.json());

// ============ DATABASE SETUP ============
db.exec(`
  CREATE TABLE IF NOT EXISTS usuarios (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nombre TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    rol TEXT NOT NULL CHECK(rol IN ('cliente', 'trabajador', 'admin')),
    telefono TEXT,
    empresa TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS pedidos (
    id TEXT PRIMARY KEY,
    cliente_id INTEGER NOT NULL,
    trabajador_id INTEGER,
    producto TEXT NOT NULL,
    material TEXT NOT NULL,
    dimensiones TEXT NOT NULL,
    acabado TEXT,
    color TEXT,
    cantidad INTEGER DEFAULT 1,
    precio REAL,
    estado TEXT NOT NULL DEFAULT 'pendiente' CHECK(estado IN ('pendiente', 'en_proceso', 'en_produccion', 'control_calidad', 'completado', 'entregado', 'cancelado')),
    progreso INTEGER DEFAULT 0,
    archivo_diseno TEXT,
    notas_cliente TEXT,
    tiempo_estimado INTEGER,
    fecha_entrega DATE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (cliente_id) REFERENCES usuarios(id),
    FOREIGN KEY (trabajador_id) REFERENCES usuarios(id)
  );

  CREATE TABLE IF NOT EXISTS mensajes_nel (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pedido_id TEXT,
    usuario_id INTEGER,
    rol TEXT NOT NULL CHECK(rol IN ('user', 'assistant')),
    contenido TEXT NOT NULL,
    metadata TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (pedido_id) REFERENCES pedidos(id),
    FOREIGN KEY (usuario_id) REFERENCES usuarios(id)
  );

  CREATE TABLE IF NOT EXISTS parametros_produccion (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pedido_id TEXT NOT NULL,
    rpm_husillo INTEGER,
    profundidad_corte REAL,
    velocidad_avance INTEGER,
    presion_pintura REAL,
    tiempo_curado INTEGER,
    eficiencia REAL,
    consumo_energia REAL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (pedido_id) REFERENCES pedidos(id)
  );
`);



// Create default users if not exist
const checkUsers = db.prepare('SELECT COUNT(*) as count FROM usuarios').get();
if (checkUsers.count === 0) {
  const hashedPassword = bcrypt.hashSync('password123', 10);
  
  db.prepare(`
    INSERT INTO usuarios (nombre, email, password, rol, telefono, empresa) VALUES
    ('Anthony Ramírez', 'anthony@mobinel.com', ?, 'trabajador', '+1-416-555-0100', 'MOBINEL'),
    ('Carlos Ruiz', 'carlos.ruiz@email.com', ?, 'cliente', '+57-310-555-0101', 'Constructora Ruiz'),
    ('María González', 'maria.g@email.com', ?, 'cliente', '+57-320-555-0102', 'Diseño Interior MG'),
    ('Ana Martínez', 'ana.m@email.com', ?, 'cliente', '+57-315-555-0103', 'Carpintería Martínez'),
    ('Admin', 'admin@mobinel.com', ?, 'admin', '+57-300-555-0100', 'MOBINEL')
  `).run(hashedPassword, hashedPassword, hashedPassword, hashedPassword, hashedPassword);
  
  console.log('✅ Usuarios de prueba creados');
}

// ============ AUTH MIDDLEWARE ============
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ error: 'Token no proporcionado' });
  }
  
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Token inválido' });
    }
    req.user = user;
    next();
  });
};

// ============ AUTH ROUTES ============
app.post('/api/auth/register', async (req, res) => {
  try {
    const { nombre, email, password, rol = 'cliente', telefono, empresa } = req.body;
    
    if (!nombre || !email || !password) {
      return res.status(400).json({ error: 'Datos incompletos' });
    }
    
    const hashedPassword = await bcrypt.hash(password, 10);
    
    const result = db.prepare(`
      INSERT INTO usuarios (nombre, email, password, rol, telefono, empresa)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(nombre, email, hashedPassword, rol, telefono, empresa);
    
    const token = jwt.sign({ id: result.lastInsertRowid, email, rol }, JWT_SECRET, { expiresIn: '7d' });
    
    res.json({
      token,
      user: { id: result.lastInsertRowid, nombre, email, rol, telefono, empresa }
    });
  } catch (error) {
    console.error('Error en registro:', error);
    res.status(500).json({ error: 'Error al registrar usuario' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    const user = db.prepare('SELECT * FROM usuarios WHERE email = ?').get(email);
    
    if (!user) {
      return res.status(401).json({ error: 'Credenciales inválidas' });
    }
    
    const validPassword = await bcrypt.compare(password, user.password);
    
    if (!validPassword) {
      return res.status(401).json({ error: 'Credenciales inválidas' });
    }
    
    const token = jwt.sign({ id: user.id, email: user.email, rol: user.rol }, JWT_SECRET, { expiresIn: '7d' });
    
    res.json({
      token,
      user: {
        id: user.id,
        nombre: user.nombre,
        email: user.email,
        rol: user.rol,
        telefono: user.telefono,
        empresa: user.empresa
      }
    });
  } catch (error) {
    console.error('Error en login:', error);
    res.status(500).json({ error: 'Error al iniciar sesión' });
  }
});

app.get('/api/auth/me', authenticateToken, (req, res) => {
  const user = db.prepare('SELECT id, nombre, email, rol, telefono, empresa FROM usuarios WHERE id = ?').get(req.user.id);
  res.json(user);
});

// ============ PEDIDOS ROUTES ============
app.get('/api/pedidos', authenticateToken, (req, res) => {
  try {
    let query = `
      SELECT p.*, 
             c.nombre as cliente_nombre, c.email as cliente_email,
             t.nombre as trabajador_nombre
      FROM pedidos p
      LEFT JOIN usuarios c ON p.cliente_id = c.id
      LEFT JOIN usuarios t ON p.trabajador_id = t.id
    `;
    
    if (req.user.rol === 'cliente') {
      query += ` WHERE p.cliente_id = ?`;
      const pedidos = db.prepare(query).all(req.user.id);
      return res.json(pedidos);
    } else if (req.user.rol === 'trabajador') {
      query += ` WHERE p.trabajador_id = ? OR p.estado = 'pendiente'`;
      const pedidos = db.prepare(query).all(req.user.id);
      return res.json(pedidos);
    } else {
      const pedidos = db.prepare(query).all();
      return res.json(pedidos);
    }
  } catch (error) {
    console.error('Error al obtener pedidos:', error);
    res.status(500).json({ error: 'Error al obtener pedidos' });
  }
});

app.get('/api/pedidos/:id', authenticateToken, (req, res) => {
  try {
    const pedido = db.prepare(`
      SELECT p.*, 
             c.nombre as cliente_nombre, c.email as cliente_email, c.telefono as cliente_telefono,
             t.nombre as trabajador_nombre
      FROM pedidos p
      LEFT JOIN usuarios c ON p.cliente_id = c.id
      LEFT JOIN usuarios t ON p.trabajador_id = t.id
      WHERE p.id = ?
    `).get(req.params.id);
    
    if (!pedido) {
      return res.status(404).json({ error: 'Pedido no encontrado' });
    }
    
    // Check permissions
    if (req.user.rol === 'cliente' && pedido.cliente_id !== req.user.id) {
      return res.status(403).json({ error: 'No autorizado' });
    }
    
    res.json(pedido);
  } catch (error) {
    console.error('Error al obtener pedido:', error);
    res.status(500).json({ error: 'Error al obtener pedido' });
  }
});

app.post('/api/pedidos', authenticateToken, (req, res) => {
  try {
    const {
      producto,
      material,
      dimensiones,
      acabado,
      color,
      cantidad = 1,
      notas_cliente,
      tiempo_estimado,
      fecha_entrega
    } = req.body;
    
    if (!producto || !material || !dimensiones) {
      return res.status(400).json({ error: 'Datos incompletos' });
    }
    
    // Generate order ID
    const orderId = `${Date.now()}`.slice(-4).padStart(4, '0');
    
    const result = db.prepare(`
      INSERT INTO pedidos (
        id, cliente_id, producto, material, dimensiones, acabado, color,
        cantidad, notas_cliente, tiempo_estimado, fecha_entrega, estado
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pendiente')
    `).run(
      orderId,
      req.user.id,
      producto,
      material,
      dimensiones,
      acabado,
      color,
      cantidad,
      notas_cliente,
      tiempo_estimado,
      fecha_entrega
    );
    
    const pedido = db.prepare('SELECT * FROM pedidos WHERE id = ?').get(orderId);
    res.json(pedido);
  } catch (error) {
    console.error('Error al crear pedido:', error);
    res.status(500).json({ error: 'Error al crear pedido' });
  }
});

app.put('/api/pedidos/:id', authenticateToken, (req, res) => {
  try {
    const { estado, progreso, trabajador_id, precio } = req.body;
    
    const updates = [];
    const values = [];
    
    if (estado) { updates.push('estado = ?'); values.push(estado); }
    if (progreso !== undefined) { updates.push('progreso = ?'); values.push(progreso); }
    if (trabajador_id) { updates.push('trabajador_id = ?'); values.push(trabajador_id); }
    if (precio) { updates.push('precio = ?'); values.push(precio); }
    
    updates.push('updated_at = CURRENT_TIMESTAMP');
    values.push(req.params.id);
    
    db.prepare(`UPDATE pedidos SET ${updates.join(', ')} WHERE id = ?`).run(...values);
    
    const pedido = db.prepare('SELECT * FROM pedidos WHERE id = ?').get(req.params.id);
    res.json(pedido);
  } catch (error) {
    console.error('Error al actualizar pedido:', error);
    res.status(500).json({ error: 'Error al actualizar pedido' });
  }
});

// ============ NEL CHAT ROUTES (CON PROMPT DE PRUEBA) ============
app.post('/api/nel/chat', authenticateToken, async (req, res) => {
  try {
    const { mensaje, pedido_id, contexto } = req.body;
    
    if (!mensaje) {
      return res.status(400).json({ error: 'Mensaje requerido' });
    }
    
    // Aseguramos que req.user.id sea un número entero
    const userId = parseInt(req.user.id);

    // Save user message (USA userId)
    db.prepare(`
      INSERT INTO mensajes_nel (pedido_id, usuario_id, rol, contenido)
      VALUES (?, ?, 'user', ?)
    `).run(pedido_id || null, userId, mensaje); 
    
    // Get conversation history
    let conversacion = [];
    if (pedido_id) {
      const mensajes = db.prepare(`
        SELECT rol, contenido FROM mensajes_nel
        WHERE pedido_id = ?
        ORDER BY created_at ASC
        LIMIT 20
      `).all(pedido_id);
      
      conversacion = mensajes.map(m => ({
        role: m.rol === 'user' ? 'user' : 'assistant',
        content: m.contenido
      }));
    } else {
      conversacion = [{ role: 'user', content: mensaje }];
    }
    
    // Build system prompt (PROMPT ESTATICO PARA PRUEBA DE CONEXION)
    const systemPrompt = `
      Eres NEL, el asistente inteligente de MOBINEL. 
      Tu única función es responder preguntas sobre corte CNC y materiales MDF. 
      Sé conciso y profesional.
    `; 
    
    // Call Claude API
    const response = await anthropic.messages.create({
      model: 'claude-sonnet-4-20250514',
      max_tokens: 1024,
      system: systemPrompt, 
      messages: conversacion
    });
    
    const respuestaNEL = response.content[0].text;
    
    // Save NEL response (USA userId)
    db.prepare(`
      INSERT INTO mensajes_nel (pedido_id, usuario_id, rol, contenido)
      VALUES (?, ?, 'assistant', ?)
    `).run(pedido_id || null, userId, respuestaNEL); 
    
    res.json({
      respuesta: respuestaNEL,
      timestamp: new Date().toISOString()
    });
    
  } catch (error) {
    console.error('Error en NEL chat:', error);
    // Devolver un error 500 más informativo si falla la API de Claude
    res.status(500).json({ error: 'Error al procesar mensaje. Revise la API de Anthropic o su clave.', details: error.message });
  }
});

app.get('/api/nel/historial/:pedidoId', authenticateToken, (req, res) => {
  try {
    const mensajes = db.prepare(`
      SELECT m.*, u.nombre as usuario_nombre
      FROM mensajes_nel m
      LEFT JOIN usuarios u ON m.usuario_id = u.id
      WHERE m.pedido_id = ?
      ORDER BY m.created_at ASC
    `).all(req.params.pedidoId);
    
    res.json(mensajes);
  } catch (error) {
    console.error('Error al obtener historial:', error);
    res.status(500).json({ error: 'Error al obtener historial' });
  }
});

// ============ PRODUCTION ROUTES ============
app.post('/api/produccion/iniciar', authenticateToken, (req, res) => {
  try {
    const { pedido_id } = req.body;
    
    // Update order status
    db.prepare(`
      UPDATE pedidos 
      SET estado = 'en_produccion', trabajador_id = ?, progreso = 0, updated_at = CURRENT_TIMESTAMP
      WHERE id = ?
    `).run(req.user.id, pedido_id);
    
    // Create production parameters
    db.prepare(`
      INSERT INTO parametros_produccion (
        pedido_id, rpm_husillo, profundidad_corte, velocidad_avance,
        presion_pintura, tiempo_curado, eficiencia, consumo_energia
      ) VALUES (?, 18000, 3.5, 85, 0.8, 20, 96, 0)
    `).run(pedido_id);
    
    res.json({ success: true, message: 'Producción iniciada' });
  } catch (error) {
    console.error('Error al iniciar producción:', error);
    res.status(500).json({ error: 'Error al iniciar producción' });
  }
});

app.get('/api/produccion/estado/:pedidoId', authenticateToken, (req, res) => {
  try {
    const pedido = db.prepare('SELECT * FROM pedidos WHERE id = ?').get(req.params.pedidoId);
    const parametros = db.prepare('SELECT * FROM parametros_produccion WHERE pedido_id = ? ORDER BY created_at DESC LIMIT 1').get(req.params.pedidoId);
    
    res.json({ pedido, parametros });
  } catch (error) {
    console.error('Error al obtener estado:', error);
    res.status(500).json({ error: 'Error al obtener estado' });
  }
});

// ============ HEALTH CHECK ============
app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    anthropic_configured: !!process.env.ANTHROPIC_API_KEY
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`
  ╔════════════════════════════════════════╗
  ║   🚀 MOBINEL Backend Server            ║
  ║   Puerto: ${PORT}                      ║
  ║   Estado: ✅ Funcionando               ║
  ╚════════════════════════════════════════╝
  
  Endpoints disponibles:
  - POST /api/auth/register
  - POST /api/auth/login
  - GET  /api/auth/me
  - GET  /api/pedidos
  - POST /api/pedidos
  - POST /api/nel/chat
  - GET  /api/health
  `);
});