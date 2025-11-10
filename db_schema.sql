-- db_schema.sql (El código de las tablas)
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