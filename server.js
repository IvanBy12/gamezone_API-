require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();

// === Configuración básica ===
app.use(cors());              // permitir peticiones desde Expo / navegador
app.use(express.json());      // parsear JSON en el body

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'gamezone-secret';

// "Base de datos" en memoria (para demo)
// En un proyecto real usarías MongoDB, PostgreSQL, etc.
const users = []; // { id, email, username, passwordHash }

// Función auxiliar para generar token
function generateToken(user) {
  return jwt.sign(
    { id: user.id, email: user.email },
    JWT_SECRET,
    { expiresIn: '7d' }
  );
}

// =========================
//      ENDPOINTS AUTH
// =========================

// Registro de usuario
app.post('/auth/register', async (req, res) => {
  try {
    const { email, password, username } = req.body;

    if (!email || !password || !username) {
      return res.status(400).json({
        message: 'Email, contraseña y nombre de usuario son requeridos',
      });
    }

    const normalizedEmail = email.toLowerCase();

    // ¿Ya existe ese correo?
    const existing = users.find((u) => u.email === normalizedEmail);
    if (existing) {
      return res
        .status(409)
        .json({ message: 'Este email ya está registrado' });
    }

    // Encriptar contraseña
    const passwordHash = await bcrypt.hash(password, 10);

    const newUser = {
      id: (users.length + 1).toString(),
      email: normalizedEmail,
      username: username.trim(),
      passwordHash,
    };

    users.push(newUser);

    const token = generateToken(newUser);

    // Lo que espera tu front:
    return res.status(201).json({
      user: {
        id: newUser.id,
        email: newUser.email,
        username: newUser.username,
      },
      token,
    });
  } catch (err) {
    console.error('Error en /auth/register:', err);
    return res
      .status(500)
      .json({ message: 'Error interno al registrar usuario' });
  }
});

// Login de usuario
app.post('/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res
        .status(400)
        .json({ message: 'Email y contraseña son requeridos' });
    }

    const normalizedEmail = email.toLowerCase();

    const user = users.find((u) => u.email === normalizedEmail);
    if (!user) {
      return res
        .status(401)
        .json({ message: 'Usuario no encontrado o credenciales inválidas' });
    }

    const isValid = await bcrypt.compare(password, user.passwordHash);
    if (!isValid) {
      return res
        .status(401)
        .json({ message: 'Usuario no encontrado o credenciales inválidas' });
    }

    const token = generateToken(user);

    return res.json({
      user: {
        id: user.id,
        email: user.email,
        username: user.username,
      },
      token,
    });
  } catch (err) {
    console.error('Error en /auth/login:', err);
    return res
      .status(500)
      .json({ message: 'Error interno al iniciar sesión' });
  }
});

// Endpoint simple para probar que el servidor está vivo
app.get('/', (req, res) => {
  res.json({ message: 'GameZone API funcionando 🚀' });
});

// Iniciar servidor
app.listen(PORT, () => {
  console.log(`GameZone API escuchando en http://localhost:${PORT}`);
});
