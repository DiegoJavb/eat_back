require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { PrismaClient } = require('@prisma/client');

const prisma = new PrismaClient();
const app = express();

// Middleware
app.use(cors());
app.use(express.json());
// Ruta raíz para verificación
app.get('/', (req, res) => {
  res.json({ message: 'API de Eat_Back está funcionando' });
});

// Rutas de autenticación
app.post('/api/register', async (req, res) => {
  try {
    const { email, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    
    const user = await prisma.user.create({
      data: {
        email,
        password: hashedPassword
      }
    });
    
    res.status(201).json({ message: 'Usuario registrado exitosamente' });
  } catch (error) {
    if (error.code === 'P2002') {
      res.status(400).json({ error: 'El email ya está registrado' });
    } else {
      res.status(500).json({ error: 'Error al registrar usuario' });
    }
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await prisma.user.findUnique({
      where: { email }
    });
    
    if (!user) {
      return res.status(401).json({ error: 'Credenciales inválidas' });
    }
    
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ error: 'Credenciales inválidas' });
    }
    
    const token = jwt.sign(
      { userId: user.id },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );
    
    res.json({ token });
  } catch (error) {
    res.status(500).json({ error: 'Error al iniciar sesión' });
  }
});

// Middleware de autenticación
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ error: 'Token no proporcionado' });
  }
  
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Token inválido' });
    }
    req.user = user;
    next();
  });
};

// Ruta protegida de ejemplo
app.get('/api/protected', authenticateToken, async (req, res) => {
  try {
    const user = await prisma.user.findUnique({
      where: { id: req.user.userId },
      select: { email: true }
    });
    res.json({ message: 'Ruta protegida accedida exitosamente', user });
  } catch (error) {
    res.status(500).json({ error: 'Error al obtener datos del usuario' });
  }
});

// Manejo de errores de Prisma
process.on('beforeExit', async () => {
  await prisma.$disconnect();
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Servidor corriendo en puerto ${PORT}`);
});