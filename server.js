const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const cors = require('cors');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());

// Configuração do banco de dados PostgreSQL
const pool = new Pool({
  user: process.env.DB_USER || 'postgres',
  host: process.env.DB_HOST || 'localhost',
  database: process.env.DB_NAME || 'zen_social',
  password: process.env.DB_PASSWORD || 'password',
  port: process.env.DB_PORT || 5432,
});

// Middleware de autenticação JWT
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Token de acesso necessário' });
  }

  jwt.verify(token, process.env.JWT_SECRET || 'zen_social_secret', (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Token inválido' });
    }
    req.user = user;
    next();
  });
};

// Rotas de autenticação
app.post('/api/auth/register', async (req, res) => {
  try {
    const { firstName, lastName, email, username, birthDate, password } = req.body;

    // Verificar se o usuário já existe
    const userExists = await pool.query(
      'SELECT * FROM users WHERE email = $1 OR username = $2',
      [email, username]
    );

    if (userExists.rows.length > 0) {
      return res.status(400).json({ error: 'E-mail ou nome de usuário já está em uso' });
    }

    // Validar idade (16+)
    const birth = new Date(birthDate);
    const today = new Date();
    const age = today.getFullYear() - birth.getFullYear();
    const monthDiff = today.getMonth() - birth.getMonth();
    
    let validAge = false;
    if (monthDiff < 0 || (monthDiff === 0 && today.getDate() < birth.getDate())) {
      validAge = age - 1 >= 16;
    } else {
      validAge = age >= 16;
    }

    if (!validAge) {
      return res.status(400).json({ error: 'Você deve ter pelo menos 16 anos para se registrar' });
    }

    // Hash da senha
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Inserir usuário no banco de dados
    const newUser = await pool.query(
      `INSERT INTO users (first_name, last_name, email, username, birth_date, password, created_at) 
       VALUES ($1, $2, $3, $4, $5, $6, NOW()) RETURNING id, first_name, last_name, email, username, created_at`,
      [firstName, lastName, email, username, birthDate, hashedPassword]
    );

    // Gerar token JWT
    const token = jwt.sign(
      { userId: newUser.rows[0].id },
      process.env.JWT_SECRET || 'zen_social_secret',
      { expiresIn: '24h' }
    );

    res.status(201).json({
      message: 'Usuário criado com sucesso',
      token,
      user: {
        id: newUser.rows[0].id,
        firstName: newUser.rows[0].first_name,
        lastName: newUser.rows[0].last_name,
        email: newUser.rows[0].email,
        username: newUser.rows[0].username
      }
    });
  } catch (error) {
    console.error('Erro no registro:', error);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Buscar usuário
    const user = await pool.query(
      'SELECT * FROM users WHERE email = $1',
      [email]
    );

    if (user.rows.length === 0) {
      return res.status(400).json({ error: 'Credenciais inválidas' });
    }

    // Verificar senha
    const validPassword = await bcrypt.compare(password, user.rows[0].password);
    if (!validPassword) {
      return res.status(400).json({ error: 'Credenciais inválidas' });
    }

    // Gerar token JWT
    const token = jwt.sign(
      { userId: user.rows[0].id },
      process.env.JWT_SECRET || 'zen_social_secret',
      { expiresIn: '24h' }
    );

    res.json({
      message: 'Login realizado com sucesso',
      token,
      user: {
        id: user.rows[0].id,
        firstName: user.rows[0].first_name,
        lastName: user.rows[0].last_name,
        email: user.rows[0].email,
        username: user.rows[0].username
      }
    });
  } catch (error) {
    console.error('Erro no login:', error);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

// Rotas de perfil
app.get('/api/profile/:id', authenticateToken, async (req, res) => {
  try {
    const userId = req.params.id;

    const user = await pool.query(
      `SELECT id, first_name, last_name, email, username, birth_date, bio, avatar_url, created_at 
       FROM users WHERE id = $1`,
      [userId]
    );

    if (user.rows.length === 0) {
      return res.status(404).json({ error: 'Usuário não encontrado' });
    }

    res.json({ user: user.rows[0] });
  } catch (error) {
    console.error('Erro ao buscar perfil:', error);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

app.put('/api/profile/:id', authenticateToken, async (req, res) => {
  try {
    const userId = req.params.id;
    const { bio, avatarUrl } = req.body;

    // Verificar se o usuário está atualizando seu próprio perfil
    if (req.user.userId != userId) {
      return res.status(403).json({ error: 'Acesso negado' });
    }

    const updatedUser = await pool.query(
      `UPDATE users SET bio = $1, avatar_url = $2 WHERE id = $3 
       RETURNING id, first_name, last_name, email, username, birth_date, bio, avatar_url, created_at`,
      [bio, avatarUrl, userId]
    );

    res.json({ 
      message: 'Perfil atualizado com sucesso',
      user: updatedUser.rows[0]
    });
  } catch (error) {
    console.error('Erro ao atualizar perfil:', error);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

// Rotas de recados
app.get('/api/messages/:userId', authenticateToken, async (req, res) => {
  try {
    const userId = req.params.userId;

    const messages = await pool.query(
      `SELECT m.*, u1.first_name as sender_first_name, u1.last_name as sender_last_name, 
              u1.username as sender_username, u1.avatar_url as sender_avatar
       FROM messages m
       JOIN users u1 ON m.sender_id = u1.id
       WHERE m.receiver_id = $1
       ORDER BY m.created_at DESC`,
      [userId]
    );

    res.json({ messages: messages.rows });
  } catch (error) {
    console.error('Erro ao buscar recados:', error);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

app.post('/api/messages', authenticateToken, async (req, res) => {
  try {
    const { receiverId, content } = req.body;
    const senderId = req.user.userId;

    const newMessage = await pool.query(
      `INSERT INTO messages (sender_id, receiver_id, content, created_at) 
       VALUES ($1, $2, $3, NOW()) RETURNING *`,
      [senderId, receiverId, content]
    );

    res.status(201).json({ 
      message: 'Recado enviado com sucesso',
      message: newMessage.rows[0]
    });
  } catch (error) {
    console.error('Erro ao enviar recado:', error);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

// Rotas de comunidades
app.get('/api/communities', authenticateToken, async (req, res) => {
  try {
    const communities = await pool.query(
      `SELECT c.*, u.username as creator_username, 
              COUNT(DISTINCT cm.user_id) as member_count,
              COUNT(DISTINCT t.id) as topic_count
       FROM communities c
       LEFT JOIN users u ON c.created_by = u.id
       LEFT JOIN community_members cm ON c.id = cm.community_id
       LEFT JOIN topics t ON c.id = t.community_id
       GROUP BY c.id, u.username
       ORDER BY c.created_at DESC`
    );

    res.json({ communities: communities.rows });
  } catch (error) {
    console.error('Erro ao buscar comunidades:', error);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

app.post('/api/communities', authenticateToken, async (req, res) => {
  try {
    const { name, description } = req.body;
    const createdBy = req.user.userId;

    const newCommunity = await pool.query(
      `INSERT INTO communities (name, description, created_by, created_at) 
       VALUES ($1, $2, $3, NOW()) RETURNING *`,
      [name, description, createdBy]
    );

    // Adicionar criador como membro
    await pool.query(
      'INSERT INTO community_members (community_id, user_id, joined_at) VALUES ($1, $2, NOW())',
      [newCommunity.rows[0].id, createdBy]
    );

    res.status(201).json({ 
      message: 'Comunidade criada com sucesso',
      community: newCommunity.rows[0]
    });
  } catch (error) {
    console.error('Erro ao criar comunidade:', error);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

// Rotas de tópicos do fórum
app.get('/api/communities/:id/topics', authenticateToken, async (req, res) => {
  try {
    const communityId = req.params.id;

    const topics = await pool.query(
      `SELECT t.*, u.username as author_username, u.avatar_url as author_avatar,
              COUNT(DISTINCT r.id) as reply_count
       FROM topics t
       JOIN users u ON t.author_id = u.id
       LEFT JOIN replies r ON t.id = r.topic_id
       WHERE t.community_id = $1
       GROUP BY t.id, u.username, u.avatar_url
       ORDER BY t.created_at DESC`,
      [communityId]
    );

    res.json({ topics: topics.rows });
  } catch (error) {
    console.error('Erro ao buscar tópicos:', error);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

app.post('/api/communities/:id/topics', authenticateToken, async (req, res) => {
  try {
    const communityId = req.params.id;
    const { title, content } = req.body;
    const authorId = req.user.userId;

    const newTopic = await pool.query(
      `INSERT INTO topics (community_id, author_id, title, content, created_at) 
       VALUES ($1, $2, $3, $4, NOW()) RETURNING *`,
      [communityId, authorId, title, content]
    );

    res.status(201).json({ 
      message: 'Tópico criado com sucesso',
      topic: newTopic.rows[0]
    });
  } catch (error) {
    console.error('Erro ao criar tópico:', error);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

// Rotas de respostas
app.get('/api/topics/:id/replies', authenticateToken, async (req, res) => {
  try {
    const topicId = req.params.id;

    const replies = await pool.query(
      `SELECT r.*, u.username as author_username, u.avatar_url as author_avatar
       FROM replies r
       JOIN users u ON r.author_id = u.id
       WHERE r.topic_id = $1
       ORDER BY r.created_at ASC`,
      [topicId]
    );

    res.json({ replies: replies.rows });
  } catch (error) {
    console.error('Erro ao buscar respostas:', error);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

app.post('/api/topics/:id/replies', authenticateToken, async (req, res) => {
  try {
    const topicId = req.params.id;
    const { content } = req.body;
    const authorId = req.user.userId;

    const newReply = await pool.query(
      `INSERT INTO replies (topic_id, author_id, content, created_at) 
       VALUES ($1, $2, $3, NOW()) RETURNING *`,
      [topicId, authorId, content]
    );

    res.status(201).json({ 
      message: 'Resposta enviada com sucesso',
      reply: newReply.rows[0]
    });
  } catch (error) {
    console.error('Erro ao enviar resposta:', error);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

// Inicializar servidor
app.listen(PORT, () => {
  console.log(`Servidor Zen Social rodando na porta ${PORT}`);
});
