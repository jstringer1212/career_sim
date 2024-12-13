const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();

const app = express();
app.use(express.json());

// Secret key for JWT
const JWT_SECRET = process.env.JWT;

// Middleware to authenticate user
const authenticate = (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader) {
    return res.status(401).json({ message: 'Authorization header missing' });
  }

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.userId = decoded.userId;
    next();
  } catch {
    return res.status(401).json({ message: 'Invalid or expired token' });
  }
};

// Register Route
app.post('/api/auth/register', async (req, res) => {
  const { name, password } = req.body;

  // Check if user already exists
  const existingUser = await prisma.user.findUnique({ where: { name } });
  if (existingUser) {
    return res.status(400).json({ message: 'User already exists' });
  }

  // Hash the password
  const hashedPassword = await bcrypt.hash(password, 10);

  // Create new user
  const user = await prisma.user.create({
    data: {
      name,
      password: hashedPassword,
    },
  });

  res.status(201).json({ message: 'User registered successfully', user: { id: user.id, name: user.name } });
});

// Login Route
app.post('/api/auth/login', async (req, res) => {
  const { name, password } = req.body;

  // Find the user
  const user = await prisma.user.findUnique({ where: { name } });
  if (!user) {
    return res.status(401).json({ message: 'Invalid credentials' });
  }

  // Check the password
  const isValidPassword = await bcrypt.compare(password, user.password);
  if (!isValidPassword) {
    return res.status(401).json({ message: 'Invalid credentials' });
  }

  // Generate a token
  const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '1h' });

  res.json({ message: 'Login successful', token });
});

// Get logged-in user details (Protected)
app.get('/api/auth/me', authenticate, async (req, res) => {
  const user = await prisma.user.findUnique({ where: { id: req.userId } });
  res.json({ id: user.id, name: user.name });
});

// Get all items
app.get('/api/items', async (req, res) => {
  const items = await prisma.product.findMany();
  res.json(items);
});

// Get a specific item
app.get('/api/items/:itemId', async (req, res) => {
  const item = await prisma.product.findUnique({
    where: { id: parseInt(req.params.itemId) },
  });
  if (!item) return res.status(404).json({ message: 'Item not found' });
  res.json(item);
});

// Get reviews of an item
app.get('/api/items/:itemId/reviews', async (req, res) => {
  const reviews = await prisma.review.findMany({
    where: { productId: parseInt(req.params.itemId) },
    include: { user: { select: { name: true } } },
  });
  res.json(reviews);
});

// Get a specific review for an item
app.get('/api/items/:itemId/reviews/:reviewId', async (req, res) => {
  const review = await prisma.review.findUnique({
    where: { id: parseInt(req.params.reviewId) },
    include: { user: { select: { name: true } }, product: true },
  });
  if (!review) return res.status(404).json({ message: 'Review not found' });
  res.json(review);
});

// Create a review (Authenticated)
app.post('/api/items/:itemId/reviews', authenticate, async (req, res) => {
  const { content, rating } = req.body;
  const review = await prisma.review.create({
    data: {
      content,
      rating,
      productId: parseInt(req.params.itemId),
      userId: req.userId,
    },
  });
  res.status(201).json({ message: 'Review created successfully', review });
});

// Get user's reviews (Authenticated)
app.get('/api/reviews/me', authenticate, async (req, res) => {
  const reviews = await prisma.review.findMany({
    where: { userId: req.userId },
    include: { product: { select: { name: true } } },
  });
  res.json(reviews);
});

// Edit a review (Authenticated, User must own the review)
app.put('/api/users/:userId/reviews/:reviewId', authenticate, async (req, res) => {
  const { userId, reviewId } = req.params;
  const { content, rating } = req.body;

  // Ensure the user is editing their own review
  if (parseInt(userId) !== req.userId) {
    return res.status(403).json({ message: 'You cannot edit someone else\'s review' });
  }

  const review = await prisma.review.update({
    where: { id: parseInt(reviewId) },
    data: { content, rating },
  });

  res.json({ message: 'Review updated successfully', review });
});

// Create a comment on a review (Authenticated)
app.post('/api/items/:itemId/reviews/:reviewId/comments', authenticate, async (req, res) => {
  const { comment } = req.body;
  const { reviewId } = req.params;

  const newComment = await prisma.comment.create({
    data: {
      content: comment,
      reviewId: parseInt(reviewId),
      userId: req.userId,
    },
  });

  res.status(201).json({ message: 'Comment added successfully', comment: newComment });
});

// Get user's comments (Authenticated)
app.get('/api/comments/me', authenticate, async (req, res) => {
  const comments = await prisma.comment.findMany({
    where: { userId: req.userId },
    include: { review: { select: { content: true } } },
  });
  res.json(comments);
});

// Edit a comment (Authenticated, User must own the comment)
app.put('/api/users/:userId/comments/:commentId', authenticate, async (req, res) => {
  const { userId, commentId } = req.params;
  const { content } = req.body;

  if (parseInt(userId) !== req.userId) {
    return res.status(403).json({ message: 'You cannot edit someone else\'s comment' });
  }

  const comment = await prisma.comment.update({
    where: { id: parseInt(commentId) },
    data: { content },
  });

  res.json({ message: 'Comment updated successfully', comment });
});

// Delete a comment (Authenticated, User must own the comment)
app.delete('/api/users/:userId/comments/:commentId', authenticate, async (req, res) => {
  const { userId, commentId } = req.params;

  if (parseInt(userId) !== req.userId) {
    return res.status(403).json({ message: 'You cannot delete someone else\'s comment' });
  }

  await prisma.comment.delete({
    where: { id: parseInt(commentId) },
  });

  res.json({ message: 'Comment deleted successfully' });
});

// Delete a review (Authenticated, User must own the review)
app.delete('/api/users/:userId/reviews/:reviewId', authenticate, async (req, res) => {
  const { userId, reviewId } = req.params;

  if (parseInt(userId) !== req.userId) {
    return res.status(403).json({ message: 'You cannot delete someone else\'s review' });
  }

  await prisma.review.delete({
    where: { id: parseInt(reviewId) },
  });

  res.json({ message: 'Review deleted successfully' });
});

// Start the server
const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
