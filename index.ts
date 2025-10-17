import { Hono } from "hono";
import { googleAuth } from '@hono/oauth-providers/google';
import { getCookie, setCookie } from 'hono/cookie';
import { sign, verify } from 'hono/jwt';

// Define the shape of our user session
type UserSession = {
  name: string;
  email: string;
};

// Bindings type to extend Hono's environment
type Bindings = {
  GOOGLE_CLIENT_ID: string;
  GOOGLE_CLIENT_SECRET: string;
  CF_ACCESS_ClIENT_SECRET: string;
};

const app = new Hono<{ Bindings: Bindings }>();

// OAuth middleware with correct callback URL
app.use(
  '/auth/google/*',
  googleAuth({
    client_id: (c) => c.env.GOOGLE_CLIENT_ID,
    client_secret: (c) => c.env.GOOGLE_CLIENT_SECRET,
    scope: ['openid', 'email', 'profile'],
  })
);


// Route to handle the callback from Google
app.get('/auth/google/callback', async (c) => {
  const { user } = c.get('user-google-auth');

  if (!user) {
    return c.text('User not found', 400);
  }

  // Create a JWT with user info
  const payload = {
    name: user.name,
    email: user.email,
  };
  const token = await sign(payload, c.env.CF_ACCESS_ClIENT_SECRET);
    // Set the JWT as a cookie for session management
  setCookie(c, 'token', token, {
    httpOnly: true,
    secure: true,
    maxAge: 60 * 60 * 24, // 1 day
    path: '/',
  });

  return c.redirect('/secret');
});

// Middleware to check for an active session
const authMiddleware = async (c, next) => {
  const token = getCookie(c, 'token');
  if (!token) {
    return c.text('Unauthorized', 401);
  }
    try {
    const payload = await verify(token, c.env.CF_ACCESS_ClIENT_SECRET);
    c.set('session', payload as UserSession);
    await next();
  } catch (error) {
    return c.text('Invalid token', 401);
  }
};

// Protected route that requires a session
app.get('/secret', authMiddleware, (c) => {
  const session = c.get('session');
  return c.json({
    message: `Hello, ${session.name}! Your email is ${session.email}.`,
  });
});

// Root route with login link
app.get('/secret', (c) => {
  return c.html(`
    <p>Please log in.</p>
    <a href="/auth/google">Log in with Google</a>
  `);
});

export default app;
