require('dotenv').config();
const express    = require('express');
const mongoose   = require('mongoose');
const bcrypt     = require('bcryptjs');
const jwt        = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const path       = require('path');
const session    = require('express-session');
const passport   = require('passport');
const OIDCStrategy = require('passport-azure-ad').OIDCStrategy;

const app = express();

// ─── MIDDLEWARE ───────────────────────────────────────
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
  secret: process.env.SESSION_SECRET || 'supersecret',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false }
}));
app.use(passport.initialize());
app.use(passport.session());

// ─── MONGODB CONNECTION ───────────────────────────────
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/projectdashboard')
  .then(() => console.log('✅ MongoDB Connected'))
  .catch(err => console.error('MongoDB Error:', err));

// ─── USER SCHEMA ──────────────────────────────────────
const userSchema = new mongoose.Schema({
  name:         { type: String, required: true },
  username:     { type: String, unique: true, sparse: true },
  email:        { type: String, unique: true, required: true },
  password:     { type: String },          // hashed
  department:   { type: String },
  reason:       { type: String },
  azureId:      { type: String },
  status:       { type: String, enum: ['pending','approved','rejected'], default: 'pending' },
  loginCount:   { type: Number, default: 0 },
  lastLogin:    { type: Date },
  requestedAt:  { type: Date, default: Date.now },
  approvedAt:   { type: Date },
  approvedBy:   { type: String },
  role:         { type: String, enum: ['user','admin'], default: 'user' }
});

const User = mongoose.model('User', userSchema);

// ─── EMAIL SERVICE ────────────────────────────────────
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST || 'smtp.gmail.com',
  port: 587,
  secure: false,
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS
  }
});

const sendEmail = async (to, subject, html) => {
  try {
    await transporter.sendMail({ from: process.env.SMTP_USER, to, subject, html });
    console.log(`Email sent to ${to}`);
  } catch (err) {
    console.error('Email error:', err.message);
  }
};

// ─── AZURE AD SSO ─────────────────────────────────────
passport.use(new OIDCStrategy({
  identityMetadata: `https://login.microsoftonline.com/${process.env.AZURE_TENANT_ID}/v2.0/.well-known/openid-configuration`,
  clientID:          process.env.AZURE_CLIENT_ID,
  clientSecret:      process.env.AZURE_CLIENT_SECRET,
  responseType:      'code id_token',
  responseMode:      'form_post',
  redirectUrl:       process.env.REDIRECT_URI,
  allowHttpForRedirectUrl: true,
  scope:             ['profile', 'email', 'openid'],
  passReqToCallback: false
}, async (iss, sub, profile, done) => {
  try {
    const email = profile._json.preferred_username || profile._json.email;
    let user    = await User.findOne({ email });
    if (!user) {
      user = await User.create({
        name:    profile.displayName,
        email,
        azureId: profile.oid,
        status:  'pending'
      });
      // Notify admin
      await sendEmail(process.env.ADMIN_EMAIL, '🔔 New SSO Access Request',
        `<h3>New Access Request</h3>
         <p><b>Name:</b> ${user.name}</p>
         <p><b>Email:</b> ${user.email}</p>
         <a href="${process.env.APP_URL}/admin">Review Requests →</a>`
      );
    }
    return done(null, user);
  } catch (err) {
    return done(err);
  }
}));

passport.serializeUser((user, done)   => done(null, user._id));
passport.deserializeUser(async (id, done) => {
  const user = await User.findById(id);
  done(null, user);
});

// ─── MIDDLEWARE: AUTH CHECK ───────────────────────────
const requireApproved = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1] || req.cookies?.token;
  if (!token) return res.status(401).json({ message: 'Not authenticated' });
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = decoded.userId;
    next();
  } catch {
    res.status(401).json({ message: 'Invalid token' });
  }
};

const requireAdmin = async (req, res, next) => {
  const user = await User.findById(req.userId);
  if (!user || user.role !== 'admin') return res.status(403).json({ message: 'Admin only' });
  next();
};

// ════════════════════════════════════════════════════
//                    ROUTES
// ════════════════════════════════════════════════════

// ─── Serve Login Page ─────────────────────────────────
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// ─── SSO Routes ───────────────────────────────────────
app.get('/auth/login', passport.authenticate('azuread-openidconnect', { failureRedirect: '/' }));

app.post('/auth/callback',
  passport.authenticate('azuread-openidconnect', { failureRedirect: '/' }),
  async (req, res) => {
    const user = req.user;
    if (user.status === 'pending')   return res.redirect('/?status=pending');
    if (user.status === 'rejected')  return res.redirect('/?status=rejected');
    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '8h' });
    res.redirect(`/dashboard?token=${token}`);
  }
);

// ─── API: Register / Request Access ──────────────────
app.post('/api/request-access', async (req, res) => {
  try {
    const { name, email, department, reason, username, password } = req.body;
    if (!name || !email) return res.status(400).json({ message: 'Name and email are required.' });

    const exists = await User.findOne({ email });
    if (exists) return res.status(409).json({ message: 'Email already registered.' });

    const hashedPassword = password ? await bcrypt.hash(password, 10) : undefined;

    const user = await User.create({
      name, email, department, reason,
      username: username || email,
      password: hashedPassword,
      status: 'pending'
    });

    // Notify Admin
    await sendEmail(process.env.ADMIN_EMAIL, '🔔 New Access Request - Project Execution Dashboard',
      `<div style="font-family:Arial,sans-serif;max-width:600px;margin:auto">
        <h2 style="color:#FF000F">New Access Request</h2>
        <table>
          <tr><td><b>Name:</b></td><td>${user.name}</td></tr>
          <tr><td><b>Email:</b></td><td>${user.email}</td></tr>
          <tr><td><b>Department:</b></td><td>${user.department || 'N/A'}</td></tr>
          <tr><td><b>Reason:</b></td><td>${user.reason || 'N/A'}</td></tr>
          <tr><td><b>Requested:</b></td><td>${new Date().toLocaleString()}</td></tr>
        </table>
        <br>
        <a href="${process.env.APP_URL}/admin" style="background:#FF000F;color:white;padding:10px 20px;border-radius:6px;text-decoration:none">
          Review Request →
        </a>
      </div>`
    );

    // Notify User
    await sendEmail(email, '✅ Access Request Received',
      `<h3>Hello ${name},</h3>
       <p>Your request to access <b>Project Execution Dashboard</b> has been received.</p>
       <p>The admin will review and notify you shortly.</p>`
    );

    res.status(201).json({ message: 'Request submitted! You will be notified via email.', userId: user._id });
  } catch (err) {
    res.status(500).json({ message: 'Server error.', error: err.message });
  }
});

// ─── API: Login with credentials ─────────────────────
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ $or: [{ username }, { email: username }] });

    if (!user)  return res.status(404).json({ message: 'User not found.', status: 'not_found' });
    if (user.status === 'pending')  return res.json({ status: 'pending',  message: 'Account pending admin approval.' });
    if (user.status === 'rejected') return res.json({ status: 'rejected', message: 'Access was denied.' });

    const isValid = await bcrypt.compare(password, user.password || '');
    if (!isValid) return res.status(401).json({ message: 'Invalid credentials.', status: 'error' });

    // Update login stats
    await User.findByIdAndUpdate(user._id, {
      lastLogin:  new Date(),
      $inc: { loginCount: 1 }
    });

    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '8h' });
    res.json({ status: 'approved', token, name: user.name, email: user.email });
  } catch (err) {
    res.status(500).json({ message: 'Server error.', status: 'error' });
  }
});

// ─── ADMIN: Get all pending/all users ────────────────
app.get('/admin/users', requireApproved, requireAdmin, async (req, res) => {
  const { status } = req.query;
  const filter = status ? { status } : {};
  const users  = await User.find(filter).select('-password').sort({ requestedAt: -1 });
  res.json(users);
});

// ─── ADMIN: Approve user ─────────────────────────────
app.post('/admin/approve/:userId', requireApproved, requireAdmin, async (req, res) => {
  try {
    const admin = await User.findById(req.userId);
    const user  = await User.findByIdAndUpdate(req.params.userId,
      { status: 'approved', approvedAt: new Date(), approvedBy: admin.email },
      { new: true }
    );

    await sendEmail(user.email, '✅ Access Approved - Project Execution Dashboard',
      `<div style="font-family:Arial,sans-serif;max-width:600px;margin:auto">
        <h2 style="color:#00c864">🎉 Access Approved!</h2>
        <p>Hello <b>${user.name}</b>,</p>
        <p>Your request to access the <b>Project Execution Dashboard</b> has been <b>approved</b>!</p>
        <p>You can now login using your credentials.</p>
        <br>
        <a href="${process.env.APP_URL}" style="background:#FF000F;color:white;padding:10px 20px;border-radius:6px;text-decoration:none">
          Login Now →
        </a>
      </div>`
    );

    res.json({ message: 'User approved and notified.', user });
  } catch (err) {
    res.status(500).json({ message: 'Error approving user.' });
  }
});

// ─── ADMIN: Reject user ──────────────────────────────
app.post('/admin/reject/:userId', requireApproved, requireAdmin, async (req, res) => {
  try {
    const { reason } = req.body;
    const user = await User.findByIdAndUpdate(req.params.userId,
      { status: 'rejected' },
      { new: true }
    );

    await sendEmail(user.email, '❌ Access Request Declined',
      `<p>Hello <b>${user.name}</b>,</p>
       <p>Your access request was declined.</p>
       <p><b>Reason:</b> ${reason || 'No reason provided.'}</p>
       <p>Contact the admin for more information.</p>`
    );

    res.json({ message: 'User rejected and notified.', user });
  } catch (err) {
    res.status(500).json({ message: 'Error rejecting user.' });
  }
});

// ─── Protected Dashboard ─────────────────────────────
app.get('/dashboard', (req, res) => {
  res.send(`<h1>Welcome to Project Execution Dashboard!</h1><p>You are logged in.</p>`);
});

// ─── Admin Panel ─────────────────────────────────────
app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// ─── START SERVER ─────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Server running at http://localhost:${PORT}`);
});
