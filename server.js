const express = require('express');
const supabase = require('./supabase');
const multer = require('multer');
const cors = require('cors');
require('dotenv').config();
const bcrypt = require('bcrypt');


const app = express();
const upload = multer({ storage: multer.memoryStorage() });

app.use(cors());
app.use(express.json());
const requireAuth = async (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Missing or invalid authorization header' });
  }

  const token = authHeader.split(' ')[1];
  const { data: { user }, error } = await supabase.auth.getUser(token);

  if (error || !user) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }

  req.user = user;
  next();
};


app.post("/create-account", async (req, res) => {
  try {
    const { role, firstName, lastName, employeeId,
            department, email, password, adminCode } = req.body;

    const hashedPassword = await bcrypt.hash(password, 10);

    const { data, error } = await supabase
      .from("users")
      .insert([{
        role,
        first_name: firstName,
        last_name: lastName,
        employee_id: employeeId || null,
        department:  department || null,
        email,
        password:   hashedPassword,
        admin_code: adminCode || null,
      }])
      .select(); // ← critical fix

    if (error) {
      return res.status(400).json({ success: false, message: error.message });
    }

    res.json({ success: true, message: "Account created successfully", data });

  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// ── Sign In ───────────────────────────────────────────────────────────────────
app.post('/auth/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }

  const { data, error } = await supabase.auth.signInWithPassword({ email, password });

  if (error) return res.status(401).json({ error: error.message });
  res.json({
    message: 'Login successful',
    access_token: data.session.access_token,
    refresh_token: data.session.refresh_token,
    user: data.user,
  });
});

// ── Sign Out ──────────────────────────────────────────────────────────────────
app.post('/auth/logout', requireAuth, async (req, res) => {
  const { error } = await supabase.auth.signOut();
  if (error) return res.status(400).json({ error: error.message });
  res.json({ message: 'Logged out successfully' });
});

// ── Get Current User ──────────────────────────────────────────────────────────
app.get('/auth/me', requireAuth, (req, res) => {
  res.json({ user: req.user });
});

// ── Reset Password ────────────────────────────────────────────────────────────
app.post('/auth/reset-password', async (req, res) => {
  const { email } = req.body;
  const { error } = await supabase.auth.resetPasswordForEmail(email, {
    redirectTo: `${process.env.APP_URL}/reset-password`,
  });
  if (error) return res.status(400).json({ error: error.message });
  res.json({ message: 'Password reset email sent' });
});

// ── Refresh Token ─────────────────────────────────────────────────────────────
app.post('/auth/refresh', async (req, res) => {
  const { refresh_token } = req.body;
  const { data, error } = await supabase.auth.refreshSession({ refresh_token });
  if (error) return res.status(401).json({ error: error.message });
  res.json({
    access_token: data.session.access_token,
    refresh_token: data.session.refresh_token,
  });
});

// =============================================================================
// DATABASE (CRUD) ROUTES  — example table: "work_entries"
// Change "work_entries" to your actual table name
// =============================================================================

// ── GET all records (with optional filters) ───────────────────────────────────
app.get('/entries', requireAuth, async (req, res) => {
  const { date, limit = 50, offset = 0 } = req.query;

  let query = supabase
    .from('work_entries')
    .select('*')
    .eq('employee_id', req.user.id)  // only fetch current user's data
    .order('created_at', { ascending: false })
    .range(Number(offset), Number(offset) + Number(limit) - 1);

  if (date) query = query.eq('date', date);

  const { data, error } = await query;
  if (error) return res.status(400).json({ error: error.message });
  res.json({ data, count: data.length });
});

// ── GET single record by ID ───────────────────────────────────────────────────
app.get('/entries/:id', requireAuth, async (req, res) => {
  const { data, error } = await supabase
    .from('work_entries')
    .select('*')
    .eq('id', req.params.id)
    .eq('employee_id', req.user.id)
    .single();

  if (error) return res.status(404).json({ error: 'Entry not found' });
  res.json({ data });
});

// ── CREATE record ─────────────────────────────────────────────────────────────
app.post('/entries', requireAuth, async (req, res) => {
  const { date, client, project, work_category, description, minutes, location, start_time, end_time } = req.body;

  if (!date || !client || !project || !description) {
    return res.status(400).json({ error: 'date, client, project and description are required' });
  }

  const { data, error } = await supabase
    .from('work_entries')
    .insert([{
      employee_id: req.user.id,
      date,
      client,
      project,
      work_category,
      description,
      minutes,
      location,
      start_time,
      end_time,
      created_at: new Date().toISOString(),
    }])
    .select()
    .single();

  if (error) return res.status(400).json({ error: error.message });
  res.status(201).json({ message: 'Entry created', data });
});

// ── UPDATE record ─────────────────────────────────────────────────────────────
app.put('/entries/:id', requireAuth, async (req, res) => {
  const updates = req.body;

  const { data, error } = await supabase
    .from('work_entries')
    .update({ ...updates, updated_at: new Date().toISOString() })
    .eq('id', req.params.id)
    .eq('employee_id', req.user.id) // ensure user owns the record
    .select()
    .single();

  if (error) return res.status(400).json({ error: error.message });
  res.json({ message: 'Entry updated', data });
});

// ── DELETE record ─────────────────────────────────────────────────────────────
app.delete('/entries/:id', requireAuth, async (req, res) => {
  const { error } = await supabase
    .from('work_entries')
    .delete()
    .eq('id', req.params.id)
    .eq('employee_id', req.user.id);

  if (error) return res.status(400).json({ error: error.message });
  res.json({ message: 'Entry deleted successfully' });
});

// =============================================================================
// STORAGE ROUTES
// =============================================================================

// ── Upload file ───────────────────────────────────────────────────────────────
app.post('/storage/upload', requireAuth, upload.single('file'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file provided' });

  const { bucket = 'uploads' } = req.body;
  const fileName = `${req.user.id}/${Date.now()}_${req.file.originalname}`;

  const { data, error } = await supabase.storage
    .from(bucket)
    .upload(fileName, req.file.buffer, {
      contentType: req.file.mimetype,
      upsert: false,
    });

  if (error) return res.status(400).json({ error: error.message });

  // Get public URL
  const { data: urlData } = supabase.storage.from(bucket).getPublicUrl(fileName);

  res.status(201).json({
    message: 'File uploaded successfully',
    path: data.path,
    url: urlData.publicUrl,
  });
});

// ── List files ────────────────────────────────────────────────────────────────
app.get('/storage/files', requireAuth, async (req, res) => {
  const { bucket = 'uploads' } = req.query;

  const { data, error } = await supabase.storage
    .from(bucket)
    .list(`${req.user.id}/`, {
      limit: 100,
      offset: 0,
      sortBy: { column: 'created_at', order: 'desc' },
    });

  if (error) return res.status(400).json({ error: error.message });
  res.json({ data });
});

// ── Get signed URL (private file access) ─────────────────────────────────────
app.get('/storage/signed-url', requireAuth, async (req, res) => {
  const { bucket = 'uploads', path } = req.query;
  if (!path) return res.status(400).json({ error: 'File path is required' });

  const { data, error } = await supabase.storage
    .from(bucket)
    .createSignedUrl(path, 60 * 60); // 1 hour expiry

  if (error) return res.status(400).json({ error: error.message });
  res.json({ signedUrl: data.signedUrl });
});

// ── Delete file ───────────────────────────────────────────────────────────────
app.delete('/storage/files', requireAuth, async (req, res) => {
  const { bucket = 'uploads', path } = req.body;
  if (!path) return res.status(400).json({ error: 'File path is required' });

  const { error } = await supabase.storage.from(bucket).remove([path]);
  if (error) return res.status(400).json({ error: error.message });
  res.json({ message: 'File deleted successfully' });
});

// =============================================================================
// HEALTH CHECK
// =============================================================================
app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// =============================================================================
// START SERVER
// =============================================================================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
