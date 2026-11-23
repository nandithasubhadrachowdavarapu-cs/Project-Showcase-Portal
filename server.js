require('dotenv').config();
const express = require('express'), mongoose = require('mongoose'), bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken'), multer = require('multer'), path = require('path'), fs = require('fs');

const SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';
const upDir = path.join(__dirname, 'uploads');
fs.mkdirSync(upDir, { recursive: true });
const upload = multer({
  storage: multer.diskStorage({
    destination: upDir,
    filename: (req, f, cb) => cb(null, Date.now() + '-' + f.originalname.replace(/[^\w.-]/g, '_')),
  }),
  limits: { fileSize: 5 * 1024 * 1024 },
});

const User = mongoose.model('User', new mongoose.Schema({
  name: String, email: { type: String, unique: true }, password: String,
  role: { type: String, enum: ['student', 'teacher'] },
}));
const Project = mongoose.model('Project', new mongoose.Schema({
  owner: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }, ownerName: String,
  title: String, course: String, desc: String, tags: [String], link: { type: String, default: '' },
  file: { name: String, data: String },
  status: { type: String, enum: ['submitted', 'approved', 'revision'], default: 'submitted' },
  score: Number, feedback: { type: String, default: '' }, reviewer: { type: String, default: '' },
}, { timestamps: true }));

const dto = p => ({
  id: p.id, owner: String(p.owner), ownerName: p.ownerName, title: p.title, course: p.course, desc: p.desc,
  tags: p.tags, link: p.link, file: p.file && p.file.data ? { name: p.file.name, data: p.file.data } : null,
  status: p.status, score: p.score ?? null, feedback: p.feedback, reviewer: p.reviewer, created: p.createdAt.getTime(),
});
const sign = u => jwt.sign({ id: u.id, role: u.role }, SECRET, { expiresIn: '7d' });
const userOut = u => ({ id: u.id, name: u.name, email: u.email, role: u.role });

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(upDir));

// Attach req.user if a valid token is sent (guests are allowed on public routes)
app.use(async (req, res, next) => {
  const t = (req.headers.authorization || '').replace('Bearer ', '');
  if (t) try { const d = jwt.verify(t, SECRET); req.user = await User.findById(d.id); } catch (e) {}
  next();
});
const need = role => (req, res, next) =>
  !req.user ? res.status(401).json({ error: 'Please sign in first.' })
  : role && req.user.role !== role ? res.status(403).json({ error: 'You don’t have access to that.' }) : next();

app.post('/api/register', async (req, res) => {
  const { name, email, password, role } = req.body;
  if (!name || !email || !password || password.length < 6) return res.status(400).json({ error: 'Enter your name, email and a password of at least 6 characters.' });
  if (await User.findOne({ email: email.toLowerCase() })) return res.status(400).json({ error: 'An account with that email already exists. Sign in instead.' });
  const u = await User.create({ name, email: email.toLowerCase(), password: await bcrypt.hash(password, 10), role: role === 'teacher' ? 'teacher' : 'student' });
  res.json({ token: sign(u), user: userOut(u) });
});
app.post('/api/login', async (req, res) => {
  const u = await User.findOne({ email: String(req.body.email || '').toLowerCase() });
  if (!u || !(await bcrypt.compare(req.body.password || '', u.password))) return res.status(400).json({ error: 'Email or password is incorrect. Check both and try again.' });
  res.json({ token: sign(u), user: userOut(u) });
});
app.get('/api/me', need(), (req, res) => res.json(userOut(req.user)));

app.get('/api/projects', async (req, res) => {
  const u = req.user;
  const filter = !u ? { status: 'approved' } : u.role === 'teacher' ? {} : { $or: [{ status: 'approved' }, { owner: u.id }] };
  res.json((await Project.find(filter).sort({ createdAt: -1 })).map(dto));
});
const fields = (b, file) => {
  const d = { title: b.title, course: b.course, desc: b.desc, link: b.link || '',
    tags: String(b.tags || '').split(',').map(s => s.trim()).filter(Boolean) };
  if (file) d.file = { name: file.originalname, data: '/uploads/' + file.filename };
  return d;
};
app.post('/api/projects', need('student'), upload.single('file'), async (req, res) => {
  if (!req.body.title || !req.body.course || !req.body.desc) return res.status(400).json({ error: 'Title, course and description are required.' });
  res.json(dto(await Project.create({ ...fields(req.body, req.file), owner: req.user.id, ownerName: req.user.name })));
});
app.put('/api/projects/:id', need('student'), upload.single('file'), async (req, res) => {
  const p = await Project.findOne({ _id: req.params.id, owner: req.user.id });
  if (!p) return res.status(404).json({ error: 'Project not found.' });
  Object.assign(p, fields(req.body, req.file));
  if (p.status === 'revision') p.status = 'submitted';
  res.json(dto(await p.save()));
});
app.delete('/api/projects/:id', need('student'), async (req, res) => {
  const p = await Project.findOneAndDelete({ _id: req.params.id, owner: req.user.id });
  if (!p) return res.status(404).json({ error: 'Project not found.' });
  if (p.file && p.file.data) fs.unlink(path.join(__dirname, p.file.data), () => {});
  res.json({ ok: true });
});
app.put('/api/projects/:id/review', need('teacher'), async (req, res) => {
  const { score, status, feedback } = req.body;
  if (!['approved', 'revision'].includes(status) || !(score >= 0 && score <= 100)) return res.status(400).json({ error: 'Enter a score from 0 to 100 and a decision.' });
  const p = await Project.findByIdAndUpdate(req.params.id, { score, status, feedback, reviewer: req.user.name }, { new: true });
  p ? res.json(dto(p)) : res.status(404).json({ error: 'Project not found.' });
});

app.use((err, req, res, next) => res.status(400).json({ error: err.code === 'LIMIT_FILE_SIZE' ? 'That file is over 5 MB.' : err.message }));

async function seed() {
  if (await User.countDocuments()) return;
  const h = await bcrypt.hash('learn123', 10), t = await bcrypt.hash('teach123', 10);
  const s = await User.create({ name: 'Asha Verma', email: 'student@demo.edu', password: h, role: 'student' });
  await User.create({ name: 'Dr. Rao', email: 'teacher@demo.edu', password: t, role: 'teacher' });
  await Project.create([
    { owner: s.id, ownerName: s.name, title: 'Smart Campus Attendance Tracker', course: 'Software Engineering', desc: 'A QR-based attendance system for lecture halls. Faculty open a session, students scan a rotating code, and reports export to CSV.', tags: ['Node.js', 'MongoDB', 'QR'], status: 'approved', score: 92, feedback: 'Clean architecture and a thoughtful rotating-code design.', reviewer: 'Dr. Rao' },
    { owner: s.id, ownerName: s.name, title: 'Canteen Queue Predictor', course: 'Machine Learning', desc: 'Predicts canteen wait times from timetable and weather data.', tags: ['Python', 'ML'] },
  ]);
}
mongoose.connect(process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/course_project_portal')
  .then(seed)
  .then(() => app.listen(process.env.PORT || 3000, () => console.log('Portal running on http://localhost:' + (process.env.PORT || 3000))))
  .catch(e => { console.error('Could not connect to MongoDB:', e.message); process.exit(1); });
