const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
require('dotenv').config();

const app = express();
app.use(express.json());
app.use(cors());

const dbConfig = {
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
};

let pool;
async function getPool() {
  if (!pool) pool = mysql.createPool(dbConfig);
  return pool;
}

function auth(roles = []) {
  return (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'No token' });
    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      if (roles.length && !roles.includes(decoded.role))
        return res.status(403).json({ error: 'Forbidden' });
      req.user = decoded;
      next();
    } catch {
      res.status(401).json({ error: 'Invalid token' });
    }
  };
}

app.get('/health', (req, res) => res.json({ status: 'healthy', timestamp: new Date() }));

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  const db = await getPool();
  const [rows] = await db.query('SELECT * FROM users WHERE email = ?', [email]);
  if (!rows.length) return res.status(401).json({ error: 'Invalid credentials' });
  const user = rows[0];
  const valid = await bcrypt.compare(password, user.password_hash);
  if (!valid) return res.status(401).json({ error: 'Invalid credentials' });
  const token = jwt.sign(
    { id: user.id, email: user.email, role: user.role, name: user.name },
    process.env.JWT_SECRET,
    { expiresIn: '8h' }
  );
  res.json({ token, role: user.role, name: user.name });
});

app.get('/api/students', auth(['admin', 'teacher']), async (req, res) => {
  const db = await getPool();
  const [rows] = await db.query(
    `SELECT s.id, u.name, u.email, s.roll_number, s.department, s.year
     FROM students s JOIN users u ON s.user_id = u.id ORDER BY s.roll_number`
  );
  res.json(rows);
});

app.get('/api/students/:id/results', auth(['admin', 'teacher', 'student']), async (req, res) => {
  const db = await getPool();
  const studentId = req.params.id;
  if (req.user.role === 'student') {
    const [me] = await db.query('SELECT id FROM students WHERE user_id = ?', [req.user.id]);
    if (!me.length || me[0].id != studentId)
      return res.status(403).json({ error: 'Access denied' });
  }
  const [results] = await db.query(
    `SELECT r.id, sub.name AS subject, sub.code, r.marks_obtained, r.max_marks,
            r.grade, r.semester, r.exam_date, u.name AS teacher_name
     FROM results r
     JOIN subjects sub ON r.subject_id = sub.id
     JOIN users u ON r.entered_by = u.id
     WHERE r.student_id = ?
     ORDER BY r.semester, sub.name`,
    [studentId]
  );
  res.json(results);
});

app.post('/api/results', auth(['teacher', 'admin']), async (req, res) => {
  const { student_id, subject_id, marks_obtained, max_marks, semester, exam_date } = req.body;
  const percentage = (marks_obtained / max_marks) * 100;
  const grade =
    percentage >= 90 ? 'O' :
    percentage >= 80 ? 'A+' :
    percentage >= 70 ? 'A' :
    percentage >= 60 ? 'B+' :
    percentage >= 50 ? 'B' :
    percentage >= 40 ? 'C' : 'F';

  const db = await getPool();
  const [existing] = await db.query(
    'SELECT id FROM results WHERE student_id = ? AND subject_id = ? AND semester = ?',
    [student_id, subject_id, semester]
  );
  if (existing.length) {
    await db.query(
      'UPDATE results SET marks_obtained=?, max_marks=?, grade=?, exam_date=?, entered_by=? WHERE id=?',
      [marks_obtained, max_marks, grade, exam_date, req.user.id, existing[0].id]
    );
    return res.json({ message: 'Result updated', grade });
  }
  await db.query(
    'INSERT INTO results (student_id, subject_id, marks_obtained, max_marks, grade, semester, exam_date, entered_by) VALUES (?,?,?,?,?,?,?,?)',
    [student_id, subject_id, marks_obtained, max_marks, grade, semester, exam_date, req.user.id]
  );
  res.status(201).json({ message: 'Result added', grade });
});

app.get('/api/subjects', auth(['admin', 'teacher', 'student']), async (req, res) => {
  const db = await getPool();
  const [rows] = await db.query('SELECT * FROM subjects ORDER BY department, semester, name');
  res.json(rows);
});

app.get('/api/analytics/summary', auth(['admin', 'teacher']), async (req, res) => {
  const db = await getPool();
  const [[totals]] = await db.query(
    `SELECT COUNT(DISTINCT r.student_id) AS total_students,
            COUNT(*) AS total_results,
            ROUND(AVG(r.marks_obtained / r.max_marks * 100), 2) AS avg_percentage,
            SUM(CASE WHEN r.grade = 'F' THEN 1 ELSE 0 END) AS failed_count
     FROM results r`
  );
  const [gradeBreakdown] = await db.query(
    `SELECT grade, COUNT(*) AS count FROM results GROUP BY grade ORDER BY grade`
  );
  const [topStudents] = await db.query(
    `SELECT u.name, s.roll_number, s.department,
            ROUND(AVG(r.marks_obtained / r.max_marks * 100), 2) AS avg_pct
     FROM results r
     JOIN students s ON r.student_id = s.id
     JOIN users u ON s.user_id = u.id
     GROUP BY r.student_id ORDER BY avg_pct DESC LIMIT 5`
  );
  res.json({ totals, gradeBreakdown, topStudents });
});

app.get('/api/students/me', auth(['student']), async (req, res) => {
  const db = await getPool();
  const [rows] = await db.query(
    `SELECT s.id, u.name, u.email, s.roll_number, s.department, s.year
     FROM students s JOIN users u ON s.user_id = u.id WHERE s.user_id = ?`,
    [req.user.id]
  );
  if (!rows.length) return res.status(404).json({ error: 'Student not found' });
  res.json(rows[0]);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
