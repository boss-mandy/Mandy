require("dotenv").config();

const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const rateLimit = require("express-rate-limit");
const { Pool } = require("pg");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 10000;
const JWT_SECRET = process.env.JWT_SECRET;
const DATABASE_URL = process.env.DATABASE_URL;

if (!JWT_SECRET || JWT_SECRET.length < 32) {
  console.error("Set JWT_SECRET in Render environment variables (at least 32 characters).");
  process.exit(1);
}

if (!DATABASE_URL) {
  console.error("Set DATABASE_URL to your PostgreSQL connection string.");
  process.exit(1);
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: process.env.DATABASE_SSL === "false"
    ? false
    : { rejectUnauthorized: false }
});

app.use(cors());
app.use(express.json({ limit: "1mb" }));
app.use(express.static(path.join(__dirname, "public")));

app.use("/api/auth", rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 30,
  standardHeaders: true,
  legacyHeaders: false
}));

const asyncRoute = fn => (req, res, next) =>
  Promise.resolve(fn(req, res, next)).catch(next);

function authenticate(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : "";

  if (!token) return res.status(401).json({ error: "Please sign in." });

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: "Invalid or expired token." });
  }
}

function adminOnly(req, res, next) {
  if (req.user.role !== "admin") {
    return res.status(403).json({ error: "Administrator access required." });
  }
  next();
}

function makeToken(user) {
  return jwt.sign(
    { id: user.id, role: user.role },
    JWT_SECRET,
    { expiresIn: "7d" }
  );
}

function safeUser(user) {
  return {
    id: user.id,
    name: user.name,
    email: user.email,
    role: user.role,
    created_at: user.created_at
  };
}

async function initDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS cbt_users (
      id BIGSERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'student'
        CHECK (role IN ('student','admin')),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS cbt_subjects (
      id BIGSERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      exam_type TEXT NOT NULL
        CHECK (exam_type IN ('WAEC','JAMB','BOTH')),
      description TEXT DEFAULT '',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS cbt_questions (
      id BIGSERIAL PRIMARY KEY,
      subject_id BIGINT NOT NULL REFERENCES cbt_subjects(id) ON DELETE CASCADE,
      question TEXT NOT NULL,
      options JSONB NOT NULL,
      correct_answer TEXT NOT NULL,
      explanation TEXT DEFAULT '',
      exam_type TEXT NOT NULL CHECK (exam_type IN ('WAEC','JAMB')),
      published BOOLEAN NOT NULL DEFAULT FALSE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS cbt_attempts (
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT NOT NULL REFERENCES cbt_users(id),
      subject_id BIGINT NOT NULL REFERENCES cbt_subjects(id),
      exam_type TEXT NOT NULL,
      questions JSONB NOT NULL,
      answers JSONB NOT NULL DEFAULT '{}',
      started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      ends_at TIMESTAMPTZ NOT NULL,
      submitted_at TIMESTAMPTZ,
      score INTEGER,
      total INTEGER,
      status TEXT NOT NULL DEFAULT 'in_progress'
        CHECK (status IN ('in_progress','submitted','expired'))
    );
  `);

  if (process.env.ADMIN_EMAIL && process.env.ADMIN_PASSWORD) {
    const email = process.env.ADMIN_EMAIL.trim().toLowerCase();
    const existing = await pool.query(
      "SELECT id, role FROM cbt_users WHERE email = $1",
      [email]
    );

    if (existing.rowCount) {
      if (existing.rows[0].role !== "admin") {
        await pool.query(
          "UPDATE cbt_users SET role='admin' WHERE id=$1",
          [existing.rows[0].id]
        );
      }
    } else {
      const hash = await bcrypt.hash(process.env.ADMIN_PASSWORD, 12);
      await pool.query(
        `INSERT INTO cbt_users(name,email,password_hash,role)
         VALUES($1,$2,$3,'admin')`,
        ["CBT Administrator", email, hash]
      );
    }
  }

  console.log("CBT database initialized.");
}

function validExamType(value) {
  return ["WAEC", "JAMB"].includes(value);
}

function publicQuestion(q) {
  return {
    id: q.id,
    subject_id: q.subject_id,
    question: q.question,
    options: q.options,
    exam_type: q.exam_type
  };
}

async function scoreAttempt(client, attempt, expired = false) {
  const questions = attempt.questions || [];
  const answers = attempt.answers || {};
  let score = 0;

  for (const q of questions) {
    const given = answers[String(q.id)];
    if (given !== undefined &&
        String(given).trim().toUpperCase() ===
        String(q.correct_answer).trim().toUpperCase()) {
      score++;
    }
  }

  const result = await client.query(
    `UPDATE cbt_attempts
     SET score=$1,total=$2,submitted_at=NOW(),status=$3
     WHERE id=$4 AND status='in_progress'
     RETURNING id,score,total,status,submitted_at`,
    [score, questions.length, expired ? "expired" : "submitted", attempt.id]
  );

  return result.rows[0] || attempt;
}

app.get("/api/health", (req, res) => {
  res.json({ status: "ok", service: "Mandy CBT API" });
});

/* REGISTER */

app.post("/api/auth/register", asyncRoute(async (req, res) => {
  const { name, email, password } = req.body || {};

  if (typeof name !== "string" || name.trim().length < 2 || name.trim().length > 100) {
    return res.status(400).json({ error: "Enter your full name." });
  }
  if (typeof email !== "string" ||
      !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim()) ||
      email.length > 254) {
    return res.status(400).json({ error: "Enter a valid email address." });
  }
  if (typeof password !== "string" || password.length < 8 || password.length > 128) {
    return res.status(400).json({ error: "Password must contain 8 to 128 characters." });
  }

  const normalizedEmail = email.trim().toLowerCase();
  const hash = await bcrypt.hash(password, 12);

  try {
    const result = await pool.query(
      `INSERT INTO cbt_users(name,email,password_hash,role)
       VALUES($1,$2,$3,'student')
       RETURNING id,name,email,role,created_at`,
      [name.trim(), normalizedEmail, hash]
    );
    const user = result.rows[0];
    res.status(201).json({
      message: "Account created successfully.",
      token: makeToken(user),
      user: safeUser(user)
    });
  } catch (error) {
    if (error.code === "23505") {
      return res.status(409).json({ error: "This email is already registered. Please sign in." });
    }
    throw error;
  }
}));

/* LOGIN */

app.post("/api/auth/login", asyncRoute(async (req, res) => {
  const { email, password } = req.body || {};
  if (typeof email !== "string" || typeof password !== "string") {
    return res.status(400).json({ error: "Email and password are required." });
  }

  const result = await pool.query(
    `SELECT id,name,email,password_hash,role,created_at
     FROM cbt_users WHERE email=$1`,
    [email.trim().toLowerCase()]
  );
  const user = result.rows[0];

  if (!user || !(await bcrypt.compare(password, user.password_hash))) {
    return res.status(401).json({ error: "Incorrect email or password." });
  }

  res.json({
    message: "Login successful.",
    token: makeToken(user),
    user: safeUser(user)
  });
}));

app.get("/api/me", authenticate, asyncRoute(async (req, res) => {
  const result = await pool.query(
    "SELECT id,name,email,role,created_at FROM cbt_users WHERE id=$1",
    [req.user.id]
  );
  if (!result.rowCount) return res.status(404).json({ error: "User not found." });
  res.json({ user: safeUser(result.rows[0]) });
}));

/* SUBJECTS */

app.get("/api/subjects", asyncRoute(async (req, res) => {
  const type = String(req.query.exam_type || "").toUpperCase();
  if (type && !validExamType(type)) {
    return res.status(400).json({ error: "exam_type must be WAEC or JAMB." });
  }

  const result = type
    ? await pool.query(
        `SELECT s.*, COUNT(q.id)::int AS question_count
         FROM cbt_subjects s
         LEFT JOIN cbt_questions q ON q.subject_id=s.id AND q.published=TRUE
           AND (q.exam_type=$1 OR s.exam_type='BOTH')
         WHERE s.exam_type=$1 OR s.exam_type='BOTH'
         GROUP BY s.id ORDER BY s.name`,
        [type]
      )
    : await pool.query(
        `SELECT s.*, COUNT(q.id)::int AS question_count
         FROM cbt_subjects s
         LEFT JOIN cbt_questions q ON q.subject_id=s.id AND q.published=TRUE
         GROUP BY s.id ORDER BY s.name`
      );

  res.json({ subjects: result.rows });
}));

/* PRACTICE QUESTIONS: correct answers are not exposed */

app.get("/api/subjects/:id/questions", authenticate, asyncRoute(async (req, res) => {
  const type = String(req.query.exam_type || "WAEC").toUpperCase();
  const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 20, 1), 100);

  if (!validExamType(type)) {
    return res.status(400).json({ error: "exam_type must be WAEC or JAMB." });
  }

  const subject = await pool.query(
    "SELECT id FROM cbt_subjects WHERE id=$1 AND (exam_type=$2 OR exam_type='BOTH')",
    [req.params.id, type]
  );
  if (!subject.rowCount) return res.status(404).json({ error: "Subject not found." });

  const result = await pool.query(
    `SELECT id,subject_id,question,options,exam_type
     FROM cbt_questions
     WHERE subject_id=$1 AND exam_type=$2 AND published=TRUE
     ORDER BY RANDOM() LIMIT $3`,
    [req.params.id, type, limit]
  );

  res.json({ questions: result.rows });
}));

/* START A TIMED EXAM */

app.post("/api/exams/start", authenticate, asyncRoute(async (req, res) => {
  const { subject_id, exam_type } = req.body || {};
  const type = String(exam_type || "").toUpperCase();
  const count = Math.min(Math.max(parseInt(req.body.count, 10) || 40, 1), 100);
  const duration = Math.min(Math.max(parseInt(req.body.duration_minutes, 10) || 60, 1), 180);

  if (!subject_id || !validExamType(type)) {
    return res.status(400).json({ error: "Select a valid subject and exam type." });
  }

  const subject = await pool.query(
    "SELECT id,name FROM cbt_subjects WHERE id=$1 AND (exam_type=$2 OR exam_type='BOTH')",
    [subject_id, type]
  );
  if (!subject.rowCount) return res.status(404).json({ error: "Subject not found." });

  const questionsResult = await pool.query(
    `SELECT id,subject_id,question,options,correct_answer,explanation,exam_type
     FROM cbt_questions
     WHERE subject_id=$1 AND exam_type=$2 AND published=TRUE
     ORDER BY RANDOM() LIMIT $3`,
    [subject_id, type, count]
  );

  if (!questionsResult.rowCount) {
    return res.status(400).json({ error: "No published questions are available for this subject yet." });
  }

  const questions = questionsResult.rows;
  const endsAt = new Date(Date.now() + duration * 60000);

  const result = await pool.query(
    `INSERT INTO cbt_attempts(user_id,subject_id,exam_type,questions,ends_at)
     VALUES($1,$2,$3,$4,$5)
     RETURNING id,started_at,ends_at,status`,
    [req.user.id, subject_id, type, JSON.stringify(questions), endsAt]
  );

  res.status(201).json({
    attempt: result.rows[0],
    subject: subject.rows[0],
    questions: questions.map(publicQuestion),
    duration_minutes: duration
  });
}));

/* SAVE ANSWERS */

app.put("/api/exams/:id/answers", authenticate, asyncRoute(async (req, res) => {
  const { answers } = req.body || {};
  if (!answers || typeof answers !== "object" || Array.isArray(answers)) {
    return res.status(400).json({ error: "Send an answers object." });
  }

  const result = await pool.query(
    `SELECT * FROM cbt_attempts
     WHERE id=$1 AND user_id=$2 AND status='in_progress'`,
    [req.params.id, req.user.id]
  );
  const attempt = result.rows[0];

  if (!attempt) return res.status(404).json({ error: "Active exam not found." });

  if (Date.now() >= new Date(attempt.ends_at).getTime()) {
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const locked = await client.query(
        "SELECT * FROM cbt_attempts WHERE id=$1 FOR UPDATE",
        [attempt.id]
      );
      const finished = await scoreAttempt(client, locked.rows[0], true);
      await client.query("COMMIT");
      return res.status(410).json({ error: "Time is up.", result: finished });
    } catch (e) {
      await client.query("ROLLBACK");
      throw e;
    } finally {
      client.release();
    }
  }

  const allowedIds = new Set((attempt.questions || []).map(q => String(q.id)));
  for (const [id, answer] of Object.entries(answers)) {
    if (!allowedIds.has(id) || typeof answer !== "string" || answer.length > 20) {
      return res.status(400).json({ error: "One or more answers are invalid." });
    }
  }

  const merged = { ...(attempt.answers || {}), ...answers };
  await pool.query(
    "UPDATE cbt_attempts SET answers=$1 WHERE id=$2 AND user_id=$3 AND status='in_progress'",
    [JSON.stringify(merged), attempt.id, req.user.id]
  );

  res.json({ message: "Answers saved." });
}));

/* SUBMIT EXAM */

app.post("/api/exams/:id/submit", authenticate, asyncRoute(async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const result = await client.query(
      "SELECT * FROM cbt_attempts WHERE id=$1 AND user_id=$2 FOR UPDATE",
      [req.params.id, req.user.id]
    );
    const attempt = result.rows[0];

    if (!attempt) {
      await client.query("ROLLBACK");
      return res.status(404).json({ error: "Exam attempt not found." });
    }
    if (attempt.status !== "in_progress") {
      await client.query("ROLLBACK");
      return res.status(409).json({ error: "This exam has already been submitted." });
    }

    const expired = Date.now() >= new Date(attempt.ends_at).getTime();
    const finished = await scoreAttempt(client, attempt, expired);
    await client.query("COMMIT");

    res.json({
      message: expired ? "Time expired. Exam submitted." : "Exam submitted successfully.",
      result: finished
    });
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}));

/* STUDENT RESULTS */

app.get("/api/results", authenticate, asyncRoute(async (req, res) => {
  const result = await pool.query(
    `SELECT a.id,a.exam_type,a.score,a.total,a.status,a.started_at,a.submitted_at,
            s.name AS subject
     FROM cbt_attempts a
     JOIN cbt_subjects s ON s.id=a.subject_id
     WHERE a.user_id=$1 AND a.status <> 'in_progress'
     ORDER BY a.submitted_at DESC NULLS LAST`,
    [req.user.id]
  );
  res.json({ results: result.rows });
}));

app.get("/api/results/:id", authenticate, asyncRoute(async (req, res) => {
  const result = await pool.query(
    `SELECT a.*,s.name AS subject
     FROM cbt_attempts a
     JOIN cbt_subjects s ON s.id=a.subject_id
     WHERE a.id=$1 AND a.user_id=$2 AND a.status <> 'in_progress'`,
    [req.params.id, req.user.id]
  );
  if (!result.rowCount) return res.status(404).json({ error: "Result not found." });

  const attempt = result.rows[0];
  const review = (attempt.questions || []).map(q => ({
    ...publicQuestion(q),
    correct_answer: q.correct_answer,
    explanation: q.explanation,
    selected_answer: (attempt.answers || {})[String(q.id)] || null,
    is_correct: String((attempt.answers || {})[String(q.id)] || "").toUpperCase() ===
      String(q.correct_answer).toUpperCase()
  }));

  res.json({ result: {
    id: attempt.id,
    subject: attempt.subject,
    exam_type: attempt.exam_type,
    score: attempt.score,
    total: attempt.total,
    status: attempt.status,
    submitted_at: attempt.submitted_at,
    review
  }});
}));

/* ADMIN: STUDENTS */

app.get("/api/admin/students", authenticate, adminOnly, asyncRoute(async (req, res) => {
  const result = await pool.query(
    `SELECT u.id,u.name,u.email,u.created_at,
            COUNT(a.id)::int AS exams_taken
     FROM cbt_users u
     LEFT JOIN cbt_attempts a ON a.user_id=u.id AND a.status <> 'in_progress'
     WHERE u.role='student'
     GROUP BY u.id ORDER BY u.created_at DESC`
  );
  res.json({ students: result.rows });
}));

/* ADMIN: CREATE SUBJECT */

app.post("/api/admin/subjects", authenticate, adminOnly, asyncRoute(async (req, res) => {
  const { name, exam_type, description = "" } = req.body || {};
  const type = String(exam_type || "").toUpperCase();

  if (typeof name !== "string" || name.trim().length < 2 ||
      !["WAEC", "JAMB", "BOTH"].includes(type)) {
    return res.status(400).json({ error: "Enter a subject name and valid exam type." });
  }

  const result = await pool.query(
    `INSERT INTO cbt_subjects(name,exam_type,description)
     VALUES($1,$2,$3) RETURNING *`,
    [name.trim(), type, String(description).slice(0, 1000)]
  );
  res.status(201).json({ subject: result.rows[0] });
}));

/* ADMIN: ADD QUESTION */

app.post("/api/admin/questions", authenticate, adminOnly, asyncRoute(async (req, res) => {
  const { subject_id, question, options, correct_answer, explanation = "", exam_type } = req.body || {};
  const type = String(exam_type || "").toUpperCase();

  if (!subject_id || typeof question !== "string" || !question.trim() ||
      !options || typeof options !== "object" || Array.isArray(options) ||
      Object.keys(options).length < 2 ||
      typeof correct_answer !== "string" ||
      !Object.prototype.hasOwnProperty.call(options, correct_answer) ||
      !["WAEC", "JAMB"].includes(type)) {
    return res.status(400).json({
      error: "Provide subject_id, question, options, correct_answer key and exam_type."
    });
  }

  const subject = await pool.query(
    "SELECT id FROM cbt_subjects WHERE id=$1 AND (exam_type=$2 OR exam_type='BOTH')",
    [subject_id, type]
  );
  if (!subject.rowCount) return res.status(400).json({ error: "Subject does not match this exam type." });

  const result = await pool.query(
    `INSERT INTO cbt_questions
     (subject_id,question,options,correct_answer,explanation,exam_type,published)
     VALUES($1,$2,$3,$4,$5,$6,TRUE) RETURNING id,subject_id,question,options,exam_type,published`,
    [
      subject_id,
      question.trim(),
      JSON.stringify(options),
      correct_answer,
      String(explanation).slice(0, 2000),
      type
    ]
  );
  res.status(201).json({ question: result.rows[0] });
}));

/* ADMIN: LIST QUESTIONS INCLUDING ANSWERS */

app.get("/api/admin/questions", authenticate, adminOnly, asyncRoute(async (req, res) => {
  const result = await pool.query(
    `SELECT q.*,s.name AS subject_name
     FROM cbt_questions q JOIN cbt_subjects s ON s.id=q.subject_id
     ORDER BY q.created_at DESC LIMIT 500`
  );
  res.json({ questions: result.rows });
}));

/* ADMIN: PUBLISH OR UNPUBLISH QUESTION */

app.patch("/api/admin/questions/:id", authenticate, adminOnly, asyncRoute(async (req, res) => {
  const { published } = req.body || {};
  if (typeof published !== "boolean") {
    return res.status(400).json({ error: "published must be true or false." });
  }
  const result = await pool.query(
    "UPDATE cbt_questions SET published=$1 WHERE id=$2 RETURNING *",
    [published, req.params.id]
  );
  if (!result.rowCount) return res.status(404).json({ error: "Question not found." });
  res.json({ question: result.rows[0] });
}));

/* ADMIN: DELETE QUESTION */

app.delete("/api/admin/questions/:id", authenticate, adminOnly, asyncRoute(async (req, res) => {
  const result = await pool.query(
    "DELETE FROM cbt_questions WHERE id=$1 RETURNING id",
    [req.params.id]
  );
  if (!result.rowCount) return res.status(404).json({ error: "Question not found." });
  res.json({ message: "Question deleted." });
}));

/* ADMIN: VIEW RESULTS */

app.get("/api/admin/results", authenticate, adminOnly, asyncRoute(async (req, res) => {
  const result = await pool.query(
    `SELECT a.id,a.exam_type,a.score,a.total,a.status,a.started_at,a.submitted_at,
            u.name AS student_name,u.email,s.name AS subject
     FROM cbt_attempts a
     JOIN cbt_users u ON u.id=a.user_id
     JOIN cbt_subjects s ON s.id=a.subject_id
     ORDER BY a.started_at DESC LIMIT 1000`
  );
  res.json({ results: result.rows });
}));

/* ADMIN: DELETE SUBJECT */

app.delete("/api/admin/subjects/:id", authenticate, adminOnly, asyncRoute(async (req, res) => {
  const active = await pool.query(
    "SELECT id FROM cbt_attempts WHERE subject_id=$1 LIMIT 1",
    [req.params.id]
  );
  if (active.rowCount) {
    return res.status(409).json({ error: "This subject has exam history and cannot be deleted." });
  }
  const result = await pool.query(
    "DELETE FROM cbt_subjects WHERE id=$1 RETURNING id",
    [req.params.id]
  );
  if (!result.rowCount) return res.status(404).json({ error: "Subject not found." });
  res.json({ message: "Subject deleted." });
}));

app.get("/api/admin/subjects", authenticate, adminOnly, asyncRoute(async (req, res) => {
  const result = await pool.query("SELECT * FROM cbt_subjects ORDER BY name");
  res.json({ subjects: result.rows });
}));

/* HOME */

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"), error => {
    if (error && !res.headersSent) {
      res.status(200).send(
        "Mandy CBT API is running. Create public/index.html for the student website."
      );
    }
  });
});

/* ERROR HANDLING */

app.use((err, req, res, next) => {
  console.error(err);
  if (res.headersSent) return next(err);
  res.status(500).json({ error: "An internal server error occurred." });
});

initDatabase()
  .then(() => {
    app.listen(PORT, "0.0.0.0", () => {
      console.log(`Mandy CBT server listening on port ${PORT}`);
    });
  })
  .catch(error => {
    console.error("Failed to initialize CBT database:", error);
    process.exit(1);
  });

process.on("SIGTERM", async () => {
  await pool.end();
  process.exit(0);
});
