const express = require("express");
const multer = require("multer");
const os = require("node:os");
const path = require("node:path");
const { randomUUID, createHmac, timingSafeEqual } = require("node:crypto");
const {
  STORAGE_ROOT,
  UPLOADS_DIRECTORY,
  createPerson,
  deletePerson,
  deleteStoredAudio,
  findPersonByCode,
  findPersonById,
  getPersistenceMode,
  listPeople,
  saveAudioFile,
  updatePerson
} = require("./persistence");

const ROOT_DIR = __dirname;
const PORT = Number(process.env.PORT || 3000);
const HOST = normalizeHost(process.env.HOST || "0.0.0.0");
const CONFIGURED_PUBLIC_BASE_URL = normalizeBaseUrl(
  process.env.PUBLIC_BASE_URL ||
    toHttpsUrl(process.env.VERCEL_PROJECT_PRODUCTION_URL) ||
    toHttpsUrl(process.env.VERCEL_BRANCH_URL) ||
    toHttpsUrl(process.env.VERCEL_URL) ||
    process.env.RENDER_EXTERNAL_URL
);
const DETECTED_LAN_BASE_URL = detectLanBaseUrl(PORT);
const DEMO_PUBLIC_CODE = "demo-card";
const AUDIO_EXTENSIONS = new Set([".mp3", ".wav", ".m4a", ".ogg", ".aac", ".webm"]);
const LOCALHOST_HOSTS = new Set(["localhost", "127.0.0.1", "::1"]);
const ADMIN_USERNAME = normalizeText(process.env.ADMIN_USERNAME || "admin") || "admin";
const ADMIN_PASSWORD = normalizeText(process.env.ADMIN_PASSWORD);
const ADMIN_COOKIE_SECRET = normalizeText(process.env.ADMIN_COOKIE_SECRET || randomUUID());
const ADMIN_SESSION_COOKIE = "nfc_admin_session";
const ADMIN_SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const IS_PRODUCTION = process.env.NODE_ENV === "production" || Boolean(process.env.RENDER) || Boolean(process.env.VERCEL);
const IS_VERCEL = Boolean(process.env.VERCEL);
const MAX_AUDIO_FILE_SIZE_MB = Number(process.env.MAX_AUDIO_FILE_SIZE_MB || (IS_VERCEL ? 4 : 15));

const upload = multer({
  storage: multer.memoryStorage(),
  fileFilter: (_req, file, callback) => {
    const extension = path.extname(file.originalname || "").toLowerCase();
    const isAudio = file.mimetype.startsWith("audio/") || AUDIO_EXTENSIONS.has(extension);

    if (isAudio) {
      callback(null, true);
      return;
    }

    callback(new Error("يرجى رفع ملف صوتي صالح مثل MP3 أو WAV."));
  },
  limits: {
    fileSize: MAX_AUDIO_FILE_SIZE_MB * 1024 * 1024
  }
});

const app = express();

app.set("trust proxy", 1);
app.use(express.urlencoded({ extended: true }));
app.use(applySecurityHeaders);
app.use(express.static(path.join(ROOT_DIR, "public")));
app.use("/uploads", express.static(UPLOADS_DIRECTORY, { index: false }));
app.use("/admin", requireAdminAccess);

app.get("/admin/login", (req, res) => {
  if (hasValidAdminSession(req)) {
    res.redirect(safeNextPath(req.query.next));
    return;
  }

  if (!ADMIN_PASSWORD) {
    if (!IS_PRODUCTION) {
      res.redirect("/admin");
      return;
    }

    res.status(503).send(renderAdminConfigPage());
    return;
  }

  res.send(
    renderLayout({
      title: "تسجيل دخول الإدارة",
      content: renderAdminLoginPage({
        nextPath: safeNextPath(req.query.next)
      })
    })
  );
});

app.post("/admin/login", (req, res) => {
  if (!ADMIN_PASSWORD) {
    if (!IS_PRODUCTION) {
      res.redirect("/admin");
      return;
    }

    res.status(503).send(renderAdminConfigPage());
    return;
  }

  const username = normalizeText(req.body.username);
  const password = normalizeText(req.body.password);
  const nextPath = safeNextPath(req.body.next);

  if (username === ADMIN_USERNAME && password === ADMIN_PASSWORD) {
    writeAdminSessionCookie(res, req);
    res.redirect(nextPath);
    return;
  }

  res.status(401).send(
    renderLayout({
      title: "تسجيل دخول الإدارة",
      content: renderAdminLoginPage({
        errorMessage: "بيانات الدخول غير صحيحة.",
        nextPath
      })
    })
  );
});

app.post("/admin/logout", (req, res) => {
  clearAdminSessionCookie(res, req);
  res.redirect("/admin/login");
});

app.get("/admin/logout", (req, res) => {
  clearAdminSessionCookie(res, req);
  res.redirect("/admin/login");
});

app.get("/", async (req, res) => {
  const people = await listPeople();

  res.send(
    renderLayout({
      title: "بطاقات NFC للمكفوفين",
      content: `
        <section class="hero">
          <div class="hero-panel">
            <span class="hero-kicker">NFC 13.56MHz + صفحة تعريف ذكية</span>
            <h1>حل عملي يساعد المكفوفين يوصلوا بياناتهم الأساسية بسرعة وأمان.</h1>
            <p class="lead">
              الكارت يحمل رابط قصير فقط، وعند لمسه بالموبايل تفتح صفحة فيها الاسم، العنوان، أرقام التواصل،
              وصف الحالة، وتسجيل صوتي يشرح التشخيص أو التعليمات المهمة.
            </p>
            <div class="hero-actions">
              <a class="button button-primary" href="/admin">فتح لوحة الإدارة</a>
              <a class="button button-secondary" href="/p/${DEMO_PUBLIC_CODE}">عرض بطاقة تجريبية</a>
            </div>
            <div class="stats">
              <div class="stat">
                <strong>${people.length}</strong>
                <span>بطاقات مسجلة حاليًا</span>
              </div>
              <div class="stat">
                <strong>1 رابط</strong>
                <span>يُكتب على الكارت بدل تخزين كل البيانات</span>
              </div>
              <div class="stat">
                <strong>صوت + نص</strong>
                <span>لشرح الحالة بشكل أوضح لمن يساعد</span>
              </div>
            </div>
          </div>

          <aside class="highlight-panel">
            <h2>كيف يشتغل المشروع؟</h2>
            <div class="stack">
              <div class="mini-card">
                <strong>1. تسجيل الحالة</strong>
                <span class="muted">تضيف بيانات الشخص وملف صوتي من لوحة الإدارة.</span>
              </div>
              <div class="mini-card">
                <strong>2. إنشاء رابط البطاقة</strong>
                <span class="muted">الموقع ينشئ رابطًا ثابتًا مثل /p/demo-card.</span>
              </div>
              <div class="mini-card">
                <strong>3. كتابة الرابط على NFC</strong>
                <span class="muted">يتم تخزين الرابط فقط على الكارت أو على QR كنسخة احتياطية.</span>
              </div>
            </div>
          </aside>
        </section>

        <section>
          <div class="section-head">
            <h2>البطاقات الموجودة</h2>
            <a class="button button-secondary" href="/admin/new">إضافة بطاقة جديدة</a>
          </div>
          ${
            people.length
              ? `<div class="grid">${people
                  .map((person) => renderHomeCard(person, req))
                  .join("")}</div>`
              : `<div class="empty-state">
                  <h3>لسه مفيش بطاقات مضافة</h3>
                  <p class="muted">ابدأ بإضافة أول بطاقة من لوحة الإدارة ثم اكتب الرابط على كارت الـ NFC.</p>
                </div>`
          }
        </section>
      `
    })
  );
});

app.get("/admin", async (req, res) => {
  const people = await listPeople();
  const success = normalizeText(req.query.success);

  res.send(
    renderLayout({
      title: "لوحة الإدارة",
      content: `
        <section class="section-head">
          <div>
            <span class="hero-kicker">لوحة الإدارة</span>
            <h1 class="page-title">إدارة بطاقات المكفوفين</h1>
            <p class="muted">أضف الحالات، حدّث البيانات، وارفع التسجيلات الصوتية التي ستظهر في الرابط العام.</p>
          </div>
          <div class="button-row">
            <a class="button button-primary" href="/admin/new">إضافة بطاقة</a>
            <a class="button button-secondary" href="/">العودة للرئيسية</a>
            ${renderAdminSessionActions()}
          </div>
        </section>

        ${renderLocalAdminWarning()}
        ${success ? renderAlert("success", success) : ""}

        <section class="table-card">
          ${
            people.length
              ? `
                <table class="responsive-table">
                  <thead>
                    <tr>
                      <th>الاسم</th>
                      <th>كود البطاقة</th>
                      <th>التواصل</th>
                      <th>الرابط العام</th>
                      <th>التحكم</th>
                    </tr>
                  </thead>
                  <tbody>
                    ${people.map((person) => renderAdminRow(person, req)).join("")}
                  </tbody>
                </table>
              `
              : `
                <div class="empty-state">
                  <h3>ابدأ بأول بطاقة</h3>
                  <p class="muted">أنشئ بطاقة جديدة، وبعدها انسخ الرابط واكتبه على كارت الـ NFC.</p>
                  <a class="button button-primary" href="/admin/new">إضافة أول بطاقة</a>
                </div>
              `
          }
        </section>
      `
    })
  );
});

app.get("/admin/new", (req, res) => {
  res.send(
    renderLayout({
      title: "إضافة بطاقة جديدة",
      content: renderPersonFormPage({
        title: "إضافة بطاقة جديدة",
        description: "أدخل البيانات الأساسية وارفع تسجيلًا صوتيًا يشرح التشخيص أو التعليمات المهمة.",
        action: "/admin/people",
        submitLabel: "حفظ البطاقة",
        person: emptyPerson(),
        previewUrl: buildPublicUrl(req, "generated-automatically")
      })
    })
  );
});

app.post("/admin/people", async (req, res) => {
  let uploadedAudioPath = "";

  try {
    await runUploader(req, res);

    const input = parsePersonInput(req.body);
    const validationError = validatePersonInput(input);

    if (validationError) {
      res.status(400).send(
        renderLayout({
          title: "إضافة بطاقة جديدة",
          content: renderPersonFormPage({
            title: "إضافة بطاقة جديدة",
            description: "صحح البيانات المطلوبة ثم أعد الحفظ.",
            action: "/admin/people",
            submitLabel: "حفظ البطاقة",
            person: input,
            errorMessage: validationError,
            previewUrl: buildPublicUrl(req, input.publicCode || "generated-automatically")
          })
        })
      );
      return;
    }

    const publicCode = input.publicCode || generatePublicCode();
    const timestamp = new Date().toISOString();
    uploadedAudioPath = req.file ? await saveAudioFile(req.file) : "";

    await createPerson({
      public_code: publicCode,
      full_name: input.fullName,
      address: input.address,
      phone: input.phone,
      emergency_phone: input.emergencyPhone || null,
      diagnosis_summary: input.diagnosisSummary || null,
      audio_path: uploadedAudioPath || null,
      notes: input.notes || null,
      created_at: timestamp,
      updated_at: timestamp
    });

    res.redirect(`/admin?success=${encodeURIComponent("تم إنشاء البطاقة بنجاح.")}`);
  } catch (error) {
    if (uploadedAudioPath) {
      await deleteStoredAudio(uploadedAudioPath);
    }

    const message = mapErrorToMessage(error);
    res.status(400).send(
      renderLayout({
        title: "إضافة بطاقة جديدة",
        content: renderPersonFormPage({
          title: "إضافة بطاقة جديدة",
          description: "تأكد من البيانات وحاول مرة أخرى.",
          action: "/admin/people",
          submitLabel: "حفظ البطاقة",
          person: parsePersonInput(req.body || {}),
          errorMessage: message,
          previewUrl: buildPublicUrl(req, normalizeCode(req.body?.publicCode) || "generated-automatically")
        })
      })
    );
  }
});

app.get("/admin/people/:id/edit", async (req, res) => {
  const person = await findPersonById(req.params.id);

  if (!person) {
    res.status(404).send(renderNotFoundPage("البطاقة المطلوبة غير موجودة."));
    return;
  }

  res.send(
    renderLayout({
      title: `تعديل بطاقة ${escapeHtml(person.full_name)}`,
      content: renderPersonFormPage({
        title: `تعديل بطاقة ${escapeHtml(person.full_name)}`,
        description: "يمكنك تعديل البيانات أو استبدال التسجيل الصوتي الحالي.",
        action: `/admin/people/${person.id}`,
        submitLabel: "حفظ التعديلات",
        person,
        previewUrl: buildPublicUrl(req, person.public_code)
      })
    })
  );
});

app.post("/admin/people/:id", async (req, res) => {
  const current = await findPersonById(req.params.id);
  let uploadedAudioPath = "";

  if (!current) {
    res.status(404).send(renderNotFoundPage("البطاقة المطلوبة غير موجودة."));
    return;
  }

  try {
    await runUploader(req, res);

    const input = parsePersonInput(req.body);
    const validationError = validatePersonInput(input);

    if (validationError) {
      res.status(400).send(
        renderLayout({
          title: `تعديل بطاقة ${escapeHtml(current.full_name)}`,
          content: renderPersonFormPage({
            title: `تعديل بطاقة ${escapeHtml(current.full_name)}`,
            description: "صحح البيانات المطلوبة ثم أعد الحفظ.",
            action: `/admin/people/${current.id}`,
            submitLabel: "حفظ التعديلات",
            person: { ...current, ...input },
            errorMessage: validationError,
            previewUrl: buildPublicUrl(req, input.publicCode || current.public_code)
          })
        })
      );
      return;
    }

    const shouldRemoveAudio = req.body.removeAudio === "on";
    let audioPath = current.audio_path;

    if (req.file) {
      uploadedAudioPath = await saveAudioFile(req.file);
      audioPath = uploadedAudioPath;
    } else if (shouldRemoveAudio) {
      audioPath = null;
    }

    const nextPublicCode = input.publicCode || current.public_code || generatePublicCode();

    await updatePerson(current.id, {
      public_code: nextPublicCode,
      full_name: input.fullName,
      address: input.address,
      phone: input.phone,
      emergency_phone: input.emergencyPhone || null,
      diagnosis_summary: input.diagnosisSummary || null,
      audio_path: audioPath,
      notes: input.notes || null,
      updated_at: new Date().toISOString()
    });

    if (req.file && current.audio_path) {
      await deleteStoredAudio(current.audio_path);
    }

    if (shouldRemoveAudio && current.audio_path && !req.file) {
      await deleteStoredAudio(current.audio_path);
    }

    res.redirect(`/admin?success=${encodeURIComponent("تم تحديث البطاقة بنجاح.")}`);
  } catch (error) {
    if (uploadedAudioPath) {
      await deleteStoredAudio(uploadedAudioPath);
    }

    const message = mapErrorToMessage(error);
    res.status(400).send(
      renderLayout({
        title: `تعديل بطاقة ${escapeHtml(current.full_name)}`,
        content: renderPersonFormPage({
          title: `تعديل بطاقة ${escapeHtml(current.full_name)}`,
          description: "تأكد من البيانات وحاول مرة أخرى.",
          action: `/admin/people/${current.id}`,
          submitLabel: "حفظ التعديلات",
          person: { ...current, ...parsePersonInput(req.body || {}) },
          errorMessage: message,
          previewUrl: buildPublicUrl(req, normalizeCode(req.body?.publicCode) || current.public_code)
        })
      })
    );
  }
});

app.post("/admin/people/:id/delete", async (req, res) => {
  const person = await findPersonById(req.params.id);

  if (!person) {
    res.status(404).send(renderNotFoundPage("البطاقة المطلوبة غير موجودة."));
    return;
  }

  await deletePerson(person.id);

  if (person.audio_path) {
    await deleteStoredAudio(person.audio_path);
  }

  res.redirect(`/admin?success=${encodeURIComponent("تم حذف البطاقة بنجاح.")}`);
});

app.get("/p/:publicCode", async (req, res) => {
  const person = await findPersonByCode(req.params.publicCode);

  if (!person) {
    res.status(404).send(renderNotFoundPage("الرابط غير صحيح أو البطاقة لم تعد متاحة."));
    return;
  }

  res.send(
    renderLayout({
      title: person.full_name,
      content: renderPublicProfile(person)
    })
  );
});

app.get("/health", (_req, res) => {
  res.json({ ok: true, persistence: getPersistenceMode() });
});

app.use((_req, res) => {
  res.status(404).send(renderNotFoundPage("الصفحة المطلوبة غير موجودة."));
});

app.use((error, _req, res, _next) => {
  console.error(error);
  res.status(500).send(renderNotFoundPage("حدث خطأ غير متوقع. جرّب مرة أخرى بعد قليل."));
});

if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`NFC care app is running on http://${HOST}:${PORT}`);
    console.log(`Admin dashboard: http://${HOST}:${PORT}/admin`);
    console.log(`Storage root: ${STORAGE_ROOT}`);
    console.log(`Persistence mode: ${getPersistenceMode()}`);
  });
}

module.exports = app;

function runUploader(req, res) {
  return new Promise((resolve, reject) => {
    upload.single("audio")(req, res, (error) => {
      if (error) {
        reject(error);
        return;
      }

      resolve();
    });
  });
}

function parsePersonInput(body = {}) {
  return {
    publicCode: normalizeCode(body.publicCode),
    fullName: normalizeText(body.fullName),
    address: normalizeText(body.address),
    phone: normalizeText(body.phone),
    emergencyPhone: normalizeText(body.emergencyPhone),
    diagnosisSummary: normalizeText(body.diagnosisSummary),
    notes: normalizeText(body.notes)
  };
}

function emptyPerson() {
  return {
    id: "",
    public_code: "",
    publicCode: "",
    full_name: "",
    fullName: "",
    address: "",
    phone: "",
    emergency_phone: "",
    emergencyPhone: "",
    diagnosis_summary: "",
    diagnosisSummary: "",
    audio_path: "",
    notes: ""
  };
}

function validatePersonInput(input) {
  if (!input.fullName) {
    return "الاسم مطلوب.";
  }

  if (!input.address) {
    return "العنوان مطلوب.";
  }

  if (!input.phone) {
    return "رقم الموبايل مطلوب.";
  }

  if (input.publicCode && input.publicCode.length < 4) {
    return "كود البطاقة يجب أن يكون 4 أحرف أو أرقام على الأقل.";
  }

  return "";
}

function normalizeText(value) {
  return String(value || "").trim();
}

function normalizeCode(value) {
  return String(value || "")
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9-_]/g, "-")
    .replace(/-+/g, "-")
    .replace(/^-|-$/g, "");
}

function generatePublicCode() {
  return `card-${randomUUID().replace(/-/g, "").slice(0, 8)}`;
}

function seedDemoRecord() {
  const existing = findPersonByCode(DEMO_PUBLIC_CODE);

  if (existing) {
    return;
  }

  const timestamp = new Date().toISOString();

  db.prepare(`
    INSERT INTO people (
      public_code,
      full_name,
      address,
      phone,
      emergency_phone,
      diagnosis_summary,
      audio_path,
      notes,
      created_at,
      updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    DEMO_PUBLIC_CODE,
    "حالة تجريبية",
    "القاهرة - عنوان تجريبي",
    "01000000000",
    "01011111111",
    "هذه بطاقة تجريبية لشرح الفكرة. يمكن استبدالها ببيانات حقيقية من لوحة الإدارة.",
    null,
    "يفضل إظهار البيانات العامة فقط، وترك التفاصيل الطبية الحساسة لمستخدم مصرح له.",
    timestamp,
    timestamp
  );
}

function cleanupUploadedFile(file) {
  if (!file?.path) {
    return;
  }

  try {
    fs.unlinkSync(file.path);
  } catch (error) {
    if (error.code !== "ENOENT") {
      console.error(error);
    }
  }
}

function deleteStoredAudioLocal(audioPath) {
  const filePath = path.join(UPLOADS_DIRECTORY, path.basename(audioPath));

  try {
    fs.unlinkSync(filePath);
  } catch (error) {
    if (error.code !== "ENOENT") {
      console.error(error);
    }
  }
}

function buildPublicUrl(req, publicCode) {
  const safeCode = publicCode || "generated-automatically";
  return `${resolvePublicBaseUrl(req)}/p/${encodeURIComponent(safeCode)}`;
}

function renderLayout({ title, content }) {
  return `<!DOCTYPE html>
  <html lang="ar" dir="rtl">
    <head>
      <meta charset="utf-8" />
      <meta name="viewport" content="width=device-width, initial-scale=1" />
      <title>${escapeHtml(title)} | بطاقات NFC</title>
      <link rel="preconnect" href="https://fonts.googleapis.com" />
      <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
      <link href="https://fonts.googleapis.com/css2?family=Cairo:wght@400;600;700;800&display=swap" rel="stylesheet" />
      <link rel="stylesheet" href="/styles.css" />
    </head>
    <body>
      <main class="shell">
        <header class="topbar">
          <a class="brand" href="/">
            <span class="brand-mark">◎</span>
            <span class="brand-copy">
              <strong>بطاقات NFC للمكفوفين</strong>
              <span>هوية ذكية + صفحة مساعدة فورية</span>
            </span>
          </a>
          <nav class="nav">
            <a href="/">الرئيسية</a>
            <a href="/admin">لوحة الإدارة</a>
          </nav>
        </header>
        ${content}
        <p class="footer-note">
          النسخة الحالية مخصصة كبداية عملية للمشروع. يفضل إضافة تسجيل دخول وصلاحيات قبل الاستخدام الفعلي.
        </p>
      </main>
    </body>
  </html>`;
}

function renderHomeCard(person, req) {
  return `
    <article class="card">
      <span class="chip">كود البطاقة: ${escapeHtml(person.public_code)}</span>
      <h3>${escapeHtml(person.full_name)}</h3>
      <p class="muted">${escapeHtml(person.diagnosis_summary || "لا يوجد وصف حالة مضاف حتى الآن.")}</p>
      <div class="meta">
        <div class="meta-item">
          <span>العنوان</span>
          <span>${escapeHtml(person.address)}</span>
        </div>
        <div class="meta-item">
          <span>الموبايل</span>
          <span>${escapeHtml(person.phone)}</span>
        </div>
      </div>
      <div class="button-row">
        <a class="button button-primary" href="/p/${encodeURIComponent(person.public_code)}">فتح الصفحة العامة</a>
        <a class="button button-secondary" href="/admin/people/${person.id}/edit">تعديل</a>
      </div>
      <p class="helper">الرابط: ${escapeHtml(buildPublicUrl(req, person.public_code))}</p>
    </article>
  `;
}

function renderAdminRow(person, req) {
  return `
    <tr>
      <td data-label="الاسم">
        <strong>${escapeHtml(person.full_name)}</strong><br />
        <span class="helper">${escapeHtml(person.address)}</span>
      </td>
      <td data-label="كود البطاقة">
        <span class="status-chip">${escapeHtml(person.public_code)}</span>
      </td>
      <td data-label="التواصل">
        <div>${escapeHtml(person.phone)}</div>
        <div class="helper">${escapeHtml(person.emergency_phone || "لا يوجد رقم طوارئ")}</div>
      </td>
      <td data-label="الرابط العام">
        <a href="/p/${encodeURIComponent(person.public_code)}">${escapeHtml(buildPublicUrl(req, person.public_code))}</a>
      </td>
      <td data-label="التحكم">
        <div class="table-actions">
          <a class="button button-secondary" href="/admin/people/${person.id}/edit">تعديل</a>
          <form method="post" action="/admin/people/${person.id}/delete" onsubmit="return confirm('هل تريد حذف البطاقة؟');">
            <button class="button-danger" type="submit">حذف</button>
          </form>
        </div>
      </td>
    </tr>
  `;
}

function renderPersonFormPage({ title, description, action, submitLabel, person, errorMessage = "", previewUrl }) {
  const fullName = person.full_name ?? person.fullName ?? "";
  const address = person.address ?? "";
  const phone = person.phone ?? "";
  const emergencyPhone = person.emergency_phone ?? person.emergencyPhone ?? "";
  const diagnosisSummary = person.diagnosis_summary ?? person.diagnosisSummary ?? "";
  const notes = person.notes ?? "";
  const publicCode = person.public_code ?? person.publicCode ?? "";
  const previewNeedsPublicHostWarning = isLocalOnlyBaseUrl(previewUrl);

  return `
    <section class="section-head">
      <div>
        <span class="hero-kicker">إدارة البيانات</span>
        <h1 class="page-title">${title}</h1>
        <p class="muted">${description}</p>
      </div>
      <a class="button button-secondary" href="/admin">العودة للوحة الإدارة</a>
    </section>

    ${renderLocalAdminWarning()}
    ${errorMessage ? renderAlert("error", errorMessage) : ""}

    <section class="form-card">
      <form method="post" action="${action}" enctype="multipart/form-data" class="stack">
        <div class="form-grid">
          <div class="field">
            <label for="fullName">الاسم</label>
            <input id="fullName" name="fullName" type="text" required value="${escapeAttribute(fullName)}" placeholder="الاسم الكامل" />
          </div>

          <div class="field">
            <label for="publicCode">كود البطاقة / الرابط</label>
            <input id="publicCode" name="publicCode" type="text" value="${escapeAttribute(publicCode)}" placeholder="مثال: card-001" />
            <span class="helper">اكتب حروفًا وأرقامًا إنجليزية فقط، أو اتركه فارغًا ليتم توليده تلقائيًا.</span>
          </div>

          <div class="field field-full">
            <label for="address">العنوان</label>
            <input id="address" name="address" type="text" required value="${escapeAttribute(address)}" placeholder="المدينة - الشارع - أي وصف يساعد للوصول" />
          </div>

          <div class="field">
            <label for="phone">رقم الموبايل</label>
            <input id="phone" name="phone" type="tel" required value="${escapeAttribute(phone)}" placeholder="01xxxxxxxxx" />
          </div>

          <div class="field">
            <label for="emergencyPhone">رقم الطوارئ</label>
            <input id="emergencyPhone" name="emergencyPhone" type="tel" value="${escapeAttribute(emergencyPhone)}" placeholder="رقم ولي الأمر أو الشخص المسؤول" />
          </div>

          <div class="field field-full">
            <label for="diagnosisSummary">وصف الحالة</label>
            <textarea id="diagnosisSummary" name="diagnosisSummary" placeholder="ملخص سريع للحالة أو التعليمات المهمة">${escapeHtml(diagnosisSummary)}</textarea>
          </div>

          <div class="field field-full">
            <label for="notes">ملاحظات إضافية</label>
            <textarea id="notes" name="notes" placeholder="مثل الحساسية، الأدوية، أو أي بيانات غير حساسة">${escapeHtml(notes)}</textarea>
          </div>

          <div class="field field-full">
            <label for="audio">التسجيل الصوتي</label>
            <input id="audio" name="audio" type="file" accept="audio/*" />
            <span class="helper">يفضل تسجيل قصير وواضح يشرح التشخيص أو طريقة التواصل المناسبة.</span>
            ${
              person.audio_path
                ? `
                  <div class="audio-box">
                    <strong>التسجيل الحالي</strong>
                    <audio controls src="${escapeAttribute(person.audio_path)}"></audio>
                    <label class="check" for="removeAudio">
                      <input id="removeAudio" name="removeAudio" type="checkbox" />
                      حذف التسجيل الحالي إذا لم يتم رفع ملف بديل
                    </label>
                  </div>
                `
                : ""
            }
          </div>
        </div>

        <div class="link-preview">
          <strong>الرابط المتوقع على الكارت:</strong>
          <div data-link-preview>${escapeHtml(previewUrl)}</div>
        </div>
        ${
          previewNeedsPublicHostWarning
            ? `<p class="helper">تنبيه: لا تكتب رابطًا فيه localhost على الكارت، لأن الموبايل سيحاول فتح نفسه. استخدم دومين حقيقي أو اضبط PUBLIC_BASE_URL أو افتح الموقع بعنوان الشبكة مثل 192.168.x.x.</p>`
            : `<p class="helper">هذا هو الرابط الذي تكتبه على الكارت كتسجيل URL من نوع NDEF.</p>`
        }
        <p class="helper">بعد الكتابة على الكارت، اختبره بالموبايل قبل قفل الكارت أو توزيعه.</p>

        <div class="button-row">
          <input type="submit" value="${escapeAttribute(submitLabel)}" />
          <a class="button button-secondary" href="/admin">إلغاء</a>
          ${renderAdminSessionActions()}
        </div>
      </form>
    </section>

    <script>
      (function () {
        const codeInput = document.getElementById("publicCode");
        const preview = document.querySelector("[data-link-preview]");

        if (!codeInput || !preview) {
          return;
        }

        const baseUrl = window.location.origin + "/p/";

        const sanitizeCode = (value) =>
          String(value || "")
            .trim()
            .toLowerCase()
            .replace(/[^a-z0-9-_]/g, "-")
            .replace(/-+/g, "-")
            .replace(/^-|-$/g, "");

        const refreshPreview = () => {
          const code = sanitizeCode(codeInput.value);
          preview.textContent = baseUrl + (code || "generated-automatically");
        };

        codeInput.addEventListener("input", refreshPreview);
        refreshPreview();
      })();
    </script>
  `;
}

function renderPublicProfile(person) {
  const phoneLink = normalizePhoneHref(person.phone);
  const emergencyLink = normalizePhoneHref(person.emergency_phone);

  return `
    <section class="profile-header">
      <div class="profile-summary">
        <span class="hero-kicker">بطاقة تعريف ذكية</span>
        <h1 class="page-title">${escapeHtml(person.full_name)}</h1>
        <p class="lead">${escapeHtml(person.diagnosis_summary || "لا يوجد وصف حالة مضاف حتى الآن.")}</p>
        <div class="quick-actions">
          <a class="button button-secondary" href="tel:${escapeAttribute(phoneLink)}">اتصال بالموبايل</a>
          ${
            emergencyLink
              ? `<a class="button button-secondary" href="tel:${escapeAttribute(emergencyLink)}">اتصال بالطوارئ</a>`
              : ""
          }
        </div>
      </div>

      <aside class="profile-card">
        <span class="chip">كود البطاقة: ${escapeHtml(person.public_code)}</span>
        <div class="meta">
          <div class="meta-item">
            <span>العنوان</span>
            <span>${escapeHtml(person.address)}</span>
          </div>
          <div class="meta-item">
            <span>رقم الموبايل</span>
            <span><a href="tel:${escapeAttribute(phoneLink)}">${escapeHtml(person.phone)}</a></span>
          </div>
          <div class="meta-item">
            <span>رقم الطوارئ</span>
            <span>${
              person.emergency_phone
                ? `<a href="tel:${escapeAttribute(emergencyLink)}">${escapeHtml(person.emergency_phone)}</a>`
                : "غير متوفر"
            }</span>
          </div>
        </div>
      </aside>
    </section>

    <section class="profile-grid">
      <article class="profile-card">
        <h3>وصف الحالة</h3>
        <p class="muted">${formatMultiline(person.diagnosis_summary || "لم يتم إضافة وصف للحالة بعد.")}</p>
      </article>

      <article class="profile-card">
        <h3>ملاحظات إضافية</h3>
        <p class="muted">${formatMultiline(person.notes || "لا توجد ملاحظات إضافية.")}</p>
      </article>

      <article class="profile-card">
        <h3>التسجيل الصوتي</h3>
        ${
          person.audio_path
            ? `
              <div class="audio-box">
                <div>يمكن تشغيل التسجيل لشرح الحالة أو التشخيص بشكل أوضح.</div>
                <audio controls src="${escapeAttribute(person.audio_path)}"></audio>
              </div>
            `
            : `<p class="muted">لا يوجد تسجيل صوتي مرفوع لهذه البطاقة حتى الآن.</p>`
        }
      </article>
    </section>
  `;
}

function renderAlert(type, message) {
  const className = type === "success" ? "alert-success" : "alert-error";
  return `<div class="alert ${className}">${escapeHtml(message)}</div>`;
}

function renderNotFoundPage(message) {
  return renderLayout({
    title: "غير موجود",
    content: `
      <section class="empty-state">
        <h1 class="page-title">غير موجود</h1>
        <p class="muted">${escapeHtml(message)}</p>
        <div class="button-row">
          <a class="button button-primary" href="/">العودة للرئيسية</a>
          <a class="button button-secondary" href="/admin">لوحة الإدارة</a>
        </div>
      </section>
    `
  });
}

function formatMultiline(text) {
  return escapeHtml(text).replace(/\n/g, "<br />");
}

function normalizePhoneHref(phone) {
  const cleaned = String(phone || "").replace(/[^\d+]/g, "");
  return cleaned || "";
}

function applySecurityHeaders(_req, res, next) {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("X-Frame-Options", "SAMEORIGIN");
  res.setHeader("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; media-src 'self' https: data: blob:; img-src 'self' data:; form-action 'self'; frame-ancestors 'self'; base-uri 'self'; object-src 'none'");
  next();
}

function requireAdminAccess(req, res, next) {
  if (req.path === "/login" || req.path === "/logout") {
    next();
    return;
  }

  if (!ADMIN_PASSWORD) {
    if (!IS_PRODUCTION) {
      next();
      return;
    }

    res.status(503).send(renderAdminConfigPage());
    return;
  }

  if (hasValidAdminSession(req)) {
    next();
    return;
  }

  if (req.method === "GET") {
    res.redirect(`/admin/login?next=${encodeURIComponent(req.originalUrl || "/admin")}`);
    return;
  }

  res.status(401).send(
    renderLayout({
      title: "تسجيل دخول الإدارة",
      content: renderAdminLoginPage({
        errorMessage: "يجب تسجيل الدخول أولاً.",
        nextPath: safeNextPath(req.originalUrl)
      })
    })
  );
}

function hasValidAdminSession(req) {
  const cookies = parseCookies(req);
  const sessionValue = cookies[ADMIN_SESSION_COOKIE];

  if (!sessionValue || !ADMIN_PASSWORD) {
    return false;
  }

  const [payload, signature] = sessionValue.split(".");

  if (!payload || !signature) {
    return false;
  }

  const expectedSignature = signValue(payload);

  if (!safeCompare(signature, expectedSignature)) {
    return false;
  }

  try {
    const parsed = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));

    if (parsed.username !== ADMIN_USERNAME) {
      return false;
    }

    if (!parsed.expiresAt || Number(parsed.expiresAt) < Date.now()) {
      return false;
    }

    return true;
  } catch {
    return false;
  }
}

function writeAdminSessionCookie(res, req) {
  const payload = Buffer.from(
    JSON.stringify({
      username: ADMIN_USERNAME,
      expiresAt: Date.now() + ADMIN_SESSION_TTL_MS
    }),
    "utf8"
  ).toString("base64url");

  const token = `${payload}.${signValue(payload)}`;
  setCookie(res, req, ADMIN_SESSION_COOKIE, token, {
    httpOnly: true,
    maxAgeMs: ADMIN_SESSION_TTL_MS,
    sameSite: "Lax",
    path: "/"
  });
}

function clearAdminSessionCookie(res, req) {
  setCookie(res, req, ADMIN_SESSION_COOKIE, "", {
    httpOnly: true,
    maxAgeMs: 0,
    sameSite: "Lax",
    path: "/"
  });
}

function setCookie(res, req, name, value, options = {}) {
  const cookieParts = [`${name}=${encodeURIComponent(value)}`];

  cookieParts.push(`Path=${options.path || "/"}`);
  cookieParts.push(`Max-Age=${Math.max(0, Math.floor((options.maxAgeMs || 0) / 1000))}`);

  if (options.httpOnly) {
    cookieParts.push("HttpOnly");
  }

  if (options.sameSite) {
    cookieParts.push(`SameSite=${options.sameSite}`);
  }

  if (isSecureRequest(req)) {
    cookieParts.push("Secure");
  }

  res.append("Set-Cookie", cookieParts.join("; "));
}

function isSecureRequest(req) {
  return req.secure || String(req.get("x-forwarded-proto") || "").includes("https");
}

function parseCookies(req) {
  const rawCookie = String(req.headers.cookie || "");
  const cookies = {};

  for (const item of rawCookie.split(";")) {
    const [key, ...rest] = item.trim().split("=");

    if (!key) {
      continue;
    }

    try {
      cookies[key] = decodeURIComponent(rest.join("="));
    } catch {
      cookies[key] = rest.join("=");
    }
  }

  return cookies;
}

function signValue(value) {
  return createHmac("sha256", ADMIN_COOKIE_SECRET).update(String(value)).digest("base64url");
}

function safeCompare(left, right) {
  const leftBuffer = Buffer.from(String(left));
  const rightBuffer = Buffer.from(String(right));

  if (leftBuffer.length !== rightBuffer.length) {
    return false;
  }

  return timingSafeEqual(leftBuffer, rightBuffer);
}

function safeNextPath(value) {
  const text = normalizeText(value);

  if (!text.startsWith("/") || text.startsWith("//")) {
    return "/admin";
  }

  return text;
}

function renderAdminLoginPage({ errorMessage = "", nextPath = "/admin" }) {
  return `
    <section class="section-head">
      <div>
        <span class="hero-kicker">حماية لوحة الإدارة</span>
        <h1 class="page-title">تسجيل دخول الإدارة</h1>
        <p class="muted">البيانات الطبية والمحتوى الإداري يجب أن يكونا محميين قبل النشر على الإنترنت.</p>
      </div>
      <a class="button button-secondary" href="/">العودة للرئيسية</a>
    </section>

    ${errorMessage ? renderAlert("error", errorMessage) : ""}

    <section class="form-card">
      <form method="post" action="/admin/login" class="stack">
        <input type="hidden" name="next" value="${escapeAttribute(nextPath)}" />
        <div class="form-grid">
          <div class="field">
            <label for="username">اسم المستخدم</label>
            <input id="username" name="username" type="text" required value="${escapeAttribute(ADMIN_USERNAME)}" />
          </div>
          <div class="field">
            <label for="password">كلمة المرور</label>
            <input id="password" name="password" type="password" required placeholder="اكتب كلمة المرور" />
          </div>
        </div>
        <div class="button-row">
          <button type="submit">دخول</button>
          <a class="button button-secondary" href="/">إلغاء</a>
        </div>
      </form>
    </section>
  `;
}

function renderAdminConfigPage() {
  return renderLayout({
    title: "إعداد الإدارة",
    content: `
      <section class="empty-state">
        <h1 class="page-title">لوحة الإدارة غير جاهزة</h1>
        <p class="muted">قبل تشغيل المشروع أونلاين، عيّن متغير البيئة <code>ADMIN_PASSWORD</code> لحماية صفحة الإدارة.</p>
        <div class="button-row">
          <a class="button button-primary" href="/">العودة للرئيسية</a>
        </div>
      </section>
    `
  });
}

function renderAdminSessionActions() {
  if (!ADMIN_PASSWORD) {
    return "";
  }

  return `<a class="button button-secondary" href="/admin/logout">تسجيل الخروج</a>`;
}

function renderLocalAdminWarning() {
  if (IS_PRODUCTION || ADMIN_PASSWORD) {
    return "";
  }

  return renderAlert("error", "لوحة الإدارة مفتوحة محليًا فقط لأن ADMIN_PASSWORD غير مضبوط. قبل النشر أونلاين يجب تعيين كلمة مرور.");
}

function resolveStorageRoot(storageRoot) {
  const normalized = normalizeText(storageRoot);

  if (!normalized) {
    return ROOT_DIR;
  }

  return path.isAbsolute(normalized) ? normalized : path.join(ROOT_DIR, normalized);
}

function normalizeHost(value) {
  return normalizeText(value) || "0.0.0.0";
}

function resolvePublicBaseUrl(req) {
  if (CONFIGURED_PUBLIC_BASE_URL) {
    return CONFIGURED_PUBLIC_BASE_URL;
  }

  const requestBaseUrl = `${req.protocol}://${req.get("host")}`;

  if (isLocalOnlyBaseUrl(requestBaseUrl) && DETECTED_LAN_BASE_URL) {
    return DETECTED_LAN_BASE_URL;
  }

  return requestBaseUrl;
}

function normalizeBaseUrl(value) {
  return String(value || "").trim().replace(/\/+$/, "");
}

function toHttpsUrl(value) {
  const normalized = normalizeText(value);

  if (!normalized) {
    return "";
  }

  if (normalized.startsWith("http://") || normalized.startsWith("https://")) {
    return normalized;
  }

  return `https://${normalized}`;
}

function isLocalOnlyBaseUrl(baseUrl) {
  try {
    const parsedUrl = new URL(baseUrl);
    return LOCALHOST_HOSTS.has(parsedUrl.hostname.toLowerCase());
  } catch {
    return false;
  }
}

function detectLanBaseUrl(port) {
  const networks = os.networkInterfaces();

  for (const addresses of Object.values(networks)) {
    for (const address of addresses || []) {
      if (address.family !== "IPv4" || address.internal || address.address.startsWith("169.254.")) {
        continue;
      }

      return `http://${address.address}:${port}`;
    }
  }

  return "";
}

function mapErrorToMessage(error) {
  if (!error) {
    return "حدث خطأ غير متوقع.";
  }

  const message = String(error.message || error);
  const lowerMessage = message.toLowerCase();

  if (
    message.includes("UNIQUE constraint failed") ||
    lowerMessage.includes("duplicate key value") ||
    lowerMessage.includes("people_public_code_key")
  ) {
    return "كود البطاقة مستخدم بالفعل. اختر كودًا مختلفًا.";
  }

  if (lowerMessage.includes("file too large") || lowerMessage.includes("request entity too large")) {
    return `حجم الملف الصوتي كبير. الحد الأقصى الحالي هو ${MAX_AUDIO_FILE_SIZE_MB}MB.`;
  }

  if (lowerMessage.includes("people table is not ready")) {
    return "ربط Supabase موجود لكن قاعدة البيانات لم تُجهز بعد. شغّل ملف schema أولًا ثم أعد المحاولة.";
  }

  return message;
}

function escapeHtml(value) {
  return String(value || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function escapeAttribute(value) {
  return escapeHtml(value);
}
