const fs = require("node:fs");
const path = require("node:path");
const { randomUUID } = require("node:crypto");
const { DatabaseSync } = require("node:sqlite");
const { createClient } = require("@supabase/supabase-js");

const ROOT_DIR = __dirname;
const STORAGE_ROOT = resolveStorageRoot(process.env.APP_STORAGE_ROOT);
const DATA_DIRECTORY = path.join(STORAGE_ROOT, "data");
const UPLOADS_DIRECTORY = path.join(STORAGE_ROOT, "uploads");
const DATABASE_PATH = path.join(DATA_DIRECTORY, "nfc-care.sqlite");
const DEMO_PUBLIC_CODE = "demo-card";
const SUPABASE_URL = normalizeText(process.env.SUPABASE_URL);
const SUPABASE_SERVICE_ROLE_KEY = normalizeText(process.env.SUPABASE_SERVICE_ROLE_KEY);
const SUPABASE_STORAGE_BUCKET = normalizeText(process.env.SUPABASE_STORAGE_BUCKET || "audio-recordings");
const AUDIO_EXTENSIONS = new Set([".mp3", ".wav", ".m4a", ".ogg", ".aac", ".webm"]);
const USE_SUPABASE = Boolean(SUPABASE_URL && SUPABASE_SERVICE_ROLE_KEY);

let db = null;
let supabase = null;
let initializationError = null;
let initializationStage = "starting";

const readyPromise = initialize().catch((error) => {
  initializationError = error;
  initializationStage = "error";

  if (!USE_SUPABASE) {
    throw error;
  }

  console.error("[persistence] Supabase initialization failed:", error.message || error);
});

module.exports = {
  DATA_DIRECTORY,
  DATABASE_PATH,
  STORAGE_ROOT,
  SUPABASE_STORAGE_BUCKET,
  UPLOADS_DIRECTORY,
  createPerson,
  deletePerson,
  deleteStoredAudio,
  findPersonByCode,
  findPersonById,
  getPersistenceMode,
  getPersistenceStatus,
  listPeople,
  saveAudioFile,
  updatePerson
};

async function initialize() {
  if (USE_SUPABASE) {
    initializationStage = "connecting";
    supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
      auth: {
        persistSession: false
      }
    });

    await verifySupabaseAccess();
    initializationStage = "seeding";

    try {
      await seedDemoRecordRemote();
    } catch (error) {
      console.error("[persistence] Unable to seed remote demo card:", error.message || error);
    }

    initializationError = null;
    initializationStage = "ready";
    return;
  }

  initializationStage = "local";
  ensureDirectory(DATA_DIRECTORY);
  ensureDirectory(UPLOADS_DIRECTORY);

  db = new DatabaseSync(DATABASE_PATH);
  db.exec(`
    PRAGMA journal_mode = WAL;

    CREATE TABLE IF NOT EXISTS people (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      public_code TEXT NOT NULL UNIQUE,
      full_name TEXT NOT NULL,
      address TEXT NOT NULL,
      phone TEXT NOT NULL,
      emergency_phone TEXT,
      diagnosis_summary TEXT,
      audio_path TEXT,
      notes TEXT,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );
  `);

  seedDemoRecordLocal();
  initializationError = null;
  initializationStage = "ready";
}

async function verifySupabaseAccess() {
  const { error } = await supabase.from("people").select("id", { head: true, count: "exact" }).limit(1);

  if (error) {
    throw new Error(`Supabase is configured but the people table is not ready yet: ${error.message}`);
  }
}

async function listPeople() {
  await readyPromise;

  if (USE_SUPABASE) {
    const { data, error } = await supabase.from("people").select("*").order("created_at", { ascending: false });

    if (error) {
      throw new Error(`Unable to load people: ${error.message}`);
    }

    initializationError = null;
    return data || [];
  }

  return db.prepare("SELECT * FROM people ORDER BY created_at DESC").all();
}

async function findPersonById(id) {
  await readyPromise;

  if (USE_SUPABASE) {
    const { data, error } = await supabase.from("people").select("*").eq("id", Number(id)).limit(1);

    if (error) {
      throw new Error(`Unable to load card: ${error.message}`);
    }

    initializationError = null;
    return data?.[0] || null;
  }

  return db.prepare("SELECT * FROM people WHERE id = ?").get(Number(id));
}

async function findPersonByCode(publicCode) {
  await readyPromise;
  const normalizedCode = String(publicCode);

  if (USE_SUPABASE) {
    const { data, error } = await supabase.from("people").select("*").eq("public_code", normalizedCode).limit(1);

    if (error) {
      if (normalizedCode === DEMO_PUBLIC_CODE) {
        return buildDemoRecord();
      }

      throw new Error(`Unable to load public profile: ${error.message}`);
    }

    initializationError = null;
    return data?.[0] || null;
  }

  return db.prepare("SELECT * FROM people WHERE public_code = ?").get(normalizedCode);
}

async function createPerson(person) {
  await readyPromise;

  if (USE_SUPABASE) {
    const { data, error } = await supabase.from("people").insert(person).select("*").single();

    if (error) {
      throw new Error(`Unable to create card: ${error.message}`);
    }

    initializationError = null;
    return data;
  }

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
    person.public_code,
    person.full_name,
    person.address,
    person.phone,
    person.emergency_phone,
    person.diagnosis_summary,
    person.audio_path,
    person.notes,
    person.created_at,
    person.updated_at
  );

  return findPersonByCode(person.public_code);
}

async function updatePerson(id, person) {
  await readyPromise;

  if (USE_SUPABASE) {
    const { data, error } = await supabase.from("people").update(person).eq("id", Number(id)).select("*").single();

    if (error) {
      throw new Error(`Unable to update card: ${error.message}`);
    }

    initializationError = null;
    return data;
  }

  db.prepare(`
    UPDATE people
    SET public_code = ?,
        full_name = ?,
        address = ?,
        phone = ?,
        emergency_phone = ?,
        diagnosis_summary = ?,
        audio_path = ?,
        notes = ?,
        updated_at = ?
    WHERE id = ?
  `).run(
    person.public_code,
    person.full_name,
    person.address,
    person.phone,
    person.emergency_phone,
    person.diagnosis_summary,
    person.audio_path,
    person.notes,
    person.updated_at,
    Number(id)
  );

  return findPersonById(id);
}

async function deletePerson(id) {
  await readyPromise;

  if (USE_SUPABASE) {
    const { error } = await supabase.from("people").delete().eq("id", Number(id));

    if (error) {
      throw new Error(`Unable to delete card: ${error.message}`);
    }

    initializationError = null;
    return;
  }

  db.prepare("DELETE FROM people WHERE id = ?").run(Number(id));
}

async function saveAudioFile(file) {
  await readyPromise;

  if (!file?.buffer?.length) {
    return null;
  }

  const extension = resolveAudioExtension(file);
  const fileName = `${Date.now()}-${randomUUID()}${extension}`;

  if (USE_SUPABASE) {
    const { error } = await supabase.storage.from(SUPABASE_STORAGE_BUCKET).upload(fileName, file.buffer, {
      cacheControl: "3600",
      contentType: file.mimetype || "application/octet-stream",
      upsert: false
    });

    if (error) {
      throw new Error(`Unable to upload audio: ${error.message}`);
    }

    initializationError = null;
    const { data } = supabase.storage.from(SUPABASE_STORAGE_BUCKET).getPublicUrl(fileName);
    return data.publicUrl;
  }

  ensureDirectory(UPLOADS_DIRECTORY);
  const filePath = path.join(UPLOADS_DIRECTORY, fileName);
  fs.writeFileSync(filePath, file.buffer);
  return `/uploads/${fileName}`;
}

async function deleteStoredAudio(audioPath) {
  await readyPromise;

  const objectName = extractStoredObjectName(audioPath);

  if (!objectName) {
    return;
  }

  if (USE_SUPABASE) {
    const { error } = await supabase.storage.from(SUPABASE_STORAGE_BUCKET).remove([objectName]);

    if (error && error.message && !error.message.toLowerCase().includes("not found")) {
      throw new Error(`Unable to delete audio: ${error.message}`);
    }

    initializationError = null;
    return;
  }

  deleteFileIfExists(path.join(UPLOADS_DIRECTORY, objectName));
}

function getPersistenceMode() {
  return USE_SUPABASE ? "supabase" : "local";
}

function getPersistenceStatus() {
  return {
    mode: getPersistenceMode(),
    ready: !initializationError,
    stage: initializationStage,
    error: initializationError ? String(initializationError.message || initializationError) : ""
  };
}

function buildDemoRecord() {
  const timestamp = new Date(2026, 6, 1).toISOString();

  return {
    id: "demo-fallback",
    public_code: DEMO_PUBLIC_CODE,
    full_name: "حالة تجريبية",
    address: "القاهرة - عنوان تجريبي",
    phone: "01000000000",
    emergency_phone: "01011111111",
    diagnosis_summary: "هذه بطاقة تجريبية لشرح الفكرة. يمكنك استبدالها ببيانات حقيقية من لوحة الإدارة.",
    audio_path: null,
    notes: "يفضل إظهار البيانات العامة فقط، وترك التفاصيل الطبية الحساسة لمستخدم مصرح له.",
    created_at: timestamp,
    updated_at: timestamp
  };
}

function seedDemoRecordLocal() {
  const existing = db.prepare("SELECT id FROM people WHERE public_code = ?").get(DEMO_PUBLIC_CODE);

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
    "هذه بطاقة تجريبية لشرح الفكرة. يمكنك استبدالها ببيانات حقيقية من لوحة الإدارة.",
    null,
    "يفضل إظهار البيانات العامة فقط، وترك التفاصيل الطبية الحساسة لمستخدم مصرح له.",
    timestamp,
    timestamp
  );
}

async function seedDemoRecordRemote() {
  const { data, error } = await supabase.from("people").select("id").eq("public_code", DEMO_PUBLIC_CODE).limit(1);

  if (error) {
    throw new Error(`Unable to check demo card: ${error.message}`);
  }

  if (data?.length) {
    return;
  }

  const timestamp = new Date().toISOString();
  const { error: insertError } = await supabase.from("people").insert({
    public_code: DEMO_PUBLIC_CODE,
    full_name: "حالة تجريبية",
    address: "القاهرة - عنوان تجريبي",
    phone: "01000000000",
    emergency_phone: "01011111111",
    diagnosis_summary: "هذه بطاقة تجريبية لشرح الفكرة. يمكنك استبدالها ببيانات حقيقية من لوحة الإدارة.",
    audio_path: null,
    notes: "يفضل إظهار البيانات العامة فقط، وترك التفاصيل الطبية الحساسة لمستخدم مصرح له.",
    created_at: timestamp,
    updated_at: timestamp
  });

  if (insertError && !String(insertError.message || "").toLowerCase().includes("duplicate")) {
    throw new Error(`Unable to create demo card: ${insertError.message}`);
  }
}

function resolveAudioExtension(file) {
  const extension = path.extname(file.originalname || "").toLowerCase();
  return AUDIO_EXTENSIONS.has(extension) ? extension : ".bin";
}

function extractStoredObjectName(audioPath) {
  if (!audioPath) {
    return "";
  }

  try {
    const parsedUrl = new URL(audioPath);
    return decodeURIComponent(path.posix.basename(parsedUrl.pathname));
  } catch {
    return path.posix.basename(String(audioPath).split("?")[0]);
  }
}

function deleteFileIfExists(filePath) {
  try {
    fs.unlinkSync(filePath);
  } catch (error) {
    if (error.code !== "ENOENT") {
      throw error;
    }
  }
}

function ensureDirectory(directoryPath) {
  fs.mkdirSync(directoryPath, { recursive: true });
}

function normalizeText(value) {
  return String(value || "").trim();
}

function resolveStorageRoot(storageRoot) {
  const normalized = normalizeText(storageRoot);

  if (!normalized) {
    return ROOT_DIR;
  }

  return path.isAbsolute(normalized) ? normalized : path.join(ROOT_DIR, normalized);
}
