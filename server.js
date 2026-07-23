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
  getPersistenceStatus,
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
const LANGUAGE_COOKIE = "nfc_lang";
const LANGUAGE_COOKIE_TTL_MS = 365 * 24 * 60 * 60 * 1000;
const DEFAULT_LANGUAGE = "en";
const SUPPORTED_LANGUAGES = new Set(["en", "ar"]);
const FLASH_MESSAGE_KEYS = new Set(["card_created_success", "card_updated_success", "card_deleted_success"]);
const IS_PRODUCTION = process.env.NODE_ENV === "production" || Boolean(process.env.RENDER) || Boolean(process.env.VERCEL);
const IS_VERCEL = Boolean(process.env.VERCEL);
const MAX_AUDIO_FILE_SIZE_MB = Number(process.env.MAX_AUDIO_FILE_SIZE_MB || (IS_VERCEL ? 4 : 15));

const upload = multer({
  storage: multer.memoryStorage(),
  fileFilter: (req, file, callback) => {
    const extension = path.extname(file.originalname || "").toLowerCase();
    const isAudio = file.mimetype.startsWith("audio/") || AUDIO_EXTENSIONS.has(extension);

    if (isAudio) {
      callback(null, true);
      return;
    }

    callback(new Error(t(getRequestLanguage(req), "invalid_audio_file")));
  },
  limits: {
    fileSize: MAX_AUDIO_FILE_SIZE_MB * 1024 * 1024
  }
});

const app = express();

app.set("trust proxy", 1);
app.use(express.urlencoded({ extended: true }));
app.use(applyLanguagePreference);
app.use(applySecurityHeaders);
app.use(express.static(path.join(ROOT_DIR, "public")));
app.use("/uploads", express.static(UPLOADS_DIRECTORY, { index: false }));
app.use("/admin", requireAdminAccess);

app.get("/admin/login", (req, res) => {
  const lang = getRequestLanguage(req);

  if (hasValidAdminSession(req)) {
    res.redirect(safeNextPath(req.query.next));
    return;
  }

  if (!ADMIN_PASSWORD) {
    if (!IS_PRODUCTION) {
      res.redirect("/admin");
      return;
    }

    res.status(503).send(renderAdminConfigPage(req));
    return;
  }

  res.send(
    renderLayout({
      req,
      title: t(lang, "admin_login_title"),
      content: renderAdminLoginPage({
        req,
        nextPath: safeNextPath(req.query.next)
      })
    })
  );
});

app.post("/admin/login", (req, res) => {
  const lang = getRequestLanguage(req);

  if (!ADMIN_PASSWORD) {
    if (!IS_PRODUCTION) {
      res.redirect("/admin");
      return;
    }

    res.status(503).send(renderAdminConfigPage(req));
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
      req,
      title: t(lang, "admin_login_title"),
      content: renderAdminLoginPage({
        req,
        errorMessage: t(lang, "login_invalid"),
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
  const lang = getRequestLanguage(req);
  const { people, warningMessage } = await loadPeopleForLanding(req);

  res.send(
    renderLayout({
      req,
      title: t(lang, "home_title"),
      content: `
        <section class="hero">
          <div class="hero-panel">
            <span class="hero-kicker">${escapeHtml(t(lang, "hero_kicker"))}</span>
            <h1>${escapeHtml(t(lang, "hero_title"))}</h1>
            <p class="lead">${escapeHtml(t(lang, "hero_description"))}</p>
            <div class="hero-actions">
              <a class="button button-primary" href="/admin">${escapeHtml(t(lang, "open_dashboard"))}</a>
              <a class="button button-secondary" href="/p/${DEMO_PUBLIC_CODE}">${escapeHtml(t(lang, "view_demo_card"))}</a>
            </div>
            <div class="stats">
              <div class="stat">
                <strong>${people.length}</strong>
                <span>${escapeHtml(t(lang, "cards_registered_count"))}</span>
              </div>
              <div class="stat">
                <strong>${escapeHtml(t(lang, "one_link_value"))}</strong>
                <span>${escapeHtml(t(lang, "one_link_label"))}</span>
              </div>
              <div class="stat">
                <strong>${escapeHtml(t(lang, "voice_text_value"))}</strong>
                <span>${escapeHtml(t(lang, "voice_text_label"))}</span>
              </div>
            </div>
          </div>

          <aside class="highlight-panel">
            <h2>${escapeHtml(t(lang, "how_it_works_title"))}</h2>
            <div class="stack">
              <div class="mini-card">
                <strong>${escapeHtml(t(lang, "step_1_title"))}</strong>
                <span class="muted">${escapeHtml(t(lang, "step_1_copy"))}</span>
              </div>
              <div class="mini-card">
                <strong>${escapeHtml(t(lang, "step_2_title"))}</strong>
                <span class="muted">${escapeHtml(t(lang, "step_2_copy"))}</span>
              </div>
              <div class="mini-card">
                <strong>${escapeHtml(t(lang, "step_3_title"))}</strong>
                <span class="muted">${escapeHtml(t(lang, "step_3_copy"))}</span>
              </div>
            </div>
          </aside>
        </section>

        <section>
          <div class="section-head">
            <h2>${escapeHtml(t(lang, "existing_cards_title"))}</h2>
            <a class="button button-secondary" href="/admin/new">${escapeHtml(t(lang, "add_new_card"))}</a>
          </div>
          ${warningMessage ? renderAlert("warning", warningMessage) : ""}
          ${
            people.length
              ? `<div class="grid">${people
                  .map((person) => renderHomeCard(person, req))
                  .join("")}</div>`
              : `<div class="empty-state">
                  <h3>${escapeHtml(t(lang, "no_cards_title"))}</h3>
                  <p class="muted">${escapeHtml(t(lang, "no_cards_copy"))}</p>
                </div>`
          }
        </section>
      `
    })
  );
});

app.get("/admin", async (req, res) => {
  const lang = getRequestLanguage(req);
  const success = resolveFlashMessage(req, req.query.success);
  const { people, warningMessage } = await loadPeopleForDashboard(req);

  res.send(
    renderLayout({
      req,
      title: t(lang, "admin_title"),
      content: `
        <section class="section-head">
          <div>
            <span class="hero-kicker">${escapeHtml(t(lang, "admin_kicker"))}</span>
            <h1 class="page-title">${escapeHtml(t(lang, "admin_heading"))}</h1>
            <p class="muted">${escapeHtml(t(lang, "admin_description"))}</p>
          </div>
          <div class="button-row">
            <a class="button button-primary" href="/admin/new">${escapeHtml(t(lang, "add_card"))}</a>
            <a class="button button-secondary" href="/">${escapeHtml(t(lang, "back_home"))}</a>
            ${renderAdminSessionActions(req)}
          </div>
        </section>

        ${renderLocalAdminWarning(req)}
        ${warningMessage ? renderAlert("warning", warningMessage) : ""}
        ${success ? renderAlert("success", success) : ""}

        <section class="table-card">
          ${
            people.length
              ? `
                <table class="responsive-table">
                  <thead>
                    <tr>
                      <th>${escapeHtml(t(lang, "name_column"))}</th>
                      <th>${escapeHtml(t(lang, "card_code_column"))}</th>
                      <th>${escapeHtml(t(lang, "contact_column"))}</th>
                      <th>${escapeHtml(t(lang, "public_link_column"))}</th>
                      <th>${escapeHtml(t(lang, "actions_column"))}</th>
                    </tr>
                  </thead>
                  <tbody>
                    ${people.map((person) => renderAdminRow(person, req)).join("")}
                  </tbody>
                </table>
              `
              : `
                <div class="empty-state">
                  <h3>${escapeHtml(t(lang, "start_first_card_title"))}</h3>
                  <p class="muted">${escapeHtml(t(lang, "start_first_card_copy"))}</p>
                  <a class="button button-primary" href="/admin/new">${escapeHtml(t(lang, "add_first_card"))}</a>
                </div>
              `
          }
        </section>
      `
    })
  );
});

app.get("/admin/new", (req, res) => {
  const lang = getRequestLanguage(req);

  res.send(
    renderLayout({
      req,
      title: t(lang, "add_card_page_title"),
      content: renderPersonFormPage({
        req,
        title: t(lang, "add_card_page_title"),
        description: t(lang, "add_card_description"),
        action: "/admin/people",
        submitLabel: t(lang, "save_card"),
        person: emptyPerson(),
        previewUrl: buildPublicUrl(req, "generated-automatically")
      })
    })
  );
});

app.post("/admin/people", async (req, res) => {
  let uploadedAudioPath = "";
  const lang = getRequestLanguage(req);

  try {
    await runUploader(req, res);

    const input = parsePersonInput(req.body);
    const validationError = validatePersonInput(input, lang);

    if (validationError) {
      res.status(400).send(
        renderLayout({
          req,
          title: t(lang, "add_card_page_title"),
          content: renderPersonFormPage({
            req,
            title: t(lang, "add_card_page_title"),
            description: t(lang, "form_fix_required"),
            action: "/admin/people",
            submitLabel: t(lang, "save_card"),
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

    res.redirect(`/admin?success=${encodeURIComponent("card_created_success")}`);
  } catch (error) {
    if (uploadedAudioPath) {
      await deleteStoredAudio(uploadedAudioPath);
    }

    const message = mapErrorToMessage(error, lang);
    res.status(400).send(
      renderLayout({
        req,
        title: t(lang, "add_card_page_title"),
        content: renderPersonFormPage({
          req,
          title: t(lang, "add_card_page_title"),
          description: t(lang, "form_retry_check"),
          action: "/admin/people",
          submitLabel: t(lang, "save_card"),
          person: parsePersonInput(req.body || {}),
          errorMessage: message,
          previewUrl: buildPublicUrl(req, normalizeCode(req.body?.publicCode) || "generated-automatically")
        })
      })
    );
  }
});

app.get("/admin/people/:id/edit", async (req, res) => {
  const lang = getRequestLanguage(req);
  let person;

  try {
    person = await findPersonById(req.params.id);
  } catch (error) {
    console.error(error);
    res.status(503).send(renderNotFoundPage(req, t(lang, "persistence_service_unavailable")));
    return;
  }

  if (!person) {
    res.status(404).send(renderNotFoundPage(req, t(lang, "card_not_found")));
    return;
  }

  res.send(
    renderLayout({
      req,
      title: t(lang, "edit_card_page_title", { name: person.full_name }),
      content: renderPersonFormPage({
        req,
        title: t(lang, "edit_card_page_title", { name: person.full_name }),
        description: t(lang, "edit_card_description"),
        action: `/admin/people/${person.id}`,
        submitLabel: t(lang, "save_changes"),
        person,
        previewUrl: buildPublicUrl(req, person.public_code)
      })
    })
  );
});

app.post("/admin/people/:id", async (req, res) => {
  const current = await findPersonById(req.params.id);
  let uploadedAudioPath = "";
  const lang = getRequestLanguage(req);

  if (!current) {
    res.status(404).send(renderNotFoundPage(req, t(lang, "card_not_found")));
    return;
  }

  try {
    await runUploader(req, res);

    const input = parsePersonInput(req.body);
    const validationError = validatePersonInput(input, lang);

    if (validationError) {
      res.status(400).send(
        renderLayout({
          req,
          title: t(lang, "edit_card_page_title", { name: current.full_name }),
          content: renderPersonFormPage({
            req,
            title: t(lang, "edit_card_page_title", { name: current.full_name }),
            description: t(lang, "form_fix_required"),
            action: `/admin/people/${current.id}`,
            submitLabel: t(lang, "save_changes"),
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

    res.redirect(`/admin?success=${encodeURIComponent("card_updated_success")}`);
  } catch (error) {
    if (uploadedAudioPath) {
      await deleteStoredAudio(uploadedAudioPath);
    }

    const message = mapErrorToMessage(error, lang);
    res.status(400).send(
      renderLayout({
        req,
        title: t(lang, "edit_card_page_title", { name: current.full_name }),
        content: renderPersonFormPage({
          req,
          title: t(lang, "edit_card_page_title", { name: current.full_name }),
          description: t(lang, "form_retry_check"),
          action: `/admin/people/${current.id}`,
          submitLabel: t(lang, "save_changes"),
          person: { ...current, ...parsePersonInput(req.body || {}) },
          errorMessage: message,
          previewUrl: buildPublicUrl(req, normalizeCode(req.body?.publicCode) || current.public_code)
        })
      })
    );
  }
});

app.post("/admin/people/:id/delete", async (req, res) => {
  const lang = getRequestLanguage(req);
  let person;

  try {
    person = await findPersonById(req.params.id);
  } catch (error) {
    console.error(error);
    res.status(503).send(renderNotFoundPage(req, t(lang, "persistence_service_unavailable")));
    return;
  }

  if (!person) {
    res.status(404).send(renderNotFoundPage(req, t(lang, "card_not_found")));
    return;
  }

  await deletePerson(person.id);

  if (person.audio_path) {
    await deleteStoredAudio(person.audio_path);
  }

  res.redirect(`/admin?success=${encodeURIComponent("card_deleted_success")}`);
});

app.get("/p/:publicCode", async (req, res) => {
  const lang = getRequestLanguage(req);
  const normalizedCode = normalizeCode(req.params.publicCode) || String(req.params.publicCode || "");
  let person;
  let warningMessage = "";

  try {
    person = await findPersonByCode(req.params.publicCode);
    if (!getPersistenceStatus().ready) {
      warningMessage = t(lang, "persistence_public_warning");
    }
  } catch (error) {
    console.error(error);
    if (normalizedCode === DEMO_PUBLIC_CODE) {
      warningMessage = t(lang, "persistence_public_warning");
      person = await findPersonByCode(DEMO_PUBLIC_CODE);
    } else {
      res.status(503).send(renderNotFoundPage(req, t(lang, "persistence_service_unavailable")));
      return;
    }
  }

  if (!person) {
    res.status(404).send(renderNotFoundPage(req, t(lang, "invalid_public_link")));
    return;
  }

  res.send(
    renderLayout({
      req,
      title: person.full_name,
      content: `${warningMessage ? renderAlert("warning", warningMessage) : ""}${renderPublicProfile(person, req)}`
    })
  );
});

app.get("/health", (_req, res) => {
  const status = getPersistenceStatus();
  res.status(status.ready ? 200 : 503).json({
    ok: status.ready,
    persistence: getPersistenceMode(),
    stage: status.stage,
    error: status.error
  });
});

app.use((req, res) => {
  res.status(404).send(renderNotFoundPage(req, t(getRequestLanguage(req), "page_not_found")));
});

app.use((error, req, res, _next) => {
  console.error(error);
  res.status(500).send(renderNotFoundPage(req, t(getRequestLanguage(req), "unexpected_error_try_again")));
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

const TRANSLATIONS = {
  en: {
    site_short_name: "NFC Care Cards",
    site_name: "NFC Cards for Blind People",
    site_tagline: "Smart identity + instant help page",
    nav_home: "Home",
    nav_admin: "Dashboard",
    language_toggle_label: "Language switch",
    lang_english: "English",
    lang_arabic: "العربية",
    footer_note:
      "This version is a practical starting point for the project. Add stronger login and permissions before real-world use.",
    admin_login_title: "Admin Login",
    home_title: "NFC Cards for Blind People",
    hero_kicker: "NFC 13.56MHz + smart ID page",
    hero_title: "A practical way for blind people to share essential details quickly and safely.",
    hero_description:
      "The card stores only a short link. When tapped with a phone, it opens a page with the name, address, contact numbers, a case summary, and a voice recording for diagnosis or key instructions.",
    open_dashboard: "Open Dashboard",
    view_demo_card: "View Demo Card",
    persistence_warning:
      "The database connection is temporarily unavailable. The page is showing limited content until Supabase is reachable again.",
    persistence_public_warning:
      "The live database is currently unavailable. This public page may be temporarily limited.",
    persistence_write_warning:
      "The live database connection is currently unavailable, so dashboard changes may not save until Supabase is reconnected.",
    cards_registered_count: "cards registered right now",
    one_link_value: "1 link",
    one_link_label: "written to the card instead of storing all details",
    voice_text_value: "Voice + text",
    voice_text_label: "to explain the case more clearly to anyone helping",
    how_it_works_title: "How it works",
    step_1_title: "1. Register the person",
    step_1_copy: "Add the person's details and a voice file from the dashboard.",
    step_2_title: "2. Generate the card link",
    step_2_copy: "The website creates a stable public link like /p/demo-card.",
    step_3_title: "3. Write the link to NFC",
    step_3_copy: "Store only the link on the card, or on a QR code as a backup.",
    existing_cards_title: "Available cards",
    add_new_card: "Add New Card",
    no_cards_title: "No cards yet",
    no_cards_copy: "Add the first card from the dashboard, then write its link to the NFC card.",
    admin_title: "Dashboard",
    admin_kicker: "Admin Dashboard",
    admin_heading: "Manage NFC care cards",
    admin_description: "Add cases, update details, and upload voice recordings that appear on the public link.",
    add_card: "Add Card",
    back_home: "Back Home",
    name_column: "Name",
    card_code_column: "Card Code",
    contact_column: "Contact",
    public_link_column: "Public Link",
    actions_column: "Actions",
    start_first_card_title: "Start with the first card",
    start_first_card_copy: "Create a new card, then copy its link and write it to the NFC card.",
    add_first_card: "Add First Card",
    card_code_label: "Card code",
    address_label: "Address",
    mobile_label: "Mobile",
    emergency_label: "Emergency",
    open_public_page: "Open Public Page",
    edit_label: "Edit",
    link_label: "Link",
    no_case_summary: "No case summary has been added yet.",
    no_emergency_phone: "No emergency number",
    delete_confirm: "Do you want to delete this card?",
    delete_label: "Delete",
    data_management_kicker: "Data Management",
    back_to_admin: "Back to Dashboard",
    name_label: "Name",
    full_name_placeholder: "Full name",
    card_code_input_label: "Card code / link",
    card_code_placeholder: "Example: card-001",
    card_code_helper: "Use English letters and numbers only, or leave it blank to generate automatically.",
    address_placeholder: "City - street - any description that helps someone reach the person",
    phone_placeholder: "01xxxxxxxxx",
    emergency_phone_label: "Emergency phone",
    emergency_placeholder: "Parent or caregiver phone number",
    diagnosis_label: "Case summary",
    diagnosis_placeholder: "Short summary of the case or any important instructions",
    notes_label: "Additional notes",
    notes_placeholder: "Such as allergies, medications, or any non-sensitive details",
    audio_label: "Voice recording",
    audio_helper: "A short, clear recording is best for explaining the diagnosis or how to communicate.",
    current_recording: "Current recording",
    remove_current_recording: "Remove the current recording if no replacement file is uploaded",
    expected_link_label: "Expected link on the card",
    localhost_warning:
      "Warning: do not write a localhost link onto the card. The phone will try to open itself. Use a real domain, set PUBLIC_BASE_URL, or open the site through a network address like 192.168.x.x.",
    ndef_helper: "This is the URL you should write to the card as an NDEF URL record.",
    test_card_helper: "After writing the card, test it with a phone before locking or distributing it.",
    cancel: "Cancel",
    add_card_page_title: "Add New Card",
    add_card_description: "Enter the essential details and upload a voice recording for diagnosis or key instructions.",
    save_card: "Save Card",
    form_fix_required: "Fix the required fields, then save again.",
    form_retry_check: "Check the data and try again.",
    edit_card_page_title: "Edit {name}",
    edit_card_description: "You can update the details or replace the current voice recording.",
    save_changes: "Save Changes",
    smart_identity_kicker: "Smart identity card",
    call_mobile: "Call Mobile",
    call_emergency: "Call Emergency",
    unavailable: "Not available",
    case_description_heading: "Case Summary",
    no_case_description_yet: "No case summary has been added yet.",
    additional_notes_heading: "Additional Notes",
    no_additional_notes: "No additional notes.",
    audio_heading: "Voice Recording",
    audio_description: "You can play the recording for a clearer explanation of the case or diagnosis.",
    no_audio_yet: "No voice recording has been uploaded for this card yet.",
    autoplay_retry_note: "The page will try to play the voice recording automatically when it opens.",
    autoplay_blocked_note: "If audio does not start automatically, tap the button below or touch the page once.",
    play_recording: "Play Recording",
    not_found_title: "Not Found",
    not_found_heading: "Not Found",
    login_kicker: "Dashboard Protection",
    login_heading: "Admin Login",
    login_description: "Medical data and dashboard content should stay protected before publishing online.",
    username_label: "Username",
    password_label: "Password",
    password_placeholder: "Enter the password",
    login_button: "Log In",
    admin_config_title: "Admin Setup",
    admin_config_heading: "Dashboard is not ready",
    admin_config_prefix: "Before putting the project online, set the environment variable",
    admin_config_suffix: "to protect the admin page.",
    logout: "Log Out",
    local_admin_warning:
      "The dashboard is open locally only because ADMIN_PASSWORD is not set. Set a password before publishing online.",
    persistence_service_unavailable:
      "The live database service is currently unavailable. Please check the Supabase connection settings and try again.",
    login_invalid: "Invalid login credentials.",
    login_required: "You need to log in first.",
    card_created_success: "Card created successfully.",
    card_updated_success: "Card updated successfully.",
    card_deleted_success: "Card deleted successfully.",
    card_not_found: "The requested card could not be found.",
    invalid_public_link: "This link is invalid or the card is no longer available.",
    page_not_found: "The requested page could not be found.",
    unexpected_error_try_again: "An unexpected error occurred. Please try again shortly.",
    name_required: "Name is required.",
    address_required: "Address is required.",
    mobile_required: "Mobile number is required.",
    card_code_min: "The card code must be at least 4 English letters or numbers.",
    invalid_audio_file: "Please upload a valid audio file such as MP3 or WAV.",
    duplicate_card_code: "This card code is already in use. Choose a different code.",
    audio_file_too_large: "The audio file is too large. The current limit is {size}MB.",
    supabase_schema_missing: "Supabase is connected, but the database is not ready yet. Run the schema first, then try again.",
    unexpected_error_generic: "An unexpected error occurred."
  },
  ar: {
    site_short_name: "بطاقات NFC",
    site_name: "بطاقات NFC للمكفوفين",
    site_tagline: "هوية ذكية + صفحة مساعدة فورية",
    nav_home: "الرئيسية",
    nav_admin: "لوحة الإدارة",
    language_toggle_label: "تبديل اللغة",
    lang_english: "English",
    lang_arabic: "العربية",
    footer_note:
      "النسخة الحالية مخصصة كبداية عملية للمشروع. يفضل إضافة تسجيل دخول وصلاحيات قبل الاستخدام الفعلي.",
    admin_login_title: "تسجيل دخول الإدارة",
    home_title: "بطاقات NFC للمكفوفين",
    hero_kicker: "NFC 13.56MHz + صفحة تعريف ذكية",
    hero_title: "حل عملي يساعد المكفوفين يوصلوا بياناتهم الأساسية بسرعة وأمان.",
    hero_description:
      "الكارت يحمل رابط قصير فقط، وعند لمسه بالموبايل تفتح صفحة فيها الاسم، العنوان، أرقام التواصل، وصف الحالة، وتسجيل صوتي يشرح التشخيص أو التعليمات المهمة.",
    open_dashboard: "فتح لوحة الإدارة",
    view_demo_card: "عرض بطاقة تجريبية",
    persistence_warning:
      "اتصال قاعدة البيانات غير متاح مؤقتًا. الصفحة تعرض محتوى محدودًا إلى أن يعود اتصال Supabase للعمل.",
    persistence_public_warning:
      "قاعدة البيانات المباشرة غير متاحة حاليًا، لذلك قد تكون هذه الصفحة العامة محدودة مؤقتًا.",
    persistence_write_warning:
      "اتصال قاعدة البيانات المباشرة غير متاح حاليًا، لذلك قد لا يتم حفظ التعديلات من لوحة الإدارة حتى يعود Supabase للعمل.",
    cards_registered_count: "بطاقات مسجلة حاليًا",
    one_link_value: "1 رابط",
    one_link_label: "يُكتب على الكارت بدل تخزين كل البيانات",
    voice_text_value: "صوت + نص",
    voice_text_label: "لشرح الحالة بشكل أوضح لمن يساعد",
    how_it_works_title: "كيف يشتغل المشروع؟",
    step_1_title: "1. تسجيل الحالة",
    step_1_copy: "تضيف بيانات الشخص وملف صوتي من لوحة الإدارة.",
    step_2_title: "2. إنشاء رابط البطاقة",
    step_2_copy: "الموقع ينشئ رابطًا ثابتًا مثل /p/demo-card.",
    step_3_title: "3. كتابة الرابط على NFC",
    step_3_copy: "يتم تخزين الرابط فقط على الكارت أو على QR كنسخة احتياطية.",
    existing_cards_title: "البطاقات الموجودة",
    add_new_card: "إضافة بطاقة جديدة",
    no_cards_title: "لسه مفيش بطاقات مضافة",
    no_cards_copy: "ابدأ بإضافة أول بطاقة من لوحة الإدارة ثم اكتب الرابط على كارت الـ NFC.",
    admin_title: "لوحة الإدارة",
    admin_kicker: "لوحة الإدارة",
    admin_heading: "إدارة بطاقات المكفوفين",
    admin_description: "أضف الحالات، حدّث البيانات، وارفع التسجيلات الصوتية التي ستظهر في الرابط العام.",
    add_card: "إضافة بطاقة",
    back_home: "العودة للرئيسية",
    name_column: "الاسم",
    card_code_column: "كود البطاقة",
    contact_column: "التواصل",
    public_link_column: "الرابط العام",
    actions_column: "التحكم",
    start_first_card_title: "ابدأ بأول بطاقة",
    start_first_card_copy: "أنشئ بطاقة جديدة، وبعدها انسخ الرابط واكتبه على كارت الـ NFC.",
    add_first_card: "إضافة أول بطاقة",
    card_code_label: "كود البطاقة",
    address_label: "العنوان",
    mobile_label: "الموبايل",
    emergency_label: "الطوارئ",
    open_public_page: "فتح الصفحة العامة",
    edit_label: "تعديل",
    link_label: "الرابط",
    no_case_summary: "لا يوجد وصف حالة مضاف حتى الآن.",
    no_emergency_phone: "لا يوجد رقم طوارئ",
    delete_confirm: "هل تريد حذف البطاقة؟",
    delete_label: "حذف",
    data_management_kicker: "إدارة البيانات",
    back_to_admin: "العودة للوحة الإدارة",
    name_label: "الاسم",
    full_name_placeholder: "الاسم الكامل",
    card_code_input_label: "كود البطاقة / الرابط",
    card_code_placeholder: "مثال: card-001",
    card_code_helper: "اكتب حروفًا وأرقامًا إنجليزية فقط، أو اتركه فارغًا ليتم توليده تلقائيًا.",
    address_placeholder: "المدينة - الشارع - أي وصف يساعد للوصول",
    phone_placeholder: "01xxxxxxxxx",
    emergency_phone_label: "رقم الطوارئ",
    emergency_placeholder: "رقم ولي الأمر أو الشخص المسؤول",
    diagnosis_label: "وصف الحالة",
    diagnosis_placeholder: "ملخص سريع للحالة أو التعليمات المهمة",
    notes_label: "ملاحظات إضافية",
    notes_placeholder: "مثل الحساسية، الأدوية، أو أي بيانات غير حساسة",
    audio_label: "التسجيل الصوتي",
    audio_helper: "يفضل تسجيل قصير وواضح يشرح التشخيص أو طريقة التواصل المناسبة.",
    current_recording: "التسجيل الحالي",
    remove_current_recording: "حذف التسجيل الحالي إذا لم يتم رفع ملف بديل",
    expected_link_label: "الرابط المتوقع على الكارت",
    localhost_warning:
      "تنبيه: لا تكتب رابطًا فيه localhost على الكارت، لأن الموبايل سيحاول فتح نفسه. استخدم دومين حقيقي أو اضبط PUBLIC_BASE_URL أو افتح الموقع بعنوان الشبكة مثل 192.168.x.x.",
    ndef_helper: "هذا هو الرابط الذي تكتبه على الكارت كتسجيل URL من نوع NDEF.",
    test_card_helper: "بعد الكتابة على الكارت، اختبره بالموبايل قبل قفل الكارت أو توزيعه.",
    cancel: "إلغاء",
    add_card_page_title: "إضافة بطاقة جديدة",
    add_card_description: "أدخل البيانات الأساسية وارفع تسجيلًا صوتيًا يشرح التشخيص أو التعليمات المهمة.",
    save_card: "حفظ البطاقة",
    form_fix_required: "صحح البيانات المطلوبة ثم أعد الحفظ.",
    form_retry_check: "تأكد من البيانات وحاول مرة أخرى.",
    edit_card_page_title: "تعديل بطاقة {name}",
    edit_card_description: "يمكنك تعديل البيانات أو استبدال التسجيل الصوتي الحالي.",
    save_changes: "حفظ التعديلات",
    smart_identity_kicker: "بطاقة تعريف ذكية",
    call_mobile: "اتصال بالموبايل",
    call_emergency: "اتصال بالطوارئ",
    unavailable: "غير متوفر",
    case_description_heading: "وصف الحالة",
    no_case_description_yet: "لم يتم إضافة وصف للحالة بعد.",
    additional_notes_heading: "ملاحظات إضافية",
    no_additional_notes: "لا توجد ملاحظات إضافية.",
    audio_heading: "التسجيل الصوتي",
    audio_description: "يمكن تشغيل التسجيل لشرح الحالة أو التشخيص بشكل أوضح.",
    no_audio_yet: "لا يوجد تسجيل صوتي مرفوع لهذه البطاقة حتى الآن.",
    autoplay_retry_note: "سيحاول الموقع تشغيل التسجيل الصوتي تلقائيًا بمجرد فتح الصفحة.",
    autoplay_blocked_note: "إذا لم يبدأ الصوت تلقائيًا، اضغط الزر التالي أو المس الصفحة مرة واحدة.",
    play_recording: "تشغيل التسجيل",
    not_found_title: "غير موجود",
    not_found_heading: "غير موجود",
    login_kicker: "حماية لوحة الإدارة",
    login_heading: "تسجيل دخول الإدارة",
    login_description: "البيانات الطبية والمحتوى الإداري يجب أن يكونا محميين قبل النشر على الإنترنت.",
    username_label: "اسم المستخدم",
    password_label: "كلمة المرور",
    password_placeholder: "اكتب كلمة المرور",
    login_button: "دخول",
    admin_config_title: "إعداد الإدارة",
    admin_config_heading: "لوحة الإدارة غير جاهزة",
    admin_config_prefix: "قبل تشغيل المشروع أونلاين، عيّن متغير البيئة",
    admin_config_suffix: "لحماية صفحة الإدارة.",
    logout: "تسجيل الخروج",
    local_admin_warning:
      "لوحة الإدارة مفتوحة محليًا فقط لأن ADMIN_PASSWORD غير مضبوط. قبل النشر أونلاين يجب تعيين كلمة مرور.",
    persistence_service_unavailable:
      "خدمة قاعدة البيانات المباشرة غير متاحة حاليًا. راجع إعدادات اتصال Supabase ثم حاول مرة أخرى.",
    login_invalid: "بيانات الدخول غير صحيحة.",
    login_required: "يجب تسجيل الدخول أولاً.",
    card_created_success: "تم إنشاء البطاقة بنجاح.",
    card_updated_success: "تم تحديث البطاقة بنجاح.",
    card_deleted_success: "تم حذف البطاقة بنجاح.",
    card_not_found: "البطاقة المطلوبة غير موجودة.",
    invalid_public_link: "الرابط غير صحيح أو البطاقة لم تعد متاحة.",
    page_not_found: "الصفحة المطلوبة غير موجودة.",
    unexpected_error_try_again: "حدث خطأ غير متوقع. جرّب مرة أخرى بعد قليل.",
    name_required: "الاسم مطلوب.",
    address_required: "العنوان مطلوب.",
    mobile_required: "رقم الموبايل مطلوب.",
    card_code_min: "كود البطاقة يجب أن يكون 4 أحرف أو أرقام على الأقل.",
    invalid_audio_file: "يرجى رفع ملف صوتي صالح مثل MP3 أو WAV.",
    duplicate_card_code: "كود البطاقة مستخدم بالفعل. اختر كودًا مختلفًا.",
    audio_file_too_large: "حجم الملف الصوتي كبير. الحد الأقصى الحالي هو {size}MB.",
    supabase_schema_missing: "ربط Supabase موجود لكن قاعدة البيانات لم تُجهز بعد. شغّل ملف schema أولًا ثم أعد المحاولة.",
    unexpected_error_generic: "حدث خطأ غير متوقع."
  }
};

function validatePersonInput(input, lang = DEFAULT_LANGUAGE) {
  if (!input.fullName) {
    return t(lang, "name_required");
  }

  if (!input.address) {
    return t(lang, "address_required");
  }

  if (!input.phone) {
    return t(lang, "mobile_required");
  }

  if (input.publicCode && input.publicCode.length < 4) {
    return t(lang, "card_code_min");
  }

  return "";
}

function applyLanguagePreference(req, res, next) {
  const requestedLanguage = normalizeLanguage(req.query?.lang);
  const cookieLanguage = normalizeLanguage(parseCookies(req)[LANGUAGE_COOKIE]);
  const language = requestedLanguage || cookieLanguage || DEFAULT_LANGUAGE;

  req.language = language;

  if (requestedLanguage && requestedLanguage !== cookieLanguage) {
    setCookie(res, req, LANGUAGE_COOKIE, requestedLanguage, {
      maxAgeMs: LANGUAGE_COOKIE_TTL_MS,
      sameSite: "Lax",
      path: "/"
    });
  }

  next();
}

function normalizeLanguage(value) {
  const normalized = String(value || "").trim().toLowerCase();
  return SUPPORTED_LANGUAGES.has(normalized) ? normalized : "";
}

function getRequestLanguage(req) {
  return normalizeLanguage(req?.language) || normalizeLanguage(parseCookies(req)[LANGUAGE_COOKIE]) || DEFAULT_LANGUAGE;
}

function isRtlLanguage(language) {
  return language === "ar";
}

function t(language, key, variables = {}) {
  const normalizedLanguage = normalizeLanguage(language) || DEFAULT_LANGUAGE;
  const dictionary = TRANSLATIONS[normalizedLanguage] || TRANSLATIONS[DEFAULT_LANGUAGE];
  const fallback = TRANSLATIONS[DEFAULT_LANGUAGE][key] || key;
  const template = dictionary[key] || fallback;

  return String(template).replace(/\{(\w+)\}/g, (_match, variableName) => String(variables[variableName] ?? ""));
}

function resolveFlashMessage(req, value) {
  const key = normalizeText(value);

  if (!key) {
    return "";
  }

  if (FLASH_MESSAGE_KEYS.has(key)) {
    return t(getRequestLanguage(req), key);
  }

  return key;
}

function buildLanguageUrl(req, language) {
  const baseUrl = `${req.protocol}://${req.get("host")}`;
  const currentUrl = new URL(req.originalUrl || req.url || "/", baseUrl);
  currentUrl.searchParams.set("lang", language);
  return `${currentUrl.pathname}${currentUrl.search}`;
}

function renderLanguageToggle(req) {
  const currentLanguage = getRequestLanguage(req);

  return `
    <div class="lang-toggle" aria-label="${escapeAttribute(t(currentLanguage, "language_toggle_label"))}">
      <a href="${escapeAttribute(buildLanguageUrl(req, "en"))}"${currentLanguage === "en" ? ' aria-current="page"' : ""}>
        ${escapeHtml(t(currentLanguage, "lang_english"))}
      </a>
      <a href="${escapeAttribute(buildLanguageUrl(req, "ar"))}"${currentLanguage === "ar" ? ' aria-current="page"' : ""}>
        ${escapeHtml(t(currentLanguage, "lang_arabic"))}
      </a>
    </div>
  `;
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

function renderLayout({ req, title, content }) {
  const lang = getRequestLanguage(req);
  const direction = isRtlLanguage(lang) ? "rtl" : "ltr";

  return `<!DOCTYPE html>
  <html lang="${escapeAttribute(lang)}" dir="${escapeAttribute(direction)}">
    <head>
      <meta charset="utf-8" />
      <meta name="viewport" content="width=device-width, initial-scale=1" />
      <title>${escapeHtml(title)} | ${escapeHtml(t(lang, "site_short_name"))}</title>
      <link rel="preconnect" href="https://fonts.googleapis.com" />
      <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
      <link href="https://fonts.googleapis.com/css2?family=Cairo:wght@400;600;700;800&family=Manrope:wght@400;500;700;800&display=swap" rel="stylesheet" />
      <link rel="stylesheet" href="/styles.css" />
    </head>
    <body>
      <main class="shell">
        <header class="topbar">
          <a class="brand" href="/">
            <span class="brand-mark">◎</span>
            <span class="brand-copy">
              <strong>${escapeHtml(t(lang, "site_name"))}</strong>
              <span>${escapeHtml(t(lang, "site_tagline"))}</span>
            </span>
          </a>
          <div class="topbar-actions">
            <nav class="nav">
              <a href="/">${escapeHtml(t(lang, "nav_home"))}</a>
              <a href="/admin">${escapeHtml(t(lang, "nav_admin"))}</a>
            </nav>
            ${renderLanguageToggle(req)}
          </div>
        </header>
        ${content}
        <p class="footer-note">
          ${escapeHtml(t(lang, "footer_note"))}
        </p>
      </main>
    </body>
  </html>`;
}

function renderHomeCard(person, req) {
  const lang = getRequestLanguage(req);

  return `
    <article class="card">
      <span class="chip">${escapeHtml(t(lang, "card_code_label"))}: ${escapeHtml(person.public_code)}</span>
      <h3>${escapeHtml(person.full_name)}</h3>
      <p class="muted">${escapeHtml(person.diagnosis_summary || t(lang, "no_case_summary"))}</p>
      <div class="meta">
        <div class="meta-item">
          <span>${escapeHtml(t(lang, "address_label"))}</span>
          <span>${escapeHtml(person.address)}</span>
        </div>
        <div class="meta-item">
          <span>${escapeHtml(t(lang, "mobile_label"))}</span>
          <span>${escapeHtml(person.phone)}</span>
        </div>
      </div>
      <div class="button-row">
        <a class="button button-primary" href="/p/${encodeURIComponent(person.public_code)}">${escapeHtml(t(lang, "open_public_page"))}</a>
        <a class="button button-secondary" href="/admin/people/${person.id}/edit">${escapeHtml(t(lang, "edit_label"))}</a>
      </div>
      <p class="helper">${escapeHtml(t(lang, "link_label"))}: ${escapeHtml(buildPublicUrl(req, person.public_code))}</p>
    </article>
  `;
}

function renderAdminRow(person, req) {
  const lang = getRequestLanguage(req);

  return `
    <tr>
      <td data-label="${escapeAttribute(t(lang, "name_column"))}">
        <strong>${escapeHtml(person.full_name)}</strong><br />
        <span class="helper">${escapeHtml(person.address)}</span>
      </td>
      <td data-label="${escapeAttribute(t(lang, "card_code_column"))}">
        <span class="status-chip">${escapeHtml(person.public_code)}</span>
      </td>
      <td data-label="${escapeAttribute(t(lang, "contact_column"))}">
        <div>${escapeHtml(person.phone)}</div>
        <div class="helper">${escapeHtml(person.emergency_phone || t(lang, "no_emergency_phone"))}</div>
      </td>
      <td data-label="${escapeAttribute(t(lang, "public_link_column"))}">
        <a href="/p/${encodeURIComponent(person.public_code)}">${escapeHtml(buildPublicUrl(req, person.public_code))}</a>
      </td>
      <td data-label="${escapeAttribute(t(lang, "actions_column"))}">
        <div class="table-actions">
          <a class="button button-secondary" href="/admin/people/${person.id}/edit">${escapeHtml(t(lang, "edit_label"))}</a>
          <form method="post" action="/admin/people/${person.id}/delete" onsubmit="return confirm('${escapeAttribute(t(lang, "delete_confirm"))}');">
            <button class="button-danger" type="submit">${escapeHtml(t(lang, "delete_label"))}</button>
          </form>
        </div>
      </td>
    </tr>
  `;
}

function renderPersonFormPage({ req, title, description, action, submitLabel, person, errorMessage = "", previewUrl }) {
  const lang = getRequestLanguage(req);
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
        <span class="hero-kicker">${escapeHtml(t(lang, "data_management_kicker"))}</span>
        <h1 class="page-title">${escapeHtml(title)}</h1>
        <p class="muted">${escapeHtml(description)}</p>
      </div>
      <a class="button button-secondary" href="/admin">${escapeHtml(t(lang, "back_to_admin"))}</a>
    </section>

    ${renderLocalAdminWarning(req)}
    ${errorMessage ? renderAlert("error", errorMessage) : ""}

    <section class="form-card">
      <form method="post" action="${action}" enctype="multipart/form-data" class="stack">
        <div class="form-grid">
          <div class="field">
            <label for="fullName">${escapeHtml(t(lang, "name_label"))}</label>
            <input id="fullName" name="fullName" type="text" required value="${escapeAttribute(fullName)}" placeholder="${escapeAttribute(t(lang, "full_name_placeholder"))}" />
          </div>

          <div class="field">
            <label for="publicCode">${escapeHtml(t(lang, "card_code_input_label"))}</label>
            <input id="publicCode" name="publicCode" type="text" value="${escapeAttribute(publicCode)}" placeholder="${escapeAttribute(t(lang, "card_code_placeholder"))}" />
            <span class="helper">${escapeHtml(t(lang, "card_code_helper"))}</span>
          </div>

          <div class="field field-full">
            <label for="address">${escapeHtml(t(lang, "address_label"))}</label>
            <input id="address" name="address" type="text" required value="${escapeAttribute(address)}" placeholder="${escapeAttribute(t(lang, "address_placeholder"))}" />
          </div>

          <div class="field">
            <label for="phone">${escapeHtml(t(lang, "mobile_label"))}</label>
            <input id="phone" name="phone" type="tel" required value="${escapeAttribute(phone)}" placeholder="${escapeAttribute(t(lang, "phone_placeholder"))}" />
          </div>

          <div class="field">
            <label for="emergencyPhone">${escapeHtml(t(lang, "emergency_phone_label"))}</label>
            <input id="emergencyPhone" name="emergencyPhone" type="tel" value="${escapeAttribute(emergencyPhone)}" placeholder="${escapeAttribute(t(lang, "emergency_placeholder"))}" />
          </div>

          <div class="field field-full">
            <label for="diagnosisSummary">${escapeHtml(t(lang, "diagnosis_label"))}</label>
            <textarea id="diagnosisSummary" name="diagnosisSummary" placeholder="${escapeAttribute(t(lang, "diagnosis_placeholder"))}">${escapeHtml(diagnosisSummary)}</textarea>
          </div>

          <div class="field field-full">
            <label for="notes">${escapeHtml(t(lang, "notes_label"))}</label>
            <textarea id="notes" name="notes" placeholder="${escapeAttribute(t(lang, "notes_placeholder"))}">${escapeHtml(notes)}</textarea>
          </div>

          <div class="field field-full">
            <label for="audio">${escapeHtml(t(lang, "audio_label"))}</label>
            <input id="audio" name="audio" type="file" accept="audio/*" />
            <span class="helper">${escapeHtml(t(lang, "audio_helper"))}</span>
            ${
              person.audio_path
                ? `
                  <div class="audio-box">
                    <strong>${escapeHtml(t(lang, "current_recording"))}</strong>
                    <audio controls src="${escapeAttribute(person.audio_path)}"></audio>
                    <label class="check" for="removeAudio">
                      <input id="removeAudio" name="removeAudio" type="checkbox" />
                      ${escapeHtml(t(lang, "remove_current_recording"))}
                    </label>
                  </div>
                `
                : ""
            }
          </div>
        </div>

        <div class="link-preview">
          <strong>${escapeHtml(t(lang, "expected_link_label"))}:</strong>
          <div data-link-preview>${escapeHtml(previewUrl)}</div>
        </div>
        ${
          previewNeedsPublicHostWarning
            ? `<p class="helper">${escapeHtml(t(lang, "localhost_warning"))}</p>`
            : `<p class="helper">${escapeHtml(t(lang, "ndef_helper"))}</p>`
        }
        <p class="helper">${escapeHtml(t(lang, "test_card_helper"))}</p>

        <div class="button-row">
          <input type="submit" value="${escapeAttribute(submitLabel)}" />
          <a class="button button-secondary" href="/admin">${escapeHtml(t(lang, "cancel"))}</a>
          ${renderAdminSessionActions(req)}
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

function renderPublicProfile(person, req) {
  const lang = getRequestLanguage(req);
  const phoneLink = normalizePhoneHref(person.phone);
  const emergencyLink = normalizePhoneHref(person.emergency_phone);

  return `
    <section class="profile-header">
      <div class="profile-summary">
        <span class="hero-kicker">${escapeHtml(t(lang, "smart_identity_kicker"))}</span>
        <h1 class="page-title">${escapeHtml(person.full_name)}</h1>
        <p class="lead">${escapeHtml(person.diagnosis_summary || t(lang, "no_case_summary"))}</p>
        <div class="quick-actions">
          <a class="button button-secondary" href="tel:${escapeAttribute(phoneLink)}">${escapeHtml(t(lang, "call_mobile"))}</a>
          ${
            emergencyLink
              ? `<a class="button button-secondary" href="tel:${escapeAttribute(emergencyLink)}">${escapeHtml(t(lang, "call_emergency"))}</a>`
              : ""
          }
        </div>
      </div>

      <aside class="profile-card">
        <span class="chip">${escapeHtml(t(lang, "card_code_label"))}: ${escapeHtml(person.public_code)}</span>
        <div class="meta">
          <div class="meta-item">
            <span>${escapeHtml(t(lang, "address_label"))}</span>
            <span>${escapeHtml(person.address)}</span>
          </div>
          <div class="meta-item">
            <span>${escapeHtml(t(lang, "mobile_label"))}</span>
            <span><a href="tel:${escapeAttribute(phoneLink)}">${escapeHtml(person.phone)}</a></span>
          </div>
          <div class="meta-item">
            <span>${escapeHtml(t(lang, "emergency_phone_label"))}</span>
            <span>${
              person.emergency_phone
                ? `<a href="tel:${escapeAttribute(emergencyLink)}">${escapeHtml(person.emergency_phone)}</a>`
                : escapeHtml(t(lang, "unavailable"))
            }</span>
          </div>
        </div>
      </aside>
    </section>

    <section class="profile-grid">
      <article class="profile-card">
        <h3>${escapeHtml(t(lang, "case_description_heading"))}</h3>
        <p class="muted">${formatMultiline(person.diagnosis_summary || t(lang, "no_case_description_yet"))}</p>
      </article>

      <article class="profile-card">
        <h3>${escapeHtml(t(lang, "additional_notes_heading"))}</h3>
        <p class="muted">${formatMultiline(person.notes || t(lang, "no_additional_notes"))}</p>
      </article>

      <article class="profile-card">
        <h3>${escapeHtml(t(lang, "audio_heading"))}</h3>
        ${
          person.audio_path
            ? `
              <div class="audio-box">
                <div>${escapeHtml(t(lang, "audio_description"))}</div>
                <p class="helper">${escapeHtml(t(lang, "autoplay_retry_note"))}</p>
                <audio
                  controls
                  autoplay
                  playsinline
                  preload="auto"
                  data-public-audio
                  src="${escapeAttribute(person.audio_path)}"
                ></audio>
                <div class="audio-autoplay-note" data-audio-fallback hidden>
                  <p class="helper">${escapeHtml(t(lang, "autoplay_blocked_note"))}</p>
                  <button class="button button-secondary" type="button" data-audio-play>
                    ${escapeHtml(t(lang, "play_recording"))}
                  </button>
                </div>
              </div>
            `
            : `<p class="muted">${escapeHtml(t(lang, "no_audio_yet"))}</p>`
        }
      </article>
    </section>

    <script>
      (function () {
        const audio = document.querySelector("[data-public-audio]");
        const fallback = document.querySelector("[data-audio-fallback]");
        const playButton = document.querySelector("[data-audio-play]");

        if (!audio) {
          return;
        }

        let hasStarted = false;

        const showFallback = () => {
          if (fallback) {
            fallback.hidden = false;
          }
        };

        const hideFallback = () => {
          if (fallback) {
            fallback.hidden = true;
          }
        };

        const detachRetryListeners = () => {
          document.removeEventListener("touchstart", retryOnInteraction, retryOptions);
          document.removeEventListener("click", retryOnInteraction, retryOptions);
          document.removeEventListener("visibilitychange", retryOnVisibility);
        };

        const tryPlay = async () => {
          if (hasStarted) {
            return true;
          }

          try {
            audio.muted = false;
            await audio.play();
            hasStarted = true;
            hideFallback();
            detachRetryListeners();
            return true;
          } catch (_error) {
            showFallback();
            return false;
          }
        };

        const retryOptions = { passive: true };
        const retryOnInteraction = () => {
          tryPlay();
        };
        const retryOnVisibility = () => {
          if (document.visibilityState === "visible") {
            tryPlay();
          }
        };

        if (playButton) {
          playButton.addEventListener("click", tryPlay);
        }

        audio.addEventListener("play", () => {
          hasStarted = true;
          hideFallback();
          detachRetryListeners();
        });

        audio.addEventListener("loadeddata", tryPlay, { once: true });
        window.addEventListener("load", tryPlay, { once: true });
        document.addEventListener("touchstart", retryOnInteraction, retryOptions);
        document.addEventListener("click", retryOnInteraction, retryOptions);
        document.addEventListener("visibilitychange", retryOnVisibility);

        tryPlay();
      })();
    </script>
  `;
}

function renderAlert(type, message) {
  const className =
    type === "success" ? "alert-success" : type === "warning" ? "alert-warning" : "alert-error";
  return `<div class="alert ${className}">${escapeHtml(message)}</div>`;
}

async function loadPeopleForLanding(req) {
  const lang = getRequestLanguage(req);

  try {
    const people = await listPeople();
    const warningMessage = getPersistenceStatus().ready ? "" : t(lang, "persistence_warning");
    return { people, warningMessage };
  } catch (error) {
    console.error(error);
    return {
      people: [],
      warningMessage: t(lang, "persistence_warning")
    };
  }
}

async function loadPeopleForDashboard(req) {
  const lang = getRequestLanguage(req);

  try {
    const people = await listPeople();
    const warningMessage = getPersistenceStatus().ready ? "" : t(lang, "persistence_write_warning");
    return { people, warningMessage };
  } catch (error) {
    console.error(error);
    return {
      people: [],
      warningMessage: t(lang, "persistence_write_warning")
    };
  }
}

function renderNotFoundPage(req, message) {
  const lang = getRequestLanguage(req);

  return renderLayout({
    req,
    title: t(lang, "not_found_title"),
    content: `
      <section class="empty-state">
        <h1 class="page-title">${escapeHtml(t(lang, "not_found_heading"))}</h1>
        <p class="muted">${escapeHtml(message)}</p>
        <div class="button-row">
          <a class="button button-primary" href="/">${escapeHtml(t(lang, "back_home"))}</a>
          <a class="button button-secondary" href="/admin">${escapeHtml(t(lang, "nav_admin"))}</a>
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
  const lang = getRequestLanguage(req);

  if (req.path === "/login" || req.path === "/logout") {
    next();
    return;
  }

  if (!ADMIN_PASSWORD) {
    if (!IS_PRODUCTION) {
      next();
      return;
    }

    res.status(503).send(renderAdminConfigPage(req));
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
      req,
      title: t(lang, "admin_login_title"),
      content: renderAdminLoginPage({
        req,
        errorMessage: t(lang, "login_required"),
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

function renderAdminLoginPage({ req, errorMessage = "", nextPath = "/admin" }) {
  const lang = getRequestLanguage(req);

  return `
    <section class="section-head">
      <div>
        <span class="hero-kicker">${escapeHtml(t(lang, "login_kicker"))}</span>
        <h1 class="page-title">${escapeHtml(t(lang, "login_heading"))}</h1>
        <p class="muted">${escapeHtml(t(lang, "login_description"))}</p>
      </div>
      <a class="button button-secondary" href="/">${escapeHtml(t(lang, "back_home"))}</a>
    </section>

    ${errorMessage ? renderAlert("error", errorMessage) : ""}

    <section class="form-card">
      <form method="post" action="/admin/login" class="stack">
        <input type="hidden" name="next" value="${escapeAttribute(nextPath)}" />
        <div class="form-grid">
          <div class="field">
            <label for="username">${escapeHtml(t(lang, "username_label"))}</label>
            <input id="username" name="username" type="text" required value="${escapeAttribute(ADMIN_USERNAME)}" />
          </div>
          <div class="field">
            <label for="password">${escapeHtml(t(lang, "password_label"))}</label>
            <input id="password" name="password" type="password" required placeholder="${escapeAttribute(t(lang, "password_placeholder"))}" />
          </div>
        </div>
        <div class="button-row">
          <button type="submit">${escapeHtml(t(lang, "login_button"))}</button>
          <a class="button button-secondary" href="/">${escapeHtml(t(lang, "cancel"))}</a>
        </div>
      </form>
    </section>
  `;
}

function renderAdminConfigPage(req) {
  const lang = getRequestLanguage(req);

  return renderLayout({
    req,
    title: t(lang, "admin_config_title"),
    content: `
      <section class="empty-state">
        <h1 class="page-title">${escapeHtml(t(lang, "admin_config_heading"))}</h1>
        <p class="muted">${escapeHtml(t(lang, "admin_config_prefix"))} <code>ADMIN_PASSWORD</code> ${escapeHtml(t(lang, "admin_config_suffix"))}</p>
        <div class="button-row">
          <a class="button button-primary" href="/">${escapeHtml(t(lang, "back_home"))}</a>
        </div>
      </section>
    `
  });
}

function renderAdminSessionActions(req) {
  if (!ADMIN_PASSWORD) {
    return "";
  }

  return `<a class="button button-secondary" href="/admin/logout">${escapeHtml(t(getRequestLanguage(req), "logout"))}</a>`;
}

function renderLocalAdminWarning(req) {
  if (IS_PRODUCTION || ADMIN_PASSWORD) {
    return "";
  }

  return renderAlert("error", t(getRequestLanguage(req), "local_admin_warning"));
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

function mapErrorToMessage(error, lang = DEFAULT_LANGUAGE) {
  if (!error) {
    return t(lang, "unexpected_error_generic");
  }

  const message = String(error.message || error);
  const lowerMessage = message.toLowerCase();

  if (
    message.includes("UNIQUE constraint failed") ||
    lowerMessage.includes("duplicate key value") ||
    lowerMessage.includes("people_public_code_key")
  ) {
    return t(lang, "duplicate_card_code");
  }

  if (lowerMessage.includes("file too large") || lowerMessage.includes("request entity too large")) {
    return t(lang, "audio_file_too_large", { size: MAX_AUDIO_FILE_SIZE_MB });
  }

  if (lowerMessage.includes("people table is not ready")) {
    return t(lang, "supabase_schema_missing");
  }

  if (
    lowerMessage.includes("fetch failed") ||
    lowerMessage.includes("enotfound") ||
    lowerMessage.includes("getaddrinfo") ||
    lowerMessage.includes("network")
  ) {
    return t(lang, "persistence_service_unavailable");
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
