const { createApp, ref, reactive, computed, onMounted } = Vue;

const SEVERITIES = [
  { key: "expired", label: "Expired" },
  { key: "critical", label: "Critical" },
  { key: "urgent", label: "Urgent" },
  { key: "warning", label: "Warning" },
  { key: "notice", label: "Notice" },
  { key: "healthy", label: "Healthy" },
];

const SEV_COLOR = {
  healthy: "#16a34a",
  notice: "#2563eb",
  warning: "#d97706",
  urgent: "#ea580c",
  critical: "#dc2626",
  expired: "#7f1d1d",
};

// Lifecycle states a certificate can be in, independent of how urgent its
// expiry is. Severity answers "how long have I got"; this answers "what is
// happening to it right now".
const LIFECYCLE = {
  deleted:   { label: "Deleted",   hint: "Soft-deleted — an administrator can restore it" },
  rotated:   { label: "Rotated",   hint: "Replaced by a newer certificate; no longer alerting" },
  in_review: { label: "In review", hint: "A rotation was submitted and is waiting for a second person" },
  active:    { label: "Active",    hint: "Being tracked and alerted on" },
};

// Audit action → the label and colour bucket shown in the log.
const AUDIT_TABS = [
  { key: "all",         label: "All" },
  { key: "certificate", label: "Certificates" },
  { key: "rotation",    label: "Rotations" },
  { key: "user",        label: "Users" },
  { key: "auth",        label: "Sign-in" },
  { key: "system",      label: "System" },
];

const ACTION_LABEL = {
  "certificate.create": "Created",
  "certificate.update": "Updated",
  "certificate.delete": "Deleted",
  "certificate.restore": "Restored",
  "certificate.transfer_owner": "Owner changed",
  "certificate.test_notification": "Test sent",
  "renewal.submit": "Renewal submitted",
  "renewal.approve": "Renewal approved",
  "renewal.reject": "Renewal rejected",
  "renewal.withdraw": "Renewal withdrawn",
  "user.create": "User created",
  "user.update": "User updated",
  "user.password_change": "Password changed",
  "auth.login": "Signed in",
  "auth.login_failed": "Sign-in failed",
  "auth.logout": "Signed out",
  "task.run_check": "Reminder scan",
};

// Colour bucket per action: green = something was created or approved,
// red = something was removed or refused, amber = needs attention.
const ACTION_TONE = {
  "certificate.create": "good",
  "certificate.restore": "good",
  "renewal.approve": "good",
  "certificate.delete": "bad",
  "renewal.reject": "bad",
  "auth.login_failed": "bad",
  "renewal.submit": "warn",
  "renewal.withdraw": "warn",
  "certificate.transfer_owner": "warn",
  "user.password_change": "warn",
};

// Thrown when the server says the session is gone, so callers can bounce the
// user back to the login screen instead of showing a generic error.
class Unauthorized extends Error {}

async function request(method, url, body) {
  const opts = { method, headers: {}, credentials: "same-origin" };
  if (body instanceof FormData) {
    // Let the browser set the multipart boundary.
    opts.body = body;
  } else if (body !== undefined) {
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(body);
  }
  const res = await fetch(url, opts);
  const text = await res.text();
  let data = null;
  if (text) {
    try { data = JSON.parse(text); } catch (e) { data = null; }
  }
  if (res.status === 401) {
    throw new Unauthorized((data && data.error) || "Sign in to continue");
  }
  if (!res.ok) {
    const msg = (data && (data.error || (data.errors && data.errors.join("; ")))) || ("Request failed (" + res.status + ")");
    throw new Error(msg);
  }
  return data;
}

function todayStr() {
  return new Date().toISOString().slice(0, 10);
}

function parseEmails(text) {
  return (text || "")
    .split(/[\s,;]+/)
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

function fmtDateTime(s) {
  if (!s) return "";
  const d = new Date(s);
  return d.toLocaleString(undefined, {
    year: "numeric", month: "short", day: "2-digit",
    hour: "2-digit", minute: "2-digit",
  });
}

function fmtBytes(n) {
  if (!n) return "0 B";
  if (n < 1024) return n + " B";
  if (n < 1024 * 1024) return (n / 1024).toFixed(0) + " KB";
  return (n / 1024 / 1024).toFixed(1) + " MB";
}

createApp({
  setup() {
    // ---------- session ----------
    const booting = ref(true);
    const authEnabled = ref(true);
    const me = ref(null);
    const loginForm = reactive({ username: "", password: "" });
    const loginError = ref("");
    const loggingIn = ref(false);

    const isAdmin = computed(() => !!me.value && me.value.role === "admin");
    const signedIn = computed(() => !!me.value);

    // ---------- data ----------
    const certs = ref([]);
    const renewals = ref([]);
    const users = ref([]);
    const auditEntries = ref([]);
    const config = ref(null);
    const loading = ref(true);

    const view = ref("certs"); // certs | reviews | audit | users
    const auditCategory = ref("all");
    const auditSearch = ref("");
    const filterEnv = ref("all");
    const filterSev = ref(null);
    const showRotated = ref(false);
    const showDeleted = ref(false);

    const toasts = ref([]);

    // Which dropdown is open, by id ("user" or "cert-<id>"). One at a time, and
    // a document-level click closes it — cheaper than a listener per menu.
    const menu = ref(null);
    function toggleMenu(id) { menu.value = menu.value === id ? null : id; }
    function closeMenu() { menu.value = null; }

    // ---------- modals ----------
    const showModal = ref(false);
    const editing = ref(null);
    const saving = ref(false);
    const formError = ref("");
    const form = reactive(blankForm());

    const renewModal = ref(null); // the cert being renewed
    const renewForm = reactive({ new_issued_date: todayStr(), new_expiry_date: "", note: "" });
    const renewFile = ref(null);
    const renewPreview = ref("");
    const renewError = ref("");
    const renewSaving = ref(false);

    const reviewModal = ref(null); // the renewal being reviewed
    const reviewNote = ref("");
    // Which review action is in flight: "" | "approve" | "reject". Bound to
    // :disabled as !!reviewBusy — an empty string is truthy for HTML boolean
    // attributes, so binding the bare string would disable the buttons forever.
    const reviewBusy = ref("");

    const ownerModal = ref(null);
    const ownerTarget = ref(null);

    const historyModal = ref(null);
    const historyEntries = ref([]);

    const passwordModal = ref(false);
    const passwordForm = reactive({ current_password: "", new_password: "", confirm: "" });
    const passwordError = ref("");

    const userModal = ref(null); // { mode: 'create'|'edit', ... }
    const userForm = reactive({ username: "", display_name: "", email: "", password: "", role: "user", disabled: false });
    const userError = ref("");

    function blankForm() {
      return {
        name: "",
        environment: "prd",
        issued_date: todayStr(),
        expiry_date: "",
        reminder_days: [30, 45, 60, 75, 90],
        teams_webhook_url: "",
        emails_text: "",
        notes: "",
      };
    }

    // ---------- derived ----------
    const environments = computed(() =>
      config.value ? config.value.environments : ["dev", "stg", "prd"]
    );
    const reminderOptions = computed(() =>
      config.value ? config.value.reminder_options : [30, 45, 60, 75, 90]
    );
    const emailEnabled = computed(() => (config.value ? config.value.email_enabled : false));
    const escalation = computed(() => (config.value && config.value.reminder_escalation) || []);
    const maxUploadMB = computed(() =>
      config.value ? Math.round(config.value.max_upload_bytes / 1024 / 1024) : 5
    );

    const activeCerts = computed(() => certs.value.filter((c) => !c.rotated_at && !c.deleted_at));
    const rotatedCerts = computed(() => certs.value.filter((c) => !!c.rotated_at));
    const deletedCerts = computed(() => certs.value.filter((c) => !!c.deleted_at));

    const envCerts = computed(() =>
      filterEnv.value === "all"
        ? activeCerts.value
        : activeCerts.value.filter((c) => c.environment === filterEnv.value)
    );
    const counts = computed(() => {
      const m = {};
      for (const c of envCerts.value) m[c.severity] = (m[c.severity] || 0) + 1;
      return m;
    });
    const filteredCerts = computed(() =>
      filterSev.value ? envCerts.value.filter((c) => c.severity === filterSev.value) : envCerts.value
    );

    const pendingRenewals = computed(() => renewals.value.filter((r) => r.status === "pending_review"));
    // Requests this user is allowed to action — the four-eyes rule means your
    // own submissions never show up here.
    const myReviewQueue = computed(() => pendingRenewals.value.filter((r) => r.can_review));
    const awaitingOthers = computed(() => pendingRenewals.value.filter((r) => !r.can_review));

    const activeUsers = computed(() => users.value.filter((u) => !u.disabled));

    function sevColor(sev) { return SEV_COLOR[sev] || "#6b7280"; }
    function sevLabel(sev) {
      const s = SEVERITIES.find((x) => x.key === sev);
      return s ? s.label : sev;
    }
    function cadenceText(c) {
      if (!c.reminder_interval_days) return "milestones only";
      if (c.reminder_interval_days === 1) return "repeats daily";
      return "repeats every " + c.reminder_interval_days + " days";
    }
    // Initials for the owner chip — two letters at most, from a username like
    // "alice" or "a.chen".
    function initials(name) {
      if (!name) return "?";
      const parts = String(name).split(/[.\-_\s]+/).filter(Boolean);
      return (parts.length > 1 ? parts[0][0] + parts[1][0] : name.slice(0, 2)).toUpperCase();
    }

    // The pending renewal record behind a certificate's "in review" state, so
    // the card can name who submitted it and offer the right next action.
    function pendingRenewalFor(c) {
      if (!c.pending_renewal_id) return null;
      return renewals.value.find((r) => r.id === c.pending_renewal_id) || null;
    }

    function lifecycleKey(c) {
      if (c.deleted_at) return "deleted";
      if (c.rotated_at) return "rotated";
      if (c.pending_renewal_id) return "in_review";
      return "active";
    }
    function lifecycle(c) { return LIFECYCLE[lifecycleKey(c)]; }

    function actionLabel(a) { return ACTION_LABEL[a] || a; }
    function actionTone(a) { return ACTION_TONE[a] || "neutral"; }

    function statusLabel(s) {
      return {
        pending_review: "Awaiting review",
        approved: "Approved",
        rejected: "Rejected",
        withdrawn: "Withdrawn",
      }[s] || s;
    }

    function toast(message, type) {
      const id = Date.now() + Math.random();
      toasts.value.push({ id, message, type: type || "" });
      setTimeout(() => {
        toasts.value = toasts.value.filter((t) => t.id !== id);
      }, 5000);
    }

    // Every network call funnels through here so an expired session always
    // lands on the login screen rather than a wall of red toasts.
    async function guard(fn, onError) {
      try {
        return await fn();
      } catch (e) {
        if (e instanceof Unauthorized) {
          me.value = null;
          loginError.value = e.message;
          return undefined;
        }
        if (onError) onError(e);
        else toast(e.message, "err");
        return undefined;
      }
    }

    // ---------- session actions ----------
    async function loadSession() {
      try {
        const s = await request("GET", "/api/auth/session");
        authEnabled.value = s.auth_enabled;
        me.value = s.authenticated ? s.user : null;
      } catch (e) {
        me.value = null;
      }
    }

    async function doLogin() {
      loginError.value = "";
      if (!loginForm.username || !loginForm.password) {
        loginError.value = "Enter your username and password.";
        return;
      }
      loggingIn.value = true;
      try {
        const r = await request("POST", "/api/auth/login", {
          username: loginForm.username,
          password: loginForm.password,
        });
        me.value = r.user;
        loginForm.password = "";
        await loadAll();
      } catch (e) {
        loginError.value = e.message;
      } finally {
        loggingIn.value = false;
      }
    }

    async function doLogout() {
      try { await request("POST", "/api/auth/logout"); } catch (e) { /* falling through logs out locally anyway */ }
      me.value = null;
      certs.value = [];
      renewals.value = [];
      users.value = [];
      auditEntries.value = [];
      view.value = "certs";
    }

    async function submitPassword() {
      passwordError.value = "";
      if (passwordForm.new_password !== passwordForm.confirm) {
        passwordError.value = "The two new passwords do not match.";
        return;
      }
      if ((passwordForm.new_password || "").length < 10) {
        passwordError.value = "New password must be at least 10 characters.";
        return;
      }
      try {
        await request("POST", "/api/auth/password", {
          current_password: passwordForm.current_password,
          new_password: passwordForm.new_password,
        });
        passwordModal.value = false;
        passwordForm.current_password = passwordForm.new_password = passwordForm.confirm = "";
        toast("Password changed. Other sessions were signed out.", "ok");
      } catch (e) {
        passwordError.value = e.message;
      }
    }

    // ---------- loading ----------
    async function loadConfig() {
      await guard(async () => {
        config.value = await request("GET", "/api/config");
        if (!editing.value && !showModal.value) {
          const d = blankForm();
          d.reminder_days = config.value.reminder_default_days.slice();
          Object.assign(form, d);
        }
      });
    }

    async function loadCerts() {
      loading.value = true;
      const url = showDeleted.value && isAdmin.value
        ? "/api/certificates?include_deleted=1"
        : "/api/certificates";
      await guard(async () => { certs.value = await request("GET", url); });
      loading.value = false;
    }

    async function loadRenewals() {
      await guard(async () => { renewals.value = await request("GET", "/api/renewals"); });
    }

    async function loadUsers() {
      await guard(async () => { users.value = await request("GET", "/api/users"); });
    }

    async function loadAudit() {
      if (!isAdmin.value) return;
      // The category is applied server-side so the 200-row limit counts rows of
      // that category, rather than whatever survives from the 200 most recent
      // entries overall.
      const q = "/api/audit?limit=200" +
        (auditCategory.value === "all" ? "" : "&category=" + encodeURIComponent(auditCategory.value));
      await guard(async () => { auditEntries.value = await request("GET", q); });
    }

    async function setAuditCategory(key) {
      auditCategory.value = key;
      await loadAudit();
    }

    // Free-text narrowing on top of the category, applied locally.
    const visibleAudit = computed(() => {
      const q = auditSearch.value.trim().toLowerCase();
      if (!q) return auditEntries.value;
      return auditEntries.value.filter((e) =>
        (e.actor || "").toLowerCase().includes(q) ||
        actionLabel(e.action).toLowerCase().includes(q) ||
        describeEntry(e).toLowerCase().includes(q)
      );
    });

    async function loadAll() {
      await loadConfig();
      await Promise.all([loadCerts(), loadRenewals(), loadUsers()]);
      if (isAdmin.value) await loadAudit();
    }

    function switchView(v) {
      view.value = v;
      if (v === "audit") loadAudit();
      if (v === "users") loadUsers();
      if (v === "reviews") loadRenewals();
    }

    function toggleSevFilter(key) {
      filterSev.value = filterSev.value === key ? null : key;
    }

    async function toggleDeleted() {
      showDeleted.value = !showDeleted.value;
      await loadCerts();
    }

    // ---------- certificate CRUD ----------
    function openCreate() {
      const d = blankForm();
      if (config.value) d.reminder_days = config.value.reminder_default_days.slice();
      Object.assign(form, d);
      editing.value = null;
      formError.value = "";
      showModal.value = true;
    }

    function openEdit(c) {
      Object.assign(form, {
        name: c.name,
        environment: c.environment,
        issued_date: c.issued_date.slice(0, 10),
        expiry_date: c.expiry_date.slice(0, 10),
        reminder_days: c.reminder_days.slice(),
        teams_webhook_url: c.teams_webhook_url || "",
        emails_text: (c.notify_emails || []).join(", "),
        notes: c.notes || "",
      });
      editing.value = c;
      formError.value = "";
      showModal.value = true;
    }

    function closeModal() { showModal.value = false; }

    function toggleDay(d) {
      const i = form.reminder_days.indexOf(d);
      if (i === -1) form.reminder_days.push(d);
      else form.reminder_days.splice(i, 1);
    }

    async function submitForm() {
      formError.value = "";
      if (!form.name.trim()) { formError.value = "Name is required."; return; }
      if (!form.expiry_date) { formError.value = "Expiry date is required."; return; }

      const payload = {
        name: form.name.trim(),
        environment: form.environment,
        issued_date: form.issued_date,
        expiry_date: form.expiry_date,
        reminder_days: form.reminder_days.slice().sort((a, b) => a - b),
        teams_webhook_url: form.teams_webhook_url.trim(),
        notify_emails: parseEmails(form.emails_text),
        notes: form.notes.trim(),
      };

      saving.value = true;
      try {
        if (editing.value) {
          await request("PUT", "/api/certificates/" + editing.value.id, payload);
          toast("Changes saved.", "ok");
        } else {
          await request("POST", "/api/certificates", payload);
          toast("Certificate added.", "ok");
        }
        showModal.value = false;
        await loadCerts();
      } catch (e) {
        if (e instanceof Unauthorized) { me.value = null; return; }
        formError.value = e.message;
      } finally {
        saving.value = false;
      }
    }

    async function deleteCert(c) {
      if (!confirm('Delete "' + c.name + '"?\n\nIt is hidden but recoverable — an administrator can restore it.')) return;
      await guard(async () => {
        await request("DELETE", "/api/certificates/" + c.id);
        toast("Certificate deleted. An administrator can restore it.", "ok");
        await loadCerts();
      });
    }

    async function restoreCert(c) {
      await guard(async () => {
        await request("POST", "/api/certificates/" + c.id + "/restore");
        toast("Certificate restored.", "ok");
        await loadCerts();
      });
    }

    async function testCert(c) {
      await guard(
        async () => {
          await request("POST", "/api/certificates/" + c.id + "/test");
          toast("Test notification sent for " + c.name + ".", "ok");
        },
        (e) => toast("Test failed: " + e.message, "err")
      );
    }

    async function runCheck() {
      await guard(async () => {
        const r = await request("POST", "/api/tasks/run-check");
        toast("Check complete — " + (r.alerts_sent || 0) + " alert(s) sent.", "ok");
        await Promise.all([loadCerts(), loadAudit()]);
      });
    }

    // ---------- owner transfer ----------
    function openOwner(c) {
      ownerModal.value = c;
      ownerTarget.value = c.owner_id || null;
    }

    async function submitOwner() {
      const c = ownerModal.value;
      if (!c || !ownerTarget.value) return;
      await guard(async () => {
        await request("PUT", "/api/certificates/" + c.id + "/owner", { owner_id: Number(ownerTarget.value) });
        ownerModal.value = null;
        toast("Owner updated.", "ok");
        await loadCerts();
      });
    }

    // ---------- renewal ----------
    function openRenew(c) {
      renewModal.value = c;
      renewForm.new_issued_date = todayStr();
      renewForm.new_expiry_date = "";
      renewForm.note = "";
      renewFile.value = null;
      renewPreview.value = "";
      renewError.value = "";
    }

    function onEvidencePicked(ev) {
      const f = ev.target.files && ev.target.files[0];
      renewError.value = "";
      if (!f) { renewFile.value = null; renewPreview.value = ""; return; }
      if (!f.type.startsWith("image/")) {
        renewError.value = "Evidence must be an image (PNG, JPEG, WebP or GIF).";
        renewFile.value = null;
        renewPreview.value = "";
        return;
      }
      if (f.size > (config.value ? config.value.max_upload_bytes : 5 * 1024 * 1024)) {
        renewError.value = "That image is larger than " + maxUploadMB.value + " MB.";
        renewFile.value = null;
        renewPreview.value = "";
        return;
      }
      renewFile.value = f;
      renewPreview.value = URL.createObjectURL(f);
    }

    async function submitRenewal() {
      renewError.value = "";
      const c = renewModal.value;
      if (!c) return;
      if (!renewForm.new_expiry_date) { renewError.value = "The new expiry date is required."; return; }
      if (!renewFile.value) { renewError.value = "Attach a picture of the new certificate."; return; }

      const fd = new FormData();
      fd.append("new_issued_date", renewForm.new_issued_date);
      fd.append("new_expiry_date", renewForm.new_expiry_date);
      fd.append("note", renewForm.note || "");
      fd.append("evidence", renewFile.value);

      renewSaving.value = true;
      try {
        await request("POST", "/api/certificates/" + c.id + "/renewals", fd);
        renewModal.value = null;
        toast("Renewal submitted. It needs a second person to approve it.", "ok");
        await Promise.all([loadCerts(), loadRenewals()]);
      } catch (e) {
        if (e instanceof Unauthorized) { me.value = null; return; }
        renewError.value = e.message;
      } finally {
        renewSaving.value = false;
      }
    }

    function openReview(r) {
      reviewModal.value = r;
      reviewNote.value = "";
    }

    async function approveRenewal() {
      const r = reviewModal.value;
      if (!r) return;
      if (!confirm("Approve this rotation?\n\n" + r.certificate_name +
        "\nThe current certificate is marked rotated and a replacement is created, expiring " +
        r.new_expiry_date.slice(0, 10) + ".")) return;
      reviewBusy.value = "approve";
      await guard(async () => {
        await request("POST", "/api/renewals/" + r.id + "/approve", { note: reviewNote.value });
        reviewModal.value = null;
        toast("Rotation approved. The replacement certificate is now being tracked.", "ok");
        await Promise.all([loadCerts(), loadRenewals(), loadAudit()]);
      });
      reviewBusy.value = "";
    }

    async function rejectRenewal() {
      const r = reviewModal.value;
      if (!r) return;
      if (!reviewNote.value.trim()) {
        toast("Give a reason so the submitter knows what to fix.", "err");
        return;
      }
      reviewBusy.value = "reject";
      await guard(async () => {
        await request("POST", "/api/renewals/" + r.id + "/reject", { note: reviewNote.value.trim() });
        reviewModal.value = null;
        toast("Renewal rejected.", "ok");
        await Promise.all([loadCerts(), loadRenewals(), loadAudit()]);
      });
      reviewBusy.value = "";
    }

    async function withdrawRenewal(r) {
      if (!confirm("Withdraw this renewal request?")) return;
      await guard(async () => {
        await request("POST", "/api/renewals/" + r.id + "/withdraw");
        toast("Request withdrawn.", "ok");
        await Promise.all([loadCerts(), loadRenewals()]);
      });
    }

    function renewalsFor(certID) {
      return renewals.value.filter((r) => r.certificate_id === certID);
    }

    // ---------- history ----------
    async function openHistory(c) {
      historyModal.value = c;
      historyEntries.value = [];
      await guard(async () => {
        historyEntries.value = await request("GET", "/api/certificates/" + c.id + "/audit");
      });
    }

    function describeEntry(e) {
      const d = e.detail || {};
      switch (e.action) {
        case "certificate.create":
          return d.via === "renewal"
            ? "Created as the replacement for #" + d.renewed_from_id + ", expiring " + d.expiry_date
            : "Created, expiring " + d.expiry_date;
        case "certificate.update":
          return d.expiry_changed
            ? "Updated — expiry moved from " + d.prev_expiry + " to " + d.expiry_date + " (reminders re-armed)"
            : "Updated settings";
        case "certificate.delete": return "Deleted";
        case "certificate.restore": return "Restored";
        case "certificate.transfer_owner": return "Owner changed to " + d.new_owner;
        case "certificate.test_notification": return "Sent a test notification";
        case "renewal.submit": return "Renewal submitted, new expiry " + d.new_expiry_date;
        case "renewal.approve": return "Renewal approved — replacement is #" + d.new_certificate_id;
        case "renewal.reject": return "Renewal rejected: " + (d.reason || "");
        case "renewal.withdraw": return "Renewal withdrawn";
        case "user.create": return "Created user " + d.username + " (" + d.role + ")";
        case "user.update": return "Updated user " + d.username + " — role " + d.role + (d.disabled ? ", disabled" : "");
        case "user.password_change": return d.self_service ? "Changed their own password" : "Password reset by an administrator";
        case "auth.login": return "Signed in from " + (d.remote || "unknown");
        case "auth.login_failed": return "Failed sign-in from " + (d.remote || "unknown");
        case "auth.logout": return "Signed out";
        case "task.run_check": return "Ran a reminder scan — " + d.alerts_sent + " alert(s) sent";
        default: return e.action;
      }
    }

    // ---------- users admin ----------
    function openUserCreate() {
      Object.assign(userForm, { username: "", display_name: "", email: "", password: "", role: "user", disabled: false });
      userError.value = "";
      userModal.value = { mode: "create" };
    }

    function openUserEdit(u) {
      Object.assign(userForm, {
        username: u.username, display_name: u.display_name || "", email: u.email || "",
        password: "", role: u.role, disabled: !!u.disabled,
      });
      userError.value = "";
      userModal.value = { mode: "edit", id: u.id };
    }

    async function submitUser() {
      userError.value = "";
      const m = userModal.value;
      try {
        if (m.mode === "create") {
          await request("POST", "/api/users", {
            username: userForm.username, display_name: userForm.display_name,
            email: userForm.email, password: userForm.password,
            role: userForm.role, disabled: false,
          });
          toast("User created.", "ok");
        } else {
          await request("PUT", "/api/users/" + m.id, {
            username: userForm.username, display_name: userForm.display_name,
            email: userForm.email, password: "", role: userForm.role, disabled: userForm.disabled,
          });
          toast("User updated.", "ok");
        }
        userModal.value = null;
        await loadUsers();
      } catch (e) {
        if (e instanceof Unauthorized) { me.value = null; return; }
        userError.value = e.message;
      }
    }

    async function resetUserPassword(u) {
      const pw = prompt('New password for "' + u.username + '" (at least 10 characters).\nEvery session for this account will be signed out.');
      if (!pw) return;
      await guard(async () => {
        await request("POST", "/api/users/" + u.id + "/password", { new_password: pw });
        toast("Password reset for " + u.username + ".", "ok");
      });
    }

    onMounted(async () => {
      document.addEventListener("click", closeMenu);
      await loadSession();
      if (me.value) await loadAll();
      booting.value = false;
    });

    return {
      // session
      booting, authEnabled, me, isAdmin, signedIn, loginForm, loginError, loggingIn,
      doLogin, doLogout, passwordModal, passwordForm, passwordError, submitPassword,
      // data
      certs, renewals, users, auditEntries, config, loading, view, switchView,
      menu, toggleMenu, closeMenu, initials,
      auditCategory, auditSearch, visibleAudit, setAuditCategory,
      auditTabs: AUDIT_TABS, actionLabel, actionTone,
      lifecycle, lifecycleKey, pendingRenewalFor,
      filterEnv, filterSev, showRotated, showDeleted, toggleDeleted, toasts,
      environments, reminderOptions, emailEnabled, escalation, maxUploadMB,
      activeCerts, rotatedCerts, deletedCerts, envCerts, counts, filteredCerts,
      pendingRenewals, myReviewQueue, awaitingOthers, activeUsers,
      severities: SEVERITIES, sevColor, sevLabel, cadenceText, statusLabel,
      fmtDateTime, fmtBytes,
      // certs
      showModal, editing, saving, formError, form,
      openCreate, openEdit, closeModal, toggleDay, submitForm,
      deleteCert, restoreCert, testCert, runCheck, toggleSevFilter,
      // owner
      ownerModal, ownerTarget, openOwner, submitOwner,
      // renewal
      renewModal, renewForm, renewFile, renewPreview, renewError, renewSaving,
      openRenew, onEvidencePicked, submitRenewal, renewalsFor,
      reviewModal, reviewNote, reviewBusy, openReview, approveRenewal, rejectRenewal, withdrawRenewal,
      // history
      historyModal, historyEntries, openHistory, describeEntry,
      // users
      userModal, userForm, userError, openUserCreate, openUserEdit, submitUser, resetUserPassword,
    };
  },

  template: `
  <div v-if="booting" class="loading">Loading…</div>

  <!-- ================= sign in ================= -->
  <div v-else-if="!signedIn" class="login">
    <aside class="login-pitch">
      <div class="mark mark-lg">
        <svg viewBox="0 0 24 24" fill="none" aria-hidden="true">
          <path d="M12 2.6 4.4 5.9v5.4c0 4.6 3.1 8.6 7.6 9.9 4.5-1.3 7.6-5.3 7.6-9.9V5.9L12 2.6Z"
                stroke="currentColor" stroke-width="1.6" stroke-linejoin="round"/>
          <path d="m8.6 12.1 2.4 2.4 4.4-4.8" stroke="currentColor" stroke-width="1.8"
                stroke-linecap="round" stroke-linejoin="round"/>
        </svg>
      </div>
      <h2>Certificate Rotation Tracker</h2>
      <p class="pitch-lede">Know how much runway every certificate has left — and never let one expire unnoticed.</p>
      <ul class="pitch-list">
        <li>
          <strong>Escalating reminders</strong>
          Milestones first, then repeats that tighten as the deadline closes in — daily in the last ten days.
        </li>
        <li>
          <strong>Owner-scoped changes</strong>
          Only the owner and administrators can edit a certificate. Everyone else reads, with credentials redacted.
        </li>
        <li>
          <strong>Four-eyes rotation</strong>
          Marking a certificate renewed needs proof and a second person's approval.
        </li>
      </ul>
    </aside>

    <div class="login-panel">
      <form class="login-card" @submit.prevent="doLogin">
        <div class="mark mark-sm login-mark">
          <svg viewBox="0 0 24 24" fill="none" aria-hidden="true">
            <path d="M12 2.6 4.4 5.9v5.4c0 4.6 3.1 8.6 7.6 9.9 4.5-1.3 7.6-5.3 7.6-9.9V5.9L12 2.6Z"
                  stroke="currentColor" stroke-width="1.6" stroke-linejoin="round"/>
            <path d="m8.6 12.1 2.4 2.4 4.4-4.8" stroke="currentColor" stroke-width="1.8"
                  stroke-linecap="round" stroke-linejoin="round"/>
          </svg>
        </div>
        <h1>Sign in</h1>
        <p class="sub">Use your tracker account to continue.</p>

        <div v-if="loginError" class="form-error">{{ loginError }}</div>

        <div class="field">
          <label for="lg-user">Username</label>
          <input id="lg-user" type="text" v-model="loginForm.username" autocomplete="username" autofocus />
        </div>
        <div class="field">
          <label for="lg-pass">Password</label>
          <input id="lg-pass" type="password" v-model="loginForm.password" autocomplete="current-password" />
        </div>
        <button class="btn btn-primary btn-block" type="submit" :disabled="loggingIn">
          {{ loggingIn ? 'Signing in…' : 'Sign in' }}
        </button>
        <p class="login-foot">
          No account yet? An administrator creates one for you.
        </p>
      </form>
    </div>
  </div>

  <!-- ================= app ================= -->
  <template v-else>
  <header class="topbar">
    <div class="topbar-inner">
      <div class="brand">
        <div class="mark mark-sm">
          <svg viewBox="0 0 24 24" fill="none" aria-hidden="true">
            <path d="M12 2.6 4.4 5.9v5.4c0 4.6 3.1 8.6 7.6 9.9 4.5-1.3 7.6-5.3 7.6-9.9V5.9L12 2.6Z"
                  stroke="currentColor" stroke-width="1.6" stroke-linejoin="round"/>
            <path d="m8.6 12.1 2.4 2.4 4.4-4.8" stroke="currentColor" stroke-width="1.8"
                  stroke-linecap="round" stroke-linejoin="round"/>
          </svg>
        </div>
        <div class="brand-text">
          <h1>Rotation Tracker</h1>
          <span v-if="config" class="env-pill">{{ config.app_env }}</span>
        </div>
      </div>

      <nav class="viewtabs">
        <button :class="{ active: view === 'certs' }" @click="switchView('certs')">Certificates</button>
        <button :class="{ active: view === 'reviews' }" @click="switchView('reviews')">
          Reviews
          <span v-if="myReviewQueue.length" class="badge-count">{{ myReviewQueue.length }}</span>
        </button>
        <button v-if="isAdmin" :class="{ active: view === 'audit' }" @click="switchView('audit')">Audit</button>
        <button v-if="isAdmin" :class="{ active: view === 'users' }" @click="switchView('users')">Users</button>
      </nav>

      <div class="menu-wrap">
        <button class="user-chip" @click.stop="toggleMenu('user')" :class="{ open: menu === 'user' }">
          <span class="avatar">{{ initials(me.username) }}</span>
          <span class="user-meta">
            <span class="user-name">{{ me.username }}</span>
            <span class="user-role">{{ me.role }}</span>
          </span>
          <svg class="chev" viewBox="0 0 24 24" fill="none" aria-hidden="true">
            <path d="m7 10 5 5 5-5" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
          </svg>
        </button>
        <div v-if="menu === 'user'" class="menu menu-right" @click.stop>
          <div class="menu-head">
            <strong>{{ me.username }}</strong>
            <span class="role-pill" :class="me.role">{{ me.role }}</span>
          </div>
          <button @click="closeMenu(); passwordModal = true">Change password…</button>
          <button class="danger" @click="closeMenu(); doLogout()">Sign out</button>
        </div>
      </div>
    </div>
  </header>

  <main class="container">

    <!-- ---------- certificates ---------- -->
    <template v-if="view === 'certs'">
    <div class="summary">
      <button v-for="s in severities" :key="s.key" class="summary-card"
        :class="{ active: filterSev === s.key }"
        :style="{ '--sev-color': sevColor(s.key) }"
        @click="toggleSevFilter(s.key)">
        <div class="count">{{ counts[s.key] || 0 }}</div>
        <div class="label">{{ s.label }}</div>
      </button>
    </div>

    <div class="toolbar">
      <div class="tabs">
        <button :class="{ active: filterEnv === 'all' }" @click="filterEnv = 'all'">All</button>
        <button v-for="e in environments" :key="e" :class="{ active: filterEnv === e }" @click="filterEnv = e">{{ e }}</button>
      </div>
      <span class="result-count">{{ filteredCerts.length }} shown</span>
      <span v-if="filterSev" class="result-count">
        · {{ sevLabel(filterSev) }} only
        <button class="btn btn-sm btn-ghost" @click="filterSev = null">clear</button>
      </span>
      <span class="spacer"></span>
      <button v-if="isAdmin" class="btn btn-sm btn-ghost" @click="runCheck">Run check now</button>
      <button class="btn btn-sm btn-primary" @click="openCreate">Add certificate</button>
    </div>

    <div v-if="loading" class="loading">Loading certificates…</div>

    <div v-else-if="filteredCerts.length === 0" class="empty">
      <h3 v-if="activeCerts.length === 0">No certificates tracked yet</h3>
      <h3 v-else>Nothing matches this filter</h3>
      <p v-if="activeCerts.length === 0">Add one to start getting rotation reminders before it expires.</p>
      <p v-else>Try a different environment or clear the severity filter.</p>
      <button v-if="activeCerts.length === 0" class="btn btn-primary" @click="openCreate">Add certificate</button>
    </div>

    <div v-else class="grid">
      <div v-for="c in filteredCerts" :key="c.id" class="card" :data-sev="c.severity"
        :style="{ '--sev-color': sevColor(c.severity) }">
        <div class="card-head">
          <div>
            <div class="card-name">{{ c.name }}</div>
            <div class="card-meta">
              <span class="tag">{{ c.environment }}</span>
              <span class="owner" :class="{ mine: c.can_edit }"
                    :title="'Owned by ' + (c.owner_username || 'nobody')">
                <span class="owner-dot">{{ initials(c.owner_username) }}</span>
                {{ c.owner_username || 'unowned' }}
              </span>
            </div>
          </div>
          <div class="badge-stack">
            <span class="sev-badge">{{ sevLabel(c.severity) }}</span>
            <span v-if="lifecycleKey(c) !== 'active'" class="life-pill"
                  :class="lifecycleKey(c)" :title="lifecycle(c).hint">
              {{ lifecycle(c).label }}
            </span>
          </div>
        </div>

        <div v-if="c.pending_renewal_id" class="ribbon pending">
          <div class="ribbon-body">
            <strong>Rotation in review</strong>
            <span v-if="pendingRenewalFor(c)">
              Submitted by <strong>{{ pendingRenewalFor(c).submitted_by_username }}</strong>
              · new expiry <span class="mono">{{ pendingRenewalFor(c).new_expiry_date.slice(0,10) }}</span>
            </span>
            <span v-else>Waiting for a second person to approve it.</span>
          </div>
          <button v-if="pendingRenewalFor(c) && pendingRenewalFor(c).can_review"
                  class="btn btn-sm btn-primary" @click="openReview(pendingRenewalFor(c))">Review</button>
          <button v-else-if="pendingRenewalFor(c) && pendingRenewalFor(c).can_withdraw"
                  class="btn btn-sm btn-ghost" @click="withdrawRenewal(pendingRenewalFor(c))">Withdraw</button>
        </div>

        <div class="countdown">
          <template v-if="c.days_remaining < 0">
            <span class="expired-txt">EXPIRED</span>
          </template>
          <template v-else-if="c.days_remaining === 0">
            <span class="num">0</span><span class="unit">expires today</span>
          </template>
          <template v-else>
            <span class="num">{{ c.days_remaining }}</span><span class="unit">days left</span>
          </template>
        </div>

        <div class="runway">
          <div class="runway-track">
            <div class="runway-fill" :style="{ width: c.life_percent + '%' }"></div>
          </div>
          <div class="runway-labels">
            <span>{{ c.issued_date.slice(0,10) }}</span>
            <span>{{ c.expiry_date.slice(0,10) }}</span>
          </div>
        </div>

        <div class="detail">
          <div class="detail-row">
            <span class="k">Expiry</span>
            <span class="v">{{ c.expiry_date.slice(0,10) }}</span>
          </div>
          <div class="detail-row">
            <span class="k">Remind before</span>
            <span class="chips">
              <span v-for="d in c.reminder_days" :key="d" class="chip">{{ d }}d</span>
              <span v-if="c.reminder_days.length === 0" class="chip">none</span>
            </span>
          </div>
          <div class="detail-row">
            <span class="k">Alert cadence</span>
            <span class="v" :class="{ hot: c.reminder_interval_days === 1 }">{{ cadenceText(c) }}</span>
          </div>
          <div class="detail-row">
            <span class="k">Status</span>
            <span class="v" :title="lifecycle(c).hint">{{ lifecycle(c).label }}</span>
          </div>
          <div class="detail-row" v-if="c.notes">
            <span class="k">Notes</span>
            <span class="v" style="font-family:var(--sans);text-align:right;max-width:60%">{{ c.notes }}</span>
          </div>
        </div>

        <div class="channels">
          <span v-if="c.teams_webhook_set" class="channel">Teams</span>
          <span v-if="c.notify_email_count" class="channel email">Email ({{ c.notify_email_count }})</span>
          <span v-if="!c.teams_webhook_set && !c.notify_email_count" class="channel none">No alerts set</span>
        </div>

        <div class="card-actions">
          <button class="icon-btn" title="Change history" aria-label="Change history" @click="openHistory(c)">
            <svg viewBox="0 0 24 24" fill="none" aria-hidden="true">
              <circle cx="12" cy="12" r="8.4" stroke="currentColor" stroke-width="1.7"/>
              <path d="M12 7.4V12l3 1.8" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/>
            </svg>
          </button>
          <span class="spacer"></span>
          <template v-if="c.can_edit">
            <button v-if="!c.pending_renewal_id" class="btn btn-sm btn-accent"
                    title="Mark renewed — needs proof and a second person's approval"
                    @click="openRenew(c)">Renew</button>
            <button class="btn btn-sm btn-ghost" @click="openEdit(c)">Edit</button>
            <div class="menu-wrap">
              <button class="icon-btn" title="More actions" aria-label="More actions"
                      :class="{ open: menu === 'cert-' + c.id }" @click.stop="toggleMenu('cert-' + c.id)">
                <svg viewBox="0 0 24 24" fill="none" aria-hidden="true">
                  <circle cx="5.5" cy="12" r="1.6" fill="currentColor"/>
                  <circle cx="12"  cy="12" r="1.6" fill="currentColor"/>
                  <circle cx="18.5" cy="12" r="1.6" fill="currentColor"/>
                </svg>
              </button>
              <div v-if="menu === 'cert-' + c.id" class="menu menu-right" @click.stop>
                <button @click="closeMenu(); testCert(c)">Send test notification</button>
                <button @click="closeMenu(); openOwner(c)">Change owner…</button>
                <button class="danger" @click="closeMenu(); deleteCert(c)">Delete certificate</button>
              </div>
            </div>
          </template>
          <span v-else class="read-only-note"
                title="Only the owner and administrators can edit this certificate or see its webhook URL and recipient list">
            Read-only · {{ c.owner_username || 'unowned' }}
          </span>
        </div>
      </div>
    </div>

    <!-- rotated history -->
    <section v-if="rotatedCerts.length" class="section">
      <button class="disclosure" :class="{ open: showRotated }" @click="showRotated = !showRotated"
              :aria-expanded="showRotated ? 'true' : 'false'">
        <span class="disclosure-chev">
          <svg viewBox="0 0 24 24" fill="none" aria-hidden="true">
            <path d="m9 6 6 6-6 6" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
          </svg>
        </span>
        <span class="disclosure-text">
          <strong>Rotated</strong>
          <span class="hint">Completed rotations — replaced, and no longer alerting</span>
        </span>
        <span class="disclosure-count">{{ rotatedCerts.length }}</span>
      </button>
      <div v-if="showRotated" class="table-wrap"><table class="table">
        <thead><tr><th>Certificate</th><th>Env</th><th>Expired</th><th>Owner</th><th>Rotated</th></tr></thead>
        <tbody>
          <tr v-for="c in rotatedCerts" :key="c.id">
            <td>{{ c.name }}</td>
            <td><span class="tag">{{ c.environment }}</span></td>
            <td class="mono">{{ c.expiry_date.slice(0,10) }}</td>
            <td>{{ c.owner_username }}</td>
            <td><span class="life-pill rotated">Rotated</span> {{ fmtDateTime(c.rotated_at) }}</td>
          </tr>
        </tbody>
      </table></div>
    </section>

    <!-- deleted (admin) -->
    <section v-if="isAdmin" class="section">
      <button class="disclosure" :class="{ open: showDeleted }" @click="toggleDeleted"
              :aria-expanded="showDeleted ? 'true' : 'false'">
        <span class="disclosure-chev">
          <svg viewBox="0 0 24 24" fill="none" aria-hidden="true">
            <path d="m9 6 6 6-6 6" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
          </svg>
        </span>
        <span class="disclosure-text">
          <strong>Deleted</strong>
          <span class="hint">Soft-deleted certificates — nothing is lost, restore any of them</span>
        </span>
        <span v-if="showDeleted" class="disclosure-count">{{ deletedCerts.length }}</span>
      </button>
      <div v-if="showDeleted" class="table-wrap"><table class="table">
        <thead><tr><th>Certificate</th><th>Env</th><th>Owner</th><th>Deleted</th><th></th></tr></thead>
        <tbody>
          <tr v-if="deletedCerts.length === 0"><td colspan="5" class="hint">Nothing deleted.</td></tr>
          <tr v-for="c in deletedCerts" :key="c.id">
            <td>{{ c.name }}</td>
            <td><span class="tag">{{ c.environment }}</span></td>
            <td>{{ c.owner_username }}</td>
            <td><span class="life-pill deleted">Deleted</span> {{ fmtDateTime(c.deleted_at) }}</td>
            <td><button class="btn btn-sm btn-ghost" @click="restoreCert(c)">Restore</button></td>
          </tr>
        </tbody>
      </table></div>
    </section>
    </template>

    <!-- ---------- reviews ---------- -->
    <template v-if="view === 'reviews'">
      <div class="panel-intro">
        <h2>Rotation reviews</h2>
        <p>A rotation is only recorded once a <strong>second person</strong> confirms the evidence.
           You cannot approve a request you submitted yourself.</p>
      </div>

      <h3 class="list-head">Waiting for you ({{ myReviewQueue.length }})</h3>
      <div v-if="myReviewQueue.length === 0" class="empty small"><p>Nothing needs your review.</p></div>
      <div v-else class="review-list">
        <div v-for="r in myReviewQueue" :key="r.id" class="review-row">
          <div class="review-main">
            <div class="review-name">{{ r.certificate_name }} <span class="tag">{{ r.environment }}</span></div>
            <div class="hint">
              Submitted by <strong>{{ r.submitted_by_username }}</strong> · {{ fmtDateTime(r.submitted_at) }}
              · new expiry <span class="mono">{{ r.new_expiry_date.slice(0,10) }}</span>
            </div>
          </div>
          <button class="btn btn-sm btn-primary" @click="openReview(r)">Review</button>
        </div>
      </div>

      <h3 class="list-head">Submitted, waiting for someone else ({{ awaitingOthers.length }})</h3>
      <div v-if="awaitingOthers.length === 0" class="empty small"><p>Nothing pending.</p></div>
      <div v-else class="review-list">
        <div v-for="r in awaitingOthers" :key="r.id" class="review-row muted">
          <div class="review-main">
            <div class="review-name">{{ r.certificate_name }} <span class="tag">{{ r.environment }}</span></div>
            <div class="hint">
              You submitted this {{ fmtDateTime(r.submitted_at) }} · new expiry
              <span class="mono">{{ r.new_expiry_date.slice(0,10) }}</span>
            </div>
          </div>
          <button v-if="r.can_withdraw" class="btn btn-sm btn-ghost" @click="withdrawRenewal(r)">Withdraw</button>
        </div>
      </div>

      <h3 class="list-head">Recently decided</h3>
      <div class="table-wrap"><table class="table">
        <thead><tr><th>Certificate</th><th>Status</th><th>Submitted by</th><th>Reviewed by</th><th>When</th><th></th></tr></thead>
        <tbody>
          <tr v-for="r in renewals.filter(x => x.status !== 'pending_review').slice(0, 25)" :key="r.id">
            <td>{{ r.certificate_name }}</td>
            <td><span class="status" :class="r.status">{{ statusLabel(r.status) }}</span></td>
            <td>{{ r.submitted_by_username }}</td>
            <td>{{ r.reviewed_by_username || '—' }}</td>
            <td>{{ fmtDateTime(r.reviewed_at || r.submitted_at) }}</td>
            <td><a class="btn btn-sm btn-ghost" :href="'/api/renewals/' + r.id + '/evidence'" target="_blank" rel="noopener">Evidence</a></td>
          </tr>
          <tr v-if="renewals.filter(x => x.status !== 'pending_review').length === 0">
            <td colspan="6" class="hint">No decisions yet.</td>
          </tr>
        </tbody>
      </table></div>
    </template>

    <!-- ---------- audit ---------- -->
    <template v-if="view === 'audit' && isAdmin">
      <div class="panel-intro">
        <h2>Audit log</h2>
        <p>Every change, who made it and when. Append-only — nothing here can be edited or removed.</p>
      </div>

      <div class="toolbar">
        <div class="tabs">
          <button v-for="t in auditTabs" :key="t.key"
                  :class="{ active: auditCategory === t.key }"
                  @click="setAuditCategory(t.key)">{{ t.label }}</button>
        </div>
        <span class="spacer"></span>
        <input class="search" type="search" v-model="auditSearch"
               placeholder="Filter by person, action or detail…" />
      </div>

      <div class="table-wrap"><table class="table">
        <thead><tr><th>When</th><th>Who</th><th>Action</th><th>What happened</th><th>Entity</th></tr></thead>
        <tbody>
          <tr v-for="e in visibleAudit" :key="e.id">
            <td class="nowrap">{{ fmtDateTime(e.created_at) }}</td>
            <td class="nowrap"><span class="who-cell"><span class="avatar sm">{{ initials(e.actor) }}</span>{{ e.actor || '—' }}</span></td>
            <td class="nowrap"><span class="action-pill" :class="actionTone(e.action)">{{ actionLabel(e.action) }}</span></td>
            <td>{{ describeEntry(e) }}</td>
            <td class="hint nowrap">{{ e.entity_type }}<template v-if="e.entity_id"> #{{ e.entity_id }}</template></td>
          </tr>
          <tr v-if="visibleAudit.length === 0">
            <td colspan="5" class="hint">
              <template v-if="auditSearch">Nothing matches “{{ auditSearch }}” in this category.</template>
              <template v-else-if="auditCategory !== 'all'">Nothing recorded in this category yet.</template>
              <template v-else>Nothing recorded yet.</template>
            </td>
          </tr>
        </tbody>
      </table></div>
      <p class="hint" style="margin-top:10px">
        Showing {{ visibleAudit.length }}
        <template v-if="visibleAudit.length !== auditEntries.length">of {{ auditEntries.length }} </template>
        most recent entries<template v-if="auditCategory !== 'all'"> in this category</template>.
      </p>
    </template>

    <!-- ---------- users ---------- -->
    <template v-if="view === 'users' && isAdmin">
      <div class="panel-intro">
        <h2>Users</h2>
        <p>Accounts are disabled rather than deleted, so certificate ownership and audit history keep pointing at a real person.</p>
      </div>
      <div class="toolbar">
        <span class="spacer"></span>
        <button class="btn btn-sm btn-primary" @click="openUserCreate">Add user</button>
      </div>
      <div class="table-wrap"><table class="table">
        <thead><tr><th>Username</th><th>Name</th><th>Email</th><th>Role</th><th>Status</th><th></th></tr></thead>
        <tbody>
          <tr v-for="u in users" :key="u.id" :class="{ muted: u.disabled }">
            <td class="mono">{{ u.username }}</td>
            <td>{{ u.display_name || '—' }}</td>
            <td>{{ u.email || '—' }}</td>
            <td><span class="role-pill" :class="u.role">{{ u.role }}</span></td>
            <td>{{ u.disabled ? 'Disabled' : 'Active' }}</td>
            <td class="nowrap">
              <button class="btn btn-sm btn-ghost" @click="openUserEdit(u)">Edit</button>
              <button class="btn btn-sm btn-ghost" @click="resetUserPassword(u)">Reset password</button>
            </td>
          </tr>
        </tbody>
      </table></div>
    </template>

  </main>

  <!-- ================= modals ================= -->

  <!-- certificate form -->
  <div v-if="showModal" class="overlay" @click.self="closeModal">
    <div class="modal">
      <div class="modal-head">
        <h2>{{ editing ? 'Edit certificate' : 'Add certificate' }}</h2>
        <button class="btn btn-sm btn-ghost" @click="closeModal">Close</button>
      </div>
      <div class="modal-body">
        <div v-if="formError" class="form-error">{{ formError }}</div>

        <div class="field">
          <label>Name</label>
          <input type="text" v-model="form.name" placeholder="e.g. api.example.com TLS" />
        </div>

        <div class="row-2">
          <div class="field">
            <label>Environment</label>
            <select v-model="form.environment">
              <option v-for="e in environments" :key="e" :value="e">{{ e }}</option>
            </select>
          </div>
          <div class="field">
            <label>Issued date</label>
            <input type="date" v-model="form.issued_date" />
          </div>
        </div>

        <div class="field">
          <label>Expiry date</label>
          <input type="date" v-model="form.expiry_date" />
        </div>

        <div class="field">
          <label>Remind before expiry</label>
          <div class="day-toggle">
            <button v-for="d in reminderOptions" :key="d" type="button"
              :class="{ on: form.reminder_days.includes(d) }" @click="toggleDay(d)">{{ d }}d</button>
          </div>
          <span class="hint">One alert per milestone as the deadline approaches.</span>
          <div v-if="escalation.length" class="escalation-note">
            <strong>Then it escalates automatically:</strong>
            <span v-for="(r, i) in escalation" :key="r.within_days">
              under {{ r.within_days }} days → every {{ r.every_days === 1 ? 'day' : r.every_days + ' days' }}<template v-if="i < escalation.length - 1">, </template>
            </span>
          </div>
        </div>

        <div class="field">
          <label>Teams webhook URL</label>
          <input type="text" class="mono" v-model="form.teams_webhook_url"
            placeholder="https://…  (Power Automate Workflows URL)" />
          <span class="hint">Leave blank to skip Teams. Only you and administrators can see this value.</span>
        </div>

        <div class="field">
          <label>Email recipients</label>
          <input type="text" class="mono" v-model="form.emails_text"
            placeholder="alice@example.com, bob@example.com" />
          <span class="hint" v-if="emailEnabled">Comma-separated. Leave blank to skip email.</span>
          <span class="hint" v-else>Email delivery is not configured on the server (set SMTP_* to enable).</span>
        </div>

        <div class="field">
          <label>Notes <span class="hint">(optional)</span></label>
          <textarea v-model="form.notes" placeholder="Where it lives, who owns it, rotation steps…"></textarea>
        </div>
      </div>
      <div class="modal-foot">
        <button class="btn btn-ghost" @click="closeModal">Cancel</button>
        <button class="btn btn-primary" :disabled="saving" @click="submitForm">
          {{ saving ? 'Saving…' : (editing ? 'Save changes' : 'Add certificate') }}
        </button>
      </div>
    </div>
  </div>

  <!-- mark renewed -->
  <div v-if="renewModal" class="overlay" @click.self="renewModal = null">
    <div class="modal">
      <div class="modal-head">
        <h2>Mark "{{ renewModal.name }}" renewed</h2>
        <button class="btn btn-sm btn-ghost" @click="renewModal = null">Close</button>
      </div>
      <div class="modal-body">
        <div class="callout">
          This does <strong>not</strong> complete the rotation on its own. Once submitted, another
          person has to check the evidence and approve it. Only then is this certificate marked
          rotated and a replacement created with the new dates below.
        </div>
        <div v-if="renewError" class="form-error">{{ renewError }}</div>

        <div class="row-2">
          <div class="field">
            <label>New issued date</label>
            <input type="date" v-model="renewForm.new_issued_date" />
          </div>
          <div class="field">
            <label>New expiry date</label>
            <input type="date" v-model="renewForm.new_expiry_date" />
          </div>
        </div>

        <div class="field">
          <label>Proof of the new certificate</label>
          <input type="file" accept="image/png,image/jpeg,image/webp,image/gif" @change="onEvidencePicked" />
          <span class="hint">A screenshot of the new certificate's details. PNG, JPEG, WebP or GIF, up to {{ maxUploadMB }} MB.</span>
          <div v-if="renewPreview" class="evidence-preview">
            <img :src="renewPreview" alt="Evidence preview" />
            <span class="hint">{{ renewFile.name }} · {{ fmtBytes(renewFile.size) }}</span>
          </div>
        </div>

        <div class="field">
          <label>Note for the reviewer <span class="hint">(optional)</span></label>
          <textarea v-model="renewForm.note" placeholder="Serial number, where it was deployed, ticket reference…"></textarea>
        </div>
      </div>
      <div class="modal-foot">
        <button class="btn btn-ghost" @click="renewModal = null">Cancel</button>
        <button class="btn btn-primary" :disabled="renewSaving" @click="submitRenewal">
          {{ renewSaving ? 'Submitting…' : 'Submit for review' }}
        </button>
      </div>
    </div>
  </div>

  <!-- review a renewal -->
  <div v-if="reviewModal" class="overlay" @click.self="reviewModal = null">
    <div class="modal modal-wide">
      <div class="modal-head">
        <h2>Review rotation — {{ reviewModal.certificate_name }}</h2>
        <button class="btn btn-sm btn-ghost" @click="reviewModal = null">Close</button>
      </div>
      <div class="modal-body">
        <div class="detail">
          <div class="detail-row"><span class="k">Submitted by</span><span class="v">{{ reviewModal.submitted_by_username }}</span></div>
          <div class="detail-row"><span class="k">Submitted at</span><span class="v">{{ fmtDateTime(reviewModal.submitted_at) }}</span></div>
          <div class="detail-row"><span class="k">New issued</span><span class="v">{{ reviewModal.new_issued_date.slice(0,10) }}</span></div>
          <div class="detail-row"><span class="k">New expiry</span><span class="v">{{ reviewModal.new_expiry_date.slice(0,10) }}</span></div>
          <div class="detail-row"><span class="k">Evidence</span><span class="v">{{ reviewModal.evidence_filename }} · {{ fmtBytes(reviewModal.evidence_size) }}</span></div>
          <div class="detail-row"><span class="k">SHA-256</span><span class="v mono tiny">{{ reviewModal.evidence_sha256 }}</span></div>
        </div>

        <div v-if="reviewModal.note" class="field">
          <label>Submitter's note</label>
          <div class="quote">{{ reviewModal.note }}</div>
        </div>

        <div class="field">
          <label>Evidence</label>
          <div class="evidence-frame">
            <img :src="'/api/renewals/' + reviewModal.id + '/evidence'" alt="Renewal evidence" />
          </div>
          <a class="hint" :href="'/api/renewals/' + reviewModal.id + '/evidence'" target="_blank" rel="noopener">Open full size</a>
        </div>

        <div class="field">
          <label>Review note <span class="hint">(required to reject)</span></label>
          <textarea v-model="reviewNote" placeholder="What you checked, or what is wrong with this submission…"></textarea>
        </div>
      </div>
      <div class="modal-foot">
        <button class="btn btn-danger-solid" :disabled="!!reviewBusy" @click="rejectRenewal">
          {{ reviewBusy === 'reject' ? 'Rejecting…' : 'Reject' }}
        </button>
        <span class="spacer"></span>
        <button class="btn btn-ghost" @click="reviewModal = null">Cancel</button>
        <button class="btn btn-primary" :disabled="!!reviewBusy" @click="approveRenewal">
          {{ reviewBusy === 'approve' ? 'Approving…' : 'Approve rotation' }}
        </button>
      </div>
    </div>
  </div>

  <!-- transfer owner -->
  <div v-if="ownerModal" class="overlay" @click.self="ownerModal = null">
    <div class="modal modal-sm">
      <div class="modal-head">
        <h2>Owner of "{{ ownerModal.name }}"</h2>
        <button class="btn btn-sm btn-ghost" @click="ownerModal = null">Close</button>
      </div>
      <div class="modal-body">
        <p class="hint">The owner is the only person besides an administrator who can edit or
           delete this certificate. Hand it over before you leave the team, or it will need an
           administrator to unstick it.</p>
        <div class="field">
          <label>New owner</label>
          <select v-model="ownerTarget">
            <option v-for="u in activeUsers" :key="u.id" :value="u.id">
              {{ u.username }}<template v-if="u.display_name"> — {{ u.display_name }}</template>
            </option>
          </select>
        </div>
      </div>
      <div class="modal-foot">
        <button class="btn btn-ghost" @click="ownerModal = null">Cancel</button>
        <button class="btn btn-primary" @click="submitOwner">Transfer</button>
      </div>
    </div>
  </div>

  <!-- certificate history -->
  <div v-if="historyModal" class="overlay" @click.self="historyModal = null">
    <div class="modal modal-wide">
      <div class="modal-head">
        <h2>History — {{ historyModal.name }}</h2>
        <button class="btn btn-sm btn-ghost" @click="historyModal = null">Close</button>
      </div>
      <div class="modal-body">
        <div class="table-wrap"><table class="table">
          <thead><tr><th>When</th><th>Who</th><th>What</th></tr></thead>
          <tbody>
            <tr v-for="e in historyEntries" :key="e.id">
              <td class="nowrap">{{ fmtDateTime(e.created_at) }}</td>
              <td><strong>{{ e.actor }}</strong></td>
              <td>{{ describeEntry(e) }}</td>
            </tr>
            <tr v-if="historyEntries.length === 0"><td colspan="3" class="hint">No history yet.</td></tr>
          </tbody>
        </table></div>

        <h3 class="list-head">Renewal requests</h3>
        <div class="table-wrap"><table class="table">
          <thead><tr><th>Status</th><th>New expiry</th><th>Submitted by</th><th>Reviewed by</th><th></th></tr></thead>
          <tbody>
            <tr v-for="r in renewalsFor(historyModal.id)" :key="r.id">
              <td><span class="status" :class="r.status">{{ statusLabel(r.status) }}</span></td>
              <td class="mono">{{ r.new_expiry_date.slice(0,10) }}</td>
              <td>{{ r.submitted_by_username }}</td>
              <td>{{ r.reviewed_by_username || '—' }}</td>
              <td><a class="btn btn-sm btn-ghost" :href="'/api/renewals/' + r.id + '/evidence'" target="_blank" rel="noopener">Evidence</a></td>
            </tr>
            <tr v-if="renewalsFor(historyModal.id).length === 0"><td colspan="5" class="hint">None.</td></tr>
          </tbody>
        </table></div>
      </div>
    </div>
  </div>

  <!-- change password -->
  <div v-if="passwordModal" class="overlay" @click.self="passwordModal = false">
    <div class="modal modal-sm">
      <div class="modal-head">
        <h2>Change password</h2>
        <button class="btn btn-sm btn-ghost" @click="passwordModal = false">Close</button>
      </div>
      <div class="modal-body">
        <div v-if="passwordError" class="form-error">{{ passwordError }}</div>
        <div class="field">
          <label>Current password</label>
          <input type="password" v-model="passwordForm.current_password" autocomplete="current-password" />
        </div>
        <div class="field">
          <label>New password</label>
          <input type="password" v-model="passwordForm.new_password" autocomplete="new-password" />
          <span class="hint">At least 10 characters. All your other sessions will be signed out.</span>
        </div>
        <div class="field">
          <label>Confirm new password</label>
          <input type="password" v-model="passwordForm.confirm" autocomplete="new-password" />
        </div>
      </div>
      <div class="modal-foot">
        <button class="btn btn-ghost" @click="passwordModal = false">Cancel</button>
        <button class="btn btn-primary" @click="submitPassword">Change password</button>
      </div>
    </div>
  </div>

  <!-- user form -->
  <div v-if="userModal" class="overlay" @click.self="userModal = null">
    <div class="modal modal-sm">
      <div class="modal-head">
        <h2>{{ userModal.mode === 'create' ? 'Add user' : 'Edit user' }}</h2>
        <button class="btn btn-sm btn-ghost" @click="userModal = null">Close</button>
      </div>
      <div class="modal-body">
        <div v-if="userError" class="form-error">{{ userError }}</div>
        <div class="field">
          <label>Username</label>
          <input type="text" class="mono" v-model="userForm.username" :disabled="userModal.mode === 'edit'" />
          <span v-if="userModal.mode === 'create'" class="hint">Lower-case letters, digits, dot, dash or underscore.</span>
        </div>
        <div class="field">
          <label>Display name</label>
          <input type="text" v-model="userForm.display_name" />
        </div>
        <div class="field">
          <label>Email</label>
          <input type="text" class="mono" v-model="userForm.email" />
        </div>
        <div v-if="userModal.mode === 'create'" class="field">
          <label>Initial password</label>
          <input type="text" class="mono" v-model="userForm.password" />
          <span class="hint">At least 10 characters. Ask them to change it after their first sign-in.</span>
        </div>
        <div class="field">
          <label>Role</label>
          <select v-model="userForm.role">
            <option value="user">user — can create and manage their own certificates</option>
            <option value="admin">admin — can manage every certificate and user</option>
          </select>
        </div>
        <div v-if="userModal.mode === 'edit'" class="field">
          <label class="checkline">
            <input type="checkbox" v-model="userForm.disabled" />
            Disabled — cannot sign in; existing sessions end immediately
          </label>
        </div>
      </div>
      <div class="modal-foot">
        <button class="btn btn-ghost" @click="userModal = null">Cancel</button>
        <button class="btn btn-primary" @click="submitUser">
          {{ userModal.mode === 'create' ? 'Create user' : 'Save changes' }}
        </button>
      </div>
    </div>
  </div>
  </template>

  <div class="toasts">
    <div v-for="t in toasts" :key="t.id" class="toast" :class="t.type">{{ t.message }}</div>
  </div>
  `,
}).mount("#app");
