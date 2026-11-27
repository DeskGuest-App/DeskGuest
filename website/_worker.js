// DeskGuest website — report-form relay (Pages advanced-mode worker).
//
// Scoped by _routes.json to /api/* and /files/* only; every other path
// falls through to the static site. The relay takes a report from the
// website's own form and files it as an issue on the project tracker,
// so a visitor never has to leave the site or hold an account anywhere.
//
// Secrets live in the Pages project's environment, never in this file:
//   GH_TOKEN          tracker credential (secret)
//   TURNSTILE_SECRET  Turnstile secret key (secret)
//   FORMS_ENABLED     "1" normally; anything else pauses the forms
// Bindings: DG_FILES (KV, attachments), DG_RL (KV, rate limiting).

const REPO = "DeskGuest-App/DeskGuest";
const PROJECT_ID = "PVT_kwHOD5a-Zs4BtHa9";
const STATUS_FIELD = "PVTSSF_lAHOD5a-Zs4BtHa9zhrSZIc";
const TODO_OPTION = "f75ad846";
const AREA_FIELD = "PVTSSF_lAHOD5a-Zs4BtHa9zhrSZeI";
const AREA_OPTIONS = { windows: "8f7a195e", android: "96caf066", website: "d59585f5" };
const PRIORITY_FIELD = "PVTSSF_lAHOD5a-Zs4BtHa9zhrSZeA";
const PRIORITY_OPTIONS = { p1: "c651cc10", p2: "41979969", p3: "b9da1f74" };

const MAX_FILES = 8;
const MAX_FILE_BYTES = 10 * 1024 * 1024;
const MAX_TOTAL_BYTES = 25 * 1024 * 1024;
const RL_PER_IP_HOUR = 6;
const RL_GLOBAL_DAY = 200;

const TEXT_CAPS = {
  summary: 150, trying: 2000, happened: 5000, steps: 5000,
  details: 5000, contact: 200,
};
const AREAS = ["Windows app", "Android app", "This website", "Pairing & connecting", "An AI session", "Something else"];
const AREA_KEYS = { "Windows app": "windows", "Android app": "android", "This website": "website" };
const SEVERITIES = [
  "It stops me using DeskGuest",
  "It's wrong, but I can work around it",
  "It's minor — a glitch or something that looks off",
  "Not sure",
];
const SEVERITY_PRIORITY = {
  "It stops me using DeskGuest": "p1",
  "It's wrong, but I can work around it": "p2",
  "It's minor — a glitch or something that looks off": "p3",
};
const CONNECTIONS = ["Same network (both devices at home)", "DeskGuest hub", "Tailscale", "NetBird", "Direct or relay", "I don't know", "Not about a connection"];
const AI_CHOICES = ["No AI — a person was helping me", "Claude", "ChatGPT", "DeepSeek", "Gemini", "Another AI agent", "Not sure"];

// Extension allowlist + magic-byte expectations. SVG is excluded on
// purpose: it is a script carrier when served. Executables likewise.
const FILE_TYPES = {
  png: { mime: "image/png", magic: [[0x89, 0x50, 0x4e, 0x47]] },
  jpg: { mime: "image/jpeg", magic: [[0xff, 0xd8, 0xff]] },
  jpeg: { mime: "image/jpeg", magic: [[0xff, 0xd8, 0xff]] },
  gif: { mime: "image/gif", magic: [[0x47, 0x49, 0x46, 0x38]] },
  webp: { mime: "image/webp", magic: "webp" },
  pdf: { mime: "application/pdf", magic: [[0x25, 0x50, 0x44, 0x46]] },
  zip: { mime: "application/zip", magic: [[0x50, 0x4b, 0x03, 0x04], [0x50, 0x4b, 0x05, 0x06]] },
  mp4: { mime: "video/mp4", magic: "ftyp" },
  webm: { mime: "video/webm", magic: [[0x1a, 0x45, 0xdf, 0xa3]] },
  txt: { mime: "text/plain", magic: null },
  log: { mime: "text/plain", magic: null },
  md: { mime: "text/plain", magic: null },
};
const INLINE_MIMES = new Set(["image/png", "image/jpeg", "image/gif", "image/webp"]);

function json(status, obj) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
  });
}
const fail = (status, error) => json(status, { ok: false, error });

function cleanText(v, cap) {
  if (typeof v !== "string") return "";
  return v.replace(/\r\n?/g, "\n").trim().slice(0, cap);
}

function safeName(name) {
  const base = String(name || "file").replace(/\\/g, "/");
  const parts = base.split("/").filter((p) => p && p !== "." && p !== "..");
  return (parts.join("/") || "file").replace(/[<>\x00-\x1f\x7f"]/g, "").slice(0, 160) || "file";
}

function extOf(name) {
  const m = /\.([A-Za-z0-9]{1,8})$/.exec(name);
  return m ? m[1].toLowerCase() : "";
}

function magicOk(ext, bytes) {
  const spec = FILE_TYPES[ext];
  if (!spec) return false;
  // Executables are refused whatever the extension claims.
  if (bytes.length >= 2 && bytes[0] === 0x4d && bytes[1] === 0x5a) return false; // MZ
  if (bytes.length >= 4 && bytes[0] === 0x7f && bytes[1] === 0x45 && bytes[2] === 0x4c && bytes[3] === 0x46) return false; // ELF
  if (!spec.magic) {
    // Text family: must look like text (no NUL in the head, mostly printable).
    const head = bytes.subarray(0, Math.min(1024, bytes.length));
    for (const b of head) if (b === 0) return false;
    return true;
  }
  if (spec.magic === "webp") {
    return bytes.length >= 12 &&
      String.fromCharCode(...bytes.subarray(0, 4)) === "RIFF" &&
      String.fromCharCode(...bytes.subarray(8, 12)) === "WEBP";
  }
  if (spec.magic === "ftyp") {
    return bytes.length >= 8 && String.fromCharCode(...bytes.subarray(4, 8)) === "ftyp";
  }
  return spec.magic.some((sig) => sig.every((b, i) => bytes[i] === b));
}

async function rateLimited(env, ip) {
  if (!env.DG_RL) return false;
  const hour = new Date().toISOString().slice(0, 13);
  const day = hour.slice(0, 10);
  const ipKey = `rl:ip:${hour}:${ip}`;
  const gKey = `rl:global:${day}`;
  const [ipCount, gCount] = await Promise.all([
    env.DG_RL.get(ipKey).then((v) => parseInt(v || "0", 10)),
    env.DG_RL.get(gKey).then((v) => parseInt(v || "0", 10)),
  ]);
  if (ipCount >= RL_PER_IP_HOUR || gCount >= RL_GLOBAL_DAY) return true;
  await Promise.all([
    env.DG_RL.put(ipKey, String(ipCount + 1), { expirationTtl: 3700 }),
    env.DG_RL.put(gKey, String(gCount + 1), { expirationTtl: 90000 }),
  ]);
  return false;
}

async function turnstileOk(env, token, ip) {
  if (!token) return false;
  const body = new URLSearchParams({ secret: env.TURNSTILE_SECRET, response: token, remoteip: ip });
  const r = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
    method: "POST", body,
  });
  if (!r.ok) return false;
  const data = await r.json();
  return data.success === true && ["deskguest.app", "www.deskguest.app", "deskguest.pages.dev"].includes(data.hostname);
}

async function gh(env, path, init) {
  return fetch(`https://api.github.com${path}`, {
    ...init,
    headers: {
      Authorization: `Bearer ${env.GH_TOKEN}`,
      Accept: "application/vnd.github+json",
      "X-GitHub-Api-Version": "2022-11-28",
      "User-Agent": "deskguest-website-forms",
      ...(init && init.body ? { "Content-Type": "application/json" } : {}),
    },
  });
}

async function boardIssue(env, issue, kind, area, severity) {
  // Best-effort: the issue already landed labelled; boarding must never
  // fail the visitor's submission.
  try {
    const q = (query, variables) =>
      gh(env, "/graphql", { method: "POST", body: JSON.stringify({ query, variables }) })
        .then((r) => r.json());
    const added = await q(
      `mutation($p:ID!,$c:ID!){ addProjectV2ItemById(input:{projectId:$p, contentId:$c}){ item { id } } }`,
      { p: PROJECT_ID, c: issue.node_id });
    const itemId = added?.data?.addProjectV2ItemById?.item?.id;
    if (!itemId) return;
    const setField = (field, option) =>
      q(`mutation($p:ID!,$i:ID!,$f:ID!,$o:String!){ updateProjectV2ItemFieldValue(input:{projectId:$p, itemId:$i, fieldId:$f, value:{singleSelectOptionId:$o}}){ projectV2Item { id } } }`,
        { p: PROJECT_ID, i: itemId, f: field, o: option });
    await setField(STATUS_FIELD, TODO_OPTION);
    const areaKey = AREA_KEYS[area];
    if (areaKey && AREA_OPTIONS[areaKey]) await setField(AREA_FIELD, AREA_OPTIONS[areaKey]);
    if (kind === "bug" && SEVERITY_PRIORITY[severity]) {
      await setField(PRIORITY_FIELD, PRIORITY_OPTIONS[SEVERITY_PRIORITY[severity]]);
    }
  } catch (_) { /* boarding is a nicety, never a blocker */ }
}

async function handleReport(request, env) {
  if (env.FORMS_ENABLED !== "1") {
    return fail(503, "Reports are paused right now. Please try again later.");
  }
  const ip = request.headers.get("CF-Connecting-IP") || "unknown";
  if (await rateLimited(env, ip)) {
    return fail(429, "That's a lot of reports in a short time. Please wait a little and try again.");
  }
  let form;
  try {
    form = await request.formData();
  } catch (_) {
    return fail(400, "That submission couldn't be read. Please try again.");
  }

  // Honeypot + time trap: a tripped trap gets a quiet fake success and
  // files nothing, so a bot learns nothing.
  const honeypot = form.get("website");
  const ts = parseInt(form.get("form_ts") || "0", 10);
  const ageMs = Date.now() - ts;
  if ((typeof honeypot === "string" && honeypot.trim() !== "") || !(ageMs > 2500 && ageMs < 2 * 3600 * 1000)) {
    return json(200, { ok: true });
  }

  if (!(await turnstileOk(env, form.get("cf-turnstile-response"), ip))) {
    return fail(403, "The “I'm human” check didn't pass. Please tick it and try again.");
  }

  const kind = form.get("kind");
  if (kind !== "bug" && kind !== "feedback") {
    return fail(400, "Please choose whether this is a bug or feedback.");
  }
  const summary = cleanText(form.get("summary"), TEXT_CAPS.summary);
  const area = cleanText(form.get("area"), 60);
  const contact = cleanText(form.get("contact"), TEXT_CAPS.contact);
  if (summary.length < 3) return fail(400, "Please add a short summary — one line is enough.");
  if (!AREAS.includes(area)) return fail(400, "Please choose the area this is about.");
  if (contact && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(contact)) {
    return fail(400, "That email address doesn't look complete — or clear it and send without one.");
  }

  const f = { kind, summary, area, contact };
  if (kind === "bug") {
    f.trying = cleanText(form.get("trying"), TEXT_CAPS.trying);
    f.happened = cleanText(form.get("happened"), TEXT_CAPS.happened);
    f.steps = cleanText(form.get("steps"), TEXT_CAPS.steps);
    f.severity = cleanText(form.get("severity"), 80);
    f.connection = cleanText(form.get("connection"), 80);
    f.ai = cleanText(form.get("ai"), 80);
    if (!f.happened) return fail(400, "Please tell us what happened — even a sentence helps.");
    if (f.severity && !SEVERITIES.includes(f.severity)) f.severity = "";
    if (f.connection && !CONNECTIONS.includes(f.connection)) f.connection = "";
    if (f.ai && !AI_CHOICES.includes(f.ai)) f.ai = "";
  } else {
    f.details = cleanText(form.get("details"), TEXT_CAPS.details);
    if (!f.details) return fail(400, "Please tell us a little more — a sentence or two is plenty.");
  }

  // Attachments: validate everything before anything is stored.
  const files = form.getAll("files").filter((x) => x && typeof x === "object" && "size" in x && x.size > 0);
  if (files.length > MAX_FILES) return fail(400, `Please attach at most ${MAX_FILES} files.`);
  let total = 0;
  const checked = [];
  for (const file of files) {
    total += file.size;
    if (file.size > MAX_FILE_BYTES) return fail(400, "One of the files is over 10 MB. Please remove it and try again.");
    const name = safeName(file.name);
    const ext = extOf(name);
    const buf = new Uint8Array(await file.arrayBuffer());
    if (!magicOk(ext, buf)) {
      return fail(400, `“${name.split("/").pop()}” isn't a file type we can accept. Screenshots, text or log files, PDFs, ZIPs and short videos are welcome.`);
    }
    checked.push({ name, ext, buf });
  }
  if (total > MAX_TOTAL_BYTES) return fail(400, "The files together are over 25 MB. Please remove the largest and try again.");

  const origin = new URL(request.url).origin;
  const stored = [];
  for (const c of checked) {
    const id = `${crypto.randomUUID()}-${Array.from(crypto.getRandomValues(new Uint8Array(8)), (b) => b.toString(16).padStart(2, "0")).join("")}`;
    await env.DG_FILES.put(`f:${id}`, c.buf.buffer, {
      metadata: { name: c.name, mime: FILE_TYPES[c.ext].mime, size: c.buf.length },
    });
    stored.push({ ...c, id, url: `${origin}/files/${id}/${encodeURIComponent(c.name.split("/").pop())}` });
  }

  // Body assembled the way GitHub's own issue forms assemble it:
  // one ### heading per answered field, in order.
  const section = (label, value) => (value ? `### ${label}\n${value}\n` : "");
  let body = "";
  body += section("Area", f.area);
  if (kind === "bug") {
    body += section("What were you trying to do?", f.trying);
    body += section("What happened instead?", f.happened);
    body += section("Steps to make it happen again", f.steps);
    body += section("How much does it affect you?", f.severity);
    body += section("How were the devices connected?", f.connection);
    body += section("Was an AI agent involved?", f.ai);
  } else {
    body += section("Details", f.details);
  }
  if (form.get("include_details") === "yes") {
    const os = cleanText(form.get("detected_os"), 120);
    const browser = cleanText(form.get("detected_browser"), 120);
    const screen = cleanText(form.get("detected_screen"), 60);
    const from = cleanText(form.get("detected_from"), 200);
    const lines = [
      os && `- System: ${os}`,
      browser && `- Browser: ${browser}`,
      screen && `- Screen: ${screen}`,
      from && `- Came from: ${from}`,
    ].filter(Boolean).join("\n");
    body += section("Details from the sender's device", lines);
  }
  if (stored.length) {
    body += "### Attachments\n" + stored.map((s) =>
      `- [${s.name}](${s.url}) (${Math.max(1, Math.round(s.buf.length / 1024))} KB)`).join("\n") + "\n";
  }
  body += section("Contact", f.contact);
  body += "\n---\nSent from the report form on deskguest.app.\n";

  const labels = kind === "bug"
    ? ["type: bug", "source: website", "state: triage"]
    : ["type: feedback", "source: website", "state: triage"];
  const res = await gh(env, `/repos/${REPO}/issues`, {
    method: "POST",
    body: JSON.stringify({ title: f.summary, body, labels }),
  });
  if (!res.ok) {
    return fail(502, "Your report couldn't be filed just now. Nothing was lost — please try again in a moment.");
  }
  const issue = await res.json();
  await boardIssue(env, issue, kind, f.area, f.severity);
  return json(200, { ok: true });
}

async function handleFile(request, env) {
  const m = /^\/files\/([0-9a-f-]{36}-[0-9a-f]{16})(\/.*)?$/.exec(new URL(request.url).pathname);
  if (!m) return new Response("Not found", { status: 404 });
  const got = await env.DG_FILES.getWithMetadata(`f:${m[1]}`, { type: "arrayBuffer" });
  if (!got || !got.value) return new Response("Not found", { status: 404 });
  const meta = got.metadata || {};
  const mime = INLINE_MIMES.has(meta.mime) || meta.mime === "application/pdf" ? meta.mime : "application/octet-stream";
  const name = safeName(meta.name || "file").split("/").pop();
  const headers = {
    "Content-Type": mime,
    "X-Content-Type-Options": "nosniff",
    "Content-Security-Policy": "sandbox",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "private, max-age=3600",
    "Content-Disposition": `${INLINE_MIMES.has(meta.mime) ? "inline" : "attachment"}; filename="${name}"`,
  };
  return new Response(got.value, { headers });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    try {
      if (url.pathname === "/api/health" && request.method === "GET") {
        return json(200, { ok: true, forms: env.FORMS_ENABLED === "1" });
      }
      if (url.pathname === "/api/report") {
        if (request.method !== "POST") return fail(405, "Method not allowed.");
        return await handleReport(request, env);
      }
      if (url.pathname.startsWith("/files/") && request.method === "GET") {
        return await handleFile(request, env);
      }
      return fail(404, "Not found.");
    } catch (_) {
      return fail(500, "Something went wrong on our side. Please try again in a moment.");
    }
  },
};
