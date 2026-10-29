/* =====================================================================
   WorxLead — bendras duomenų sluoksnis (svetainė + /admin)
   Du režimai:
     local     — localStorage (demo, be serverio)
     supabase  — tikra duomenų bazė per REST
   Abiem atvejais įrašų forma ta pati, tad /admin kodas nesikeičia.
   ===================================================================== */
(function () {
  "use strict";
  var C = window.WL_CONFIG || {};
  /* Testai nustato wl_force_local, kad niekada nerašytų į tikrą duomenų bazę.
     Gyvoje svetainėje į tai neatsižvelgiama: kitaip bet kuris lankytojas
     galėtų atsidaryti netikrą skydelį su vieša slaptažodžio fraze. */
  var LOCALHOST = (function () {
    try {
      var h = location.hostname;
      return h === "localhost" || h === "127.0.0.1" || h === "[::1]" ||
             h === "" || /\.local$/.test(h);
    } catch (e) { return false; }
  })();
  var FORCED = false;
  try { FORCED = LOCALHOST && localStorage.getItem("wl_force_local") === "1"; } catch (e) {}
  var MODE = (!FORCED && C.supabaseUrl && C.supabaseKey) ? "supabase" : "local";
  var SB = String(C.supabaseUrl || "").replace(/\/+$/, "");
  var K = {
    req: "wl_db_requests", par: "wl_db_partners", unl: "wl_db_unlocks",
    msg: "wl_db_messages", con: "wl_db_contacts", tpl: "wl_templates", ses: "wl_admin_session"
  };

  /* ---------------- vietinė saugykla ---------------- */
  function lget(k, d) { try { var v = localStorage.getItem(k); return v ? JSON.parse(v) : d; } catch (e) { return d; } }
  function lset(k, v) { try { localStorage.setItem(k, JSON.stringify(v)); return true; } catch (e) { return false; } }
  function uid() {
    if (window.crypto && crypto.randomUUID) return crypto.randomUUID();
    return "id-" + Date.now().toString(36) + "-" + Math.random().toString(36).slice(2, 10);
  }
  function code(prefix) {
    var d = new Date(), p = function (n) { return String(n).padStart(2, "0"); };
    return prefix + "-" + String(d.getFullYear()).slice(2) + p(d.getMonth() + 1) + p(d.getDate()) +
      "-" + Math.random().toString(36).slice(2, 6).toUpperCase();
  }

  /* ---------------- sesija ----------------
     Prisijungimo raktas (access_token) galioja valandą. Anksčiau jam pasibaigus
     skydelis tiesiog nustodavo rodyti duomenis ir išmesdavo „JWT expired".
     Dabar raktas atnaujinamas savaime pagal refresh_token — administratoriui
     nereikia nieko daryti. Jei nepavyksta ir to, sesija švariai uždaroma. */
  function session() { return lget(K.ses, null); }
  function setSession(s) {
    if (!s) { localStorage.removeItem(K.ses); return; }
    /* Supabase grąžina expires_in sekundėmis — pasiverčiam į laiko žymę. */
    if (!s.expires_at_ms) {
      var sek = Number(s.expires_in || 3600);
      s.expires_at_ms = Date.now() + (isFinite(sek) ? sek : 3600) * 1000;
    }
    lset(K.ses, s);
  }

  /* ---------------- dviejų veiksnių prisijungimas (TOTP) ----------------
     Slaptažodžio nebeužtenka: jei administratorius prisiregistravo kodų
     generatorių, duomenis jis pamato tik suvedęs vienkartinį kodą. */
  function authFetch(path, opts) {
    opts = opts || {};
    var s = session();
    return fetch(SB + "/auth/v1" + path, {
      method: opts.method || "GET",
      headers: {
        apikey: C.supabaseKey,
        Authorization: "Bearer " + ((s && s.access_token) || C.supabaseKey),
        "Content-Type": "application/json"
      },
      body: opts.body ? JSON.stringify(opts.body) : undefined
    }).then(function (r) {
      return r.text().then(function (t) {
        var j = t.trim() ? JSON.parse(t) : {};
        if (!r.ok) throw new Error(j.msg || j.error_description || j.message || ("HTTP " + r.status));
        return j;
      });
    });
  }
  /* VISI generatoriai, įskaitant nebaigtus registruoti. */
  function mfaAllFactors() {
    var s = session();
    if (!s || !s.access_token) return Promise.resolve([]);
    if (s.expires_at_ms && s.expires_at_ms < Date.now()) return Promise.resolve([]);
    return authFetch("/user").then(function (u) { return (u && u.factors) || []; })
      .catch(function () { return []; });
  }
  /* Ar šis naudotojas jau turi patvirtintą kodų generatorių? */
  function mfaFactors() {
    /* Be galiojančios sesijos klausti nėra ko — kitaip naršyklė užsirašytų
       bereikalingą 401 klaidą. */
    var s = session();
    if (!s || !s.access_token) return Promise.resolve([]);
    if (s.expires_at_ms && s.expires_at_ms < Date.now()) return Promise.resolve([]);
    return authFetch("/user").then(function (u) {
      return ((u && u.factors) || []).filter(function (f) { return f.status === "verified"; });
    }).catch(function () { return []; });
  }
  function mfaEnroll() {
    /* Nebaigti registruoti generatoriai (žmogus paspaudė „Įjungti“ ir
       nepatvirtino) trukdytų pradėti iš naujo, todėl juos pašalinam.
       Pavadinimas su laiko žyma — kad vardai niekada nesikartotų. */
    return mfaAllFactors().then(function (fs) {
      var nebaigti = fs.filter(function (f) { return f.status !== "verified"; });
      return Promise.all(nebaigti.map(function (f) {
        return mfaRemove(f.id).catch(function () {});
      }));
    }).then(function () {
      return authFetch("/factors", { method: "POST", body: {
        factor_type: "totp",
        friendly_name: "WorxLead " + new Date().toISOString().slice(0, 16).replace("T", " ")
      } });
    });
  }
  function mfaChallenge(factorId) {
    return authFetch("/factors/" + factorId + "/challenge", { method: "POST" });
  }
  function mfaVerify(factorId, challengeId, code) {
    return authFetch("/factors/" + factorId + "/verify", { method: "POST",
      body: { challenge_id: challengeId, code: String(code).replace(/\s/g, "") }
    }).then(function (j) {
      if (j && j.access_token) setSession(j);   /* naujas raktas jau su aal2 */
      return j;
    });
  }
  function mfaRemove(factorId) {
    return authFetch("/factors/" + factorId, { method: "DELETE" });
  }
  /* Koks dabartinis lygis: aal1 (tik slaptažodis) ar aal2 (su kodu). */
  function mfaLevel() {
    var s = session();
    if (!s || !s.access_token) return null;
    try {
      var p = JSON.parse(atob(s.access_token.split(".")[1].replace(/-/g, "+").replace(/_/g, "/")));
      return p.aal || "aal1";
    } catch (e) { return null; }
  }

  var _atnaujinimas = null;          /* kad keli užklausimai nesiųstų kelių atnaujinimų */
  function refreshSession() {
    if (_atnaujinimas) return _atnaujinimas;
    var s = session();
    if (!s || !s.refresh_token) return Promise.resolve(null);
    _atnaujinimas = fetch(SB + "/auth/v1/token?grant_type=refresh_token", {
      method: "POST",
      headers: { apikey: C.supabaseKey, "Content-Type": "application/json" },
      body: JSON.stringify({ refresh_token: s.refresh_token })
    }).then(function (r) { return r.ok ? r.json() : null; })
      .then(function (j) {
        if (j && j.access_token) { setSession(j); return j; }
        setSession(null);            /* nebegalioja ir refresh_token — reikia prisijungti iš naujo */
        return null;
      })
      .catch(function () { return null; })
      .then(function (v) { _atnaujinimas = null; return v; });
    return _atnaujinimas;
  }

  /* Prieš kreipiantis patikrinam, ar raktas dar negreit baigs galioti. */
  function ensureSession() {
    var s = session();
    if (!s || !s.access_token) return Promise.resolve(null);
    if (!s.expires_at_ms || s.expires_at_ms - Date.now() > 60000) return Promise.resolve(s);
    return refreshSession();
  }

  /* ---------------- Supabase REST ---------------- */
  function headers(extra) {
    var s = session(), h = {
      "apikey": C.supabaseKey,
      "Authorization": "Bearer " + ((s && s.access_token) || C.supabaseKey),
      "Content-Type": "application/json"
    };
    if (extra) for (var k in extra) h[k] = extra[k];
    return h;
  }
  function rest(path, opts) {
    opts = opts || {};
    var siusti = function () {
      return fetch(SB + "/rest/v1/" + path, {
        method: opts.method || "GET",
        headers: headers(opts.headers),
        body: opts.body ? JSON.stringify(opts.body) : undefined
      });
    };
    var buvoSesija = !!(session() && session().access_token);
    /* Jei raktas tuoj baigs galioti — atnaujinam dar prieš siunčiant. */
    return ensureSession().then(function (nauja) {
      /* Svarbu: jei sesija buvo, bet atnaujinti nepavyko, NEGALIMA tyliai
         kreiptis viešuoju raktu — tada administratorius pamatytų tuščią
         skydelį ir pagalvotų, kad dingo duomenys. */
      if (buvoSesija && !(nauja && nauja.access_token)) {
        var e = new Error("Sesija baigėsi — prisijunkite iš naujo");
        e.sessionExpired = true;
        throw e;
      }
      return siusti();
    }).then(function (r) {
      if (r.status === 401 && session()) {
        /* Raktas paseno tarp užklausų: atnaujinam ir kartojam vieną kartą. */
        return refreshSession().then(function (nauja) {
          if (!nauja) {
            var e = new Error("Sesija baigėsi — prisijunkite iš naujo");
            e.sessionExpired = true;
            throw e;
          }
          return siusti();
        });
      }
      return r;
    }).then(function (r) {
      if (!r.ok) {
        return r.text().then(function (txt) {
          if (r.status === 401) {
            var e = new Error("Sesija baigėsi — prisijunkite iš naujo");
            e.sessionExpired = true;
            setSession(null);
            throw e;
          }
          throw new Error(r.status + " " + txt.slice(0, 300));
        });
      }
      /* 201/204 su Prefer: return=minimal grąžina tuščią kūną */
      return r.text().then(function (txt) { return txt.trim() ? JSON.parse(txt) : null; });
    });
  }

  /* ---------------- formos vertimas į DB ---------------- */
  function reqToDB(r) {
    return {
      code: r.code, status: "new", category: r.cat, jobs: r.jobs || [], object: r.obj || null,
      extra: r.extra || {}, description: r.desc || "", region: r.region || null, city: r.city || null,
      timing: r.timing || null, budget: r.budget || null, name: r.name, phone: r.phone, email: r.email,
      pref: r.pref || null, best_time: r.when || null, news: !!r.news, lang: r.lang || "lt",
      files: r.files || [],
      max_unlocks: C.maxOffers || 5, unlocks: 0, notes: [], source: "web"
    };
  }
  function parToDB(p) {
    return {
      code: p.code, status: "new", company: p.company, reg_code: p.reg, person: p.person,
      phone: p.phone, email: p.email, web: p.web || null, categories: p.catIds || [],
      regions: p.regIds || [], team: p.team || null, experience: p.exp || null,
      pack: p.pack || null, credits: 0, msg: p.msg || null, promo: p.promo || null, notes: []
    };
  }

  /* =====================================================================
     Viešoji dalis — naudoja svetainė
     ===================================================================== */
  /* Paleidžia automatinius laiškus (Edge Function „notify“).
     Nelaukiame atsakymo — klientas neturi stabčioti dėl pašto. */
  function notify(code) {
    if (!code || MODE !== "supabase") return;
    try {
      fetch(SB + "/functions/v1/notify", {
        method: "POST",
        headers: { apikey: C.supabaseKey, Authorization: "Bearer " + C.supabaseKey, "Content-Type": "application/json" },
        body: JSON.stringify({ code: code })
      }).catch(function () {});
    } catch (e) { /* tyliai — užklausa jau išsaugota */ }
  }
  function submit(table, row) {
    if (MODE === "supabase") {
      /* Būtinai return=minimal: anon neturi SELECT teisės, o „representation“
         priverstų PostgreSQL taikyti SELECT taisyklę RETURNING sakiniui ir
         įrašymas būtų atmestas. Visus duomenis jau turime vietoje. */
      return rest(table, { method: "POST", body: row, headers: { Prefer: "return=minimal" } })
        .then(function () {
          if (table === "requests") notify(row.code);
          return { ok: true, row: row };
        })
        .catch(function (e) { localAdd(table, row); return { ok: false, error: String(e.message || e), row: row }; });
    }
    if (C.endpoint) {
      return fetch(C.endpoint, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(row) })
        .then(function (r) { localAdd(table, row); return { ok: r.ok, row: row }; })
        .catch(function (e) { localAdd(table, row); return { ok: false, error: String(e), row: row }; });
    }
    localAdd(table, row);
    return Promise.resolve({ ok: false, local: true, row: row });
  }
  function localAdd(table, row) {
    var key = { requests: K.req, partners: K.par, contact_messages: K.con }[table];
    if (!key) return;
    var list = lget(key, []);
    list.unshift(Object.assign({ id: uid(), created_at: new Date().toISOString(), updated_at: new Date().toISOString() }, row));
    lset(key, list.slice(0, 500));
  }

  /* =====================================================================
     Administravimas
     ===================================================================== */
  function signIn(email, password) {
    if (MODE !== "supabase") {
      if (String(password) === String(C.adminPin || "worxlead")) {
        setSession({ demo: true, email: email || "demo", at: Date.now() });
        return Promise.resolve({ ok: true, demo: true });
      }
      return Promise.resolve({ ok: false, error: "Neteisingas slaptažodis" });
    }
    return fetch(SB + "/auth/v1/token?grant_type=password", {
      method: "POST", headers: { apikey: C.supabaseKey, "Content-Type": "application/json" },
      body: JSON.stringify({ email: email, password: password })
    }).then(function (r) { return r.json().then(function (j) { return { r: r, j: j }; }); })
      .then(function (x) {
        if (!x.r.ok) return { ok: false, error: x.j.error_description || x.j.msg || "Prisijungti nepavyko" };
        setSession(x.j);
        return rest("wl_admins?select=user_id&limit=1").then(function (rows) {
          if (!rows || !rows.length) { setSession(null); return { ok: false, error: "Šis vartotojas nėra administratorius. Paleiskite: select wl_make_admin('" + email + "');" }; }
          return { ok: true, email: email };
        }).catch(function (e) { setSession(null); return { ok: false, error: String(e.message || e) }; });
      }).catch(function (e) { return { ok: false, error: String(e) }; });
  }
  /* Išsiunčia slaptažodžio atstatymo laišką. redirect_to turi būti
     leidžiamų adresų sąraše (supabase/config.toml -> additional_redirect_urls),
     kitaip Supabase nukreipia į site_url. */
  function sendRecovery(email) {
    if (MODE !== "supabase") return Promise.resolve({ ok: false, error: "Demo režimu laiškai nesiunčiami" });
    var back = location.origin + location.pathname;
    return fetch(SB + "/auth/v1/recover?redirect_to=" + encodeURIComponent(back), {
      method: "POST",
      headers: { apikey: C.supabaseKey, "Content-Type": "application/json" },
      body: JSON.stringify({ email: email })
    }).then(function (r) {
      if (r.ok) return { ok: true };
      return r.json().catch(function () { return {}; }).then(function (j) {
        return { ok: false, error: j.msg || j.error_description || ("Klaida " + r.status) };
      });
    }).catch(function (e) { return { ok: false, error: String(e) }; });
  }
  /* Nustato naują slaptažodį naudojant iš laiško gautą žymą. */
  function setPassword(accessToken, password) {
    return fetch(SB + "/auth/v1/user", {
      method: "PUT",
      headers: { apikey: C.supabaseKey, Authorization: "Bearer " + accessToken, "Content-Type": "application/json" },
      body: JSON.stringify({ password: password })
    }).then(function (r) {
      if (r.ok) return { ok: true };
      return r.json().catch(function () { return {}; }).then(function (j) {
        return { ok: false, error: j.msg || j.error_description || ("Klaida " + r.status) };
      });
    }).catch(function (e) { return { ok: false, error: String(e) }; });
  }
  /* ---------------- redaguojami svetainės tekstai ----------------
     Svetainė juos užsikrauna paleisdama; nepavykus lieka numatytieji,
     todėl puslapis niekada nesugenda dėl ryšio problemų. */
  var CONTENT = {};
  var K_CONTENT = "wl_content_cache";
  function contentLoad(timeoutMs) {
    try { CONTENT = lget(K_CONTENT, {}) || {}; } catch (e) { CONTENT = {}; }
    if (MODE !== "supabase") return Promise.resolve(CONTENT);
    return new Promise(function (res) {
      var done = false;
      var finish = function () { if (!done) { done = true; res(CONTENT); } };
      setTimeout(finish, timeoutMs || 2500);
      fetch(SB + "/rest/v1/site_content?select=key,lt,en", {
        headers: { apikey: C.supabaseKey, Authorization: "Bearer " + C.supabaseKey }
      }).then(function (r) { return r.ok ? r.json() : []; })
        .then(function (rows) {
          var map = {};
          (rows || []).forEach(function (r) { map[r.key] = { lt: r.lt, en: r.en }; });
          CONTENT = map;
          lset(K_CONTENT, map);
          finish();
        }).catch(finish);
    });
  }
  /* Grąžina pakeistą tekstą arba numatytąjį. */
  function txt(key, defLt, defEn) {
    var o = CONTENT[key], lang = (window.WL_LANG || "lt");
    var v = o ? (lang === "en" ? o.en : o.lt) : null;
    if (v != null && String(v).trim() !== "") return v;
    return lang === "en" && defEn != null ? defEn : defLt;
  }
  function contentAll() { return CONTENT; }
  function contentSave(key, lt, en) {
    /* Demo režimu (be Supabase) tekstai ir spalvos saugomi tik šiame
       įrenginyje — kitaip redaktorius be duomenų bazės apskritai neveiktų. */
    if (MODE !== "supabase") {
      CONTENT[key] = { lt: lt, en: en }; lset(K_CONTENT, CONTENT);
      return Promise.resolve({ ok: true, local: true });
    }
    return rest("site_content", {
      method: "POST", body: { key: key, lt: lt, en: en, updated_at: new Date().toISOString() },
      headers: { Prefer: "resolution=merge-duplicates,return=minimal" }
    }).then(function () {
      CONTENT[key] = { lt: lt, en: en }; lset(K_CONTENT, CONTENT); return { ok: true };
    }).catch(function (e) { return { ok: false, error: String(e.message || e) }; });
  }
  function contentReset(key) {
    if (MODE !== "supabase") {
      delete CONTENT[key]; lset(K_CONTENT, CONTENT);
      return Promise.resolve({ ok: true, local: true });
    }
    return rest("site_content?key=eq." + encodeURIComponent(key), { method: "DELETE" })
      .then(function () { delete CONTENT[key]; lset(K_CONTENT, CONTENT); return { ok: true }; })
      .catch(function (e) { return { ok: false, error: String(e.message || e) }; });
  }
  function signOut() {
    if (MODE === "supabase" && session() && session().access_token) {
      fetch(SB + "/auth/v1/logout", { method: "POST", headers: headers() }).catch(function () {});
    }
    setSession(null);
  }

  function list(table, opts) {
    opts = opts || {};
    if (MODE === "supabase") {
      var q = "select=*&order=created_at.desc&limit=" + (opts.limit || 500);
      return rest(table + "?" + q);
    }
    var key = { requests: K.req, partners: K.par, unlocks: K.unl, messages: K.msg, contact_messages: K.con }[table];
    return Promise.resolve(lget(key, []));
  }
  function update(table, id, patch) {
    patch = Object.assign({}, patch, { updated_at: new Date().toISOString() });
    if (MODE === "supabase") {
      var p = Object.assign({}, patch); delete p.updated_at;
      if (table === "requests" || table === "partners") p.updated_at = patch.updated_at;
      return rest(table + "?id=eq." + encodeURIComponent(id), {
        method: "PATCH", body: p, headers: { Prefer: "return=representation" }
      }).then(function (r) { return (r && r[0]) || null; });
    }
    var key = { requests: K.req, partners: K.par, unlocks: K.unl, contact_messages: K.con }[table];
    var rows = lget(key, []), hit = null;
    rows = rows.map(function (r) { if (r.id === id) { hit = Object.assign(r, patch); } return r; });
    lset(key, rows);
    return Promise.resolve(hit);
  }
  function remove(table, id) {
    if (MODE === "supabase") return rest(table + "?id=eq." + encodeURIComponent(id), { method: "DELETE" });
    var key = { requests: K.req, partners: K.par, unlocks: K.unl, contact_messages: K.con }[table];
    lset(key, lget(key, []).filter(function (r) { return r.id !== id; }));
    return Promise.resolve(null);
  }
  function insert(table, row) {
    row = Object.assign({ id: uid(), created_at: new Date().toISOString() }, row);
    if (MODE === "supabase") {
      var body = Object.assign({}, row); delete body.id;
      return rest(table, { method: "POST", body: body, headers: { Prefer: "return=representation" } })
        .then(function (r) { return (r && r[0]) || row; });
    }
    var key = { requests: K.req, partners: K.par, unlocks: K.unl, messages: K.msg, contact_messages: K.con }[table];
    var list2 = lget(key, []); list2.unshift(row); lset(key, list2.slice(0, 1000));
    return Promise.resolve(row);
  }

  /* užrašai (istorija įraše) */
  function addNote(table, row, text) {
    var notes = (row.notes || []).slice();
    notes.unshift({ at: new Date().toISOString(), text: text });
    return update(table, row.id, { notes: notes });
  }

  /* atrakinimas: partneris nusiperka užklausą */
  function addUnlock(request, partner, price) {
    return insert("unlocks", { request_id: request.id, partner_id: partner.id, price: price, refunded: false })
      .then(function (u) {
        var jobs = [];
        if (partner.credits > 0) jobs.push(update("partners", partner.id, { credits: partner.credits - 1 }));
        if (MODE !== "supabase") {
          jobs.push(update("requests", request.id, {
            unlocks: (request.unlocks || 0) + 1,
            status: request.status === "new" || request.status === "review" ? "published" : request.status
          }));
        } else if (request.status === "new" || request.status === "review") {
          jobs.push(update("requests", request.id, { status: "published" }));
        }
        return Promise.all(jobs).then(function () { return u; });
      });
  }
  function refundUnlock(u, partner) {
    var jobs = [update("unlocks", u.id, { refunded: true })];
    if (partner) jobs.push(update("partners", partner.id, { credits: (partner.credits || 0) + 1 }));
    if (MODE !== "supabase") {
      jobs.push(list("requests").then(function (rs) {
        var r = rs.find(function (x) { return x.id === u.request_id; });
        if (r) return update("requests", r.id, { unlocks: Math.max(0, (r.unlocks || 0) - 1) });
      }));
    }
    return Promise.all(jobs);
  }

  /* ---------------- rangovų parinkimas užklausai ---------------- */
  function matchPartners(request, partners) {
    return (partners || []).filter(function (p) {
      if (p.status !== "verified") return false;
      var cats = p.categories || [], regs = p.regions || [];
      return cats.indexOf(request.category) >= 0 && (regs.indexOf(request.region) >= 0 || regs.indexOf("visa") >= 0);
    });
  }

  /* ---------------- laiškų šablonai ---------------- */
  var DEFAULT_TPL = {
    client_confirm: {
      name: "Klientui — užklausa gauta",
      subject: "Jūsų užklausa {{kodas}} priimta | WorxLead",
      body: "Sveiki, {{vardas}},\n\ngavome Jūsų užklausą {{kodas}} ({{kategorija}}, {{vieta}}).\n\nKą darome toliau: užklausą jau matys mūsų patikrinti to regiono rangovai. Su Jumis susisieks iki {{maxrangovu}} jų — dažniausiai per {{valandu}} val. Kontaktų viešai nerodome: juos mato tik tie rangovai, kurie už užklausą sumoka.\n\nJei kas nors pasikeitė arba darbas nebeaktualus — atrašykite į šį laišką su kodu {{kodas}} ir užklausą uždarysime.\n\nGeros dienos,\nWorxLead\n{{telefonas}} | {{elpastas}}"
    },
    client_followup: {
      name: "Klientui — ar susisiekė rangovai?",
      subject: "Ar sulaukėte pasiūlymų? ({{kodas}})",
      body: "Sveiki, {{vardas}},\n\ntikriname, kaip sekasi su užklausa {{kodas}} ({{kategorija}}).\n\nAr su Jumis jau susisiekė rangovai? Jei ne arba pasiūlymai netiko — parašykite, peržiūrėsime užklausą ir pasiūlysime kitų partnerių.\n\nPagarbiai,\nWorxLead\n{{telefonas}}"
    },
    lead_blast: {
      name: "Rangovams — nauja užklausa",
      subject: "Nauja užklausa: {{kategorija}}, {{vieta}} ({{kodas}})",
      body: "Sveiki,\n\nnauja užklausa pagal Jūsų profilį:\n\nKategorija: {{kategorija}}\nDarbai: {{darbai}}\nVieta: {{vieta}}\nObjektas: {{objektas}}\nTerminas: {{terminas}}\nBiudžetas: {{biudzetas}}\nPriedai: {{priedai}}\n\nAprašymas:\n{{aprasymas}}\n\nUžklausos kodas: {{kodas}}\nAtrakinimo kaina: {{kaina}} €. Vieną užklausą gali atrakinti ne daugiau kaip {{maxrangovu}} rangovai, šiuo metu atrakinta: {{atrakinta}}.\n\nNorite kontaktų? Atsakykite į šį laišką su kodu {{kodas}} — atsiųsime kliento duomenis ir sąskaitą.\n\nWorxLead\n{{telefonas}} | {{elpastas}}"
    },
    lead_contacts: {
      name: "Rangovui — kontaktai po atrakinimo",
      subject: "Kontaktai užklausai {{kodas}}",
      body: "Sveiki, {{asmuo}},\n\nužklausa {{kodas}} atrakinta. Kliento duomenys:\n\nVardas: {{vardas}}\nTelefonas: {{telefonas_kliento}}\nEl. paštas: {{elpastas_kliento}}\nPatogiausia susisiekti: {{budas}} {{laikas}}\n\nPrašome susisiekti per 24 val. — greičiausiai atsakantys partneriai laimi dažniausiai. Jei klientas neatsilieps nei telefonu, nei el. paštu per {{grazinimas}} darbo dienas, parašykite mums ir grąžinsime kreditą.\n\nSėkmės,\nWorxLead"
    },
    partner_approve: {
      name: "Rangovui — anketa patvirtinta",
      subject: "Sveiki prisijungę prie WorxLead, {{imone}}",
      body: "Sveiki, {{asmuo}},\n\npatikrinome {{imone}} duomenis — anketa patvirtinta. Nuo šiol siųsime pranešimus apie užklausas šiose srityse:\n{{kategorijos}}\nRegionai: {{regionai}}\n\nKainos: 1 užklausa — 20 €, 3 už 50 €, 5 už 80 €. Kreditai negalioja terminuotai, abonentinio mokesčio nėra.\n\nJei norite pakeisti kategorijas ar regionus — tiesiog atrašykite.\n\nWorxLead\n{{telefonas}} | {{elpastas}}"
    },
    partner_reject: {
      name: "Rangovui — anketa atmesta",
      subject: "Dėl {{imone}} anketos",
      body: "Sveiki, {{asmuo}},\n\ndėkojame už anketą. Šiuo metu negalime jos patvirtinti: {{priezastis}}\n\nJei situacija pasikeis — parašykite, mielai peržiūrėsime iš naujo.\n\nWorxLead\n{{elpastas}}"
    }
  };
  function templates() { return Object.assign({}, DEFAULT_TPL, lget(K.tpl, {})); }
  function saveTemplate(id, tpl) { var all = lget(K.tpl, {}); all[id] = tpl; lset(K.tpl, all); }
  function resetTemplates() { localStorage.removeItem(K.tpl); }
  function fill(str, vars) {
    return String(str || "").replace(/\{\{(\w+)\}\}/g, function (m, k) {
      return vars[k] != null && vars[k] !== "" ? vars[k] : "—";
    });
  }

  /* ---------------- demo duomenys ---------------- */
  function seedDemo(CATS, REGIONS) {
    var now = Date.now(), day = 86400000;
    var reqs = [
      ["plyteles", ["Vonios kambario plytelės"], "butas", { plotas: "28", formatas: "60×120 cm" }, "vilnius", "Antakalnis",
        "asap", "b2", "Rasa", "+37060011122", "rasa@pavyzdys.lt",
        "Vonios kambarys 6 m², reikia nuimti senas plyteles, padaryti hidroizoliaciją ir pakloti naujas 60×120. Plyteles jau turiu.", 0.2, "new"],
      ["baldai", ["Virtuvės baldai pagal matmenis"], "naujas", { ilgis: "4.2", tipas: "Virtuvė", fasadai: "Dažytas MDF" }, "kaunas", "Žaliakalnis",
        "1men", "b3", "Tomas", "+37061122233", "tomas@pavyzdys.lt",
        "Naujos statybos butas, virtuvė 4,2 m su sala. Norėčiau dažytų MDF fasadų, technika jau nupirkta.", 1.4, "published"],
      ["energija", ["Saulės elektrinė ant stogo"], "namas", { galia: "10", vieta: "Ant namo stogo" }, "klaipeda", "Gargždai",
        "3men", "b4", "Gintaras", "+37069988877", "gintaras@pavyzdys.lt",
        "Namas 180 m², metinis suvartojimas ~7000 kWh. Domina 10 kW elektrinė su kaupikliu ir ES parama.", 2.6, "published"],
      ["santechnika", ["Vamzdynų keitimas bute"], "butas", { taskai: "6", tipas: "Keitimas / renovacija" }, "vilnius", "Naujamiestis",
        "asap", "b2", "Agnė", "+37067744455", "agne@pavyzdys.lt",
        "Senos statybos bute reikia pakeisti visus vandentiekio ir nuotekų vamzdžius, 6 taškai.", 3.1, "won"],
      ["apdaila", ["Sienų glaistymas ir dažymas"], "komercija", { plotas: "140", apimtis: "Komercinės patalpos" }, "siauliai", "Centras",
        "1men", "b3", "Mindaugas", "+37062233344", "mindaugas@pavyzdys.lt",
        "Biuro patalpos 140 m², reikia glaistyti ir dažyti sienas bei lubas po nuomininkų.", 5.5, "closed"]
    ].map(function (r) {
      return {
        id: uid(), code: code("WL"), created_at: new Date(now - r[12] * day).toISOString(),
        updated_at: new Date(now - r[12] * day).toISOString(), status: r[13], category: r[0], jobs: r[1],
        object: r[2], extra: r[3], description: r[11], region: r[4], city: r[5], timing: r[6], budget: r[7],
        name: r[8], phone: r[9], email: r[10], pref: "phone", best_time: "", news: false, lang: "lt",
        unlocks: 0, max_unlocks: 5, notes: [], source: "demo", demo: true
      };
    });
    var pars = [
      ["UAB Plytelių meistrai", "302011223", "Darius", "+37061000111", "info@plyteles.pavyzdys.lt", ["plyteles", "apdaila"], ["vilnius", "kaunas"], "verified", 4],
      ["MB Baldų studija", "304556677", "Eglė", "+37062000222", "info@baldai.pavyzdys.lt", ["baldai", "akmuo"], ["kaunas", "vilnius"], "verified", 2],
      ["UAB Saulės energija LT", "305667788", "Rokas", "+37063000333", "info@saule.pavyzdys.lt", ["energija", "svok"], ["klaipeda", "telsiai"], "verified", 5],
      ["Santechnikos sprendimai", "309887766", "Vytas", "+37064000444", "vytas@santechnika.pavyzdys.lt", ["santechnika", "svok"], ["vilnius"], "verified", 0],
      ["MB Naujokas", "306112233", "Karolis", "+37065000555", "karolis@naujokas.pavyzdys.lt", ["apdaila", "grindys"], ["siauliai", "panevezys"], "new", 0]
    ].map(function (p, i) {
      return {
        id: uid(), code: code("WLP"), created_at: new Date(now - (i + 2) * day).toISOString(),
        updated_at: new Date(now - (i + 2) * day).toISOString(), status: p[7], company: p[0], reg_code: p[1],
        person: p[2], phone: p[3], email: p[4], web: "", categories: p[5], regions: p[6],
        team: "2-5", experience: "5-10", pack: "3 x 50 EUR", credits: p[8], msg: "", notes: [], demo: true
      };
    });
    var unl = [];
    [[1, 0, 20], [1, 1, 20], [2, 2, 16], [3, 3, 20], [3, 0, 16]].forEach(function (x) {
      unl.push({ id: uid(), created_at: new Date(now - 1.5 * day).toISOString(), request_id: reqs[x[0]].id, partner_id: pars[x[1]].id, price: x[2], refunded: false, demo: true });
    });
    reqs.forEach(function (r) { r.unlocks = unl.filter(function (u) { return u.request_id === r.id; }).length; });
    lset(K.req, reqs.concat(lget(K.req, []).filter(function (r) { return !r.demo; })));
    lset(K.par, pars.concat(lget(K.par, []).filter(function (p) { return !p.demo; })));
    lset(K.unl, unl.concat(lget(K.unl, []).filter(function (u) { return !u.demo; })));
    return { requests: reqs.length, partners: pars.length, unlocks: unl.length };
  }
  function clearDemo() {
    [K.req, K.par, K.unl].forEach(function (k) {
      lset(k, lget(k, []).filter(function (r) { return !r.demo; }));
    });
  }
  function hasDemo() { return lget(K.req, []).some(function (r) { return r.demo; }); }


  /* ---------------- bendras žodynas (id -> pavadinimas) ----------------
     Turi sutapti su CATS/REGIONS index.html faile — tikrinama test.html. */
  var TAX = {
    cats: [
      { id: "architektai", lt: "Architektai ir dizaineriai", en: "Architects & designers", lead: 25 },
      { id: "santechnika", lt: "Santechnika", en: "Plumbing", lead: 20 },
      { id: "elektra", lt: "Elektros darbai", en: "Electrical work", lead: 20 },
      { id: "plyteles", lt: "Plytelės ir jų meistrai", en: "Tiling", lead: 20 },
      { id: "svok", lt: "ŠVOK sprendimai", en: "HVAC solutions", lead: 25 },
      { id: "grindys", lt: "Grindys ir jų meistrai", en: "Flooring", lead: 20 },
      { id: "baldai", lt: "Baldų gamyba", en: "Furniture manufacturing", lead: 25 },
      { id: "apdaila", lt: "Vidaus apdaila", en: "Interior finishing", lead: 20 },
      { id: "technika", lt: "Buitinė įranga", en: "Home appliances", lead: 20 },
      { id: "minksti", lt: "Minkšti baldai", en: "Upholstered furniture", lead: 20 },
      { id: "energija", lt: "Atsinaujinanti energija", en: "Renewable energy", lead: 30 },
      { id: "akmuo", lt: "Akmens gaminiai", en: "Stone products", lead: 25 },
      { id: "prieziura", lt: "Statybos vadovai ir techninė priežiūra", en: "Site managers & technical supervision", lead: 25 }
    ],
    regions: [
      { id: "vilnius", lt: "Vilnius ir rajonas" }, { id: "kaunas", lt: "Kaunas ir rajonas" },
      { id: "klaipeda", lt: "Klaipėda ir pajūris" }, { id: "siauliai", lt: "Šiauliai" },
      { id: "panevezys", lt: "Panevėžys" }, { id: "alytus", lt: "Alytus / Dzūkija" },
      { id: "marijampole", lt: "Marijampolė / Suvalkija" }, { id: "utena", lt: "Utena / Aukštaitija" },
      { id: "telsiai", lt: "Telšiai / Žemaitija" }, { id: "kita", lt: "Kita vieta Lietuvoje" },
      { id: "visa", lt: "Visa Lietuva" }
    ],
    fields: {
      plotas: "Plotas", ilgis: "Ilgis / plotis", taskai: "Taškų skaičius", galia: "Galia",
      etapas: "Reikalingas etapas", tipas: "Darbų pobūdis", formatas: "Plytelių formatas",
      medziagos: "Medžiagos", sistema: "Sistema", danga: "Danga", fasadai: "Fasadų tipas",
      apimtis: "Apimtis", prietaisai: "Prietaisai", vieta: "Įrengimo vieta", medziaga: "Medžiaga",
      specialistas: "Reikalingas specialistas", kategorija: "Statinio kategorija"
    },
    objects: { butas: "Butas", namas: "Privatus namas", naujas: "Naujos statybos objektas", komercija: "Komercinės patalpos", kita: "Kita" },
    timing: { asap: "Kuo greičiau", "1men": "Per mėnesį", "3men": "Per 1–3 mėnesius", planuoju: "Tik planuoja" },
    budget: { b1: "iki 1 000 €", b2: "1 000 – 5 000 €", b3: "5 000 – 15 000 €", b4: "15 000 – 50 000 €", b5: "50 000 € ir daugiau", b0: "Dar nežino" },
    pref: { phone: "Skambutis", sms: "SMS / Messenger", email: "El. paštas" },
    reqStatus: [
      { id: "new", n: "Nauja", c: "warn" },
      { id: "review", n: "Tikrinama", c: "info" },
      { id: "published", n: "Išsiųsta rangovams", c: "brand" },
      { id: "won", n: "Darbai prasidėjo", c: "ok" },
      { id: "closed", n: "Uždaryta", c: "mute" },
      { id: "spam", n: "Atmesta / šlamštas", c: "err" }
    ],
    parStatus: [
      { id: "lead", n: "Registracija (akcija)", c: "brand" },
      { id: "new", n: "Nauja anketa", c: "warn" },
      { id: "verified", n: "Patvirtintas", c: "ok" },
      { id: "paused", n: "Pristabdytas", c: "mute" },
      { id: "rejected", n: "Atmestas", c: "err" }
    ]
  };
  function fieldName(k) { return TAX.fields[k] || k; }
  function catName(id) { var c = TAX.cats.find(function (x) { return x.id === id; }); return c ? c.lt : id || "—"; }
  function regName(id) { var r = TAX.regions.find(function (x) { return x.id === id; }); return r ? r.lt : id || "—"; }
  function leadPrice(id) { var c = TAX.cats.find(function (x) { return x.id === id; }); return c ? c.lead : 20; }


  /* =====================================================================
     Priedai: nuotraukos, brėžiniai, PDF
     Vietinis režimas — IndexedDB (localStorage per mažas nuotraukoms).
     Supabase — privatus Storage segmentas, skaitomas tik administratoriaus.
     ===================================================================== */
  var FILE_MAX = 15 * 1024 * 1024, FILES_MAX = 8, TOTAL_MAX = 40 * 1024 * 1024;
  var BUCKET = "request-files";
  var ACCEPT = "image/*,.pdf,.dwg,.dxf,.heic,.zip,.doc,.docx,.xls,.xlsx";
  function fmtSize(n) {
    if (n < 1024) return n + " B";
    if (n < 1048576) return Math.round(n / 1024) + " KB";
    return (n / 1048576).toFixed(1).replace(".", ",") + " MB";
  }
  function isImage(t) { return /^image\/(jpeg|png|webp|gif)$/.test(t || ""); }

  /* Telefono nuotraukos būna 4–8 MB — sumažiname prieš siunčiant. */
  function shrink(file, maxPx, quality) {
    if (!isImage(file.type) || file.size < 400 * 1024) return Promise.resolve(file);
    return new Promise(function (res) {
      var url = URL.createObjectURL(file), img = new Image();
      img.onload = function () {
        var w = img.naturalWidth, h = img.naturalHeight, k = Math.min(1, maxPx / Math.max(w, h));
        if (k >= 1 && file.size < 1200 * 1024) { URL.revokeObjectURL(url); return res(file); }
        var c = document.createElement("canvas");
        c.width = Math.round(w * k); c.height = Math.round(h * k);
        c.getContext("2d").drawImage(img, 0, 0, c.width, c.height);
        c.toBlob(function (b) {
          URL.revokeObjectURL(url);
          if (!b || b.size >= file.size) return res(file);
          res(new File([b], file.name.replace(/\.(png|webp|gif)$/i, ".jpg"), { type: "image/jpeg" }));
        }, "image/jpeg", quality || 0.82);
      };
      img.onerror = function () { URL.revokeObjectURL(url); res(file); };
      img.src = url;
    });
  }

  /* ---- IndexedDB ---- */
  var IDB_NAME = "wl_files", IDB_STORE = "files";
  var _db = null;
  function idb() {
    if (_db) return Promise.resolve(_db);
    return new Promise(function (res, rej) {
      if (!window.indexedDB) return rej(new Error("IndexedDB nepasiekiama"));
      var r = indexedDB.open(IDB_NAME, 1);
      r.onupgradeneeded = function (e) {
        var db = e.target.result;
        if (!db.objectStoreNames.contains(IDB_STORE)) {
          var os = db.createObjectStore(IDB_STORE, { keyPath: "id" });
          os.createIndex("code", "code", { unique: false });
        }
      };
      r.onsuccess = function (e) {
        _db = e.target.result;
        /* Kitas skirtukas gali prašyti naujesnės versijos — tada ryšį privalom
           atlaisvinti, kitaip ten viskas pakibtų. */
        _db.onversionchange = function () { try { _db.close(); } catch (er) {} _db = null; };
        _db.onclose = function () { _db = null; };
        res(_db);
      };
      r.onerror = function () { rej(r.error || new Error("IndexedDB klaida")); };
      /* BŪTINA: kai bazė užimta, naršyklė iškviečia tik „blocked“ — nei
         onsuccess, nei onerror. Be šitos eilutės pažadas niekada neišsisprendžia
         ir priedų peržiūra tyliai pakimba ties „Atidaroma…“. */
      r.onblocked = function () { rej(new Error("Failų saugykla užimta kito lango")); };
    });
  }
  function idbTx(mode, fn) {
    return idb().then(function (db) {
      return new Promise(function (res, rej) {
        var tx;
        try { tx = db.transaction(IDB_STORE, mode); }
        catch (e) { _db = null; return rej(e); }   /* ryšys užsivėrė — atstatom */
        var st = tx.objectStore(IDB_STORE), out = fn(st);
        tx.oncomplete = function () { res(out && out.__v !== undefined ? out.__v : out); };
        tx.onerror = function () { rej(tx.error || new Error("Failų saugyklos klaida")); };
        /* Nutraukta operacija nesukelia nei oncomplete, nei onerror. */
        tx.onabort = function () { rej(tx.error || new Error("Failų operacija nutraukta")); };
      });
    });
  }
  /* Kad naudotojas niekada nelauktų be galo: po nustatyto laiko pažadas
     baigiamas klaida ir sąsaja gali parodyti pranešimą. */
  function suRiba(p, ms, kas) {
    return new Promise(function (res, rej) {
      var baigta = false;
      var t = setTimeout(function () {
        if (!baigta) { baigta = true; rej(new Error((kas || "Operacija") + " užtruko per ilgai")); }
      }, ms || 20000);
      p.then(function (v) { if (!baigta) { baigta = true; clearTimeout(t); res(v); } },
             function (e) { if (!baigta) { baigta = true; clearTimeout(t); rej(e); } });
    });
  }
  function filePut(rec) { return idbTx("readwrite", function (st) { st.put(rec); return rec; }); }
  function fileDel(id) { return idbTx("readwrite", function (st) { st.delete(id); }); }
  function filesByCode(code) {
    return idbTx("readonly", function (st) {
      var box = { __v: [] };
      st.index("code").openCursor(IDBKeyRange.only(code)).onsuccess = function (e) {
        var c = e.target.result;
        if (c) { box.__v.push(c.value); c.continue(); }
      };
      return box;
    }).then(function (rows) {
      /* Žymeklis eina pagal id (atsitiktinį), todėl rikiuojam pagal tą tvarką,
         kuria žmogus failus pasirinko. */
      return rows.sort(function (a, b) {
        return (a.ord != null ? a.ord : 1e9) - (b.ord != null ? b.ord : 1e9) ||
               (a.at || 0) - (b.at || 0) ||
               String(a.name || "").localeCompare(String(b.name || ""));
      });
    });
  }
  function filesMove(from, to) {
    return filesByCode(from).then(function (rows) {
      return Promise.all(rows.map(function (r) { r.code = to; return filePut(r); }));
    });
  }
  function filesClear(code) {
    return filesByCode(code).then(function (rows) { return Promise.all(rows.map(function (r) { return fileDel(r.id); })); });
  }
  /* Nuoroda peržiūrai: vietinis — blob, Supabase — laikina pasirašyta nuoroda. */
  function fileURL(meta) {
    if (meta.path && MODE === "supabase") {
      return fetch(SB + "/storage/v1/object/sign/" + BUCKET + "/" + meta.path, {
        method: "POST", headers: headers(), body: JSON.stringify({ expiresIn: 3600 })
      }).then(function (r) { return r.json(); })
        .then(function (j) { return j.signedURL ? SB + "/storage/v1" + j.signedURL : null; });
    }
    return suRiba(idbTx("readonly", function (st) {
      var box = { __v: null };
      st.get(meta.id).onsuccess = function (e) { box.__v = e.target.result || null; };
      return box;
    }), 15000, "Failo atidarymas")
      .then(function (rec) { return rec && rec.blob ? URL.createObjectURL(rec.blob) : null; });
  }
  /* Įkėlimas pateikiant užklausą: paima juodraščio failus iš IndexedDB
     ir grąžina metaduomenis, kurie įrašomi į užklausos eilutę. */
  function uploadFiles(code, onProgress) {
    return filesByCode("draft").then(function (rows) {
      if (!rows.length) return [];
      /* filesByCode jau grąžina teisinga tvarka — papildomai rikiuoti nereikia. */
      var done = 0;
      var step = function () { done++; if (onProgress) onProgress(done, rows.length); };
      if (MODE !== "supabase") {
        return filesMove("draft", code).then(function () {
          rows.forEach(step);
          return rows.map(function (r) { return { id: r.id, name: r.name, size: r.size, type: r.type, local: true }; });
        });
      }
      return Promise.all(rows.map(function (r, i) {
        var safe = String(r.name).replace(/[^\w.\-]+/g, "_").slice(-80);
        var path = code + "/" + (i + 1) + "-" + safe;
        return fetch(SB + "/storage/v1/object/" + BUCKET + "/" + encodeURI(path), {
          method: "POST",
          headers: { apikey: C.supabaseKey, Authorization: "Bearer " + C.supabaseKey,
                     "Content-Type": r.type || "application/octet-stream" },
          body: r.blob
        }).then(function (res) {
          step();
          if (!res.ok) throw new Error("upload " + res.status);
          return { name: r.name, size: r.size, type: r.type, path: path };
        });
      })).then(function (metas) {
        filesClear("draft");
        return metas;
      }).catch(function (e) {
        console.warn("Nepavyko įkelti priedų:", e.message);
        return filesMove("draft", code).then(function () {
          return rows.map(function (r) { return { id: r.id, name: r.name, size: r.size, type: r.type, local: true, failed: true }; });
        });
      });
    }).catch(function () { return []; });
  }

  window.WLData = {
    MODE: MODE, CONFIG: C, KEYS: K,
    uid: uid, code: code, lget: lget, lset: lset,
    reqToDB: reqToDB, parToDB: parToDB, submit: submit, notify: notify,
    signIn: signIn, signOut: signOut, session: session, refreshSession: refreshSession,
    mfaFactors: mfaFactors, mfaAllFactors: mfaAllFactors, mfaEnroll: mfaEnroll, mfaChallenge: mfaChallenge,
    mfaVerify: mfaVerify, mfaRemove: mfaRemove, mfaLevel: mfaLevel,
    sendRecovery: sendRecovery, setPassword: setPassword,
    contentLoad: contentLoad, contentAll: contentAll, contentSave: contentSave, contentReset: contentReset, txt: txt,
    list: list, insert: insert, update: update, remove: remove, addNote: addNote,
    addUnlock: addUnlock, refundUnlock: refundUnlock, matchPartners: matchPartners,
    templates: templates, saveTemplate: saveTemplate, resetTemplates: resetTemplates, fill: fill,
    DEFAULT_TPL: DEFAULT_TPL, seedDemo: seedDemo, clearDemo: clearDemo, hasDemo: hasDemo,
    TAX: TAX, catName: catName, regName: regName, leadPrice: leadPrice, fieldName: fieldName,
    FILE_MAX: FILE_MAX, FILES_MAX: FILES_MAX, TOTAL_MAX: TOTAL_MAX, ACCEPT: ACCEPT, BUCKET: BUCKET,
    fmtSize: fmtSize, isImage: isImage, shrink: shrink, uploadFiles: uploadFiles, fileURL: fileURL,
    filePut: filePut, fileDel: fileDel, filesByCode: filesByCode, filesMove: filesMove, filesClear: filesClear
  };
})();
