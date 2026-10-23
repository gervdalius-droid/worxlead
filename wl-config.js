/* =====================================================================
   WorxLead — vienintelė vieta, kurią reikia redaguoti paleidžiant
   =====================================================================

   1) DEMO / VIETINIS REŽIMAS (numatytasis)
      Palikite supabaseUrl tuščią. Užklausos saugomos naršyklės atmintyje
      (localStorage) tame pačiame įrenginyje ir paruošiamas laiškas.
      Tinka išbandyti, bet klientų užklausos NEATKELIAUJA į /admin kitame
      kompiuteryje — tam reikia 2 punkto.

   2) TIKRAS REŽIMAS — Supabase (nemokamas planas užtenka pradžiai)
      a) supabase.com -> New project
      b) SQL Editor -> įklijuokite visą schema.sql -> Run
      c) Project Settings -> API -> nukopijuokite Project URL ir
         publishable (anon) raktą žemiau
      d) Authentication -> Users -> Add user: jūsų el. paštas + slaptažodis.
         Tuo prisijungsite prie /admin.
      e) SQL Editor -> paleiskite (savo el. paštu):
         select wl_make_admin('jusu@pastas.lt');
   ===================================================================== */
window.WL_CONFIG = {
  /* --- Supabase (palikite tuščia demo režimui) --- */
  supabaseUrl: "https://szqgchsvoinzvhvmvsuq.supabase.co",
  supabaseKey: "sb_publishable_3jSWVorheLrawZeJu-c4Xw_XJLmx0kB",

  /* --- Atsarginis variantas: bet koks POST endpoint'as (n8n, Formspree, Make) ---
     Naudojamas tik tada, kai Supabase nesukonfigūruotas. --- */
  endpoint: "",

  /* --- Svetainės adresas. Naudojamas sitemap.xml ir laiškų nuorodoms.
     Perkėlus į worxlead.lt — pakeiskite čia ir perkurkite dist/. --- */
  siteUrl: "https://worxlead.lt",

  /* --- Spalvų paletė: "amber" (numatyta), "navy", "teal", "ink" ---
     Peržiūrai naršyklėje: pridėkite ?p=navy prie adreso. --- */
  palette: "navy-gold",

  /* --- Įmonė ir kontaktai, rodomi svetainėje ---
     Tušti laukai niekur nerodomi: nei poraštėje, nei kontaktuose, nei
     teisiniuose tekstuose, nei struktūriniuose duomenyse. Norint grąžinti —
     tiesiog įrašykite reikšmes atgal ir paleiskite scripts/build-dist.py. */
  company: "WorxLead",
  companyCode: "",                 /* 9 skaitmenys */
  email: "labas@worxlead.lt",
  phone: "",                       /* "+3706…" be tarpų */
  phoneHuman: "",                  /* su tarpais, rodymui */

  /* --- Meta (Facebook) reklamos pikselis ---
     Įrašykite savo rinkinio (dataset / pixel) numerį, pvz. "1234567890".
     Tuščias laukas = pikselio nėra, sutikimo juosta nerodoma.
     SVARBU: pikselis įkeliamas TIK lankytojui paspaudus „Sutinku“ —
     taip reikalauja BDAR ir e. privatumo taisyklės. */
  metaPixel: "1838829450605367",

  /* --- Veiklos taisyklės --- */
  maxOffers: 5,          // kiek rangovų daugiausia gali atrakinti vieną užklausą
  replyHours: "24–72",   // pažadas klientui (valandomis)
  refundDays: 3,         // per kiek dienų grąžinamas kreditas neatsiliepus klientui

  /* --- /admin apsauga DEMO režime (Supabase režime naudojamas el. paštas + slaptažodis) --- */
  /* Akcija: pirmam prisiregistravusiam rangovui viena užklausa nemokamai.
     Norint akciją išjungti — pakeiskite į false, iššokantis langas dings. */
  promoFirstFree: true,

  adminPin: "worxlead"
};
