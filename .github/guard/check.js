#!/usr/bin/env node
// Охоронець DefTech Daily: перевіряє, що змінено лише блоки даних і що дані безпечні.
// Використання:
//   node .github/guard/check.js                    — перевірити index.html і web/index.html у робочій копії
//   node .github/guard/check.js --update-baseline   — записати новий еталон коду (лише після свідомої зміни коду)
//   node .github/guard/check.js --live <file> <name> — перевірити завантажену з сайту сторінку (name: app | web)
'use strict';
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const vm = require('vm');

const ROOT = path.resolve(__dirname, '..', '..');
const BASE = path.join(__dirname, 'baseline.json');
const PAGES = { app: 'index.html', web: 'web/index.html' };
const BLOCKS = ['NEWS', 'CONFLICTS', 'INNOVATIONS'];
const LIMITS = { ARTICLES: [8, 80], CONFLICTS: [5, 40], INNOVATIONS: [50, 600] };

const errors = [];
const fail = (m) => errors.push(m);

function marks(name) { return ['  // === ' + name + ' DATA START ===', '  // === ' + name + ' DATA END ===']; }

function split(html, label) {
  const blocks = {};
  let template = html;
  for (const b of BLOCKS) {
    const [A, B] = marks(b);
    const i = template.indexOf(A), j = template.indexOf(B);
    if (i < 0 || j < 0 || j < i || template.indexOf(A, i + 1) >= 0) { fail(label + ': маркери блоку ' + b + ' пошкоджені або дубльовані'); continue; }
    blocks[b] = template.slice(i + A.length, j);
    template = template.slice(0, i + A.length) + '\n' + template.slice(j);
  }
  return { blocks, template };
}

function sha(s) { return crypto.createHash('sha256').update(s, 'utf8').digest('hex'); }

// Дані мають бути лише оголошеннями змінних із літералами — без викликів функцій і коду.
const FORBIDDEN_CODE = /\b(function|=>|eval|Function|import|require|fetch|XMLHttpRequest|document|window|location|setTimeout|setInterval|constructor|__proto__|prototype)\b|`/;

function evalBlock(src, label) {
  const code = src.replace(/^\s*\/\/[^\n]*$/gm, '');
  // Прибираємо рядкові літерали, щоб перевіряти лише «каркас» коду.
  const skeleton = code.replace(/'(?:[^'\\\n]|\\.)*'/g, "''");
  if (FORBIDDEN_CODE.test(skeleton)) { fail(label + ': у блоці даних є виконуваний код (' + skeleton.match(FORBIDDEN_CODE)[0] + ')'); return null; }
  if (/\(/.test(skeleton)) { fail(label + ': у блоці даних є виклик функції'); return null; }
  const ctx = vm.createContext(Object.create(null));
  try { vm.runInContext(code, ctx, { timeout: 1000 }); } catch (e) { fail(label + ': блок даних не виконується: ' + e.message); return null; }
  return ctx;
}

function walk(v, at, label) {
  if (typeof v === 'string') {
    if (/<\s*[a-z!\/?]/i.test(v)) fail(label + ' ' + at + ': HTML-тег у тексті');
    if (/javascript:|vbscript:|data:text|data:image\/svg/i.test(v)) fail(label + ' ' + at + ': небезпечна схема URL');
    if (/^[a-z][a-z0-9+.-]*:\/\//i.test(v.trim()) && !/^https:\/\/[^\s"'<>]+$/.test(v)) fail(label + ' ' + at + ': посилання не https або з пробілами/лапками: ' + v.slice(0, 80));
    if (v.length > 4000) fail(label + ' ' + at + ': підозріло довгий рядок');
  } else if (Array.isArray(v)) v.forEach((x, i) => walk(x, at + '[' + i + ']', label));
  else if (v && typeof v === 'object') for (const k of Object.keys(v)) walk(v[k], at + '.' + k, label);
  else if (!(typeof v === 'number' || typeof v === 'boolean' || v == null)) fail(label + ' ' + at + ': неочікуваний тип');
}

function checkData(blocks, label) {
  const out = {};
  for (const b of BLOCKS) {
    if (blocks[b] == null) continue;
    const ctx = evalBlock(blocks[b], label + ' ' + b);
    if (!ctx) continue;
    out[b] = ctx;
    walk(Object.assign({}, ctx), b, label);
  }
  const n = out.NEWS, c = out.CONFLICTS, iv = out.INNOVATIONS;
  const size = (arr, key) => { const [lo, hi] = LIMITS[key]; if (!Array.isArray(arr) || arr.length < lo || arr.length > hi) fail(label + ': ' + key + ' має ' + (arr ? arr.length : 'нуль') + ' записів (очікується ' + lo + '–' + hi + ')'); };
  if (n) {
    size(n.ARTICLES, 'ARTICLES');
    const ids = new Set();
    (n.ARTICLES || []).forEach((a, i) => {
      if (!a || typeof a.t !== 'string' || typeof a.link !== 'string') fail(label + ': новина #' + i + ' без заголовка чи посилання');
      if (a && a.link && !/^https:\/\//.test(a.link)) fail(label + ': новина #' + i + ' посилання не https');
      if (a && a.img && !/^https:\/\//.test(a.img)) fail(label + ': новина #' + i + ' фото не https');
      if (a && ids.has(a.id)) fail(label + ': повтор id ' + a.id); if (a) ids.add(a.id);
    });
    if (!n.NEWS_AS_OF || !Array.isArray(n.NEWS_AS_OF.dayTitles)) fail(label + ': NEWS_AS_OF пошкоджено');
  }
  if (c) size(c.CONFLICTS, 'CONFLICTS');
  if (iv) {
    size(iv.INNOVATIONS, 'INNOVATIONS');
    const ids = new Set();
    (iv.INNOVATIONS || []).forEach((p) => { if (ids.has(p.id)) fail(label + ': повтор id інновації ' + p.id); ids.add(p.id);
      if (!['dev', 'test', 'prod', 'service'].includes(p.stage)) fail(label + ': інновація ' + p.id + ' має невідому стадію'); });
  }
}

function checkScripts(html, label) {
  const re = /<script\b([^>]*)>([\s\S]*?)<\/script>/gi; let m, n = 0;
  while ((m = re.exec(html))) {
    n++;
    if (/\bsrc\s*=/.test(m[1])) fail(label + ': з’явився зовнішній скрипт ' + m[1].trim());
    try { new vm.Script(m[2]); } catch (e) { fail(label + ': синтаксична помилка в скрипті: ' + e.message); }
  }
  if (n !== 1) fail(label + ': очікувався 1 вбудований скрипт, знайдено ' + n);
  if (!/http-equiv="Content-Security-Policy"/.test(html)) fail(label + ': зникла політика безпеки CSP');
  if (/<iframe|<object|<embed|<form\b/i.test(html)) fail(label + ': з’явився iframe/object/embed/form');
}

function analyse(html, name, label) {
  const { blocks, template } = split(html, label);
  checkScripts(html, label);
  checkData(blocks, label);
  return { blocks, hash: sha(template) };
}

const args = process.argv.slice(2);
if (args[0] === '--live') {
  const [file, name] = args.slice(1);
  const html = fs.readFileSync(file, 'utf8');
  const base = JSON.parse(fs.readFileSync(BASE, 'utf8'));
  const r = analyse(html, name, 'сайт ' + name);
  if (base[name] !== r.hash) fail('сайт ' + name + ': код сторінки відрізняється від еталона (можлива підміна)');
} else {
  const res = {};
  for (const [name, rel] of Object.entries(PAGES)) res[name] = analyse(fs.readFileSync(path.join(ROOT, rel), 'utf8'), name, rel);
  for (const b of BLOCKS) if (res.app.blocks[b] !== res.web.blocks[b]) fail('блок ' + b + ' відрізняється в index.html і web/index.html');
  if (args[0] === '--update-baseline') {
    if (errors.length) { console.error(errors.join('\n')); process.exit(1); }
    fs.writeFileSync(BASE, JSON.stringify({ app: res.app.hash, web: res.web.hash }, null, 2) + '\n');
    console.log('Еталон оновлено:', res.app.hash.slice(0, 12), res.web.hash.slice(0, 12));
    process.exit(0);
  }
  const base = JSON.parse(fs.readFileSync(BASE, 'utf8'));
  for (const name of Object.keys(PAGES)) if (base[name] !== res[name].hash) fail(PAGES[name] + ': змінено код поза блоками даних (еталон не збігається)');
}
if (errors.length) { console.error('ОХОРОНЕЦЬ: ЗНАЙДЕНО ПРОБЛЕМИ\n- ' + errors.join('\n- ')); process.exit(1); }
console.log('ОХОРОНЕЦЬ: усе гаразд');
