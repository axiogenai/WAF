'use strict';

const fs   = require('fs');
const path = require('path');

const REGISTRY_FILE = path.join(__dirname, '..', 'domains.json');

function load() {
  try {
    if (fs.existsSync(REGISTRY_FILE)) {
      return JSON.parse(fs.readFileSync(REGISTRY_FILE, 'utf-8'));
    }
  } catch {}
  return {};
}

function save(reg) {
  try { fs.writeFileSync(REGISTRY_FILE, JSON.stringify(reg, null, 2)); } catch {}
}

function normalise(domain) {
  return (domain || '').toLowerCase()
    .replace(/^https?:\/\//, '')
    .replace(/\/$/, '')
    .split(':')[0]
    .trim();
}

function register(domain, originUrl, rules = {}) {
  const reg  = load();
  const key  = normalise(domain);
  if (!key) throw new Error('Invalid domain');
  let origin = originUrl.trim();
  if (!/^https?:\/\//i.test(origin)) origin = 'https://' + origin;
  reg[key] = {
    domain: key,
    origin,
    rules: { sqli: true, xss: true, pathTraversal: true, rfiLfi: true, commandInjection: true, botDetection: true, ...rules },
    registeredAt: Date.now(),
    stats: { total: 0, blocked: 0, allowed: 0 }
  };
  save(reg);
  return reg[key];
}

function lookup(host) {
  const reg = load();
  const key = normalise(host);
  return reg[key] || null;
}

function list() {
  return Object.values(load());
}

function remove(domain) {
  const reg = load();
  delete reg[normalise(domain)];
  save(reg);
}

function incrementStat(host, field) {
  const reg = load();
  const key = normalise(host);
  if (!reg[key]) return;
  reg[key].stats = reg[key].stats || { total: 0, blocked: 0, allowed: 0 };
  reg[key].stats[field] = (reg[key].stats[field] || 0) + 1;
  reg[key].stats.total  = (reg[key].stats.total  || 0) + 1;
  save(reg);
}

module.exports = { register, lookup, list, remove, incrementStat, normalise };
