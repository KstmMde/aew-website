-- Run once in Cloudflare: Storage & databases > D1 > aew-signups > Console. Safe to keep: it only adds things.
CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, provider TEXT NOT NULL, provider_sub TEXT NOT NULL, email TEXT, name TEXT, created_at TEXT NOT NULL DEFAULT (datetime('now')), last_login_at TEXT NOT NULL DEFAULT (datetime('now')), UNIQUE (provider, provider_sub));
ALTER TABLE tasks ADD COLUMN user_id TEXT;
ALTER TABLE tasks ADD COLUMN parent_id TEXT;
CREATE INDEX IF NOT EXISTS tasks_user ON tasks (user_id, created_at);
CREATE UNIQUE INDEX IF NOT EXISTS tasks_parent ON tasks (parent_id) WHERE parent_id IS NOT NULL;
