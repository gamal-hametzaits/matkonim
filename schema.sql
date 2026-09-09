CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  pass_hash TEXT NOT NULL,
  salt TEXT NOT NULL,
  role TEXT NOT NULL CHECK(role IN ('creator','responder')),
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
  token TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS recipes (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  title TEXT NOT NULL,
  ingredients TEXT NOT NULL,
  instructions TEXT NOT NULL,
  photo_key TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS responses (
  id TEXT PRIMARY KEY,
  recipe_id TEXT NOT NULL REFERENCES recipes(id),
  user_id TEXT NOT NULL REFERENCES users(id),
  photo_key TEXT NOT NULL,
  caption TEXT,
  created_at TEXT NOT NULL
);
-- Reserved for future releases (not exposed in v1 UI):
CREATE TABLE IF NOT EXISTS comments (
  id TEXT PRIMARY KEY,
  recipe_id TEXT NOT NULL REFERENCES recipes(id),
  user_id TEXT NOT NULL REFERENCES users(id),
  body TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS reactions (
  id TEXT PRIMARY KEY,
  target_type TEXT NOT NULL CHECK(target_type IN ('recipe','response')),
  target_id TEXT NOT NULL,
  user_id TEXT NOT NULL REFERENCES users(id),
  emoji TEXT NOT NULL,
  created_at TEXT NOT NULL,
  UNIQUE(target_type, target_id, user_id, emoji)
);
CREATE INDEX IF NOT EXISTS idx_recipes_created ON recipes(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_responses_recipe ON responses(recipe_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expiry ON sessions(expires_at);
