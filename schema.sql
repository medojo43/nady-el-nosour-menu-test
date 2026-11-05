CREATE TABLE IF NOT EXISTS menu_items (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  section TEXT NOT NULL,
  category TEXT NOT NULL DEFAULT '',
  item TEXT NOT NULL,
  civilian_price REAL,
  member_price REAL,
  sort_order TEXT NOT NULL DEFAULT '',
  notes TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_menu_section_category ON menu_items(section, category);
