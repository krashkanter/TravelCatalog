-- Users table for authentication and role management
CREATE TABLE users
(
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    name     TEXT NOT NULL,
    email    TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    role     TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user', 'admin'))
);

-- Districts table (top-level geographic division)
CREATE TABLE districts
(
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    name      TEXT NOT NULL,
    image_url TEXT
);

-- Taluks table (sub-divisions of districts)
CREATE TABLE taluks
(
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT    NOT NULL,
    district_id INTEGER NOT NULL,
    FOREIGN KEY (district_id) REFERENCES districts (id) ON DELETE CASCADE
);

-- Destinations within taluks
CREATE TABLE destinations
(
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    title     TEXT    NOT NULL,
    desc      TEXT,
    image_url TEXT,
    taluk_id  INTEGER NOT NULL,
    FOREIGN KEY (taluk_id) REFERENCES taluks (id) ON DELETE CASCADE
);

-- Food options within taluks
CREATE TABLE food
(
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    name      TEXT    NOT NULL,
    desc      TEXT,
    image_url TEXT,
    taluk_id  INTEGER NOT NULL,
    FOREIGN KEY (taluk_id) REFERENCES taluks (id) ON DELETE CASCADE
);

-- Accommodation options within taluks
CREATE TABLE accommodation
(
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    name      TEXT    NOT NULL,
    details   TEXT,
    image_url TEXT,
    taluk_id  INTEGER NOT NULL,
    FOREIGN KEY (taluk_id) REFERENCES taluks (id) ON DELETE CASCADE
);

-- Experiences available within taluks
CREATE TABLE experiences
(
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    name      TEXT    NOT NULL,
    desc      TEXT,
    image_url TEXT,
    taluk_id  INTEGER NOT NULL,
    FOREIGN KEY (taluk_id) REFERENCES taluks (id) ON DELETE CASCADE
);

-- Comments table for user feedback
CREATE TABLE comments
(
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id   INTEGER NOT NULL,
    taluk_id  INTEGER NOT NULL,
    category  TEXT    NOT NULL CHECK (category IN ('destination', 'food', 'accommodation', 'experience')),
    content   TEXT    NOT NULL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
    FOREIGN KEY (taluk_id) REFERENCES taluks (id) ON DELETE CASCADE
);

-- Create indexes for performance optimization
CREATE INDEX idx_taluks_district ON taluks (district_id);
CREATE INDEX idx_destinations_taluk ON destinations (taluk_id);
CREATE INDEX idx_food_taluk ON food (taluk_id);
CREATE INDEX idx_accommodation_taluk ON accommodation (taluk_id);
CREATE INDEX idx_experiences_taluk ON experiences (taluk_id);
CREATE INDEX idx_comments_user ON comments (user_id);
CREATE INDEX idx_comments_taluk ON comments (taluk_id);
CREATE INDEX idx_comments_category ON comments (category);