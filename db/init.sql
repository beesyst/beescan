-- Создание пользователя, если не существует
DO $$
BEGIN
   IF NOT EXISTS (
      SELECT FROM pg_catalog.pg_roles WHERE rolname = 'secscan'
   ) THEN
      CREATE ROLE secscan LOGIN PASSWORD 'securepass';
   END IF;
END
$$;

-- Удаление старых таблиц
DROP TABLE IF EXISTS registry;
DROP TABLE IF EXISTS results;

-- Основная таблица results
CREATE TABLE results (
    id SERIAL PRIMARY KEY,
    target TEXT NOT NULL,
    plugin TEXT NOT NULL,
    category TEXT NOT NULL,
    severity TEXT DEFAULT 'info',
    data JSONB NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_results_data ON results USING GIN (data);
CREATE INDEX idx_results_plugin ON results (plugin);
CREATE INDEX idx_results_target ON results (target);

-- Новая таблица реестра целей
CREATE TABLE registry (
    id SERIAL PRIMARY KEY,
    target_type TEXT NOT NULL,
    target_value TEXT NOT NULL,
    port INTEGER,
    protocol TEXT,
    source_plugin TEXT,
    status TEXT DEFAULT 'new',
    tags TEXT[],
    meta JSONB,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    UNIQUE (target_type, target_value, port, protocol)
);

CREATE INDEX idx_registry_target_value ON registry (target_value);
CREATE INDEX idx_registry_target_type ON registry (target_type);
CREATE INDEX idx_registry_status ON registry (status);
CREATE INDEX idx_registry_tags ON registry USING GIN (tags);
CREATE INDEX idx_registry_meta ON registry USING GIN (meta);
