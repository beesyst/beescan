-- Создание пользователя для БД (если его нет)
DO $$
BEGIN
   IF NOT EXISTS (
      SELECT FROM pg_catalog.pg_roles WHERE rolname = 'beescan'
   ) THEN
      CREATE ROLE beescan LOGIN PASSWORD 'securepass';
   END IF;
END
$$;

-- Удаление всех таблиц (в нужном порядке)
DROP TABLE IF EXISTS evidence CASCADE;
DROP TABLE IF EXISTS vuln CASCADE;
DROP TABLE IF EXISTS services CASCADE;
DROP TABLE IF EXISTS hosts CASCADE;
DROP TABLE IF EXISTS registry CASCADE;

-- Таблица хостов (hosts): информация о хостах/целях
CREATE TABLE hosts (
    id SERIAL PRIMARY KEY,
    ip TEXT,
    fqdn TEXT,
    os TEXT,
    meta JSONB,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_hosts_ip ON hosts (ip);
CREATE INDEX idx_hosts_fqdn ON hosts (fqdn);

-- Таблица сервисов (services): открытые сервисы на хостах
CREATE TABLE services (
    id SERIAL PRIMARY KEY,
    host_id INTEGER REFERENCES hosts(id) ON DELETE CASCADE,
    port INTEGER,
    protocol TEXT,
    service_name TEXT,
    product TEXT,
    version TEXT,
    banner TEXT,
    plugin TEXT,
    meta JSONB,
    created_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(host_id, port, protocol, service_name, plugin)
);

CREATE INDEX idx_services_plugin ON services (plugin);
CREATE INDEX idx_services_host_id ON services (host_id);
CREATE INDEX idx_services_port ON services (port);
CREATE INDEX idx_services_protocol ON services (protocol);

-- Таблица уязвимостей (vuln): всё что касается findings/vuln
CREATE TABLE vuln (
    id SERIAL PRIMARY KEY,
    service_id INTEGER REFERENCES services(id) ON DELETE CASCADE,
    host_id INTEGER REFERENCES hosts(id) ON DELETE CASCADE,
    plugin TEXT,
    source TEXT,
    category TEXT,
    severity TEXT,
    title TEXT,
    description TEXT,
    refs TEXT[],
    created_at TIMESTAMP DEFAULT NOW(),
    meta JSONB
);

CREATE INDEX idx_vuln_source ON vuln (source);
CREATE INDEX idx_vuln_service_id ON vuln (service_id);
CREATE INDEX idx_vuln_host_id ON vuln (host_id);
CREATE INDEX idx_vuln_plugin ON vuln (plugin);
CREATE INDEX idx_vuln_severity ON vuln (severity);
CREATE INDEX idx_vuln_meta ON vuln USING GIN (meta);

-- Таблица сырых логов и доказательств (evidence)
CREATE TABLE evidence (
    id SERIAL PRIMARY KEY,
    vuln_id INTEGER REFERENCES vuln(id) ON DELETE CASCADE,
    plugin TEXT,
    log_type TEXT,
    log_path TEXT,
    raw_log TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_evidence_vuln_id ON evidence (vuln_id);
CREATE INDEX idx_evidence_plugin ON evidence (plugin);

-- Таблица реестра целей и промежуточных задач (registry)
CREATE TABLE registry (
    id SERIAL PRIMARY KEY,
    target_type TEXT NOT NULL,
    target_value TEXT NOT NULL,
    port INTEGER,
    protocol TEXT,
    host_id INTEGER REFERENCES hosts(id) ON DELETE SET NULL,
    service_id INTEGER REFERENCES services(id) ON DELETE SET NULL,
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
CREATE INDEX idx_registry_host_id ON registry (host_id);
CREATE INDEX idx_registry_service_id ON registry (service_id);

-- Выдать все права пользователю beescan
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO beescan;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO beescan;
