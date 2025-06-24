import importlib.util
import json
import logging
import os
import sys
from datetime import datetime

sys.path.insert(0, "/")

import psycopg2
from core.logger_container import setup_container_logger

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG_PATH = os.path.join(ROOT_DIR, "config", "config.json")
PLUGINS_DIR = os.path.join(ROOT_DIR, "plugins")

setup_container_logger()

with open(CONFIG_PATH) as config_file:
    CONFIG = json.load(config_file)

DB_CONFIG = CONFIG["database"]
PLUGINS = CONFIG.get("plugins", [])


# Подключение к БД
def connect_to_db():
    try:
        conn = psycopg2.connect(
            database=DB_CONFIG["POSTGRES_DB"],
            user=DB_CONFIG["POSTGRES_USER"],
            password=DB_CONFIG["POSTGRES_PASSWORD"],
            host=DB_CONFIG["POSTGRES_HOST"],
            port=DB_CONFIG["POSTGRES_PORT"],
        )
        logging.info("Успешное подключение к базе данных.")
        return conn
    except psycopg2.Error as e:
        logging.critical(f"Ошибка подключения к БД: {e}")
        exit(1)


# Очистка таблиц (purge)
def purge_tables(cursor):
    try:
        cursor.execute("TRUNCATE evidence RESTART IDENTITY CASCADE;")
        cursor.execute("TRUNCATE vuln RESTART IDENTITY CASCADE;")
        cursor.execute("TRUNCATE services RESTART IDENTITY CASCADE;")
        cursor.execute("TRUNCATE hosts RESTART IDENTITY CASCADE;")
        cursor.execute("TRUNCATE registry RESTART IDENTITY CASCADE;")
        logging.info("Все основные таблицы успешно очищены.")
    except psycopg2.Error as e:
        logging.critical(f"Ошибка при очистке таблиц: {e}")
        exit(1)


# Динамическая загрузка парсера плагина
def load_plugin_parser(plugin_name):
    plugin_path = os.path.join(PLUGINS_DIR, f"{plugin_name}.py")
    if not os.path.exists(plugin_path):
        logging.error(f"Файл парсера {plugin_path} не найден.")
        return None

    try:
        spec = importlib.util.spec_from_file_location(plugin_name, plugin_path)
        plugin = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(plugin)
        return plugin
    except Exception as e:
        logging.error(f"Ошибка загрузки парсера {plugin_name}: {e}")
        return None


# Вспомогательная функция для meaningful записи
def is_meaningful_entry(entry, important_fields):
    return not all(
        str(entry.get(k, "-")).strip() in ["-", "", "None", "null", "0"]
        for k in important_fields
    )


# Получить или создать host (по ip/fqdn)
def get_or_create_host(cursor, ip=None, fqdn=None, os_name=None, meta=None):
    cursor.execute("SELECT id FROM hosts WHERE ip = %s AND fqdn = %s", (ip, fqdn))
    row = cursor.fetchone()
    if row:
        return row[0]
    cursor.execute(
        "INSERT INTO hosts (ip, fqdn, os, meta, created_at) VALUES (%s, %s, %s, %s, %s) RETURNING id",
        (ip, fqdn, os_name, json.dumps(meta or {}, ensure_ascii=False), datetime.now()),
    )
    return cursor.fetchone()[0]


# Получить или создать service
def get_or_create_service(
    cursor,
    host_id,
    port,
    protocol,
    service_name,
    product=None,
    version=None,
    banner=None,
    plugin=None,
    meta=None,
):
    cursor.execute(
        "SELECT id FROM services WHERE host_id = %s AND port = %s AND protocol = %s AND service_name = %s AND plugin = %s",
        (host_id, port, protocol, service_name, plugin),
    )
    row = cursor.fetchone()
    if row:
        return row[0]
    cursor.execute(
        "INSERT INTO services (host_id, port, protocol, service_name, product, version, banner, plugin, meta, created_at) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id",
        (
            host_id,
            port,
            protocol,
            service_name,
            product,
            version,
            banner,
            plugin,
            json.dumps(meta or {}, ensure_ascii=False),
            datetime.now(),
        ),
    )
    return cursor.fetchone()[0]


# Создать уязвимость (vulnerability)
def create_vuln(
    cursor,
    service_id,
    host_id,
    plugin,
    source,
    category,
    severity,
    title,
    description,
    refs,
    meta=None,
):
    cursor.execute(
        """
        INSERT INTO vuln (service_id, host_id, plugin, source, category, severity, title, description, refs, created_at, meta)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        RETURNING id
        """,
        (
            service_id,
            host_id,
            plugin,
            source,
            category,
            severity,
            title,
            description,
            refs,
            datetime.now(),
            json.dumps(meta or {}, ensure_ascii=False),
        ),
    )
    return cursor.fetchone()[0]


# Создать evidence (raw-лог/доказательство)
def create_evidence(cursor, vuln_id, plugin, log_type, log_path, raw_log):
    cursor.execute(
        """
        INSERT INTO evidence (vuln_id, plugin, log_type, log_path, raw_log, created_at)
        VALUES (%s,%s,%s,%s,%s,%s)
        RETURNING id
        """,
        (vuln_id, plugin, log_type, log_path, raw_log, datetime.now()),
    )
    return cursor.fetchone()[0]


# Обработка временных файлов (главная логика разбора)
def process_temp_files(cursor, temp_files):
    total_added = 0
    grouped_files = {}

    ip_target = CONFIG.get("scan_config", {}).get("target_ip", "unknown")
    domain_target = CONFIG.get("scan_config", {}).get("target_domain", "unknown")

    for temp_file_info in temp_files:
        plugin_name = temp_file_info.get("plugin")
        if not plugin_name:
            logging.warning(f"Некорректные данные в буфере: {temp_file_info}")
            continue
        grouped_files.setdefault(plugin_name, []).append(temp_file_info)

    for plugin_name, files in grouped_files.items():
        plugin_parser = load_plugin_parser(plugin_name)
        if not plugin_parser:
            logging.error(f"Парсер для плагина {plugin_name} не загружен. Пропускаем.")
            continue
        if not hasattr(plugin_parser, "parse"):
            logging.error(
                f"Плагин {plugin_name} не содержит функцию parse(). Пропускаем."
            )
            continue

        important_fields = []
        if hasattr(plugin_parser, "get_important_fields"):
            important_fields = plugin_parser.get_important_fields()

        # Парсим файлы и нормализуем данные
        try:
            results = []
            if hasattr(plugin_parser, "merge_entries") and len(files) > 1:
                parsed_lists = []
                for f in files:
                    label = f.get("source", "unknown")
                    parsed = plugin_parser.parse(f["path"], source_label=label)
                    parsed_lists.append(parsed)
                merged_data = plugin_parser.merge_entries(*parsed_lists)
                results = [
                    d
                    for d in merged_data
                    if not important_fields or is_meaningful_entry(d, important_fields)
                ]
            else:
                for f in files:
                    parsed = plugin_parser.parse(
                        f["path"], f.get("source", "unknown"), f.get("port", "-")
                    )
                    for entry in parsed:
                        if not important_fields or is_meaningful_entry(
                            entry, important_fields
                        ):
                            results.append(entry)
        except Exception as e:
            logging.error(f"Ошибка выполнения parse() для {plugin_name}: {e}")
            continue

        if not results:
            logging.info(f"Нет данных для вставки из {plugin_name}.")
            continue

        # Для каждого результата — разложить по таблицам
        for item in results:
            try:
                # Host (по ip/domain)
                ip = item.get("ip") or (
                    ip_target if item.get("target_type") == "ip" else None
                )
                fqdn = item.get("fqdn") or (
                    domain_target if item.get("target_type") == "domain" else None
                )
                os_name = item.get("os")
                host_meta = item.get("host_meta", {})
                host_id = get_or_create_host(cursor, ip, fqdn, os_name, host_meta)

                # Service (если порт/протокол есть)
                port = (
                    int(item.get("port", 0))
                    if "port" in item and str(item["port"]).isdigit()
                    else None
                )
                protocol = item.get("protocol")
                service_name = item.get("service_name")
                product = item.get("product")
                version = item.get("version")
                banner = item.get("banner")
                service_meta = item.get("service_meta", {})  # <- только что дал плагин!
                service_id = None
                if port and protocol and service_name:
                    service_id = get_or_create_service(
                        cursor,
                        host_id,
                        port,
                        protocol,
                        service_name,
                        product,
                        version,
                        banner,
                        plugin_name,
                        service_meta,
                    )

                # Vuln (или просто finding)
                category = next(
                    (
                        p.get("category", "General Info")
                        for p in PLUGINS
                        if p["name"] == plugin_name
                    ),
                    "General Info",
                )
                severity = item.get("severity", "info")
                title = item.get("title") or item.get("msg") or "Finding"
                description = (
                    item.get("description") or item.get("script_output") or "-"
                )
                refs = item.get("refs")
                if isinstance(refs, str):
                    refs = [refs]
                vuln_meta = item.get("vuln_meta", {})
                source = (
                    item.get("source") or (item.get("meta") or {}).get("source") or "-"
                )
                vuln_id = create_vuln(
                    cursor,
                    service_id,
                    host_id,
                    plugin_name,
                    source,
                    category,
                    severity,
                    title,
                    description,
                    refs,
                    vuln_meta,
                )

                evidence_path = item.get("evidence_path")
                evidence_type = item.get("evidence_type", source)
                if evidence_path:
                    create_evidence(
                        cursor, vuln_id, plugin_name, evidence_type, evidence_path, None
                    )

                # Evidence (сырые логи и т.д.)
                evidence = item.get("evidence")
                if evidence or item.get("raw_log") or item.get("log_path"):
                    create_evidence(
                        cursor,
                        vuln_id,
                        plugin_name,
                        item.get("log_type", "raw"),
                        item.get("log_path"),
                        evidence or item.get("raw_log", ""),
                    )

                total_added += 1
            except Exception as e:
                logging.warning(f"Ошибка вставки данных из {plugin_name}: {e}")
                continue

        logging.info(f"[{plugin_name}] Добавлено записей: {total_added}")

    return total_added


# Главная точка входа
def collect(temp_files=None, purge_only=False):
    try:
        with connect_to_db() as conn:
            with conn.cursor() as cursor:
                if purge_only:
                    logging.info("Режим очистки базы (--purge_only).")
                    purge_tables(cursor)
                    return

                if not temp_files:
                    logging.error("Не передан список временных файлов. Прерывание.")
                    return

                total_added = process_temp_files(cursor, temp_files)
                conn.commit()  # Не забываем!
                logging.info(
                    f"Сбор данных завершён. Всего добавлено: {total_added} записей."
                )
    except Exception as e:
        logging.critical(f"Фатальная ошибка при сборе данных: {e}")
        exit(1)


# CLI обработчик
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--temp-file", help="Путь к JSON-файлу с путями временных файлов"
    )
    parser.add_argument(
        "--purge-only", action="store_true", help="Очистить базу и выйти"
    )
    args = parser.parse_args()

    if args.purge_only:
        collect(purge_only=True)
    elif args.temp_file:
        if os.path.exists(args.temp_file):
            try:
                with open(args.temp_file, "r", encoding="utf-8") as f:
                    temp_data = json.load(f)

                if isinstance(temp_data, dict) and "paths" in temp_data:
                    temp_files = temp_data["paths"]
                else:
                    logging.error("Файл не содержит ключ 'paths'. Проверь формат.")
                    exit(1)

                collect(temp_files=temp_files)
            except Exception as e:
                logging.error(f"Ошибка при чтении временного файла: {e}")
        else:
            logging.error(f"Файл не найден: {args.temp_file}")
    else:
        logging.error("Не передан аргумент --temp-file и не указан флаг --purge-only.")
