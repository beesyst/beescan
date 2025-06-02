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


def purge_results(cursor):
    try:
        cursor.execute("TRUNCATE results RESTART IDENTITY CASCADE;")
        cursor.execute("TRUNCATE registry RESTART IDENTITY CASCADE;")
        logging.info("Таблицы results и registry успешно очищены.")
    except psycopg2.Error as e:
        logging.critical(f"Ошибка при очистке таблиц results/registry: {e}")
        exit(1)


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


def is_meaningful_entry(entry, important_fields):
    return not all(
        str(entry.get(k, "-")).strip() in ["-", "", "None", "null", "0"]
        for k in important_fields
    )


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

        try:
            results = []
            if hasattr(plugin_parser, "merge_entries") and len(files) > 1:
                logging.info(
                    f"Объединение данных через merge_entries() для {plugin_name}..."
                )

                source_map = {
                    "IP": ip_target,
                    "Http": domain_target,
                    "Https": domain_target,
                }

                parsed_lists = []
                for f in files:
                    label = f.get("source", "unknown")
                    parsed = plugin_parser.parse(f["path"], source_label=label)
                    parsed_lists.append(parsed)

                merged_data = plugin_parser.merge_entries(*parsed_lists)

                results = []
                for data in merged_data:
                    source = data.get("source", "unknown")
                    if "+" in source:
                        data["target"] = (
                            domain_target
                            if "Http" in source or "Https" in source
                            else ip_target
                        )
                    else:
                        data["target"] = source_map.get(source, "unknown")

                    if not important_fields or is_meaningful_entry(
                        data, important_fields
                    ):
                        results.append(data)
            else:
                for f in files:
                    parsed = plugin_parser.parse(
                        f["path"], f.get("source", "unknown"), f.get("port", "-")
                    )
                    for entry in parsed:
                        entry["target"] = (
                            ip_target if f.get("source") == "IP" else domain_target
                        )
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

        for item in results:
            try:
                timestamp = datetime.now()
                item["created_at"] = timestamp.strftime("%Y-%m-%d %H:%M:%S")
                category = next(
                    (
                        p.get("category", "General Info")
                        for p in PLUGINS
                        if p["name"] == plugin_name
                    ),
                    "General Info",
                )

                cursor.execute(
                    """
                    INSERT INTO results (target, plugin, category, severity, data, created_at)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    """,
                    (
                        item.get("target", "unknown"),
                        plugin_name,
                        category,
                        item.get("severity", "info"),
                        json.dumps(item, ensure_ascii=False),
                        timestamp,
                    ),
                )
                total_added += 1
            except psycopg2.Error as e:
                logging.warning(f"Ошибка вставки данных из {plugin_name}: {e}")
                continue

        logging.info(f"[{plugin_name}] Добавлено записей: {total_added}")

    return total_added


def collect(temp_files=None, purge_only=False):
    try:
        with connect_to_db() as conn:
            with conn.cursor() as cursor:
                if purge_only:
                    logging.info("Режим очистки базы (--purge_only).")
                    purge_results(cursor)
                    return

                if not temp_files:
                    logging.error("Не передан список временных файлов. Прерывание.")
                    return

                total_added = process_temp_files(cursor, temp_files)

                logging.info(
                    f"Сбор данных завершён. Всего добавлено: {total_added} записей."
                )
    except Exception as e:
        logging.critical(f"Фатальная ошибка при сборе данных: {e}")
        exit(1)


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
