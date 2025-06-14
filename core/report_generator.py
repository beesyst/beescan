import importlib
import os
import sys

# Добавляем корень проекта для импортов core.*
sys.path.insert(0, "/")

import argparse
import json
import logging
import re
import shutil
import textwrap
from collections import OrderedDict, defaultdict
from datetime import datetime

import psycopg2
from core.logger_container import setup_container_logger
from jinja2 import Environment, FileSystemLoader
from rich.console import Console
from rich.table import Table
from weasyprint import HTML

setup_container_logger()

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEMPLATES_DIR = os.path.join(ROOT_DIR, "templates")
OUTPUT_DIR = os.path.join(ROOT_DIR, "reports")
os.makedirs(OUTPUT_DIR, exist_ok=True)

CONFIG_PATH = os.path.join(ROOT_DIR, "config", "config.json")
with open(CONFIG_PATH, "r") as f:
    CONFIG = json.load(f)
DB_CONFIG = CONFIG["database"]
PLUGINS = CONFIG.get("plugins", [])


# Подключение к БД
def connect_to_db():
    return psycopg2.connect(
        database=DB_CONFIG["POSTGRES_DB"],
        user=DB_CONFIG["POSTGRES_USER"],
        password=DB_CONFIG["POSTGRES_PASSWORD"],
        host=DB_CONFIG["POSTGRES_HOST"],
        port=DB_CONFIG["POSTGRES_PORT"],
    )


# Фильтр для Jinja2 — красиво подсвечивает ключевые слова/заголовки в тексте
def highlight_keywords(text):
    if not isinstance(text, str):
        return text
    lines = text.splitlines()
    html = []
    current_sublist = []
    current_title = None

    def flush():
        nonlocal current_sublist, current_title
        if current_title and current_sublist:
            html.append(f"<li>{current_title}<ul>")
            for item in current_sublist:
                html.append(f"<li>{item}</li>")
            html.append("</ul></li>")
        elif current_title:
            html.append(f"<li>{current_title}</li>")
        elif current_sublist:
            html.append("<ul>")
            for item in current_sublist:
                html.append(f"<li>{item}</li>")
            html.append("</ul>")
        current_title = None
        current_sublist = []

    for line in lines:
        line = line.strip()
        if not line:
            flush()
            continue
        if line.startswith("[") and line.endswith("]"):
            flush()
            html.append(f"<strong>{line}</strong>")
        elif re.match(r"^[A-Za-z0-9_.:-]+:$", line):
            flush()
            current_title = line.rstrip(":")
        else:
            current_sublist.append(line)
    flush()
    return "<ul>\n" + "\n".join(html) + "\n</ul>"


# Создание окружения Jinja2 для рендеринга шаблонов
def get_jinja_env():
    env = Environment(loader=FileSystemLoader(TEMPLATES_DIR))
    env.filters["highlight_keywords"] = highlight_keywords
    return env


# Категоризация результатов по категориям и плагинам
def categorize_results(entries):
    plugin_categories = {
        plugin["name"]: plugin.get("category", "General Info") for plugin in PLUGINS
    }
    plugin_order = {plugin["name"]: idx for idx, plugin in enumerate(PLUGINS)}
    structured = defaultdict(dict)
    global_meta = {"created_at": None}
    for entry in entries:
        plugin = entry.get("plugin")
        category = plugin_categories.get(plugin, "General Info")
        if plugin not in structured[category]:
            structured[category][plugin] = []
        structured[category][plugin].append(entry)
        if global_meta["created_at"] is None and entry.get("created_at"):
            global_meta["created_at"] = entry["created_at"]
    for cat in structured:
        structured[cat] = OrderedDict(
            sorted(structured[cat].items(), key=lambda x: plugin_order.get(x[0], 999))
        )
    return structured, global_meta


# Сортировка категорий в отчете по приоритету из конфига
def sort_categories_by_priority(raw_results):
    category_order = CONFIG.get("report_category_order", [])
    order = {cat: idx for idx, cat in enumerate(category_order)}
    return OrderedDict(
        sorted(raw_results.items(), key=lambda item: order.get(item[0], 999))
    )


# Получение и загрузка результатов из snapshot
def load_snapshot():
    conn = connect_to_db()
    cursor = conn.cursor()
    result = {}

    for table in ["hosts", "services", "vuln", "evidence", "registry"]:
        cursor.execute(f"SELECT * FROM {table}")
        rows = cursor.fetchall()
        columns = [desc[0] for desc in cursor.description]
        result[table] = [dict(zip(columns, row)) for row in rows]

    cursor.close()
    conn.close()
    meta = {"created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
    return result, meta


# Собирает structured_results с помощью get_view_rows для каждого плагина
def build_structured_results(snapshot):
    structured = {}
    for plugin_cfg in PLUGINS:
        if not plugin_cfg.get("enabled", False):
            continue
        plugin = plugin_cfg["name"]
        try:
            plugin_mod = importlib.import_module(f"plugins.{plugin}")
        except Exception:
            continue
        if hasattr(plugin_mod, "get_view_rows"):
            entries = plugin_mod.get_view_rows(snapshot)
        else:
            entries = [v for v in snapshot.get("vuln", []) if v.get("plugin") == plugin]
        category = plugin_cfg.get("category", "General Info")
        if category not in structured:
            structured[category] = {}
        structured[category][plugin] = entries
    return structured


# Рендеринг HTML-отчета через Jinja2
def render_html(results, output_path, meta, duration_map):
    logging.info(f"Поиск шаблона в: {TEMPLATES_DIR}")
    env = get_jinja_env()
    try:
        template = env.get_template("report.html.j2")
    except Exception as e:
        logging.error(f"Ошибка загрузки шаблона: {e}")
        raise
    theme = CONFIG.get("scan_config", {}).get("report_theme", "light")

    structured_results = build_structured_results(results)

    rendered = template.render(
        snapshot=results,
        structured_results=structured_results,
        generation_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        report_theme=theme,
        config=CONFIG,
        meta=meta,
        duration_map=duration_map,
    )
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(rendered)
    logging.info(f"HTML-отчет создан: {output_path}")


def fix_datetimes(obj):
    if isinstance(obj, dict):
        return {k: fix_datetimes(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [fix_datetimes(x) for x in obj]
    elif isinstance(obj, datetime):
        return obj.strftime("%Y-%m-%d %H:%M:%S")
    return obj


def export_json_report(results, meta, duration_map, output_path):
    payload = {
        "snapshot": fix_datetimes(results),
        "meta": meta,
        "duration_map": duration_map,
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "config": CONFIG,
    }
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
    logging.info(f"JSON-отчет сохранен: {output_path}")


def export_txt_report(snapshot, meta, duration_map, output_path):
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(f"# BeeScan Report\nGenerated at: {meta.get('created_at')}\n\n")
        for table, rows in snapshot.items():
            f.write(f"## {table.upper()}\n")
            for row in rows:
                for k, v in row.items():
                    f.write(f"- {k}: {v}\n")
                f.write("\n")


# Генерация PDF-отчета на основе HTML (WeasyPrint)
def generate_pdf(html_path, pdf_path):
    HTML(html_path).write_pdf(pdf_path)
    logging.info(f"PDF-отчет создан: {pdf_path}")


# Красивое обрезание длинных ячеек для терминала
def wrap_cell(value, width=80):
    return "\n".join(
        textwrap.wrap(
            str(value), width=width, break_long_words=True, replace_whitespace=False
        )
    )


# Отрисовка отчета в терминале (таблично, с шириной экрана)
def show_in_terminal(snapshot, duration_map):
    terminal_width = shutil.get_terminal_size((160, 20)).columns
    console = Console(width=terminal_width)
    for plugin_cfg in CONFIG["plugins"]:
        plugin_name = plugin_cfg["name"]
        if not plugin_cfg.get("enabled", False):
            continue

        try:
            plugin_module = importlib.import_module(f"plugins.{plugin_name}")
        except Exception:
            plugin_module = None

        # Получаем все данные для плагина
        if plugin_module and hasattr(plugin_module, "get_view_rows"):
            all_data = plugin_module.get_view_rows(snapshot)
        else:
            all_data = []
            for table_name, rows in snapshot.items():
                for row in rows:
                    if row.get("plugin") == plugin_name:
                        all_data.append(row)

        if not all_data:
            continue

        # Параметры колонок, merge, постпроцессинг и пр.
        important_fields = getattr(plugin_module, "get_important_fields", lambda: [])()
        merge_enabled = getattr(plugin_module, "should_merge_entries", lambda: True)()
        column_order = getattr(plugin_module, "get_column_order", None)
        if callable(column_order):
            column_order = column_order()
        wide_fields = getattr(plugin_module, "get_wide_fields", lambda: [])()
        postprocess = getattr(plugin_module, "postprocess_result", lambda x: x)

        # meaningful
        if important_fields:

            def is_meaningful(entry):
                return not all(
                    str(entry.get(k, "-")).strip() in ["-", "", "null", "None", "0"]
                    for k in important_fields
                )

            all_data = [d for d in all_data if is_meaningful(d)]

        # merge
        if merge_enabled:
            seen = {}
            for d in all_data:
                key = (d.get("port"), d.get("protocol"), d.get("service_name"))
                if key in seen:
                    existing = seen[key]
                    existing_sources = set(str(existing.get("source", "")).split("+"))
                    new_sources = set(str(d.get("source", "")).split("+"))
                    combined_sources = sorted(existing_sources.union(new_sources))
                    existing["source"] = "+".join(combined_sources)
                else:
                    seen[key] = d
            unique_data = list(seen.values())
        else:
            unique_data = all_data

        if not unique_data:
            continue

        # Определяем порядок колонок
        if column_order:
            keys = []
            if "source" in column_order:
                keys.append("source")
            keys.extend([k for k in column_order if k != "source"])
        else:
            all_keys = list(
                dict.fromkeys(
                    k
                    for d in unique_data
                    for k in d.keys()
                    if k
                    not in [
                        "created_at",
                        "plugin",
                        "target",
                        "data",
                        "host_meta",
                        "service_meta",
                    ]
                )
            )
            keys = []
            if "source" in all_keys:
                keys.append("source")
            keys.extend([k for k in all_keys if k != "source"])

        # -- ВСТАВКА: отдельный заголовок секции по центру, перед таблицей --
        section_title = f"{plugin_cfg['category']} / {plugin_name}"
        pad = max(0, (terminal_width - len(section_title)) // 2)
        console.print(" " * pad + section_title, style="bold blue")
        # -- КОНЕЦ ВСТАВКИ --

        # Саму таблицу печатаем без title (title=None)
        table = Table(
            title=None,
            show_lines=True,
        )
        for k in keys:
            max_w = max(15, terminal_width // len(keys)) if k in wide_fields else 20
            table.add_column(
                k.replace("_", " ").title(),
                overflow="fold",
                max_width=max_w,
            )
        for d in unique_data:
            processed = postprocess(d)
            raw_values = [processed.get(k, "-") for k in keys]
            if all(v in ["-", None, ""] for v in raw_values):
                continue
            row_values = [str(v) for v in raw_values]
            table.add_row(*row_values)
        console.print(table)
        if plugin_name in duration_map:
            console.print(
                f"[italic cyan]⏱️ Время сканирования: {duration_map[plugin_name]} сек.[/italic cyan]\n"
            )


# Основная логика генерации отчетов (html, pdf, терминал)
def main(format=None, timestamp=None, clear_reports=False):
    if clear_reports:
        logging.info("Очистка папки reports перед генерацией отчета...")
        for filename in os.listdir(OUTPUT_DIR):
            file_path = os.path.join(OUTPUT_DIR, filename)
            try:
                if os.path.isfile(file_path):
                    os.remove(file_path)
            except Exception as e:
                logging.warning(f"Не удалось удалить файл {filename}: {e}")

    TEMP_PATH = os.path.join("/tmp", f"temp_files_{timestamp}.json")
    duration_map = {}
    if os.path.exists(TEMP_PATH):
        try:
            with open(TEMP_PATH, "r", encoding="utf-8") as f:
                temp_data = json.load(f)
            if isinstance(temp_data, dict):
                duration_list = temp_data.get("durations", [])
                for item in duration_list:
                    if (
                        isinstance(item, dict)
                        and "plugin" in item
                        and "duration" in item
                    ):
                        duration_map[item["plugin"]] = item["duration"]
        except Exception as e:
            logging.warning(f"Не удалось загрузить durations из {TEMP_PATH}: {e}")

    if not timestamp:
        logging.error("Не передан параметр --timestamp, и он обязателен.")
        return

    formats = CONFIG.get("scan_config", {}).get("report_formats", ["html"])
    if format:
        formats = [format]

    # Получаем данные только из snapshot (таблицы)
    results, meta = load_snapshot()

    json_output = os.path.join(OUTPUT_DIR, f"report_{timestamp}.json")
    export_json_report(results, meta, duration_map, json_output)

    if "txt" in formats:
        txt_output = os.path.join(OUTPUT_DIR, f"report_{timestamp}.txt")
        export_txt_report(results, meta, duration_map, txt_output)

    if "terminal" in formats:
        show_in_terminal(results, duration_map)

    if "html" in formats:
        logging.info("Проверка доступности шаблона...")
        logging.info(f"TEMPLATES_DIR = {TEMPLATES_DIR}")
        if not os.path.exists(TEMPLATES_DIR):
            logging.error("Папка шаблонов не найдена!")
            return
        try:
            files = os.listdir(TEMPLATES_DIR)
            logging.info(f"Файлы в шаблоне: {files}")
            if "report.html.j2" not in files:
                logging.error("Файл report.html.j2 не найден в шаблонах!")
                return
        except Exception as e:
            logging.error(f"Ошибка при чтении шаблонов: {e}")
            return
        html_output = os.path.join(OUTPUT_DIR, f"report_{timestamp}.html")
        render_html(results, html_output, meta, duration_map)
        if "pdf" in formats:
            pdf_output = os.path.join(OUTPUT_DIR, f"report_{timestamp}.pdf")
            generate_pdf(html_output, pdf_output)


# Точка входа: аргументы командной строки
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--format", help="Single format for backward compatibility")
    parser.add_argument("--timestamp", help="Timestamp to use in output filename")
    parser.add_argument(
        "--clear-reports",
        action="store_true",
        help="Clear reports folder before generating",
    )
    args = parser.parse_args()
    main(args.format, args.timestamp, clear_reports=args.clear_reports)
