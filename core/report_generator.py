import os
import sys

sys.path.insert(0, "/")

import argparse
import importlib
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


def connect_to_db():
    return psycopg2.connect(
        database=DB_CONFIG["POSTGRES_DB"],
        user=DB_CONFIG["POSTGRES_USER"],
        password=DB_CONFIG["POSTGRES_PASSWORD"],
        host=DB_CONFIG["POSTGRES_HOST"],
        port=DB_CONFIG["POSTGRES_PORT"],
    )


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


def get_jinja_env():
    env = Environment(loader=FileSystemLoader(TEMPLATES_DIR))
    env.filters["highlight_keywords"] = highlight_keywords
    return env


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


def sort_categories_by_priority(raw_results):
    category_order = CONFIG.get("report_category_order", [])
    order = {cat: idx for idx, cat in enumerate(category_order)}
    return OrderedDict(
        sorted(raw_results.items(), key=lambda item: order.get(item[0], 999))
    )


def load_and_categorize_results():
    raw_entries = []
    conn = connect_to_db()
    cursor = conn.cursor()

    try:
        cursor.execute(
            "SELECT target, category, data, created_at, plugin FROM results ORDER BY created_at DESC"
        )
        rows = cursor.fetchall()

        for row in rows:
            target, category, data, created_at, plugin = row

            if isinstance(data, str):
                try:
                    data = json.loads(data)
                except Exception:
                    pass

            raw_entries.append(
                {
                    "target": target,
                    "category": category,
                    "data": data,
                    "created_at": created_at.strftime("%Y-%m-%d %H:%M:%S"),
                    "plugin": plugin,
                }
            )

    except Exception as e:
        logging.error(f"Ошибка при загрузке из results: {e}")

    cursor.close()
    conn.close()

    return categorize_results(raw_entries)


def render_html(results, output_path, meta, duration_map):
    logging.info(f"Поиск шаблона в: {TEMPLATES_DIR}")
    env = get_jinja_env()

    try:
        template = env.get_template("report.html.j2")
    except Exception as e:
        logging.error(f"Ошибка загрузки шаблона: {e}")
        raise

    theme = CONFIG.get("scan_config", {}).get("report_theme", "light")

    rendered = template.render(
        structured_results=results,
        generation_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        report_theme=theme,
        config=CONFIG,
        meta=meta,
        duration_map=duration_map,
    )

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(rendered)

    logging.info(f"HTML-отчет создан: {output_path}")


def generate_pdf(html_path, pdf_path):
    HTML(html_path).write_pdf(pdf_path)
    logging.info(f"PDF-отчет создан: {pdf_path}")


def wrap_cell(value, width=80):
    return "\n".join(
        textwrap.wrap(
            str(value), width=width, break_long_words=True, replace_whitespace=False
        )
    )


def show_in_terminal(results, duration_map):
    terminal_width = shutil.get_terminal_size((160, 20)).columns
    console = Console(width=terminal_width)

    for category, plugins in results.items():
        for plugin_name, entries in plugins.items():
            if not isinstance(entries, list):
                continue

            all_data = []
            for entry in entries:
                data = entry.get("data")
                if isinstance(data, list) and all(isinstance(d, dict) for d in data):
                    all_data.extend(data)
                elif isinstance(data, dict):
                    all_data.append(data)

            if not all_data:
                continue

            important_fields = []
            merge_enabled = True

            try:
                plugin_module = importlib.import_module(f"plugins.{plugin_name}")
                if hasattr(plugin_module, "get_important_fields"):
                    important_fields = plugin_module.get_important_fields()
                if hasattr(plugin_module, "should_merge_entries"):
                    merge_enabled = plugin_module.should_merge_entries()
            except Exception:
                pass

            if important_fields:

                def is_meaningful(entry):
                    return not all(
                        str(entry.get(k, "-")).strip() in ["-", "", "null", "None", "0"]
                        for k in important_fields
                    )

                all_data = [d for d in all_data if is_meaningful(d)]

            if merge_enabled:
                seen = {}
                for d in all_data:
                    key = (d.get("port"), d.get("protocol"), d.get("service_name"))
                    if key in seen:
                        existing = seen[key]
                        existing_sources = set(existing.get("source", "").split("+"))
                        new_sources = set(d.get("source", "").split("+"))
                        combined_sources = sorted(existing_sources.union(new_sources))
                        existing["source"] = "+".join(combined_sources)
                    else:
                        seen[key] = d
                unique_data = list(seen.values())
            else:
                unique_data = all_data

            if not unique_data:
                continue

            all_keys = list(
                dict.fromkeys(
                    k
                    for d in unique_data
                    for k in d.keys()
                    if k not in ["severity", "created_at", "plugin", "target", "data"]
                )
            )
            if "severity" not in all_keys:
                all_keys.append("severity")

            column_order = None
            wide_fields = []
            try:
                if not plugin_module:
                    plugin_module = importlib.import_module(f"plugins.{plugin_name}")
                if hasattr(plugin_module, "get_column_order"):
                    column_order = plugin_module.get_column_order()
                if hasattr(plugin_module, "get_wide_fields"):
                    wide_fields = plugin_module.get_wide_fields()
            except Exception:
                pass

            if column_order:
                keys = []
                if "source" in all_keys:
                    keys.append("source")
                keys.extend(
                    [k for k in column_order if k in all_keys and k != "source"]
                )
                keys.extend([k for k in all_keys if k not in keys])
                if "severity" not in keys:
                    keys.append("severity")
                else:
                    keys.append("severity")
            else:
                keys = []
                if "source" in all_keys:
                    keys.append("source")
                keys.extend([k for k in all_keys if k != "source"])

            table = Table(
                title=f"[bold blue]{category} / {plugin_name}", show_lines=True
            )

            for k in keys:
                max_w = max(15, terminal_width // len(keys)) if k in wide_fields else 20
                table.add_column(
                    k.replace("_", " ").title(),
                    overflow="fold",
                    max_width=max_w,
                )

            for d in unique_data:
                raw_values = [d.get(k, "-") for k in keys]
                if all(v in ["-", None, ""] for v in raw_values):
                    continue
                row_values = [str(v) for v in raw_values]
                table.add_row(*row_values)

            console.print(table)
            if plugin_name in duration_map:
                console.print(
                    f"[italic cyan]⏱️ Время сканирования: {duration_map[plugin_name]} сек.[/italic cyan]\n"
                )


def main(format=None, timestamp=None, clear_reports=False):
    TEMP_PATH = os.path.join("/tmp", f"temp_files_{timestamp}.json")
    duration_map = {}

    if os.path.exists(TEMP_PATH):
        try:
            with open(TEMP_PATH, "r", encoding="utf-8") as f:
                temp_data = json.load(f)

            # Новый формат: один файл с двумя ключами
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

    raw_results, meta = load_and_categorize_results()
    results = sort_categories_by_priority(raw_results)

    for target_data in results.values():
        for plugin_name, plugin_data in target_data.items():
            try:
                plugin_module = importlib.import_module(f"plugins.{plugin_name}")
                if hasattr(plugin_module, "postprocess_result"):
                    for entry in plugin_data:
                        if isinstance(entry.get("data"), list):
                            entry["data"] = [
                                plugin_module.postprocess_result(row)
                                for row in entry["data"]
                            ]
            except Exception as e:
                logging.warning(f"Ошибка при постобработке плагина {plugin_name}: {e}")

    if not timestamp:
        logging.error("Не передан параметр --timestamp, и он обязателен.")
        return

    formats = CONFIG.get("scan_config", {}).get("report_formats", ["html"])
    if format:
        formats = [format]

    if clear_reports:
        logging.info("Очистка папки reports перед генерацией отчёта...")
        for filename in os.listdir(OUTPUT_DIR):
            file_path = os.path.join(OUTPUT_DIR, filename)
            try:
                if os.path.isfile(file_path):
                    os.remove(file_path)
            except Exception as e:
                logging.warning(f"Не удалось удалить файл {filename}: {e}")

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
