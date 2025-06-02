import asyncio
import json
import logging
import os
import re
import subprocess
import tempfile
from shutil import which

import psycopg2
from core.logger_plugin import setup_plugin_logger
from core.registry import get_targets

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG_PATH = os.path.join(ROOT_DIR, "config", "config.json")
NIKTO_LEVELS_PATH = os.path.join(ROOT_DIR, "config", "plugins", "nikto.json")

container_log = logging.getLogger()
plugin_log = setup_plugin_logger("nikto")


def is_installed() -> bool:
    return which("nikto") is not None and os.path.exists("/opt/nikto/program")


def fix_invalid_json_escapes(s):
    try:
        s = re.sub(r"\\(?![\"\\/bfnrtu])", r"\\\\", s)
        s = s.replace("\r", "\\r").replace("\n", "\\n")
        return s
    except Exception as e:
        raise RuntimeError(
            f"Ошибка при очистке JSON от некорректных escape-символов: {e}"
        )


def run_nikto(target: str, suffix: str, args: str):
    temp_file = tempfile.NamedTemporaryFile(
        delete=False, suffix=f"_{suffix}_nikto.json"
    )
    output_path = temp_file.name
    temp_file.close()

    container_log.info(f"Создан временный файл для Nikto: {output_path}")

    cmd = (
        ["nikto", "-h", target]
        + args.strip().split()
        + ["-Format", "json", "-o", output_path]
    )
    container_log.info(f"Запуск Nikto на {target}: {' '.join(cmd)}")

    result = subprocess.run(cmd, capture_output=True, text=True)

    log_parts = [f"Запуск Nikto на {target}: {' '.join(cmd)}"]
    if result.stdout.strip():
        log_parts.append(result.stdout.strip())
    if result.stderr.strip():
        log_parts.append(f"[STDERR]:\n{result.stderr.strip()}")
    plugin_log.info("\n".join(log_parts))

    if result.returncode != 0:
        raise RuntimeError(f"Nikto завершился с ошибкой: {result.stderr.strip()}")

    if not os.path.exists(output_path):
        raise RuntimeError("Nikto не создал JSON-файл")

    with open(output_path, "r", encoding="utf-8") as f:
        content = f.read().strip()

    if not content:
        raise RuntimeError("Nikto JSON-файл пустой (0 байт)")

    try:
        content = fix_invalid_json_escapes(content)
        data = json.loads(content)
        if not data:
            container_log.warning(
                "Nikto завершился без уязвимостей — JSON пустой список."
            )
    except json.JSONDecodeError:
        raise RuntimeError("Nikto вернул некорректный JSON")

    return output_path


def parse(json_path: str, source_label: str = "unknown", port="-"):
    try:
        with open(json_path, "r", encoding="utf-8") as f:
            raw = f.read()
            raw = fix_invalid_json_escapes(raw)
            data = json.loads(raw)

        if not data or not isinstance(data, list):
            return []

        findings = []
        for item in data:
            for vuln in item.get("vulnerabilities", []):
                findings.append(
                    {
                        "url": vuln.get("url", "-"),
                        "method": vuln.get("method", "-"),
                        "msg": vuln.get("msg", "-"),
                        "id": vuln.get("id", "-"),
                        "references": vuln.get("references", "-"),
                        "source": source_label,
                        "port": port,
                    }
                )

        return findings

    except Exception as e:
        raise RuntimeError(f"Ошибка при парсинге Nikto JSON: {e}")


def get_targets_from_plugins(db_config, plugin_names, target_type, target):
    conn = psycopg2.connect(
        database=db_config["POSTGRES_DB"],
        user=db_config["POSTGRES_USER"],
        password=db_config["POSTGRES_PASSWORD"],
        host=db_config["POSTGRES_HOST"],
        port=db_config["POSTGRES_PORT"],
    )
    cursor = conn.cursor()
    found = set()
    if not plugin_names:
        cursor.close()
        conn.close()
        return []
    placeholders = ",".join(["%s"] * len(plugin_names))
    cursor.execute(
        f"SELECT target, plugin, data FROM results WHERE plugin IN ({placeholders})",
        tuple(plugin_names),
    )
    for row_target, plugin, data in cursor.fetchall():
        try:
            if isinstance(data, str):
                data = json.loads(data)
            if isinstance(data, dict):
                data = [data]
            for d in data:
                if (
                    d.get("state") == "open"
                    and d.get("protocol") == "tcp"
                    and str(d.get("port", "")) not in ["", "-", "0", "None"]
                ):
                    svc = d.get("service_name", "").lower()
                    if any(
                        x in svc
                        for x in [
                            "http",
                            "https",
                            "proxy",
                            "ssl",
                            "web",
                            "jetty",
                            "tomcat",
                        ]
                    ):
                        proto = "https" if "ssl" in svc or "https" in svc else "http"
                        if (
                            target_type == "ip"
                            and re.match(r"^\d{1,3}(\.\d{1,3}){3}$", row_target)
                            and row_target == str(target)
                        ) or (
                            target_type == "domain"
                            and not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", row_target)
                            and row_target == str(target)
                        ):
                            found.add((str(row_target), int(d["port"]), proto))
        except Exception:
            continue
    cursor.close()
    conn.close()
    return list(found)


def get_important_fields():
    return ["msg"]


def get_column_order():
    return ["source", "port", "url", "method", "msg", "id", "references"]


def get_wide_fields():
    return ["url", "msg", "references"]


def should_merge_entries():
    return False


def get_targets_from_registry(target_type, target_value):
    rows = get_targets(
        filter_status="new",
        filter_type=target_type,
        filter_plugin="nmap",
        protocol="tcp",
    )
    out = set()
    for row in rows:
        _, t_type, t_value, port, proto, status, tags, meta = row
        if t_value == target_value:
            proto_detected = "http"
            tags = tags or ""
            meta = meta or ""
            if "ssl" in tags or "https" in tags or "443" in str(port):
                proto_detected = "https"
            out.add((t_value, int(port), proto_detected))
    return out


def build_args(flags: str, ports: list[int], tuning: str) -> str:
    port_str = f"-p {','.join(map(str, ports))}" if ports else ""
    tuning_str = f"-Tuning {tuning}" if tuning else ""
    return f"{tuning_str} {flags} {port_str}".strip()


def get_nikto_conf(level_config, target_type, proto):
    section = level_config.get(target_type, {})
    return section.get(proto, {})


async def scan(config):
    ip = config.get("scan_config", {}).get("target_ip")
    domain = config.get("scan_config", {}).get("target_domain")
    plugin_config = next(
        (p for p in config.get("plugins", []) if p["name"] == "nikto"), {}
    )
    level = plugin_config.get("level", "easy")
    strict_nmap = plugin_config.get("strict_dependencies", False)

    with open(NIKTO_LEVELS_PATH) as f:
        all_levels = json.load(f)
    level_config = all_levels["levels"].get(level, {})

    tasks = []
    sources = []
    added_nikto_targets = set()

    all_targets = []
    if ip:
        all_targets.append(("ip", ip))
    if domain:
        all_targets.append(("domain", domain))

    for target_type, target in all_targets:
        if strict_nmap:
            port_set = get_targets_from_registry(target_type, target)
        else:
            port_set = set()
            for proto in ["http", "https"]:
                conf = level_config.get(target_type, {}).get(proto, {})
                if not conf.get("enabled", False):
                    continue
                for port in conf.get("ports", []):
                    port_set.add((str(target), int(port), proto))

        container_log.info(
            f"Nikto: Итоговый список целей для {target_type} {target}: {sorted(port_set)}"
        )

        for port_tuple in sorted(port_set):
            tgt, port, proto = port_tuple
            conf = get_nikto_conf(level_config, target_type, proto)
            if not conf or not conf.get("enabled", False):
                container_log.info(
                    f"Nikto: Пропуск {tgt}:{port}/{proto} — не включено в конфиге"
                )
                continue
            args = build_args(conf.get("flags", ""), [port], conf.get("tuning", ""))
            suffix = f"{target_type}_{proto}"
            key = (str(tgt), int(port), proto)
            if key in added_nikto_targets:
                continue
            tasks.append(asyncio.to_thread(run_nikto, tgt, suffix, args))

            if strict_nmap:
                depends_on = plugin_config.get("depends_on", [])
                depends_str = "+".join(sorted(dep for dep in depends_on if dep))
                source = (
                    f"{depends_str}_{target_type}_{proto}"
                    if depends_str
                    else f"{target_type}_{proto}"
                )
            else:
                source = f"{target_type}_{proto}"

            sources.append((source, port))
            added_nikto_targets.add(key)

    results = await asyncio.gather(*tasks, return_exceptions=True)
    valid = []
    for path, (src, port) in zip(results, sources):
        if isinstance(path, Exception):
            container_log.error(f"Nikto ошибка в {src}: {path}")
        else:
            valid.append({"plugin": "nikto", "path": path, "source": src, "port": port})
    return valid


if __name__ == "__main__":
    with open(CONFIG_PATH) as f:
        CONFIG = json.load(f)
    result = asyncio.run(scan(CONFIG))
    print(json.dumps(result, indent=2, ensure_ascii=False))
