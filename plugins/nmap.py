import asyncio
import json
import logging
import os
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from collections import Counter

from core.logger_plugin import setup_plugin_logger
from core.registry import add_target
from core.severity import classify_severity

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG_PATH = os.path.join(ROOT_DIR, "config", "config.json")

container_log = logging.getLogger()
plugin_log = setup_plugin_logger("nmap")


# Запуск Nmap и сохранение XML-результата во временный файл
def run_nmap(target: str, suffix: str, args: str):
    container_log = logging.getLogger()
    from core.logger_plugin import setup_plugin_logger

    plugin_log = setup_plugin_logger("nmap")

    temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=f"_{suffix}.xml")
    output_path = temp_file.name
    temp_file.close()

    container_log.info(f"Создан временный файл для Nmap: {output_path}")
    cmd = f"nmap {args} {target} -oX {output_path}"
    container_log.info(f"Запуск Nmap на {target}: {cmd}")

    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

    # Всё, что вывел nmap (stdout+stderr), пишем ТОЛЬКО в плагиновый лог
    full_log = f"Запуск Nmap на {target}: {cmd}\n"
    if result.stdout:
        full_log += result.stdout.strip()
    if result.stderr:
        full_log += f"\n[STDERR]:\n{result.stderr.strip()}"
    plugin_log.info(full_log)

    if result.returncode != 0:
        raise RuntimeError(f"Nmap завершился с ошибкой: {result.stderr.strip()}")

    # --- Новый код: копируем xml-файл в /reports/tmp/ для доступа из html-отчёта ---
    reports_tmp = "/reports/tmp"
    os.makedirs(reports_tmp, exist_ok=True)
    basename = os.path.basename(output_path)
    new_path = os.path.join(reports_tmp, basename)
    shutil.copy2(output_path, new_path)
    container_log.info(f"Копия XML создана: {new_path}")

    return new_path


# Форматирование вывода скриптов (например TLS, сертификаты, уязвимости)
def format_script_output(raw: str) -> str:
    raw = raw.strip()
    if raw == "-" or not raw:
        return "-"
    lines = [
        line.strip()
        for line in raw.splitlines()
        if line.strip() and line.strip() != "-"
    ]
    unique_lines = list(dict.fromkeys(lines))
    sections = []

    # TLS Section
    if any("TLSv1." in l or "TLSv1.3" in l for l in unique_lines):
        tls_lines = []
        current_version = ""
        for line in unique_lines:
            if "TLSv1." in line or "TLSv1.3" in line:
                current_version = line.strip().strip(":")
                tls_lines.append(f"\n{current_version}")
            elif "TLS_" in line or "TLS_AKE_" in line:
                tls_lines.append(f"- {line.strip()}")
        if tls_lines:
            sections.append("[TLS Cipher Support]\n" + "\n".join(tls_lines))
    # Certificate Section
    if any("Subject:" in l or "Valid:" in l for l in unique_lines):
        cert_block = ["[Cert Info]"]
        for key in [
            "Subject:",
            "Subject Alternative Name",
            "Issuer:",
            "Public Key",
            "Signature Algorithm",
            "Not valid",
            "MD5:",
            "SHA-1:",
        ]:
            cert_block.extend([line for line in unique_lines if key in line])
        sections.append("\n".join(cert_block))
    # FTP Section
    if any("FTP" in l or "Anonymous FTP login allowed" in l for l in unique_lines):
        ftp_block = ["[FTP Info]"]
        ftp_block.extend([line for line in unique_lines if "FTP" in line])
        sections.append("\n".join(ftp_block))
    # SSH Section
    if any("SSH" in l for l in unique_lines):
        ssh_block = ["[SSH Info]"]
        ssh_block.extend([line for line in unique_lines if "SSH" in line])
        sections.append("\n".join(ssh_block))
    # HTTP Response Patterns
    if any("/nice ports" in l or "FourOhFourRequest" in l for l in unique_lines):
        http_block = ["[HTTP Response Patterns]"]
        http_block.extend(
            [
                f"- {line}"
                for line in unique_lines
                if any(k in line for k in ["FourOhFourRequest", "Request", "OPTIONS"])
            ]
        )
        sections.append("\n".join(http_block))
    # Vulnerabilities/CVE
    if any("CVE-" in l or "vulnerab" in l.lower() for l in unique_lines):
        vuln_lines = [
            line
            for line in unique_lines
            if "CVE-" in line or "vulnerab" in line.lower()
        ]
        cves = [
            word
            for line in vuln_lines
            for word in line.split()
            if word.startswith("CVE-")
        ]
        cve_counter = Counter(cves)
        counted_cves = sorted(
            [
                f"{cve} (×{count})" if count > 1 else cve
                for cve, count in cve_counter.items()
            ]
        )
        vuln_block = "[Vulnerabilities]\n" + "\n".join(counted_cves + vuln_lines)
        sections.append(vuln_block)
    return "\n\n".join(sections).strip() if sections else "\n".join(unique_lines)


# Парсер XML-результата Nmap для нормализованного вывода (для collector)
def parse(xml_path: str, source_label: str = "unknown"):
    results = []
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
        host = root.find("host")
        ports = host.find("ports") if host is not None else None

        # IP, FQDN, OS из hostinfo
        ip = None
        fqdn = None
        os_name = None
        for addr in host.findall("address") if host is not None else []:
            if addr.attrib.get("addrtype") == "ipv4":
                ip = addr.attrib.get("addr")
        for hostnames in host.findall("hostnames") if host is not None else []:
            hn = hostnames.find("hostname")
            if hn is not None:
                fqdn = hn.attrib.get("name")
        for os_el in host.findall("os") if host is not None else []:
            match = os_el.find("osmatch")
            if match is not None:
                os_name = match.attrib.get("name")

        if ports is not None:
            for port in ports.findall("port"):
                state_el = port.find("state")
                service_el = port.find("service")
                raw_output = (
                    "; ".join(
                        s.attrib.get("output", "") for s in port.findall("script")
                    )
                    or "-"
                )
                data = {
                    "ip": ip,
                    "fqdn": fqdn,
                    "os": os_name,
                    "port": int(port.attrib.get("portid", 0)),
                    "protocol": port.attrib.get("protocol", "-"),
                    "state": (
                        state_el.attrib.get("state", "-")
                        if state_el is not None
                        else "-"
                    ),
                    "reason": (
                        state_el.attrib.get("reason", "-")
                        if state_el is not None
                        else "-"
                    ),
                    "service_name": (
                        service_el.attrib.get("name", "-")
                        if service_el is not None
                        else "-"
                    ),
                    "product": (
                        service_el.attrib.get("product", "-")
                        if service_el is not None
                        else "-"
                    ),
                    "version": (
                        service_el.attrib.get("version", "-")
                        if service_el is not None
                        else "-"
                    ),
                    "extra": (
                        service_el.attrib.get("extrainfo", "-")
                        if service_el is not None
                        else "-"
                    ),
                    "cpe": (
                        service_el.findtext("cpe", default="-")
                        if service_el is not None
                        else "-"
                    ),
                    "script_output": format_script_output(raw_output),
                    "source": source_label,
                    "evidence_path": xml_path,
                    "evidence_type": source_label,
                }
                data["severity"] = classify_severity(data)
                data["host_meta"] = {"os": os_name}
                data["service_meta"] = {"cpe": data["cpe"], "extra": data["extra"]}
                data["vuln_meta"] = {
                    "state": data["state"],
                    "reason": data["reason"],
                    "product": data["product"],
                    "version": data["version"],
                    "extra": data["extra"],
                    "cpe": data["cpe"],
                    "script_output": data["script_output"],
                }
                results.append(data)
    except Exception as e:
        raise RuntimeError(f"Ошибка при парсинге XML файла {xml_path}: {e}")
    return results


# Важные поля для meaningful-логики
def get_important_fields():
    return [
        "port",
        "protocol",
        "state",
        "reason",
        "service_name",
        "product",
        "version",
        "extra",
        "cpe",
        "script_output",
    ]


# Слияние результатов по разным источникам (например, IP+domain)
def merge_sources(a, b):
    return "+".join(sorted(set(a.split("+")) | set(b.split("+"))))


def merge_entries(*entry_lists):
    merged = {}
    important_fields = get_important_fields()

    def is_empty(entry):
        return all(
            str(entry.get(k, "-")).strip() in ["-", "", "null", "None", "0"]
            for k in important_fields
        )

    for entries in entry_lists:
        for entry in [e for e in entries if not is_empty(e)]:
            key = (entry.get("port"), entry.get("protocol"), entry.get("service_name"))
            if key in merged:
                existing = merged[key]
                identical = True
                for k in important_fields:
                    v1 = str(entry.get(k, "-")).strip()
                    v2 = str(existing.get(k, "-")).strip()
                    if v1 in ["-", "", "None", "null"] and v2 in [
                        "-",
                        "",
                        "None",
                        "null",
                    ]:
                        continue
                    if v1 != v2:
                        identical = False
                        break
                if identical:
                    existing["source"] = merge_sources(
                        existing["source"], entry["source"]
                    )
                    if "script_output" in entry and "script_output" in existing:
                        if entry["script_output"] != existing["script_output"]:
                            combined = "\n\n".join(
                                set([existing["script_output"], entry["script_output"]])
                            )
                            existing["script_output"] = format_script_output(combined)
                else:
                    new_key = key + (entry["source"],)
                    merged[new_key] = entry
            else:
                merged[key] = entry
    return list(merged.values())


# Нормализация списка портов
def normalize_ports(port_list):
    normalized = []
    for item in port_list:
        if isinstance(item, int):
            normalized.append(str(item))
        elif isinstance(item, str) and "-" in item:
            normalized.append(item)
        else:
            try:
                normalized.append(str(int(item)))
            except:
                continue
    return ",".join(normalized)


# Асинхронный запуск Nmap сканов по всем профилям (ip, domain, network)
async def scan(config):
    ip = config.get("scan_config", {}).get("target_ip")
    domain = config.get("scan_config", {}).get("target_domain")
    plugin_config = next(
        (p for p in config.get("plugins", []) if p["name"] == "nmap"), {}
    )
    level = plugin_config.get("level", "easy")
    NMAP_LEVELS_PATH = os.path.join(ROOT_DIR, "config", "plugins", "nmap.json")
    with open(NMAP_LEVELS_PATH) as f:
        NMAP_LEVELS = json.load(f)["levels"]
    level_config = NMAP_LEVELS.get(level, {})

    tasks = []
    sources = []

    # IP scan
    if ip:
        for proto, proto_conf in level_config.get("ip", {}).items():
            if not proto_conf.get("enabled", True):
                continue
            if proto_conf.get("flags"):
                ports = proto_conf.get("ports", [])
                ports_str = f"-p {normalize_ports(ports)}" if ports else ""
                scripts = proto_conf.get("scripts", [])
                script_names = []
                script_args = []
                for s in scripts:
                    if isinstance(s, str):
                        script_names.append(s)
                    elif isinstance(s, dict) and "name" in s:
                        script_names.append(s["name"])
                        if "args" in s and s["args"]:
                            script_args.append(s["args"].replace('"', "'"))
                parts = [
                    proto_conf["flags"],
                    ports_str,
                    f"--script {','.join(script_names)}" if script_names else "",
                    f"--script-args {','.join(script_args)}" if script_args else "",
                ]
                full_args = " ".join(part for part in parts if part).strip()
                tasks.append(asyncio.to_thread(run_nmap, ip, f"ip_{proto}", full_args))
                sources.append(f"ip_{proto}")

    # Domain scan
    if domain:
        for proto, proto_conf in level_config.get("domain", {}).items():
            if not proto_conf.get("enabled", True):
                continue
            if proto_conf.get("flags"):
                ports = proto_conf.get("ports", [])
                ports_str = f"-p {normalize_ports(ports)}" if ports else ""
                scripts = proto_conf.get("scripts", [])
                script_names = []
                script_args = []
                for s in scripts:
                    if isinstance(s, str):
                        script_names.append(s)
                    elif isinstance(s, dict) and "name" in s:
                        script_names.append(s["name"])
                        if "args" in s and s["args"]:
                            script_args.append(s["args"].replace('"', "'"))
                parts = [
                    proto_conf["flags"],
                    ports_str,
                    f"--script {','.join(script_names)}" if script_names else "",
                    f"--script-args {','.join(script_args)}" if script_args else "",
                ]
                full_args = " ".join(part for part in parts if part).strip()
                tasks.append(
                    asyncio.to_thread(run_nmap, domain, f"domain_{proto}", full_args)
                )
                sources.append(f"domain_{proto}")

    # Network scan (по /24)
    network = config.get("scan_config", {}).get("target_network")
    if network:
        for proto, proto_conf in level_config.get("network", {}).items():
            if not proto_conf.get("enabled", True):
                continue
            if proto_conf.get("flags"):
                ports = proto_conf.get("ports", [])
                ports_str = f"-p {normalize_ports(ports)}" if ports else ""
                scripts = proto_conf.get("scripts", [])
                script_names = []
                script_args = []
                for s in scripts:
                    if isinstance(s, str):
                        script_names.append(s)
                    elif isinstance(s, dict) and "name" in s:
                        script_names.append(s["name"])
                        if "args" in s and s["args"]:
                            script_args.append(s["args"].replace('"', "'"))
                parts = [
                    proto_conf["flags"],
                    ports_str,
                    f"--script {','.join(script_names)}" if script_names else "",
                    f"--script-args {','.join(script_args)}" if script_args else "",
                ]
                full_args = " ".join(part for part in parts if part).strip()
                tasks.append(
                    asyncio.to_thread(run_nmap, network, f"network_{proto}", full_args)
                )
                sources.append(f"network_{proto}")

    results = await asyncio.gather(*tasks)

    # После каждого скана, парсим XML и добавляем цели в registry
    for path, src in zip(results, sources):
        entries = parse(path, src)
        for ent in entries:
            # Добавляем только открытые web-порты (http/https)
            if (
                ent.get("state") == "open"
                and ent.get("protocol") == "tcp"
                and ent.get("service_name", "").lower() in ["http", "https"]
            ):
                add_target(
                    target_type="ip" if "ip" in src else "domain",
                    target_value=(
                        config.get("scan_config", {}).get("target_ip")
                        if "ip" in src
                        else config.get("scan_config", {}).get("target_domain")
                    ),
                    port=ent.get("port"),
                    protocol=ent.get("protocol"),
                    source_plugin="nmap",
                    tags=["web"],
                    meta={"service": ent.get("service_name")},
                )

    return [
        {"plugin": "nmap", "path": path, "source": src}
        for path, src in zip(results, sources)
    ]


# Метаданные для генератора/таблиц/отчетов
def get_summary(data):
    return " | ".join(
        f"{d.get('port', '?')}/{d.get('protocol', '?')} {d.get('state', '?')}"
        for d in data
        if isinstance(d, dict)
    )


def get_column_order():
    return [
        "source",
        "port",
        "protocol",
        "state",
        "reason",
        "service_name",
        "product",
        "version",
        "extra",
        "cpe",
        "details",
        "severity",
    ]


def get_wide_fields():
    return ["details", "extra", "cpe"]


def get_view_rows(snapshot):
    results = []
    for vuln in snapshot.get("vuln", []):
        if vuln.get("plugin") == "nmap":
            service = None
            if vuln.get("service_id"):
                service = next(
                    (
                        s
                        for s in snapshot.get("services", [])
                        if s["id"] == vuln["service_id"]
                    ),
                    None,
                )
            merged = vuln.copy()
            if service:
                merged.update(
                    {
                        "port": service.get("port"),
                        "protocol": service.get("protocol"),
                        "service_name": service.get("service_name"),
                        "product": service.get("product"),
                        "version": service.get("version"),
                        "extra": (service.get("meta") or {}).get("extra", "-"),
                        "cpe": (service.get("meta") or {}).get("cpe", "-"),
                    }
                )
            meta = vuln.get("meta", {}) or {}
            merged["state"] = meta.get("state", "-")
            merged["reason"] = meta.get("reason", "-")

            desc = (vuln.get("description") or "-").strip()
            script_out = meta.get("script_output", "-")
            if desc and script_out and script_out != "-" and script_out != desc:
                merged["details"] = f"{desc}\n\n{script_out}"
            elif script_out and script_out != "-":
                merged["details"] = script_out
            elif desc:
                merged["details"] = desc
            else:
                merged["details"] = "-"

            results.append(merged)

    return results


def should_merge_entries():
    return True


def postprocess_result(entry):
    cleaned = {}
    for k, v in entry.items():
        val = str(v).strip()
        if val in ["", "None", "null"]:
            cleaned[k] = "-"
        else:
            cleaned[k] = val
    if "script_output" in cleaned:
        cleaned["script_output"] = format_script_output(cleaned["script_output"])
    return cleaned


if __name__ == "__main__":
    with open(CONFIG_PATH) as f:
        CONFIG = json.load(f)
    result = asyncio.run(scan(CONFIG))
    print(json.dumps(result, indent=2, ensure_ascii=False))
