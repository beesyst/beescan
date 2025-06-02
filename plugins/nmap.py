import asyncio
import json
import logging
import os
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


def run_nmap(target: str, suffix: str, args: str):
    temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=f"_{suffix}.xml")
    output_path = temp_file.name
    temp_file.close()

    container_log.info(f"Создан временный файл для Nmap: {output_path}")

    cmd = f"nmap {args} {target} -oX {output_path}"
    container_log.info(f"Запуск Nmap на {target}: {cmd}")

    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

    full_log = f"Запуск Nmap на {target}: {cmd}\n"

    if result.stdout:
        full_log += result.stdout.strip()

    if result.stderr:
        full_log += f"\n[STDERR]:\n{result.stderr.strip()}"

    plugin_log.info(full_log)

    if result.returncode != 0:
        raise RuntimeError(f"Nmap завершился с ошибкой: {result.stderr.strip()}")

    return output_path


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

    if any("FTP" in l or "Anonymous FTP login allowed" in l for l in unique_lines):
        ftp_block = ["[FTP Info]"]
        ftp_block.extend([line for line in unique_lines if "FTP" in line])
        sections.append("\n".join(ftp_block))

    if any("SSH" in l for l in unique_lines):
        ssh_block = ["[SSH Info]"]
        ssh_block.extend([line for line in unique_lines if "SSH" in line])
        sections.append("\n".join(ssh_block))

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


def parse(xml_path: str, source_label: str = "unknown"):
    results = []
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
        host = root.find("host")
        ports = host.find("ports") if host is not None else None

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
                }

                data["severity"] = classify_severity(data)
                results.append(data)

    except Exception as e:
        raise RuntimeError(f"Ошибка при парсинге XML файла {xml_path}: {e}")

    return results


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
                                filter(
                                    None,
                                    set(
                                        [
                                            existing["script_output"],
                                            entry["script_output"],
                                        ]
                                    ),
                                )
                            )
                            existing["script_output"] = format_script_output(combined)
                else:
                    new_key = key + (entry["source"],)
                    merged[new_key] = entry
            else:
                merged[key] = entry

    return list(merged.values())


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

                script_str = (
                    f'--script "{",".join(script_names)}"' if script_names else ""
                )
                args_str = (
                    f'--script-args "{",".join(script_args)}"' if script_args else ""
                )
                full_args = (
                    f"{proto_conf['flags']} {ports_str} {script_str} {args_str}".strip()
                )
                tasks.append(
                    asyncio.to_thread(run_nmap, domain, f"domain_{proto}", full_args)
                )
                sources.append(f"domain_{proto}")

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
                script_str = (
                    f'--script "{",".join(script_names)}"' if script_names else ""
                )
                args_str = (
                    f'--script-args "{",".join(script_args)}"' if script_args else ""
                )
                full_args = (
                    f"{proto_conf['flags']} {ports_str} {script_str} {args_str}".strip()
                )
                tasks.append(
                    asyncio.to_thread(run_nmap, network, f"network_{proto}", full_args)
                )
                sources.append(f"network_{proto}")

    results = await asyncio.gather(*tasks)

    # После каждого скана, парсим XML и добавляем цели в registry
    for path, src in zip(results, sources):
        entries = parse(path, src)
        for ent in entries:
            # Только открытые веб-порты (http/https/web)
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
        "script_output",
    ]


def get_wide_fields():
    return ["product", "version", "extra", "script_output", "cpe"]


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
