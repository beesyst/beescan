import os
import sys

sys.path.insert(0, "/")

import argparse
import asyncio
import importlib.util
import json
import logging
import shutil
import subprocess
import time

from core.logger_container import setup_container_logger
from core.logger_plugin import clear_plugin_logs_if_needed

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG_PATH = os.path.join(ROOT_DIR, "config", "config.json")
PLUGINS_DIR = os.path.join(ROOT_DIR, "plugins")

with open(CONFIG_PATH) as f:
    CONFIG = json.load(f)

setup_container_logger()
clear_plugin_logs_if_needed(CONFIG)
PLUGINS = CONFIG.get("plugins", [])
SCAN_CONFIG = CONFIG.get("scan_config", {})
TARGET_IP = SCAN_CONFIG.get("target_ip")
TARGET_DOMAIN = SCAN_CONFIG.get("target_domain")

if not TARGET_IP and not TARGET_DOMAIN:
    raise ValueError(
        "Не указан ни target_ip, ни target_domain в конфиге. Укажите хотя бы один."
    )


def is_tool_installed(tool_name):
    try:
        plugin_path = os.path.join(PLUGINS_DIR, f"{tool_name}.py")
        if os.path.exists(plugin_path):
            spec = importlib.util.spec_from_file_location(tool_name, plugin_path)
            plugin_module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(plugin_module)
            if hasattr(plugin_module, "is_installed"):
                return plugin_module.is_installed()
    except Exception as e:
        logging.warning(f"Не удалось проверить установлен ли {tool_name}: {e}")

    return shutil.which(tool_name) is not None


def get_tool_version(tool_name, version_arg="--version"):
    try:
        result = subprocess.run(
            [tool_name, version_arg], capture_output=True, text=True
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except Exception:
        pass
    return None


async def install_plugin(plugin):
    name = plugin["name"]
    required_version = plugin.get("version")
    install_cmds = plugin.get("install", [])

    if not install_cmds:
        return True

    already_installed = is_tool_installed(name)
    if already_installed:
        if required_version:
            version = get_tool_version(name)
            if version and required_version not in version:
                logging.info(f"{name} найдена, но версия устарела! Обновляем...")
                for cmd in install_cmds:
                    if "install" in cmd:
                        cmd = cmd.replace("install -y", "install --reinstall -y")
                    logging.info(f"Выполняется команда: {cmd}")
                    process = await asyncio.create_subprocess_shell(
                        cmd,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )
                    await process.communicate()
                return True
            else:
                logging.info(f"{name} уже свежая версия.")
                return True
        else:
            logging.info(f"{name} уже установлен. Пропускаем установку.")
            return True

    logging.info(f"Установка зависимостей для {name}...")
    is_root = os.geteuid() == 0

    for cmd in install_cmds:
        if not is_root:
            cmd = f"sudo {cmd}"
        logging.info(f"Выполняется команда: {cmd}")
        process = await asyncio.create_subprocess_shell(
            cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await process.communicate()
        if process.returncode != 0:
            logging.error(
                f"Установка {name} не удалась на команде: {cmd}\n{stderr.decode().strip()}"
            )
            return False
    logging.info(f"{name} успешно установлен.")
    return True


async def run_plugin(plugin):
    name = plugin["name"]

    if not plugin.get("enabled", False):
        logging.info(f"Плагин {name} отключен в конфиге. Пропускаем.")
        return name, ([], 0)

    success = await install_plugin(plugin)
    if not success:
        return name, ([], 0)

    plugin_path = os.path.join(PLUGINS_DIR, f"{name}.py")
    if not os.path.exists(plugin_path):
        logging.error(f"Файл плагина {plugin_path} не найден!")
        return name, ([], 0)

    try:
        spec = importlib.util.spec_from_file_location(name, plugin_path)
        loaded_plugin = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(loaded_plugin)

        if hasattr(loaded_plugin, "scan"):
            logging.info(f"Запуск функции scan() из плагина {name}...")
            start = time.time()
            temp_paths = await loaded_plugin.scan(CONFIG)
            duration = round(time.time() - start, 2)
            logging.info(f"Плагин {name} успешно завершил работу за {duration} сек.")

            paths = []
            if isinstance(temp_paths, list):
                for path in temp_paths:
                    if isinstance(path, str):
                        paths.append({"plugin": name, "path": path})
                    elif isinstance(path, dict):
                        paths.append(path)
            elif isinstance(temp_paths, str):
                paths.append({"plugin": name, "path": temp_paths})
            return name, (paths, duration)
        else:
            logging.error(f"Плагин {name} не содержит функцию scan(). Пропускаем.")
            return name, ([], 0)
    except Exception as e:
        logging.exception(f"Ошибка при запуске плагина {name}: {e}")
        return name, ([], 0)


def plugins_have_dependencies(plugins):
    return any(
        p.get("enabled") and p.get("strict_dependencies", False) for p in plugins
    )


async def main():
    if plugins_have_dependencies(PLUGINS):
        from core.orchestrator import orchestrate

        logging.info("Обнаружены зависимости между плагинами, запуск orchestrator!")
        results, duration_map = await orchestrate(CONFIG)
        generated_temp_paths = []
        for plugin, plugin_paths in results.items():
            if isinstance(plugin_paths, list):
                generated_temp_paths.extend(plugin_paths)
            elif isinstance(plugin_paths, dict):
                generated_temp_paths.append(plugin_paths)
        return generated_temp_paths, duration_map
    else:
        logging.info("Зависимости не обнаружены, запуск плагинов в параллели.")
        tasks = [run_plugin(plugin) for plugin in PLUGINS if plugin.get("enabled")]
        results = await asyncio.gather(*tasks)

        generated_temp_paths = []
        duration_map = {}
        for name, (paths, duration) in results:
            if paths:
                generated_temp_paths.extend(paths)
            duration_map[name] = duration
        return generated_temp_paths, duration_map


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        required=True,
        help="Путь для сохранения JSON-файла с результатами сканирования",
    )
    args = parser.parse_args()

    paths, duration_map = asyncio.run(main())

    combined_data = {
        "paths": paths,
        "durations": [{"plugin": k, "duration": v} for k, v in duration_map.items()],
    }

    try:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(combined_data, f, ensure_ascii=False, indent=2)
        logging.info(f"Сохранены пути и duration-данные: {args.output}")
    except Exception as e:
        logging.error(f"Ошибка записи JSON-файлов: {e}")
        print(f"❌ Ошибка записи JSON: {e}")
        exit(1)
