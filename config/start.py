import glob
import json
import logging
import os
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT_DIR)

from core.logger_container import clear_container_log_if_needed
from core.logger_host import setup_host_logger

CONFIG_PATH = os.path.join(ROOT_DIR, "config", "config.json")
LOGS_PATH = os.path.join(ROOT_DIR, "logs", "host.log")

with open(CONFIG_PATH, "r") as config_file:
    CONFIG = json.load(config_file)

setup_host_logger(CONFIG)
clear_container_log_if_needed(CONFIG)

DB_CONTAINER = CONFIG["database"]["container_name"]
NETWORK_NAME = CONFIG["docker_network"]


# Упрощённый CLI-спиннер: чередует [+] и [-] внутри одной строки
def spinner(
    prefix: str, stop_event: threading.Event, success_event: threading.Event = None
):
    symbols = ["[+]", "[-]"]
    i = 0
    while not stop_event.is_set():
        sys.stdout.write(f"\r{symbols[i % 2]} {prefix}")
        sys.stdout.flush()
        i += 1
        time.sleep(0.18)
    # После завершения: [+] если успех, [-] если ошибка
    if success_event and success_event.is_set():
        sys.stdout.write(f"\r[+] {prefix}\n")
    else:
        sys.stdout.write(f"\r[-] {prefix}\n")
    sys.stdout.flush()


# Универсальный запуск shell-команды
def run_command(command, cwd=None, hide_output=True):
    logging.info(f"Выполнение команды: {command}")
    result = subprocess.run(
        command,
        shell=True,
        cwd=cwd,
        stdout=subprocess.DEVNULL if hide_output else None,
        stderr=subprocess.DEVNULL if hide_output else None,
    )
    if result.returncode != 0:
        logging.error(f"Ошибка выполнения команды: {command}")
        return False
    return True


# Проверка установки Docker
def check_docker_installed():
    stage = "Проверка Docker"
    stop_event = threading.Event()
    ok_event = threading.Event()
    spinner_thread = threading.Thread(
        target=spinner, args=(stage, stop_event, ok_event)
    )
    spinner_thread.start()
    try:
        subprocess.run(["docker", "--version"], check=True, stdout=subprocess.DEVNULL)
        logging.info("Docker установлен.")
        ok_event.set()
    except subprocess.CalledProcessError:
        logging.critical("Docker не установлен!")
    finally:
        stop_event.set()
        spinner_thread.join()
    if not ok_event.is_set():
        sys.exit(1)


# Проверка/создание docker-сети
def clean_docker_environment():
    stage = f"Сеть {NETWORK_NAME}"
    stop_event = threading.Event()
    ok_event = threading.Event()
    spinner_thread = threading.Thread(
        target=spinner, args=(stage, stop_event, ok_event)
    )
    spinner_thread.start()
    result = subprocess.run(
        ["docker", "network", "ls", "-q", "--filter", f"name={NETWORK_NAME}"],
        stdout=subprocess.PIPE,
        text=True,
    )
    try:
        if not result.stdout.strip():
            logging.info(f"Сеть {NETWORK_NAME} не найдена. Создание...")
            created = run_command(f"docker network create {NETWORK_NAME}")
            if created:
                logging.info(f"Создана сеть Docker: {NETWORK_NAME}")
                ok_event.set()
        else:
            logging.info(f"Сеть {NETWORK_NAME} уже существует.")
            ok_event.set()
    finally:
        stop_event.set()
        spinner_thread.join()
    if not ok_event.is_set():
        sys.exit(1)


# Запуск PostgreSQL-контейнера
def wait_postgres_ready_from_logs(container_name, timeout=90):
    start_time = time.time()
    while time.time() - start_time < timeout:
        log_result = subprocess.run(
            ["docker", "logs", container_name],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        if "database system is ready to accept connections" in log_result.stdout:
            return True
        time.sleep(2)
    return False


def start_postgres():
    stage = "PostgreSQL"
    stop_event = threading.Event()
    ok_event = threading.Event()
    spinner_thread = threading.Thread(
        target=spinner, args=(stage, stop_event, ok_event)
    )
    spinner_thread.start()
    try:
        result = subprocess.run(
            ["docker", "ps", "-q", "--filter", f"name={DB_CONTAINER}"],
            stdout=subprocess.PIPE,
            text=True,
        )
        if result.stdout.strip():
            logging.info("PostgreSQL уже работает.")
            ok_event.set()
            return

        logging.info("Контейнер PostgreSQL не найден. Запуск...")
        run_command(
            "docker compose -f db/compose.yaml up --build -d",
            cwd=ROOT_DIR,
            hide_output=True,
        )

        time.sleep(2)

        ready = False
        for i in range(10):  # 10 попыток по 1.5 сек (макс 15 сек)
            result = subprocess.run(
                [
                    "docker",
                    "exec",
                    DB_CONTAINER,
                    "pg_isready",
                    "-U",
                    CONFIG["database"]["POSTGRES_USER"],
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            if result.returncode == 0:
                ready = True
                break
            time.sleep(1.5)

        if not ready:
            logging.info("pg_isready не ответил — ждём по логам готовности Postgres...")
            ready = wait_postgres_ready_from_logs(DB_CONTAINER, timeout=90)

        if ready:
            try:
                ver_result = subprocess.run(
                    [
                        "docker",
                        "exec",
                        DB_CONTAINER,
                        "psql",
                        "-U",
                        CONFIG["database"]["POSTGRES_USER"],
                        "-d",
                        CONFIG["database"]["POSTGRES_DB"],
                        "-c",
                        "SELECT version();",
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                if ver_result.returncode == 0 and "PostgreSQL" in ver_result.stdout:
                    version_line = [
                        line
                        for line in ver_result.stdout.splitlines()
                        if "PostgreSQL" in line
                    ]
                    if version_line:
                        logging.info(
                            f"{version_line[0].strip()} запущен и готов к работе."
                        )
                else:
                    logging.info("PostgreSQL запущен и готов к работе.")
            except Exception:
                logging.info("PostgreSQL запущен и готов к работе.")
            ok_event.set()
    finally:
        stop_event.set()
        spinner_thread.join()
    if not ok_event.is_set():
        try:
            log_result = subprocess.run(
                ["docker", "logs", DB_CONTAINER],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
            with open(os.path.join(ROOT_DIR, "logs", "postgres_last.log"), "w") as f:
                f.write(log_result.stdout)
        except Exception as e:
            logging.error(f"Не удалось получить логи postgres: {e}")
        logging.critical("PostgreSQL не стартовал вовремя!")
        sys.exit(1)


# Проверка и сборка docker-образа beescan-base
def ensure_beescan_base_image():
    stage = "Образ beescan-base"
    stop_event = threading.Event()
    ok_event = threading.Event()
    spinner_thread = threading.Thread(
        target=spinner, args=(stage, stop_event, ok_event)
    )
    spinner_thread.start()
    try:
        result = subprocess.run(
            ["docker", "images", "-q", "beescan-base"],
            stdout=subprocess.PIPE,
            text=True,
        )
        if not result.stdout.strip():
            logging.info("Образ beescan-base не найден. Запуск сборки...")
            success = run_command(
                "docker build -t beescan-base -f docker/Dockerfile.base .", cwd=ROOT_DIR
            )
            if success:
                logging.info("Сборка beescan-base завершена успешно.")
                ok_event.set()
        else:
            logging.info("Образ beescan-base найден.")
            ok_event.set()
    finally:
        stop_event.set()
        spinner_thread.join()
    if not ok_event.is_set():
        logging.critical("Сборка beescan-base не удалась.")
        sys.exit(1)


# Запуск контейнера beescan_base
def start_beescan_container():
    stage = "Контейнер beescan_base"
    stop_event = threading.Event()
    ok_event = threading.Event()
    spinner_thread = threading.Thread(
        target=spinner, args=(stage, stop_event, ok_event)
    )
    spinner_thread.start()
    try:
        result = subprocess.run(
            ["docker", "ps", "-q", "--filter", "name=beescan_base"],
            stdout=subprocess.PIPE,
            text=True,
        )
        if result.stdout.strip():
            logging.info("Контейнер beescan_base уже запущен.")
            ok_event.set()
            return

        result_all = subprocess.run(
            ["docker", "ps", "-aq", "--filter", "name=beescan_base"],
            stdout=subprocess.PIPE,
            text=True,
        )
        if result_all.stdout.strip():
            logging.info("Удаление остановленного контейнера beescan_base.")
            subprocess.run(["docker", "rm", "-f", "beescan_base"])

        logging.info("Запуск контейнера beescan_base...")
        volumes = [
            "-v",
            f"{os.path.join(ROOT_DIR, 'core')}:/core",
            "-v",
            f"{os.path.join(ROOT_DIR, 'logs')}:/logs",
            "-v",
            f"{os.path.join(ROOT_DIR, 'config')}:/config",
            "-v",
            f"{os.path.join(ROOT_DIR, 'templates')}:/templates",
            "-v",
            f"{os.path.join(ROOT_DIR, 'reports')}:/reports",
            "-v",
            f"{os.path.join(ROOT_DIR, 'reports', 'tmp')}:/reports/tmp",
            "-v",
            f"{os.path.join(ROOT_DIR, 'plugins')}:/plugins",
            "-v",
            "/etc/timezone:/etc/timezone:ro",
            "-v",
            "/etc/localtime:/etc/localtime:ro",
        ]
        success = run_command(
            f"docker run -d --name beescan_base --network {NETWORK_NAME} "
            + " ".join(volumes)
            + " beescan-base tail -f /dev/null",
            cwd=ROOT_DIR,
        )
        if success:
            logging.info("Контейнер beescan_base запущен успешно.")
            ok_event.set()
    finally:
        stop_event.set()
        spinner_thread.join()
    if not ok_event.is_set():
        logging.critical("Контейнер beescan_base не удалось запустить.")
        sys.exit(1)


# Очистка базы данных если clear_db=true
def purge_database():
    stage = "Очистка базы данных"
    if CONFIG.get("scan_config", {}).get("clear_db", False):
        stop_event = threading.Event()
        ok_event = threading.Event()
        spinner_thread = threading.Thread(
            target=spinner, args=(stage, stop_event, ok_event)
        )
        spinner_thread.start()
        try:
            success = run_command(
                "docker exec beescan_base python3 /core/collector.py --purge-only",
                hide_output=True,
            )
            if success:
                logging.info("Очистка базы данных перед сканированием")
                ok_event.set()
        finally:
            stop_event.set()
            spinner_thread.join()
        if not ok_event.is_set():
            logging.critical("Очистка базы данных не удалась.")
            sys.exit(1)
    else:
        logging.info("Флаг clear_db=false. Пропуск очистки базы.")


# Очистка временных XML-файлов
def cleanup_all_tmp_files():
    stage = "Удаление временных файлов"
    stop_event = threading.Event()
    ok_event = threading.Event()
    spinner_thread = threading.Thread(
        target=spinner, args=(stage, stop_event, ok_event)
    )
    spinner_thread.start()
    try:
        # Системный /tmp (xml, которые генерят плагины)
        tmp_dir = tempfile.gettempdir()
        tmp_patterns = [f"{tmp_dir}/*_ip.xml", f"{tmp_dir}/*_domain_*.xml"]
        files_deleted = 0
        for pattern in tmp_patterns:
            for f in glob.glob(pattern):
                try:
                    os.remove(f)
                    logging.info(f"Удалён временный файл: {f}")
                    files_deleted += 1
                except Exception as e:
                    logging.warning(f"Не удалось удалить {f}: {e}")

        # Папка beescan/reports/tmp
        reports_tmp = os.path.join(ROOT_DIR, "reports", "tmp")
        if os.path.isdir(reports_tmp):
            for filename in os.listdir(reports_tmp):
                file_path = os.path.join(reports_tmp, filename)
                try:
                    if os.path.isfile(file_path):
                        os.remove(file_path)
                        logging.info(f"Удален файл из reports/tmp: {file_path}")
                        files_deleted += 1
                except Exception as e:
                    logging.warning(f"Не удалось удалить {file_path}: {e}")
        else:
            os.makedirs(reports_tmp, exist_ok=True)

        if files_deleted >= 0:
            ok_event.set()
    finally:
        stop_event.set()
        spinner_thread.join()


# Запуск всех плагинов через plugin_runner.py
def run_plugins(temp_files_path):
    stage = "Запуск плагинов"
    stop_event = threading.Event()
    ok_event = threading.Event()
    spinner_thread = threading.Thread(
        target=spinner, args=(stage, stop_event, ok_event)
    )
    spinner_thread.start()
    try:
        cmd = f"docker exec beescan_base python3 /core/plugin_runner.py --output {temp_files_path}"
        result = subprocess.run(cmd, shell=True)
        if result.returncode == 0:
            logging.info(f"Плагины завершили выполнение, output: {temp_files_path}")
            ok_event.set()
    finally:
        stop_event.set()
        spinner_thread.join()
    if not ok_event.is_set():
        logging.error("Ошибка выполнения плагинов.")
        sys.exit(1)


# Сбор всех результатов в БД
def run_collector(temp_files_path):
    stage = "Сбор результатов в БД"
    stop_event = threading.Event()
    ok_event = threading.Event()
    spinner_thread = threading.Thread(
        target=spinner, args=(stage, stop_event, ok_event)
    )
    spinner_thread.start()
    try:
        cmd = f"docker exec beescan_base python3 /core/collector.py --temp-file {temp_files_path}"
        result = subprocess.run(cmd, shell=True)
        if result.returncode == 0:
            ok_event.set()
            logging.info("Сбор результатов collector.py завершён.")
    finally:
        stop_event.set()
        spinner_thread.join()
    if not ok_event.is_set():
        logging.error("Ошибка выполнения collector.py.")


# Генерация отчетов всех форматов
def generate_reports(timestamp):
    formats = CONFIG.get("scan_config", {}).get("report_formats", ["html"])
    open_report = CONFIG.get("scan_config", {}).get("open_report", False)
    html_report_name = f"report_{timestamp}.html"
    html_report_path = os.path.join(ROOT_DIR, "reports", html_report_name)

    for i, fmt in enumerate(formats):
        stage = f"Генерация отчета {fmt.upper()}"
        stop_event = threading.Event()
        ok_event = threading.Event()
        spinner_thread = threading.Thread(
            target=spinner, args=(stage, stop_event, ok_event)
        )
        spinner_thread.start()
        try:
            if fmt not in ["html", "pdf", "txt", "terminal"]:
                logging.warning(f"Неподдерживаемый формат отчета: {fmt}")
                continue

            clear_flag = "--clear-reports" if i == 0 else ""
            if fmt == "terminal":
                ok_event.set()
                stop_event.set()
                spinner_thread.join()
                run_command(
                    f"docker exec beescan_base python3 /core/report_generator.py --format {fmt} --timestamp {timestamp} {clear_flag}",
                    hide_output=False,
                )
                ok_event.set()
            else:
                success = run_command(
                    f"docker exec beescan_base python3 /core/report_generator.py --format {fmt} --timestamp {timestamp} {clear_flag}",
                    hide_output=True,
                )
                if success:
                    ok_event.set()
                    logging.info(f"Отчет {fmt.upper()} сгенерирован успешно.")
        finally:
            stop_event.set()
            spinner_thread.join()

        if open_report and fmt == "html" and os.path.exists(html_report_path):
            try:
                if sys.platform.startswith("linux"):
                    subprocess.Popen(
                        ["xdg-open", html_report_path],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                    )
                elif sys.platform == "darwin":
                    subprocess.Popen(
                        ["open", html_report_path],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                    )
                elif sys.platform == "win32":
                    os.startfile(html_report_path)
                logging.info(f"Открытие HTML-отчета: {html_report_path}")
            except Exception as e:
                logging.warning(f"Не удалось открыть HTML-отчет: {e}")


# Смена владельца папки с отчетами (Linux)
def post_scan_chown():
    stage = "Обновление прав /reports"
    stop_event = threading.Event()
    ok_event = threading.Event()
    spinner_thread = threading.Thread(
        target=spinner, args=(stage, stop_event, ok_event)
    )
    spinner_thread.start()
    try:
        try:
            user_id = os.getuid()
            group_id = os.getgid()
            success = run_command(
                f"docker exec beescan_base chown -R {user_id}:{group_id} /reports",
                hide_output=True,
            )
            if success:
                ok_event.set()
                logging.info(
                    f"Изменены права доступа к /reports на {user_id}:{group_id}"
                )
        except Exception as e:
            logging.warning(f"Не удалось изменить владельца отчётов: {e}")
    finally:
        stop_event.set()
        spinner_thread.join()


# Основной workflow сканирования
def main():
    print("[+] Запуск beescan...")
    logging.info("==== START ====")
    check_docker_installed()
    clean_docker_environment()
    start_postgres()
    ensure_beescan_base_image()
    start_beescan_container()
    purge_database()
    cleanup_all_tmp_files()
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    temp_files_path = os.path.join(
        tempfile.gettempdir(), f"temp_files_{timestamp}.json"
    )
    run_plugins(temp_files_path)
    run_collector(temp_files_path)
    generate_reports(timestamp)
    post_scan_chown()
    print("[+] beescan завершил выполнение!")
    logging.info("==== FINISH ====")
    sys.exit(0)


if __name__ == "__main__":
    main()
