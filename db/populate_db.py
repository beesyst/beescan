import json
import os

import psycopg2

# Конфиг для подключения к БД
DB = {
    "user": os.getenv("POSTGRES_USER", "secweb_user"),
    "password": os.getenv("POSTGRES_PASSWORD", "secweb_pass"),
    "db": os.getenv("POSTGRES_DB", "beescan"),
    "host": os.getenv("POSTGRES_HOST", "beescan_postgres"),
    "port": os.getenv("POSTGRES_PORT", "5432"),
}

CONFIG_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "config", "config.json"
)

with open(CONFIG_PATH, "r") as f:
    CONFIG = json.load(f)

PURGE_ON_START = CONFIG.get("scan_config", {}).get("purge_on_start", False)

# Все таблицы, которые надо очищать перед запуском!
PURGE_TABLES = [
    "evidence",
    "registry",
]


def connect():
    return psycopg2.connect(
        dbname=DB["db"],
        user=DB["user"],
        password=DB["password"],
        host=DB["host"],
        port=DB["port"],
    )


def purge():
    conn = connect()
    cur = conn.cursor()
    for table in PURGE_TABLES:
        try:
            cur.execute(f"DELETE FROM {table};")
            print(f"🗑 Очистка таблицы {table} завершена.")
        except Exception as e:
            print(f"⚠️ Ошибка при очистке {table}: {e}")
    conn.commit()
    cur.close()
    conn.close()


def main():
    if PURGE_ON_START:
        purge()
    else:
        print("ℹ️ Очистка БД отключена (purge_on_start = false).")


if __name__ == "__main__":
    main()
