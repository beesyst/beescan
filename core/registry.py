import json
import os
from datetime import datetime

import psycopg2

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG_PATH = os.path.join(ROOT_DIR, "config", "config.json")

with open(CONFIG_PATH, "r") as f:
    CONFIG = json.load(f)
DB_CONFIG = CONFIG["database"]


def connect():
    return psycopg2.connect(
        database=DB_CONFIG["POSTGRES_DB"],
        user=DB_CONFIG["POSTGRES_USER"],
        password=DB_CONFIG["POSTGRES_PASSWORD"],
        host=DB_CONFIG["POSTGRES_HOST"],
        port=DB_CONFIG["POSTGRES_PORT"],
    )


def add_target(
    target_type,
    target_value,
    port=None,
    protocol=None,
    source_plugin=None,
    tags=None,
    meta=None,
    status="new",
):
    tags = tags or []
    meta = meta or {}
    now = datetime.now()
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO registry (target_type, target_value, port, protocol, source_plugin, status, tags, meta, created_at, updated_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (target_type, target_value, port, protocol)
                DO UPDATE SET
                    status = EXCLUDED.status,
                    updated_at = EXCLUDED.updated_at
                RETURNING id;
                """,
                (
                    target_type,
                    target_value,
                    port,
                    protocol,
                    source_plugin,
                    status,
                    tags,
                    json.dumps(meta, ensure_ascii=False),
                    now,
                    now,
                ),
            )
            return cur.fetchone()[0]


def get_targets(
    filter_status=None,
    filter_type=None,
    filter_plugin=None,
    filter_tags=None,
    protocol=None,
):
    query = "SELECT id, target_type, target_value, port, protocol, status, tags, meta FROM registry WHERE 1=1"
    params = []
    if filter_status:
        query += " AND status = %s"
        params.append(filter_status)
    if filter_type:
        query += " AND target_type = %s"
        params.append(filter_type)
    if filter_plugin:
        query += " AND source_plugin = %s"
        params.append(filter_plugin)
    if filter_tags:
        query += " AND tags && %s"
        params.append(filter_tags)
    if protocol:
        query += " AND protocol = %s"
        params.append(protocol)
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(query, params)
            return cur.fetchall()


def update_target_status(target_id, new_status):
    now = datetime.now()
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE registry SET status = %s, updated_at = %s WHERE id = %s",
                (new_status, now, target_id),
            )


def delete_target(target_id):
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM registry WHERE id = %s", (target_id,))


if __name__ == "__main__":
    tid = add_target(
        "ip",
        "8.8.8.8",
        port=80,
        protocol="tcp",
        source_plugin="nmap",
        tags=["web"],
        meta={"service": "http"},
    )
    print("Target added:", tid)
    print(
        get_targets(
            filter_status="new",
            filter_type="ip",
            filter_plugin="nmap",
            filter_tags=["web"],
            protocol="tcp",
        )
    )
