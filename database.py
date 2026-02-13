import sqlite3



def get_db():
    conn = sqlite3.connect("dns_data.db")
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS packets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            protocol TEXT NOT NULL,
            src_ip TEXT NOT NULL,
            dst_ip TEXT NOT NULL,
            src_port INTEGER,
            dst_port INTEGER,
            ttl INTEGER,
            length INTEGER,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS dns_attributes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            packet_id INTEGER NOT NULL,
            query_name TEXT,
            query_type TEXT,
            response_code TEXT,
            is_response TEXT,
            FOREIGN KEY (packet_id) REFERENCES packets(id)
        )
    """)
    conn.commit()
    conn.close()