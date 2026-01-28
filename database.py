import sqlite3

conn = sqlite3.connect("traffic.db", check_same_thread=False)
cursor = conn.cursor()

def create_tables() :
    
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS packets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        source_ip TEXT,
        destination_ip TEXT,
        source_port  INTEGER,
        destination_port  INTEGER,
        protocol TEXT,
        packet_size INTEGER,
        date TEXT,
        time TEXT
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        source_ip TEXT,
        alert_description TEXT,
        date TEXT,
        time TEXT
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS traffic (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        protocol TEXT,
        packet_count INTEGER,
        date TEXT,
        start_time TEXT
    )
    """)

    conn.commit()


def delete_table(name ):
    cursor.execute("drop table "+name)
    conn.commit()


def print_tables():
    cursor.execute("""
    SELECT name FROM sqlite_master
    WHERE type='table';
    """)
    print(cursor.fetchall())


def print_all(name):
    cursor.execute("SELECT * FROM "+name)
    rows = cursor.fetchall()
    for r in rows:
        print(r)


# delete_table("alerts")
# delete_table("packets")
# delete_table("traffic")
create_tables()
print_tables()
# print_all("packets")
# print_all("traffic")
# print_all("alerts")

conn.close()