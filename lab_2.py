import hashlib, time, sqlite3

DB = 'blockchain.db'
DIFFICULTY = 6
PREFIX = '0' * DIFFICULTY

def init_db():
    """Створює таблицю transactions, якщо її немає."""
    conn = sqlite3.connect(DB)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS transactions (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            tx_hash        TEXT    NOT NULL,
            previous_hash  TEXT    NOT NULL,
            Nonce          INTEGER,
            BlockChainHash TEXT,
            IsMiner        INTEGER NOT NULL DEFAULT 1,
            confirmed      INTEGER NOT NULL DEFAULT 0,
            timestamp      DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()

def seed_tx():
    """Якщо таблиця порожня, додає одну тестову транзакцію."""
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM transactions")
    if cur.fetchone()[0] == 0:
        conn.execute(
            "INSERT INTO transactions (tx_hash, previous_hash) VALUES (?, ?)",
            ("sample_tx_hash_001", "0" * 64)
        )
        conn.commit()
    conn.close()

def mine_block(tx_hash, prev_hash, prefix=PREFIX):
    """
    Proof-of-Work: шукає SHA-256-хеш, що починається з prefix.
    Повертає (блок-hash, nonce, час у секундах).
    """
    nonce = 0
    start = time.time()
    while True:
        h = hashlib.sha256(f"{tx_hash}{prev_hash}{nonce}".encode()).hexdigest()
        if h.startswith(prefix):
            return h, nonce, time.time() - start
        nonce += 1

def update_tx(tx_id, h, nonce):
    """Оновлює транзакцію: записує блок-хеш, nonce та ставить confirmed=1."""
    conn = sqlite3.connect(DB)
    conn.execute(
        "UPDATE transactions SET BlockChainHash=?, Nonce=?, confirmed=1 WHERE id=?",
        (h, nonce, tx_id)
    )
    conn.commit()
    conn.close()

def main():
    init_db()
    seed_tx()

    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    cur.execute("""
        SELECT id, tx_hash, previous_hash
          FROM transactions
         WHERE IsMiner=1 AND confirmed=0
      ORDER BY timestamp
         LIMIT 1
    """)
    tx_id, tx_hash, prev_hash = cur.fetchone()
    conn.close()

    print("=== Результати майнінгу ===")
    h, nonce, elapsed = mine_block(tx_hash, prev_hash)
    print("Значення блоку:      ", h)
    print("Сіль (nonce):        ", nonce)
    print("Час виконання (сек): ", f"{elapsed:.2f}")
    print("Підтверджено tx ID:  ", tx_id)

    update_tx(tx_id, h, nonce)

if __name__ == "__main__":
    main()
