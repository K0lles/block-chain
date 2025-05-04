import hashlib
import uuid
import sqlite3
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.exceptions import InvalidSignature

# === Хеш-функція MD5 ===
def md5_hash(data: str) -> str:
    return hashlib.md5(data.encode()).hexdigest()

# === Генерація nonce ===
def generate_nonce() -> str:
    return str(uuid.uuid4())

# === Ініціалізація БД ===
conn = sqlite3.connect("cnucoin.db")
c = conn.cursor()

# === Таблиці згідно структури ===
c.execute('''CREATE TABLE IF NOT EXISTS CnuCoinMembersTable (
    CNUCoinID TEXT PRIMARY KEY,
    PublicKey TEXT,
    IsMiner BOOLEAN
)''')

c.execute('''CREATE TABLE IF NOT EXISTS PrivateTable (
    CNUCoinID TEXT PRIMARY KEY,
    PrivateKey TEXT,
    PublicKey TEXT
)''')

c.execute('''CREATE TABLE IF NOT EXISTS EWalletTable (
    CNUCoinID TEXT PRIMARY KEY,
    ODate TEXT,
    OFrom TEXT,
    OTo TEXT,
    TASum REAL
)''')

c.execute('''CREATE TABLE IF NOT EXISTS TransactionsTable (
    CNUCoinID TEXT,
    TADate TEXT,
    TAID TEXT,
    OFrom TEXT,
    OTo TEXT,
    TAHash TEXT,
    Nonce TEXT,
    TAApproved BOOLEAN,
    TAssign TEXT
)''')

c.execute('''CREATE TABLE IF NOT EXISTS BlockChainTable (
    MinerID TEXT,
    DateTime TEXT,
    BlockChainHash TEXT,
    Nonce TEXT,
    BlockAssign TEXT
)''')

conn.commit()

# === Основний клас для роботи ===
class CNUCoinSystem:
    def register_user(self, is_miner=False) -> str:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        private_key = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode()
        public_key = key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
        identifier = md5_hash(public_key)

        c.execute("INSERT INTO CnuCoinMembersTable VALUES (?, ?, ?)", (identifier, public_key, int(is_miner)))
        c.execute("INSERT INTO PrivateTable VALUES (?, ?, ?)", (identifier, private_key, public_key))
        c.execute("INSERT INTO EWalletTable VALUES (?, ?, ?, ?, ?)", (identifier, datetime.now().isoformat(), '', '', 100.0))
        conn.commit()
        return identifier

    def get_last_blockchain_hash(self) -> str:
        c.execute("SELECT BlockChainHash FROM BlockChainTable ORDER BY DateTime DESC LIMIT 1")
        row = c.fetchone()
        return row[0] if row else '0'

    def get_last_blockchain_nonce(self) -> str:
        c.execute("SELECT Nonce FROM BlockChainTable ORDER BY DateTime DESC LIMIT 1")
        row = c.fetchone()
        return row[0] if row else '0'

    def sign_data(self, private_key_str: str, data: str) -> str:
        private_key = serialization.load_pem_private_key(private_key_str.encode(), password=None)
        signature = private_key.sign(
            data.encode(),
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return signature.hex()

    def make_transaction(self, sender_id: str, receiver_id: str, amount: float):
        c.execute("SELECT PrivateKey FROM PrivateTable WHERE CNUCoinID = ?", (sender_id,))
        sender_private_key = c.fetchone()
        if not sender_private_key:
            raise Exception("Sender not found")

        c.execute("SELECT TASum FROM EWalletTable WHERE CNUCoinID = ?", (sender_id,))
        sender_balance = c.fetchone()
        if not sender_balance or sender_balance[0] < amount:
            raise Exception("Insufficient funds")

        c.execute("SELECT CNUCoinID FROM EWalletTable WHERE CNUCoinID = ?", (receiver_id,))
        if not c.fetchone():
            raise Exception("Receiver not found")

        ta_id = str(uuid.uuid4())
        ta_date = datetime.now().isoformat()
        nonce = generate_nonce()
        prev_hash = self.get_last_blockchain_hash()
        prev_nonce = self.get_last_blockchain_nonce()

        tx_data = f"{sender_id}{receiver_id}{amount}{prev_hash}{prev_nonce}"
        ta_hash = md5_hash(tx_data)
        signature = self.sign_data(sender_private_key[0], tx_data)

        c.execute("INSERT INTO TransactionsTable VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                  (sender_id, ta_date, ta_id, sender_id, receiver_id, ta_hash, nonce, True, signature))

        # Оновлення балансу
        c.execute("UPDATE EWalletTable SET TASum = TASum - ? WHERE CNUCoinID = ?", (amount, sender_id))
        c.execute("UPDATE EWalletTable SET TASum = TASum + ? WHERE CNUCoinID = ?", (amount, receiver_id))

        # Додавання в блокчейн
        c.execute("INSERT INTO BlockChainTable VALUES (?, ?, ?, ?, ?)",
                  (sender_id, ta_date, ta_hash, nonce, signature))
        conn.commit()

# === Демонстрація ===
system = CNUCoinSystem()
a_id = system.register_user(is_miner=True)
b_id = system.register_user()
system.make_transaction(a_id, b_id, 30.0)

# Перевірка
print("Учасники:")
for row in c.execute("SELECT * FROM CnuCoinMembersTable"):
    print(row)

print("\nГаманці:")
for row in c.execute("SELECT * FROM EWalletTable"):
    print(row)

print("\nТранзакції:")
for row in c.execute("SELECT * FROM TransactionsTable"):
    print(row)

print("\nБлокчейн:")
for row in c.execute("SELECT * FROM BlockChainTable"):
    print(row)

conn.close()
