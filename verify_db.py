import argparse  # New import
import base64
import json
import sqlite3

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

DB_FILE = "threats.db"


# --- Encryption Key Derivation ---
def get_encryption_key(password, salt):
    """Derives a key from the provided password and salt."""
    if not password:
        raise ValueError("A password is required for decryption.")

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key


def verify_hash_chain(rows):
    """Verifies the integrity of the hash chain."""
    is_chain_valid = True
    for i in range(1, len(rows)):
        prev_row = rows[i - 1]
        current_row = rows[i]

        # In Python 3, all strings are Unicode. We need to encode them to bytes before hashing.
        # The hash stored in the DB is a hex digest, so we compare with that.

        # This is the hash of the *previous* record's content
        prev_content_hash = prev_row["content_hash"]

        # This is the hash that the *current* record says the previous one should have
        hash_in_current = current_row["previous_hash"]

        if prev_content_hash != hash_in_current:
            is_chain_valid = False
            print("!!! TAMPERING DETECTED !!!")
            print(f"  - Record ID: {current_row['id']}")
            print(f"  - Stored Previous Hash: {hash_in_current}")
            print(f"  - Actual Previous Hash:   {prev_content_hash}")
            break  # Stop on first error

    return is_chain_valid


def verify_db_contents(password):
    """Connects, decrypts, and prints database contents."""
    con = None  # Initialize con to None
    try:
        con = sqlite3.connect(DB_FILE)
        con.row_factory = sqlite3.Row
        cur = con.cursor()

        cur.execute("SELECT * FROM threats ORDER BY id ASC")
        rows = cur.fetchall()

        if not rows:
            print("Database is empty.")
            return

        print("--- Verifying Hash Chain Integrity ---")
        if verify_hash_chain(rows):
            print(">>> Hash chain is valid. Data integrity verified. <<<")
        else:
            print("!!! Hash chain is broken. Data may have been tampered with. !!!")

        print("\n--- Verifying Encrypted Database Contents ---")
        for row in rows:
            if row["url"] == "genesis":
                print(f"\nRecord ID: {row['id']} (Genesis Record)")
                continue

            print(f"\nRecord ID: {row['id']}")
            try:
                salt = row["salt"]
                key = get_encryption_key(password, salt)
                fernet = Fernet(key)
                decrypted_keywords = fernet.decrypt(row["keywords"])
                decrypted_is_phishing = fernet.decrypt(row["is_phishing"])
                print(f"  Keywords: {json.loads(decrypted_keywords)}")
                print(f"  Is Phishing: {json.loads(decrypted_is_phishing)}")
            except Exception as e:
                print(f"  Error decrypting record: {e}")
            print(f"  Content Hash (SHA-256): {row['content_hash']}")
            print(f"  Previous Hash: {row['previous_hash']}")

        print(f"\nTotal records: {len(rows)}")

    except Exception as e:
        print(f"Database or decryption error: {e}")
        print("This may be because the password is incorrect or the data is corrupt.")
    finally:
        if con:
            con.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Verify encrypted database.")
    parser.add_argument(
        "--password", required=True, help="Password for database decryption."
    )
    args = parser.parse_args()
    verify_db_contents(args.password)
