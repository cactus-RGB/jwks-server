from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from urllib.parse import urlparse, parse_qs
import base64
import json
import jwt
import datetime
import sqlite3
import time

# AI Acknowledgment:
# I used ChatGPT for guidance and clarification on how to design and structure
# the JWKS server, including database setup and endpoint logic.
# The final implementation and code were written and debugged by me.

# Server configuration
hostName = "localhost"
serverPort = 8080
DB_PATH = "totally_not_my_privateKeys.db"


def int_to_base64(value):
    """Convert an integer to a Base64URL-encoded string"""
    value_hex = format(value, 'x')
    # Ensure even length
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')


def serialize_private_key_to_pem(priv_key_obj) -> bytes:
    """Serialize RSA private key to PEM format"""
    return priv_key_obj.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )


def deserialize_private_key_from_pem(pem_bytes: bytes):
    """Deserialize PEM bytes back to RSA private key object"""
    return serialization.load_pem_private_key(pem_bytes, password=None)


def open_db():
    """Open SQLite database connection"""
    return sqlite3.connect(DB_PATH, check_same_thread=False)


def init_db(conn):
    """Create the keys table if it doesn't exist"""
    conn.execute("""
        CREATE TABLE IF NOT EXISTS keys(
            kid INTEGER PRIMARY KEY AUTOINCREMENT,
            key BLOB NOT NULL,
            exp INTEGER NOT NULL
        )
    """)
    conn.commit()


def rsa_generate_pem():
    """Generate a new RSA key pair and return as PEM bytes"""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return serialize_private_key_to_pem(key)


def seed_keys_if_empty(conn):
    """Seed database with one expired and one valid key if empty"""
    cur = conn.execute("SELECT COUNT(*) FROM keys")
    (count,) = cur.fetchone()
    
    if count == 0:
        now = int(time.time())
        one_hour = 3600

        expired_pem = rsa_generate_pem()
        valid_pem = rsa_generate_pem()

        # Insert one expired key (exp <= now)
        conn.execute(
            "INSERT INTO keys(key, exp) VALUES (?, ?)",
            (expired_pem, now - 60)
        )
        # Insert one valid key (exp >= now + 1h)
        conn.execute(
            "INSERT INTO keys(key, exp) VALUES (?, ?)",
            (valid_pem, now + one_hour)
        )
        conn.commit()


def select_one_key(conn, expired: bool):
    """Select a single key from database based on expiry status"""
    now = int(time.time())
    if expired:
        sql = "SELECT kid, key, exp FROM keys WHERE exp <= ? ORDER BY exp DESC LIMIT 1"
        args = (now,)
    else:
        sql = "SELECT kid, key, exp FROM keys WHERE exp > ? ORDER BY exp ASC LIMIT 1"
        args = (now,)
    
    cur = conn.execute(sql, args)
    row = cur.fetchone()
    return row  # (kid, key_blob, exp) or None


def select_all_valid_keys(conn):
    """Select all non-expired keys from database"""
    now = int(time.time())
    cur = conn.execute(
        "SELECT kid, key, exp FROM keys WHERE exp > ? ORDER BY exp ASC",
        (now,)
    )
    return cur.fetchall()  # list of (kid, key_blob, exp)


def rsa_numbers_from_private_pem(pem_bytes: bytes):
    """Extract public key numbers (n, e) from private key PEM"""
    priv = deserialize_private_key_from_pem(pem_bytes)
    pub_numbers = priv.public_key().public_numbers()
    return pub_numbers.n, pub_numbers.e


# Initialize database on module import
conn = open_db()
init_db(conn)
seed_keys_if_empty(conn)


class MyServer(BaseHTTPRequestHandler):
    def do_PUT(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_PATCH(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_DELETE(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_HEAD(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_POST(self):
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)

        if parsed_path.path == "/auth":
            # Determine if expired key is requested
            want_expired = 'expired' in params

            # Select appropriate key from database
            row = select_one_key(conn, expired=want_expired)
            if row is None:
                self.send_response(503)
                self.end_headers()
                self.wfile.write(b"No suitable key in database.")
                return

            kid, key_blob, key_exp = row
            priv = deserialize_private_key_from_pem(key_blob)

            # Create token payload with appropriate expiration
            now_dt = datetime.datetime.utcnow()
            if want_expired:
                token_exp = now_dt - datetime.timedelta(hours=1)
            else:
                token_exp = now_dt + datetime.timedelta(hours=1)

            token_payload = {
                "user": "username",
                "exp": token_exp
            }
            headers = {"kid": str(kid)}  # kid must match DB row

            # Sign JWT with private key from database
            encoded_jwt = jwt.encode(
                token_payload,
                serialize_private_key_to_pem(priv),
                algorithm="RS256",
                headers=headers
            )

            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(encoded_jwt.encode("utf-8"))
            return

        self.send_response(405)
        self.end_headers()
        return

    def do_GET(self):
        if self.path == "/.well-known/jwks.json":
            # Retrieve all valid (non-expired) keys from database
            rows = select_all_valid_keys(conn)

            jwks_keys = []
            for kid, key_blob, exp_ts in rows:
                n_int, e_int = rsa_numbers_from_private_pem(key_blob)
                jwks_keys.append({
                    "alg": "RS256",
                    "kty": "RSA",
                    "use": "sig",
                    "kid": str(kid),
                    "n": int_to_base64(n_int),
                    "e": int_to_base64(e_int),
                })

            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"keys": jwks_keys}).encode("utf-8"))
            return

        self.send_response(405)
        self.end_headers()
        return


if __name__ == "__main__":
    webServer = HTTPServer((hostName, serverPort), MyServer)
    print(f"Server started at http://{hostName}:{serverPort}")
    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass
    webServer.server_close()
    print("Server stopped.")
