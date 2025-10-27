import unittest
import sqlite3
import json
import jwt
import time
import os
import sys
import threading
from http.client import HTTPConnection
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# AI Acknowledgment:
# I used ChatGPT for guidance and clarification on how to design and structure
# the JWKS server, including database setup and endpoint logic.
# The final implementation and code were written and debugged by me.

# Import your project2 module and refer to it as 'server' for convenience
import project2 as server

class TestDatabaseFunctions(unittest.TestCase):
    """Test database initialization and operations"""

    def setUp(self):
        """Create a test database before each test"""
        self.test_db = "test_keys.db"
        self.conn = sqlite3.connect(self.test_db)
        server.init_db(self.conn)

    def tearDown(self):
        """Clean up test database after each test"""
        self.conn.close()
        if os.path.exists(self.test_db):
            os.remove(self.test_db)

    def test_init_db_creates_table(self):
        """Test that init_db creates the keys table"""
        cursor = self.conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='keys'"
        )
        result = cursor.fetchone()
        self.assertIsNotNone(result)
        self.assertEqual(result[0], 'keys')

    def test_seed_keys_if_empty_creates_two_keys(self):
        """Test that seeding creates exactly two keys"""
        server.seed_keys_if_empty(self.conn)
        cursor = self.conn.execute("SELECT COUNT(*) FROM keys")
        count = cursor.fetchone()[0]
        self.assertEqual(count, 2)

    def test_seed_keys_does_not_duplicate(self):
        """Test that seeding doesn't create duplicates"""
        server.seed_keys_if_empty(self.conn)
        server.seed_keys_if_empty(self.conn)
        cursor = self.conn.execute("SELECT COUNT(*) FROM keys")
        count = cursor.fetchone()[0]
        self.assertEqual(count, 2)

    def test_select_one_key_expired(self):
        """Test selecting an expired key"""
        server.seed_keys_if_empty(self.conn)
        row = server.select_one_key(self.conn, expired=True)
        self.assertIsNotNone(row)
        kid, key_blob, exp = row
        now = int(time.time())
        self.assertLessEqual(exp, now)

    def test_select_one_key_valid(self):
        """Test selecting a valid (non-expired) key"""
        server.seed_keys_if_empty(self.conn)
        row = server.select_one_key(self.conn, expired=False)
        self.assertIsNotNone(row)
        kid, key_blob, exp = row
        now = int(time.time())
        self.assertGreater(exp, now)

    def test_select_all_valid_keys(self):
        """Test selecting all valid keys"""
        server.seed_keys_if_empty(self.conn)
        rows = server.select_all_valid_keys(self.conn)
        self.assertGreaterEqual(len(rows), 1)
        now = int(time.time())
        for kid, key_blob, exp in rows:
            self.assertGreater(exp, now)


class TestKeySerialization(unittest.TestCase):
    """Test key serialization and deserialization"""

    def test_serialize_and_deserialize_key(self):
        """Test that a key can be serialized and deserialized"""
        original_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        pem_bytes = server.serialize_private_key_to_pem(original_key)
        self.assertIsInstance(pem_bytes, bytes)
        self.assertIn(b'BEGIN RSA PRIVATE KEY', pem_bytes)

        deserialized_key = server.deserialize_private_key_from_pem(pem_bytes)
        self.assertIsNotNone(deserialized_key)

        # Verify the keys are equivalent by comparing their numbers
        orig_numbers = original_key.private_numbers()
        deser_numbers = deserialized_key.private_numbers()
        self.assertEqual(orig_numbers.public_numbers.n, deser_numbers.public_numbers.n)
        self.assertEqual(orig_numbers.public_numbers.e, deser_numbers.public_numbers.e)

    def test_rsa_numbers_from_private_pem(self):
        """Test extracting RSA numbers from PEM"""
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem_bytes = server.serialize_private_key_to_pem(key)
        n, e = server.rsa_numbers_from_private_pem(pem_bytes)
        self.assertIsInstance(n, int)
        self.assertIsInstance(e, int)
        self.assertEqual(e, 65537)


class TestUtilityFunctions(unittest.TestCase):
    """Test utility functions"""

    def test_int_to_base64(self):
        """Test integer to base64 conversion"""
        result = server.int_to_base64(65537)
        self.assertIsInstance(result, str)
        self.assertNotIn('=', result)  # Should not have padding

    def test_int_to_base64_large_number(self):
        """Test base64 conversion with large numbers"""
        large_num = 2**2048
        result = server.int_to_base64(large_num)
        self.assertIsInstance(result, str)
        self.assertGreater(len(result), 0)


class TestServerEndpoints(unittest.TestCase):
    """Test HTTP endpoints"""

    @classmethod
    def setUpClass(cls):
        """Start the server in a separate thread"""
        from http.server import HTTPServer
        cls.server_thread = threading.Thread(
            target=lambda: HTTPServer(
                (server.hostName, server.serverPort),
                server.MyServer
            ).serve_forever()
        )
        cls.server_thread.daemon = True
        cls.server_thread.start()
        time.sleep(1)  # Give server time to start

    def setUp(self):
        """Create HTTP connection before each test"""
        self.conn = HTTPConnection(server.hostName, server.serverPort)

    def tearDown(self):
        """Close HTTP connection after each test"""
        self.conn.close()

    def test_post_auth_returns_valid_jwt(self):
        """Test POST /auth returns a valid JWT"""
        self.conn.request("POST", "/auth")
        response = self.conn.getresponse()
        self.assertEqual(response.status, 200)
        
        token = response.read().decode('utf-8')
        self.assertIsNotNone(token)
        self.assertGreater(len(token), 0)

        # Decode without verification to check structure
        decoded = jwt.decode(token, options={"verify_signature": False})
        self.assertIn("user", decoded)
        self.assertIn("exp", decoded)

    def test_post_auth_expired_returns_expired_jwt(self):
        """Test POST /auth?expired returns expired JWT"""
        self.conn.request("POST", "/auth?expired")
        response = self.conn.getresponse()
        self.assertEqual(response.status, 200)
        
        token = response.read().decode('utf-8')
        decoded = jwt.decode(token, options={"verify_signature": False})
        
        # Check that token is expired
        exp_timestamp = decoded['exp']
        now_timestamp = time.time()
        self.assertLess(exp_timestamp, now_timestamp)

    def test_post_auth_kid_matches_database(self):
        """Test that JWT kid header matches database"""
        self.conn.request("POST", "/auth")
        response = self.conn.getresponse()
        token = response.read().decode('utf-8')
        
        # Extract kid from JWT header
        header = jwt.get_unverified_header(token)
        kid = header['kid']
        
        # Verify kid exists in database
        db_conn = server.open_db()
        cursor = db_conn.execute("SELECT kid FROM keys WHERE kid = ?", (int(kid),))
        result = cursor.fetchone()
        db_conn.close()
        
        self.assertIsNotNone(result)

    def test_get_jwks_returns_valid_json(self):
        """Test GET /.well-known/jwks.json returns valid JSON"""
        self.conn.request("GET", "/.well-known/jwks.json")
        response = self.conn.getresponse()
        self.assertEqual(response.status, 200)
        self.assertEqual(response.getheader('Content-type'), 'application/json')
        
        data = json.loads(response.read().decode('utf-8'))
        self.assertIn("keys", data)
        self.assertIsInstance(data["keys"], list)

    def test_get_jwks_only_returns_valid_keys(self):
        """Test JWKS endpoint only returns non-expired keys"""
        self.conn.request("GET", "/.well-known/jwks.json")
        response = self.conn.getresponse()
        data = json.loads(response.read().decode('utf-8'))
        
        # Get all kids from JWKS
        jwks_kids = [key['kid'] for key in data['keys']]
        
        # Verify all kids are from valid keys in database
        now = int(time.time())
        db_conn = server.open_db()
        for kid in jwks_kids:
            cursor = db_conn.execute(
                "SELECT exp FROM keys WHERE kid = ?",
                (int(kid),)
            )
            result = cursor.fetchone()
            self.assertIsNotNone(result)
            self.assertGreater(result[0], now)
        db_conn.close()

    def test_get_jwks_key_structure(self):
        """Test JWKS keys have correct structure"""
        self.conn.request("GET", "/.well-known/jwks.json")
        response = self.conn.getresponse()
        data = json.loads(response.read().decode('utf-8'))
        
        if len(data['keys']) > 0:
            key = data['keys'][0]
            self.assertEqual(key['alg'], 'RS256')
            self.assertEqual(key['kty'], 'RSA')
            self.assertEqual(key['use'], 'sig')
            self.assertIn('kid', key)
            self.assertIn('n', key)
            self.assertIn('e', key)

    def test_unsupported_methods_return_405(self):
        """Test that unsupported HTTP methods return 405"""
        methods = ['PUT', 'PATCH', 'DELETE', 'HEAD']
        for method in methods:
            self.conn.request(method, "/auth")
            response = self.conn.getresponse()
            self.assertEqual(response.status, 405)
            response.read()  # Consume response body

    def test_invalid_endpoint_returns_405(self):
        """Test that invalid endpoints return 405"""
        self.conn.request("GET", "/invalid")
        response = self.conn.getresponse()
        self.assertEqual(response.status, 405)

    def test_database_file_exists_in_current_directory(self):
        """Test that database file exists in current directory for gradebot"""
        db_path = "totally_not_my_privateKeys.db"
        self.assertTrue(
            os.path.exists(db_path),
            f"Database file '{db_path}' must exist in current directory for gradebot"
        )

    def test_post_auth_with_json_payload(self):
        """Test POST /auth with JSON payload (gradebot compatibility)"""
        import json as json_module
        
        payload = json_module.dumps({
            "username": "userABC",
            "password": "password123"
        })
        
        headers = {
            "Content-Type": "application/json",
            "Content-Length": str(len(payload))
        }
        
        self.conn.request("POST", "/auth", body=payload, headers=headers)
        response = self.conn.getresponse()
        
        # Should return 200 (or at least not crash)
        self.assertIn(response.status, [200, 400, 401])
        
        body = response.read().decode('utf-8')
        # If it returns 200, should be a JWT
        if response.status == 200:
            self.assertGreater(len(body), 0)

    def test_post_auth_with_basic_auth(self):
        """Test POST /auth with HTTP Basic Auth (gradebot compatibility)"""
        import base64
        
        # Create Basic Auth header
        credentials = base64.b64encode(b"userABC:password123").decode('ascii')
        headers = {
            "Authorization": f"Basic {credentials}"
        }
        
        self.conn.request("POST", "/auth", headers=headers)
        response = self.conn.getresponse()
        
        # Should return 200 (or at least not crash)
        self.assertIn(response.status, [200, 400, 401])
        
        body = response.read().decode('utf-8')
        # If it returns 200, should be a JWT
        if response.status == 200:
            self.assertGreater(len(body), 0)


if __name__ == '__main__':
    print("=" * 70)
    print("RUNNING TEST SUITE")
    print("=" * 70)
    print()
    
    # Create test suite
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromModule(sys.modules[__name__])
    
    # Run tests with verbose output
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Print summary
    print("\n" + "=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)
    print(f"Tests run: {result.testsRun}")
    print(f"Successes: {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    
    if result.wasSuccessful():
        success_rate = 100.0
        print(f"\n✅ ALL TESTS PASSED! (100%)")
    else:
        success_rate = ((result.testsRun - len(result.failures) - len(result.errors)) 
                       / result.testsRun * 100)
        print(f"\n⚠️  Success Rate: {success_rate:.1f}%")
    
    print("=" * 70)
    
    # Exit with appropriate code
    sys.exit(0 if result.wasSuccessful() else 1)
