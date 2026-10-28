import re
import tempfile
import unittest
from pathlib import Path

import app


class PaymentDemoTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        app.DB_PATH = Path(self.temp.name) / "payments.sqlite3"
        app.app.config.update(TESTING=True, SECRET_KEY="test-secret")
        self.client = app.app.test_client()

    def tearDown(self):
        self.temp.cleanup()

    def csrf(self, page):
        return re.search(r'name="csrf_token" value="([^"]+)"', page).group(1)

    def test_simulated_payment_is_atomic_idempotent_and_role_checked(self):
        home = self.client.get("/").get_data(as_text=True)
        self.client.post("/customer/register", data={"email": "buyer@example.test", "password": "A-long-test-password-123", "csrf_token": self.csrf(home)})
        self.assertEqual(self.client.get("/admin").status_code, 403)
        page = self.client.get("/customer").get_data(as_text=True)
        csrf = self.csrf(page)
        idem = re.search(r'name="idempotency_key" value="([^"]+)"', page).group(1)
        form = {"csrf_token": csrf, "idempotency_key": idem, "amount": "12.34"}
        self.client.post("/payment/charge", data=form)
        self.client.post("/payment/charge", data=form)
        with app.connect() as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM payments").fetchone()[0], 1)
            rows = conn.execute("SELECT side,amount_cents FROM ledger").fetchall()
            self.assertEqual(len(rows), 2)
            self.assertEqual(sum(amount for _, amount in rows), 2468)

    def test_missing_csrf_is_rejected(self):
        self.assertEqual(self.client.post("/customer/register", data={"email": "a@example.test", "password": "A-long-test-password-123"}).status_code, 400)


if __name__ == "__main__":
    unittest.main()

