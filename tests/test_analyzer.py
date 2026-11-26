
import unittest
from datetime import datetime, timedelta, timezone
from io import StringIO
from contextlib import redirect_stdout

from src.main import detect_brute_force


class TestBruteForceDetection(unittest.TestCase):

    def create_login(self, source_ip, event_time, username="testuser"):
        return {
            "source_ip": source_ip,
            "time": event_time.isoformat(),
            "username": username
        }

    def test_brute_force_detected(self):
        """60 saniyede 10 başarısız giriş varsa tespit edilmeli."""

        start_time = datetime(2026, 11, 26, 12, 0, 0, tzinfo=timezone.utc)

        failed_logins = []

        for i in range(10):
            event_time = start_time + timedelta(seconds=i * 5)
            failed_logins.append(
                self.create_login("192.168.1.100", event_time)
            )

        output = StringIO()

        with redirect_stdout(output):
            detect_brute_force(failed_logins)

        self.assertIn("ŞÜPHELİ AKTİVİTE TESPİT EDİLDİ", output.getvalue())

    def test_brute_force_not_detected(self):
        """60 saniyede 9 başarısız giriş varsa uyarı oluşmamalı."""

        start_time = datetime(2026, 11, 26, 12, 0, 0, tzinfo=timezone.utc)

        failed_logins = []

        for i in range(9):
            event_time = start_time + timedelta(seconds=i * 5)
            failed_logins.append(
                self.create_login("192.168.1.100", event_time)
            )

        output = StringIO()

        with redirect_stdout(output):
            detect_brute_force(failed_logins)

        self.assertIn(
            "Belirlenen eşik değere ulaşan şüpheli aktivite bulunamadı.",
            output.getvalue()
        )

    def test_missing_ip_is_ignored(self):
        """Kaynak IP bilgisi olmayan kayıtlar analize alınmamalı."""

        start_time = datetime(2026, 11, 26, 12, 0, 0, tzinfo=timezone.utc)

        failed_logins = []

        for i in range(10):
            event_time = start_time + timedelta(seconds=i * 5)
            failed_logins.append(
                self.create_login("-", event_time)
            )

        output = StringIO()

        with redirect_stdout(output):
            detect_brute_force(failed_logins)

        self.assertIn(
            "Belirlenen eşik değere ulaşan şüpheli aktivite bulunamadı.",
            output.getvalue()
        )


if __name__ == "__main__":
    unittest.main()
