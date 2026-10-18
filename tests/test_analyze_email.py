import sys
import tempfile
import unittest
from pathlib import Path


# ============================================================
# PROJECT CONFIGURATION
# ============================================================

# Locate the main project directory.
PROJECT_DIR = Path(__file__).resolve().parent.parent

# Allow Python to import the analyzer from the scripts folder.
SCRIPTS_DIR = PROJECT_DIR / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

from analyze_email import (
    analyze_email,
    extract_urls,
    analyze_url,
    analyze_email_headers
)


# ============================================================
# URL EXTRACTION TESTS
# ============================================================

class TestURLExtraction(unittest.TestCase):

    def test_extracts_https_url(self):
        """Verify that a standard HTTPS URL is extracted."""

        text = "Visit https://example.com/login for training."

        result = extract_urls(text)

        self.assertEqual(
            result,
            ["https://example.com/login"]
        )

    def test_extracts_defanged_url(self):
        """Verify that a defanged HTTPS URL is extracted."""

        text = "Training URL: hxxps://example.com/login"

        result = extract_urls(text)

        self.assertEqual(
            result,
            ["hxxps://example.com/login"]
        )

    def test_returns_empty_list_without_urls(self):
        """Verify that text without URLs returns an empty list."""

        text = "This email contains no links."

        result = extract_urls(text)

        self.assertEqual(result, [])

    def test_removes_duplicate_urls(self):
        """Verify that duplicate URLs are removed."""

        text = (
            "First: https://example.com "
            "Second: https://example.com"
        )

        result = extract_urls(text)

        self.assertEqual(
            result,
            ["https://example.com"]
        )


# ============================================================
# URL ANALYSIS TESTS
# ============================================================

class TestURLAnalysis(unittest.TestCase):

    def test_analyzes_defanged_url(self):
        """Verify defanged URL detection and hostname extraction."""

        url = "hxxps://account-verification.example.com/login"

        result = analyze_url(url)

        self.assertEqual(
            result["url"],
            url
        )

        self.assertTrue(
            result["defanged_notation"]
        )

        self.assertEqual(
            result["hostname"],
            "account-verification.example.com"
        )

        self.assertTrue(
            any(
                "defanged notation" in observation
                for observation in result["observations"]
            )
        )

    def test_analyzes_normal_https_url(self):
        """Verify that a normal HTTPS URL is parsed locally."""

        url = "https://example.com/login"

        result = analyze_url(url)

        self.assertEqual(
            result["url"],
            url
        )

        self.assertFalse(
            result["defanged_notation"]
        )

        self.assertEqual(
            result["hostname"],
            "example.com"
        )

        self.assertTrue(
            result["observations"]
        )

    def test_handles_url_without_hostname(self):
        """Verify that a URL without a hostname is handled safely."""

        result = analyze_url("https://")

        self.assertIsNone(
            result["hostname"]
        )

        self.assertTrue(
            any(
                "No hostname" in observation
                for observation in result["observations"]
            )
        )


# ============================================================
# EMAIL HEADER SECURITY TESTS
# ============================================================

class TestEmailHeaderAnalysis(unittest.TestCase):

    def test_detects_reply_to_mismatch(self):
        """Verify that different sender and Reply-To addresses are flagged."""

        result = analyze_email_headers(
            "IT Support <support@example.com>",
            "external@example.net"
        )

        self.assertEqual(
            result["sender_address"],
            "support@example.com"
        )

        self.assertEqual(
            result["reply_to_address"],
            "external@example.net"
        )

        self.assertTrue(
            result["reply_to_mismatch"]
        )

        self.assertTrue(
            any(
                "differs from the sender address" in observation
                for observation in result["observations"]
            )
        )

    def test_matching_sender_and_reply_to(self):
        """Verify that matching addresses are not flagged."""

        result = analyze_email_headers(
            "support@example.com",
            "support@example.com"
        )

        self.assertEqual(
            result["sender_address"],
            "support@example.com"
        )

        self.assertEqual(
            result["reply_to_address"],
            "support@example.com"
        )

        self.assertFalse(
            result["reply_to_mismatch"]
        )

    def test_missing_reply_to(self):
        """Verify that a missing Reply-To address is handled correctly."""

        result = analyze_email_headers(
            "support@example.com",
            "Not provided"
        )

        self.assertEqual(
            result["sender_address"],
            "support@example.com"
        )

        self.assertIsNone(
            result["reply_to_address"]
        )

        self.assertIsNone(
            result["reply_to_mismatch"]
        )


# ============================================================
# EMAIL ANALYSIS TESTS
# ============================================================

class TestEmailAnalysis(unittest.TestCase):

    def analyze_sample(self, email_content):
        """Create and analyze a temporary email file."""

        with tempfile.TemporaryDirectory() as temp_dir:
            email_path = Path(temp_dir) / "test_email.eml"

            email_path.write_text(
                email_content,
                encoding="utf-8"
            )

            return analyze_email(email_path)

    def test_extracts_email_headers(self):
        """Verify extraction of important email headers."""

        email_content = (
            "From: Analyst <analyst@example.net>\n"
            "To: employee@example.com\n"
            "Subject: Routine Notification\n"
            "Date: Sun, 18 Oct 2026 10:00:00 +0000\n"
            "Content-Type: text/plain; charset=UTF-8\n"
            "\n"
            "This is a training email without links.\n"
        )

        result = self.analyze_sample(email_content)

        self.assertIn(
            "analyst@example.net",
            result["sender"]
        )

        self.assertEqual(
            result["recipient"],
            "employee@example.com"
        )

        self.assertEqual(
            result["subject"],
            "Routine Notification"
        )

    def test_detects_urgency_wording(self):
        """Verify that urgency-related subject wording is recorded."""

        email_content = (
            "From: sender@example.net\n"
            "To: employee@example.com\n"
            "Subject: Urgent Account Verification\n"
            "Content-Type: text/plain; charset=UTF-8\n"
            "\n"
            "This is a fictional training message.\n"
        )

        result = self.analyze_sample(email_content)

        self.assertTrue(
            any(
                "urgency-related wording" in finding
                for finding in result["observations"]
            )
        )

    def test_email_without_urls(self):
        """Verify that emails without URLs are handled correctly."""

        email_content = (
            "From: sender@example.net\n"
            "To: employee@example.com\n"
            "Subject: Routine Notice\n"
            "Content-Type: text/plain; charset=UTF-8\n"
            "\n"
            "No links are included in this message.\n"
        )

        result = self.analyze_sample(email_content)

        self.assertEqual(
            result["extracted_urls"],
            []
        )

        self.assertEqual(
            result["url_analysis"],
            []
        )

        self.assertTrue(
            any(
                "No URLs were extracted" in finding
                for finding in result["observations"]
            )
        )

    def test_extracts_routing_headers(self):
        """Verify that Return-Path and Received headers are extracted."""

        email_content = (
            "From: sender@example.net\n"
            "To: employee@example.com\n"
            "Subject: Routing Header Test\n"
            "Return-Path: <bounce@example.net>\n"
            "Received: from mail.example.net by mx.example.com;\n"
            "Date: Sun, 18 Oct 2026 10:00:00 +0000\n"
            "Content-Type: text/plain; charset=UTF-8\n"
            "\n"
            "Synthetic email for testing.\n"
        )

        result = self.analyze_sample(email_content)

        self.assertEqual(
            result["return_path"],
            "<bounce@example.net>"
        )

        self.assertEqual(
            len(result["received_headers"]),
            1
        )

        self.assertIn(
            "mail.example.net",
            result["received_headers"][0]
        )

    def test_missing_routing_headers(self):
        """Verify that missing routing headers are handled correctly."""

        email_content = (
            "From: sender@example.net\n"
            "To: employee@example.com\n"
            "Subject: Missing Header Test\n"
            "Content-Type: text/plain; charset=UTF-8\n"
            "\n"
            "Synthetic email without routing headers.\n"
        )

        result = self.analyze_sample(email_content)

        self.assertEqual(
            result["return_path"],
            "Not provided"
        )

        self.assertEqual(
            result["received_headers"],
            []
        )


# ============================================================
# TEST EXECUTION
# ============================================================

if __name__ == "__main__":
    unittest.main(verbosity=2)