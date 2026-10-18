from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from pathlib import Path
from urllib.parse import urlsplit
import re
import json
import sys


# ============================================================
# PROJECT CONFIGURATION
# ============================================================

PROJECT_DIR = Path(__file__).resolve().parent.parent
SAMPLES_DIR = PROJECT_DIR / "samples"
REPORTS_DIR = PROJECT_DIR / "reports"


# ============================================================
# URL EXTRACTION
# ============================================================

def extract_urls(text):
    """Extract URL-like strings without visiting them."""

    pattern = r"""(?i)\b(?:https?://|hxxps?://)[^\s<>"']+"""

    found_urls = re.findall(pattern, text)

    # Remove common punctuation from the end of extracted URLs.
    cleaned_urls = [
        url.rstrip(".,;:!?)\u005d}")
        for url in found_urls
    ]

    # Remove duplicate URLs while preserving their original order.
    return list(dict.fromkeys(cleaned_urls))


# ============================================================
# URL ANALYSIS
# ============================================================

def analyze_url(url):
    """
    Record basic URL characteristics without visiting the URL.

    This function parses URL text locally. It does not make
    network requests or determine whether a URL is malicious.
    """

    findings = {
        "url": url,
        "defanged_notation": False,
        "hostname": None,
        "observations": []
    }

    # Detect common defanged URL schemes.
    if url.lower().startswith(("hxxp://", "hxxps://")):
        findings["defanged_notation"] = True

        findings["observations"].append(
            "The URL uses defanged notation and has not been visited."
        )

        # Convert the scheme in memory for local parsing only.
        # This does not open or visit the URL.
        parsing_url = re.sub(
            r"(?i)^hxxps?://",
            lambda match: (
                "https://"
                if match.group(0).lower() == "hxxps://"
                else "http://"
            ),
            url,
            count=1
        )

    else:
        parsing_url = url

    # Parse the URL locally without making a network request.
    try:
        parsed = urlsplit(parsing_url)
        hostname = parsed.hostname

        if hostname:
            findings["hostname"] = hostname
        else:
            findings["observations"].append(
                "No hostname could be extracted; manual review is needed."
            )

    except ValueError:
        findings["observations"].append(
            "The URL could not be parsed reliably."
        )

    # Add a general observation when no other observation was recorded.
    if not findings["observations"]:
        findings["observations"].append(
            "The URL was parsed locally. "
            "This does not establish whether it is safe."
        )

    return findings


# ============================================================
# EMAIL HEADER SECURITY ANALYSIS
# ============================================================

def analyze_email_headers(sender, reply_to):
    """
    Compare sender and Reply-To addresses.

    A mismatch is an investigative clue, not proof of phishing.
    """

    findings = {
        "sender_address": None,
        "reply_to_address": None,
        "reply_to_mismatch": None,
        "observations": []
    }

    # Extract the sender's email address.
    sender_address = parseaddr(sender)[1].strip().lower()

    # Extract the Reply-To address when provided.
    reply_to_address = None

    if reply_to != "Not provided":
        extracted_reply_to = parseaddr(reply_to)[1].strip().lower()

        if extracted_reply_to:
            reply_to_address = extracted_reply_to

    findings["sender_address"] = sender_address or None
    findings["reply_to_address"] = reply_to_address

    # Compare addresses only when both are available.
    if sender_address and reply_to_address:

        findings["reply_to_mismatch"] = (
            sender_address != reply_to_address
        )

        if findings["reply_to_mismatch"]:
            findings["observations"].append(
                "The Reply-To address differs from the sender address. "
                "Review this discrepancy; it is not proof of phishing."
            )
        else:
            findings["observations"].append(
                "The sender and Reply-To addresses match."
            )

    elif reply_to_address:
        findings["observations"].append(
            "A Reply-To address is present, but the sender address "
            "could not be extracted for comparison."
        )

    else:
        findings["observations"].append(
            "No usable Reply-To address was provided, so a mismatch "
            "could not be assessed."
        )

    return findings


# ============================================================
# EMAIL ANALYSIS
# ============================================================

def analyze_email(file_path):
    """Extract email fields and record basic investigation findings."""

    # Open and parse the email file.
    with file_path.open("rb") as email_file:
        message = BytesParser(
            policy=policy.default
        ).parse(email_file)

    # Extract email headers.
    sender = str(message.get("From", "Not provided"))
    recipient = str(message.get("To", "Not provided"))
    subject = str(message.get("Subject", "Not provided"))
    date = str(message.get("Date", "Not provided"))
    reply_to = str(message.get("Reply-To", "Not provided"))
    message_id = str(message.get("Message-ID", "Not provided"))

    # Extract additional email routing headers.
    return_path = str(message.get("Return-Path", "Not provided"))

    received_headers = [
        str(header)
        for header in message.get_all("Received", [])
    ]

    # Analyze the sender and Reply-To relationship.
    header_analysis = analyze_email_headers(
        sender,
        reply_to
    )

    # Extract readable text from the email body.
    body_parts = []

    if message.is_multipart():
        for part in message.walk():

            if part.get_content_type() == "text/plain":
                try:
                    content = part.get_content()

                    if isinstance(content, str):
                        body_parts.append(content)

                except (LookupError, UnicodeDecodeError):
                    continue

    else:
        try:
            content = message.get_content()

            if isinstance(content, str):
                body_parts.append(content)

        except (LookupError, UnicodeDecodeError):
            body_parts.append("")

    body = "\n".join(body_parts)

    # Extract URL-like strings without opening them.
    urls = extract_urls(body)

    # Analyze each extracted URL locally.
    url_details = [
        analyze_url(url)
        for url in urls
    ]

    # Record general email observations.
    findings = []

    # Check for urgency-related subject wording.
    urgency_words = [
        "urgent",
        "verify",
        "suspended",
        "immediately",
        "action required",
        "account restriction"
    ]

    if subject != "Not provided":
        if any(word in subject.lower() for word in urgency_words):
            findings.append(
                "The subject contains urgency-related wording. "
                "This is an observation, not proof of phishing."
            )

    # Record Reply-To observations.
    if reply_to != "Not provided":
        findings.append(
            "A Reply-To header is present. Review its relationship "
            "with the sender address."
        )

    # Record Return-Path availability.
    if return_path == "Not provided":
        findings.append(
            "No Return-Path header was provided in this email sample."
        )

    # Record Received header availability.
    if not received_headers:
        findings.append(
            "No Received headers were provided in this email sample."
        )

    # Record URL-related observations.
    if urls:
        findings.append(
            f"The email contains {len(urls)} unique URL-like string(s). "
            "Review them safely without visiting them."
        )
    else:
        findings.append(
            "No URLs were extracted from the email body."
        )

    # Build the investigation report.
    results = {
        "case_type": "Email phishing triage",
        "source_file": file_path.name,
        "sender": sender,
        "recipient": recipient,
        "subject": subject,
        "date": date,
        "reply_to": reply_to,
        "message_id": message_id,
        "return_path": return_path,
        "received_headers": received_headers,
        "header_analysis": header_analysis,
        "extracted_urls": urls,
        "url_analysis": url_details,
        "observations": findings,
        "limitations": [
            "This tool performs basic triage, not a definitive phishing verdict.",
            "URLs are extracted as text and are never opened.",
            "URL hostnames are parsed locally and are not contacted.",
            "Email authentication is not verified by this script.",
            "URL extraction does not establish whether a destination is malicious.",
            "Header values are not independently authenticated by this script.",
            "Reply-To mismatches are investigative clues, not proof of phishing.",
            "Received headers are collected but are not independently validated.",
            "Missing headers in a sample do not establish malicious activity."
        ]
    }

    return results


# ============================================================
# REPORT GENERATION
# ============================================================

def save_report(results, email_filename):
    """Save a separate JSON report for each email sample."""

    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    # Use the email filename to create a corresponding report name.
    report_name = f"{Path(email_filename).stem}_report.json"
    output_file = REPORTS_DIR / report_name

    output_file.write_text(
        json.dumps(results, indent=4, ensure_ascii=False),
        encoding="utf-8"
    )

    return output_file


# ============================================================
# MAIN PROGRAM
# ============================================================

def main():
    """Run the analyzer using a selected sample filename."""

    # Use a default sample when no filename is supplied.
    if len(sys.argv) > 1:
        email_filename = sys.argv[1]
    else:
        email_filename = "sample_phishing_email.eml"

    # Only accept a filename directly inside the samples folder.
    if (
        Path(email_filename).name != email_filename
        or email_filename in ("", ".", "..")
    ):
        print(
            "Error: Provide only a filename located directly "
            "inside the samples folder."
        )
        raise SystemExit(1)

    email_file = SAMPLES_DIR / email_filename

    # Check that the input exists.
    if not email_file.is_file():
        print(f"Error: Email sample not found: {email_file}")
        print("Available samples:")

        if SAMPLES_DIR.is_dir():
            for sample in sorted(SAMPLES_DIR.glob("*.eml")):
                print(f"  - {sample.name}")

        raise SystemExit(1)

    # Analyze the email.
    try:
        results = analyze_email(email_file)

    except (OSError, ValueError) as error:
        print(f"Error: Could not analyze the email: {error}")
        raise SystemExit(1)

    # Display the results.
    print("\n=== EMAIL TRIAGE REPORT ===\n")

    print(
        json.dumps(
            results,
            indent=4,
            ensure_ascii=False
        )
    )

    # Save a separate JSON report.
    try:
        output_file = save_report(results, email_filename)

    except OSError as error:
        print(f"\nError: Could not save the report: {error}")
        raise SystemExit(1)

    print(f"\nReport saved to: {output_file}")


if __name__ == "__main__":
    main()