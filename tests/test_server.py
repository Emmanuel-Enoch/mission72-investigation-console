"""
Tests for Mission 72 Investigator Console server and upload parsing.
Verifies Python 3.13 standard library compatibility (absence of deprecated 'cgi'),
multipart form parsing, error handling, and server HTTP endpoints.
"""

import io
import threading
import unittest
import urllib.error
import urllib.parse
import urllib.request
from http.server import ThreadingHTTPServer

from mission72.server import (
    GLOBAL_STATE,
    InvestigatorRequestHandler,
    parse_multipart_form_data,
)


def build_multipart_payload(
    fields: dict,
    boundary: str = "---------------------------735323031399963166993862150",
) -> tuple[bytes, str]:
    """Helper to build standard RFC 7578 multipart/form-data byte streams."""
    lines: list[bytes] = []
    b_boundary = boundary.encode("latin1")

    for field_name, val in fields.items():
        lines.append(b"--" + b_boundary + b"\r\n")
        if isinstance(val, tuple):
            filename, file_bytes = val
            lines.append(
                f'Content-Disposition: form-data; name="{field_name}"; filename="{filename}"\r\n'.encode("latin1")
            )
            lines.append(b"Content-Type: text/csv\r\n\r\n")
            lines.append(file_bytes)
            lines.append(b"\r\n")
        else:
            lines.append(
                f'Content-Disposition: form-data; name="{field_name}"\r\n\r\n'.encode("latin1")
            )
            lines.append(val.encode("utf-8"))
            lines.append(b"\r\n")

    lines.append(b"--" + b_boundary + b"--\r\n")
    body = b"".join(lines)
    content_type = f"multipart/form-data; boundary={boundary}"
    return body, content_type


class TestMultipartFormParser(unittest.TestCase):
    """Unit tests for parse_multipart_form_data without starting an HTTP server."""

    def test_parse_valid_multipart_upload(self) -> None:
        eval_csv = (
            b"timestamp,username,source_ip,destination_host,event_type,result,logon_type\n"
            b"2026-04-06T10:00:00Z,alice,192.168.1.50,corp-dc01,LOGON,SUCCESS,INTERACTIVE\n"
        )
        train_csv = (
            b"timestamp,username,source_ip,destination_host,event_type,result,logon_type\n"
            b"2026-04-01T10:00:00Z,alice,192.168.1.50,corp-dc01,LOGON,SUCCESS,INTERACTIVE\n"
        )

        body, ctype = build_multipart_payload({
            "train_file": ("train.csv", train_csv),
            "eval_file": ("eval.csv", eval_csv),
        })

        headers = {
            "Content-Type": ctype,
            "Content-Length": str(len(body)),
        }
        rfile = io.BytesIO(body)

        fields, err = parse_multipart_form_data(headers, rfile)
        self.assertIsNone(err)
        self.assertIn("train_file", fields)
        self.assertIn("eval_file", fields)

        train_fn, train_data = fields["train_file"]
        eval_fn, eval_data = fields["eval_file"]

        self.assertEqual(train_fn, "train.csv")
        self.assertEqual(train_data, train_csv)
        self.assertEqual(eval_fn, "eval.csv")
        self.assertEqual(eval_data, eval_csv)

    def test_missing_or_invalid_content_type(self) -> None:
        rfile = io.BytesIO(b"dummy")
        fields, err = parse_multipart_form_data({}, rfile)
        self.assertIn("Invalid Content-Type", err or "")

        fields, err = parse_multipart_form_data({"Content-Type": "application/json"}, rfile)
        self.assertIn("Invalid Content-Type", err or "")

    def test_missing_or_invalid_content_length(self) -> None:
        rfile = io.BytesIO(b"dummy")
        ctype = "multipart/form-data; boundary=bound123"

        fields, err = parse_multipart_form_data({"Content-Type": ctype}, rfile)
        self.assertIn("Missing Content-Length", err or "")

        fields, err = parse_multipart_form_data({"Content-Type": ctype, "Content-Length": "abc"}, rfile)
        self.assertIn("Invalid Content-Length", err or "")

        fields, err = parse_multipart_form_data({"Content-Type": ctype, "Content-Length": "-5"}, rfile)
        self.assertIn("negative", err or "")

    def test_content_length_exceeds_limit(self) -> None:
        rfile = io.BytesIO(b"")
        ctype = "multipart/form-data; boundary=bound123"
        fields, err = parse_multipart_form_data(
            {"Content-Type": ctype, "Content-Length": str(100 * 1024 * 1024)},
            rfile,
        )
        self.assertIn("Payload too large", err or "")

    def test_incomplete_payload(self) -> None:
        body = b"--bound\r\nContent-Disposition: form-data; name=\"test\"\r\n\r\n"
        rfile = io.BytesIO(body)
        ctype = "multipart/form-data; boundary=bound"
        # Claim length is longer than available bytes
        fields, err = parse_multipart_form_data(
            {"Content-Type": ctype, "Content-Length": str(len(body) + 50)},
            rfile,
        )
        self.assertIn("Incomplete payload", err or "")

    def test_malformed_multipart_structure(self) -> None:
        body = b"This is just random garbage without boundary formatting\r\n"
        rfile = io.BytesIO(body)
        ctype = "multipart/form-data; boundary=nonexistent_boundary"
        fields, err = parse_multipart_form_data(
            {"Content-Type": ctype, "Content-Length": str(len(body))},
            rfile,
        )
        self.assertIn("delimiter not found", err or "")


class TestServerEndpoints(unittest.TestCase):
    """End-to-end integration tests using an ephemeral local ThreadingHTTPServer."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), InvestigatorRequestHandler)
        cls.port = cls.server.server_address[1]
        cls.base_url = f"http://127.0.0.1:{cls.port}"
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()

    def test_get_dashboard_home(self) -> None:
        req = urllib.request.Request(f"{self.base_url}/")
        with urllib.request.urlopen(req) as resp:
            self.assertEqual(resp.status, 200)
            self.assertEqual(resp.headers.get_content_type(), "text/html")
            content = resp.read().decode("utf-8")
            self.assertIn("Mission 72", content)
            self.assertIn("Analyze new logs", content)

    def test_analyze_synthetic_and_export_reports(self) -> None:
        # Trigger synthetic analysis
        req = urllib.request.Request(f"{self.base_url}/analyze-synthetic")
        with urllib.request.urlopen(req) as resp:
            self.assertEqual(resp.status, 200)  # Follows 302 redirect to /
            content = resp.read().decode("utf-8")
            self.assertIn("INC-", content)
            self.assertIn("Risk Score / 100", content)

        # Verify export endpoints work cleanly
        for path, expected_type in [
            ("/export/incidents.csv", "text/csv"),
            ("/export/evidence.csv", "text/csv"),
            ("/export/users.csv", "text/csv"),
            ("/export/report.html", "text/html"),
        ]:
            with urllib.request.urlopen(f"{self.base_url}{path}") as resp:
                self.assertEqual(resp.status, 200)
                self.assertEqual(resp.headers.get_content_type(), expected_type)
                data = resp.read()
                self.assertGreater(len(data), 0)

    def test_post_upload_valid_logs(self) -> None:
        eval_csv = (
            b"timestamp,username,source_ip,destination_host,event_type,result,logon_type\n"
            b"2026-04-06T12:00:00Z,charlie,198.51.100.22,corp-dc01,LOGON,FAILURE,NETWORK\n"
            b"2026-04-06T12:01:00Z,charlie,198.51.100.22,corp-dc01,LOGON,FAILURE,NETWORK\n"
            b"2026-04-06T12:02:00Z,charlie,198.51.100.22,corp-dc01,LOGON,FAILURE,NETWORK\n"
            b"2026-04-06T12:03:00Z,charlie,198.51.100.22,corp-dc01,LOGON,FAILURE,NETWORK\n"
            b"2026-04-06T12:04:00Z,charlie,198.51.100.22,corp-dc01,LOGON,FAILURE,NETWORK\n"
        )
        body, ctype = build_multipart_payload({
            "eval_file": ("test_eval.csv", eval_csv),
        })

        req = urllib.request.Request(
            f"{self.base_url}/analyze",
            data=body,
            headers={
                "Content-Type": ctype,
                "Content-Length": str(len(body)),
            },
            method="POST",
        )
        with urllib.request.urlopen(req) as resp:
            self.assertEqual(resp.status, 200)  # Followed 302 to /
            content = resp.read().decode("utf-8")
            self.assertIn("charlie", content)

    def test_post_upload_missing_eval_file_returns_400(self) -> None:
        # Upload with empty eval_file
        body, ctype = build_multipart_payload({
            "train_file": ("train.csv", b"timestamp,username\n"),
            "eval_file": ("", b""),
        })

        req = urllib.request.Request(
            f"{self.base_url}/analyze",
            data=body,
            headers={
                "Content-Type": ctype,
                "Content-Length": str(len(body)),
            },
            method="POST",
        )
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req)
        self.assertEqual(ctx.exception.code, 400)
        err_msg = ctx.exception.read().decode("utf-8")
        self.assertIn("Evaluation CSV file is required", err_msg)

    def test_post_upload_invalid_content_type_returns_400(self) -> None:
        req = urllib.request.Request(
            f"{self.base_url}/analyze",
            data=b"raw body text",
            headers={
                "Content-Type": "text/plain",
                "Content-Length": "13",
            },
            method="POST",
        )
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req)
        self.assertEqual(ctx.exception.code, 400)


if __name__ == "__main__":
    unittest.main()
