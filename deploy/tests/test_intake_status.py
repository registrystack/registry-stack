import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "examples" / "intake-status"))
from intake_status import status_payload


class IntakeStatusTest(unittest.TestCase):
    def test_returns_only_public_status(self):
        self.assertEqual(
            status_payload('{"acceptingApplications":true,"nextReviewWeekday":"Monday"}'),
            b'{"acceptingApplications":true,"nextReviewWeekday":"Monday"}\n',
        )

    def test_rejects_private_or_invalid_config(self):
        for text in (
            '{"acceptingApplications":true,"nextReviewWeekday":"Monday","applicant":"private"}',
            '{"acceptingApplications":"yes","nextReviewWeekday":"Monday"}',
            '{"acceptingApplications":true,"nextReviewWeekday":"Yesterday"}',
        ):
            with self.subTest(text=text), self.assertRaises(ValueError):
                status_payload(text)
