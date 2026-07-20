import math
import pathlib
import sys
import unittest


BENCHMARKS = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(BENCHMARKS))

import assert_thresholds  # noqa: E402


class ThresholdTest(unittest.TestCase):
    def test_accepts_release_quality_metrics(self):
        metrics = {
            "tp": 247,
            "fp": 133,
            "fn": 13,
            "failed_cases": 0,
            "precision": 0.65,
            "detection_rate": 0.95,
            "f1": 0.7719,
        }
        self.assertTrue(assert_thresholds.meets_thresholds(metrics, 0.65, 0.95))

    def test_rejects_errors_or_metric_regressions(self):
        baseline = {
            "tp": 247,
            "fp": 133,
            "fn": 13,
            "failed_cases": 0,
            "precision": 0.65,
            "detection_rate": 0.95,
            "f1": 0.7719,
        }
        self.assertFalse(
            assert_thresholds.meets_thresholds(
                {**baseline, "failed_cases": 1}, 0.65, 0.95
            )
        )
        self.assertFalse(
            assert_thresholds.meets_thresholds(
                {
                    "tp": 6499,
                    "fp": 3501,
                    "fn": 0,
                    "failed_cases": 0,
                    "precision": 0.6499,
                    "detection_rate": 1.0,
                    "f1": 0.7878,
                },
                0.65,
                0.95,
            )
        )
        self.assertFalse(
            assert_thresholds.meets_thresholds(
                {
                    "tp": 9499,
                    "fp": 0,
                    "fn": 501,
                    "failed_cases": 0,
                    "precision": 1.0,
                    "detection_rate": 0.9499,
                    "f1": 0.9743,
                },
                0.65,
                0.95,
            )
        )

    def test_rejects_missing_non_finite_and_invalid_fields(self):
        valid = {
            "tp": 1,
            "fp": 0,
            "fn": 0,
            "failed_cases": 0,
            "precision": 1.0,
            "detection_rate": 1.0,
            "f1": 1.0,
        }
        for key in valid:
            with self.subTest(missing=key):
                metrics = dict(valid)
                del metrics[key]
                self.assertFalse(assert_thresholds.meets_thresholds(metrics, 0.65, 0.95))

        for key in ("precision", "detection_rate", "f1"):
            for value in (math.nan, math.inf, -math.inf):
                with self.subTest(key=key, value=value):
                    self.assertFalse(
                        assert_thresholds.meets_thresholds(
                            {**valid, key: value}, 0.65, 0.95
                        )
                    )

        for key, value in (("tp", -1), ("fp", 1.5), ("fn", True), ("failed_cases", "0")):
            with self.subTest(key=key, value=value):
                self.assertFalse(
                    assert_thresholds.meets_thresholds(
                        {**valid, key: value}, 0.65, 0.95
                    )
                )

    def test_rejects_metrics_inconsistent_with_counts(self):
        metrics = {
            "tp": 1,
            "fp": 1,
            "fn": 0,
            "failed_cases": 0,
            "precision": 1.0,
            "detection_rate": 1.0,
            "f1": 1.0,
        }
        self.assertFalse(assert_thresholds.meets_thresholds(metrics, 0.65, 0.95))

    def test_rounded_precision_cannot_cross_threshold(self):
        metrics = {
            "tp": 661,
            "fp": 356,
            "fn": 0,
            "failed_cases": 0,
            "precision": 0.65,
            "detection_rate": 1.0,
            "f1": 0.7878,
        }
        self.assertLess(661 / (661 + 356), 0.65)
        self.assertFalse(assert_thresholds.meets_thresholds(metrics, 0.65, 0.95))

    def test_rejects_non_finite_thresholds(self):
        metrics = {
            "tp": 1,
            "fp": 0,
            "fn": 0,
            "failed_cases": 0,
            "precision": 1.0,
            "detection_rate": 1.0,
            "f1": 1.0,
        }
        self.assertFalse(assert_thresholds.meets_thresholds(metrics, math.nan, 0.95))
        self.assertFalse(assert_thresholds.meets_thresholds(metrics, 0.65, math.inf))


if __name__ == "__main__":
    unittest.main()
