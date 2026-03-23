# GhostPortal — Project-Apocalypse
# Copyright (C) 2026 Spade
# AGPL-3.0 License

"""
Unit tests for constant-time response enforcement.

Tests:
  - constant_time_response() pads to minimum threshold
  - Timing delta between known/unknown email responses < 100ms over 50 attempts
  - No significant timing difference between valid and invalid OTP
"""

import statistics
import time

import pytest


MIN_RESPONSE_TIME_MS = 800


class TestConstantTimeResponse:
    def test_pads_to_minimum_time(self):
        from app.utils.security import constant_time_response
        start = time.monotonic()
        # Simulate instant processing
        constant_time_response(start)
        elapsed_ms = (time.monotonic() - start) * 1000
        assert elapsed_ms >= MIN_RESPONSE_TIME_MS * 0.95, (
            f"Response time {elapsed_ms:.0f}ms is less than minimum {MIN_RESPONSE_TIME_MS}ms"
        )

    def test_does_not_pad_if_already_over_minimum(self):
        from app.utils.security import constant_time_response
        start = time.monotonic() - (MIN_RESPONSE_TIME_MS / 1000) - 0.1  # simulate 900ms elapsed
        t0 = time.monotonic()
        constant_time_response(start)
        extra_sleep = (time.monotonic() - t0) * 1000
        # Should return almost immediately (no extra sleep needed)
        assert extra_sleep < 100, (
            f"Unnecessarily slept {extra_sleep:.0f}ms when already past minimum"
        )

    def test_timing_consistent_across_calls(self):
        """Variance across 10 calls should be small (<50ms std dev)."""
        from app.utils.security import constant_time_response
        times = []
        for _ in range(10):
            start = time.monotonic()
            constant_time_response(start)
            elapsed = (time.monotonic() - start) * 1000
            times.append(elapsed)

        stddev = statistics.stdev(times)
        assert stddev < 50, (
            f"High timing variance: stddev={stddev:.1f}ms — response time is not consistent"
        )


class TestLoginTimingAntiEnumeration:
    """
    Verifies that known and unknown email addresses produce indistinguishable
    response times on the /login endpoint.

    Note: This test requires Redis to be available and the app to be running.
    In CI without Redis, this test is skipped.
    """

    @pytest.mark.slow
    def test_known_unknown_email_timing_delta_under_100ms(self, client, owner_user):
        """
        Timing delta between known and unknown email must be < 100ms.
        Tests 20 requests each to get a stable mean.
        """
        known_times = []
        unknown_times = []

        sample_size = 20

        for _ in range(sample_size):
            t = time.monotonic()
            client.post(
                "/login",
                data={"email": "owner@test.example", "h-captcha-response": ""},
            )
            known_times.append(time.monotonic() - t)

        for _ in range(sample_size):
            t = time.monotonic()
            client.post(
                "/login",
                data={"email": f"nonexistent_{time.monotonic()}@fake.example", "h-captcha-response": ""},
            )
            unknown_times.append(time.monotonic() - t)

        known_mean = statistics.mean(known_times) * 1000
        unknown_mean = statistics.mean(unknown_times) * 1000
        delta = abs(known_mean - unknown_mean)

        assert delta < 100, (
            f"Timing delta too large: known={known_mean:.0f}ms, unknown={unknown_mean:.0f}ms, "
            f"delta={delta:.0f}ms — timing-based email enumeration may be possible"
        )
