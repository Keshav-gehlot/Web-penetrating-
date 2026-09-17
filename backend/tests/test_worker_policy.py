from app.worker import MAX_ATTEMPTS, normalize_attempt, recovery_attempt


def test_normalize_attempt_defaults_invalid_values():
    assert normalize_attempt(None) == 1
    assert normalize_attempt("invalid") == 1


def test_normalize_attempt_stays_within_retry_ceiling():
    assert normalize_attempt(0) == 1
    assert normalize_attempt(1) == 1
    assert normalize_attempt(MAX_ATTEMPTS) == MAX_ATTEMPTS
    assert normalize_attempt(MAX_ATTEMPTS + 10) == MAX_ATTEMPTS


def test_recovery_advances_attempt_until_ceiling():
    assert recovery_attempt(None) == 2
    assert recovery_attempt(1) == 2
    assert recovery_attempt(MAX_ATTEMPTS - 1) == MAX_ATTEMPTS
    assert recovery_attempt(MAX_ATTEMPTS) is None
    assert recovery_attempt(MAX_ATTEMPTS + 5) is None


def test_recovery_handles_invalid_attempt_values():
    assert recovery_attempt("invalid") == 2
