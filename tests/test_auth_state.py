from xsscane.modules.navigator import AuthState, AuthStateDetector

D = AuthStateDetector()


def _signals(**kw):
    base = {"loginForm": False, "loginKeywords": False, "otp": False, "captcha": False,
            "blocked": False, "logout": False, "accountUi": False}
    base.update(kw)
    return base


def classify(signals, status, authed):
    return D.classify_detailed(signals, status, authed)[0]


def test_anonymous_and_login_link():
    assert classify(_signals(), 200, False) == AuthState.ANONYMOUS
    assert classify(_signals(loginKeywords=True), 200, False) == AuthState.ANONYMOUS


def test_login_vs_expired_is_history_aware():
    assert classify(_signals(loginForm=True), 200, False) == AuthState.LOGIN_PAGE
    assert classify(_signals(loginForm=True), 200, True) == AuthState.EXPIRED


def test_change_password_while_authed_is_not_expired():
    state = classify(_signals(loginForm=True, logout=True, accountUi=True), 200, True)
    assert state == AuthState.AUTHENTICATED


def test_authenticated_signals():
    assert classify(_signals(logout=True), 200, False) == AuthState.AUTHENTICATED
    assert classify(_signals(accountUi=True), 200, False) == AuthState.AUTHENTICATED


def test_hard_walls():
    assert classify(_signals(otp=True), 200, True) == AuthState.MFA_REQUIRED
    assert classify(_signals(captcha=True), 200, False) == AuthState.CAPTCHA
    assert classify(_signals(), 429, True) == AuthState.BLOCKED
    assert classify(_signals(), 403, True) == AuthState.BLOCKED
    assert classify(_signals(loginForm=True), 403, False) == AuthState.LOGIN_PAGE
    assert classify(_signals(loginForm=True, otp=True), 200, True) == AuthState.MFA_REQUIRED
