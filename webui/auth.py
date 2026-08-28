"""Optional login gate for the WebUI, configured entirely from the environment.

Credentials are read from environment variables rather than config.toml so that
deployments can enable authentication without writing secrets to disk. config.toml
is a bind-mounted file shared with the API container, and on PaaS platforms it is
frequently re-created from config.example.toml, so it is a poor home for a
password.

The gate is disabled when MPT_WEBUI_PASSWORD is unset or empty, which preserves
the default "local tool, just run it" experience. This mirrors the API side,
where an empty app.api_key means authentication is off (see app/asgi.py).

Scope: this protects the WebUI only. The FastAPI service is a separate process
and is guarded independently by app.api_key.
"""

import hmac
import os
import time

import streamlit as st
from loguru import logger

USERNAME_ENV = "MPT_WEBUI_USERNAME"
PASSWORD_ENV = "MPT_WEBUI_PASSWORD"

_DEFAULT_USERNAME = "admin"
_AUTHENTICATED_KEY = "_webui_authenticated"
_DISABLED_WARNING_KEY = "_webui_auth_disabled_warned"

# 登录失败后固定延时，压低在线爆破速率。与 compare_digest 一起使用，避免
# 通过响应时间区分"用户名错误"和"密码错误"。
_FAILED_ATTEMPT_DELAY_SECONDS = 1.0


def _expected_credentials():
    """Return the (username, password) pair the gate accepts."""
    username = os.getenv(USERNAME_ENV, "").strip() or _DEFAULT_USERNAME
    password = os.getenv(PASSWORD_ENV, "")
    return username, password


def is_enabled():
    """The gate is active only once a non-empty password is configured."""
    _, password = _expected_credentials()
    return bool(password)


def _credentials_match(username, password):
    expected_username, expected_password = _expected_credentials()
    # 两个比较都执行完再取与：`and` 的短路会让"用户名错误"比"密码错误"提前
    # 返回，从而通过响应时间泄露哪一项不匹配。
    username_ok = hmac.compare_digest(
        username.encode("utf-8"), expected_username.encode("utf-8")
    )
    password_ok = hmac.compare_digest(
        password.encode("utf-8"), expected_password.encode("utf-8")
    )
    return username_ok and password_ok


def _render_login_form(translate):
    _, center, _ = st.columns([1, 2, 1])
    with center:
        st.title(translate("Login Required"))
        with st.form("webui_login"):
            username = st.text_input(translate("Username"), autocomplete="username")
            password = st.text_input(
                translate("Password"), type="password", autocomplete="current-password"
            )
            submitted = st.form_submit_button(translate("Login"))

        if not submitted:
            return

        if not username or not password:
            st.error(translate("Please enter your username and password"))
            return

        if _credentials_match(username, password):
            st.session_state[_AUTHENTICATED_KEY] = True
            st.rerun()

        time.sleep(_FAILED_ATTEMPT_DELAY_SECONDS)
        # 不记录尝试使用的用户名，避免把口令粘贴到用户名框的输入写进日志。
        logger.warning("WebUI login attempt failed")
        st.error(translate("Incorrect username or password"))


def _render_logout_control(translate):
    with st.sidebar:
        if st.button(translate("Logout"), key="webui_logout"):
            st.session_state[_AUTHENTICATED_KEY] = False
            st.rerun()


def require_login(translate=None):
    """Block the page until the visitor authenticates.

    Call this before any settings are rendered. When the gate is disabled this
    returns immediately, so the local workflow is unchanged.

    Args:
        translate: optional ``tr``-style lookup used for the form labels. The
            required keys already ship in every webui/i18n locale.
    """
    translate = translate or (lambda key: key)

    if not is_enabled():
        if not st.session_state.get(_DISABLED_WARNING_KEY):
            logger.warning(
                "WebUI authentication is disabled; "
                f"set {PASSWORD_ENV} to require a login"
            )
            st.session_state[_DISABLED_WARNING_KEY] = True
        return

    if st.session_state.get(_AUTHENTICATED_KEY):
        _render_logout_control(translate)
        return

    _render_login_form(translate)
    # st.stop() 结束本次脚本执行，页面上只会留下上面的登录表单。
    st.stop()
