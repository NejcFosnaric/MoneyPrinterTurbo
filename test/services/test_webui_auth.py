import os
import textwrap
import unittest
from pathlib import Path
from unittest.mock import patch

from streamlit.testing.v1 import AppTest

from webui import auth


ROOT_DIR = Path(__file__).parent.parent.parent

# 登录门用一个最小脚本驱动即可完整覆盖。webui/Main.py 会加载全部业务服务，
# 在这里引入只会让用例变慢，并把无关模块的故障算到鉴权测试头上。
GATE_SCRIPT = textwrap.dedent(
    f"""
    import sys

    sys.path.insert(0, {str(ROOT_DIR)!r})

    import streamlit as st

    from webui import auth

    auth.require_login()
    st.write("PROTECTED CONTENT")
    """
)

PROTECTED_MARKER = "PROTECTED CONTENT"


def _rendered_text(app):
    """收集页面上所有文本，用于断言受保护内容是否真的渲染。"""
    chunks = [element.value for element in app.markdown]
    chunks.extend(element.value for element in app.title)
    chunks.extend(element.value for element in app.error)
    return "\n".join(str(chunk) for chunk in chunks)


class TestWebuiAuthCredentials(unittest.TestCase):
    """凭据校验只依赖环境变量，与 Streamlit 运行时无关。"""

    def test_gate_is_disabled_until_a_password_is_configured(self):
        """未配置密码时保持本地工具的免登录体验。"""

        with patch.dict(os.environ, {}, clear=True):
            self.assertFalse(auth.is_enabled())

        with patch.dict(os.environ, {auth.PASSWORD_ENV: ""}, clear=True):
            self.assertFalse(auth.is_enabled())

        with patch.dict(os.environ, {auth.PASSWORD_ENV: "s3cret"}, clear=True):
            self.assertTrue(auth.is_enabled())

    def test_username_defaults_to_admin_and_ignores_surrounding_spaces(self):
        """部署平台的变量输入常带首尾空格，不应因此锁死账号。"""

        with patch.dict(os.environ, {auth.PASSWORD_ENV: "s3cret"}, clear=True):
            self.assertTrue(auth._credentials_match("admin", "s3cret"))

        with patch.dict(
            os.environ,
            {auth.PASSWORD_ENV: "s3cret", auth.USERNAME_ENV: "  nejc  "},
            clear=True,
        ):
            self.assertTrue(auth._credentials_match("nejc", "s3cret"))
            # 配置了自定义用户名后，默认的 admin 必须失效。
            self.assertFalse(auth._credentials_match("admin", "s3cret"))

    def test_wrong_credentials_are_rejected(self):
        with patch.dict(os.environ, {auth.PASSWORD_ENV: "s3cret"}, clear=True):
            self.assertFalse(auth._credentials_match("admin", "wrong"))
            self.assertFalse(auth._credentials_match("root", "s3cret"))
            self.assertFalse(auth._credentials_match("", ""))

    def test_non_ascii_credentials_do_not_raise(self):
        """compare_digest 只接受同类型字节串，非 ASCII 口令必须显式编码。"""

        with patch.dict(
            os.environ,
            {auth.PASSWORD_ENV: "pä$$wörd", auth.USERNAME_ENV: "üser"},
            clear=True,
        ):
            self.assertTrue(auth._credentials_match("üser", "pä$$wörd"))
            self.assertFalse(auth._credentials_match("üser", "pässword"))


class TestWebuiAuthGate(unittest.TestCase):
    """从真实 Streamlit 运行时验证登录门确实拦住了页面内容。"""

    def setUp(self):
        # 登录失败的固定延时用于限速，会拖慢用例，这里去掉。
        patcher = patch.object(auth, "_FAILED_ATTEMPT_DELAY_SECONDS", 0)
        patcher.start()
        self.addCleanup(patcher.stop)

    def _run(self, env):
        with patch.dict(os.environ, env, clear=True):
            app = AppTest.from_string(GATE_SCRIPT, default_timeout=30)
            app.run()
            return app

    def test_disabled_gate_renders_the_page_directly(self):
        app = self._run({})

        self.assertFalse(app.exception, msg=str(app.exception))
        self.assertIn(PROTECTED_MARKER, _rendered_text(app))

    def test_enabled_gate_blocks_content_and_shows_the_login_form(self):
        """st.stop() 之后受保护内容不得出现在响应里。"""

        app = self._run({auth.PASSWORD_ENV: "s3cret"})

        rendered = _rendered_text(app)
        self.assertNotIn(PROTECTED_MARKER, rendered)
        self.assertIn("Login Required", rendered)
        self.assertEqual(len(app.text_input), 2)

    def test_wrong_password_keeps_the_page_blocked(self):
        with patch.dict(os.environ, {auth.PASSWORD_ENV: "s3cret"}, clear=True):
            app = AppTest.from_string(GATE_SCRIPT, default_timeout=30)
            app.run()

            app.text_input[0].set_value("admin")
            app.text_input[1].set_value("wrong")
            app.button[0].click().run()

            rendered = _rendered_text(app)
            self.assertNotIn(PROTECTED_MARKER, rendered)
            self.assertIn("Incorrect username or password", rendered)

    def test_correct_password_unlocks_the_page(self):
        with patch.dict(os.environ, {auth.PASSWORD_ENV: "s3cret"}, clear=True):
            app = AppTest.from_string(GATE_SCRIPT, default_timeout=30)
            app.run()

            app.text_input[0].set_value("admin")
            app.text_input[1].set_value("s3cret")
            app.button[0].click().run()

            self.assertIn(PROTECTED_MARKER, _rendered_text(app))

    def test_submitting_an_empty_form_reports_missing_input(self):
        with patch.dict(os.environ, {auth.PASSWORD_ENV: "s3cret"}, clear=True):
            app = AppTest.from_string(GATE_SCRIPT, default_timeout=30)
            app.run()

            app.button[0].click().run()

            rendered = _rendered_text(app)
            self.assertNotIn(PROTECTED_MARKER, rendered)
            self.assertIn("Please enter your username and password", rendered)


if __name__ == "__main__":
    unittest.main()
