# -*- coding: utf-8 -*-
"""
CPA OAuth 交互与浏览器静默授权模块

流程：
1. 向 CPA Management API 发起 GET /v0/management/xai-auth-url
2. 拿到 CPA 发起的 device flow URL (含 user_code) 与 state
3. 使用带账号 SSO 的 Chromium 浏览器打开 URL
4. 页面若出现 Allow 按钮自动点击；或表单自动提交 user_code 完成授权
5. 轮询 CPA GET /v0/management/get-auth-status?state=... 直至 ok，由 CPA 自己完成 token 交换和文件落盘
"""

from __future__ import annotations

import time
import urllib.parse
from typing import Callable, Optional

from curl_cffi import requests
import browser_session as _bs

LogFn = Optional[Callable[[str], None]]
StopFn = Optional[Callable[[], bool]]


def start_cpa_xai_auth(cpa_url: str, management_key: str, timeout: int = 15) -> dict:
    """调 CPA GET /v0/management/xai-auth-url，返回 dict(url, state, user_code, ...)"""
    base = (cpa_url or "").strip().rstrip("/")
    key = (management_key or "").strip()
    if not base:
        raise ValueError("cpa_remote_url 为空")
    if not key:
        raise ValueError("cpa_management_key 为空")

    url = f"{base}/v0/management/xai-auth-url"
    resp = requests.get(
        url,
        headers={
            "Authorization": f"Bearer {key}",
            "Accept": "application/json",
        },
        timeout=timeout,
    )
    if resp.status_code >= 400:
        raise RuntimeError(f"CPA xai-auth-url 响应 HTTP {resp.status_code}: {(resp.text or '')[:200]}")
    data = resp.json()
    if data.get("status") != "ok" or not data.get("url") or not data.get("state"):
        raise RuntimeError(f"CPA xai-auth-url 响应异常: {data}")
    return data


def poll_cpa_auth_status(
    cpa_url: str,
    management_key: str,
    state: str,
    timeout: int = 120,
    interval: float = 2.0,
    should_stop: StopFn = None,
    log: LogFn = None,
) -> bool:
    """轮询 CPA GET /v0/management/get-auth-status?state=...，直到 status == 'ok'"""
    base = (cpa_url or "").strip().rstrip("/")
    key = (management_key or "").strip()
    url = f"{base}/v0/management/get-auth-status"

    deadline = time.time() + timeout
    while time.time() < deadline:
        if should_stop and should_stop():
            cancel_cpa_auth_session(cpa_url, management_key, state, log=log)
            return False

        try:
            resp = requests.get(
                url,
                params={"state": state},
                headers={
                    "Authorization": f"Bearer {key}",
                    "Accept": "application/json",
                },
                timeout=10,
            )
            if resp.status_code == 200:
                data = resp.json()
                st = data.get("status")
                if st == "ok":
                    return True
                if st == "error":
                    err_msg = data.get("error") or "未知错误"
                    if log:
                        log(f"[CPA-OAuth] 授权被拒或失败: {err_msg}")
                    return False
        except Exception as exc:
            if log:
                log(f"[CPA-OAuth] 查询 status 轮询异常: {exc}")

        time.sleep(interval)

    if log:
        log("[CPA-OAuth] 等待 CPA 授权完成超时")
    cancel_cpa_auth_session(cpa_url, management_key, state, log=log)
    return False


def cancel_cpa_auth_session(
    cpa_url: str, management_key: str, state: str, log: LogFn = None
) -> None:
    """取消 CPA pending oauth session"""
    try:
        base = (cpa_url or "").strip().rstrip("/")
        key = (management_key or "").strip()
        url = f"{base}/v0/management/oauth-session"
        requests.delete(
            url,
            params={"state": state},
            headers={"Authorization": f"Bearer {key}"},
            timeout=5,
        )
        if log:
            log(f"[CPA-OAuth] 已取消 CPA Session: {state}")
    except Exception:
        pass


def authorize_in_browser(
    auth_url: str,
    sso_cookie: str,
    log: LogFn = None,
    should_stop: StopFn = None,
) -> bool:
    """复用当前注册使用的浏览器页面（若存在），或启动新浏览器，注入 SSO 后进行 CPA OAuth 授权。"""
    page_obj = _bs.active_page()
    browser_obj = _bs.active_browser()
    own_browser = False

    if page_obj is None or browser_obj is None:
        try:
            _bs._keep_windows_background = False
            browser_obj, page_obj = _bs.start_browser(log_callback=log, cancel_callback=should_stop)
            own_browser = True
        except Exception as exc:
            if log:
                log(f"[CPA-OAuth] 启动浏览器失败: {exc}")
            return False

    try:
        if should_stop and should_stop():
            return False

        # 1. 注入 SSO cookie 到 x.ai 相关全域
        clean_sso = str(sso_cookie or "").strip()
        if clean_sso.lower().startswith("sso="):
            clean_sso = clean_sso[4:].split(";")[0].strip()

        try:
            current_url = str(page_obj.url or "").lower()
            if "x.ai" not in current_url:
                page_obj.get("https://accounts.x.ai/", timeout=10)
        except Exception:
            pass

        cookies_to_set = [
            {"name": "sso", "value": clean_sso, "domain": ".x.ai", "path": "/"},
            {"name": "sso-rw", "value": clean_sso, "domain": ".x.ai", "path": "/"},
            {"name": "sso", "value": clean_sso, "domain": "accounts.x.ai", "path": "/"},
            {"name": "sso-rw", "value": clean_sso, "domain": "accounts.x.ai", "path": "/"},
        ]
        try:
            page_obj.set.cookies(cookies_to_set)
        except Exception as e:
            if log:
                log(f"[CPA-OAuth] 写入 SSO Cookie 警告: {e}")

        # 2. 导航至 CPA 返回的 oauth url
        if log:
            log(f"[CPA-OAuth] 浏览器（复用注册窗口）打开授权页面: {auth_url}")
        page_obj.get(auth_url, timeout=20)

        # 3. 页面交互逻辑：检测授权状态并自动处理按钮/表单（如“继续”、“Allow”、“授权”等）
        deadline = time.time() + 35
        clicked = False
        while time.time() < deadline:
            if should_stop and should_stop():
                return False

            url_now = str(page_obj.url or "").lower()
            if "device/done" in url_now or "authorized" in url_now or "success" in url_now:
                if log:
                    log("[CPA-OAuth] 浏览器已跳转至授权完成页")
                return True

            # 自动匹配各种界面的确认/授权按钮（包括“继续”、“Allow”、“同意”、“Confirm”等）
            try:
                btn = None
                for selector in (
                    "@type=submit",
                    "css:form button[type='submit']",
                    "text:继续", "text:Continue", "text:Allow", "text:允许",
                    "text:Authorize", "text:授权", "text:Confirm", "text:确认"
                ):
                    try:
                        found = page_obj.ele(selector, timeout=0.3)
                        if found and found.is_valid:
                            btn = found
                            break
                    except Exception:
                        pass

                if not btn:
                    for b in page_obj.eles("tag:button") or []:
                        txt = str(b.text or "").strip().lower()
                        if any(kw in txt for kw in ("继续", "continue", "allow", "允许", "authorize", "授权", "confirm", "确认", "yes", "同意", "提交")):
                            btn = b
                            break

                if btn and btn.is_valid:
                    btn_text = str(btn.text or "").strip()
                    if log:
                        log(f"[CPA-OAuth] 找到授权提交按钮: {btn_text!r}，正在触发点击...")
                    try:
                        btn.click()
                    except Exception:
                        btn.click(by_js=True)
                    clicked = True
                    time.sleep(2)
                    url_after = str(page_obj.url or "").lower()
                    if "device/done" in url_after or "authorized" in url_after or "success" in url_after:
                        if log:
                            log("[CPA-OAuth] 点击按钮后浏览器已跳转至授权完成页")
                        return True
            except Exception:
                pass

            time.sleep(1)

        url_final = str(page_obj.url or "").lower()
        if clicked or "done" in url_final or "authorized" in url_final or "success" in url_final:
            return True

        if log:
            log(f"[CPA-OAuth] 浏览器等待授权界面超时 (当前 URL: {page_obj.url})")
        return False
    except Exception as exc:
        if log:
            log(f"[CPA-OAuth] 浏览器授权过程异常: {exc}")
        return False
    finally:
        # 如果是本函数自己新建的浏览器才关闭；如果是复用注册过程的浏览器，不要强制 quit
        if own_browser:
            try:
                _bs.stop_browser()
            except Exception:
                pass


def process_cpa_oauth_flow(
    sso_cookie: str,
    cpa_url: str,
    management_key: str,
    email: str = "",
    log: LogFn = None,
    should_stop: StopFn = None,
) -> bool:
    """全流程：向 CPA 申请 oauth url -> 浏览器注入 SSO 自动点击 -> 轮询 CPA 确认入库完成"""
    cpa_url = (cpa_url or "").strip().rstrip("/")
    management_key = (management_key or "").strip()
    if not cpa_url or not management_key:
        if log:
            log("[CPA-OAuth] 未配置 cpa_remote_url 或 cpa_management_key")
        return False

    if log:
        log(f"[CPA-OAuth] 开始为 {email or '账号'} 发起 CPA 官方 OAuth 授权流程...")

    # 1. 申请 OAuth URL
    try:
        auth_data = start_cpa_xai_auth(cpa_url, management_key)
    except Exception as exc:
        if log:
            log(f"[CPA-OAuth] 调 CPA xai-auth-url 失败: {exc}")
        return False

    auth_url = auth_data["url"]
    state = auth_data["state"]
    user_code = auth_data.get("user_code", "")
    if log:
        log(f"[CPA-OAuth] 成功获取 CPA Device Flow 链接, user_code={user_code}, state={state}")

    # 2. 浏览器打开链接并授权
    browser_ok = authorize_in_browser(
        auth_url,
        sso_cookie,
        log=log,
        should_stop=should_stop,
    )
    if not browser_ok:
        if log:
            log("[CPA-OAuth] 浏览器端授权未成功完成")
        cancel_cpa_auth_session(cpa_url, management_key, state, log=log)
        return False

    # 3. 轮询 CPA 状态直到保存完成
    if log:
        log("[CPA-OAuth] 浏览器授权提交完成，等待 CPA 后台换 Token 并落盘...")

    ok = poll_cpa_auth_status(
        cpa_url,
        management_key,
        state,
        timeout=60,
        interval=1.5,
        should_stop=should_stop,
        log=log,
    )
    if ok:
        if log:
            log(f"[CPA-OAuth] ✅ 账号 {email or ''} 已通过 CPA OAuth 成功保存并热加载！")
        return True
    else:
        if log:
            log(f"[CPA-OAuth] ❌ 账号 {email or ''} CPA OAuth 确认超时或失败")
        return False
