# -*- coding: utf-8 -*-
import os
import glob
import json
import requests

APP_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(APP_DIR, "config.json")
ACCOUNTS_DIR = os.path.join(APP_DIR, "accounts")


def load_grok2api_config():
    """从 config.json 读取 grok2api 地址与管理员凭据。"""
    cfg = {}
    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            cfg = json.load(f)
    except (OSError, ValueError):
        pass
    if not isinstance(cfg, dict):
        cfg = {}
    base = str(cfg.get("grok2api_url", "") or "").strip().rstrip("/")
    if not base:
        base = "http://127.0.0.1:8000"
    return {
        "base": base,
        "user": str(cfg.get("grok2api_admin_user", "admin") or "admin").strip(),
        "password": str(cfg.get("grok2api_admin_password", "") or "").strip(),
    }


def get_admin_token():
    g2a = load_grok2api_config()
    if not g2a["password"]:
        print("[!] config.json 未配置 grok2api_admin_password，无法登录")
        return None
    login_url = f"{g2a['base']}/api/admin/v1/auth/login"
    try:
        resp = requests.post(
            login_url,
            json={"username": g2a["user"], "password": g2a["password"]},
            timeout=10,
            proxies={"http": None, "https": None}
        )
        if resp.status_code == 200:
            data = resp.json()
            tokens = (data.get("data") or {}).get("tokens") or {}
            token = tokens.get("accessToken") or data.get("accessToken")
            return token
        else:
            print(f"[FAIL] 登录 grok2api 失败 HTTP {resp.status_code}: {resp.text}")
            return None
    except Exception as e:
        print(f"[ERROR] 登录 grok2api 请求异常: {e}")
        return None

def parse_account_file(file_path):
    accounts = []
    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            parts = line.split("----")
            if len(parts) >= 3:
                email = parts[0].strip()
                sso = parts[2].strip()
                accounts.append({"email": email, "sso_token": sso, "token": sso, "sso": sso})
            elif len(parts) == 2:
                email = parts[0].strip()
                sso = parts[1].strip()
                accounts.append({"email": email, "sso_token": sso, "token": sso, "sso": sso})
            elif len(parts) == 1:
                sso = parts[0].strip()
                accounts.append({"email": "", "sso_token": sso, "token": sso, "sso": sso})
    return accounts

def main():
    g2a = load_grok2api_config()
    import_url = f"{g2a['base']}/api/admin/v1/accounts/web/import"
    token = get_admin_token()
    if not token:
        print("[!] 无法获取 admin 鉴权 token，停止导入")
        return
    print(f"[OK] 成功登录 grok2api，获取到鉴权 Token！")

    txt_files = glob.glob(os.path.join(ACCOUNTS_DIR, "accounts_*.txt"))
    print(f"找到 {len(txt_files)} 个账号 TXT 文件")

    all_items = []
    seen_sso = set()

    for tf in txt_files:
        accs = parse_account_file(tf)
        for a in accs:
            sso = a["sso_token"]
            if sso and sso not in seen_sso:
                seen_sso.add(sso)
                all_items.append(a)

    print(f"去重后共收集到 {len(all_items)} 个历史账号 Cookie (SSO)")
    if not all_items:
        print("没有可导入的账号")
        return

    headers = {"Authorization": f"Bearer {token}"}

    # 按照 grok2api 官方的标准文档结构打包
    import_doc = {
        "provider": "grok_web",
        "accounts": all_items
    }

    payload_data = json.dumps(import_doc, ensure_ascii=False).encode("utf-8")
    files = {"file": ("grok_web_import.json", payload_data, "application/json")}

    try:
        resp = requests.post(
            IMPORT_URL,
            files=files,
            headers=headers,
            timeout=30,
            proxies={"http": None, "https": None}
        )
        if resp.status_code == 200:
            print(f"[OK] 批量 {len(all_items)} 个账号导入响应成功!")
        else:
            print(f"[FAIL] 导入失败 HTTP {resp.status_code}: {resp.text[:150]}")
    except Exception as e:
        print(f"[ERROR] 请求异常: {e}")

if __name__ == "__main__":
    main()
