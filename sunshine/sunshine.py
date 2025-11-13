import os
import json
import base64
import requests
import getpass
import urllib3
import subprocess
import glob
from typing import Tuple, Optional, Dict, List
from config.constants import DEFAULT_IMAGE, SUNSHINE_API_URL
from utils.utils import run_command
from launchers.lutris import get_lutris_command
from launchers.heroic import get_heroic_command
from launchers.steam import get_steam_command
from launchers.retroarch import get_retroarch_command

#Remove SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

INSTALLATION_TYPE = None

def set_installation_type(type_: str):
    global INSTALLATION_TYPE
    INSTALLATION_TYPE = type_

def get_covers_path():
    if INSTALLATION_TYPE == "flatpak":
        return os.path.expanduser("~/.var/app/dev.lizardbyte.app.Sunshine/config/sunshine/covers")
    else:
        return os.path.expanduser("~/.config/sunshine/covers")

def get_api_key_path():
    if INSTALLATION_TYPE == "flatpak":
        return os.path.expanduser("~/.var/app/dev.lizardbyte.app.Sunshine/config/sunshine/steamgriddb_api_key.txt")
    else:
        return os.path.expanduser("~/.config/sunshine/steamgriddb_api_key.txt")

def get_credentials_path():
    if INSTALLATION_TYPE == "flatpak":
        return os.path.expanduser("~/.var/app/dev.lizardbyte.app.Sunshine/config/sunshine/credentials")
    else:
        return os.path.expanduser("~/.config/sunshine/credentials")

def detect_sunshine_installation() -> Tuple[bool, str]:
    """Detect if Sunshine is installed and how."""
    # Check for Flatpak installation
    if run_command("flatpak list | grep dev.lizardbyte.app.Sunshine").returncode == 0:
        return True, "flatpak"
    # Check for native installation
    elif run_command("which apollo").returncode == 0:
        return True, "native"
    # Check for AppImage installation
    else:
        appimage_paths = (
            glob.glob(os.path.expanduser("~/sunshine.AppImage")) +
            glob.glob(os.path.expanduser("~/.local/share/applications/sunshine.AppImage")) +
            glob.glob(os.path.expanduser("~/AppImages/sunshine.AppImage")) +
            glob.glob(os.path.expanduser("~/bin/sunshine.AppImage")) +
            glob.glob(os.path.expanduser("~/Downloads/sunshine.AppImage"))
        )
        if appimage_paths:
            return True, "appimage"
        return False, ""

def add_game_to_sunshine_api(game_name: str, cmd: str, image_path: str) -> None:
    """Add a game to the Sunshine configuration using the API."""
    payload = {
        "name": game_name,
        "output": "",
        "cmd": cmd,
        "index": -1,
        "exclude-global-prep-cmd": False,
        "elevated": False,
        "auto-detach": True,
        "wait-all": True,
        "exit-timeout": 5,
        "prep-cmd": [],
        "detached": [],
        "image-path": image_path
    }

    _, error = sunshine_api_request("POST", "/api/apps", json=payload)
    if error:
        print(f"Error adding {game_name} to Sunshine via API: {error}")
    else:
        print(f"Added {game_name} to Sunshine.")

def get_sunshine_credentials() -> Tuple[str, str]:
    """Prompts the user for their Sunshine username and password."""
    username = input("Enter your Sunshine username: ")
    password = getpass.getpass("Enter your Sunshine password: ")
    return username, password

def is_sunshine_running() -> bool:
    """Checks if Sunshine is currently running."""
    try:
        # Run the ps command to check for the Sunshine process
        output = subprocess.check_output(["ps", "-A"], stderr=subprocess.STDOUT).decode()
        return "apollo" in output.lower() or "sunshine" in output.lower()  # Check if "apollo" or "sunshine" is present in the process list
    except subprocess.CalledProcessError:
        return False

def _cookies_file_path():
    return os.path.join(get_credentials_path(), "cookies.json")

def _save_session_cookies(session: requests.Session):
    os.makedirs(get_credentials_path(), exist_ok=True)
    cookies_dict = dict_from_cookiejar(session.cookies)
    try:
        with open(_cookies_file_path(), "w") as f:
            json.dump(cookies_dict, f)
    except Exception as e:
        print(f"Warning: Failed to save cookies: {e}")

def _load_session_from_cookies() -> requests.Session:
    session = requests.Session()
    cookie_file = _cookies_file_path()
    if os.path.exists(cookie_file):
        try:
            with open(cookie_file, "r") as f:
                cookies_dict = json.load(f)
            session.cookies = cookiejar_from_dict(cookies_dict)
        except Exception:
            # If cookie file is corrupt, remove it
            try:
                os.remove(cookie_file)
            except Exception:
                pass
    return session

def get_auth_session() -> Optional[requests.Session]:
    """
    Retrieves or creates a requests.Session authenticated with Sunshine via cookies.
    This function:
      - Returns a session loaded with saved cookies if valid.
      - Otherwise prompts for credentials and attempts to log in to Sunshine to obtain cookies.
      - Saves the cookies for future runs.
    """
    if not is_sunshine_running():
        print("Error: Sunshine is not running. Please start Sunshine and try again.")
        return None

    # Try to reuse saved cookies
    session = _load_session_from_cookies()
    try:
        resp = session.get(f"{SUNSHINE_API_URL}/api/apps", verify=False, timeout=10)
        if resp.status_code == 200:
            return session
        else:
            # saved cookies invalid; remove cookie file and prompt for login
            try:
                os.remove(_cookies_file_path())
            except Exception:
                pass
    except requests.exceptions.RequestException:
        # Could not use saved cookies; proceed to login prompt
        pass

    # Prompt for credentials and perform login attempts
    username, password = get_sunshine_credentials()
    if not username or not password:
        return None

    session = requests.Session()

    # Try a list of common login endpoints and payload formats
    login_endpoints = [
        "/api/login",
        "/login",
        "/auth/login",
        "/api/auth/login"
    ]

    login_payloads = [
        ("json", {"username": username, "password": password}),
        ("form", {"username": username, "password": password}),
    ]

    for endpoint in login_endpoints:
        url = f"{SUNSHINE_API_URL}{endpoint}"
        for mode, payload in login_payloads:
            try:
                if mode == "json":
                    resp = session.post(url, json=payload, verify=False, timeout=10)
                else:
                    resp = session.post(url, data=payload, verify=False, timeout=10)
            except requests.exceptions.RequestException:
                continue

            # If the server set cookies or returned success, test the session
            try:
                test = session.get(f"{SUNSHINE_API_URL}/api/apps", verify=False, timeout=10)
                if test.status_code == 200:
                    _save_session_cookies(session)
                    return session
            except requests.exceptions.RequestException:
                continue

    # As a fallback, some Sunshine setups accept HTTP Basic auth and then set session cookies.
    try:
        resp = requests.get(f"{SUNSHINE_API_URL}/api/apps", auth=(username, password), verify=False, timeout=10)
        # If server set cookies, capture them by reusing a session with basic auth
        session = requests.Session()
        try:
            # Perform a request with auth using session so cookies set by server are stored in session
            resp2 = session.get(f"{SUNSHINE_API_URL}/api/apps", auth=(username, password), verify=False, timeout=10)
            if resp2.status_code == 200:
                _save_session_cookies(session)
                return session
        except requests.exceptions.RequestException:
            pass
    except requests.exceptions.RequestException:
        pass

    print("Error: Authentication failed. Could not obtain session cookies from Sunshine.")
    return None

def add_game_to_sunshine(game_id: str, game_name: str, image_path: str, runner) -> None:
    """Add a game to the Sunshine configuration."""
    if runner == "Lutris":
        lutris_cmd = get_lutris_command()
        cmd = f"{lutris_cmd} lutris:rungameid/{game_id}"
    elif runner in ["legendary", "gog", "nile", "sideload"]:
        heroic_cmd, _ = get_heroic_command()
        cmd = f"{heroic_cmd} heroic://launch/{runner}/{game_id} --no-gui --no-sandbox"
    elif runner == "Steam":
        steam_cmd = get_steam_command()
        cmd = f"{steam_cmd} steam://run/{game_id}"
    elif runner == "Ryubing":
        cmd = f"flatpak run io.github.ryubing.Ryujinx \"{game_id}\""
    elif isinstance(runner, dict) and runner.get("type") == "RetroArch":
        core_path = runner.get("core_path", "")
        core_path = os.path.expanduser(core_path) if core_path else core_path
        retroarch_cmd = get_retroarch_command()
        if not retroarch_cmd or not core_path:
            print(f"Warning: Unable to determine RetroArch launch command for {game_name}. Skipping.")
            return
        cmd = f'{retroarch_cmd} -L "{core_path}" "{game_id}"'
    else:  # Bottles
        cmd = f'flatpak run --command=bottles-cli com.usebottles.bottles run -b "{runner}" -p "{game_id}"'

    # Prefix commands with flatpak-spawn --host if Sunshine is installed as Flatpak
    if INSTALLATION_TYPE == "flatpak":
        cmd = f"flatpak-spawn --host {cmd}"

    # Use the API instead of directly modifying apps.json
    add_game_to_sunshine_api(game_name, cmd, image_path)

def get_existing_apps() -> List[Dict]:
    """Retrieves the list of existing apps from the Sunshine API."""
    data, error = sunshine_api_request("GET", "/api/apps")
    if error:
        print(f"Error retrieving existing apps from Sunshine API: {error}")
        return []

    existing_apps = []
    apps_list = []
    if data is not None:
        apps_list = data.get("apps", [])
    else:
        print("Warning: No data received from Sunshine API.")

    if isinstance(apps_list, list):
        for app_data in apps_list:
            if isinstance(app_data, dict) and "name" in app_data:
                existing_apps.append({"name": app_data["name"]})
    else:
        print("Warning: Unexpected data structure in API response.")

    return existing_apps

def sunshine_api_request(method, endpoint, **kwargs):
    """Makes an API request to Sunshine.

    Args:
        method (str): The HTTP method (GET, POST, etc.)
        endpoint (str): The API endpoint.
        **kwargs: Additional keyword arguments for the requests.request() function.

    Returns:
        Tuple[Optional[Dict], Optional[str]]: A tuple containing the JSON response data 
                                              (if successful) and an error message (if any).
    """
    # Allow callers to pass an existing session; otherwise obtain one
    session = kwargs.pop("session", None)
    if session is None:
        session = get_auth_session()

    if not session:
        return None, "Error: Could not obtain authenticated session."

    url = f"{SUNSHINE_API_URL}{endpoint}"

    try:
        response = session.request(method, url, verify=False, **kwargs)
        response.raise_for_status()
        try:
            return response.json(), None
        except ValueError:
            # Not JSON; return text
            return {"text": response.text}, None

    except requests.exceptions.RequestException as e:
        return None, str(e)
