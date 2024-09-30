#!/usr/bin/env python3
# Fetch SSH key from Cyberark PAM cached MFA service and store it
# in the SSH agent for the current session. If SSH agent is not running,
# store the retrieved key under ~/.ssh/id_cyberark_session* files.
# Deletes old cached ~/.ssh/id_cyberark_session* keys before writing new ones.
#

import json
import logging
import requests
import getpass
import os
import glob
from datetime import datetime
import subprocess
import dotenv
import argparse


class CyberarkSSHKeyFetcher:

    def __init__(self, baseurl, username, password) -> None:
        self.BASEURL = baseurl
        self.token = None
        self.username = username
        self.password = password
        self.auth()

    def auth(self) -> None:
        resp = requests.post(
            f"{self.BASEURL}/PasswordVault/API/auth/RADIUS/Logon/",
            headers = { "Content-Type": "application/json",
                        "Accept": "application/json" },
            data = json.dumps({ "username": self.username,
                                "password": self.password,
                                "type": "radius",
                                "secureMode": "true" })
        )
        if resp.status_code == 200:
            self.token = resp.content.decode('utf-8').strip('"')
            logging.debug(f"Authentication successful. Session token: {self.token[0:10]}..")
        else:
            logging.error(f"Authentication failed. Status={resp.status_code}, response: {resp.content}")
            exit(1)

    def get_ssh_keyfile_path(self, keyname):
        """Return the full path to the SSH key file."""
        homepath = os.getenv('HOME') or os.getenv('USERPROFILE')
        if homepath is None:
            logging.error(
                "Could not determine current user's home directory. " +
                "Check your HOME/USERPROFILE environment variables.")
            exit(1)
        return os.path.join(homepath, '.ssh', keyname)

    def delete_old_keys(self, filepathprefix):
        """Delete old key files with the given prefix."""
        if not filepathprefix:
            raise ValueError("filepathprefix must be set")
        file_pattern = f"{filepathprefix}_*"
        files = glob.glob(file_pattern)
        for file in files:
            logging.debug(f"Deleting old key file: {file}")
            os.remove(file)

    def get_key(self):
        """Retrieve the SSH key(s) from TSPAM and write them to ~/.ssh/id_cyberark_session* files."""
        resp = requests.post(
            f"{self.BASEURL}/PasswordVault/API/Users/Secret/SSHKeys/Cache/",
            headers = { "Content-Type": "application/json",
                        "Accept": "application/json",
                        "Authorization": self.token },
            data = '{}'
        )
        if resp.status_code != 200:
            logging.error(f"Failed to get SSH key. Status={resp.status_code}, response: {resp.content}")
            exit(1)

        data = json.loads(resp.content)
        logging.debug(f"Got key data: {data}")
        filepath = self.get_ssh_keyfile_path('id_cyberark_session')
        self.delete_old_keys(filepath)
        for key in data['value']:
            expiration_time = datetime.fromtimestamp(data['expirationTime']).isoformat()
            filename = f"{filepath}_{key['format'].lower()}_{key['keyAlg'].lower()}"
            with open(filename, 'w') as f:
                f.write(key['privateKey'])
                os.chmod(f.name, 0o600)
            logging.info(f"Wrote SSH {key['keyAlg']} key with" +
                        f" expires='{expiration_time}'" +
                        f" publickey='{data.get('publicKey','n/a')[0:30]}..'" +
                        f" to {filename}")
            subprocess.run(["ls", "-l", filename])
            result = subprocess.run(["ssh-add", filename], capture_output=True, text=True)
            if result.returncode == 0:
                logging.info(f"Added key to SSH agent: {result.stdout}")
                os.unlink(filename)
                logging.info(f"Key file {filename} deleted.")
            else:
                logging.error(f"Failed to add key to SSH agent: {result.stderr}")
                logging.info(f"Key file {filename} was left for manual usage. Consider protecting it.")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s')
    if os.getenv('DEBUG'):
        logging.getLogger().setLevel(logging.DEBUG)
    dotenv.load_dotenv(os.path.join(os.path.dirname(os.path.realpath(__file__)), ".env"))

    try:
        parser = argparse.ArgumentParser(description='Fetch SSH key from Cyberark PAM and store it in the SSH agent.')
        parser.add_argument('-s', '--server', help='Base URL for Cyberark PAM in format https://server.domain')
        parser.add_argument('-u', '--username', help='Cyberark username. Defaults to current user.')
        args = parser.parse_args()
        baseurl = args.server or os.getenv('CYBERARK_BASEURL')
        if not baseurl:
            print("Error: Base URL for Cyberark required. Set it either via --server param or CYBERARK_BASEURL env.")
            exit(1)
        print(f"Authenticating to {baseurl}")
        username = args.username or os.getenv('CYBERARK_USERNAME')
        if not username:
            default_username = os.getlogin()
            username = input(f"Enter your Cyberark username [{default_username}]: ")
            if not username:
                username = default_username
        password = getpass.getpass(f"Enter Cyberark password for {username}: ")
        if not password:
            print(f"No password set. Exiting.")
            exit(1)

        app = CyberarkSSHKeyFetcher(baseurl, username, password)
        app.get_key()
    except KeyboardInterrupt:
        print("\nInterrupted.")
        exit(1)
