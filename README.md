# Fetch MFA-cached SSH key from Cyberark PAM

This app fetches MFA cached SSH key from Cyberark PAM API and automatically
either stores it to your SSH agent (diskless), or if your SSH agent doesn't
work, then to your home directory in .ssh/id_cyberark_session* file(s).

Each request will first ask for your Cyberark (one-time) password and then
generate a new SSH key. Old keys won't be deleted from your SSH agent in case
you already had some. Keys expire after a while. The expiration time is shown to
the user.

This app should work in all operating systems. It has been tested only with
python 3.12 on WSL2 linux.


## Usage

You need to set your target Cyberark URL either via environment
(CYBERARK_BASEURL) or via command-line parameter (--server). The expected format
is 'https://cyberarkserver.domain'. Username can be set either in environment
(CYBERARK_USERNAME), via --username parameter or via stdin. Password is always
asked via stdin. Environment variables can be set via .env file. See .env.sample
for an example.

Fetching a new SSH key requires then just calling the script: python3 get-cyberark-ssh-key.py

If your python doesn't already have all the libraries, you may have to install
them under virtual environment:

* python3 -m venv .venv
* source .venv/bin/activate
* pip install -r requirements.txt


## Validate received keys

Run 'ssh-add -L'

If your SSH agent is properly set up, the next sessions over Cyberark SSH gateway
won't ask for authentication.


## Debugging

Set environment variable DEBUG=1

DEBUG=1 ./get-cyberark-ssh-key.py ..


## Author

Markku Parviainen, 2024
