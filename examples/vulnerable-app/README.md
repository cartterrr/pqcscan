# vulnerable-app

A made-up project full of old-style crypto, used for the pqcscan tests and the
sample report. None of it runs anywhere.

There are no real secrets in here. The private key in `app/legacy_config.py`
is just a PEM header with nothing behind it, and the certificate and SSH keys
are public halves generated for this folder.

    pqcscan scan examples/vulnerable-app
