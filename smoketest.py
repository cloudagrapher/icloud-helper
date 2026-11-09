import imaplib, pathlib
sec = pathlib.Path.home() / "icloud-helper" / "secrets"
user = (sec / "icloud_email").read_text().strip()
pw = (sec / "icloud_app_password").read_text().strip()
HOST = "imap.mail.me.com"
print(f"connecting to {HOST}:993 as {user} ...")
M = imaplib.IMAP4_SSL(HOST, 993)
try:
    M.login(user, pw)
    print("LOGIN OK")
    typ, folders = M.list()
    print(f"folders ({len(folders)}):")
    for f in folders[:25]:
        print("   ", f.decode(errors="replace"))
    typ, data = M.select("INBOX", readonly=True)
    print("INBOX messages:", data[0].decode() if data and data[0] else "?")
except imaplib.IMAP4.error as e:
    print("IMAP ERROR:", e)
finally:
    try: M.logout()
    except Exception: pass
