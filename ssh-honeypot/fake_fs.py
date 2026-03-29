"""
fake_fs.py
Simulated filesystem and command responses for the HoneyShell SSH honeypot.
Returns plausible-looking output for common post-login enumeration commands.
"""
 
HOSTNAME = "web-prod-03"
USERNAME = "ubuntu"
 
# Fake /etc/passwd realistic-looking but fictional
ETC_PASSWD = """\
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
mysql:x:112:117:MySQL Server,,,:/nonexistent:/bin/false
"""
 
# Fake /etc/hostname
ETC_HOSTNAME = f"{HOSTNAME}\n"
 
# Fake /etc/os-release
ETC_OS_RELEASE = """\
NAME="Ubuntu"
VERSION="20.04.6 LTS (Focal Fossa)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 20.04.6 LTS"
VERSION_ID="20.04"
HOME_URL="https://www.ubuntu.com/"
"""
 
# Fake directory listings
DIRS = {
    "/": [
        "bin   boot  dev  etc  home  lib  lib64",
        "media mnt   opt  proc root  run  sbin",
        "srv   sys   tmp  usr  var",
    ],
    "/home": ["ubuntu"],
    "/home/ubuntu": [
        "total 32",
        "drwxr-xr-x 4 ubuntu ubuntu 4096 Jan 12 09:14 .",
        "drwxr-xr-x 3 root   root   4096 Jan 10 18:32 ..",
        "-rw------- 1 ubuntu ubuntu  220 Jan 10 18:32 .bash_logout",
        "-rw-r--r-- 1 ubuntu ubuntu 3771 Jan 10 18:32 .bashrc",
        "drwx------ 2 ubuntu ubuntu 4096 Jan 12 09:14 .ssh",
        "-rw-r--r-- 1 ubuntu ubuntu  807 Jan 10 18:32 .profile",
        "drwxrwxr-x 3 ubuntu ubuntu 4096 Jan 11 14:02 app",
    ],
    "/var/www": [
        "total 12",
        "drwxr-xr-x  3 root     root     4096 Jan 10 18:35 .",
        "drwxr-xr-x 14 root     root     4096 Jan 10 18:35 ..",
        "drwxr-xr-x  2 www-data www-data 4096 Jan 10 18:35 html",
    ],
    "/tmp": [
        "total 8",
        "drwxrwxrwt  2 root root 4096 Jan 12 09:00 .",
        "drwxr-xr-x 22 root root 4096 Jan 10 18:32 ..",
    ],
    "/root": ["Permission denied"],
}
 
# Fake process list
PS_OUTPUT = """\
  PID TTY          TIME CMD
    1 ?        00:00:02 systemd
  412 ?        00:00:00 sshd
  891 ?        00:00:01 nginx
  892 ?        00:00:01 nginx
  934 ?        00:00:04 python3
 1021 pts/0    00:00:00 bash
 1103 pts/0    00:00:00 ps
"""
 
# Fake network interfaces
IFCONFIG_OUTPUT = """\
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.0.2.15  netmask 255.255.255.0  broadcast 10.0.2.255
        ether 02:42:ac:11:00:02  txqueuelen 0  (Ethernet)
        RX packets 4821  bytes 892341 (892.3 KB)
        TX packets 3142  bytes 541209 (541.2 KB)
 
lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        loop  txqueuelen 1000  (Local Loopback)
"""
 
IP_ADDR_OUTPUT = """\
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP
    link/ether 02:42:ac:11:00:02 brd ff:ff:ff:ff:ff:ff
    inet 10.0.2.15/24 brd 10.0.2.255 scope global eth0
"""
 
# Fake crontab (tempting for attackers looking for persistence)
CRONTAB_OUTPUT = """\
# Edit this file to introduce tasks to be run by cron.
# m h  dom mon dow   command
17 *	* * *	root    cd / && run-parts --report /etc/cron.hourly
25 6	* * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
"""
 
# Fake sudo -l response (no sudo access, realistic for www/app user)
SUDO_OUTPUT = """\
[sudo] password for ubuntu:
Sorry, user ubuntu may not run sudo on {hostname}.
""".format(hostname=HOSTNAME)
 
 
def resolve_command(cmd: str, cwd: str) -> tuple[str, str]:
    """
    Given a shell command string and current working directory,
    return (output, new_cwd).
    """
    cmd = cmd.strip()
    if not cmd:
        return "", cwd
 
    parts = cmd.split()
    base = parts[0]
 
    # navigation
    if base == "cd":
        target = parts[1] if len(parts) > 1 else f"/home/{USERNAME}"
        if target == "~":
            target = f"/home/{USERNAME}"
        if target.startswith("/"):
            new_cwd = target.rstrip("/") or "/"
        else:
            new_cwd = (cwd.rstrip("/") + "/" + target)
        if new_cwd in DIRS:
            return "", new_cwd
        return f"bash: cd: {target}: No such file or directory", cwd
 
    if base == "pwd":
        return cwd, cwd
 
    # identity / system info
    if base == "whoami":
        return USERNAME, cwd
 
    if base == "id":
        return f"uid=1000({USERNAME}) gid=1000({USERNAME}) groups=1000({USERNAME}),4(adm),27(sudo)", cwd
 
    if base in ("uname",):
        if "-a" in parts:
            return f"Linux {HOSTNAME} 5.15.0-1034-aws #38-Ubuntu SMP Mon Mar 20 15:41:27 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux", cwd
        if "-r" in parts:
            return "5.15.0-1034-aws", cwd
        return "Linux", cwd
 
    if base == "hostname":
        return HOSTNAME, cwd
 
    if base == "uptime":
        return " 09:14:32 up 1 day, 14:22,  1 user,  load average: 0.08, 0.03, 0.01", cwd
 
    if base in ("w", "who"):
        return f"{USERNAME}   pts/0   2024-01-12 09:00 (127.0.0.1)", cwd
 
    if base == "last":
        return (
            f"{USERNAME}  pts/0        127.0.0.1        Fri Jan 12 09:00   still logged in\n"
            f"reboot   system boot  5.15.0-1034-aws  Thu Jan 11 18:52 - 09:14  (14:22)"
        ), cwd
 
    # filesystem
    if base == "ls":
        target = cwd
        for p in parts[1:]:
            if not p.startswith("-"):
                target = p if p.startswith("/") else cwd.rstrip("/") + "/" + p
        listing = DIRS.get(target.rstrip("/") or "/", None)
        if listing is None:
            return f"ls: cannot access '{target}': No such file or directory", cwd
        if listing == ["Permission denied"]:
            return f"ls: cannot open directory '{target}': Permission denied", cwd
        if "-la" in cmd or "-al" in cmd or "-l" in cmd:
            return "\n".join(listing), cwd
        return "  ".join([l.split()[-1] for l in listing if l and not l.startswith("total") and not l.startswith("d")]) or "\n".join(listing), cwd
 
    if base == "cat":
        if len(parts) < 2:
            return "", cwd
        target = parts[1]
        file_map = {
            "/etc/passwd":     ETC_PASSWD,
            "/etc/hostname":   ETC_HOSTNAME,
            "/etc/os-release": ETC_OS_RELEASE,
            "/etc/crontab":    CRONTAB_OUTPUT,
            "~/.bashrc":       f"# ~/.bashrc for {USERNAME}\nexport PATH=$PATH:/usr/local/bin\n",
            ".bashrc":         f"# ~/.bashrc for {USERNAME}\nexport PATH=$PATH:/usr/local/bin\n",
        }
        if target in file_map:
            return file_map[target].rstrip(), cwd
        return f"cat: {target}: No such file or directory", cwd
 
    if base == "find":
        return (
            f"/home/{USERNAME}/app\n"
            f"/home/{USERNAME}/app/config.py\n"
            f"/home/{USERNAME}/app/requirements.txt\n"
            f"/home/{USERNAME}/.ssh\n"
            f"/home/{USERNAME}/.ssh/authorized_keys"
        ), cwd
 
    # processes / network
    if base == "ps":
        return PS_OUTPUT.strip(), cwd
 
    if base == "netstat":
        return (
            "Active Internet connections (only servers)\n"
            "Proto Recv-Q Send-Q Local Address   Foreign Address  State\n"
            "tcp        0      0 0.0.0.0:22      0.0.0.0:*        LISTEN\n"
            "tcp        0      0 0.0.0.0:80      0.0.0.0:*        LISTEN\n"
            "tcp        0      0 127.0.0.1:3306  0.0.0.0:*        LISTEN"
        ), cwd
 
    if base == "ifconfig":
        return IFCONFIG_OUTPUT.strip(), cwd
 
    if base in ("ip",):
        return IP_ADDR_OUTPUT.strip(), cwd
 
    # privilege escalation attempts
    if base == "sudo":
        return SUDO_OUTPUT.strip(), cwd
 
    if base == "su":
        return "su: Authentication failure", cwd
 
    # download attempts (log but pretend to hang/fail)
    if base in ("wget", "curl"):
        url = next((p for p in parts[1:] if p.startswith("http")), "<url>")
        return f"curl: (6) Could not resolve host: {url.split('/')[2] if '//' in url else url}", cwd
 
    # history
    if base == "history":
        return (
            "    1  sudo apt update\n"
            "    2  sudo apt install nginx\n"
            "    3  cd /var/www/html\n"
            "    4  ls -la\n"
            "    5  history"
        ), cwd
 
    # environment
    if base in ("env", "printenv", "export"):
        return (
            f"USER={USERNAME}\n"
            f"HOME=/home/{USERNAME}\n"
            "SHELL=/bin/bash\n"
            f"HOSTNAME={HOSTNAME}\n"
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n"
            "LANG=en_US.UTF-8"
        ), cwd
 
    # crontab
    if base == "crontab":
        return CRONTAB_OUTPUT.strip(), cwd
 
    # exit
    if base in ("exit", "logout", "quit"):
        return "__EXIT__", cwd
 
    # unknown command
    return f"bash: {base}: command not found", cwd