import subprocess
import os
from collections import defaultdict

class Rule:
    def __init__(self, chain, protocol="all", source="any", destination="any", 
                 target="ACCEPT", sport=None, dport=None, state=None, 
                 comment="", table='filter'):
        self.table = table
        self.chain = chain
        self.protocol = protocol
        self.source = source
        self.destination = destination
        self.target = target
        self.sport = sport
        self.dport = dport
        self.state = state
        self.comment = comment

    def __str__(self):
        parts = ["-A", self.chain]
        if self.protocol and self.protocol != "all":
            parts.extend(["-p", self.protocol])
        any_addrs = ["0.0.0.0/0", "::/0", "anywhere", "any"]
        if self.source and self.source not in any_addrs:
            parts.extend(["-s", self.source])
        if self.destination and self.destination not in any_addrs:
            parts.extend(["-d", self.destination])
        if self.sport: parts.extend(["--sport", str(self.sport)])
        if self.dport: parts.extend(["--dport", str(self.dport)])
        if self.state: parts.extend(["-m", "state", "--state", self.state])
        if self.comment: parts.extend(["-m", "comment", "--comment", f'"{self.comment}"'])
        parts.extend(["-j", self.target])
        return " ".join(parts)

class IptablesManager:
    def __init__(self):
        self.is_ipv6_mode = False

    def load_rules(self):
        cmd = "ip6tables-save" if self.is_ipv6_mode else "iptables-save"
        try:
            result = subprocess.run([cmd], capture_output=True, text=True, check=True)
            return self._parse_output(result.stdout)
        except Exception:
            return {}

    def _parse_output(self, output):
        data = defaultdict(lambda: defaultdict(list))
        current_table = "filter"
        for line in output.splitlines():
            if line.startswith("*"): current_table = line[1:].strip()
            elif line.startswith("-A"):
                parts = line.split()
                params = {"chain": parts[1], "table": current_table, "target": "ACCEPT"}
                i = 2
                while i < len(parts):
                    arg = parts[i]
                    if i + 1 < len(parts):
                        val = parts[i+1]
                        if arg == "-p": params["protocol"] = val; i += 2
                        elif arg == "-s": params["source"] = val; i += 2
                        elif arg == "-d": params["destination"] = val; i += 2
                        elif arg == "-j": params["target"] = val; i += 2
                        elif arg == "--sport": params["sport"] = val; i += 2
                        elif arg == "--dport": params["dport"] = val; i += 2
                        elif arg == "--state": params["state"] = val; i += 2
                        elif arg == "--comment": params["comment"] = val.strip('"'); i += 2
                        else: i += 1
                    else: i += 1
                data[current_table][params["chain"]].append(Rule(**params))
        return data

    def apply_rules(self, structured_data):
        ipt_cmd = "ip6tables" if self.is_ipv6_mode else "iptables"
        commands = []
        for table in structured_data:
            commands.append(f"{ipt_cmd} -t {table} -F")
            for chain in structured_data[table]:
                for rule in structured_data[table][chain]:
                    commands.append(f"{ipt_cmd} -t {table} {str(rule)}")
        try:
            for c in commands: subprocess.run(c, shell=True, check=True, capture_output=True)
            return True, ""
        except subprocess.CalledProcessError as e:
            return False, e.stderr.decode()

    def save_to_system(self):
        try:
            os.makedirs("/etc/iptables", exist_ok=True)
            with open("/etc/iptables/rules.v4", "w") as f:
                subprocess.run(["iptables-save"], stdout=f, check=True)
            with open("/etc/iptables/rules.v6", "w") as f:
                subprocess.run(["ip6tables-save"], stdout=f, check=True)
            return self._setup_systemd_service()
        except Exception as e:
            return False, str(e)

    def _setup_systemd_service(self):
        service_content = """[Unit]
Description=Restore IPTables Rules (Forge GUI)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/sbin/iptables-restore /etc/iptables/rules.v4
ExecStart=/sbin/ip6tables-restore /etc/iptables/rules.v6
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
"""
        service_path = "/etc/systemd/system/iptables-forge.service"
        try:
            with open(service_path, "w") as f:
                f.write(service_content)
            subprocess.run(["systemctl", "daemon-reload"], check=True)
            subprocess.run(["systemctl", "enable", "iptables-forge.service"], check=True)
            return True, ""
        except Exception as e:
            return False, f"Systemd Error: {str(e)}"

    def disable_persistence(self):
        try:
            subprocess.run(["systemctl", "disable", "iptables-forge.service"], capture_output=True)
            path = "/etc/systemd/system/iptables-forge.service"
            if os.path.exists(path): os.remove(path)
            subprocess.run(["systemctl", "daemon-reload"], check=True)
            return True, ""
        except Exception:
            return False, "Failed to disable service"
