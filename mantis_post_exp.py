class MantisPostExp:
    def __init__(self, target_ip):
        self.target_ip = target_ip

    def exfiltrate_env_data(self, content):
        # Sederhana: mencari kunci AWS atau DB
        extracted = [line for line in content.splitlines() if "KEY" in line or "PASS" in line]
        return extracted
