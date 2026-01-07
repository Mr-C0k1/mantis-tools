#!/bin/bash
echo "[*] Installing Mantis-Tools..."
go build -o scanner scanner.go
pip3 install rich requests paramiko --quiet
current_dir=$(pwd)
cat <<EOF > mantis-tools
#!/bin/bash
python3 $current_dir/mantis.py "\$@"
EOF
nuclei
chmod +x mantis-tools
chmod +x scanner
sudo mv mantis-tools /usr/local/bin/
echo "[+] Done. Usage: mantis-tools -t <target> -e"
