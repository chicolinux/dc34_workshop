# -*- mode: ruby -*-
# vi: set ft=ruby :
#
# DEF CON 34 — Offensive Packet Wizardry with Scapy
# Three-VM lab, fully provisioned. Build it with:  vagrant up
#
#   attacker (Kali Linux)    192.168.56.1   — your machine, all tooling installed
#   target   (Ubuntu 24.04)  192.168.56.2   — the victim, vulnerable services running
#   gateway  (Alpine Linux)  192.168.56.254 — real L2 node; enables ARP MitM exercises
#
# Isolated internal network 192.168.56.0/24 — nothing touches your real network.
# Latest boxes on Vagrant Cloud as of build time:
#   kalilinux/rolling 2025.2.1  (official OffSec box, command-line only)
#   bento/ubuntu-24.04          (Chef bento; Canonical no longer ships Ubuntu boxes)
#   generic/alpine319           (Alpine 3.19; tiny gateway, ~256 MB RAM)

Vagrant.configure("2") do |config|

  # ── Gateway VM: Alpine Linux (tiny L2 router for ARP MitM exercises) ──────
  config.vm.define "gateway" do |gw|
    gw.vm.box      = "generic/alpine319"
    gw.vm.hostname = "gateway"

    gw.vm.network "private_network", ip: "192.168.56.254", netmask: "255.255.255.0",
      virtualbox__intnet: "dc34lab"

    gw.vm.provider "virtualbox" do |vb|
      vb.name   = "dc34-gateway"
      vb.memory = 256
      vb.cpus   = 1
      vb.gui    = false
      # Promiscuous mode so it sees all lab traffic when acting as a router.
      vb.customize ["modifyvm", :id, "--nicpromisc2", "allow-all"]
    end

    gw.vm.provision "shell", inline: <<-'SHELL'
      set -e
      apk update
      apk add iptables
      # Enable IP forwarding so traffic actually routes through this VM when MitM'd.
      sysctl -w net.ipv4.ip_forward=1
      echo 'net.ipv4.ip_forward = 1' > /etc/sysctl.d/99-ipforward.conf
      echo "[+] gateway ready at 192.168.56.254, IP forwarding ON"
    SHELL
  end

  # ── Target VM: Ubuntu 24.04 (the victim) ──────────────────────────────────
  config.vm.define "target" do |target|
    target.vm.box      = "bento/ubuntu-24.04"
    target.vm.hostname = "target"

    # Lab interface (guest's second NIC; NIC1 is Vagrant's NAT/SSH).
    # virtualbox__intnet: isolated internal network — no host adapter, no host DHCP,
    # so nothing collides with the host's own 192.168.56.1 vboxnet or your real LAN.
    target.vm.network "private_network", ip: "192.168.56.2", netmask: "255.255.255.0",
      virtualbox__intnet: "dc34lab"

    target.vm.provider "virtualbox" do |vb|
      vb.name   = "dc34-target"
      vb.memory = 2048
      vb.cpus   = 1
      vb.gui    = false
      # Promiscuous mode on the lab NIC so MitM/sniffing exercises see all traffic.
      vb.customize ["modifyvm", :id, "--nicpromisc2", "allow-all"]
    end

    target.vm.provision "shell", inline: <<-'SHELL'
      set -e
      export DEBIAN_FRONTEND=noninteractive
      apt-get update
      apt-get install -y python3 python3-pip git dnsmasq netcat-openbsd inetutils-telnetd

      # The Module 6 covert-channel tools (ICMP C2 agent, DNS exfil) run ON the victim
      # and use Scapy, so the target needs the latest Scapy from source too.
      # --ignore-installed: Ubuntu ships apt-managed deps with no pip RECORD file.
      if [ -d /opt/scapy/.git ]; then
        git -C /opt/scapy pull --ff-only
      else
        git clone https://github.com/secdev/scapy.git /opt/scapy
      fi
      pip3 install --break-system-packages --ignore-installed /opt/scapy

      # Enable IP forwarding (used by several routing/redirect exercises).
      sysctl -w net.ipv4.ip_forward=1
      grep -q '^net.ipv4.ip_forward=1' /etc/sysctl.conf || echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf

      # Run the intentionally-vulnerable fuzz target (Module 5) as a service on :9000.
      cat > /etc/systemd/system/dc34-target.service <<'UNIT'
[Unit]
Description=DC34 vulnerable protocol server (Module 5)
# RequiresMountsFor: the server lives on the /vagrant vboxsf share, which mounts
# late in boot — without this the service races the mount and fails on reboot.
RequiresMountsFor=/vagrant
After=network.target
StartLimitIntervalSec=0

[Service]
ExecStart=/usr/bin/python3 /vagrant/module5/target_server.py --port 9000
Restart=always
RestartSec=2
User=root

[Install]
WantedBy=multi-user.target
UNIT
      systemctl daemon-reload
      systemctl enable --now dc34-target.service

      # ── Snort IDS (Module 2 evasion verification) ─────────────────────────
      # Pre-seed the interface so the package install is fully non-interactive.
      echo "snort snort/interface string eth1" | debconf-set-selections
      if apt-get install -y snort; then
        IDS=snort
        echo "[+] Snort installed"
      else
        # Fallback: Suricata is always in the Ubuntu 24.04 repos and accepts
        # the same Snort community rule format.
        apt-get install -y suricata
        IDS=suricata
        echo "[+] Snort not available — Suricata installed as IDS fallback"
      fi

      if [ "$IDS" = "snort" ]; then
        # HOME_NET = target only so that the attacker (192.168.56.1) is classified as
        # EXTERNAL_NET — this is what makes sfPortscan fire on attacker-vs-target scans.
        sed -i 's|^var HOME_NET.*|var HOME_NET [192.168.56.2]|' /etc/snort/snort.conf
        sed -i 's|^ipvar HOME_NET.*|ipvar HOME_NET [192.168.56.2]|' /etc/snort/snort.conf
        sed -i 's|^var EXTERNAL_NET.*|var EXTERNAL_NET !$HOME_NET|' /etc/snort/snort.conf
        sed -i 's|^ipvar EXTERNAL_NET.*|ipvar EXTERNAL_NET !$HOME_NET|' /etc/snort/snort.conf

        # Uncomment the sfPortscan preprocessor line (catches SYN scans and slow scans).
        # The default Ubuntu snort.conf ships with this line commented out.
        sed -i 's|^# *preprocessor sfportscan:.*|preprocessor sfportscan: proto { all } memcap { 10000000 } sense_level { low }|' \
          /etc/snort/snort.conf

        # sfPortscan outputs events via GID 122 — enable the preprocessor rules so they get
        # human-readable names in the alert log.
        mkdir -p /etc/snort/preproc_rules
        cat > /etc/snort/preproc_rules/preprocessor.rules <<'PREPROC'
alert ( msg:"(portscan) TCP Portscan"; sid:1; gid:122; rev:1; classtype:attempted-recon; )
alert ( msg:"(portscan) UDP Portscan"; sid:2; gid:122; rev:1; classtype:attempted-recon; )
alert ( msg:"(portscan) ICMP Portscan"; sid:3; gid:122; rev:1; classtype:attempted-recon; )
alert ( msg:"(portscan) TCP Decoy Portscan"; sid:4; gid:122; rev:1; classtype:attempted-recon; )
alert ( msg:"(portscan) TCP Distributed Portscan"; sid:7; gid:122; rev:1; classtype:attempted-recon; )
alert ( msg:"(portscan) TCP Filtered Portscan"; sid:10; gid:122; rev:1; classtype:attempted-recon; )
alert ( msg:"(portscan) TCP Port Sweep"; sid:16; gid:122; rev:1; classtype:attempted-recon; )
PREPROC
        sed -i 's|^# *include \$PREPROC_RULE_PATH/preprocessor.rules.*|include $PREPROC_RULE_PATH/preprocessor.rules|' \
          /etc/snort/snort.conf

        # Download community rules (no auth required).
        wget -q https://www.snort.org/downloads/community/community-rules.tar.gz \
             -O /tmp/community-rules.tar.gz
        tar -xzf /tmp/community-rules.tar.gz -C /etc/snort/rules/ --strip-components=1 2>/dev/null || true
        # Ensure snort.conf includes the community rules file.
        if ! grep -q 'community.rules' /etc/snort/snort.conf; then
          echo 'include $RULE_PATH/community.rules' >> /etc/snort/snort.conf
        fi

        # Alert log directory owned by snort user (created by the package).
        mkdir -p /var/log/snort
        chown snort:snort /var/log/snort

        # Validate config before writing the service.
        snort -T -i eth1 -c /etc/snort/snort.conf -q && echo "[+] Snort config OK"

        cat > /etc/systemd/system/dc34-snort.service <<'UNIT'
[Unit]
Description=Snort IDS — DC34 lab (Module 2 evasion verification)
After=network.target

[Service]
ExecStart=/usr/sbin/snort -D -i eth1 -u snort -g snort -c /etc/snort/snort.conf -l /var/log/snort -A fast -q
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
UNIT
        systemctl daemon-reload
        systemctl enable --now dc34-snort.service
        systemctl is-active dc34-snort.service && echo "[+] Snort IDS running on eth1 — alerts at /var/log/snort/alert"
      fi

      echo "[+] target ready — vulnerable server on 192.168.56.2:9000"
    SHELL
  end

  # ── Attacker VM: Kali Linux (your machine) ────────────────────────────────
  config.vm.define "attacker", primary: true do |attacker|
    attacker.vm.box         = "kalilinux/rolling"
    attacker.vm.box_version = "2025.2.1"
    attacker.vm.hostname    = "attacker"

    attacker.vm.network "private_network", ip: "192.168.56.1", netmask: "255.255.255.0",
      virtualbox__intnet: "dc34lab"

    # Reach the Streamlit dashboards from your host browser at http://localhost:8501
    attacker.vm.network "forwarded_port", guest: 8501, host: 8501, auto_correct: true

    # The Kali box ships without VirtualBox guest additions, so sync via rsync.
    # The whole workshop repo lands at /vagrant inside the VM.
    attacker.vm.synced_folder ".", "/vagrant", type: "rsync",
      rsync__exclude: [".git/", "scapy/"]

    attacker.vm.provider "virtualbox" do |vb|
      vb.name   = "dc34-attacker"
      vb.memory = 4096
      vb.cpus   = 2
      vb.gui    = false
      vb.customize ["modifyvm", :id, "--nicpromisc2", "allow-all"]
    end

    attacker.vm.provision "shell", inline: <<-'SHELL'
      set -e
      export DEBIAN_FRONTEND=noninteractive

      # Preseed so tshark/wireshark installs non-interactively and allows capture.
      echo "wireshark-common wireshark-common/install-setuid boolean true" | debconf-set-selections

      apt-get update
      apt-get install -y git python3-pip tcpdump nmap tshark

      # Install the LATEST Scapy from source (per the workshop requirement).
      # --ignore-installed: the Kali box ships an apt-managed Scapy (no RECORD file),
      # which pip cannot uninstall; install the source build over it instead.
      if [ -d /opt/scapy/.git ]; then
        git -C /opt/scapy pull --ff-only
      else
        git clone https://github.com/secdev/scapy.git /opt/scapy
      fi
      pip3 install --break-system-packages --ignore-installed /opt/scapy

      # Remaining Python dependencies (Scapy is intentionally NOT in this file).
      # --ignore-installed for the same reason as Scapy: several deps would otherwise
      # try to upgrade apt-managed packages (e.g. typing_extensions) that pip can't uninstall.
      pip3 install --break-system-packages --ignore-installed -r /vagrant/requirements.txt

      # Kali's NetworkManager ignores Vagrant's static assignment and DHCPs the lab NIC,
      # so pin eth1 to the workshop address with a persistent NM connection.
      OLD_CON=$(nmcli -t -f NAME,DEVICE connection show | awk -F: '$2=="eth1"{print $1; exit}')
      [ -n "$OLD_CON" ] && nmcli connection delete "$OLD_CON" 2>/dev/null || true
      nmcli connection add type ethernet ifname eth1 con-name dc34-lab autoconnect yes \
        ipv4.method manual ipv4.addresses 192.168.56.1/24 ipv4.never-default yes
      nmcli connection up dc34-lab || true

      # Enable IP forwarding so MitM exercises can relay intercepted traffic.
      sysctl -w net.ipv4.ip_forward=1
      grep -q '^net.ipv4.ip_forward=1' /etc/sysctl.conf || echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf

      # Put the lab interface into promiscuous mode.
      ip link set eth1 promisc on || true

      echo "[+] attacker ready — workshop repo at /vagrant; lab interface eth1 = $(ip -4 -o addr show eth1 | awk '{print $4}')"
      echo "[+] verify with:  sudo python3 /vagrant/setup/verify_env.py"
    SHELL
  end
end
