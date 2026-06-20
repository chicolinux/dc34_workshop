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
