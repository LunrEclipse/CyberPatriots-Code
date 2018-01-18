#!/bin/bash
#copy and paste onto text file and use command sudo sh [file path]
apt-get -y install ufw
apt-get -y install libpam-cracklib
ufw enable
echo FireWall Up
apt-get -y purge john 
apt-get -y purge telnet
apt-get -y purge netcat
apt-get -y purge hydra
apt-get -y autoremove
echo Standard Suspicious Files Purged
echo allow-guest=false >> /etc/lightdm/lightdm.conf
echo Guest Account Disabled
sed -i '/^PermitRootLogin/ c\PermitRootLogin no' /etc/ssh/sshd_config
service ssh restart
echo root login set to no on ssh
sudo sed -i '/^PASS_MAX_DAYS/ c\PASS_MAX_DAYS   90' /etc/login.defs
sudo sed -i '/^PASS_MIN_DAYS/ c\PASS_MIN_DAYS   10'  /etc/login.defs
sudo sed -i '/^PASS_WARN_AGE/ c\PASS_WARN_AGE   7' /etc/login.defs
echo Password Length Set
sed -i '1 s/^/auth optional pam_tally.so deny=5 unlock_time=900 onerr=fail audit even_deny_root_account silent\n/' /etc/pam.d/common-auth
sed -i '1 s/^/password requisite pam_cracklib.so retry=3 minlen=8 difok=3 reject_username minclass=3 maxrepeat=2 dcredit=1 ucredit=1 lcredit=1 ocredit=1\n/' /etc/pam.d/common-password
