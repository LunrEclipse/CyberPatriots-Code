#!/bin/bash
#copy and paste onto text file and use command sudo bash [file path]

apt-get -y install ufw
apt-get -y install libpam-cracklib

ufw enable
echo FireWall Up

read -p "Do you want to uninstall telnet? [y/N]: " telnet 
if [[ "${telnet^^}" == "Y" ]]
then
    apt-get -y purge telnet
else
    echo Netcat Not Removed
fi
read -p "Do you want to uninstall netcat? [y/N]: " netcat 
if [[ "${netcat^^}" == "Y" ]]
then
    apt-get -y purge netcat
else
    echo netcat not Removed
fi
read -p "Do you want to uninstall ssh? [y/N]: " ssh 
if [[ "${ssh^^}" == "Y" ]]
then
    apt-get -y purge ssh
else
    echo SSH not Removed
fi
read -p "Do you want to uninstall samba? [y/N]: " samba 
if [[ "${samba^^}" == "Y" ]]
then
    apt-get -y purge samba
else
    echo samba not Removed
fi
read -p "Do you want to uninstall vsftpd? [y/N]: " vsftpd 
if [[ "${vsftpd^^}" == "Y" ]]
then
    apt-get -y purge vsftpd
else
    echo vsftpd not Removed
fi
apt-get -y purge hydra
apt-get -y autoremove
apt-get -y purge john 
apt-get -y purge Medusa
apt-get -y purge truecrack
apt-get -y purge ophcrack
apt-get -y purge Kismet
apt-get -y purge Nikto
apt-get -y purge cryptcat
apt-get -y purge nc
echo Standard Suspicious Files Purged

echo allow-guest=false >> /etc/lightdm/lightdm.conf
echo Guest Account Disabled

sed -i '/^PermitRootLogin/ c\PermitRootLogin no' /etc/ssh/sshd_config
sed -i '/^Protocol 1/ c\Protocol 2' /etc/ssh/sshd_config
sed -i '/^StrictModes/ c\StrictModes yes' /etc/ssh/sshd_config
service ssh restart
echo root login set to no on ssh

sudo sed -i '/^PASS_MAX_DAYS/ c\PASS_MAX_DAYS 90' /etc/login.defs
sudo sed -i '/^PASS_MIN_DAYS/ c\PASS_MIN_DAYS 10'  /etc/login.defs
sudo sed -i '/^PASS_WARN_AGE/ c\PASS_WARN_AGE 7' /etc/login.defs
echo Password Length Set

sed -i '1 s/^/auth optional pam_tally.so deny=5 unlock_time=900 onerr=fail audit even_deny_root_account silent\n/' /etc/pam.d/common-auth
sed -i '1 s/^/password requisite pam_cracklib.so retry=3 minlen=8 difok=3 reject_username minclass=3 maxrepeat=2 dcredit=1 ucredit=1 lcredit=1 ocredit=1\n/' /etc/pam.d/common-password
echo Password Policies Set

read -p "Do you want to run security software? [y/N]: " clamtk 
if [[ "${clamtk^^}" == "Y" ]]
then
    apt-get install clamtk
apt-get install clamav
apt-get install rkhunter
apt-get install chkrootkit
clamscan
echo ClamScan Complete

read -n 1
rkhunter --checkall
echo RKHunter Scan Complete

read -n 1
chkrootkit -q
echo CHKRootKit Scan Complete

read -n 1
echo Script Complete

else
    echo Script Complete
fi
