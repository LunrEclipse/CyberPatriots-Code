#!/bin/bash
#copy and paste onto text file and use command sudo bash [file path]

function ask_yes_or_no()
{
	read -p "$1 ([Y]es or [n]): "
	case $(echo $REPLY | tr '[A-Z]' '[a-z]') in
		n|no) echo "no" ;;
		*)	echo "yes" ;;
	esac
}

#Downloads UFW and Libpam (passwords)
apt-get -y install ufw
apt-get -y install libpam-cracklib

#Enables Firewall
ufw enable
echo FireWall Up

#Critical Services and Configurations

if[[ "yes" == $(ask_yes_or_no "Do you want to remove Telnet")]]
then
	apt-get -y purge telnet
else
	echo Telnet Not Removed
fi

if[[ "yes" == $(ask_yes_or_no "Do you want to remove NetCat")]]
then
	apt-get -y purge netcat
else
	echo netcat not Removed
fi


if[[ "yes" == $(ask_yes_or_no "Do you want to remove SSH")]]
then
	apt-get -y purge ssh
else
	sed -i '/PermitRootLogin yes/c\PermitRootLogin no' /etc/ssh/sshd_config
	sed -i '/PasswordAuthentication no/c\PasswordAuthentication yes' /etc/ssh/sshd_config
	sed -i '/PermitEmptyPasswords yes/c\PermitEmptyPasswords no' /etc/ssh/sshd_config
	sed -i '/Port 22/c\Port 222' /etc/ssh/sshd_config
	sed -i '/Protocol/c\Protocol 2' /etc/ssh/sshd_config
	sed -i '/X11Forwarding/c\X11Forwarding no' /etc/ssh/sshd_config
	ufw allow 222
	service sshd restart
fi

if[[ "yes" == $(ask_yes_or_no "Do you want to remove Samba")]]
then
	apt-get -y purge samba
else
	echo Samba not Removed
fi


if[[ "yes" == $(ask_yes_or_no "Do you want to remove VSFTPD")]]
then
	apt-get -y purge vsftpd
else
	echo vsftpd not Removed
	sed -i '/anonymous_enable/c\anonymous_enable=NO' /etc/vsftpd.conf
	sed -i '/local_enable/c\local_enable=NO' /etc/vsftpd.conf
	sed -i '/write_enable/c\write_enable=NO' /etc/vsftpd.conf
	sed -i '/chroot_local_user/c\chroot_local_user=YES' /etc/vsftpd.conf
	service vsftpd restart
fi


if[[ "yes" == $(ask_yes_or_no "Do you want to remove Pure-FTP")]]
then
	apt-get -y purge pure-ftpd
else
	echo vsftpd not Removed
fi


if[[ "yes" == $(ask_yes_or_no "Do you want to remove Apache")]]
then
	apt-get -y purge apache
    	apt-get -y purge apache2
else
	echo apache not Removed
fi

#Malicious Programs
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
apt-get -y purge bind9
apt-get -y purge iodine
apt-get -y purge johntheripper
apt-get -y purge fcrackzip
apt-get -y purge ayttm
apt-get -y purge empathy
apt-get -y purge logkeys
apt-get -y purge vino
apt-get -y purge tightvncserver
apt-get -y purge rdesktop
apt-get -y purge remmina
apt-get -y purge vinagre
apt-get -y purge knocker
apt-get -y purge aircrack-ng
echo Standard Suspicious Files Purged

#Guest and Root
passwd -l root
echo allow-guest=false >> /etc/lightdm/lightdm.conf
echo Guest Account Disabled

#Password Policies
sudo sed -i '/^PASS_MAX_DAYS/ c\PASS_MAX_DAYS 90' /etc/login.defs
sudo sed -i '/^PASS_MIN_DAYS/ c\PASS_MIN_DAYS 10'  /etc/login.defs
sudo sed -i '/^PASS_WARN_AGE/ c\PASS_WARN_AGE 7' /etc/login.defs
echo Password Length Set

# IP Hardening
sysctl -w net.ipv4.tcp_syncookies=1
sysctl -w net.ipv4.ip_forward=0
sysctl -w net.ipv4.conf.all.send_redirects=0
sysctl -w net.ipv4.conf.default.send_redirects=0
sysctl -w net.ipv4.conf.all.accept_redirects=0
sysctl -w net.ipv4.conf.default.accept_redirects=0
sysctl -w net.ipv4.conf.all.secure_redirects=0
sysctl -w net.ipv4.conf.default.secure_redirects=0
sysctl -p
# Disable IP Forwarding
echo 0 > /proc/sys/net/ipv4/ip_forward
# Disable IP Spoofing
echo "nospoof on" >> /etc/host.conf
# Disable ipv6
sed -i '/net.ipv6.conf.all.disable_ipv6/d' /etc/sysctl.conf
echo 'net.ipv6.conf.all.disable_ipv6 = 1' >> /etc/sysctl.conf
sed -i '/^net.ipv4.ip_forward=1/ c\net.ipv4.ip_forward=0' /etc/sysctl.conf

sed -i '1 s/^/auth optional pam_tally.so deny=5 unlock_time=900 onerr=fail audit even_deny_root_account silent\n/' /etc/pam.d/common-auth
sed -i '1 s/^/password requisite pam_cracklib.so retry=3 minlen=8 difok=3 reject_username minclass=3 maxrepeat=2 dcredit=1 ucredit=1 lcredit=1 ocredit=1\n/' /etc/pam.d/common-password
echo Password Policies Set

crontab -r
cd /etc/
/bin/rm -f cron.deny at.deny
echo root >cron.allow
echo root >at.allow
/bin/chown root:root cron.allow at.allow
/bin/chmod 644 cron.allow at.allow
echo Crontab Complete

find / -name '*.mp3' -type f -delete
find / -name '*.mov' -type f -delete
find / -name '*.mp4' -type f -delete
find / -name '*.avi' -type f -delete
find / -name '*.mpg' -type f -delete
find / -name '*.mpeg' -type f -delete
find / -name '*.flac' -type f -delete
find / -name '*.m4a' -type f -delete
find / -name '*.flv' -type f -delete
find / -name '*.ogg' -type f -delete
find /home -name '*.gif' -type f -delete
find /home -name '*.png' -type f -delete
find /home -name '*.jpg' -type f -delete
find /home -name '*.jpeg' -type f -delete
echo Shady Filetypes Checked

read -p "Do you want to run security software? [y/N]: " clamtk 
if [[ "${clamtk^^}" == "Y" ]]
then
    apt-get install clamtk
apt-get install clamav
apt-get install rkhunter
apt-get install chkrootkit
clamscan -ir --remove=yes
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
