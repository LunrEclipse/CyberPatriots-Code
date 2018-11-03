#!/bin/bash
#copy and paste onto text file and use command sudo bash [file path]

#Downloads UFW and Libpam (passwords)
apt-get -y install ufw
apt-get -y install libpam-cracklib

#Enables Firewall
ufw enable
echo FireWall Up

#Critical Services and Configurations
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
	sed -i '/PermitRootLogin yes/c\PermitRootLogin no' /etc/ssh/sshd_config
	sed -i '/PasswordAuthentication no/c\PasswordAuthentication yes' /etc/ssh/sshd_config
	sed -i '/PermitEmptyPasswords yes/c\PermitEmptyPasswords no' /etc/ssh/sshd_config
	sed -i '/Port 22/c\Port 222' /etc/ssh/sshd_config
	sed -i '/Protocol/c\Protocol 2' /etc/ssh/sshd_config
	sed -i '/X11Forwarding/c\X11Forwarding no' /etc/ssh/sshd_config
	ufw allow 222
	service sshd restart

fi

read -p "Do you want to uninstall samba? [y/N]: " samba 
if [[ "${samba^^}" == "Y" ]]
then
    apt-get -y purge samba
else
    echo samba not Removed
    if test -e /etc/samba/smb.conf
    then 
        sed -i '/server role =/c\	server role = standalone server' /etc/samba/smb.conf
        sed -i '/obey pam restrictions/c\	obey pam restrictions = yes' /etc/samba/smb.conf
        sed -i '/usershare max shares =/c\;	usershare max shares  = 100' /etc/samba/smb.conf
        sed -i '/usershare allow guests =/c\	usershare allow guests = no' /etc/samba/smb.conf
    if grep 'min protocol' /etc/samba/smb.conf
    then
	    sed -i '/min protocol = /c\min protocol = SMB3' /etc/samba/smb.conf
    else
    for line_number in $(grep -n '\[global\]' /etc/samba/smb.conf | cut -d: -f1)
    do
		sed -i "$line_number a min protocol = SMB3" /etc/samba/smb.conf 
    done
    fi
    if grep 'restrict anonymous' /etc/samba/smb.conf
    then
	    sed -i '/restrict anonymous = /c\restrict anonymous = 2' /etc/samba/smb.conf
    else
	    for line_number in $(grep -n '\[global\]' /etc/samba/smb.conf | cut -d: -f1)
    do
		    sed -i "$line_number a restrict anonymous = 2" /etc/samba/smb.conf 
    done
    fi
    ufw deny 135/TCP
    ufw deny 139/TCP
    ufw deny 135/UDP
    ufw deny 137/UDP
    ufw deny 138/UDP
    ufw deny 139/UDP
    service smbd restart

fi

read -p "Do you want to uninstall vsftpd? [y/N]: " vsftpd 
if [[ "${vsftpd^^}" == "Y" ]]
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

read -p "Do you want to uninstall FTP? [y/N]: " ftp 
if [[ "${ftp^^}" == "Y" ]]
then
    apt-get -y purge pure-ftpd
else
    echo vsftpd not Removed
fi

read -p "Do you want to uninstall Apache? [y/N]: " apache 
if [[ "${apache^^}" == "Y" ]]
then
    apt-get -y purge apache
    apt-get -y purge apache2
else
    echo apache not Removed
    if test -e /etc/apache2/conf-enabled/security.conf
	then 
		sed -i '/ServerSignature/c\ServerSignature Off' /etc/apache2/conf-enabled/security.conf
		sed -i '/ServerTokens/c\ServerTokens Prod' /etc/apache2/conf-enabled/security.conf
		sed -i '/TraceEnable/c\TraceEnable Off' /etc/apache2/conf-enabled/security.conf
		sed -i '/ServerTokens/c\ServerTokens Prod' /etc/apache2/conf-enabled/security.conf

	fi
	if test -d /etc/modsecurity
	then
		mv /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf
		sed -i '/SecRuleEngine/c\SecRuleEngine On' /etc/modsecurity/modsecurity.conf
	else
		apt-get -y install libapache2-modsecurity
		mv /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf
		sed -i '/SecRuleEngine/c\SecRuleEngine On' /etc/modsecurity/modsecurity.conf
	fi
	service apache2 restart

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
# Enable cookie protection
sysctl -n net.ipv4.tcp_syncookies
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
