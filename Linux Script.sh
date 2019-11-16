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
	#goes and replaces the /etc/ssh/sshd_config with clean one
cp /etc/ssh/sshd_config /etc/ssh/.sshd_config
echo "# Package generated configuration file
# See the sshd_config(5) manpage for details
# What ports, IPs and protocols we listen for
Port 22
# Use these options to restrict which interfaces/protocols sshd will bind to
#ListenAddress ::
#ListenAddress 0.0.0.0
Protocol 2
# HostKeys for protocol version 2
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_dsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
#Privilege Separation is turned on for security
UsePrivilegeSeparation yes
# Lifetime and size of ephemeral version 1 server key
KeyRegenerationInterval 3600
ServerKeyBits 768
# Logging
SyslogFacility AUTH
LogLevel INFO
# Authentication:
LoginGraceTime 120
PermitRootLogin no
StrictModes yes
RSAAuthentication yes
PubkeyAuthentication yes
#AuthorizedKeysFile	%h/.ssh/authorized_keys
# Don't read the user's ~/.rhosts and ~/.shosts files
IgnoreRhosts yes
# For this to work you will also need host keys in /etc/ssh_known_hosts
RhostsRSAAuthentication no
# similar for protocol version 2
HostbasedAuthentication no
# Uncomment if you don't trust ~/.ssh/known_hosts for RhostsRSAAuthentication
#IgnoreUserKnownHosts yes
# To enable empty passwords, change to yes (NOT RECOMMENDED)
PermitEmptyPasswords no
# Change to yes to enable challenge-response passwords (beware issues with
# some PAM modules and threads)
ChallengeResponseAuthentication no
# Change to no to disable tunnelled clear text passwords
#PasswordAuthentication yes
# Kerberos options
#KerberosAuthentication no
#KerberosGetAFSToken no
#KerberosOrLocalPasswd yes
#KerberosTicketCleanup yes
# GSSAPI options
#GSSAPIAuthentication no
#GSSAPICleanupCredentials yes
X11Forwarding no
X11DisplayOffset 10
PrintMotd no
PrintLastLog yes
TCPKeepAlive yes
#UseLogin no
#MaxStartups 10:30:60
#Banner /etc/issue.net
# Allow client to pass locale environment variables
AcceptEnv LANG LC_*
Subsystem sftp /usr/lib/openssh/sftp-server
# Set this to 'yes' to enable PAM authentication, account processing,
# and session processing. If this is enabled, PAM authentication will
# be allowed through the ChallengeResponseAuthentication and
# PasswordAuthentication.  Depending on your PAM configuration,
# PAM authentication via ChallengeResponseAuthentication may bypass
# the setting of \"PermitRootLogin without-password\".
# If you just want the PAM account and session checks to run without
# PAM authentication, then enable this but set PasswordAuthentication
# and ChallengeResponseAuthentication to 'no'.
UsePAM yes" > /etc/ssh/sshd_config
service ssh restart
	ufw allow 22
	service sshd restart

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

#Change the ownership and permissions of files that could commonly be exploited otherwise
chown root:root /etc/securetty
chmod 0600 /etc/securetty
chmod 644 /etc/crontab
chmod 640 /etc/ftpusers
chmod 440 /etc/inetd.conf
chmod 440 /etc/xinetd.conf
chmod 400 /etc/inetd.d
chmod 644 /etc/hosts.allow
chmod 440 /etc/sudoers
chmod 640 /etc/shadow
chown root:root /etc/shadow
echo "Finished changing permissions"


#Clears out the control-alt-delete, as this could possibly be a problem
echo "# control-alt-delete - emergency keypress handling
#
# This task is run whenever the Control-Alt-Delete key combination is
# pressed, and performs a safe reboot of the machine.
description	\"emergency keypress handling\"
author		\"Scott James Remnant <scott@netsplit.com>\"
start on control-alt-delete
task
exec false" > /etc/init/control-alt-delete.conf
echo "Finished cleaning control-alt-delete"


#Guest and Root
passwd -l root
sh -c 'printf "[SeatDefaults]\nallow-guest=false\n" >/usr/share/lightdm/lightdm.conf.d/50-no-guest.conf'
echo Guest Account Disabled

#Password Policies
sudo sed -i '/^PASS_MAX_DAYS/ c\PASS_MAX_DAYS 90' /etc/login.defs
sudo sed -i '/^PASS_MIN_DAYS/ c\PASS_MIN_DAYS 10'  /etc/login.defs
sudo sed -i '/^PASS_WARN_AGE/ c\PASS_WARN_AGE 7' /etc/login.defs
echo Password Length Set

# IP Hardening
#enable cookie protection
echo "#### ipv4 networking and equivalent ipv6 parameters ####
## TCP SYN cookie protection (default)
## helps protect against SYN flood attacks
## only kicks in when net.ipv4.tcp_max_syn_backlog is reached
net.ipv4.tcp_syncookies = 1
## protect against tcp time-wait assassination hazards
## drop RST packets for sockets in the time-wait state
## (not widely supported outside of linux, but conforms to RFC)
##CALLED TIME-WAIT ASSASSINATION PROTECTION
net.ipv4.tcp_rfc1337 = 1
## sets the kernels reverse path filtering mechanism to value 1(on)
## will do source validation of the packet's recieved from all the interfaces on the machine
## protects from attackers that are using ip spoofing methods to do harm
net.ipv4.conf.all.rp_filter = 1
net.ipv6.conf.all.rp_filter = 1
## tcp timestamps
## + protect against wrapping sequence numbers (at gigabit speeds)
## + round trip time calculation implemented in TCP
## - causes extra overhead and allows uptime detection by scanners like nmap
## enable @ gigabit speeds
net.ipv4.tcp_timestamps = 0
#net.ipv4.tcp_timestamps = 1
## log martian packets
net.ipv4.conf.all.log_martians = 1
## ignore echo broadcast requests to prevent being part of smurf attacks (default)
net.ipv4.icmp_echo_ignore_broadcasts = 1
## ignore bogus icmp errors (default)
net.ipv4.icmp_ignore_bogus_error_responses = 1
## send redirects (not a router, disable it)
net.ipv4.conf.all.send_redirects = 0
## ICMP routing redirects (only secure)
#net.ipv4.conf.all.secure_redirects = 1 (default)
net.ipv4.conf.default.accept_redirects=0
net.ipv4.conf.all.accept_redirects=0
net.ipv6.conf.default.accept_redirects=0
net.ipv6.conf.all.accept_redirects=0
" >> /etc/sysctl.conf
sysctl --system > /dev/null
echo "Enabled Cookie Protection"

# Disable IP Forwarding
echo 0 > /proc/sys/net/ipv4/ip_forward

# Disable IP Spoofing
echo "nospoof on" >> /etc/host.conf

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

#This clears out the HOST file so that unintentional/malicious networks are accidentally accessed.
echo "Clearing HOSTS file"
#echo $(date): Clearing HOSTS file >> Warnings.txt
cp /etc/hosts hosts
echo 127.0.0.1	localhost > /etc/hosts
echo 127.0.1.1	ubuntu  >> /etc/hosts

echo ::1     ip6-localhost ip6-loopback >> /etc/hosts
echo fe00::0 ip6-localnet >> /etc/hosts
echo ff00::0 ip6-mcastprefix >> /etc/hosts
echo ff02::1 ip6-allnodes >> /etc/hosts
echo ff02::2 ip6-allrouters >> /etc/hosts



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
