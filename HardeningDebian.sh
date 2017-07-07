##############################
# Author : Samy BELARBI 	   #
# Creation Date: 04 Jul 2017 #
##############################




####################################################
# 3 level of Hardening : normal, high, advance
####################################################


###	 TODO


### UPCOMING FEATURES ###
#ENABLE WARNING BANNER
#Place the system directories to their own partitions: /tmp, /var, /var/log, /var/log/audit, /home
#Add nodev, nosuid, and noexec options to temporary storage partitions
##Add nodev, nosuid, and noexec options to /tmp
##Add nodev, nosuid, and noexec options to /dev/shm
#Disable the automounter
#Disable GNOME automounting
#Disable mounting of uncommon filesystem types
#Verify permissions on passwd, shadow, group and gshadow files
#Verify that all world-writable directories have sticky bits set
#Find unauthorized world-writable files
#Find unauthorized SUID/SGID system executables
#Find and repair unowned files
#Verify that all world-writable directories have proper ownership
#Disable core dumps or at least apply restrictive permissions on the files
#Configure sudo to improve auditing of root access
#Verify that no non-root accounts have UID 0
#Set password expiration parameters
#Remove legacy ’+’ entries from password files
#Create and maintain a group containing all human users
#Set lockouts for failed password attempts
#Use pam deny.so to quickly deny access to a service
#Upgrade password hashing algorithm to SHA-512
#Enable automatic security updates unattended-upgrades
#CONFIGURE SECURE PACKAGE REPOSITORY
#CONFIGURE SECURE DNS SERVER
#CONFIGURE SECURE NTP SERVER
#CONFIGURE NETWORK
#CONFIGURE PRINTER if needed or delete (cups..)
#DELETE ALL GUI PACKAGE (X...), disable at boot and siable startx
#remote AVAHI
#DISABLE ROOT SSH LOGIN
#Disable host-based authentication
#Disable .rhosts files
#Set idle timeout interval for user logins
#Limit users’ SSH access
#SSH Ensure only protocol 2 connections allowed
#Restrict at and cron to authorized users
#Restrict permissions on files used by cron
# Remove the anacron subsystem
# If not used, disable the Raw Devices Daemon
#Disable the irda service & Remove the irda-utils package
#Disable the Advanced Power Management Subsystem (apmd) if power management is not necessary
#Disable the Bluetooth input devices (hidd) & Disable Bluetooth Kernel Modules
#Disabler the Bluetooth host controller interface daemon (bluetooth)
#Disable the HAL Daemon (haldaemon)
#Disable the D-Bus IPC Service (messagebus)
#Disable the boot caching
#Disable Smart Cards service if Smart Cards are not in use on the system
#Disable zeroconf networking
#Disable the IA32 microcode utility (microcode ctl) if the system is not running an Intel IA32 processor
#Disable Kudzu hardware probing utility (kudzu)
#Disable the ISDN support (isdn) service
#Disable the Kdump kernel crash analyzer (kdump) service
#Disable the installation helper service (firstboot)
#Remove the talk software
#Remove the TFTP server
#Remove the NIS service
#Remove the rlogin, rsh, and rcp services, telnet
#If possible, remove the Inetd and Xinetd software packages
#Remove the pam ccreds Package if Possible"




############################################################################################

#Disclaimer
echo -n "I do not claim any responsibility for your use of this script."

#Check Debian Version
OS=$(lsb_release -si)
ARCH=$(uname -m | sed 's/x86_//;s/i[3-6]86/32/')
VER=$(lsb_release -sr)

if [ "$OS" != "Debian" ]; then
echo "Your operating system is not supported" 1>&2
exit 1
fi

#check user executing the script
if [ "$(id -u)" != "0" ]; then
echo "This script must be run as root" 1>&2
exit 1
fi

############################################################################################

sys_upgrades() {
apt-get --yes --force-yes update
apt-get --yes --force-yes upgrade
apt-get --yes --force-yes autoremove
apt-get --yes --force-yes autoclean
}

account_check() {
#check if an account has an empty password
##to lock account with empty password : passwd -l accountName
if [ `awk -F: '($2 == "") {print}' /etc/shadow | wc -c` != 0 ] ; then echo "Mot de passe vide pour un ou plusieurs compte" ; fi

#Verify that All Account Password Hashes are Shadowed
if [ `awk -F: '($2 != "x") {print}' /etc/passwd | wc -c` != 0 ] ; then echo "Hash de mot de passe présent dans /etc/passwd pour les comptes suivants :" ; awk -F: '($2 != "x") {print}' /etc/passwd ; fi

#Verify that No Non-Root Accounts Have UID 0
if [ `awk -F: '($3 == "0") {print}' /etc/passwd | wc -l` != 1 ] ; then echo "Plusieurs comptes ont un UID=0" ; fi

#Remove Legacy + Entries from Password Files
if [ `grep "^+:" /etc/passwd /etc/shadow /etc/group | wc -c` != 0 ] ; then echo "Présence du caractère + dans /etc/shadow ou /etc/group - NIS inclusion" ; fi

}

permissions_check() {
#Verify Permissions on passwd, shadow, group and gshadow Files
cd /etc
chown root:root passwd shadow group gshadow
chmod 644 passwd group
chmod 400 shadow gshadow

purge_nfs() {
# This the standard network file sharing for Unix/Linux/BSD
# style operating systems.
# Unless you require to share data in this manner,
# less layers = more sec
apt-get --yes purge nfs-kernel-server nfs-common portmap rpcbind autofs
}

disable_compilers() {
chmod 000 /usr/bin/cc
chmod 000 /usr/bin/gcc
# 755 to bring them back online
# It is better to restrict access to them
# unless you are working with a specific one
}

#firewall() {}

harden_ssh() {
# Many attackers will try to use your SSH server to brute-force passwords.
# This will only allow 6 connections every 30 seconds from the same IP address.
ufw limit OpenSSH

#disable ssh root login before disable it create a standard user or you lost connection on your server !
#sudo sh -c 'echo "PermitRootLogin no" >> /etc/ssh/ssh_config'
}

disable_avahi() {
update-rc.d -f avahi-daemon disable
# The Avahi daemon provides mDNS/DNS-SD discovery support
# (Bonjour/Zeroconf) allowing applications to discover services on the network.
}

process_accounting() {
# Linux process accounting keeps track of all sorts of details about which commands have been run on the server, who ran them, when, etc.
apt-get --yes --force-yes install acct
touch /var/log/wtmp
# To show users' connect times, run ac. To show information about commands previously run by users, run sa. To see the last commands run, run lastcomm.
#Documentation acct : https://www.tecmint.com/how-to-monitor-user-activity-with-psacct-or-acct-tools/
}

kernel_tuning() {
sudo sh -c 'echo "kernel.randomize_va_space=1" >> /etc/sysctl.conf'

# Enable IP spoofing protection
sudo sh -c 'echo "net.ipv4.conf.all.rp_filter=1" >> /etc/sysctl.conf'

# Disable source packet routing
sudo sh -c 'echo "net.ipv4.conf.all.accept_source_route = 0" >> /etc/sysctl.conf'
sudo sh -c 'echo "net.ipv6.conf.all.accept_source_route = 0 " >> /etc/sysctl.conf'
sudo sh -c 'echo "net.ipv4.conf.default.accept_source_route = 0" >> /etc/sysctl.conf'
sudo sh -c 'echo "net.ipv6.conf.default.accept_source_route = 0" >> /etc/sysctl.conf'

# Ignoring broadcasts request
sudo sh -c 'echo "net.ipv4.icmp_echo_ignore_broadcasts=1" >> /etc/sysctl.conf'

# Make sure spoofed packets get logged
sudo sh -c 'echo "net.ipv4.conf.all.log_martians=1" >> /etc/sysctl.conf'
sudo sh -c 'echo "net.ipv4.conf.default.log_martians=1" >> /etc/sysctl.conf'

# Disable ICMP routing redirects
sudo sh -c 'echo "net.ipv4.conf.all.accept_redirects=0" >> /etc/sysctl.conf'
sudo sh -c 'echo "net.ipv6.conf.all.accept_redirects=0" >> /etc/sysctl.conf'
sudo sh -c 'echo "net.ipv4.conf.all.send_redirects=0" >> /etc/sysctl.conf'

# Disables the magic-sysrq key
sudo sh -c 'echo "kernel.sysrq=0" >> /etc/sysctl.conf'

# Turn off the tcp_timestamps
sudo sh -c 'echo "net.ipv4.tcp_timestamps=0" >> /etc/sysctl.conf'

# Block SYN attacks
sudo sh -c 'echo "net.ipv4.tcp_syncookies = 1" >> /etc/sysctl.conf'
sudo sh -c 'echo "net.ipv4.tcp_max_syn_backlog = 2048" >> /etc/sysctl.conf'
sudo sh -c 'echo "net.ipv4.tcp_synack_retries = 2" >> /etc/sysctl.conf'
sudo sh -c 'echo "net.ipv4.tcp_syn_retries = 5" >> /etc/sysctl.conf'

# Enable bad error message Protection
sudo sh -c 'echo "net.ipv4.icmp_ignore_bogus_error_responses=1" >> /etc/sysctl.conf'

# RELOAD WITH NEW SETTINGS
/sbin/sysctl -p
}


main() {
sys_upgrades
account_check
purge_nfs
disable_compilers
harden_ssh
disable_avahi
process_accounting
kernel_tuning
}


main "$@"
