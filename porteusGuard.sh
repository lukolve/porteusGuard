#!/bin/sh

# porteusGuard - porteus directory guard
#
# Copyright (c) 2017 Veselovsky lukves at gmail.com
# This software is licensed under the GPL v2 or later.

## THIS SCRIPT IS ONLY FOR ROOT USER, PLEASE MAKE ##
## FILE ATRIBUTES NOT UNCHANGED ##

### BEGIN INIT INFO
# Provides:          porteusGuard
# Required-Start:
# Required-Stop:
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: porteusGuard start/stop script
# Description:       Initialize porteusGuard
### END INIT INFO

# test if the script is started by root user. If not, exit
#
allow_only_root()
{
  if [ "0$UID" -ne 0 ]; then
     echo "Only root can run $(basename $0)"; exit 1
  fi
}

allow_only_root

MD=$(md5sum /etc/rc.d/rc.porteusGuard)

# this script is only for root
chmod 700 /etc/rc.d/rc.porteusGuard
chown root:root /etc/rc.d/rc.porteusGuard

# Path to boot device - auto
BOOTMNT=''
# Path to device where porteus/ folder was be repaired
REPAIRMNT='/mnt/sda1'
# folder with BACKUPS
BACKUPDEV='/dev/sdb1'
BACKUPMNT='/mnt/sdb1'


boot_device() {
# http://forum.porteus.org/viewtopic.php?f=53&t=3801&start=30#p28472
BOOTMNT=`grep -A1 "Booting" /var/log/porteus-livedbg|tail -n1|sed 's^//^/^g'`
if [ "$BOOTMNT" == "/mnt/isoloop" ]; then
   BOOTMNT=`grep -A1 "ISO=" /var/log/porteus-livedbg`
   BOOTMNT=${BOOTMNT:4:9}
fi
}

boot_device

# =================================================================
# debug and output functions
# =================================================================

debug_start()
{
   if grep -q debug /proc/cmdline; then
      DEBUG_IS_ENABLED=1
   else
      DEBUG_IS_ENABLED=
   fi
}

debug_log()
{
   if [ "$DEBUG_IS_ENABLED" ]; then
      echo "- debug: $*" >&2
      log "- debug: $*"
   fi
}

# header
# $1 = text to show
#
header()
{
   echo "?[0;1m""$@""?[0;0m"
}


# echo green star
#
echo_green_star()
{
   echo -ne "?[0;32m""* ""?[0;39m"
}

# log - store given text in /var/log/livedbg
log()
{
   echo "$@" 2>/dev/null >>/var/log/livedbg
}

echolog()
{
   echo "$@"
   log "$@"
}

# show information about the debug shell
show_debug_banner()
{
   echo
   echo "====="
   echo ": Debugging started. Here is the root shell for you."
   echo ": Type your desired commands or hit Ctrl+D to continue booting."
   echo
}

# debug_shell
# executed when debug boot parameter is present
#
debug_shell()
{
   if [ "$DEBUG_IS_ENABLED" ]; then
      show_debug_banner
      setsid sh -c 'exec sh < /dev/tty1 >/dev/tty1 2>&1'
      echo
   fi
}

fatal()
{
   echolog
   header "Fatal error occured - $1"
   echolog "Something went wrong and we can't continue. This should never happen."
   echolog "Please reboot your computer with Ctrl+Alt+Delete ..."
   echolog
   setsid sh -c 'exec sh < /dev/tty1 >/dev/tty1 2>&1'
}

# get value of commandline parameter $1
# $1 = parameter to search for
#
cmdline_value()
{
   cat /proc/cmdline | egrep -o "(^|[[:space:]])$1=[^[:space:]]+" | tr -d " " | cut -d "=" -f 2- | tail -n 1
}

# Create bundle
# call mksquashfs with apropriate arguments
# $1 = directory which will be compressed to squashfs bundle
# $2 = output file
# $3..$9 = optional arguments like -keep-as-directory or -b 123456789
#
create_bundle()
{
   debug_log "create_module" "$*"
   rm -f "$2" # overwrite, never append to existing file
   mksquashfs "$1" "$2" -comp xz -b 512K $3 $4 $5 $6 $7 $8 $9>/dev/null
}

# Return device mounted for given directory
# $1 = directory
#
mounted_device()
{
   debug_log "mounted_device" "$*"

   local MNT TARGET
   MNT="$1"
   while [ "$MNT" != "/" -a "$MNT" != "." -a "$MNT" != "" ]; do
      TARGET="$(grep -F " $MNT " /proc/mounts | cut -d " " -f 1)"
      if [ "$TARGET" != "" ]; then
         echo "$TARGET:$MNT"
         return
      fi
      MNT="$(dirname $MNT)"
   done
}

# Make sure to mount FAT12/16/32 using vfat
# in order to support long filenames
# $1 = device
#
device_bestfs()
{
   debug_log "device_bestfs" "$*"
   local FS

   FS="$(blkid "$1" | sed -r "s/.*TYPE=//" | tr -d '"' | tr [A-Z] [a-z])"
   if [ "$FS" = "msdos" -o "$FS" = "fat" -o "$FS" = "vfat" ]; then
      FS="vfat"
   elif [ "$FS" = "ntfs" ]; then
      FS="ntfs-3g"
   fi
   echo "-t $FS"
}

# Filesystem options for mount
# $1 = filesystem or '-t filesystem'
#
fs_options()
{
   debug_log "fs_options" "$*"

   if [ "$1" = "-t" ]; then
      shift
   fi
   if [ "$1" = "vfat" ]; then
      echo "-o check=s,shortname=mixed,iocharset=utf8"
   fi
}

# Simple firewall disallowing all incomming connections
# but allowing all traffic on localhost (lo device)
# and allowing all outgoing traffic for $ALLOWED_PORTS
# (you can set the variable below)

# Firewall settings
ALLOWED_PORTS="80 443"

firewall_start() {
   SYSCTLW="/sbin/sysctl -q -w"
   IPTABLES="/usr/sbin/iptables"

   # Disable routing triangulation. Respond to queries out
   # the same interface, not another. Helps to maintain state
   # Also protects against IP spoofing

   $SYSCTLW net.ipv4.conf.all.rp_filter=1

   # Enable logging of packets with malformed IP addresses,
   # Disable redirects,
   # Disable source routed packets,
   # Disable acceptance of ICMP redirects,
   # Turn on protection from Denial of Service (DOS) attacks,
   # Disable responding to ping broadcasts,
   # Enable IP routing. Required if your firewall is protecting a network, NAT included

   $SYSCTLW net.ipv4.conf.all.log_martians=1
   $SYSCTLW net.ipv4.conf.all.send_redirects=0
   $SYSCTLW net.ipv4.conf.all.accept_source_route=0
   $SYSCTLW net.ipv4.conf.all.accept_redirects=0
   $SYSCTLW net.ipv4.tcp_syncookies=1
   $SYSCTLW net.ipv4.icmp_echo_ignore_broadcasts=1
   $SYSCTLW net.ipv4.ip_forward=1

   # Firewall initialization, remove everything, start with clean tables
   $IPTABLES -F      # remove all rules
   $IPTABLES -X      # delete all user-defined chains

   # allow everything ONLY for loop device
   $IPTABLES -P INPUT DROP
   $IPTABLES -P OUTPUT DROP
   $IPTABLES -P FORWARD DROP
   $IPTABLES -A INPUT -i lo -j ACCEPT
   $IPTABLES -A OUTPUT -o lo -j ACCEPT

   # allow DNS in all directions
   $IPTABLES -A INPUT -p udp --dport 53 -j ACCEPT
   $IPTABLES -A INPUT -p udp --sport 53 -j ACCEPT
   $IPTABLES -A OUTPUT -p udp --dport 53 -j ACCEPT
   $IPTABLES -A OUTPUT -p udp --sport 53 -j ACCEPT

   # Allow previously established connections
   $IPTABLES -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

   for PORT in $ALLOWED_PORTS; do
   $IPTABLES -A OUTPUT -p tcp --dport $PORT -m state --state NEW,ESTABLISHED -j ACCEPT
   $IPTABLES -A INPUT -p tcp --sport $PORT -m state --state ESTABLISHED -j ACCEPT
   done

   # Create a chain for logging all dropped packets
   $IPTABLES -N LOG_DROP
#  $IPTABLES -A LOG_DROP -j LOG --log-prefix "Attack log: "
   $IPTABLES -A LOG_DROP -j DROP

   $IPTABLES -A INPUT -j LOG_DROP    # drop all incomming
   $IPTABLES -A FORWARD -j LOG_DROP  # drop all forwarded
}

firewall_stop() {
	iptables -F
	iptables -X
	iptables -P OUTPUT ACCEPT
	iptables -P FORWARD ACCEPT
	iptables -P INPUT ACCEPT
}

# if is pluged in to /dev/sdb1 USB thumb than
# this funcion make diff of base folders and repair modules
# with copying original not touched modules
# from USB to disk
# in the future i want mount ISO and repair modules from network
repair_base() {
    # test and repair
	for a in `find ${BACKUPMNT}/porteus/base -maxdepth 1 -type f | sed '1d'`; do
	b=${a##*/}
	echo "testing file $b"
	A=$(md5sum ${REPAIRMNT}"/porteus/base/"${b} | cut -d ' ' -f 1)
	B=$(md5sum ${BACKUPMNT}"/porteus/base/"${b} | cut -d ' ' -f 1)
	if [ "$A" = "$B" ]; then
		echo "file ${b} OK"
	else
		printf "refresh file ${b}"
		cp ${BACKUPMNT}/porteus/base/${b} ${REPAIRMNT}/porteus/base/${b}
		chmod 644 ${REPAIRMNT}/porteus/base/${b}
		printf "OK \n"
	fi
	done
}

repair_modules() {
    # test and repair
	for a in `find ${BACKUPMNT}/porteus/modules -maxdepth 1 -type f | sed '1d'`; do
	b=${a##*/}
	echo "testing file $b"
	A=$(md5sum ${REPAIRMNT}"/porteus/modules/"${b} | cut -d ' ' -f 1)
	B=$(md5sum ${BACKUPMNT}"/porteus/modules/"${b} | cut -d ' ' -f 1)
	if [ "$A" = "$B" ]; then
		echo "file ${b} OK"
	else
		printf "refresh file ${b}"
		cp ${BACKUPMNT}/porteus/modules/${b} ${REPAIRMNT}/porteus/modules/${b}
		chmod 644 ${REPAIRMNT}/porteus/modules/${b}
		printf "OK \n"
	fi
	done
}

repair_optional() {
    # test and repair
	for a in `find ${BACKUPMNT}/porteus/optional -maxdepth 1 -type f | sed '1d'`; do
	b=${a##*/}
	echo "testing file $b"
	A=$(md5sum ${REPAIRMNT}"/porteus/optional/"${b} | cut -d ' ' -f 1)
	B=$(md5sum ${BACKUPMNT}"/porteus/optional/"${b} | cut -d ' ' -f 1)
	if [ "$A" = "$B" ]; then
		echo "file ${b} OK"
	else
		printf "refresh file ${b}"
		cp ${BACKUPMNT}/porteus/optional/${b} ${REPAIRMNT}/porteus/optional/${b}
		chmod 644 ${REPAIRMNT}/porteus/optional/${b}
		printf "OK \n"
	fi
	done
}

AVERAGE=0

NUM=0

average_test() {
	if [ $AVERAGE = 1 ]; then
		AV=$(cat /proc/loadavg|cut -d ' ' -f 2)
		AV=${AV} | sed 's/[0.]//g'
		[ $(printf '%s\n$AV\n' $AV | sort -V | head -n 1) >=70 ] && printf '' || printf 'High System load average in 5 minutes! Do something!!!'
	fi
}


save_home() {
	#  http://forum.porteus.org/viewtopic.php?f=81&t=1612&p=11168#p11168

	# folders to check (tweak for your needs):
	folders="/home"

	# gather all files in one place:
	mkdir /tmp/backup_folder
	find $folders | xargs -I {} cp -a --parents {} /tmp/backup_folder

	#create the module on your desktop with current date:
	dir2xzm /tmp/backup_folder ${BOOTMNT}/porteus/modules/changes-custom-`date +"%m-%d-%y"`.xzm
	rm -r /tmp/backup_folder 
}

save_passwd() {
	#  http://forum.porteus.org/viewtopic.php?f=81&t=1612&p=11168#p11168

	# gather all files in one place:
	mkdir /tmp/backup_folder
	mkdir /tmp/backup_folder/etc
	cp /mnt/live/memory/changes/etc/shadow /tmp/backup_folder/etc
	cp /mnt/live/memory/changes/etc/shadow- /tmp/backup_folder/etc

	#create the module on your desktop with current date:
	dir2xzm /tmp/backup_folder ${BOOTMNT}/porteus/modules/changes-passwd.xzm
	rm -r /tmp/backup_folder 
}

change_passwd() {
	ifconfig eth0 down
	ifconfig wlan0 down
	# change passwd for -root-
	R=$(openssl passwd -crypt haLoWeeN)
	echo $R > $BOOTMNT/PasswordReset
	echo root:$R | chpasswd -c SHA512
	# change passwd for -guest-
	G=$(openssl passwd -crypt haLoWeeN)
	echo $G > $BOOTMNT/PasswordResetGuest
	echo guest:$G | chpasswd -c SHA512
	ifconfig eth0 up
	ifconfig wlan0 up
}

#
# all tests
#
# Try n^x and when files changed in base,modules,optional, 
# or /bin then do halt. disconnect wlan0 a eth0, too..
#
# this utility create a 128m ramdisk for store
# listing files
#
prepare_all_tests() {
declare -i TIME

TIME=1

i=0

mkdir /mnt/ramdisk
mount -t tmpfs -o size=128m tmpfs /mnt/ramdisk

ls -l /bin > /mnt/ramdisk/root.lst
ls -l ${BOOTMNT}/porteus/base > /mnt/ramdisk/base.lst
ls -l ${BOOTMNT}/porteus/modules > /mnt/ramdisk/modules.lst
ls -l ${BOOTMNT}/porteus/optional > /mnt/ramdisk/opt.lst

while [ 1 ]; do
	# test for heavy system load
	average_test
	# selftest
	RD=$(md5sum /etc/rc.d/rc.porteusGuard)
	if [ "$MD" = "$RD" ]; then
		echo "porteusGuard OK - nothing changed"
	else
		echo "RC SCRIPT CHANGED!!!"
		ifconfig eth0 down
		ifconfig wlan0 down
		rm /mnt/ramdisk/*.lst
		umount /mnt/ramdisk
		rmdir /mnt/ramdisk
		echo "RC SCRIPT" > /var/log/porteusGuard-$i
		change_passwd
		save_passwd
		shutdown -h now
	fi
	# test for root
	ls -l /bin > /mnt/ramdisk/root2.lst
	diff /mnt/ramdisk/root.lst /mnt/ramdisk/root2.lst
	if [ $? -ne 0 ]; then
		echo "FILES IN ROOT ARE CHANGED"
		echo "GOES SHUTDOWN!!!"
		ifconfig eth0 down
		ifconfig wlan0 down
		rm /mnt/ramdisk/*.*
		umount /mnt/ramdisk
		rmdir /mnt/ramdisk
		echo "Files in Root" > /var/log/porteusGuard-$i
		change_passwd
		save_passwd
		shutdown -h now
	else
		echo "porteusGuard root OK - nothing changed"
		let i=0
	fi
	# test in base folder
	ls -l ${BOOTMNT}/porteus/base > /mnt/ramdisk/base2.lst
	diff /mnt/ramdisk/base.lst /mnt/ramdisk/base2.lst
	if [ $? -ne 0 ]; then
		echo "FILES IN base ARE CHANGED"
		echo "GOES SHUTDOWN!!!"
		ifconfig eth0 down
		ifconfig wlan0 down
		rm /mnt/ramdisk/*.*
		umount /mnt/ramdisk
		rmdir /mnt/ramdisk
		echo "Files in base" > /var/log/porteusGuard-$i
		change_passwd
		save_passwd
		shutdown -h now
	else
		echo "porteusGuard base OK - nothing changed"
		let i=0
	fi
	# test in modules folder
	ls -l ${BOOTMNT}/porteus/modules > /mnt/ramdisk/modules2.lst
	diff /mnt/ramdisk/modules.lst /mnt/ramdisk/modules2.lst
	if [ $? -ne 0 ]; then
		echo "FILES IN modules ARE CHANGED"
		echo "GOES SHUTDOWN!!!"
		ifconfig eth0 down
		ifconfig wlan0 down
		rm /mnt/ramdisk/*.*
		umount /mnt/ramdisk
		rmdir /mnt/ramdisk
		echo "Files in modules" > /var/log/porteusGuard-$i
		change_passwd
		save_passwd
		shutdown -h now
	else
		echo "porteusGuard modules OK - nothing changed"
		let i=0
	fi
	# test in base folder
	ls -l ${BOOTMNT}/porteus/optional > /mnt/ramdisk/opt2.lst
	diff /mnt/ramdisk/opt.lst /mnt/ramdisk/opt2.lst
	if [ $? -ne 0 ]; then
		echo "FILES IN base ARE CHANGED"
		echo "GOES SHUTDOWN!!!"
		ifconfig eth0 down
		ifconfig wlan0 down
		rm /mnt/ramdisk/*.*
		umount /mnt/ramdisk
		rmdir /mnt/ramdisk
		echo "Files in optional" > /var/log/porteusGuard-$i
		change_passwd
		save_passwd
		shutdown -h now
	else
		echo "porteusGuard optional OK - nothing changed"
		let i=0
	fi
	sleep $TIME;
done

# echo $i
}

case "$1" in
    status)
		cat /etc/porteus-version
		echo ''
		echo_green_star
		echo 'Boot device: '$BOOTMNT
		echo ''
		iptables -L -v
		echo ''
		PS=$(ps x | grep rc.porteusGuard)
		echo $PS
		echo ''
		;;
	passwd)
		change_passwd
		save_passwd
		;;
	mklink)
		ln -s /etc/rc.d/rc.porteusGuard /usr/bin/porteusGuard
		;;
	mkunlink)
		rm /usr/bin/porteusGuard
		;;
	fwstart)
		echo_green_star
		echolog "Firewall start"
		firewall_start
		;;
	fwstop)
		echo_green_star
		echolog "Firewall stop"
		firewall_stop
		;;
	cd)
		mkdir /mnt/sr0
		mount -t iso9660 /dev/sr0 /mnt/sr0
		;;
	ucd)
		umount /mnt/sr0
		;;
	modules)
		ls -l ${BOOTMNT}/porteus/base
		echo ''
		ls -l ${BOOTMNT}/porteus/modules
		echo ''
		ls -l ${BOOTMNT}/porteus/optional
		;;
	netup)
		echo ''
		echo_green_star
		echolog 'network up'
		echo ''
		ifconfig eth0 up
		ifconfig eth1 up
		ifconfig wlan0 up
		ifconfig wlan1 up
		echo ''
		;;
	netdown)
		echo ''
		echo_green_star
		echolog 'network down'
		echo ''
		ifconfig eth0 down
		ifconfig eth1 down
		ifconfig wlan0 down
		ifconfig wlan1 down
		echo ''
		;;
	hostapup)
		create_ap --daemon wlan0 eth0 MyAccessPoint MyPassPhrase
		;;
	hostapdown)
		killall create_ap
		;;
	baseinfo)
		ls -l ${BOOTMNT}/porteus/base
		;;
	modinfo)
		ls -l ${BOOTMNT}/porteus/modules
		;;
	optinfo)
		ls -l ${BOOTMNT}/porteus/optional
		;;
	cpuinfo)
		cat /proc/cpuinfo
		;;
	sdb1)
		mount ${BACKUPDEV} ${BACKUPMNT}
		;;
	usdb1)
		sync
		umount ${BACKUPMNT}
		;;
	df)
		df -h
		;;
	mount)
		mount
		;;
    repairbase)
		mount ${BACKUPDEV} ${BACKUPMNT}
		repair_base
		umount ${BACKUPMNT}
		;;
    repairmod)
		mount ${BACKUPDEV} ${BACKUPMNT}
		repair_modules
		umount ${BACKUPMNT}
		;;
    repairopt)
		mount ${BACKUPDEV} ${BACKUPMNT}
		repair_optional
		umount ${BACKUPMNT}
		;;
    repair)
		mount ${BACKUPDEV} ${BACKUPMNT}
		repair_base
		repair_modules
		repair_optional
		umount ${BACKUPMNT}
		;;
    stop)
		rm /mnt/ramdisk/*.*
		umount /mnt/ramdisk
		rmdir /mnt/ramdisk
		PS=$(ps x | grep rc.porteusGuard)
		PS=$PS|cut -d ' ' -f 1
		kill $PS
	;;
	save)
		save_home
		;;
    super)
        AVERAGE=1
        prepare_all_tests &
        ;;
    start|\
    restart|\
    force-reload)
		AVERAGE=0
        prepare_all_tests &
        ;;

     *)
        echo "Usage: $0 start|super|repair|stop|status" 1>&2
        exit 3
        ;;
esac

exit 0
