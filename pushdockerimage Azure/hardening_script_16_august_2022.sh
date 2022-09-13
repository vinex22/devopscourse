#!/bin/bash

## For Container Image Hardening
## Author - Jeffrey Ho from Microsoft Services - jeffreyho at microsoft.com
## Last Update - 2022 August 16
## Target base image: REHL UBI Standard, CentOS:7, Debian:11, Alpine:3.14
## Hardening Reference: 
###### Image ############################### CIS Standard ################################   
##    REHL UBI  ########## CIS_Red_Hat_Enterprise_Linux_8_Benchmark_v2.0.0     ###########
##    CentOS:7  ##########    CIS_CentOS_Linux_7_Benchmark_v3.1.2              ###########
##    Debian:11 ##########   CIS_Debian_Family_Linux_Benchmark_v1.0.0          ###########
##  Alpine:3.14 ########## CIS_Distribution_Independent_Linux_Benchmark_v1.1.0 ###########
##########################################################################################
# Please note that following extra security configuration is done:
# - Remove commands hexdump, chgrp, ln, od, strings, su, sudo
# - Remove root home directory
# - Remove /etc/fstab
# - Disable password login




#set -x


if cat /etc/os-release | grep "Red Hat Enterprise Linux 8"; then

    echo "----------------------- REHL UBI Hardening Begins -----------------------"
    echo "-----------------------------------------------------------------------"

    echo "Install required packages....."
    yum install -y kmod 
    yum install -y findutils iptables rsyslog dconf crontabs procps
    echo "Installation done"


    echo "1.1.1.1 Ensure mounting of cramfs filesystems is disabled (Automated)"
    printf "install cramfs /bin/false
    blacklist cramfs
    " >> /etc/modprobe.d/cramfs.conf

	modprobe -r cramfs

    echo "-----------------------------------------------------------------------"
	echo "1.1.1.2 Ensure mounting of squashfs filesystems is disabled (Automated)"
    printf "install squashfs /bin/false 
    blacklist squashfs 
    " >> /etc/modprobe.d/squashfs.conf

    modprobe -r squashfs

    echo "-----------------------------------------------------------------------"
	echo "1.1.1.3 Ensure mounting of udf filesystems is disabled (Automated)"
	printf "install udf /bin/false 
    blacklist udf
    " >> /etc/modprobe.d/udf.conf

    modprobe -r udf

    echo "-----------------------------------------------------------------------"
    echo "1.1.2.1 Ensure /tmp is a separate partition(Automated)"
    systemctl unmask tmp.mount

    echo "-----------------------------------------------------------------------"
    echo "1.1.2.2 Ensure nodev option set on /tmp partition (Automated)"

    # if ! findmnt --kernel /tmp | grep nodev;
    # then
    #     echo "No nodev option set"
    # else
    #     echo "<device> /tmp <fstype> defaults,rw,nosuid,nodev,noexec,relatime 0 0" >> /etc/fstab
    #     mount -o remount,noexec,nodev,nosuid /tmp
    # fi
    #echo " /tmp      tmpfs       defaults,rw,nosuid,nodev,noexec,relatime 0 0" >> /etc/fstab
    echo "Not applicable for containers and ensure no malicious file system mount"
    rm -f /etc/fstab


    echo "-----------------------------------------------------------------------"
    echo "1.1.2.3 Ensure noexec option set on /tmp partition (Automated)"
    # if ! findmnt --kernel /tmp | grep noexec;
    # then
    #     echo "No noexec option set"
    # else
    #     echo "<device> /tmp <fstype> defaults,rw,nosuid,nodev,noexec,relatime 0 0" >> /etc/fstab
    #     mount -o remount,noexec,nodev,nosuid /tmp
    # fi
    echo "Not applicable for containers and ensure no malicious file system mount"
    rm -f /etc/fstab
    
    echo "-----------------------------------------------------------------------"
    echo "1.1.3.1 Ensure separate partition exists for /var (Automated)"
    # if ! findmnt --kernel /var;
    # then
    #     echo "No /var is mount"
    # fi
    echo "Not applicable for containers and ensure no malicious file system mount"
    rm -f /etc/fstab
    
     
    echo "-----------------------------------------------------------------------"
    echo "1.1.3.2 Ensure nodev option set on /var partition (Automated)"
    # if ! findmnt --kernel /var | grep nodev
    # then
    #     echo "No nodev option is set"
    # else
    #     echo "<device> /var <fstype> defaults,rw,nosuid,nodev,noexec,relatime 0 0" >> /etc/fstab
    #     mount -o remount /var
    # fi    
    echo "Not applicable for containers and ensure no malicious file system mount"
    rm -f /etc/fstab
    

    echo "-----------------------------------------------------------------------"
    echo "1.1.3.3 Ensure noexec option set on /var partition (Automated)"
    # if ! findmnt --kernel /var | grep noexec
    # then
    #     echo "No noexec option is set"
    # else
    #     echo "<device> /var <fstype> defaults,rw,nosuid,nodev,noexec,relatime 0 0" >> /etc/fstab
    #     mount -o remount /var
    # fi    
    echo "Not applicable for containers and ensure no malicious file system mount"
    rm -f /etc/fstab
    
    echo "-----------------------------------------------------------------------"
    echo "1.1.3.4 Ensure nosuid option set on /var partition (Automated)"
    # if ! findmnt --kernel /var | grep nosuid
    # then
    #     echo "No nosuid option is set"
    # else
    #     echo "<device> /var <fstype> defaults,rw,nosuid,nodev,noexec,relatime 0 0" >> /etc/fstab
    #     mount -o remount /var
    # fi    
    echo "Not applicable for containers and ensure no malicious file system mount"
    rm -f /etc/fstab
    
    echo "-----------------------------------------------------------------------"
    echo "1.1.4.1 Ensure separate partition exists for /var/tmp(Automated)"
    findmnt --kernel /var/tmp


    echo "-----------------------------------------------------------------------"
    echo "1.1.4.2 Ensure noexec option set on /var/tmp partition (Automated)"
    # if ! findmnt --kernel /var/tmp | grep noexec
    # then
    #     echo "No noexec option is set"
    # else
    #     echo "<device> /var/tmp <fstype> defaults,rw,nosuid,nodev,noexec,relatime 0 0" >> /etc/fstab
    #     mount -o remount /var/tmp
    # fi    
    echo "Not applicable for containers and ensure no malicious file system mount"
    rm -f /etc/fstab
    
    echo "-----------------------------------------------------------------------"
    echo "1.1.4.3 Ensure nosuid option set on /var/tmp partition (Automated)"
    # if ! findmnt --kernel /var/tmp | grep nosuid
    # then
    #     echo "No nosuid option is set"
    # else
    #     echo "<device> /var/tmp <fstype> defaults,rw,nosuid,nodev,noexec,relatime 0 0" >> /etc/fstab
    #     mount -o remount /var/tmp
    # fi    
    echo "Not applicable for containers and ensure no malicious file system mount"
    rm -f /etc/fstab
    
    echo "-----------------------------------------------------------------------"
    echo "1.1.4.4 Ensure nosuid option set on /var/tmp partition (Automated)"
    # if ! findmnt --kernel /var/tmp | grep nodev
    # then
    #     echo "No nodev option is set"
    # else
    #     echo "<device> /var/tmp <fstype> defaults,rw,nosuid,nodev,noexec,relatime 0 0" >> /etc/fstab
    #     mount -o remount /var/tmp
    # fi    
    echo "Not applicable for containers and ensure no malicious file system mount"
    rm -f /etc/fstab
    

    echo "-----------------------------------------------------------------------"
    echo "1.1.5.1 Ensure separate partition exists for /var/log (Automated)"
    findmnt --kernel /var/log

    echo "-----------------------------------------------------------------------"
    echo "1.1.5.2 Ensure nosuid option set on /var/log partition (Automated)"
    # if ! findmnt --kernel /var/log | grep nosuid
    # then
    #     echo "No nosuid option is set"
    # else
    #     echo "<device> /var/log <fstype> defaults,rw,nosuid,nodev,noexec,relatime 0 0" >> /etc/fstab
    #     mount -o remount /var/log
    # fi    
    echo "Not applicable for containers and ensure no malicious file system mount"
    rm -f /etc/fstab
    

    echo "-----------------------------------------------------------------------"
    echo "1.1.5.3 Ensure noexec option set on /var/log partition (Automated)"
    # if ! findmnt --kernel /var/log | grep nosuid
    # then
    #     echo "No noexec option is set"
    # else
    #     echo "<device> /var/log <fstype> defaults,rw,nosuid,nodev,noexec,relatime 0 0" >> /etc/fstab
    #     mount -o remount /var/log
    # fi   
    echo "Not applicable for containers and ensure no malicious file system mount"
    rm -f /etc/fstab
    
    echo "-----------------------------------------------------------------------"
    echo "1.1.5.4 Ensure nosuid option set on /var/log partition (Automated)"
    # if ! findmnt --kernel /var/log | grep nosuid
    # then
    #     echo "No nosuid option is set"
    # else
    #     echo "<device> /var/log <fstype> defaults,rw,nosuid,nodev,noexec,relatime 0 0" >> /etc/fstab
    #     mount -o remount /var/log
    # fi   
    echo "Not applicable for containers and ensure no malicious file system mount"
    rm -f /etc/fstab
    

    echo "-----------------------------------------------------------------------"
    echo "1.1.6.1 Ensure separate partition exists for /var/log/audit (Automated)"
    if ! findmnt --kernel /var/log/audit;
    then
        echo "No /var/log/audit is mount"
    fi

    echo "-----------------------------------------------------------------------"
    echo "1.1.6.2 Ensure noexec option set on /var/log/audit partition (Automated)"
    # if ! findmnt --kernel /var/log | grep nosuid
    # then
    #     echo "No noexec option is set"
    # else
    #     echo "<device> /var/log/audit <fstype> defaults,rw,nosuid,nodev,noexec,relatime 0 0" >> /etc/fstab
    #     mount -o remount /var/log
    # fi   
    echo "Not applicable for containers and ensure no malicious file system mount"
    rm -f /etc/fstab
    
    echo "-----------------------------------------------------------------------"
    echo "1.1.6.3 Ensure nodev option set on /var/log/audit partition (Automated)"
    # if ! findmnt --kernel /var/log | grep nosuid
    # then
    #     echo "No nodev option is set"
    # else
    #     echo "<device> /var/log/audit <fstype> defaults,rw,nosuid,nodev,noexec,relatime 0 0" >> /etc/fstab
    #     mount -o remount /var/log
    # fi   
    echo "Not applicable for containers and ensure no malicious file system mount"
    rm -f /etc/fstab
    
    echo "-----------------------------------------------------------------------"
    echo "1.1.6.4 Ensure nosuid option set on /var/log/audit partition (Automated)"
    # if ! findmnt --kernel /var/log | grep nosuid
    # then
    #     echo "No nosuid option is set"
    # else
    #     echo "<device> /var/log/audit <fstype> defaults,rw,nosuid,nodev,noexec,relatime 0 0" >> /etc/fstab
    #     mount -o remount /var/log
    # fi   
    echo "Not applicable for containers and ensure no malicious file system mount"
    rm -f /etc/fstab
    
    echo "-----------------------------------------------------------------------"
    echo "1.1.7.1 Ensure separate partition exists for /home (Automated)"
    if ! findmnt --kernel /home;
    then
        echo "No /home is mount"
    fi

    echo "-----------------------------------------------------------------------"
    echo "1.1.7.2 Ensure nodev option set on /home partition (Automated)"
    # if ! findmnt --kernel /home | grep nosuid
    # then
    #     echo "No nodev option is set"
    # else
    #     echo "<device> /home <fstype> defaults,rw,nosuid,nodev,noexec,relatime 0 0" >> /etc/fstab
    #     mount -o remount  /home
    # fi   
    echo "Not applicable for containers and ensure no malicious file system mount"
    rm -f /etc/fstab
    


    echo "-----------------------------------------------------------------------"
    echo "1.1.7.3 Ensure nosuid option set on /home partition(Automated)"
    # if ! findmnt --kernel  /home | grep nosuid
    # then
    #     echo "No nosuid option is set"
    # else
    #     echo "<device> /home <fstype> defaults,rw,nosuid,nodev,noexec,relatime 0 0" >> /etc/fstab
    #     mount -o remount  /home
    # fi   
    echo "Not applicable for containers and ensure no malicious file system mount"
    rm -f /etc/fstab
    

    echo "-----------------------------------------------------------------------"
    echo "1.1.7.4 Ensure usrquota option set on /home partition (Automated)"
    # if ! findmnt --kernel /home | grep usrquota
    # then
    #     echo "No usrquota option is set"
    # else
    #     echo "<device> /home <fstype> defaults,rw,usrquota,grpquota,nodev,relatime 0 0" >> /etc/fstab
    #     mount -o remount  /home
    #     quotacheck -cugv /home
    # fi   
    echo "Not applicable for containers and ensure no malicious file system mount"
    rm -f /etc/fstab
    

    echo "-----------------------------------------------------------------------"
    echo "1.1.7.5 Ensure grpquota option set on /home partition (Automated)"
    # if ! findmnt --kernel /home | grep grpquota
    # then
    #     echo "No grpquota option is set"
    # else
    #     echo "<device> /home <fstype> defaults,rw,usrquota,grpquota,nodev,relatime 0 0" >> /etc/fstab
    #     mount -o remount  /home
    #     quotacheck -cugv /home
    # fi   
    echo "Not applicable for containers and ensure no malicious file system mount"
    rm -f /etc/fstab
    
    echo "-----------------------------------------------------------------------"
    echo "1.1.8.1 Ensure nodev option set on /dev/shm partition(Automated)"
    # if  mount | grep -E '\s/dev/shm\s' | grep -v nodev
    # then
    #     echo "tmpfs on /dev/shm type tmpfs (rw,nosuid,nodev,noexec,relatime)" >> /etc/fstab 
    #     mount -o remount /dev/shm

    # fi   
    echo "Not applicable for containers and ensure no malicious file system mount"
    rm -f /etc/fstab
    
    echo "-----------------------------------------------------------------------"
    echo "1.1.8.2 Ensure noexec option set on /dev/shm partition (Automated)"
    # if  mount | grep -E '\s/dev/shm\s' | grep -v noexec
    # then
    #     echo "tmpfs on /dev/shm type tmpfs (rw,nosuid,nodev,noexec,relatime)" >> /etc/fstab 
    #     mount -o remount /dev/shm

    # fi   
    echo "Not applicable for containers and ensure no malicious file system mount"
    rm -f /etc/fstab
    
    echo "-----------------------------------------------------------------------"
    echo "1.1.8.3 Ensure nosuid option set on /dev/shm partition (Automated)"
    # if  mount | grep -E '\s/dev/shm\s' | grep -v noexec
    # then
    #     echo "tmpfs on /dev/shm type tmpfs (rw,nosuid,nodev,noexec,relatime)" >> /etc/fstab 
    #     mount -o remount /dev/shm
    # fi   
    echo "Not applicable for containers and ensure no malicious file system mount"
    rm -f /etc/fstab
    

    echo "-----------------------------------------------------------------------"
    echo "1.1.9 Disable Automounting (Automated)"
     dnf remove -y autofs


    echo "-----------------------------------------------------------------------"
    echo "1.1.10 Disable USB Storage (Automated)"
    echo "install usb-storage /bin/true" >> /etc/modprobe.d/usb_storage.conf
    if (lsmod | grep usb-storage)
    then
        rmmod usb-storage
    fi


    echo "-----------------------------------------------------------------------"
    echo "1.2.1 Ensure Red Hat Subscription Manager connection is configured (Manual)"
    echo "Skipped. Not applicable for containers."


    echo "-----------------------------------------------------------------------"
    echo "1.2.2 Ensure GPG keys are configured (Manual)"
    rpm --import /etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release
    rpm -q gpg-pubkey --qf '%{name}-%{version}-%{release} --> %{summary}\n'



    echo "-----------------------------------------------------------------------"
	echo "1.2.3 Ensure gpgcheck is globally activated (Automated)"
    u=$(find /etc/yum.repos.d/ -name "*.repo" -exec echo "Checking:" {} \; -exec sed -i 's/^gpgcheck\s*=\s*.*/gpgcheck=1/' {} \;)
    if [ -z "$u" ]; then
        echo "gpgcheck is enabled"
    else
        sed -i 's/^gpgcheck\s*=\s*.*/gpgcheck=1/' /etc/dnf/dnf.conf
    fi

    echo "-----------------------------------------------------------------------"
    echo "1.2.4 Ensure package manager repositories are configured (Manual)"
    echo "Each Red Hat UBI image is pre-configured to point to UBI yum repositories that contain the latest versions of UBI RPM packages. No need to update"
    
    echo "-----------------------------------------------------------------------"
    echo "1.3.1 Ensure AIDE is installed (Automated)"
    echo "Skipped. Not applicable for containers."

    echo "-----------------------------------------------------------------------"
    echo "1.3.2 Ensure filesystem integrity is regularly checked (Automated)"
    echo "Skipped. Not applicable for containers."

    echo "-----------------------------------------------------------------------"
    echo "1.4.1 Ensure bootloader password is set (Automated)"
    echo "Skipped. Not applicable for containers."

    echo "-----------------------------------------------------------------------"
    echo "1.4.2 Ensure permissions on bootloader config are configured (Automated)"
    echo "Skipped. Not applicable for containers."


    echo "-----------------------------------------------------------------------"	
    echo "1.4.3 Ensure authentication is required when booting into rescue mode (Automated)"
    echo "Skipped. Not applicable for containers."
     

    echo "-----------------------------------------------------------------------"	
    echo "1.5.1 Ensure core dump storage is disabled (Automated)"
    if (grep -i '^\s*storage\s*=' /etc/systemd/coredump.conf)
        then
                sed -i -E s/Storage=[a-zA-Z]+/Storage=none/g /etc/systemd/coredump.conf
        else
                echo 'Storage=none' >> /etc/systemd/coredump.conf
   fi


    echo "-----------------------------------------------------------------------"	
    echo "1.5.2 Ensure core dump backtraces are disabled (Automated)"
    if (grep -i '^\s*ProcessSizeMax\s*=' /etc/systemd/coredump.conf)
        then
                sed -i -E s/ProcessSizeMax=[a-zA-Z]+/ProcessSizeMax=none/g /etc/systemd/coredump.conf
        else
                echo 'ProcessSizeMax=none' >> /etc/systemd/coredump.conf
   fi


    echo "-----------------------------------------------------------------------"	
    echo "1.5.3 Ensure address space layout randomization (ASLR) is enabled (Automated)"
    echo "Skipped. Not applicable for containers."


    echo "-----------------------------------------------------------------------"	
    echo "1.6.1.1 Ensure SELinux is installed (Automated)"
    if (! rpm -q libselinux)
        then
                dnf install -y libselinux
    fi

    echo "-----------------------------------------------------------------------"
    echo "1.6.1.1 Ensure SELinux is not disabled in bootloader configuration"
    echo "Skipped. Not applicable for containers."


    echo "-----------------------------------------------------------------------"	
    echo "1.6.1.3 Ensure SELinux policy is configured (Automated)"
    echo "Skipped. SElinux configuration is done in host level instead of container level"

    echo "-----------------------------------------------------------------------"	
    echo "1.6.1.4 Ensure SELinux policy is enforcing or permissive (Automated)"
    echo "Skipped. SElinux configuration is done in host level instead of container level"

    echo "-----------------------------------------------------------------------"	
    echo "1.6.1.5 Ensure SELinux policy is enforcing (Automated)"
    echo "Skipped. SElinux configuration is done in host level instead of container level"

    echo "-----------------------------------------------------------------------"		
    echo "1.6.1.6 Ensure no unconfined services exist (Automated)"
    u=$(ps -eZ | grep unconfined_service_t)
    if [ -z "$u"]; then
        echo "no unconfined services are found"
    else
        echo "Stoping the unconfined services"
        while read -r line
        do 
            kill $line

        done < <( ps -eZ | grep unconfined_service_t | awk 'FNR == 1 {print $5}' )
    fi

    echo "-----------------------------------------------------------------------"	
    echo "1.6.1.7 Ensure SETroubleshoot is not installed (Automated)"
     dnf remove -y setroubleshoot


    echo "-----------------------------------------------------------------------"	
    echo "1.6.1.8 Ensure the MCS Translation Service (mcstrans) is not installed (Automated)"
     dnf remove -y mcstrans

    echo "-----------------------------------------------------------------------"	
    echo "1.7.1 Ensure message of the day is configured properly (Automated)"
    echo "All access to this system is monitored.  Any person who uses or accesses this system expressly consents to such monitoring and recording.  We may furnish information obtained by its monitoring and recording activity to law enforcement officials if such monitoring and recording reveals possible evidence of unlawful activity." > /etc/motd

    echo "-----------------------------------------------------------------------"	
    echo "1.7.2 Ensure local login warning banner is configured properly (Automated)"
    echo "Authorized uses only. All activity may be monitored and reported." > /etc/issue

    echo "-----------------------------------------------------------------------"	
    echo "1.7.3 Ensure remote login warning banner is configured properly (Automated)"
    echo "Authorized uses only. All activity may be monitored and reported." > /etc/issue.net

    echo "-----------------------------------------------------------------------"	
    echo "1.7.4 Ensure permissions on /etc/motd are configured (Automated)"
    echo "This motd is not required and is removed "
    chown root:root /etc/motd
    chmod u-x,go-wx /etc/motd

    echo "-----------------------------------------------------------------------"	
    echo "1.7.5 Ensure permissions on /etc/issue are configured (Automated)"
    chown root:root /etc/issue
    chmod u-x,go-wx /etc/issue

    echo "-----------------------------------------------------------------------"	
    echo "1.7.6 Ensure permissions on /etc/issue.net are configured (Automated)"
    chown root:root /etc/issue.net
    chmod u-x,go-wx /etc/issue.net

    echo "-----------------------------------------------------------------------"	
    echo "1.8.1 Ensure GNOME Display Manager is removed (Manual)"
    if (! rpm -q gdm | grep not)
        then
             dnf remove -y gdm
    fi    

    echo "-----------------------------------------------------------------------"
    echo "1.8.2 Ensure GDM login banner is configured (Automated)"
    echo "no GNOME Display Manager is installed"


    echo "-----------------------------------------------------------------------"
    echo "1.8.3 Ensure last logged in user display is disabled (Automated)"
    echo "no GNOME Display Manager is installed"


    echo "-----------------------------------------------------------------------"
    echo "1.8.4 Ensure XDMCP is not enabled (Automated)"
    echo "no GNOME Display Manager is installed"

    echo "-----------------------------------------------------------------------"
    echo "1.8.5 Ensure automatic mounting of removable media is disabled (Automated)"
    echo "no GNOME Display Manager installed"
    # printf"
    # [org/gnome/desktop/media-handling]
    # automount=false
    # automount-open=false
    # " >> /etc/dconf/db/local.d/00-media-automount
    # dconf update

    echo "-----------------------------------------------------------------------"	
    echo "1.9 Ensure updates, patches, and additional security software are installed (Manual)"
	dnf check-update
    dnf update -y

    echo "-----------------------------------------------------------------------"	
    echo "1.10 Ensure system-wide crypto policy is not legacy (Automated)"
	update-crypto-policies --set DEFAULT
    update-crypto-policies

    echo "-----------------------------------------------------------------------"
    echo "2.1.1 Ensure time synchronization is in use (Automated)"
    echo "Skipped. Not applicable for containers."


    echo "-----------------------------------------------------------------------"
    echo "2.1.2 Ensure chrony is configured (Automated)"
    echo "Skipped. Not applicable for containers."

    echo "-----------------------------------------------------------------------"	
    echo "2.2.1 Ensure xinetd is not installed (Automated)"
    if (! rpm -q xinetd | grep not)
        then
             dnf remove -y xinetd
    fi    

    echo "-----------------------------------------------------------------------"	
    echo "2.2.2 Ensure xorg-x11-server-common is not installed (Automated)"
    if (! rpm -q xorg-x11-server-common | grep not)
        then
             dnf remove -y xorg-x11-server-common
    fi    

    echo "-----------------------------------------------------------------------"	
    echo "2.2.3 Ensure Avahi Server is not installed (Automated)"
    if (! rpm -q avahi-autoipd avahi | grep not)
        then
             dnf remove -y avahi-autoipd avahi
    fi    

    echo "-----------------------------------------------------------------------"	
    echo "2.2.4 Ensure CUPS is not installed (Automated)"
    if (! rpm -q cups | grep not)
        then
             dnf remove -y cups
    fi    

    echo "-----------------------------------------------------------------------"	
    echo "2.2.5 Ensure DHCP Server is not installed (Automated)"
    if (! rpm -q dhcp-server | grep not)
        then
             dnf remove -y dhcp-server
    fi    

    echo "-----------------------------------------------------------------------"	
    echo "2.2.6 Ensure DNS Server is not installed (Automated)"
    if (! rpm -q bind | grep not)
        then
             dnf remove -y bind
    fi    

    echo "-----------------------------------------------------------------------"	
    echo "2.2.7 Ensure FTP Server is not installed (Automated)"
    if (! rpm -q ftp | grep not)
        then
             dnf remove -y ftp
    fi    

    echo "-----------------------------------------------------------------------"	
    echo "2.2.8 Ensure VSFTP Server is not installed (Automated)"
    if (! rpm -q vsftpd | grep not)
        then
             dnf remove -y vsftpd
    fi    

    echo "-----------------------------------------------------------------------"	
    echo "2.2.9 Ensure TFTP Server is not installed (Automated)"
    if (! rpm -q tftp-server | grep not)
        then
             dnf remove -y tftp-server
    fi    


    echo "-----------------------------------------------------------------------"	
    echo "2.2.10 Ensure a web server is not installed (Automated)"
    if (! rpm -q httpd nginx | grep not)
        then
             dnf remove -y httpd nginx
    fi    

    echo "-----------------------------------------------------------------------"	
    echo "2.2.11 Ensure IMAP and POP3 server is not installed (Automated)"
    if (! rpm -q dovecot cyrus-imapd | grep not)
        then
             dnf remove -y dovecot cyrus-imapd
    fi    

    echo "-----------------------------------------------------------------------"	
    echo "2.2.12 Ensure Samba is not installed (Automated)"
    if (! rpm -q samba | grep not)
        then
             dnf remove -y samba
    fi    

    echo "-----------------------------------------------------------------------"	
    echo "2.2.13 Ensure HTTP Proxy Server is not installed (Automated)"
    if (! rpm -q squid | grep not)
        then
             dnf remove -y squid
    fi    


    echo "-----------------------------------------------------------------------"	
    echo "2.2.14 Ensure net-snmp is not installed (Automated)"
    if (! rpm -q net-snmp | grep not)
        then
             dnf remove -y net-snmp
    fi    


    echo "-----------------------------------------------------------------------"	
    echo "2.2.15 Ensure NIS server is not installed (Automated)"
    if (! rpm -q ypserv | grep not)
        then
             dnf remove -y ypserv
    fi    

    echo "-----------------------------------------------------------------------"	
    echo "2.2.16 Ensure telnet-server is not installed (Automated)"
    if (! rpm -q telnet-server | grep not)
        then
             dnf remove -y telnet-server
    fi    


    echo "-----------------------------------------------------------------------"
    echo "2.2.17 Ensure mail transfer agent is configured for local-only mode (Automated)"
    echo "Skipped. Not applicable for containers."



    echo "-----------------------------------------------------------------------"	
    echo "2.2.18 Ensure nfs-utils is not installed or the nfs-server service is masked (Automated)"
    if (! rpm -q nfs-utils | grep not)
        then
             dnf remove -y nfs-utils
    fi    

    echo "-----------------------------------------------------------------------"	
    echo "2.2.19 Ensure rpcbind is not installed or the rpcbind services are masked (Automated)"
    if (! rpm -q rpcbind | grep not)
        then
             dnf remove -y rpcbind
    fi    


    echo "-----------------------------------------------------------------------"	
    echo "2.2.20 Ensure rsync is not installed or the rsyncd service is masked (Automated)"
    if (! rpm -q rsync | grep not)
        then
             dnf remove -y rsync
    fi    


    echo "-----------------------------------------------------------------------"	
    echo "2.3.1 Ensure NIS Client is not installed (Automated)"
    if (! rpm -q ypbind | grep not)
        then
             dnf remove -y ypbind
    fi    


    echo "-----------------------------------------------------------------------"	
    echo "2.3.2 Ensure rsh client is not installed (Automated)"
    if (! rpm -q rsh | grep not)
        then
             dnf remove -y rsh
    fi    

    echo "-----------------------------------------------------------------------"	
    echo "2.3.3 Ensure talk client is not installed (Automated)"
    if (! rpm -q talk | grep not)
        then
             dnf remove -y talk
    fi    

    echo "-----------------------------------------------------------------------"	
    echo "2.3.4 Ensure telnet client is not installed (Automated)"
    if (! rpm -q telnet | grep not)
        then
             dnf remove -y telnet
    fi    


    echo "-----------------------------------------------------------------------"	
    echo "2.3.5 Ensure LDAP client is not installed (Automated)"
    if (! rpm -q openldap-clients | grep not)
        then
             dnf remove -y openldap-clients
    fi   


    echo "-----------------------------------------------------------------------"	
    echo "2.3.6 Ensure TFTP client is not installed (Automated)"
    if (! rpm -q tftp | grep not)
        then
             dnf remove -y tftp
    fi   


	echo "-----------------------------------------------------------------------"	
	echo "2.4 Ensure nonessential services are removed or masked (Manual)"
    dnf install -y lsof
    r=$(lsof -i -P -n | grep -v "(ESTABLISHED)")
    if [ -z "$r" ]; then
            echo "No established services are found"

    else
        echo "Established service is found and is going to stop them.." 
        dnf install -y net-tools 
        netstat Drop 
        dnf remove -y net-tools        
    fi
    dnf remove -y lsof


	echo "-----------------------------------------------------------------------"	
	echo "3.1.1 Verify if IPv6 is enabled on the system (Manual)"
    echo "Skipped. Not applicable for containers."

	echo "-----------------------------------------------------------------------"	
	echo "3.1.2 Ensure SCTP is disabled (Automated)"
    printf "
    install sctp /bin/true
    " >> /etc/modprobe.d/sctp.conf

	echo "-----------------------------------------------------------------------"	
	echo "3.1.3 Ensure DCCP is disabled (Automated)"
    printf "
    install dccp /bin/true
    " >> /etc/modprobe.d/dccp.conf

	echo "-----------------------------------------------------------------------"	
	echo "3.1.4 Ensure wireless interfaces are disabled (Automated)"
    if command -v nmcli >/dev/null 2>&1 ; then
        nmcli radio all off
    else
        if [ -n "$(find /sys/class/net/*/ -type d -name wireless)" ]; then
            mname=$(for driverdir in $(find /sys/class/net/*/ -type d -name
             wireless | xargs -0 dirname); do basename "$(readlink -f "$driverdir"/device/driver/module)";done | sort -u)
             for dm in $mname; do
                echo "install $dm /bin/true" >> /etc/modprobe.d/disable_wireless.conf
            done
        fi
    fi



	echo "-----------------------------------------------------------------------"	
	echo "3.2.1 Ensure IP forwarding is disabled (Automated)"
    printf "
    net.ipv4.ip_forward = 0
    " >> /etc/sysctl.d/60-netipv4_sysctl.conf


	echo "-----------------------------------------------------------------------"	
	echo "3.2.2 Ensure packet redirect sending is disabled (Automated)"
    printf "
    net.ipv4.conf.all.send_redirects = 0
    net.ipv4.conf.default.send_redirects = 0
    " >> /etc/sysctl.d/60-netipv4_sysctl.conf
 

	echo "-----------------------------------------------------------------------"	
	echo "3.3.1 Ensure source routed packets are not accepted (Automated)"
    printf "
    net.ipv4.conf.all.accept_source_route = 0
    net.ipv4.conf.default.accept_source_route = 0
    " >> /etc/sysctl.d/60-netipv4_sysctl.conf


	echo "-----------------------------------------------------------------------"	
	echo "3.3.2 Ensure ICMP redirects are not accepted (Automated)"
    printf "
    net.ipv4.conf.all.accept_redirects = 0 
    net.ipv4.conf.default.accept_redirects = 0
    " >> /etc/sysctl.d/60-netipv4_sysctl.conf

	echo "-----------------------------------------------------------------------"	
	echo "3.3.3 Ensure secure ICMP redirects are not accepted (Automated)"
    printf "
    net.ipv4.conf.all.secure_redirects = 0
    net.ipv4.conf.default.secure_redirects = 0
    " >> /etc/sysctl.d/60-netipv4_sysctl.conf

	echo "-----------------------------------------------------------------------"	
	echo "3.3.4 Ensure suspicious packets are logged (Automated)"
    printf "
    net.ipv4.conf.all.log_martians = 1
    net.ipv4.conf.default.log_martians = 1
    " >> /etc/sysctl.d/60-netipv4_sysctl.conf

	echo "-----------------------------------------------------------------------"	
	echo "3.3.5 Ensure broadcast ICMP requests are ignored (Automated)"
    printf "
    net.ipv4.icmp_echo_ignore_broadcasts = 1
    " >> /etc/sysctl.d/60-netipv4_sysctl.conf

	echo "-----------------------------------------------------------------------"	
	echo "3.3.6 Ensure bogus ICMP responses are ignored (Automated)"
    printf "
    net.ipv4.icmp_ignore_bogus_error_responses = 1
    " >> /etc/sysctl.d/60-netipv4_sysctl.conf

	echo "-----------------------------------------------------------------------"	
	echo "3.3.7 Ensure Reverse Path Filtering is enabled (Automated)"
    printf "
    net.ipv4.conf.all.rp_filter = 1
    net.ipv4.conf.default.rp_filter = 1
    " >> /etc/sysctl.d/60-netipv4_sysctl.conf


	echo "-----------------------------------------------------------------------"	
	echo "3.3.8 Ensure TCP SYN Cookies is enabled (Automated)"
    printf "
    net.ipv4.tcp_syncookies = 1
    " >> /etc/sysctl.d/60-netipv4_sysctl.conf

	echo "-----------------------------------------------------------------------"	
	echo "3.3.9 Ensure IPv6 router advertisements are not accepted (Automated)"
    printf "
    net.ipv6.conf.all.accept_ra = 0 
    net.ipv6.conf.default.accept_ra = 0
    " >> /etc/sysctl.d/60-netipv6_sysctl.conf


	echo "-----------------------------------------------------------------------"	
	echo "3.4.1.1 Ensure firewalld is installed (Automated)"
    dnf install -y iptables


	echo "-----------------------------------------------------------------------"	
	echo "3.4.1.2 Ensure iptables-services not installed with firewalld (Automated)"
     dnf remove -y iptables-services

	echo "-----------------------------------------------------------------------"	
	echo "3.4.1.3 Ensure nftables either not installed or masked with firewalld (Automated)"
     dnf remove -y nftables

	echo "-----------------------------------------------------------------------"	
	echo "3.4.1.4 Ensure firewalld service enabled and running (Automated)"
    echo "Skipped. Not applicable for containers."

	echo "-----------------------------------------------------------------------"	
	echo "3.4.1.5 Ensure firewalld default zone is set (Automated)"
    echo "Skipped. Not applicable for containers."

	echo "-----------------------------------------------------------------------"	
	echo "3.4.1.6 Ensure network interfaces are assigned to appropriate zone"
    echo "Skipped. Not applicable for containers."

	echo "-----------------------------------------------------------------------"	
	echo "3.4.1.7 Ensure firewalld drops unnecessary services and ports (Manual)"
    echo "Skipped. Not applicable for containers."

	echo "-----------------------------------------------------------------------"	
	echo "3.4.2.1 Ensure nftables is installed (Automated)"
    echo "Skipped. Not applicable for containers."

	echo "-----------------------------------------------------------------------"	
	echo "3.4.2.2 Ensure firewalld is either not installed or masked with nftables (Automated)"
    echo "Skipped. Not applicable for containers."

	echo "-----------------------------------------------------------------------"	
	echo "3.4.2.3 Ensure iptables-services not installed with nftables (Automated)"
     dnf remove -y iptables-services

	echo "-----------------------------------------------------------------------"	
	echo "3.4.2.4 Ensure iptables are flushed with nftables (Manual)"
    echo "Skipped. Not applicable for containers."

	echo "-----------------------------------------------------------------------"	
	echo "3.4.2.5 Ensure an nftables table exists (Automated)"
    echo "Skipped. Not applicable for containers."

	echo "-----------------------------------------------------------------------"	
	echo "3.4.2.6 Ensure nftables base chains exist (Automated)"
    echo "Skipped. Not applicable for containers."

	echo "-----------------------------------------------------------------------"	
	echo "3.4.2.7 Ensure nftables loopback traffic is configured (Automated)"
    echo "Skipped. Not applicable for containers."

	echo "-----------------------------------------------------------------------"	
	echo "3.4.2.8 Ensure nftables outbound and established connections are configured (Manual)"
    echo "Skipped. Not applicable for containers."

	echo "-----------------------------------------------------------------------"	
	echo "3.4.2.9 Ensure nftables default deny firewall policy (Automated)"
    echo "Skipped. Not applicable for containers."

	echo "-----------------------------------------------------------------------"	
	echo "3.4.2.10 Ensure nftables service is enabled (Automated)"
    echo "Skipped. Not applicable for containers."

	echo "-----------------------------------------------------------------------"	
	echo "3.4.2.11 Ensure nftables rules are permanent (Automated)"
    echo "Skipped. Not applicable for containers."

	echo "-----------------------------------------------------------------------"	
	echo "3.4.3.1.1 Ensure iptables packages are installed (Automated))"
    dnf install -y iptables 

	echo "-----------------------------------------------------------------------"	
	echo "3.4.3.1.2 Ensure nftables is not installed with iptables (Automated)"
    echo "Skipped. Not applicable for containers."


	echo "-----------------------------------------------------------------------"	
	echo "3.4.3.1.3 Ensure firewalld is either not installed or masked with iptables (Automated)"
    echo "Skipped. Not applicable for containers."

	echo "-----------------------------------------------------------------------"	
	echo "3.4.3.2.1 Ensure iptables loopback traffic is configured (Automated)"
    echo "Skipped. Not applicable for containers."

	echo "-----------------------------------------------------------------------"	
	echo "3.4.3.2.2 Ensure iptables outbound and established connections are configured (Manual)"
    echo "Skipped. Not applicable for containers."


	echo "-----------------------------------------------------------------------"	
	echo "3.4.3.2.3 Ensure iptables rules exist for all open ports (Automated)"
    echo "Skipped. Not applicable for containers."



	echo "-----------------------------------------------------------------------"	
	echo "3.4.3.2.4 Ensure iptables default deny firewall policy (Automated)"
    echo "Skipped. Not applicable for containers."


	echo "-----------------------------------------------------------------------"	
	echo "3.4.3.2.5 Ensure iptables rules are saved (Automated)"
    echo "Skipped. Not applicable for containers."

	echo "-----------------------------------------------------------------------"	
	echo "3.4.3.2.6 Ensure iptables is enabled and active (Automated)"
    echo "Skipped. Not applicable for containers."

	echo "-----------------------------------------------------------------------"	
	echo "3.4.3.3.1 Ensure ip6tables loopback traffic is configured (Automated)"
    echo "Skipped. Not applicable for containers."

	echo "-----------------------------------------------------------------------"	
	echo "3.4.3.3.2 Ensure ip6tables outbound and established connections are configured (Manual)"
    echo "Skipped. Not applicable for containers."

	echo "-----------------------------------------------------------------------"	
	echo "3.4.3.3.3 Ensure ip6tables firewall rules exist for all open ports (Automated)"
    echo "Skipped. Not applicable for containers."

	echo "-----------------------------------------------------------------------"	
	echo "3.4.3.3.4 Ensure ip6tables default deny firewall policy (Automated)"
    echo "Skipped. Not applicable for containers."

	echo "-----------------------------------------------------------------------"	
	echo "3.4.3.3.5 Ensure ip6tables rules are saved (Automated)"
    echo "Skipped. Not applicable for containers."

	echo "-----------------------------------------------------------------------"	
	echo "3.4.3.3.6 Ensure ip6tables is enabled and active (Automated)"
    echo "Skipped. Not applicable for containers."

	echo "-----------------------------------------------------------------------"	
	echo "4.1.1.1 Ensure auditd is installed (Automated)"
    echo "Skipped. Not applicable for containers."

	echo "-----------------------------------------------------------------------"	
	echo "4.1.1.2 Ensure auditd service is enabled (Automated)"
    echo "Skipped. Not applicable for containers."

	echo "-----------------------------------------------------------------------"	
	echo "4.1.1.3 Ensure auditing for processes that start prior to auditd is enabled (Automated)"
    echo "Skipped. Not applicable for containers."


	echo "-----------------------------------------------------------------------"	
	echo "4.1.1.4 Ensure audit_backlog_limit is sufficient (Automated)"
    echo "Skipped. Not applicable for containers."

	echo "-----------------------------------------------------------------------"	
	echo "4.1.2.1 Ensure audit log storage size is configured (Automated)"
    echo "Skipped. Not applicable for containers."

	echo "-----------------------------------------------------------------------"	
	echo "4.1.2.2 Ensure audit logs are not automatically deleted (Automated)"
    echo "Skipped. Not applicable for containers."

	echo "-----------------------------------------------------------------------"	
	echo "4.1.2.3 Ensure system is disabled when audit logs are full (Automated)"
    echo "Skipped. Not applicable for containers."

	echo "-----------------------------------------------------------------------"	
	echo "4.1.3.1 Ensure changes to system administration scope (sudoers) is collected (Automated)"
    echo "Skipped. Not applicable for containers."

	echo "-----------------------------------------------------------------------"	
	echo "4.1.3.2 Ensure actions as another user are always logged (Automated)"
    echo "Skipped. Not applicable for containers."

	echo "-----------------------------------------------------------------------"	
	echo "4.1.3.2 Ensure actions as another user are always logged (Automated)"
    echo "Skipped. Not applicable for containers."

	echo "-----------------------------------------------------------------------"	
	echo "4.1.3.3 Ensure events that modify the sudo log file are collected (Automated)"
    echo "Skipped. Not applicable for containers."

	echo "-----------------------------------------------------------------------"	
	echo "4.1.3.4 Ensure events that modify date and time information are collected (Automated)"
    echo "Skipped. Not applicable for containers."

	echo "-----------------------------------------------------------------------"	
	echo "4.1.3.5 Ensure events that modify the system's network environment are collected (Automated)"
    echo "Skipped. Not applicable for containers."

	echo "-----------------------------------------------------------------------"	
	echo "4.1.3.6 Ensure use of privileged commands are collected (Automated)"
    echo "Skipped. Not applicable for containers."


	echo "-----------------------------------------------------------------------"	
	echo "4.1.3.7 Ensure unsuccessful file access attempts are collected (Automated)"
    echo "Skipped. Not applicable for containers."


	echo "-----------------------------------------------------------------------"	
	echo "4.1.3.8 Ensure events that modify user/group information are collected (Automated)"
    echo "Skipped. Not applicable for containers."


	echo "-----------------------------------------------------------------------"	
	echo "4.1.3.9 Ensure discretionary access control permission modification events are collected (Automated)"
    echo "Skipped. Not applicable for containers."


	echo "-----------------------------------------------------------------------"	
	echo "4.1.3.10 Ensure successful file system mounts are collected (Automated)"
    echo "Skipped. Not applicable for containers."


	echo "-----------------------------------------------------------------------"	
	echo "4.1.3.11 Ensure session initiation information is collected (Automated)"
    echo "Skipped. Not applicable for containers."



	echo "-----------------------------------------------------------------------"	
	echo "4.1.3.12 Ensure login and logout events are collected (Automated)"
    echo "Skipped. Not applicable for containers."


	echo "-----------------------------------------------------------------------"	
	echo "4.1.3.13 Ensure file deletion events by users are collected (Automated)"
    echo "Skipped. Not applicable for containers."

	echo "-----------------------------------------------------------------------"	
	echo "4.1.3.14 Ensure events that modify the system's Mandatory Access Controls are collected (Automated)"
    echo "Skipped. Not applicable for containers."

    
	echo "-----------------------------------------------------------------------"	
	echo "4.1.3.15 Ensure successful and unsuccessful attempts to use the chcon command are recorded (Automated)"
    echo "Skipped. Not applicable for containers."


	echo "-----------------------------------------------------------------------"	
	echo "4.1.3.16 Ensure successful and unsuccessful attempts to use the setfacl command are recorded (Automated)"
    echo "Skipped. Not applicable for containers."


	echo "-----------------------------------------------------------------------"	
	echo "4.1.3.17 Ensure successful and unsuccessful attempts to use the chacl command are recorded (Automated)"
    echo "Skipped. Not applicable for containers."

	echo "-----------------------------------------------------------------------"	
	echo "4.1.3.18 Ensure successful and unsuccessful attempts to use the usermod command are recorded (Automated)"
    echo "Skipped. Not applicable for containers."

	echo "-----------------------------------------------------------------------"	
	echo "4.1.3.19 Ensure kernel module loading unloading and modification is collected (Automated)"
    echo "Skipped. Not applicable for containers."

	echo "-----------------------------------------------------------------------"	
	echo "4.1.3.20 Ensure the audit configuration is immutable (Automated)"
    echo "Skipped. Not applicable for containers."

	echo "-----------------------------------------------------------------------"	
	echo "4.1.3.21 Ensure the running and on disk configuration is the same (Manual)"
    echo "Skipped. Not applicable for containers."




	echo "-----------------------------------------------------------------------"	
	echo "4.2.1.1 Ensure rsyslog is installed (Automated)"
    dnf install -y rsyslog



	echo "-----------------------------------------------------------------------"	
	echo "4.2.1.2 Ensure rsyslog service is enabled (Automated)"
    if systemctl is-enabled rsyslog | grep disabled; then
        systemctl --now enable rsyslog
    fi

	echo "-----------------------------------------------------------------------"	
	echo "4.2.1.3 Ensure journald is configured to send logs to rsyslog (Manual)"
    echo "ForwardToSyslog=yes" >> /etc/systemd/journald.conf


	echo "-----------------------------------------------------------------------"	
	echo "4.2.1.4 Ensure rsyslog default file permissions are configured"
    echo "FileCreateMode 0640" >>  /etc/rsyslog.conf 

	echo "-----------------------------------------------------------------------"	
	echo "4.2.1.5  Ensure logging is configured (Manual)"
    printf "*.emerg                         :omusrmsg:*
    auth,authpriv.*                 /var/log/secure
    cron.*                          /var/log/cron
    " >> /etc/rsyslog.conf

	echo "-----------------------------------------------------------------------"	
	echo "4.2.1.6 Ensure rsyslog is configured to send logs to a remote log host (Manual)"
    echo "Skipped. Not applicable for containers."


	echo "-----------------------------------------------------------------------"	
	echo "4.2.1.7 Ensure rsyslog is not configured to recieve logs from a remote client (Automated)"
    printf "module(load="imtcp")
    input(type="imtcp" port="514")
    " >> /etc/rsyslog.conf
    

	echo "-----------------------------------------------------------------------"	
	echo "4.2.2.1.1 Ensure systemd-journal-remote is installed (Manual)"
    echo "Skipped. Not applicable for containers."


	echo "-----------------------------------------------------------------------"	
	echo "4.2.2.1.2 Ensure systemd-journal-remote is configured (Manual)"
    echo "Skipped. Not applicable for containers."

	echo "-----------------------------------------------------------------------"	
	echo "4.2.2.1.3 Ensure systemd-journal-remote is enabled (Manual)"
    echo "Skipped. Not applicable for containers."

	echo "-----------------------------------------------------------------------"	
	echo "4.2.2.1.4 Ensure journald is not configured to recieve logs from a remote client (Automated)"
    echo "Skipped. Not applicable for containers."
       

	echo "-----------------------------------------------------------------------"	
	echo "4.2.2.2 Ensure journald service is enabled (Automated)"
    if (systemctl is-enabled systemd-journald.service | grep static); then
        echo "journald service is enabled"
    else
        echo "journald services is not enabled. By default, it cannnot be enabled/disabled. Please investigate why." 
        exit 1
    fi

	echo "-----------------------------------------------------------------------"	
	echo "4.2.2.3 Ensure journald is configured to compress large log files (Automated)"
    echo "Compress=yes" >> /etc/systemd/journald.conf 

    

	echo "-----------------------------------------------------------------------"	
	echo "4.2.2.4 Ensure journald is configured to write logfiles to persistent disk (Automated)"
    echo "Storage=persistent" >> /etc/systemd/journald.conf 

	echo "-----------------------------------------------------------------------"	
	echo "4.2.2.5 Ensure journald is not configured to send logs to rsyslog (Manual)"
    echo "Skipped. Not applicable for containers."

	echo "-----------------------------------------------------------------------"	
	echo "4.2.2.6 Ensure journald log rotation is configured per site policy (Manual)"
    sed -i -E s/.*MaxFileSec=[0-9][a-zA-Z]+/MaxFileSec=1month/g /etc/systemd/journald.conf
    sed -i -E s/.*SystemMaxUse=/SystemMaxUse=10M/g /etc/systemd/journald.conf
    sed -i -E s/.*RuntimeMaxUse=/RuntimeMaxUse=10M/g /etc/systemd/journald.conf
    sed -i -E s/.*SystemKeepFree=/SystemKeepFree=100M/g /etc/systemd/journald.conf
    sed -i -E s/.*RuntimeKeepFree=/RuntimeKeepFree=100M/g /etc/systemd/journald.conf

	echo "-----------------------------------------------------------------------"	
	echo "4.2.2.7 Ensure journald default file permissions configured (Manual)"
    chmod 640 /usr/lib/tmpfiles.d/systemd.conf

	echo "-----------------------------------------------------------------------"	
	echo "4.2.3 Ensure permissions on all logfiles are configured (Automated)"
    for file in /var/log/*/*.log; do
        chmod 640 $file
    done

	echo "-----------------------------------------------------------------------"	
	echo "4.3 Ensure logrotate is configured (Manual)"
    if (cat /etc/logrotate.d/* | grep rotate); then
        echo "Rotation is configured"
    else
        printf"/var/log/apt/term.log {
        rotate 12
        monthly
        compress
        missingok
        notifempty
        }

        /var/log/apt/history.log {
        rotate 12
        monthly
        compress
        missingok
        notifempty
        }" >> /etc/logrotate.d/rsyslog
    fi


	echo "-----------------------------------------------------------------------"	
	echo "4.4 Ensure logrotate assigns appropriate permissions (Automated)"
    echo "create 0640 root utmp" >> /etc/logrotate.conf

	echo "-----------------------------------------------------------------------"	
	echo "5.1.1 Ensure cron daemon is enabled (Automated)"
    if ! systemctl is-enabled crond | grep enabled; then
        systemctl --now enable crond
    fi


	echo "-----------------------------------------------------------------------"	
	echo "5.1.2 Ensure permissions on /etc/crontab are configured (Automated)"
    chown root:root /etc/crontab
    chmod og-rwx /etc/crontab


	echo "-----------------------------------------------------------------------"	
	echo "5.1.3 Ensure permissions on /etc/cron.hourly are configured"
    chown root:root /etc/cron.hourly
    chmod og-rwx /etc/cron.hourly


	echo "-----------------------------------------------------------------------"	
	echo "5.1.4 Ensure permissions on /etc/cron.daily are configured (Automated)"
    chown root:root /etc/cron.daily
    chmod og-rwx /etc/cron.daily

	echo "-----------------------------------------------------------------------"	
	echo "5.1.5 Ensure permissions on /etc/cron.weekly are configured (Automated)"
    chown root:root /etc/cron.weekly
    chmod og-rwx /etc/cron.weekly

	echo "-----------------------------------------------------------------------"	
	echo "5.1.6 Ensure permissions on /etc/cron.monthly are configured (Automated)"
    chown root:root /etc/cron.monthly
    chmod og-rwx /etc/cron.monthly

	echo "-----------------------------------------------------------------------"	
	echo "5.1.7 Ensure permissions on /etc/cron.d are configured (Automated)"
    chown root:root /etc/cron.d
    chmod og-rwx /etc/cron.d


	echo "-----------------------------------------------------------------------"	
	echo "5.1.8 Ensure cron is restricted to authorized users (Automated)"
    if rpm -q cronie >/dev/null; then
        [ -e /etc/cron.deny ] && rm -f /etc/cron.deny
        [ ! -e /etc/cron.allow ] && touch /etc/cron.allow
        chown root:root /etc/cron.allow
        chmod u-x,go-rwx /etc/cron.allow
    else
        echo "cron is not installed on the system"
    fi


	echo "-----------------------------------------------------------------------"	
	echo "5.1.9 Ensure at is restricted to authorized users (Automated)"
    if rpm -q at >/dev/null; then
        [ -e /etc/at.deny ] && rm -f /etc/at.deny
        [ ! -e /etc/at.allow ] && touch /etc/at.allow
        chown root:root /etc/at.allow
        chmod u-x,go-rwx /etc/at.allow
    else
        echo "at is not installed on the system"
    fi

	echo "-----------------------------------------------------------------------"	
	echo "5.2.1 Ensure permissions on /etc/ssh/sshd_config are configured (Automated)"
    echo "Skipped. Not applicable for containers."

	echo "-----------------------------------------------------------------------"	
	echo "5.2.2 Ensure permissions on SSH private host key files are configured (Automated)"
    echo "Skipped. Not applicable for containers."


	echo "-----------------------------------------------------------------------"	
	echo "5.2.3 Ensure permissions on SSH public host key files are configured (Automated)"
    echo "Skipped. Not applicable for containers."



	echo "-----------------------------------------------------------------------"	
	echo "5.2.4 Ensure SSH access is limited (Automated)"
    echo "Skipped. Not applicable for containers."

	echo "-----------------------------------------------------------------------"	
	echo "5.2.5 Ensure SSH LogLevel is appropriate (Automated)"
    echo "Skipped. Not applicable for containers."

	echo "-----------------------------------------------------------------------"	
	echo "5.2.6 Ensure SSH PAM is enabled (Automated)"
    echo "Skipped. Not applicable for containers."


	echo "-----------------------------------------------------------------------"	
	echo "5.2.7 Ensure SSH root login is disabled (Automated)"
    echo "Skipped. Not applicable for containers."


	echo "-----------------------------------------------------------------------"	
	echo "5.2.8 Ensure SSH HostbasedAuthentication is disabled (Automated)"
    echo "Skipped. Not applicable for containers."

	echo "-----------------------------------------------------------------------"	
	echo "5.2.9 Ensure SSH PermitEmptyPasswords is disabled (Automated)"
    echo "Skipped. Not applicable for containers."


	echo "-----------------------------------------------------------------------"	
	echo "5.2.10 Ensure SSH PermitUserEnvironment is disabled (Automated)"
    echo "Skipped. Not applicable for containers."

	echo "-----------------------------------------------------------------------"	
	echo "5.2.11 Ensure SSH IgnoreRhosts is enabled (Automated)"
    echo "Skipped. Not applicable for containers."

	echo "-----------------------------------------------------------------------"	
	echo "5.2.12 Ensure SSH X11 forwarding is disabled (Automated)"
    echo "Skipped. Not applicable for containers."

	echo "-----------------------------------------------------------------------"	
	echo "5.2.13 Ensure SSH AllowTcpForwarding is disabled (Automated)"
    echo "Skipped. Not applicable for containers."

	echo "-----------------------------------------------------------------------"	
	echo "5.2.14 Ensure system-wide crypto policy is not over-ridden (Automated)"
    echo "Skipped. Not applicable for containers."

	echo "-----------------------------------------------------------------------"	
	echo "5.2.15 Ensure SSH warning banner is configured (Automated)"
    echo "Skipped. Not applicable for containers."


	echo "-----------------------------------------------------------------------"	
	echo "5.2.16 Ensure SSH MaxAuthTries is set to 4 or less (Automated)"
    echo "Skipped. Not applicable for containers."

	echo "-----------------------------------------------------------------------"	
	echo "5.2.17 Ensure SSH MaxStartups is configured (Automated)"
    echo "Skipped. Not applicable for containers."


	echo "-----------------------------------------------------------------------"	
	echo "5.2.18 Ensure SSH MaxSessions is set to 10 or less (Automated)"
    echo "Skipped. Not applicable for containers."


	echo "-----------------------------------------------------------------------"	
	echo "5.2.19 Ensure SSH LoginGraceTime is set to one minute or less (Automated)"
    echo "Skipped. Not applicable for containers."


	echo "-----------------------------------------------------------------------"	
	echo "5.2.20 Ensure SSH Idle Timeout Interval is configured (Automated)"
    echo "Skipped. Not applicable for containers."

	echo "-----------------------------------------------------------------------"	
	echo "5.3.1 Ensure sudo is installed (Automated)"
    dnf install -y sudo

	echo "-----------------------------------------------------------------------"	
	echo "5.3.2 Ensure sudo commands use pty (Automated)"
    echo "Defaults use_pty" >> /etc/sudoers


	echo "-----------------------------------------------------------------------"	
	echo "5.3.3 Ensure sudo log file exists (Automated)"
    echo 'Defaults logfile="/var/log/sudo.log"' >> /etc/sudoers

	echo "-----------------------------------------------------------------------"	
	echo "5.3.4 Ensure users must provide password for escalation (Automated)"
    if (grep -r "^[^#].*NOPASSWD" /etc/sudoers*); then
        echo "Removing users not using password for escalation"
        while read -r user
        do 
            deluser -f  $user
        done < <( grep -r "^[^#].*NOPASSWD" /etc/sudoers* )
    fi    
    echo "remove interactive login shell for additional security protection"
    sed -i -r 's#^(.*):[^:]*$#\1:/sbin/nologin#' /etc/passwd



	echo "-----------------------------------------------------------------------"	
	echo "5.3.5 Ensure re-authentication for privilege escalation is not disabled globally (Automated)"
    if (grep -r "^[^#].*NOPASSWD" /etc/sudoers*); then
        u=$(grep -r "^[^#].*NOPASSWD" /etc/sudoers*)
        echo "Please remove any occurences of !authenticate tags in the /etc/sudoers*"
        exit 1
    fi


	echo "-----------------------------------------------------------------------"	
	echo "5.3.6 Ensure sudo authentication timeout is configured correctly (Automated)"
    if (grep -roP "timestamp_timeout=\K[0-9]*" /etc/sudoers*); then
        printf"Defaults env_reset, timestamp_timeout=15
        Defaults timestamp_timeout=15
        Defaults env_reset
        " >> /etc/sudoers*
    fi


	echo "-----------------------------------------------------------------------"	
	echo "5.3.7 Ensure access to the su command is restricted (Automated)"
    groupadd sugroup
    echo "auth required pam_wheel.so use_uid group=sugroup" >> /etc/pam.d/su


	echo "-----------------------------------------------------------------------"	
	echo "5.4.1 Ensure custom authselect profile is used (Manual)"
    echo "Skipped. Not applicable for containers."

	echo "-----------------------------------------------------------------------"	
	echo "5.4.2 Ensure authselect includes with-faillock (Automated)"
    echo "Skipped. Not applicable for containers."



	echo "-----------------------------------------------------------------------"	
	echo "5.5.1 Ensure password creation requirements are configured (Automated)"
    echo "minlen = 14" >> /etc/security/pwquality.conf 
    echo "minclass = 4" >> /etc/security/pwquality.conf 


	echo "-----------------------------------------------------------------------"	
	echo "5.5.2 Ensure lockout for failed password attempts is configured (Automated)"
    printf "deny = 5
    unlock_time = 900
    " >> /etc/security/faillock.conf

	echo "-----------------------------------------------------------------------"	
	echo "5.5.3 Ensure password reuse is limited (Automated)"
    grep -P '^\h*password\h+(requisite|sufficient)\h+(pam_pwhistory\.so|pam_unix\.so)\h+([^#\n\r]+\h+)?remember=([5-9]|[1-9][0-9]+)\h*(\h+.*)?$' /etc/pam.d/system-auth
    printf "password    requisite   pam_pwhistory.so try_first_pass local_users_only enforce_for_root retry=3 remember=5
    password    requisite   pam_unix.so sha512 shadow try_first_pass use_authtok remember=5
    " >>/etc/pam.d/system-auth


	echo "-----------------------------------------------------------------------"	
	echo "5.5.4 Ensure password hashing algorithm is SHA-512 (Automated)"
    if (! grep -Ei '^\s*crypt_style\s*=\s*sha512\b' /etc/libuser.conf | grep sha512); then
        echo "crypt_style = sha512" >>  /etc/libuser.conf
    fi
    if (! grep -Ei '^\s*ENCRYPT_METHOD\s+SHA512\b' /etc/login.defs | grep SHA512); then
        echo "ENCRYPT_METHOD SHA512" >>  /etc/login.defs
    fi

    
	echo "-----------------------------------------------------------------------"	
	echo "5.6.1.1 Ensure password expiration is 365 days or less  (Automated)"
    sed -i -E 's/PASS_MAX_DAYS\s*[0-9]+/PASS_MAX_DAYS    180/g' /etc/login.defs


	echo "-----------------------------------------------------------------------"	
	echo "5.6.1.2 Ensure minimum days between password changes is 7 or more (Automated)"
    sed -i -E 's/PASS_MIN_DAYS\s*[0-9]+/PASS_MIN_DAYS    7/g' /etc/login.defs

	echo "-----------------------------------------------------------------------"	
	echo "5.6.1.3 Ensure password expiration warning days is 7 or more(Automated)"
    sed -i -E 's/PASS_WARN_AGE\s*[0-9]+/PASS_WARN_AGE   7/g' /etc/login.defs


	echo "-----------------------------------------------------------------------"	
	echo "5.6.1.4 Ensure inactive password lock is 30 days or less (Automated)"
    useradd -D -f 30

	echo "-----------------------------------------------------------------------"	
	echo "5.6.1.5 Ensure all users last password change date is in the past (Automated)"
    for usr in $(cut -d: -f1 /etc/shadow); do [[ $(chage --list $usr | grep '^Last password change' | cut -d: -f2) > $(date) ]] && echo "$usr :$(chage --list $usr | grep '^Last password change' | cut -d: -f2)" && echo "Please confirm if users is required to delete"; done 
	
    echo "-----------------------------------------------------------------------"	
	echo "5.6.2 Ensure system accounts are secured (Automated)"
    for usr in $(awk -F: '($1!="root" && $1!="sync" && $1!="shutdown" && $1!="halt" && $1!~/^\+/ && $3<'"$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)"' && $7!="'"$(which nologin)"'" && $7!="/bin/false") {print}' /etc/passwd | cut -f1 -d:); do usermod -s $(which nologin) $usr; done


	echo "-----------------------------------------------------------------------"	
	echo "5.6.3 Ensure default user shell timeout is 900 seconds or less (Automated)"
    echo "readonly TMOUT=900 ; export TMOUT" >> /etc/profile


	echo "-----------------------------------------------------------------------"	
	echo "5.6.4 Ensure default group for the root account is GID 0 (Automated)"
    if (!  grep "^root:" /etc/passwd | cut -f4 -d: | grep 0); then
        usermod -g 0 root
    fi

	echo "-----------------------------------------------------------------------"	
	echo "5.6.5 Ensure default user umask is 027 or more restrictive (Automated)"
    echo "umask 027" >> /etc/profile

	echo "-----------------------------------------------------------------------"	
	echo "6.1.1 Audit system file permissions (Manual)"
    u=$(rpm -V $(rpm -qf /bin/bash))
    if [ -z "$u" ]; then
        echo "Package is installed and configured correctly"
    else
        echo "By default, all default packages should be configured correctly. Please verify and remediate based on the result."
        exit 1
    fi

	echo "-----------------------------------------------------------------------"	
	echo "6.1.2 Ensure sticky bit is set on all world-writable directories"
    df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null | xargs -I '{}' chmod a+t '{}'


	echo "-----------------------------------------------------------------------"	
	echo "6.1.3 Ensure permissions on /etc/passwd are configured (Automated)"
    chown root:root /etc/passwd
    chmod 644 /etc/passwd

	echo "-----------------------------------------------------------------------"	
	echo "6.1.4 Ensure permissions on /etc/shadow are configured (Automated)"
    chown root:root /etc/shadow
    chmod 0000 /etc/shadow

	echo "-----------------------------------------------------------------------"	
	echo "6.1.5 Ensure permissions on /etc/group are configured (Automated)"
    chown root:root /etc/group
    chmod u-x,g-wx,o-wx /etc/group


	echo "-----------------------------------------------------------------------"	
	echo "6.1.6 Ensure permissions on /etc/gshadow are configured (Automated)"
    chown root:root /etc/gshadow
    chmod 0000 /etc/gshadow


	echo "-----------------------------------------------------------------------"	
	echo "6.1.7 Ensure permissions on /etc/passwd- are configured (Automated)"
    chown root:root /etc/passwd-
    chmod u-x,go-wx /etc/passwd-


	echo "-----------------------------------------------------------------------"	
	echo "6.1.8 Ensure permissions on /etc/shadow- are configured (Automated)"
    chown root:root /etc/shadow-
    chmod 0000 /etc/shadow-

	echo "-----------------------------------------------------------------------"	
	echo "6.1.9 Ensure permissions on /etc/group- are configured (Automated)"
    chown root:root /etc/group-
    chmod u-x,go-wx /etc/group-

	echo "-----------------------------------------------------------------------"	
	echo "6.1.10 Ensure permissions on /etc/gshadow- are configured (Automated)"
    chown root:root /etc/gshadow-
    chmod 0000 /etc/gshadow-

	echo "-----------------------------------------------------------------------"	
	echo "6.1.11 Ensure no world writable files exist (Automated)"
    file=$( df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type f -perm -0002)
    for f in file; do rm -f $f; done
    echo "Remove world-writeable permissions except for /tmp/"
    find / -xdev -type d -perm -0002 -exec chmod o-w {} + \
    && find / -xdev -type f -perm -0002 -exec chmod o-w {} + \
    && chmod 777 /tmp

	echo "-----------------------------------------------------------------------"	
	echo "6.1.12 Ensure no unowned files or directories exist (Automated)"
    file=$( df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nouser)
    for f in file; do rm -f $f; done


	echo "-----------------------------------------------------------------------"	
	echo "6.1.13 Ensure no ungrouped files or directories exist (Automated)"
    file=$( df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -nogroup )
    for f in file; do rm -f $f; done



	echo "-----------------------------------------------------------------------"	
	echo "6.1.14 Audit SUID executables (Manual)"
    suid=$(df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type f -perm -4000)
    check="sudo"
    result=$(echo $suid | rev | cut -f1 -d'/' | rev)
    if [ "$result"=="$check" ]; then
    echo "No extra SUID found"
    else
    echo "Unexpected SUID executables found. Please review."
    df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type f -perm -4000  
    exit 1
    fi



	echo "-----------------------------------------------------------------------"	
	echo "6.1.15 Audit SGID executables (Manual)"
    sgid=$(df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type f -perm -2000)
    check="write"
    result=$(echo $sgid | rev | cut -f1 -d'/' | rev)
    if [ "$result"=="$check" ]; then
    echo "No extra SGID found"
    else
    echo "Unexpected SGID executables found. Please review."
    df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type f -perm -2000
    exit 1
    fi


	echo "-----------------------------------------------------------------------"	
	echo "6.2.1 Ensure password fields are not empty (Automated)"
    awk -F: '($2 == "" ) { print $1 " does not have a password "}' /etc/shadow
    echo "Disable passowrd login for additional security protection"
    while IFS=: read -r username _; do passwd -l "$username"; done < /etc/passwd || true

	echo "-----------------------------------------------------------------------"	
	echo "6.2.2 Ensure all groups in /etc/passwd exist in /etc/group (Automated)"
    for i in $(cut -s -d: -f4 /etc/passwd | sort -u ); do grep -q -P "^.*?:[^:]*:$i:" /etc/group 
    if [ $? -ne 0 ]; then  
    echo "Group $i is referenced by /etc/passwd but does not exist in /etc/group"
    groupdel -f $i
    fi
    done
    

	echo "-----------------------------------------------------------------------"	
	echo "6.2.3 Ensure no duplicate UIDs exist (Automated)"
    cat /etc/passwd | cut -f3 -d":" | sort -n | uniq -c | while read x ; do
    [ -z "${x}" ] && break
    set - $x
    if [ $1 -gt 1 ]; then
    users=`awk -F: '($3 == n) { print $1 }' n=$2 /etc/passwd | xargs`
    echo "Duplicate UID ($2): ${users}"
     echo "Duplicate UID can be only deleted manually "
    exit 1
    fi
    done



	echo "-----------------------------------------------------------------------"	
	echo "6.2.4 Ensure no duplicate GIDs exist (Automated)"
	cut -d: -f3 /etc/group | sort | uniq -d | while read x ; do
		echo "Duplicate GID ($x) in /etc/group"
        echo "Duplicate GID can be only deleted manually "
        exit 1
	done    


	echo "-----------------------------------------------------------------------"	
	echo "6.2.5 Ensure no duplicate user names exist (Automated)"
	cut -d: -f1 /etc/passwd | sort | uniq -d | while read x 
	do echo "Duplicate login name ${x} in /etc/passwd"
        echo "Duplicate user can be only deleted manually "
        exit 1
	done


	echo "-----------------------------------------------------------------------"	
	echo "6.2.6 Ensure no duplicate group names exist (Automated)"
	cut -d: -f1 /etc/group | sort | uniq -d | while read x
	do echo "Duplicate group name ${x} in /etc/group"
        echo "Duplicate group name can be only deleted manually"
        exit 1
	done


	echo "-----------------------------------------------------------------------"	
	echo "6.2.7 Ensure root PATH Integrity (Automated)"
    if [ "`echo $PATH | grep :: `" != "" ]; then
    echo "Empty Directory in PATH (::)"
    fi
    if [ "`echo $PATH | grep :$`" != "" ]; then
    echo "Trailing : in PATH"
    fi
    p=`echo $PATH | sed -e 's/::/:/' -e 's/:$//' -e 's/:/ /g'`
    set -- $p
    while [ "$1" != "" ]; do
    if [ "$1" = "." ]; then
    echo "PATH contains ."
    shift
    continue
    fi
    if [ -d $1 ]; then
    dirperm=`ls -ldH $1 | cut -f1 -d" "`
    if [ `echo $dirperm | cut -c6 ` != "-" ]; then
    echo "Group Write permission set on directory $1"
        dirown=`ls -ldH $1 | awk '{print $3}'`
    if [ "$dirown" != "root" ] ; then
        echo $1 is not owned by root
        rm -rf $1
    fi
    fi
    if [ `echo $dirperm | cut -c9 ` != "-" ]; then
    echo "Other Write permission set on directory $1"
        dirown=`ls -ldH $1 | awk '{print $3}'`
    if [ "$dirown" != "root" ] ; then
        echo $1 is not owned by root
        rm -rf $1
    fi
    fi
    
    else
    echo $1 is not a directory
    fi
    shift
    done
   


	echo "-----------------------------------------------------------------------"	
	echo "6.2.8 Ensure root is the only UID 0 account (Automated)"
    for u in $(awk -F: '($3 == 0) { print $1 }' /etc/passwd); do 
    if [ "$u" != "root" ]; then
        userdel $u
    fi
    done


	echo "-----------------------------------------------------------------------"	
	echo "6.2.9 Ensure all users' home directories exist (Automated)"
    awk -F: '($1!~/(halt|sync|shutdown|nfsnobody)/ && $7!~/^(\/usr)?\/sbin\/nologin(\/)?$/ && $7!~/(\/usr)?\/bin\/false(\/)?$/) { print $1 " " $6 }' /etc/passwd | while read -r user dir; do
        if [ ! -d "$dir" ]; then
                mkdir "$dir" chmod g-w,o-wrx "$dir" chown "$user" "$dir"
        fi
    done


	echo "-----------------------------------------------------------------------"	
	echo "6.2.10 Ensure users own their home directories (Automated)"
    awk -F: '($1!~/(halt|sync|shutdown|nfsnobody)/ && $7!~/^(\/usr)?\/sbin\/nologin(\/)?$/ && $7!~/(\/usr)?\/bin\/false(\/)?$/) { print $1 " " $6 }' /etc/passwd | while read -r user dir; do
    if [ ! -d "$dir" ]; then
    echo "User: \"$user\" home directory: \"$dir\" does not exist, creating home directory" 
    mkdir "$dir"
    chmod g-w,o-rwx "$dir"
    chown "$user" "$dir" else
    owner=$(stat -L -c "%U" "$dir")
    if [ "$owner" != "$user" ]; then
    chmod g-w,o-rwx "$dir"
    chown "$user" "$dir"
    fi
    fi
    done


	echo "-----------------------------------------------------------------------"	
	echo "6.2.11 Ensure users' home directories permissions are 750 or more restrictive  (Automated)"
    awk -F: '($1!~/(halt|sync|shutdown|nfsnobody)/ && $7!~/^(\/usr)?\/sbin\/nologin(\/)?$/ && $7!~/(\/usr)?\/bin\/false(\/)?$/) {print $6}' /etc/passwd | while read -r dir; do 
    if [ -d "$dir" ]; then 
    dirperm=$(stat -L -c "%A" "$dir") 
        if [ "$(echo "$dirperm" | cut -c6)" != "-" ] || [ "$(echo "$dirperm" | cut -c8)" != "-" ] || [ "$(echo "$dirperm" | cut -c9)" != "-" ] || [ "$(echo "$dirperm" | cut -c10)" != "-" ]; then 
            chmod g-w,o-rwx "$dir"
        fi 
    fi 
    done


	echo "-----------------------------------------------------------------------"	
	echo "6.2.12 Ensure users' dot files are not group or world writable (Automated)"
    awk -F: '($1!~/(halt|sync|shutdown|nfsnobody)/ && $7!~/^(\/usr)?\/sbin\/nologin(\/)?$/ && $7!~/(\/usr)?\/bin\/false(\/)?$/) { print $6 }' /etc/passwd | while read -r dir; do
    if [ -d "$dir" ]; then
            for file in "$dir"/.*; do \
                    if [ ! -h "$file" ] && [ -f "$file" ]; then
                            fileperm=$(stat -L -c "%A" "$file")
                                    if [ "$(echo "$fileperm" | cut -c6)" != "-" ] || [ "$(echo "$fileperm" | cut -c9)" != "-" ]; then
                                            chmod go-w "$file"
                                    fi
                    fi
            done
    fi
    done


echo "-----------------------------------------------------------------------"
echo "6.2.13 Ensure users' .netrc Files are not group or world accessible (Automated)"
	grep -E -v '^(root|halt|sync|shutdown)' /etc/passwd | awk -F: '($7 != "'"$(which nologin)"'" && $7 != "/bin/false") { print $1 " " $6 }' | while read user dir; do
		if [ ! -d "$dir" ]; then
			echo "The home directory ($dir) of user $user does not exist."
		else
			for file in $dir/.netrc; do
				if [ ! -h "$file" -a -f "$file" ]; then
					fileperm=$(ls -ld $file | cut -f1 -d" ")
					if [ $(echo $fileperm | cut -c5) != "-" ]; then
						echo "Group Read set on $file"
					fi
					if [ $(echo $fileperm | cut -c6) != "-" ]; then
						echo "Group Write set on $file"
					fi
					if [ $(echo $fileperm | cut -c7) != "-" ]; then
						echo "Group Execute set on $file"
					fi
					if [ $(echo $fileperm | cut -c8) != "-" ]; then
						echo "Other Read set on $file"
					fi
					if [ $(echo $fileperm | cut -c9) != "-" ]; then
						echo "Other Write set on $file"
					fi
					if [ $(echo $fileperm | cut -c10) != "-" ]; then
						echo "Other Execute set on $file"
					fi
				fi
			done
		fi
	done

    echo "-----------------------------------------------------------------------"
    echo "6.2.14 Ensure no users have .forward files (Scored)"
    awk -F: '($1!~/(halt|sync|shutdown)/ && $7!~/^(\/usr)?\/sbin\/nologin(\/)?$/ && $7!~/(\/usr)?\/bin\/false(\/)?$/) { print $6 }' /etc/passwd | while read -r dir; do
    if [ -d "$dir" ]; then
            file="$dir/.forward"
            [ ! -h "$file" ] && [ -f "$file" ] && rm -f "$file"
                fi
    done


    echo "-----------------------------------------------------------------------"
    echo "6.2.15 Ensure no users have .netrc files (Automated)"
    awk -F: '($1!~/(halt|sync|shutdown)/ && $7!~/^(\/usr)?\/sbin\/nologin(\/)?$/ && $7!~/(\/usr)?\/bin\/false(\/)?$/) { print $6 }' /etc/passwd | while read -r dir; do
    if [ -d "$dir" ]; then
            file="$dir/.netrc"
            [ ! -h "$file" ] && [ -f "$file" ] && rm -f "$file"
                fi
    done


    echo "-----------------------------------------------------------------------"
    echo "6.2.16 Ensure no users have .rhosts files (Automated)"
    awk -F: '($1!~/(halt|sync|shutdown)/ && $7!~/^(\/usr)?\/sbin\/nologin(\/)?$/ && $7!~/(\/usr)?\/bin\/false(\/)?$/) { print $6 }' /etc/passwd | while read -r dir; do
    if [ -d "$dir" ]; then
            file="$dir/.rhosts"
            [ ! -h "$file" ] && [ -f "$file" ] && rm -f "$file"
                fi
    done

echo "-----------------------------------------------------------------------"
echo "CIS Section completed"
echo "-----------------------------------------------------------------------"

echo "Cleaning installed packages...."
yum remove -y kmod findutils procps iptables rsyslog dconf crontabs
echo "Remove done...."

echo "-----------------------------------------------------------------------"
echo "Clean up by removing unneccessary and dangerous commands"
find /bin /etc /lib /sbin /usr -xdev \( \
  -iname hexdump -o \
  -iname chgrp -o \
  -iname ln -o \
  -iname od -o \
  -iname strings -o \
  -iname su -o \
  -iname sudo \
\) -exec rm -rf {}  \;

echo "Clean up by removing root home dir"
rm -fr /root

echo "-----------------------------------------------------------------------"
echo "Hardening Completed (Redhat)"
echo "-----------------------------------------------------------------------"


fi




if cat /etc/os-release | grep -i "Alpine Linux v3.14\|Alpine Linux v3.16"; then

echo "----------------------- Alpine Hardening Begins -----------------------"

echo "-----------------------------------------------------------------------"
echo "1.1.1.1 Ensure mounting of cramfs filesystems is disabled scored"
echo "install cramfs /bin/true" >> /etc/modprobe.d/CIS.conf
rmmod cramfs

echo "-----------------------------------------------------------------------"
echo "1.1.1.2 Ensure mounting of freevxfs filesystems is disabled scored"
echo "install freevxfs /bin/true" >> /etc/modprobe.d/CIS.conf
rmmod freevfs

echo "-----------------------------------------------------------------------"
echo "1.1.1.3 Ensure mounting of jffs2 filesystems is disabled scored"
echo "install jffs2 /bin/true" >> /etc/modprobe.d/CIS.conf
rmmod jffs2

echo "-----------------------------------------------------------------------"
echo "1.1.1.4 Ensure mounting of hfs filesystems is disabled scored"
echo "install hfs /bin/true" >> /etc/modprobe.d/CIS.conf
rmmod hfs

echo "-----------------------------------------------------------------------"
echo "1.1.1.5 Ensure mounting of hfsplus filesystems is disabled scored"
echo "install hfsplus /bin/true" >> /etc/modprobe.d/CIS.conf
rmmod hfsplus

echo "-----------------------------------------------------------------------"
echo "1.1.1.6 Ensure mounting of squashfs filesystems is disabled scored"
echo "install squashfs /bin/true" >> /etc/modprobe.d/CIS.conf
rmmod squashfs

echo "-----------------------------------------------------------------------"
echo "1.1.1.7 Ensure mounting of udf filesystems is disabled scored"
echo "install udf /bin/true" >> /etc/modprobe.d/CIS.conf
rmmod udf

echo "-----------------------------------------------------------------------"
echo "1.1.1.7 Ensure mounting of vfat filesystems is disabled scored"
echo "install vfat /bin/true" >> /etc/modprobe.d/CIS.conf
rmmod vfat



echo "-----------------------------------------------------------------------"
echo "1.1.2 Ensure separate partition exists for /tmp scored - Not applicable for container"
#echo /tmp
mount | grep tmp

echo "-----------------------------------------------------------------------"
echo "1.1.3 Ensure nodev option set on /tmp partition scored - Not applicable for container"
echo "1.1.4 Ensure nosuid option set on /tmp partition scored - Not applicable for container"
echo "1.1.5 Ensure noexec option set on /tmp partition scored - Not applicable for container"
#echo "/dev/sdz /tmp rw,nosuid,nodev,noexec,relatime 0 0" /etc/fstab 
echo "Ensure no malicious file system mount"
rm -f /etc/fstab


echo "-----------------------------------------------------------------------"
echo "1.1.6 Ensure separate partition exists for /var scored - Not applicable for container"
mount | grep /var


echo "-----------------------------------------------------------------------"
echo "1.1.7 Ensure separate partition exists for /var/tmp scored - Not applicable for container"
mount | grep /var/tmp

echo "-----------------------------------------------------------------------"
echo "1.1.8 Ensure nodev option set on /var/tmp partition scored - Not applicable for container"
echo "1.1.9 Ensure nosuid option set on /var/tmp partition scored - Not applicable for container"
echo "1.1.10 Ensure noexec option set on /var/tmp partition scored - Not applicable for container (1.1.11, 1.1.12, 1.1.13 and 1.1.14 are duplicated with 1.1.10)"
echo "Ensure no malicious file system mount"
rm -f /etc/fstab


echo "-----------------------------------------------------------------------"
echo "1.1.15 Ensure separate partition exists for /var/log scored - Not applicable for container"
mount | grep /var/log

echo "-----------------------------------------------------------------------"
echo "1.1.16 Ensure separate partition exists for /var/log/audit scored - Not applicable for container"
mount | grep /var/log/audit

echo "-----------------------------------------------------------------------"
echo "1.1.17 Ensure separate partition exists for /home scored - Not applicable for container"
mount | grep /home
# revised
echo "-----------------------------------------------------------------------"
echo "1.1.18 Ensure nodev option set on /home partition scored - Not applicable for container"
echo "Ensure no malicious file system mount"
rm -f /etc/fstab

echo "-----------------------------------------------------------------------"
echo "1.1.19 Ensure nodev option set on /dev/shm partition  scored - Not applicable for container"
echo "1.1.20 Ensure nosuid option set on /dev/shm partition  scored - Not applicable for container"
echo "1.1.21 Ensure noexec option set on /dev/shm partition  scored - Not applicable for container"
echo "1.1.22 Ensure nodev option set on removable media partitions notscored - Not applicable for container"
echo "1.1.23 Ensure nosuid option set on removable media partitions notscored - Not applicable for container"
echo "1.1.24 Ensure noexec option set on removable media partitions notscored - Not applicable for container"
echo "Ensure no malicious file system mount"
rm -f /etc/fstab



echo "-----------------------------------------------------------------------"
echo "1.1.25 Ensure sticky bit is set on all world-writable directories scored"
apk add -f findutlis
apk add -f coreutils
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type d -perm -0002 2>/dev/null | xargs chmod a+t

echo "-----------------------------------------------------------------------"
echo "1.1.26 Disable Automounting scored" 
rm -f /etc/init/autofs.conf


echo "-----------------------------------------------------------------------"
echo "1.2.2 Ensure GPG keys are configured notscored - Not applicable for container"
echo "Skipped. Not applicable for containers."

echo "-----------------------------------------------------------------------"
echo "1.3.1 Ensure AIDE is installed scored - Not applicable for container"
echo "1.3.2 Ensure filesystem integrity is regularly checked scored - Not applicable for container"
echo "Skipped. Not applicable for containers."



echo "-----------------------------------------------------------------------"
echo "1.4.1 Ensure permissions on bootloader config are configured scored"
echo "Skipped. Not applicable for containers."


echo "-----------------------------------------------------------------------"
echo "1.4.2 Ensure bootloader password is set scored - Not applicable for container"
echo "Skipped. Not applicable for containers."


echo "-----------------------------------------------------------------------"
echo "1.4.3 Ensure authentication required for single user mode scored - Not applicable for container"
echo "Skipped. Not applicable for containers."

echo "-----------------------------------------------------------------------"
echo "1.4.4 Ensure interactive boot is not enabled not scored - Not applicable for container"
echo "Skipped. Not applicable for containers."



echo "-----------------------------------------------------------------------"
echo "1.5.1 Ensure core dumps are restricted scored"
mkdir /etc/security
echo " * hard core 0 " >> /etc/security/limits.conf
echo "fs.suid_dumpable = 0" >> /etc/sysctl.conf
#sysctl -w fs.suid_dumpable=0
sysctl -p

echo "-----------------------------------------------------------------------"
echo "1.5.2 Ensure XD/NX support is enabled scored - Not applicable for container"
echo "Skipped. Not applicable for containers."


echo "-----------------------------------------------------------------------"
echo "1.5.3 Ensure address space layout randomization ASLR is enabled scored"
echo "kernel.randomize_va_space=2" >> /etc/sysctl.conf
#sysctl -w kernel.randomize_va_space=2
sysctl -p

echo "-----------------------------------------------------------------------"
echo "1.5.4 Ensure prelink is disabled scored"
prelink -ua
apk del -f prelink

echo "-----------------------------------------------------------------------"
echo "1.6.1.1 Ensure SELinux is not disabled in bootloader configuration - Not applicable for container"
echo "1.6.1.2 Ensure the SELinux state is enforcing scored - Not applicable for container"
echo "1.6.1.3 Ensure SELinux policy is configured scored - Not applicable for container"
echo "Skipped. Not applicable for containers."


echo "-----------------------------------------------------------------------"
echo "1.6.1.4 Ensure SETroubleshoot is not installed scored"
apk del setroubleshoot -f

echo "-----------------------------------------------------------------------"
echo "1.6.1.5 Ensure the MCS Translation Service (mcstrans) is not installed scored"
apk del mcstrans -f

echo "-----------------------------------------------------------------------"
echo "1.6.1.6 Ensure no unconfined daemons exist scored"
while read -r line; do
        kill $line
done < <( ps -eZ | egrep "initrc" | egrep -vw "tr|ps|egrep|bash|awk" | tr ':' ' ' | awk '{ print $NF }' )



echo "-----------------------------------------------------------------------" 
echo "1.6.2.1 Ensure all AppArmor Profiles are enforcing score - Not applicable for container"
echo "Skipped. Not applicable for containers."

echo "-----------------------------------------------------------------------" 
echo "1.6.2.2 Ensure all AppArmor Profiles are enforcing score - Not applicable for container"
echo "Skipped. Not applicable for containers."

echo "-----------------------------------------------------------------------"
echo "1.6.3 Ensure SELinux or AppArmor are installed scored - Not applicable for container"
echo "Skipped. Not applicable for containers."


echo "-----------------------------------------------------------------------"
echo "1.7.1.1 Ensure message of the day is configured properly scored"
echo "All access to this system is monitored.  Any person who uses or accesses this system expressly consents to such monitoring and recording.  We may furnish information obtained by its monitoring and recording activity to law enforcement officials if such monitoring and recording reveals possible evidence of unlawful activity." > /etc/motd
chown root:root /etc/motd
chmod 644 /etc/motd

echo "-----------------------------------------------------------------------"
echo "1.7.1.2 Ensure local login warning banner is configured properly notscored"
echo "Authorized uses only. All activity may be monitored and reported." > /etc/issue


echo "-----------------------------------------------------------------------"
echo "1.7.1.3 Ensure remote login warning banner is configured properly notscored"
echo "Authorized uses only. All activity may be monitored and reported." > /etc/issue.net

echo "-----------------------------------------------------------------------"
echo "1.7.1.4 Ensure permissions on /etc/motd are configured  notscored"
echo "Authorized uses only. All activity may be monitored and reported." > /etc/issue.net


echo "-----------------------------------------------------------------------"
echo "1.7.1.5 Ensure permissions on /etc/issue are configured scored"
chown root:root /etc/issue
chmod 644 /etc/issue

echo "-----------------------------------------------------------------------"
echo "1.7.1.6 Ensure permissions on /etc/issue.net are configured notscored"
chown root:root /etc/issue.net
chmod 644 /etc/issue.net


echo "-----------------------------------------------------------------------"
echo "1.7.2 Ensure GDM login banner is configured scored"
echo "GDM is not installed and not applicable for server hosts or container"


echo "-----------------------------------------------------------------------"
echo "1.8 Ensure updates, patches, and additional security software are installed notscored"
apk update -f && apk upgrade -f


echo "------------------------------------------------------------------------"
echo "2.1.1 Ensure chargen services are not enabled scored"
echo "2.1.2 Ensure daytime services are not enabled scored"
echo "2.1.3 Ensure discard services are not enabled scored"
echo "2.1.4 Ensure echo services are not enabled scored"
echo "2.1.5 Ensure time services are not enabled scored"
echo "2.1.6 Ensure rsh server is not enabled scored"
echo "2.1.8 Ensure telnet server is not enabled scored"
echo "2.1.9 Ensure tftp server is not enabled scored"
echo "2.1.10 Ensure xinetd is not enabled  scored"
echo "Above services are not required for container and remove all related network services"
rm -f /etc/inetd.*



echo "-----------------------------------------------------------------------"
echo "2.2.1 Ensure time synchronization is in use notscored"
echo "Skipped. Not applicable for containers."


echo "-----------------------------------------------------------------------"
echo "2.2.1.2 Ensure ntp is configured scored"
echo "Skipped. Not applicable for containers."

echo "-----------------------------------------------------------------------"
echo "2.2.1.3 Ensure chrony is configured scored"
echo "Skipped. Not applicable for containers."


echo "-----------------------------------------------------------------------"
echo "2.2.2 Ensure X Window System is not installed scored"
echo "2.2.3 Ensure Avahi Server is not enabled scored"
echo "2.2.4 Ensure CUPS is not enabled scored"
echo "2.2.5 Ensure DHCP is not enabled scored"
echo "2.2.6 Ensure LDAP and RPC are not enabled scored"
echo "2.2.7 Ensure NFS and RPC are not enabled scored"
echo "2.2.8 Ensure DNS Server is not enabled scored"
echo "2.2.9 Ensure FTP Server is not enabled scored"
echo "2.2.10 Ensure HTTP server is not enabled scored"
echo "2.2.11 Ensure IMAP and POP3 server is not enabled scored"
echo "2.2.12 Ensure Samba is not enabled scored"
echo "2.2.13 Ensure HTTP Proxy Server is not enabled scored"
echo "2.2.14 Ensure SNMP Server is not enabled scored"
apk del -f xserver-xorg* avahi-daemon cups isc-dhcp-server slapd nfs-kernel-server rpcbind bind9 vsftpd apache2 squid samba dovecot snmpd

echo "-----------------------------------------------------------------------------"
echo "2.2.15 Ensure mail transfer agent is configured for local-only mode"
#sed -i 's/inet_interfaces = all/inet_interfaces = localhost/g' /etc/postfix/main.cf

echo "-----------------------------------------------------------------------"
echo "2.2.16 Ensure rsync service is not enabled scored"
apk del -f rsync

echo "-----------------------------------------------------------------------"
echo "2.2.17 Ensure NIS Server is not enabled scored"
apk del -f ypserv 

echo "-----------------------------------------------------------------------"
echo "2.3.1 Ensure NIS clients is not installed scored"
echo "2.3.2 Ensure rsh clients is not installed scored"
echo "2.3.3 Ensure talk clients is not installed scored"
echo "2.3.4 Ensure telnet clients is not installed scored"
echo "2.3.5 Ensure LDAP clients is not installed scored"
apk del -f ypserv ypbind rsh talk telnet openldap-clients





echo "-----------------------------------------------------------------------"
echo "3.1.1 Ensure IP forwarding is disabled scored"
echo "net.ipv4.ip_forward = 0" >> /etc/sysctl.conf
echo "net.ipv4.route.flush = 1" >> /etc/sysctl.conf

echo "-----------------------------------------------------------------------"
echo "3.1.2 Ensure packet redirect sending is disabled scored"
echo "net.ipv4.conf.all.send_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.send_redirects = 0" >> /etc/sysctl.conf

echo "-----------------------------------------------------------------------"
echo "3.2.1 Ensure source routed packets are not accepted Scored"
echo "net.ipv4.conf.all.accept_source_route = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.accept_source_route = 0" >> /etc/sysctl.conf

echo "-----------------------------------------------------------------------"
echo "3.2.2 Ensure ICMP redirects are not accepted scored"
echo "net.ipv4.conf.all.accept_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.accept_redirects = 0" >> /etc/sysctl.conf 

echo "-----------------------------------------------------------------------"
echo "3.2.3 Ensure secure ICMP redirects are not accepted scored"
echo "net.ipv4.conf.all.secure_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.secure_redirects = 0" >> /etc/sysctl.conf 

echo "-----------------------------------------------------------------------"
echo "3.2.4 Ensure suspicious packets are logged scored"
echo "net.ipv4.conf.all.log_martians = 1" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.log_martians = 1" >> /etc/sysctl.conf

echo "-----------------------------------------------------------------------"
echo "3.2.5 Ensure broadcast ICMP requests are ignored Scored"
echo "net.ipv4.icmp_echo_ignore_broadcasts = 1" >> /etc/sysctl.conf

echo "-----------------------------------------------------------------------"
echo "3.2.6 Ensure bogus ICMP responses are ignored scored"
echo "net.ipv4.icmp_ignore_bogus_error_responses = 1" >> /etc/sysctl.conf

echo "-----------------------------------------------------------------------"
echo "3.2.7 Ensure Reverse Path Filtering is enabled scored"
echo "net.ipv4.conf.all.rp_filter = 1" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.rp_filter = 1" >> /etc/sysctl.conf

echo "-----------------------------------------------------------------------"
echo "3.2.8 Ensure TCP SYN Cookies is enabled scored"
echo "net.ipv4.tcp_syncookies = 1" >> /etc/sysctl.conf

echo "-----------------------------------------------------------------------"
echo "3.3.1 Ensure IPv6 router advertisements are not accepted scored "
echo "net.ipv6.conf.all.accept_ra = 0" >> /etc/sysctl.conf
echo "net.ipv6.conf.default.accept_ra = 0" >> /etc/sysctl.conf

echo "-----------------------------------------------------------------------"
echo "3.3.2 Ensure IPv6 redirects are not accepted notscored"
echo "net.ipv6.conf.all.accept_ra = 0" >> /etc/sysctl.conf
echo "net.ipv6.conf.default.accept_ra = 0" >> /etc/sysctl.conf

echo "-----------------------------------------------------------------------"
echo "3.3.3 Ensure IPv6 is disabled notscored"
echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf
echo "net.ipv6.conf.default.disable_ipv6 = 1" >> /etc/sysctl.conf




echo "-----------------------------------------------------------------------"
echo "3.4.1 Ensure TCP Wrappers is installed - The feature has been deprecated"
#apt add install tcpd

echo "-----------------------------------------------------------------------"
echo "3.4.2 Ensure /etc/hosts.allow is configured - The feature has been deprecated"
echo "It is not applicable to container image"

echo "-----------------------------------------------------------------------"
echo "3.4.3 Ensure /etc/hosts.deny is configured - The feature has been deprecated"
echo "It is not applicable to container image"

echo "-----------------------------------------------------------------------"
echo "3.4.4 Ensure permissions on /etc/hosts.allow are configured scored"
echo "It is not applicable to container image"

echo "-----------------------------------------------------------------------"
echo "3.4.5 Ensure permissions on /etc/hosts.deny are configured scored"
echo "It is not applicable to container image"

echo "-----------------------------------------------------------------------"
echo "3.5.1 Ensure DCCP is disabled notscored"
echo "install dccp /bin/true" >> /etc/modprobe.d/CIS.conf


echo "-----------------------------------------------------------------------"
echo "3.5.2 Ensure SCTP is disabled notscored"
echo "install sctp /bin/true" >> /etc/modprobe.d/CIS.conf

echo "-----------------------------------------------------------------------"
echo "3.5.3 Ensure RDS is disabled notscored"
echo "install rds /bin/true" >> /etc/modprobe.d/CIS.conf



echo "-----------------------------------------------------------------------"
echo "3.6.1 Ensure iptables is installed scored-  It is managed by the orchestrator / kube-proxy for the access control"
echo "3.6.2 Ensure default deny firewall policy scored-  It is managed by the orchestrator / kube-proxy for the access control"
echo "3.6.3 Ensure loopback traffic is configured scored -  It is managed by the orchestrator / kube-proxy for the access control"
echo "3.6.4 Ensure outbound and established connections are configured notscored -  It is managed by the orchestrator / kube-proxy for the access control"
echo "3.6.5 Ensure firewall rules exist for all open ports scored-  It is managed by the orchestrator / kube-proxy for the access control"
echo "Skipped. Not applicable for containers."
echo "3.7 Ensure wireless interfaces are disabled notscored -  It is managed by the orchestrator / kube-proxy for the access control"
    if command -v nmcli >/dev/null 2>&1 ; then
        nmcli radio all off
    else
        if [ -n "$(find /sys/class/net/*/ -type d -name wireless)" ]; then
            mname=$(for driverdir in $(find /sys/class/net/*/ -type d -name
             wireless | xargs -0 dirname); do basename "$(readlink -f "$driverdir"/device/driver/module)";done | sort -u)
             for dm in $mname; do
                echo "install $dm /bin/true" >> /etc/modprobe.d/disable_wireless.conf
            done
        fi
    fi


echo "-----------------------------------------------------------------------"
echo "4.1.1.1 Ensure audit log storage size is configured notscored - Container is a child of the init system, thus system log is collected and managed in host level"
echo "4.1.1.2 Ensure system is disabled when audit logs are full scored - Container is a child of the init system, thus system log is collected and managed in host level"
echo "4.1.1.3 Ensure audit logs are not automatically deleted scored - Container is a child of the init system, thus system log is collected and managed in host level"
echo "4.1.2 Ensure auditd service is enabled scored - Container is a child of the init system, thus system log is collected and managed in host level"
echo "4.1.3 Ensure auditing for processes that start prior to auditd is enabled scored - Container is a child of the init system, thus system log is collected and managed in host level"
echo "4.1.4 Ensure events that modify date and time information are collected scored - Container is a child of the init system, thus system log is collected and managed in host level"
echo "4.1.5 Ensure events that modify user/group information are collected scored- Container is a child of the init system, thus system log is collected and managed in host level"
echo "4.1.6 Ensure events that modify the system's network environment are collected scored - Container is a child of the init system, thus system log is collected and managed in host level"
echo "4.1.7 Ensure events that modify the system's Mandatory Access Controls are collected scored- Container is a child of the init system, thus system log is collected and managed in host level"
echo "4.1.8 Ensure login and logout events are collected  scored- Container is a child of the init system, thus system log is collected and managed in host level"
echo "4.1.9 Ensure session initiation information is collected scored- Container is a child of the init system, thus system log is collected and managed in host level"
echo "4.1.10 Ensure discretionary access control permission modification events are collected scored- Container is a child of the init system, thus system log is collected and managed in host level"
echo "4.1.11 Ensure unsuccessful unauthorized file access attempts are collected scored- Container is a child of the init system, thus system log is collected and managed in host level"
echo "4.1.12 Ensure use of privileged commands is collected scored - Container is a child of the init system, thus system log is collected and managed in host level"
echo "4.1.13 Ensure successful file system mounts are collected scored - Container is a child of the init system, thus system log is collected and managed in host level"
echo "4.1.14 Ensure file deletion events by users are collected scored - Container is a child of the init system, thus system log is collected and managed in host level"
echo "4.1.15 Ensure changes to system administration scope (sudoers) is collected scored- Container is a child of the init system, thus system log is collected and managed in host level"
echo "4.1.16 Ensure system administrator actions (sudolog) are collected scored- Container is a child of the init system, thus system log is collected and managed in host level"
echo "4.1.17 Ensure kernel module loading and unloading is collected scored -  Container is a child of the init system, thus system log is collected and managed in host level"
echo "4.1.17 Ensure kernel module loading and unloading is collected scored -  Container is a child of the init system, thus system log is collected and managed in host level"
echo "4.1.18 Ensure the audit configuration is immutable scored -  Container is a child of the init system, thus system log is collected and managed in host level"
echo "Skipped. Not applicable for containers."





echo "-----------------------------------------------------------------------"
echo "4.2.1.1 Ensure rsyslog Service is enabled scored"
    apk add rsyslog -f
    apk add -f openrc --no-cache
    rc-update add rsyslog

# revised
echo "-----------------------------------------------------------------------"
echo "4.2.1.2 Ensure logging is configured notscored"
echo "4.2.1.3 Ensure rsyslog default file permissions configured scored"
echo "4.2.1.4 Ensure rsyslog is configured to send logs to a remote log host scored"
echo "4.2.1.5 Ensure remote rsyslog messages are only accepted on designated log hosts notscored"
mkdir /etc/rsyslog.d
echo "" >> /etc/rsyslog.d/50-default.conf
cat > /etc/rsyslog.d/50-default.conf << 'EOF'
*.emerg :omusrmsg:*
mail.* -/var/log/mail
mail.info -/var/log/mail.info
mail.warning -/var/log/mail.warn
mail.err /var/log/mail.err
news.crit -/var/log/news/news.crit
news.err -/var/log/news/news.err
news.notice -/var/log/news/news.notice
*.=warning;*.=err -/var/log/warn
*.crit /var/log/warn
*.*;mail.none;news.none -/var/log/messages
local0,local1.* -/var/log/localmessages
local2,local3.* -/var/log/localmessages
local4,local5.* -/var/log/localmessages
local6,local7.* -/var/log/localmessages
FileCreateMode 0640
#$ModLoad imtcp  # provides TCP syslog reception
#$TCPServerRun 10514 # start a TCP syslog server at port 10514
EOF
pkill -HUP rsyslogd
echo "FileCreateMode 0640" >> /etc/rsyslog.conf


echo "-----------------------------------------------------------------------"
echo "4.2.2.1 Ensure syslog-ng service is enabled scored"
echo "4.2.2.2 Ensure logging is configured notscored"
echo "4.2.2.3 Ensure syslog-ng default file permissions configured scored"
echo "4.2.2.4 Ensure syslog-ng is configured to send logs to a remote log host notscored"
echo "4.2.2.5 Ensure remote syslog-ng messages are only accepted on designated log hosts notscored"
echo "Skipped as rsyslog already configured"



echo "-----------------------------------------------------------------------"
echo "4.2.3 Ensure rsyslog or syslog-ng is installed scored"
apk add rsyslog -f

echo "-----------------------------------------------------------------------"
echo "4.2.4 Ensure permissions on all logfiles are configured scored"
chmod -R g-wx,o-rwx /var/log/*
# revised
echo "-----------------------------------------------------------------------"
echo "4.3 Ensure logrotate is configured notscored"
    if (cat /etc/logrotate.d/* | grep rotate); then
        echo "Rotation is configured"
    else
        printf"/var/log/apt/term.log {
        rotate 12
        monthly
        compress
        missingok
        notifempty
        }

        /var/log/apt/history.log {
        rotate 12
        monthly
        compress
        missingok
        notifempty
        }" >> /etc/logrotate.d/rsyslog
    fi



echo "-----------------------------------------------------------------------"
echo "5.1.1 Ensure cron daemon is enabled"
echo "By default, cron is enabled. No configuration is needed"

echo "-----------------------------------------------------------------------"
echo "5.1.2 Ensure permissions on /etc/crontab are configured"
chown root:root /etc/crontabs/root
chmod og-rwx /etc/crontabs/root

echo "-----------------------------------------------------------------------"
echo "5.1.3 Ensure permissions on /etc/cron.hourly are configured"
echo "Skipped as only /etc/crontabs/root is available"

echo "-----------------------------------------------------------------------"
echo "5.1.4 Ensure permissions on /etc/cron.daily are configured"
echo "Skipped as only /etc/crontabs/root is available"

echo "-----------------------------------------------------------------------"
echo "5.1.5 Ensure permissions on /etc/cron.weekly are configured"
echo "Skipped as only /etc/crontabs/root is available"

echo "-----------------------------------------------------------------------"
echo "5.1.6 Ensure permissions on /etc/cron.monthly are configured"
echo "Skipped as only /etc/crontabs/root is available"

echo "-----------------------------------------------------------------------"
echo "5.1.7 Ensure permissions on /etc/cron.d are configured"
echo "Alpine doesn't use /etc/cron.d by default"

echo "-----------------------------------------------------------------------"
echo "5.1.8 Ensure at/cron is restricted to authorized users"
touch /etc/cron.allow
touch /etc/at.allow
chmod og-rwx /etc/cron.allow
chmod og-rwx /etc/at.allow
chown root:root /etc/cron.allow
chown root:root /etc/at.allow


echo "-----------------------------------------------------------------------"
echo "5.2.1 Ensure permissions on /etc/ssh/sshd_config are configured scored"
echo "5.2.2 Ensure SSH Protocol is set to 2 scored"
echo "5.2.3 Ensure SSH LogLevel is set to INFO scored"
echo "5.2.4 Ensure SSH X11 forwarding is disabled scored"
echo "5.2.5 Ensure SSH MaxAuthTries is set to 4 or less scored"
echo "5.2.6 Ensure SSH IgnoreRhosts is enabled scored"
echo "5.2.7 Ensure SSH HostbasedAuthentication is disabled scored"
echo "5.2.8 Ensure SSH root login is disabled scored"
echo "5.2.9 Ensure SSH PermitEmptyPasswords is disabled scored"
echo "5.2.10 Ensure SSH PermitUserEnvironment is disabled scored"
echo "5.2.11 Ensure only approved MAC algorithms are used scored"
echo "5.2.12 Ensure SSH Idle Timeout Interval is configured scored"
echo "5.2.13 Ensure SSH LoginGraceTime is set to one minute or less scored"
echo "5.2.14 Ensure SSH access is limited scored"
echo "5.2.15 Ensure SSH warning banner is configured scored"
echo "Remove sshd daemon as sshd should not be required in container"
apk del -f openssh


echo "-----------------------------------------------------------------------"
echo "5.3.1 Ensure password creation requirements are configured scored"
apk add -f libpwquality
#cp /etc/pam.d/common-password /home/
cat > /etc/security/pwquality.conf << EOF
minlen = 14
dcredit = -1
ucredit = -1
ocredit = -1
lcredit = -1
EOF

echo "-----------------------------------------------------------------------"
echo "5.3.2 Ensure lockout for failed password attempts is configured scored"
echo "auth required pam_tally2.so onerr=fail audit silent deny=5 unlock_time=900" >>  /etc/pam.d/common-auth

echo "-----------------------------------------------------------------------"
echo "5.3.3 Ensure password reuse is limited scored"
echo "password required pam_pwhistory.so remember=5" >> /etc/pam.d/common-password

echo "-----------------------------------------------------------------------"
echo "5.3.4 Ensure password hashing algorithm is SHA-512 scored"
echo "password [success=1 default=ignore] pam_unix.so sha512" >> /etc/pam.d/common-password

echo "-----------------------------------------------------------------------"
echo "5.4.1.1 Ensure password expiration is 365 days or less scored"
echo "PASS_MAX_DAYS 365" >> /etc/login.defs

echo "-----------------------------------------------------------------------"
echo "5.4.1.2 Ensure minimum days between password changes is 7 or more scored"
echo "PASS_MIN_DAYS 7" >> /etc/login.defs


echo "-----------------------------------------------------------------------"
echo "5.4.1.3 Ensure password expiration warning days is 7 or more scored"
echo "PASS_WARN_AGE 7" >> /etc/login.defs

echo "-----------------------------------------------------------------------"
echo "5.4.1.4 Ensure inactive password lock is 30 days or less scored"
echo "Skipped. By default, all accounts in alpine are locked"
# revised
echo "-----------------------------------------------------------------------"
echo "5.4.1.5 Ensure all users last password change date is in the past scored"
apk add -f shadow
for usr in $(cut -d: -f1 /etc/shadow); do [[ $(chage --list $usr | grep '^Last password change' | cut -d: -f2) > $(date) ]] && echo "$usr :$(chage --list $usr | grep '^Last password change' | cut -d: -f2)" && echo "Please confirm if users is required to delete"; done 
apk del -f shadow


echo "-----------------------------------------------------------------------"
echo "5.4.2 Ensure system accounts are non-login scored"
echo "Skipped. By default, all accounts in alpine are locked and system accounts are not able to login"

echo "-----------------------------------------------------------------------"
echo "5.4.3 Ensure default group for the root account is GID 0 scored"
u=$(id root | grep "gid=0(root)")
if [ -z "$u" ]; then
    sed -i -E s/root:x:[0=9][a-zA-Z]/root:x:0:root/g /etc/group
fi

echo "-----------------------------------------------------------------------"
echo "5.4.4 Ensure default user umask is 027 or more restrictive scored"
echo "umask 027"  >> /etc/profile
echo "umask 027"  >> /etc/bashrc
echo "umask 027"  >> /etc/profile.d/*.sh

echo "-----------------------------------------------------------------------"
echo "5.4.5 Ensure default user shell timeout is 900 seconds or less scored"
echo 'TMOUT=600' >> /etc/profile

echo "-----------------------------------------------------------------------"
echo "5.5 Ensure root login is restricted to system console notscored"
echo "remove interactive login shell"
sed -i -r 's#^(.*):[^:]*$#\1:/sbin/nologin#' /etc/passwd


echo "-----------------------------------------------------------------------"
echo "5.6 Ensure access to the su command is restricted scored"
echo 'auth required pam_wheel.so use_uid' >> /etc/pam.d/su



echo "-----------------------------------------------------------------------"
echo "6.1.2 Ensure permissions on /etc/passwd are configured scored"
chown root:root /etc/passwd
chmod 644 /etc/passwd

echo "-----------------------------------------------------------------------"
echo "6.1.3 Ensure permissions on /etc/shadow are configured scored"
chown root:shadow /etc/shadow
chmod o-rwx,g-wx /etc/shadow 

echo "-----------------------------------------------------------------------"
echo "6.1.4 Ensure permissions on /etc/group are configured scored"
chown root:root /etc/group
chmod 644 /etc/group

echo "-----------------------------------------------------------------------"
echo "6.1.5 Ensure permissions on /etc/gshadow are configured"
chown root:shadow /etc/gshadow
chmod o-rwx,g-rw /etc/gshadow

echo "-----------------------------------------------------------------------"
echo "6.1.6 Ensure permissions on /etc/passwd- are configured"
chown root:root /etc/passwd-
chmod u-x,go-wx /etc/passwd-

echo "-----------------------------------------------------------------------"
echo "6.1.7 Ensure permissions on /etc/shadow- are configured scored"
chown root:root /etc/shadow-
chmod o-rwx,g-rw /etc/shadow-

echo "-----------------------------------------------------------------------"
echo "6.1.8 Ensure permissions on /etc/group- are configured scored"
chown root:root /etc/group-
chmod u-x,go-wx /etc/group-

echo "-----------------------------------------------------------------------"
echo "6.1.9 Ensure permissions on /etc/gshadow- are configured scored"
chown root:root /etc/gshadow-
chmod o-rwx,g-rw /etc/gshadow-

echo "-----------------------------------------------------------------------"
echo "6.1.10 Ensure no world writable files exist scored"

echo "Remove world-writeable permissions except for /tmp/"
find / -xdev -type d -perm +0002 -exec chmod o-w {} + \
  && find / -xdev -type f -perm +0002 -exec chmod o-w {} + \
  && chmod 777 /tmp




echo "-----------------------------------------------------------------------"
echo "6.1.11 Ensure no unowned files or directories exist scored"
file=$(find / -nouser> /dev/null 2>&1)
for f in file; do rm -f $f; done


echo "-----------------------------------------------------------------------"
echo "6.1.12 Ensure no ungrouped files or directories exist"
file=$(find / -nogroup> /dev/null 2>&1)
for f in file; do rm -f $f; done


echo "-----------------------------------------------------------------------"
echo "6.1.13 Audit SUID executables notscored"
file=$(find / -perm /4000> /dev/null 2>&1)
for f in file; do rm -f $f; done


echo "-----------------------------------------------------------------------"
echo "6.1.14 Audit SGID executables notscored"
file=$(find / -perm /2000> /dev/null 2>&1)
for f in file; do rm -f $f; done


echo "-----------------------------------------------------------------------"
echo "6.2.1 Ensure password fields are not empty scored"
grep '^\+:' /etc/passwd
echo "Disable passowrd login for additional security protection"
while IFS=: read -r username _; do passwd -l "$username"; done < /etc/passwd || true


echo "-----------------------------------------------------------------------"
echo "6.2.2 Ensure no legacy entries exist in /etc/passwd scored"
while read -r user; do
    deluser -f $user
done < <(grep '^\+:' /etc/passwd)


echo "-----------------------------------------------------------------------"
echo "6.2.3 Ensure no legacy "+" entries exist in /etc/shadow scored"
while read -r user; do
    deluser -f $user
done < <(grep '^\+:' /etc/shadow)


echo "-----------------------------------------------------------------------"
echo "6.2.4 Ensure no legacy "+" entries exist in /etc/group scored"

while read -r user; do
    deluser -f $user
done < <(grep '^\+:' /etc/group)


echo "-----------------------------------------------------------------------"
echo "6.2.5 Ensure root is the only UID 0 account scored"
for u in $(awk -F: '($3 == 0) { print $1 }' /etc/passwd); do 
if [ "$u" != "root" ]; then
        deluser $u
fi
done

# revised
echo "-----------------------------------------------------------------------"
echo "6.2.6 Ensure root PATH Integrity scored"
    if [ "`echo $PATH | grep :: `" != "" ]; then
    echo "Empty Directory in PATH (::)"
    fi
    if [ "`echo $PATH | grep :$`" != "" ]; then
    echo "Trailing : in PATH"
    fi
    p=`echo $PATH | sed -e 's/::/:/' -e 's/:$//' -e 's/:/ /g'`
    set -- $p
    while [ "$1" != "" ]; do
    if [ "$1" = "." ]; then
    echo "PATH contains ."
    shift
    continue
    fi
    if [ -d $1 ]; then
    dirperm=`ls -ldH $1 | cut -f1 -d" "`
    if [ `echo $dirperm | cut -c6 ` != "-" ]; then
    echo "Group Write permission set on directory $1"
        dirown=`ls -ldH $1 | awk '{print $3}'`
    if [ "$dirown" != "root" ] ; then
        echo $1 is not owned by root
        rm -rf $1
    fi
    fi
    if [ `echo $dirperm | cut -c9 ` != "-" ]; then
    echo "Other Write permission set on directory $1"
        dirown=`ls -ldH $1 | awk '{print $3}'`
    if [ "$dirown" != "root" ] ; then
        echo $1 is not owned by root
        rm -rf $1
    fi
    fi
    
    else
    echo $1 is not a directory
    fi
    shift
    done
   

# revised
echo "-----------------------------------------------------------------------"
echo "6.2.7 Ensure all users' home directories exist scored"
awk -F: '($1!~/(halt|sync|shutdown|nfsnobody)/ && $7!~/^(\/usr)?\/sbin\/nologin(\/)?$/ && $7!~/(\/usr)?\/bin\/false(\/)?$/) { print $1 " " $6 }' /etc/passwd | while read -r user dir; do
   if [ ! -d "$dir" ]; then
      mkdir "$dir" chmod g-w,o-wrx "$dir" chown "$user" "$dir"
   fi
done


# revised
echo "-----------------------------------------------------------------------"
echo "6.2.8 Ensure users' home directories permissions are 750 or more restrictive scored"
    awk -F: '($1!~/(halt|sync|shutdown|nfsnobody)/ && $7!~/^(\/usr)?\/sbin\/nologin(\/)?$/ && $7!~/(\/usr)?\/bin\/false(\/)?$/) {print $6}' /etc/passwd | while read -r dir; do 
    if [ -d "$dir" ]; then 
    dirperm=$(stat -L -c "%A" "$dir") 
        if [ "$(echo "$dirperm" | cut -c6)" != "-" ] || [ "$(echo "$dirperm" | cut -c8)" != "-" ] || [ "$(echo "$dirperm" | cut -c9)" != "-" ] || [ "$(echo "$dirperm" | cut -c10)" != "-" ]; then 
            chmod g-w,o-rwx "$dir"
        fi 
    fi 
    done



# revised
echo "-----------------------------------------------------------------------"
echo "6.2.9 Ensure users own their home directories scored"
awk -F: '($1!~/(halt|sync|shutdown|nfsnobody)/ && $7!~/^(\/usr)?\/sbin\/nologin(\/)?$/ && $7!~/(\/usr)?\/bin\/false(\/)?$/) { print $1 " " $6 }' /etc/passwd | while read -r user dir; do
if [ ! -d "$dir" ]; then
echo "User: \"$user\" home directory: \"$dir\" does not exist, creating home directory" 
mkdir "$dir"
chmod g-w,o-rwx "$dir"
chown "$user" "$dir" else
owner=$(stat -L -c "%U" "$dir")
if [ "$owner" != "$user" ]; then
chmod g-w,o-rwx "$dir"
chown "$user" "$dir"
fi
fi
done

# revised
echo "-----------------------------------------------------------------------"
echo "6.2.10 Ensure users' dot files are not group or world writable scored"
    awk -F: '($1!~/(halt|sync|shutdown|nfsnobody)/ && $7!~/^(\/usr)?\/sbin\/nologin(\/)?$/ && $7!~/(\/usr)?\/bin\/false(\/)?$/) { print $6 }' /etc/passwd | while read -r dir; do
    if [ -d "$dir" ]; then
            for file in "$dir"/.*; do \
                    if [ ! -h "$file" ] && [ -f "$file" ]; then
                            fileperm=$(stat -L -c "%A" "$file")
                                    if [ "$(echo "$fileperm" | cut -c6)" != "-" ] || [ "$(echo "$fileperm" | cut -c9)" != "-" ]; then
                                            chmod go-w "$file"
                                    fi
                    fi
            done
    fi
    done

# revised
echo "-----------------------------------------------------------------------"
echo "6.2.11 Ensure no users have .forward files scored"
    awk -F: '($1!~/(halt|sync|shutdown)/ && $7!~/^(\/usr)?\/sbin\/nologin(\/)?$/ && $7!~/(\/usr)?\/bin\/false(\/)?$/) { print $6 }' /etc/passwd | while read -r dir; do
    if [ -d "$dir" ]; then
            file="$dir/.forward"
            [ ! -h "$file" ] && [ -f "$file" ] && rm -f "$file"
                fi
    done

# revised
echo "-----------------------------------------------------------------------"
echo "6.2.12 Ensure no users have .netrc files scored"
echo "6.2.13 Ensure users' .netrc Files are not group or world accessible scored"
    awk -F: '($1!~/(halt|sync|shutdown)/ && $7!~/^(\/usr)?\/sbin\/nologin(\/)?$/ && $7!~/(\/usr)?\/bin\/false(\/)?$/) { print $6 }' /etc/passwd | while read -r dir; do
    if [ -d "$dir" ]; then
            file="$dir/.netrc"
            [ ! -h "$file" ] && [ -f "$file" ] && rm -f "$file"
                fi
    done



# revised
echo "-----------------------------------------------------------------------"
echo "6.2.14 Ensure no users have .rhosts files scored"
    awk -F: '($1!~/(halt|sync|shutdown)/ && $7!~/^(\/usr)?\/sbin\/nologin(\/)?$/ && $7!~/(\/usr)?\/bin\/false(\/)?$/) { print $6 }' /etc/passwd | while read -r dir; do
    if [ -d "$dir" ]; then
            file="$dir/.rhosts"
            [ ! -h "$file" ] && [ -f "$file" ] && rm -f "$file"
                fi
    done




# revised
echo "-----------------------------------------------------------------------"
echo "6.2.15 Ensure all groups in /etc/passwd exist in /etc/group  scored"
echo
for i in $(cut -s -d: -f4 /etc/passwd | sort -u ); do grep -q "^.*?:[^:]*:$i:" /etc/group 
if [ $? -ne 0 ]; then  
   echo "Group $i is referenced by /etc/passwd but does not exist in /etc/group"
   delgroup -f $i
fi
done
# revised
echo "-----------------------------------------------------------------------"
echo "6.2.16 Ensure no duplicate UIDs exist scored"
echo
cat /etc/passwd | cut -f3 -d":" | sort -n | uniq -c | while read x ; do
[ -z "${x}" ] && break
set - $x
if [ $1 -gt 1 ]; then
 users=`awk -F: '($3 == n) { print $1 }' n=$2 /etc/passwd | xargs`
 echo "Duplicate UID ($2): ${users}"
  echo "Duplicate UID can be only deleted manually "
exit 1
fi
done

# revised
echo "-----------------------------------------------------------------------"
echo "6.2.17 Ensure no duplicate GIDs exist scored"
echo
cat /etc/group | cut -f3 -d":" | sort -n | uniq -c | while read x ; do
[ -z "${x}" ] && break
set - $x
if [ $1 -gt 1 ]; then
 groups=`awk -F: '($3 == n) { print $1 }' n=$2 /etc/group | xargs`
 echo "Duplicate GID ($2): ${groups}"
echo "Duplicate GID can be only deleted manually "
exit 1
fi
done

# revised
echo "-----------------------------------------------------------------------"
echo "6.2.18 Ensure no duplicate user names exist scored"
echo
cat /etc/passwd | cut -f1 -d":" | sort -n | uniq -c | while read x ; do
[ -z "${x}" ] && break
set - $x
if [ $1 -gt 1 ]; then
 uids=`awk -F: '($1 == n) { print $3 }' n=$2 /etc/passwd | xargs`
 echo "Duplicate User Name ($2): ${uids}"
 echo "Duplicate user can be only deleted manually "
exit 1
fi
done

# revised
echo "-----------------------------------------------------------------------"
echo "6.2.19 Ensure no duplicate group names exist scored"
echo
cat /etc/group | cut -f1 -d":" | sort -n | uniq -c | while read x ; do
[ -z "${x}" ] && break
set - $x
if [ $1 -gt 1 ]; then
 gids=`gawk -F: '($1 == n) { print $3 }' n=$2 /etc/group | xargs`
 echo "Duplicate Group Name ($2): ${gids}"
echo "Duplicate group name can be only deleted manually"
exit 1
fi
done

# revised
echo "-----------------------------------------------------------------------"
echo "6.2.20 Ensure shadow group is empty scored"
while read -r line; do
    delgroup $line
done < <(grep ^shadow:[^:]*:[^:]*:[^:]+ /etc/group)


echo "-----------------------------------------------------------------------"
echo "CIS Section completed"
echo "-----------------------------------------------------------------------"
# revised
echo "-----------------------------------------------------------------------"
echo "Clean up by removing unneccessary and dangerous commands"
find /bin /etc /lib /sbin /usr -xdev \( \
  -iname hexdump -o \
  -iname chgrp -o \
  -iname ln -o \
  -iname od -o \
  -iname strings -o \
  -iname su -o \
  -iname sudo \
  \) -exec rm -rf {}  \;

echo "Clean up by removing root home dir"
rm -fr /root

echo "Clean up unnecessary packages"
apk del -f openrc
apk del -f findutlis
apk del -f coreutils

echo "-----------------------------------------------------------------------"
echo "Hardening Completed"
echo "-----------------------------------------------------------------------"


fi




if cat /etc/os-release | grep "CentOS Linux 7"; then

    echo "----------------------- CentOS Hardening Begins -----------------------"
    echo "-----------------------------------------------------------------------"
    echo "Install required packages....."
    yum install -y kmod 
    yum install -y findutils iptables rsyslog dconf crontabs procps
    echo "Installation done"

    

    echo "1.1.1.1 Ensure mounting of cramfs filesystems is disabled (Automated)"
    modprobe -n -v cramfs | grep -E '(cramfs|install)'
	lsmod | grep cramfs
	echo "install cramfs /bin/true" >> /etc/modprobe.d/cramfs.conf
	rmmod cramfs

    echo "-----------------------------------------------------------------------"
	echo "1.1.1.2 Ensure mounting of squashfs filesystems is disabled (Automated)"
    modprobe -n -v squashfs | grep -E '(squashfs|install)'
	lsmod | grep squashfs
    echo "install squashfs /bin/true" >> /etc/modprobe.d/squashfs.conf
    rmmod squashfs

    echo "-----------------------------------------------------------------------"
	echo "1.1.1.3 Ensure mounting of udf filesystems is disabled (Automated)"
	modprobe -n -v udf | grep -E '(udf|install)'
	lsmod | grep udf
	echo "install udf /bin/true" >> /etc/modprobe.d/udf.conf
	rmmod udf

    echo "-----------------------------------------------------------------------"
	echo "1.1.1.4 Ensure mounting of FAT filesystems is limited (Manual)"
	grep -E -i '\svfat\s' /etc/fstab
	modprobe -n -v fat | grep -E '(fat|install)'
	lsmod | grep fat
	modprobe -n -v vfat | grep -E '(vfat|install)'
	lsmod | grep vfat
	modprobe -n -v msdos | grep -E '(msdos|install)'
	lsmod | grep msdos
	cat >> /etc/modprobe.d/fat.conf << EOL
install fat /bin/true
install vfat /bin/true
install msdos /bin/true
EOL
	rmmod msdos
	rmmod vfat
	rmmod fat

    echo "-----------------------------------------------------------------------"
    echo "1.1.2 Ensure /tmp is configured (Automated)"
    mount | grep -E '\s/tmp\s'

# revised
    echo "-----------------------------------------------------------------------"
    echo "1.1.3 Ensure noexec option set on /tmp partition (Automated)"
	echo "1.1.4 Ensure nodev option set on /tmp partition (Automated)"
    echo "1.1.5 Ensure nosuid option set on /tmp partition (Automated)"
	echo "Not applicable for container, instead, ensure no malicious file system mount"
	rm -f /etc/fstab
	
    echo "-----------------------------------------------------------------------"
    echo "1.1.6 Ensure /dev/shm is configured (Automated)"
    mount | grep -E '\s/dev/shm\s'


    echo "-----------------------------------------------------------------------"
    echo "1.1.7 Ensure noexec option set on /dev/shm partition (Automated)"
    echo "1.1.8 Ensure nodev option set on /dev/shm partition (Automated)"
    echo "1.1.9 Ensure nosuid option set on /dev/shm partition (Automated)"
	echo "Not applicable for container, instead, ensure no malicious file system mount"
	rm -f /etc/fstab

    echo "-----------------------------------------------------------------------"
    echo "1.1.10 Ensure separate partition exists for /var (Automated)"
    mount | grep -E '\s/var\s'

    echo "-----------------------------------------------------------------------"
    echo "1.1.11 Ensure separate partition exists for /var/tmp (Automated)"
     mount | grep /var/tmp

    echo "-----------------------------------------------------------------------"
    echo "1.1.12  Ensure /var/tmp partition includes the noexec option (Automated)"
    echo "1.1.13 Ensure /var/tmp partition includes the nodev option  (Automated)"
    echo "1.1.14 Ensure /var/tmp partition includes the nosuid option (Automated)"
	echo "Not applicable for container, instead, ensure no malicious file system mount"
	rm -f /etc/fstab


    echo "-----------------------------------------------------------------------"
    echo "1.1.15 Ensure separate partition exists for /var/log (Automated)"
    mount | grep -E '\s/var/log\s'

    echo "-----------------------------------------------------------------------"
    echo "1.1.16 Ensure separate partition exists for /var/log/audit (Automated)"
    mount | grep /var/log/audit

    echo "-----------------------------------------------------------------------"
    echo "1.1.17 Ensure separate partition exists for /home (Automated)"
    mount | grep /home

    echo "-----------------------------------------------------------------------"
    echo "1.1.18 Ensure /home partition includes the nodev opstion (Automated)"
	echo "Not applicable for container, instead, ensure no malicious file system mount"
	rm -f /etc/fstab

    echo "-----------------------------------------------------------------------"
    echo "1.1.19 Ensure removable media partitions include noexec option (Automated)" 
    echo "1.1.20 Ensure nodev option set on removable media partitions (Manual)"
    echo "1.1.21 Ensure nosuid option set on removable media partitions (Manual)"
	echo "Not applicable for container, instead, ensure no malicious file system mount"
	rm -f /etc/fstab


    echo "-----------------------------------------------------------------------"
    echo "1.1.22 Ensure sticky bit is set on all world-writable directories (Automated)"
    df --local -P 2> /dev/null | awk '{if (NR!=1) print $6}' | xargs -I '{}' 
	find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null
	df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null | xargs -I '{}' chmod a+t '{}'

    echo "-----------------------------------------------------------------------"
    echo "1.1.23 Disable Automounting (Automated)"
	yum remove -y autofs

    echo "-----------------------------------------------------------------------"
    echo "1.1.24 Disable USB Storage (Automated)"
	modprobe -n -v usb-storage
	modprobe -n -v usb-storage
	echo "install usb-storage /bin/true" >> /etc/modprobe.d/usb_storage.conf
	rmmod usb-storage

    echo "-----------------------------------------------------------------------"
    echo "1.2.1 Ensure GPG keys are configured (Manual)"
    #rpm --import /etc/pki/rpm-gpg/RPM-GPG-KEY-centosofficial
    #rpm -q gpg-pubkey --qf '%{name}-%{version}-%{release} --> %{summary}\n'
    echo "Skipped. This is configured in host level"

    echo "-----------------------------------------------------------------------"
    echo "1.2.2 Ensure package manager repositories are configured (Manual)"
    echo "By default, the repo is configured to repo name Base, Extras and Updates. No extra confiugration is required. "

    echo "-----------------------------------------------------------------------"
	echo "1.2.3 Ensure gpgcheck is globally activated (Automated)"
    u=$(awk -v 'RS=[' -F '\n' '/\n\s*enabled\s*=\s*1(\W.*)?$/ && ! /\n\s*gpgcheck\s*=\s*1(\W.*)?$/ { t=substr($1, 1, index($1, "]")-1); print t, "does not have gpgcheck enabled." }' /etc/yum.repos.d/*.repo)
    if [ -z "$u"]; then
        echo "gpgcheck is enabled"
    else
        sed -i 's/^gpgcheck\s*=\s*.*/gpgcheck=1/' /etc/yum.conf
        sed -i 's/^gpgcheck\s*=\s*.*/gpgcheck=1/' /etc/yum.repos.d/*.repo
    fi    

    echo "-----------------------------------------------------------------------"	
    echo "1.3.1 Ensure AIDE is installed (Automated)"
	echo "Skipped. Not applicable for containers."
    
    echo "-----------------------------------------------------------------------"	
    echo "1.3.2 Ensure filesystem integrity is regularly checked (Automated)"
	#revised
	#grep -Ers '^([^#]+\s+)?(\/usr\/s?bin\/|^\s*)aide(\.wrapper)?\s(--?\S+\s)*(--(check|update)|\$AIDEARGS)\b' /etc/cron.* /etc/crontab /var/spool/cron/
	echo "Skipped. Not applicable for containers."

    echo "-----------------------------------------------------------------------"	
    echo "1.4.1 Ensure bootloader password is set (Automated)" 
    echo "Skipped. Not applicable for containers."
   
    echo "-----------------------------------------------------------------------"	
    echo "1.4.2 Ensure permissions on bootloader config are configured (Automated)"
	echo "Skipped. Not applicable for containers"

    echo "-----------------------------------------------------------------------"	
    echo "1.4.3 Ensure authentication required for single user mode (Automated)"
    echo "Skipped. Not applicable for containers."
 
    echo "-----------------------------------------------------------------------"	
    echo "1.5.1 Ensure core dumps are restricted (Automated)"
	#grep -E "^\s*\*\s+hard\s+core" /etc/security/limits.conf
	sysctl fs.suid_dumpable
	#grep "fs\.suid_dumpable" /etc/sysctl.conf /etc/sysctl.d/*
	#systemctl is-enabled coredump.service
    echo "* hard core 0" >> /etc/security/limits.conf
    echo "fs.suid_dumpable = 0" >> /etc/sysctl.conf
	sysctl -w fs.suid_dumpable=0

    echo "-----------------------------------------------------------------------"	
    echo "1.5.2 Ensure XD/NX support is enabled (Automated)"
    echo "Skipped. Not applicable for containers."

    echo "-----------------------------------------------------------------------"	
    echo "1.5.3 Ensure address space layout randomization (ASLR) is enabled (Automated)"
    sysctl kernel.randomize_va_space
	grep "kernel\.randomize_va_space" /etc/sysctl.conf /etc/sysctl.d/*
	echo "kernel.randomize_va_space = 2" >> /etc/sysctl.conf
	sysctl -w kernel.randomize_va_space=2

    echo "-----------------------------------------------------------------------"
    echo "1.5.4 Ensure prelink is disabled (Automated)"
	rpm -q prelink
	prelink -ua
    yum remove -y prelink

    echo "-----------------------------------------------------------------------"	
    echo "1.6.1.1 Ensure SELinux is installed (Automated)"
	rpm -q libselinux
    yum install -y libselinux

    echo "-----------------------------------------------------------------------"	
    echo "1.6.1.2 Ensure SELinux is not disabled in bootloader configuration (Automated)"
    echo "Skipped. Not applicable for containers."

    echo "-----------------------------------------------------------------------"	
    echo "1.6.1.3 Ensure SELinux policy is configured (Automated)"
	echo "Skipped. Not applicable for containers."


    echo "-----------------------------------------------------------------------"	
    echo "1.6.1.4 Ensure the SELinux mode is enforcing or permissive (Automated)"
	echo "Skipped. Not applicable for containers."


    echo "-----------------------------------------------------------------------"	
    echo "1.6.1.5 Ensure the SELinux mode is enforcing (Automated)"
	echo "Skipped. Not applicable for containers."

    echo "-----------------------------------------------------------------------"		
    echo "1.6.1.6 Ensure no unconfined services exist (Automated)"
    u=$(ps -eZ | grep unconfined_service_t)
    if [ -z "$u"]; then
        echo "no unconfined services are found"
    else
        echo "Stoping the unconfined services"
        while read -r line
        do 
            kill $line
        done < <( ps -eZ | grep unconfined_service_t | awk 'FNR == 1 {print $5}' )
    fi



    echo "-----------------------------------------------------------------------"	
    echo "1.6.1.7 Ensure SETroubleshoot is not installed (Automated)"
	rpm -q setroubleshoot
    yum remove -y setroubleshoot

    echo "-----------------------------------------------------------------------"	
    echo "1.6.1.8 Ensure the MCS Translation Service (mcstrans) is not installed (Automated)"
	rpm -q mcstrans
    yum remove -y mcstrans

    echo "-----------------------------------------------------------------------"	
    echo "1.7.1 Ensure message of the day is configured properly (Automated)"
    echo "All access to this system is monitored.  Any person who uses or accesses this system expressly consents to such monitoring and recording.  We may furnish information obtained by its monitoring and recording activity to law enforcement officials if such monitoring and recording reveals possible evidence of unlawful activity." > /etc/motd

    echo "-----------------------------------------------------------------------"	
    echo "1.7.2 Ensure local login warning banner is configured properly (Automated)"
	cat /etc/issue
	grep -E -i "(\\\v|\\\r|\\\m|\\\s|$(grep '^ID=' /etc/os-release | cut -d= -f2 | sed -e 's/"//g'))" /etc/issue
    echo "Authorized uses only. All activity may be monitored and reported." > /etc/issue

    echo "-----------------------------------------------------------------------"	
    echo "1.7.3 Ensure remote login warning banner is configured properly (Automated)"
	cat /etc/issue.net
	grep -E -i "(\\\v|\\\r|\\\m|\\\s|$(grep '^ID=' /etc/os-release | cut -d= -f2 | sed -e 's/"//g'))" /etc/issue.net
    echo "Authorized uses only. All activity may be monitored and reported." > /etc/issue.net

    echo "-----------------------------------------------------------------------"	
    echo "1.7.4 Ensure permissions on /etc/motd are configured (Automated)"
	stat /etc/motd
    chown root:root /etc/motd
    chmod u-x,go-wx /etc/motd

    echo "-----------------------------------------------------------------------"	
    echo "1.7.5 Ensure permissions on /etc/issue are configured (Automated)"
	stat /etc/issue
    chown root:root /etc/issue
    chmod u-x,go-wx /etc/issue

    echo "-----------------------------------------------------------------------"	
    echo "1.7.6 Ensure permissions on /etc/issue.net are configured (Automated)"
	stat /etc/issue.net
    chown root:root /etc/issue.net
    chmod u-x,go-wx /etc/issue.net

    echo "-----------------------------------------------------------------------"	
    echo "1.8.1 Ensure GDM is removed or login is configured (Automated)"
	# revised
    yum remove -y gdm

    echo "-----------------------------------------------------------------------"	
    echo "1.8.2 Ensure GDM is removed or login is configured (Automated)"
	# revised 
    echo "no GNOME Display Manager is installed"


    echo "-----------------------------------------------------------------------"	
    echo "1.8.3 Ensure last logged in user display is disabled (Automated)"
	# revised 
    echo "no GNOME Display Manager is installed"


    echo "-----------------------------------------------------------------------"	
    echo "1.8.4  Ensure XDCMP is not enabled (Automated)"
	# revised 
    echo "no GNOME Display Manager is installed"



    echo "-----------------------------------------------------------------------"	
    echo "1.9 Ensure updates, patches, and additional security software are installed (Manual)"
	yum check-update -y
    yum update -y 


    echo "-----------------------------------------------------------------------"	
    echo "2.1.1 Ensure xinetd is not installed (Automated)"
	rpm -q xinetd
    yum remove -y xinetd

    echo "-----------------------------------------------------------------------"	
    echo "2.2.1.1 Ensure time synchronization is in use (Manual)"
	echo "Not applicable for container and remove unnecessary package."
	yum remove -y chrony
	yum remove -y ntp

    echo "-----------------------------------------------------------------------"	
	echo "2.2.1.2 Ensure chrony is configured (Automated)"
	echo "Skipped. Not applicable for containers."


    echo "-----------------------------------------------------------------------"
	echo "2.2.1.3 Ensure ntp is configured (Automated)"
	echo "Skipped. Not applicable for containers."

	
	echo "-----------------------------------------------------------------------"
    echo "2.2.2 Ensure X11 Server components are not installed (Automated)"
	rpm -qa xorg-x11-server*
    yum remove -y xorg-x11-server*

    echo "-----------------------------------------------------------------------"
    echo "2.2.3 Ensure Avahi Server is not installed (Automated)"
	rpm -q avahi-autoipd avahi
	systemctl stop avahi-daemon.socket avahi-daemon.service
    yum remove -y avahi-autoipd avahi

    echo "-----------------------------------------------------------------------"
    echo "2.2.4 Ensure CUPS is not installed (Automated)"
	rpm -q cups
    yum remove -y cups


    echo "-----------------------------------------------------------------------"
    echo "2.2.5 Ensure DHCP Server is not installed (Automated)"
	rpm -q dhcp
    yum remove -y dhcp

    echo "-----------------------------------------------------------------------"
    echo "2.2.6 Ensure LDAP server is not installed (Automated)"
	rpm -q openldap-servers
    yum remove -y openldap-servers


    echo "-----------------------------------------------------------------------"
    echo "2.2.7 Ensure DNS Server is not installed (Automated)"
	rpm -q bind
    yum remove -y bind	

    echo "-----------------------------------------------------------------------"
    echo "2.2.8 Ensure FTP Server is not installed (Automated)"
	rpm -q vsftpd
    yum remove -y vsftpd


    echo "-----------------------------------------------------------------------"	
    echo "2.2.9 Ensure HTTP server is not installed (Automated)"
	rpm -q httpd
    yum remove -y httpd


    echo "-----------------------------------------------------------------------"
    echo "2.2.10 Ensure IMAP and POP3 server is not installed (Automated)"
	rpm -q dovecot
    yum remove -y dovecot




    echo "-----------------------------------------------------------------------"
    echo "2.2.11 Ensure Samba is not installed (Automated)"
	rpm -q samba
    yum remove -y samba



    echo "-----------------------------------------------------------------------"
    echo "2.2.12 Ensure HTTP Proxy Server is not installed (Automated)"
	rpm -q squid
    yum remove -y squid

    echo "-----------------------------------------------------------------------"
	echo "2.2.13 Ensure net-snmp is not installed (Automated)"
	rpm -q net-snmp
	yum remove -y net-snmp

    echo "-----------------------------------------------------------------------"
    echo "2.2.14 Ensure NIS server is not installed (Automated)"
	rpm -q ypserv
    yum remove -y ypserv

	
    echo "-----------------------------------------------------------------------"
    echo "2.2.15 Ensure telnet-server is not installed (Automated)"
	rpm -q telnet-server
    yum remove -y telnet-server

	# revised
	echo "-----------------------------------------------------------------------"
    echo "2.2.16 Ensure mail transfer agent is configured for local-only mode (Automated)"
	echo "Skipped. Not applicable for containers."


    echo "-----------------------------------------------------------------------"
    echo "2.2.17 Ensure nfs-utils is not installed or the nfs-server service is masked (Automated)"
	rpm -q nfs-utils
    yum remove -y nfs-utils

    echo "-----------------------------------------------------------------------"
	echo "2.2.18 Ensure rpcbind is not installed or the rpcbind services are masked (Automated)"
	rpm -q rpcbind
	yum remove -y rpcbind




    echo "-----------------------------------------------------------------------"
    echo "2.2.19 Ensure rsync is not installed or the rsyncd service is masked (Automated)"
	rpm -q rsync
    yum remove -y rsync




    echo "-----------------------------------------------------------------------"
    echo "2.3.1 Ensure NIS Client is not installed (Automated)"
	rpm -q ypbind
    yum remove -y ypbind

    echo "-----------------------------------------------------------------------"
	echo "2.3.2 Ensure rsh client is not installed (Automated)"
	rpm -q rsh
	yum remove -y rsh

    echo "-----------------------------------------------------------------------"	
	echo "2.3.3 Ensure talk client is not installed (Automated)"
	rpm -q talk
	yum remove -y talk
	
    echo "-----------------------------------------------------------------------"	
    echo "2.3.4 Ensure telnet client is not installed (Automated)"
	rpm -q telnet
    yum remove -y telnet

    echo "-----------------------------------------------------------------------"	
	echo "2.3.5 Ensure LDAP client is not installed (Automated)"
	rpm -q openldap-clients
	yum remove -y openldap-clients
	
	echo "-----------------------------------------------------------------------"	
	echo "2.4 Ensure nonessential services are removed or masked (Manual)"
    yum install -y lsof
    r=$(lsof -i -P -n | grep -v "(ESTABLISHED)")
    if [ -z "$r" ]; then
            echo "No established services are found"

    else
        echo "Established service is found and is going to stop them.." 
        yum install -y net-tools 
        netstat Drop 
        yum remove -y net-tools        
    fi
    yum remove -y lsof
	
	echo "-----------------------------------------------------------------------"	
	echo "3.1.1 Disable IPv6 (Manual)"
	echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf
	echo "net.ipv6.conf.default.disable_ipv6 = 1" >> /etc/sysctl.conf
	sysctl -w net.ipv6.conf.all.disable_ipv6=1
	 sysctl -w net.ipv6.conf.default.disable_ipv6=1
	sysctl -w net.ipv6.route.flush=1



	echo "-----------------------------------------------------------------------"	
	echo "3.1.2 Ensure wireless interfaces are disabled (Manual)"
    if command -v nmcli >/dev/null 2>&1 ; then
        nmcli radio all off
    else
        if [ -n "$(find /sys/class/net/*/ -type d -name wireless)" ]; then
            mname=$(for driverdir in $(find /sys/class/net/*/ -type d -name wireless | xargs -0 dirname); do basename "$(readlink -f "$driverdir"/device/driver/module)";done | sort -u)
             for dm in $mname; do
                echo "install $dm /bin/true" >> /etc/modprobe.d/disable_wireless.conf
            done
        fi
    fi

	echo "-----------------------------------------------------------------------"	
	echo "3.2.1 Ensure IP forwarding is disabled (Automated)"
	sysctl net.ipv4.ip_forward
	grep -E -s "^\s*net\.ipv4\.ip_forward\s*=\s*1" /etc/sysctl.conf /etc/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /run/sysctl.d/*.conf
	grep -Els "^\s*net\.ipv4\.ip_forward\s*=\s*1" /etc/sysctl.conf /etc/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /run/sysctl.d/*.conf | while read filename; do sed -ri "s/^\s*(net\.ipv4\.ip_forward\s*)(=)(\s*\S+\b).*$/# *REMOVED* \1/" $filename; done; sysctl -w net.ipv4.ip_forward=0; sysctl -w net.ipv4.route.flush=1
	grep -Els "^\s*net\.ipv6\.conf\.all\.forwarding\s*=\s*1" /etc/sysctl.conf /etc/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /run/sysctl.d/*.conf | while read filename; do sed -ri "s/^\s*(net\.ipv6\.conf\.all\.forwarding\s*)(=)(\s*\S+\b).*$/# *REMOVED* \1/" $filename; done; sysctl -w net.ipv6.conf.all.forwarding=0; sysctl -w net.ipv6.route.flush=1
	
	echo "-----------------------------------------------------------------------"	
	echo "3.2.2 Ensure packet redirect sending is disabled (Automated)"
	sysctl net.ipv4.conf.all.send_redirects
	sysctl net.ipv4.conf.default.send_redirects
	grep "net\.ipv4\.conf\.all\.send_redirects" /etc/sysctl.conf /etc/sysctl.d/*
	cat >> /etc/sysctl.conf << EOL
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
EOL
	sysctl -w net.ipv4.conf.all.send_redirects=0
	sysctl -w net.ipv4.conf.default.send_redirects=0
	sysctl -w net.ipv4.route.flush=1
		
	echo "-----------------------------------------------------------------------"		
	echo "3.3.1 Ensure source routed packets are not accepted (Automated)"
	sysctl net.ipv4.conf.all.accept_source_route
	sysctl net.ipv4.conf.default.accept_source_route
	#grep "net\.ipv4\.conf\.all\.accept_source_route" /etc/sysctl.conf /etc/sysctl.d/*
	cat >> /etc/sysctl.conf << EOL
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
EOL
	sysctl -w net.ipv4.conf.all.accept_source_route=0
	sysctl -w net.ipv4.conf.default.accept_source_route=0
	sysctl -w net.ipv4.route.flush=1
	
	echo "-----------------------------------------------------------------------"		
	echo "3.3.2 Ensure ICMP redirects are not accepted (Automated)"
	echo "net.ipv4.conf.all.accept_redirects = 0" >> /etc/sysctl.conf
	echo "net.ipv4.conf.default.accept_redirects = 0" >> /etc/sysctl.conf 
		
	echo "-----------------------------------------------------------------------"		
	echo "3.3.3 Ensure secure ICMP redirects are not accepted (Automated)"
	echo "net.ipv4.conf.all.secure_redirects = 0" >> /etc/sysctl.conf
	echo "net.ipv4.conf.default.secure_redirects = 0" >> /etc/sysctl.conf 

	
	echo "-----------------------------------------------------------------------"		
	echo "3.3.4 Ensure suspicious packets are logged (Automated)"
	echo "net.ipv4.conf.all.secure_redirects = 0" >> /etc/sysctl.conf
	echo "net.ipv4.conf.default.secure_redirects = 0" >> /etc/sysctl.conf 

	echo "-----------------------------------------------------------------------"		
	echo "3.3.5 Ensure broadcast ICMP requests are ignored (Automated)"
	echo "net.ipv4.icmp_echo_ignore_broadcasts = 1" >> /etc/sysctl.conf
	
	echo "-----------------------------------------------------------------------"		
	echo "3.3.6 Ensure bogus ICMP responses are ignored (Automated)"
	echo "net.ipv4.icmp_ignore_bogus_error_responses = 1" >> /etc/sysctl.conf
	
	echo "-----------------------------------------------------------------------"	
	echo "3.3.7 Ensure Reverse Path Filtering is enabled (Automated)"
	echo "net.ipv4.conf.all.rp_filter = 1" >> /etc/sysctl.conf
	echo "net.ipv4.conf.default.rp_filter = 1" >> /etc/sysctl.conf

	
	echo "-----------------------------------------------------------------------"	
	echo "3.3.8 Ensure TCP SYN Cookies is enabled (Automated)"
	echo "net.ipv4.tcp_syncookies = 1" >> /etc/sysctl.conf
	
	echo "-----------------------------------------------------------------------"	
	echo "3.3.9 Ensure IPv6 router advertisements are not accepted (Automated)"
	echo "net.ipv6.conf.all.accept_ra = 0" >> /etc/sysctl.conf
	echo "net.ipv6.conf.default.accept_ra = 0" >> /etc/sysctl.conf

	
	echo "-----------------------------------------------------------------------"
    echo "3.4.1 Ensure DCCP is disabled (Automated)"
	modprobe -n -v dccp
	lsmod | grep dccp
    echo "install dccp /bin/true" >> /etc/modprobe.d/CIS.conf

    echo "-----------------------------------------------------------------------"
    echo "3.4.2 Ensure SCTP is disabled (Automated)"
	modprobe -n -v sctp
	lsmod | grep sctp
    echo "install sctp /bin/true" >> /etc/modprobe.d/CIS.conf

    echo "-----------------------------------------------------------------------"
    echo "3.5.1.1 Ensure FirewallD is installed (Automated)"
	rpm -q firewalld
	echo "Not applicable and remove uncessary packages"
    yum remove -y firewalld 

    echo "-----------------------------------------------------------------------"
	echo "3.5.1.2 Ensure iptables-services package is not installed (Automated)"
	rpm -q firewalld iptables
	yum remove -y iptables-services
	
	echo "-----------------------------------------------------------------------"
	echo "3.5.1.3 Ensure nftables is not installed or stopped and masked (Automated)"
	rpm -q nftables
	yum remove -y nftables
	
	echo "-----------------------------------------------------------------------"
	echo "3.5.1.4 Ensure firewalld service is enabled and running (Automated"
	echo "Skipped. Not applicable for containers."
	
	echo "-----------------------------------------------------------------------"
	echo "3.5.1.5 Ensure default zone is set (Automated)"
	echo "Skipped. Not applicable for containers."
	
	
	echo "-----------------------------------------------------------------------"
	echo "3.5.1.6 Ensure network interfaces are assigned to appropriate zone (Manual)"
	echo "Skipped. Not applicable for containers."
	
	
	echo "-----------------------------------------------------------------------"
	echo "3.5.1.7 Ensure unnecessary services and ports are not accepted (Manual)"
	echo "Skipped. Not applicable for containers."
	
	echo "-----------------------------------------------------------------------"
	echo "3.5.2.1 Ensure nftables is installed (Automated)"
	rpm -q nftables
	echo "Not applicable for container and remove unnecessary pacakge"
	yum remove -y nftables
	
	echo "-----------------------------------------------------------------------"
	echo "3.5.2.2 Ensure firewalld is not installed or stopped and masked (Automated)"
	rpm -q firewalld
	yum remove -y firewalld
	
	echo "-----------------------------------------------------------------------"
	echo "3.5.2.3 Ensure iptables-services package is not installed (Automated)"
	rpm -q firewalld
	yum remove -y iptables-services

# revised
	echo "-----------------------------------------------------------------------"
	echo "3.5.2.4 Ensure iptables are flushed (Manual)"
	echo "3.5.2.5 Ensure a table exists (Automated)"
	echo "3.5.2.6 Ensure base chains exist (Automated)"
	echo "3.5.2.7 Ensure loopback traffic is configured (Automated)"
	echo "3.5.2.8 Ensure outbound and established connections are configured (Manual)"
	echo "3.5.2.9 Ensure default deny firewall policy (Automated)"
	echo "3.5.2.10 Ensure nftables service is enabled (Automated)"
	echo "3.5.2.11 Ensure nftables rules are permanent (Automated)"
	echo "Skipped. Not applicable for containers."
	


	
	echo "-----------------------------------------------------------------------"
	echo "3.5.3.1.1 Ensure iptables packages are installed (Automated)"
    yum install -y iptables
	
	echo "-----------------------------------------------------------------------"
	echo "3.5.3.1.2 Ensure nftables is not installed (Automated)"
	rpm -q nftables
	yum remove -y nftables
	
	echo "-----------------------------------------------------------------------"
	echo "3.5.3.1.3 Ensure firewalld is not installed or stopped and masked (Automated)"
	rpm -q firewalld
	yum remove -y firewalld


	
	echo "-----------------------------------------------------------------------"
	echo "3.5.3.2.1 Ensure loopback traffic is configured (Automated)"
	echo "3.5.3.2.2 Ensure iptables outbound and established connections are configured (Manual)"
	echo "3.5.3.2.3 Ensure iptables rules exist for all open ports (Manual)"
	echo "3.5.3.2.4 Ensure iptables default deny firewall policy (Automated)"
	echo "3.5.3.2.5 Ensure iptables rules are saved (Automated)"
	echo "3.5.3.2.6 Ensure iptables is enabled and running (Automated)"
	echo "3.5.3.3.1 Ensure IPv6 loopback traffic is configured (Automated)"
	echo "3.5.3.3.2 Ensure IPv6 outbound and established connections are configured (Manual)"
	echo "3.5.3.3.3 Ensure IPv6 firewall rules exist for all open ports (Manual)"
	echo "3.5.3.3.4 Ensure IPv6 default deny firewall policy (Automated)"
	echo "3.5.3.3.5 Ensure ip6tables rules are saved (Automated)"
	echo "3.5.3.3.6 Ensure ip6tables is enabled and running (Automated)"
	echo "Skipped. Not applicable for containers."

	echo "-----------------------------------------------------------------------"
    echo "4.1.1.1 Ensure auditd is installed (Automated)"
	echo "4.1.1.2 Ensure auditd service is enabled and running (Automated)"
	echo "4.1.1.3 Ensure auditing for processes that start prior to auditd is enabled (Automated)"
	echo "4.1.2.1 Ensure audit log storage size is configured (Automated)"
	echo "4.1.2.2 Ensure audit logs are not automatically deleted (Automated)"	
    echo "4.1.2.3 Ensure system is disabled when audit logs are full (Automated)"
	echo "4.1.2.4 Ensure audit_backlog_limit is sufficient (Automated)"
	echo "4.1.3 Ensure events that modify date and time information are collected (Automated)"
	echo "4.1.4 Ensure events that modify user/group information are collected (Automated)"
	echo "4.1.5 Ensure events that modify the system's network environment are collected (Automated)"
	echo "4.1.6 Ensure events that modify the system's Mandatory Access Controls are collected (Automated)"
	echo "4.1.7 Ensure login and logout events are collected (Automated)"
	echo "4.1.8 Ensure session initiation information is collected (Automated)"
	echo "4.1.9 Ensure discretionary access control permission modification events are collected (Automated)"
	echo "4.1.10 Ensure unsuccessful unauthorized file access attempts are collected (Automated)"
	echo "4.1.11 Ensure use of privileged commands is collected (Automated)"
	echo "4.1.12 Ensure successful file system mounts are collected (Automated)"
	echo "4.1.13 Ensure file deletion events by users are collected (Automated)"
	echo "4.1.14 Ensure changes to system administration scope (sudoers) is collected (Automated)"
	echo "4.1.15 Ensure system administrator actions (sudolog) are collected (Automated)"
	echo "4.1.16 Ensure kernel module loading and unloading is collected (Automated)"
	echo "4.1.17 Ensure the audit configuration is immutable (Automated)"
	echo "Skipped. Not applicable for containers."
	
	echo "-----------------------------------------------------------------------"
	echo "4.2.1.1 Ensure rsyslog is installed (Automated)"
	yum install -y rsyslog
	
	echo "-----------------------------------------------------------------------"
	echo "4.2.1.2 Ensure rsyslog Service is enabled and running (Automated)"
    if systemctl is-enabled rsyslog | grep disabled; then
        systemctl --now enable rsyslog
    fi


	echo "-----------------------------------------------------------------------"
	echo "4.2.1.3 Ensure rsyslog default file permissions configured (Automated)"
    echo "FileCreateMode 0640" >>  /etc/rsyslog.conf 
	
	echo "-----------------------------------------------------------------------"
	echo "4.2.1.4 Ensure logging is configured (Manual)"
    printf "*.emerg                         :omusrmsg:*
    auth,authpriv.*                 /var/log/secure
    cron.*                          /var/log/cron
    " >> /etc/rsyslog.conf


	echo "-----------------------------------------------------------------------"
	echo "4.2.1.5 Ensure rsyslog is configured to send logs to a remote log host (Automated)"
	echo "Skipped. Not applicable for containers."
	
	echo "-----------------------------------------------------------------------"
	echo "4.2.1.6 Ensure remote rsyslog messages are only accepted on designated log hosts. (Manual)"
    printf "module(load="imtcp")
    input(type="imtcp" port="514")
    " >> /etc/rsyslog.conf
    

	echo "-----------------------------------------------------------------------"
	echo "4.2.2.1 Ensure journald is configured to send logs to rsyslog (Automated)"
	cat >> /etc/systemd/journald.conf << EOL
/etc/systemd/journald.conf
EOL
	
	echo "-----------------------------------------------------------------------"
	echo "4.2.2.2 Ensure journald is configured to compress large log files (Automated)"
	cat >> /etc/systemd/journald.conf << EOL
Compress=yes
EOL

	echo "-----------------------------------------------------------------------"
	echo "4.2.2.3 Ensure journald is configured to write logfiles to persistent disk (Automated)"
	cat >> /etc/systemd/journald.conf << EOL
Storage=persistent
EOL

	echo "-----------------------------------------------------------------------"
	echo "4.2.3 Ensure permissions on all logfiles are configured (Automated)"
	find /var/log -type f -exec chmod g-wx,o-rwx "{}" + -o -type d -exec chmod g-wx,o-rwx "{}" +

	echo "-----------------------------------------------------------------------"
	echo "4.2.4 Ensure logrotate is configured (Manual)"
    if (cat /etc/logrotate.d/* | grep rotate); then
        echo "Rotation is configured"
    else
        printf"/var/log/apt/term.log {
        rotate 12
        monthly
        compress
        missingok
        notifempty
        }

        /var/log/apt/history.log {
        rotate 12
        monthly
        compress
        missingok
        notifempty
        }" >> /etc/logrotate.d/rsyslog
    fi

	
	echo "-----------------------------------------------------------------------"
	echo "5.1.1 Ensure cron daemon is enabled and running (Automated)"
	echo "Skipped. By default, the cron daemon is enabled"
	
	echo "-----------------------------------------------------------------------"
	echo "5.1.2 Ensure permissions on /etc/crontab are configured (Automated)"
	chown root:root /etc/crontab
	chown root:root /etc/crontab
	
	echo "-----------------------------------------------------------------------"
	echo "5.1.3 Ensure permissions on /etc/cron.hourly are configured (Automated)"
	chown root:root /etc/cron.hourly/
	chmod og-rwx /etc/cron.hourly/

	echo "-----------------------------------------------------------------------"
	echo "5.1.4 Ensure permissions on /etc/cron.daily are configured (Automated)"
	chown root:root /etc/cron.daily
	chmod og-rwx /etc/cron.daily
	
	echo "-----------------------------------------------------------------------"
	echo "5.1.5 Ensure permissions on /etc/cron.weekly are configured (Automated)"
	chown root:root /etc/cron.weekly/
	chmod og-rwx /etc/cron.weekly/

	echo "-----------------------------------------------------------------------"
	echo "5.1.6 Ensure permissions on /etc/cron.monthly are configured (Automated)"
	chown root:root /etc/cron.monthly
	chmod og-rwx /etc/cron.monthly
	
	echo "-----------------------------------------------------------------------"
	echo "5.1.7 Ensure permissions on /etc/cron.d are configured (Automated)"
	chown root:root /etc/cron.d
	chmod og-rwx /etc/cron.d
	
	echo "-----------------------------------------------------------------------"
	echo "5.1.8 Ensure cron is restricted to authorized users (Automated)"
	rm /etc/cron.deny
	touch /etc/cron.allow
	chown root:root /etc/cron.allow
	chmod u-x,og-rwx /etc/cron.allow
	
	echo "-----------------------------------------------------------------------"
	echo "5.1.9 Ensure at is restricted to authorized users (Automated)"
	rm /etc/at.deny
	touch /etc/at.allow
	chown root:root /etc/at.allow
	chmod u-x,og-rwx /etc/at.allow

    echo "-----------------------------------------------------------------------"	
    echo "5.2.1 Ensure sudo is installed (Automated)"
	rpm -q sudo
    yum install -y sudo
	


    echo "-----------------------------------------------------------------------"
    echo "5.2.2 Ensure sudo commands use pty (Automated)"
	grep -Ei '^\s*Defaults\s+([^#]\S+,\s*)?use_pty\b' /etc/sudoers /etc/sudoers.d/*
    echo "Defaults use_pty" >> /etc/sudoers

    echo "-----------------------------------------------------------------------"
    echo "5.2.3 Ensure sudo log file exists (Automated)"
    echo "Defaults logfile=\"/var/log/sudo.log\"" >> /etc/sudoers

	echo "-----------------------------------------------------------------------"
	echo "5.3.1 Ensure permissions on /etc/ssh/sshd_config are configured (Automated)"
	echo "5.3.2 Ensure permissions on SSH private host key files are configured (Automated)"
	echo "5.3.3 Ensure permissions on SSH public host key files are configured (Automated)"
	echo "5.3.4 Ensure SSH access is limited (Automated)"
	echo "5.3.5 Ensure SSH LogLevel is appropriate (Automated)"
	echo "5.3.6 Ensure SSH X11 forwarding is disabled (Automated)"
	echo "5.3.7 Ensure SSH MaxAuthTries is set to 4 or less (Automated)"
	echo "5.3.8 Ensure SSH MaxAuthTries is set to 4 or less (Automated)"	
	echo "5.3.9 Ensure SSH HostbasedAuthentication is disabled (Automated)"
	echo "5.3.10 Ensure SSH root login is disabled (Automated)"
	echo "5.3.12 Ensure SSH PermitUserEnvironment is disabled (Automated)"
	echo "5.3.13 Ensure only strong Ciphers are used (Automated)"
	echo "5.3.14 Ensure only strong MAC algorithms are used (Automated)"
	echo "5.3.15 Ensure only strong Key Exchange algorithms are used (Automated)"
	echo "5.3.16 Ensure SSH Idle Timeout Interval is configured (Automated)"
	echo "5.3.17 Ensure SSH LoginGraceTime is set to one minute or less (Automated)"
	echo "5.3.18 Ensure SSH warning banner is configured (Automated)"
	echo "5.3.19 Ensure SSH PAM is enabled (Automated)"
	echo "SSH daemon is not recommended and remove unecessary package"
	echo "5.3.20 Ensure SSH AllowTcpForwarding is disabled (Automated)"
	echo "5.3.21 Ensure SSH MaxStartups is configured (Automated)"
	echo "5.3.22 Ensure SSH MaxSessions is limited (Automated)"
	yum remove -y openssh



	echo "-----------------------------------------------------------------------"
	echo "5.4.1 Ensure password creation requirements are configured (Automated)"
	grep '^\s*minlen\s*' /etc/security/pwquality.conf
	grep '^\s*minclass\s*' /etc/security/pwquality.conf
	cat >> /etc/security/pwquality.conf << EOL
minlen = 14
minclass = 4
EOL
	
	echo "-----------------------------------------------------------------------"
	echo "5.4.2 Ensure lockout for failed password attempts is configured (Automated)"
    sed -i 's/password    requisite     pam_pwquality.so try_first_pass local_users_only retry=3 authtok_type=/password    requisite     pam_pwquality.so try_first_pass local_users_only retry=3 unlock_time=900 authtok_type=/g' /etc/pam.d/system-auth
    sed -i 's/password    requisite     pam_pwquality.so try_first_pass local_users_only retry=3 authtok_type=/password    requisite     pam_pwquality.so try_first_pass local_users_only unlock_time=900 retry=3 authtok_type=/g' /etc/pam.d/password-auth    

	echo "-----------------------------------------------------------------------"
	echo "5.4.3 Ensure password hashing algorithm is SHA-512 (Automated)"
    if (! grep -Ei '\s*sha512\b' /etc/pam.d/password-auth | grep sha512); then
        sed '13 i password sufficient pam_unix.so sha512' /etc/pam.d/password-auth       
    fi
    if (! grep -Ei '\s*sha512\b' /etc/pam.d/system-auth | grep sha512); then
        sed '13 i password sufficient pam_unix.so sha512' /etc/pam.d/password-auth       
    fi

	echo "-----------------------------------------------------------------------"
	echo "5.4.4 Ensure password reuse is limited (Automated)"
	grep -E '^\s*auth\s+\S+\s+pam_(tally2|unix)\.so' /etc/pam.d/system-auth
	grep -P '^\s*password\s+(sufficient|requisite|required)\s+pam_unix\.so\s+([^#]+\s+)*remember=([5-9]|[1-9][0-9]+)\b' /etc/pam.d/system-auth
    sed -i 's/password    required      pam_deny.so/password    required      pam_deny.so remember=5/g' /etc/pam.d/system-auth
    sed -i 's/password    required      pam_deny.so/password    required      pam_deny.so remember=5/g' /etc/pam.d/password-auth   
	
	echo "-----------------------------------------------------------------------"
    echo "5.5.1.1 Ensure password expiration is 365 days or less (Automated)"
	grep ^\s*PASS_MAX_DAYS /etc/login.defs
    echo "PASS_MAX_DAYS 90" >> /etc/login.defs

    echo "-----------------------------------------------------------------------"
	echo "5.5.1.2 Ensure minimum days between password changes is configured (Automated)"
	grep ^\s*PASS_MIN_DAYS /etc/login.defs
	echo "PASS_MIN_DAYS 1" >> /etc/login.defs 

	echo "-----------------------------------------------------------------------"
	echo "5.5.1.3 Ensure password expiration warning days is 7 or more (Automated)"
	grep ^\s*PASS_WARN_AGE /etc/login.defs
	echo "PASS_WARN_AGE 7" >> /etc/login.defs
	
	echo "-----------------------------------------------------------------------"
	echo "5.5.1.4 Ensure inactive password lock is 30 days or less (Automated)"
	useradd -D | grep INACTIVE
	useradd -D -f 30
	
	echo "-----------------------------------------------------------------------"
	echo "5.5.1.5 Ensure all users last password change date is in the past (Automated)"
    for usr in $(cut -d: -f1 /etc/shadow); do [[ $(chage --list $usr | grep '^Last password change' | cut -d: -f2) > $(date) ]] && echo "$usr :$(chage --list $usr | grep '^Last password change' | cut -d: -f2)" && echo "Please confirm if users is required to delete"; done       
	
	echo "-----------------------------------------------------------------------"
	echo "5.5.2 Ensure system accounts are secured (Automated)"
	awk -F: '($1!="root" && $1!="sync" && $1!="shutdown" && $1!="halt" && $1!~/^\+/ && $3<'"$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)"' && $7!="'"$(which nologin)"'" && $7!="/bin/false") {print}' /etc/passwd
	awk -F: '($1!="root" && $1!~/^\+/ && $3<'"$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)"') {print $1}' /etc/passwd | xargs -I '{}' passwd -S '{}' | awk '($2!="L" && $2!="LK") {print $1}'
	
	echo "-----------------------------------------------------------------------"
	echo "5.5.3 Ensure default group for the root account is GID 0 (Automated)"
    if (!  grep "^root:" /etc/passwd | cut -f4 -d: | grep 0); then
        usermod -g 0 root
    fi

	
	echo "-----------------------------------------------------------------------"
	echo "5.5.4 Ensure default user shell timeout is configured (Automated)"
	for f in /etc/bashrc /etc/profile /etc/profile.d/*.sh ; do grep -Eq '(^|^[^#]*;)\s*(readonly|export(\s+[^$#;]+\s*)*)?\s*TMOUT=(900|[1-8][0-9][0-9]|[1-9][0-9]|[1-9])\b' $f && grep -Eq '(^|^[^#]*;)\s*readonly\s+TMOUT\b' $f && grep -Eq '(^|^[^#]*;)\s*export\s+([^$#;]+\s+)*TMOUT\b' $f && echo "TMOUT correctly configured in file: $f"; done
	grep -P '^\s*([^$#;]+\s+)*TMOUT=(9[0-9][1-9]|0+|[1-9]\d{3,})\b\s*(\S+\s*)*(\s+#.*)?$' /etc/profile /etc/profile.d/*.sh /etc/bashrc
    echo "readonly TMOUT=900 ; export TMOUT" >> /etc/profile
	
	echo "-----------------------------------------------------------------------"
	echo "5.5.5 Ensure default user umask is configured (Automated)"
	grep -Ev '^\s*umask\s+\s*(0[0-7][2-7]7|[0-7][2-7]7|u=(r?|w?|x?)(r?|w?|x?)(r?|w?|x?),g=(r?x?|x?r?),o=)\s*(\s*#.*)?$' /etc/profile /etc/profile.d/*.sh /etc/bashrc | grep -E '(^|^[^#]*)umask'
	grep -E '^\s*umask\s+\s*(0[0-7][2-7]7|[0-7][2-7]7|u=(r?|w?|x?)(r?|w?|x?)(r?|w?|x?),g=(r?x?|x?r?),o=)\s*(\s*#.*)?$' /etc/profile /etc/profile.d/*.sh /etc/bashrc
    echo "umask 027" >> /etc/profile

	echo "-----------------------------------------------------------------------"
	echo "5.6 Ensure root login is restricted to system console (Manual)"
	echo "remove interactive login shell"
	sed -i -r 's#^(.*):[^:]*$#\1:/sbin/nologin#' /etc/passwd

	
	echo "-----------------------------------------------------------------------"
	echo "5.7 Ensure access to the su command is restricted (Automated)"
	grep -E '^\s*auth\s+required\s+pam_wheel\.so\s+(\S+\s+)*use_uid\s+(\S+\s+)*group=\S+\s*(\S+\s*)*(\s+#.*)?$' /etc/pam.d/su
	groupadd sugroup
	echo "auth required pam_wheel.so use_uid group=sugroup" >> /etc/pam.d/su
	
	echo "-----------------------------------------------------------------------"
	echo "6.1.1 Audit system file permissions (Manual)"
    u=$(rpm -V $(rpm -qf /bin/bash))
    if [ -z "$u" ]; then
        echo "Package is installed and configured correctly"
    else
        echo "By default, all default packages should be configured correctly. Please verify and remediate based on the result."
        exit 1
    fi	
	
	echo "-----------------------------------------------------------------------"
	echo "6.1.2 Ensure permissions on /etc/passwd are configured (Automated)"
	stat /etc/passwd
	chown root:root /etc/passwd
	chmod u-x,g-wx,o-wx /etc/passwd

	echo "-----------------------------------------------------------------------"
	echo "6.1.3 Ensure permissions on /etc/passwd- are configured (Automated)"
	stat /etc/passwd-
	chown root:root /etc/passwd-
	chmod u-x,go-wx /etc/passwd-
	
	
	echo "-----------------------------------------------------------------------"
	echo "6.1.4 Ensure permissions on /etc/shadow are configured (Automated)"
	stat /etc/shadow
	chown root:root /etc/shadow
	chmod 0000 /etc/shadow

	echo "-----------------------------------------------------------------------"
	echo "6.1.5 Ensure permissions on /etc/shadow- are configured (Automated)"
	stat /etc/shadow-
	chown root:root /etc/shadow-
	chmod 0000 /etc/shadow-

	echo "-----------------------------------------------------------------------"
	echo "6.1.6 Ensure permissions on /etc/gshadow- are configured (Automated)"
	stat /etc/gshadow-
	chown root:root /etc/gshadow-
    chmod 0000 /etc/gshadow-


	echo "-----------------------------------------------------------------------"
	echo "6.1.7 Ensure permissions on /etc/gshadow are configured (Automated)"
	chown root:root /etc/gshadow
	chmod 0000 /etc/gshadow
	


	echo "-----------------------------------------------------------------------"
	echo "6.1.8 Ensure permissions on /etc/group are configured (Automated)"
	stat /etc/group
	chown root:root /etc/group
	chmod u-x,g-wx,o-wx /etc/group
	



	
	echo "-----------------------------------------------------------------------"
	echo "6.1.9 Ensure permissions on /etc/group- are configured (Automated)"
	stat /etc/group-
	chown root:root /etc/group-
    chmod u-x,go-wx /etc/group-
	

	
	echo "-----------------------------------------------------------------------"
	echo "6.1.10 Ensure no world writable files exist (Automated)"
	df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type f -perm -0002
	echo "Remove world-writeable permissions except for /tmp/"
	find / -xdev -type d -perm +0002 -exec chmod o-w {} + \
		&& find / -xdev -type f -perm +0002 -exec chmod o-w {} + \
		&& chmod 777 /tmp


	echo "-----------------------------------------------------------------------"
	echo "6.1.11 Ensure no unowned files or directories exist (Automated)"
    file=$( df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nouser)
    for f in file; do rm -f $f; done

	echo "-----------------------------------------------------------------------"
	echo "6.1.12 Ensure no ungrouped files or directories exist (Automated)"
    file=$( df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -nogroup )
    for f in file; do rm -f $f; done

	echo "-----------------------------------------------------------------------"
	echo "6.1.13 Audit SUID executables (Manual)"
    suid=$(df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type f -perm -4000)
    check="sudo"
    result=$(echo $suid | rev | cut -f1 -d'/' | rev)
    if [ "$result"=="$check" ]; then
    echo "No extra SUID found"
    else
    echo "Unexpected SUID executables found. Please review."
    df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type f -perm -4000  
    exit 1
    fi

	
	echo "-----------------------------------------------------------------------"
	echo "6.1.14 Audit SGID executables (Manual)"
    sgid=$(df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type f -perm -2000)
    check="write"
    result=$(echo $sgid | rev | cut -f1 -d'/' | rev)
    if [ "$result"=="$check" ]; then
    echo "No extra SGID found"
    else
    echo "Unexpected SGID executables found. Please review."
    df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type f -perm -2000
    exit 1
    fi

	
	echo "-----------------------------------------------------------------------"
	echo "6.2.1 Ensure accounts in /etc/passwd use shadowed passwords (Automated)"
	awk -F: '($2 != "x" ) { print $1 " is not set to shadowed passwords "}' /etc/passwd
	sed -e 's/^\([a-zA-Z0-9_]*\):[^:]*:/\1:x:/' -i /etc/passwd
	echo "Disable passowrd login for additional security protection"
	while IFS=: read -r username _; do passwd -l "$username"; done < /etc/passwd || true

	echo "-----------------------------------------------------------------------"
	echo "6.2.2 Ensure /etc/shadow password fields are not empty (Automated)"
	u=$(awk -F: '($2 == "" ) { print $1 " does not have a password "}' /etc/shadow)
	if [ -z "$u" ]; then
	 echo "no users are found"
	else
		while read -r line
		do 
			deluser -f $line
		done < <(awk -F: '($2 == "" ) { print $1 " does not have a password "}' /etc/shadow)
	fi

	echo "-----------------------------------------------------------------------"
	echo "6.2.3 Ensure all groups in /etc/passwd exist in /etc/group (Automated)"
    for i in $(cut -s -d: -f4 /etc/passwd | sort -u ); do grep -q -P "^.*?:[^:]*:$i:" /etc/group 
    if [ $? -ne 0 ]; then  
    echo "Group $i is referenced by /etc/passwd but does not exist in /etc/group"
    groupdel -f $i
    fi
    done
    

	echo "-----------------------------------------------------------------------"
	echo "6.2.4 Ensure shadow group is empty (Automated)"
    grep ^shadow:[^:]*:[^:]*:[^:]+ /etc/group
    u=$(awk -F: '($4 == "") { print }' /etc/passwd)
    if [ -z "$u"]; then
        echo "shadow group is empty"
    else
        for user in $u; do userdel -f $user; done 
    fi


	echo "-----------------------------------------------------------------------"
	echo "6.2.5 Ensure no duplicate user names exist (Automated)"
	cut -d: -f1 /etc/passwd | sort | uniq -d | while read x 
	do echo "Duplicate login name ${x} in /etc/passwd"
        echo "Duplicate username can be only deleted manually "
       exit 1
	done


	echo "-----------------------------------------------------------------------"
	echo "6.2.6 Ensure no duplicate group names exist (Automated)"
	cut -d: -f1 /etc/group | sort | uniq -d | while read x
	do echo "Duplicate group name ${x} in /etc/group"
         echo "Duplicate group can be only deleted manually "
         exit 1
	done
	




	echo "-----------------------------------------------------------------------"
	echo "6.2.7 Ensure no duplicate UIDs exist (Automated)"
	cut -f3 -d":" /etc/passwd | sort -n | uniq -c | while read x ; do
		[ -z "$x" ] && break
		set - $x
		if [ $1 -gt 1 ]; then
			users=$(awk -F: '($3 == n) { print $1 }' n=$2 /etc/passwd | xargs)
			echo "Duplicate UID ($2): $users"
            echo "Duplicate UID can be only deleted manually "
            exit 1
		fi
	done


	echo "-----------------------------------------------------------------------"
	echo "6.2.8 Ensure no duplicate GIDs exist (Automated)"
	cut -d: -f3 /etc/group | sort | uniq -d | while read x ; do
		echo "Duplicate GID ($x) in /etc/group"
        echo "Duplicate GID can be only deleted manually "
        exit 1
	done



	echo "-----------------------------------------------------------------------"
	echo "6.2.9 Ensure root is the only UID 0 account (Automated)"
    r=$(cat /etc/passwd | awk -F: '($3 == 0) { print $1 }' | wc -l )
    if [ $r -gt 1 ]; then
                u=$(cat /etc/passwd | awk -F: '($3 == 0) { print $1 }')
                    for user in $u; do
                                if ("$user" !="root"); then
                                    userdel -rf $user
                                fi
                    done
    fi




	echo "-----------------------------------------------------------------------"
	echo "6.2.10 Ensure root PATH Integrity (Automated)"
    if [ "`echo $PATH | grep :: `" != "" ]; then
    echo "Empty Directory in PATH (::)"
    fi
    if [ "`echo $PATH | grep :$`" != "" ]; then
    echo "Trailing : in PATH"
    fi
    p=`echo $PATH | sed -e 's/::/:/' -e 's/:$//' -e 's/:/ /g'`
    set -- $p
    while [ "$1" != "" ]; do
    if [ "$1" = "." ]; then
    echo "PATH contains ."
    shift
    continue
    fi
    if [ -d $1 ]; then
    dirperm=`ls -ldH $1 | cut -f1 -d" "`
    if [ `echo $dirperm | cut -c6 ` != "-" ]; then
    echo "Group Write permission set on directory $1"
        dirown=`ls -ldH $1 | awk '{print $3}'`
    if [ "$dirown" != "root" ] ; then
        echo $1 is not owned by root
        rm -rf $1
    fi
    fi
    if [ `echo $dirperm | cut -c9 ` != "-" ]; then
    echo "Other Write permission set on directory $1"
        dirown=`ls -ldH $1 | awk '{print $3}'`
    if [ "$dirown" != "root" ] ; then
        echo $1 is not owned by root
        rm -rf $1
    fi
    fi
    
    else
    echo $1 is not a directory
    fi
    shift
    done



	echo "-----------------------------------------------------------------------"
	echo "6.2.11 Ensure all users' home directories exist (Automated)"
	grep -E -v '^(halt|sync|shutdown)' /etc/passwd | awk -F: '($7 != "'"$(which nologin)"'" && $7 != "/bin/false") { print $1 " " $6 }' | while read -r user dir; do
		if [ ! -d "$dir" ]; then
			echo "The home directory ($dir) of user $user does not exist."
			mkdir "$dir" chmod g-w,o-wrx "$dir" chown "$user" "$dir"
		fi
	done


	echo "-----------------------------------------------------------------------"
	echo "6.2.12 Ensure users own their home directories (Automated)"
    awk -F: '($1!~/(halt|sync|shutdown|nfsnobody)/ && $7!~/^(\/usr)?\/sbin\/nologin(\/)?$/ && $7!~/(\/usr)?\/bin\/false(\/)?$/) { print $1 " " $6 }' /etc/passwd | while read -r user dir; do
    if [ ! -d "$dir" ]; then
    echo "User: \"$user\" home directory: \"$dir\" does not exist, creating home directory" 
    mkdir "$dir"
    chmod g-w,o-rwx "$dir"
    chown "$user" "$dir" else
    owner=$(stat -L -c "%U" "$dir")
    if [ "$owner" != "$user" ]; then
    chmod g-w,o-rwx "$dir"
    chown "$user" "$dir"
    fi
    fi
    done






	echo "-----------------------------------------------------------------------"
	echo "6.2.13 Ensure users' home directories permissions are 750 or more restrictive (Automated)"
    awk -F: '($1!~/(halt|sync|shutdown|nfsnobody)/ && $7!~/^(\/usr)?\/sbin\/nologin(\/)?$/ && $7!~/(\/usr)?\/bin\/false(\/)?$/) {print $6}' /etc/passwd | while read -r dir; do 
    if [ -d "$dir" ]; then 
    dirperm=$(stat -L -c "%A" "$dir") 
        if [ "$(echo "$dirperm" | cut -c6)" != "-" ] || [ "$(echo "$dirperm" | cut -c8)" != "-" ] || [ "$(echo "$dirperm" | cut -c9)" != "-" ] || [ "$(echo "$dirperm" | cut -c10)" != "-" ]; then 
            chmod g-w,o-rwx "$dir"
        fi 
    fi 
    done

	


	
	echo "-----------------------------------------------------------------------"
	echo "6.2.14 Ensure users' dot files are not group or world writable (Automated)"
    awk -F: '($1!~/(halt|sync|shutdown|nfsnobody)/ && $7!~/^(\/usr)?\/sbin\/nologin(\/)?$/ && $7!~/(\/usr)?\/bin\/false(\/)?$/) { print $6 }' /etc/passwd | while read -r dir; do
    if [ -d "$dir" ]; then
            for file in "$dir"/.*; do \
                    if [ ! -h "$file" ] && [ -f "$file" ]; then
                            fileperm=$(stat -L -c "%A" "$file")
                                    if [ "$(echo "$fileperm" | cut -c6)" != "-" ] || [ "$(echo "$fileperm" | cut -c9)" != "-" ]; then
                                            chmod go-w "$file"
                                    fi
                    fi
            done
    fi
    done
	
	echo "-----------------------------------------------------------------------"
	echo "6.2.15 Ensure no users have .forward files (Automated)"
    awk -F: '($1!~/(halt|sync|shutdown)/ && $7!~/^(\/usr)?\/sbin\/nologin(\/)?$/ && $7!~/(\/usr)?\/bin\/false(\/)?$/) { print $6 }' /etc/passwd | while read -r dir; do
    if [ -d "$dir" ]; then
            file="$dir/.forward"
            [ ! -h "$file" ] && [ -f "$file" ] && rm -f "$file"
                fi
    done

	echo "-----------------------------------------------------------------------"
	echo "6.2.16 Ensure no users have .netrc files (Automated)"
    awk -F: '($1!~/(halt|sync|shutdown)/ && $7!~/^(\/usr)?\/sbin\/nologin(\/)?$/ && $7!~/(\/usr)?\/bin\/false(\/)?$/) { print $6 }' /etc/passwd | while read -r dir; do
    if [ -d "$dir" ]; then
            file="$dir/.netrc"
            [ ! -h "$file" ] && [ -f "$file" ] && rm -f "$file"
                fi
    done

	echo "-----------------------------------------------------------------------"
	echo "6.2.17 Ensure no users have .rhosts files (Automated)"
    awk -F: '($1!~/(halt|sync|shutdown)/ && $7!~/^(\/usr)?\/sbin\/nologin(\/)?$/ && $7!~/(\/usr)?\/bin\/false(\/)?$/) { print $6 }' /etc/passwd | while read -r dir; do
    if [ -d "$dir" ]; then
            file="$dir/.rhosts"
            [ ! -h "$file" ] && [ -f "$file" ] && rm -f "$file"
                fi
    done

	echo "-----------------------------------------------------------------------"
	echo "6.2.18 Ensure users' .netrc Files are not group or world accessible (Automated)"
	grep -E -v '^(root|halt|sync|shutdown)' /etc/passwd | awk -F: '($7 != "'"$(which nologin)"'" && $7 != "/bin/false") { print $1 " " $6 }' | while read user dir; do
		if [ ! -d "$dir" ]; then
			echo "The home directory ($dir) of user $user does not exist."
		else
			for file in $dir/.netrc; do
				if [ ! -h "$file" -a -f "$file" ]; then
					fileperm=$(ls -ld $file | cut -f1 -d" ")
					if [ $(echo $fileperm | cut -c5) != "-" ]; then
						echo "Group Read set on $file"
					fi
					if [ $(echo $fileperm | cut -c6) != "-" ]; then
						echo "Group Write set on $file"
					fi
					if [ $(echo $fileperm | cut -c7) != "-" ]; then
						echo "Group Execute set on $file"
					fi
					if [ $(echo $fileperm | cut -c8) != "-" ]; then
						echo "Other Read set on $file"
					fi
					if [ $(echo $fileperm | cut -c9) != "-" ]; then
						echo "Other Write set on $file"
					fi
					if [ $(echo $fileperm | cut -c10) != "-" ]; then
						echo "Other Execute set on $file"
					fi
				fi
			done
		fi
	done




	
echo "-----------------------------------------------------------------------"
echo "CIS Section completed"
echo "-----------------------------------------------------------------------"
# revised
echo "-----------------------------------------------------------------------"
echo "Clean up by removing unneccessary and dangerous commands"
find /bin /etc /lib /sbin /usr -xdev \( \
  -iname hexdump -o \
  -iname chgrp -o \
  -iname ln -o \
  -iname od -o \
  -iname strings -o \
  -iname su -o \
  -iname sudo \
\) -exec rm -rf {}  \;

echo "Clean up by removing root home dir"
rm -fr /root

echo "Cleaning installed packages...."
yum remove -y kmod findutils procps iptables rsyslog dconf crontabs
echo "Remove done...."


echo "-----------------------------------------------------------------------"
echo "Hardening Completed"
echo "-----------------------------------------------------------------------"


fi



if cat /etc/os-release | grep "Debian" | grep -i "Linux 11\|Linux 10"; then

echo "----------------------- Debian Hardening Begins -----------------------"

echo "Install required package.."
apt install -y -f procps
apt install -y kmod
echo "Installation completed.."




echo "-----------------------------------------------------------------------"
echo "1.1.1.1 Ensure mounting of cramfs filesystems is disabled (Automated)"
mkdir /etc/modprobe.d
touch /etc/modprobe.d/CIS.conf
echo "install cramfs /bin/true" >> /etc/modprobe.d/CIS.conf
rmmod cramfs

echo "-----------------------------------------------------------------------"
echo "1.1.1.2 Ensure mounting of freevxfs filesystems is disabled (Automated)"
echo "install freevxfs /bin/true" >> /etc/modprobe.d/CIS.conf
rmmod freevfs

echo "-----------------------------------------------------------------------"
echo "1.1.1.3 Ensure mounting of jffs2 filesystems is disabled (Automated)"
echo "install jffs2 /bin/true" >> /etc/modprobe.d/CIS.conf
rmmod jffs2

echo "-----------------------------------------------------------------------"
echo "1.1.1.4 Ensure mounting of hfs filesystems is disabled (Automated)"
echo "install hfs /bin/true" >> /etc/modprobe.d/CIS.conf
rmmod hfs

echo "-----------------------------------------------------------------------"
echo "1.1.1.5 Ensure mounting of hfsplus filesystems is disabled (Automated)"
echo "install hfsplus /bin/true" >> /etc/modprobe.d/CIS.conf
rmmod hfsplus

# revised
echo "-----------------------------------------------------------------------"
echo "1.1.1.6  Ensure mounting of squashfs filesystems is disabled (Manual)"
echo "install squashfs /bin/true" >> /etc/modprobe.d/CIS.conf
rmmod squashfs

echo "-----------------------------------------------------------------------"
echo "1.1.1.7  Ensure mounting of udf filesystems is disabled (Automated)"
echo "install udf /bin/true" >> /etc/modprobe.d/CIS.conf
rmmod udf

echo "-----------------------------------------------------------------------"
echo "1.1.2 Ensure separate partition exists for /tmp (Automated) - Not applicable for container"
#echo /tmp
mount | grep tmp

echo "-----------------------------------------------------------------------"
echo "1.1.3 Ensure nodev option set on /tmp partition (Automated) - Not applicable for container"
#echo "/dev/sdz /tmp rw,nosuid,nodev,noexec,relatime 0 0" /etc/fstab 
mount -o remount,nodev /tmp

echo "-----------------------------------------------------------------------"
echo "1.1.4 Ensure nosuid option set on /tmp partition (Automated) - Not applicable for container"
mount -o remount,nosuid /tmp

# Revised 
echo "-----------------------------------------------------------------------"
echo "1.1.5 Ensure noexec option set on /tmp partition (Automated) - Not applicable for container"
mount -o remount,noexec /tmp
echo "Ensure no malicious file system mount"
rm -f /etc/fstab

# Revised
echo "-----------------------------------------------------------------------"
echo "1.1.6 Ensure separate partition exists for /var (Automated) - Not applicable for container"
mount | grep -E '\s/var\s'

# Revised
echo "-----------------------------------------------------------------------"
echo "1.1.7 Ensure separate partition exists for /var/tmp (Automated) - Not applicable for container"
echo "Ensure no malicious file system mount"
rm -f /etc/fstab

# Revised
echo "-----------------------------------------------------------------------"
echo "1.1.8 Ensure nodev option set on /var/tmp partition (Automated) - Not applicable for container"
echo "1.1.9 Ensure nosuid option set on /var/tmp partition (Automated) - Not applicable for container"
echo "1.1.10 Ensure noexec option set on /var/tmp partition (Automated) - Not applicable for container"
echo "Ensure no malicious file system mount"
rm -f /etc/fstab


echo "-----------------------------------------------------------------------"
echo "1.1.11 Ensure separate partition exists for /var/log (Automated) - Not applicable for container"
mount | grep -E '\s\/var\/log\s'

# revsied
echo "-----------------------------------------------------------------------"
echo "1.1.12 Ensure separate partition exists for /var/log/audit (Automated) - Not applicable for container"
mount | grep -E '\s\/var\/log\/audit\s'

# revised
echo "-----------------------------------------------------------------------"
echo "1.1.13 Ensure separate partition exists for /home (Automated) - Not applicable for container"
mount | grep /home

# revised
echo "-----------------------------------------------------------------------"
echo "1.1.14 Ensure nodev option set on /home partition (Automated) - Not applicable for container"
echo "1.1.15 Ensure nodev option set on /dev/shm partition (Automated) - Not applicable for container"
echo "1.1.16 Ensure nosuid option set on /dev/shm partition (Automated)  - Not applicable for container"
echo "1.1.17 Ensure noexec option set on /dev/shm partition (Automated)- Not applicable for container"
echo "1.1.18 Ensure nodev option set on removable media partitions (Manual) - Not applicable for container"
echo "1.1.19 Ensure nosuid option set on removable media partitions (Manual) - Not applicable for container"
echo "1.1.20 Ensure noexec option set on removable media partitions (Manual) - Not applicable for container"
echo "Ensure no malicious file system mount"
rm -f /etc/fstab






echo "-----------------------------------------------------------------------"
echo "1.1.21 Ensure sticky bit is set on all world-writable directories (Automated)"
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type d -perm -0002 2>/dev/null | xargs chmod a+t

echo "-----------------------------------------------------------------------"
echo "1.1.22 Disable Automounting (Automated)"
rm -f /etc/init/autofs.conf

# revised
echo "-----------------------------------------------------------------------"
echo "1.1.23 Disable USB Storage (Automated)"
echo "Install usb-storage /bin/true" >> /etc/modprobe.d/CIS.conf


echo "-----------------------------------------------------------------------"
echo "1.2.1 Ensure package manager repositories are configured (Manual) - Not applicable for container"
echo "Skipped. Not applicable for containers."

echo "-----------------------------------------------------------------------"
echo "1.2.1 Ensure GPG keys are configured (Manual) - Not applicable for container"
echo "Skipped. Not applicable for containers."

# revised
echo "-----------------------------------------------------------------------"
echo "1.3.1 Ensure sudo is installed (Automated)"
apt install sudo -y

# revised
echo "-----------------------------------------------------------------------"	
echo "1.3.2 Ensure sudo commands use pty (Automated)"
echo "Defaults use_pty" >> /etc/sudoers


echo "-----------------------------------------------------------------------"	
echo "1.3.3 Ensure sudo log file exists (Automated)"
echo 'Defaults logfile="/var/log/sudo.log"' >> /etc/sudoers


# revised
echo "-----------------------------------------------------------------------"
echo "1.4.1 Ensure AIDE is installed (Automated) - Not applicable for container"
echo "Skipped. Not applicable for containers."

echo "-----------------------------------------------------------------------"
echo "1.4.2 Ensure filesystem integrity is regularly checked (Automated) - Not applicable for container"
#apt-get install aide -y
#echo "0 5 * * * /usr/bin/aide --config /etc/aide/aide.conf --check" >> /var/spool/cron/crontabs/root 
echo "Skipped. Not applicable for containers."


echo "-----------------------------------------------------------------------"
echo "1.5.1 Ensure permissions on bootloader config are configured (Automated)"
echo "Skipped. Not applicable for containers."

echo "-----------------------------------------------------------------------"
echo "1.5.2 Ensure bootloader password is set (Automated) - Not applicable for container"
echo "Skipped. Not applicable for containers."



echo "-----------------------------------------------------------------------"
echo "1.5.3 Ensure authentication required for single user mode (Automated) - Not applicable for container"
echo "Skipped. Not applicable for containers."


# revised
echo "-----------------------------------------------------------------------"
echo "1.6.1 Ensure XD/NX support is enabled (Automated) - Not applicable for container"
echo "Skipped. Not applicable for containers."


echo "----------------------------------------------------------------------"
echo "1.6.2 Ensure address space layout randomization ASLR is enabled (Automated)"
echo "kernel.randomize_va_space=2" >> /etc/sysctl.conf
#sysctl -w kernel.randomize_va_space=2
sysctl -p

echo "-----------------------------------------------------------------------"
echo "1.6.3 Ensure prelink is disabled (Automated)"
if (dpkg-query -l | grep "prelink") ; then
    prelink -ua
    apt purge -y prelink
fi

echo "-----------------------------------------------------------------------"
echo "1.6.4 Ensure core dumps are restricted (Automated)"
echo "* hard core 0" >> /etc/security/limits.conf
echo "fs.suid_dumpable = 0" >> /etc/sysctl.conf
#sysctl -w fs.suid_dumpable=0
sysctl -p
#apt remove --purge procps
#apt autoremove -y


echo "-----------------------------------------------------------------------"
echo "1.7.1 Configure AppArmor - Not applicable for container (Automated)"
echo "Skipped. Not applicable for containers."


# revised
echo "-----------------------------------------------------------------------"
echo "1.7.1.2 Ensure AppArmor is enabled in the bootloader configuration - Not applicable for container(Automated)"
echo "Skipped. Not applicable for containers."

# revised
echo "-----------------------------------------------------------------------"
echo "1.7.1.3 Ensure all AppArmor Profiles are in enforce or complain mode- Not applicable for container(Automated)"
echo "Skipped. Not applicable for containers."

# revised
echo "-----------------------------------------------------------------------"
echo "1.7.1.4 Ensure all AppArmor Profiles are enforcing - Not applicable for container(Automated)"
echo "Skipped. Not applicable for containers."




echo "-----------------------------------------------------------------------"
echo "1.8.1 Ensure message of the day is configured properly (Automated)"
echo "All access to this system is monitored.  Any person who uses or accesses this system expressly consents to such monitoring and recording.  We may furnish information obtained by its monitoring and recording activity to law enforcement officials if such monitoring and recording reveals possible evidence of unlawful activity." > /etc/motd
chown root:root /etc/update-motd.d/*
chmod 644 /etc/update-motd.d

# revised
echo "-----------------------------------------------------------------------"
echo "1.8.2 Ensure permissions on /etc/issue.net are configured (Automated)"
chown root:root /etc/issue.net
chmod u-x,go-wx /etc/issue.net

# revised 
echo "-----------------------------------------------------------------------"
echo "1.8.3 Ensure permissions on /etc/issue are configured (Automated)"
chown root:root /etc/issue.net
chmod u-x,go-wx /etc/issue.net



# revised 
echo "-----------------------------------------------------------------------"
echo "1.8.4 Ensure permissions on /etc/motd are configured (Automated)"
chown root:root /etc/motd
chmod u-x,go-wx /etc/motd


echo "-----------------------------------------------------------------------"
echo "1.8.5 Ensure remote login warning banner is configured properly (Not Scored)"
 echo "Authorized uses only. All activity may be monitored and reported." > /etc/issue.net

echo "-----------------------------------------------------------------------"
echo "1.8.6 Ensure local login warning banner is configured properly (Not Scored)"
echo "Authorized uses only. All activity may be monitored and reported." > /etc/issue


echo "-----------------------------------------------------------------------"
echo "1.9 Ensure GDM is removed or login is configured (Automated)"
echo "GDM is not installed and not applicable for server hosts or container"


echo "-----------------------------------------------------------------------"
echo "1.10 Ensure updates, patches, and additional security software are 
installed (Manual)"
apt update -y
apt upgrade -y



echo "-----------------------------------------------------------------------"
echo "2.1.1.1 Ensure time synchronization is in use - Not applicable for container (Automated) "
echo "Skipped. Not applicable for containers."


echo "-----------------------------------------------------------------------"
echo "2.1.1.2 Ensure systemd-timesyncd is configured - Not applicable for container (Manual) "
echo "Skipped. Not applicable for containers."

echo "-----------------------------------------------------------------------"
echo "2.1.1.3  Ensure chrony is configured - Not applicable for container (Manual) "
echo "remove unnecessary package."
apt purge ntp -y
apt purge chrony -y 

echo "-----------------------------------------------------------------------"
echo "2.1.1.4 Ensure ntp is configured  - Not applicable for container (Manual) "
echo "Skipped. Not applicable for containers."

echo "-----------------------------------------------------------------------"
echo "2.1.2 Ensure X Window System is not installed (Automated)"
echo "2.1.3 Ensure Avahi Server is not installed (Automated)"
echo "2.1.4 Ensure CUPS is not installed (Automated)"
echo "2.1.5 Ensure DHCP is not installed (Automated)"
echo "2.1.6 Ensure LDAP and RPC are not installed (Automated)"
echo "2.1.7 Ensure NFS and RPC are not installed (Automated)"
echo "2.1.8 Ensure DNS Server is not installed (Automated)"
echo "2.1.9 Ensure FTP Server is not installed (Automated)"
echo "2.1.10 Ensure HTTP server is not installed (Automated)"
echo "2.1.11 Ensure IMAP and POP3 server is not installed (Automated)"
echo "2.1.12 Ensure Samba is not installed (Automated)"
echo "2.1.13 Ensure HTTP Proxy Server is not installed (Automated)"
echo "2.1.14 Ensure SNMP Server is not installed (Automated)"
apt purge -y xserver-xorg* avahi-daemon cups isc-dhcp-server slapd nfs-kernel-server rpcbind bind9 vsftpd apache2 squid samba dovecot* snmpd



echo "-----------------------------------------------------------------------"
echo "2.1.15 Ensure mail transfer agent is configured for local-only mode - Not included in the base image"
#sed -i 's/inet_interfaces = all/inet_interfaces = localhost/g' /etc/postfix/main.cf

echo "-----------------------------------------------------------------------"
echo "2.1.16 Ensure rsync service is not installed (Automated)"
apt purge -y rsync

echo "-----------------------------------------------------------------------"
echo "2.1.17 Ensure NIS Server is not installed(Automated)"
apt purge -y nis

# revised 
echo "-----------------------------------------------------------------------"
echo "2.2.1 Ensure NIS clients is not installed (Automated)"
echo "2.2.2 Ensure rsh clients is not installed (Automated)"
echo "2.2.3 Ensure talk clients is not installed (Automated)"
echo "2.2.4 Ensure telnet clients is not installed (Automated)"
echo "2.2.5 Ensure LDAP clients is not installed (Automated)"
echo "2.2.6 Ensure RPC is not installed (Automated)"
apt purge -y nis rsh-client rsh-redone-client talk telnet ldap-utils rpcbind


echo "-----------------------------------------------------------------------"
echo "2.3 Ensure nonessential services are removed or masked (Manual)"
apt install -y lsof
r=$(lsof -i -P -n | grep -v "(ESTABLISHED)")
if [ -z "$r" ]; then
    echo "No established services are found"
else
    echo "Established service is found and is going to stop them.." 
    apt install -y net-tools 
    netstat Drop 
    apt purge -y net-tools
fi
apt purge -y lsof

# revised 
echo "-----------------------------------------------------------------------"
echo "3.1.1 Disable IPv6 (Manual)"
echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf
echo "net.ipv6.conf.default.disable_ipv6 = 1" >> /etc/sysctl.conf
#apt install -y -f procps
sysctl -w net.ipv6.conf.all.disable_ipv6=1
sysctl -w net.ipv6.conf.default.disable_ipv6=1
sysctl -w net.ipv6.route.flush=1
#apt purge -y procps

# revised 
echo "-----------------------------------------------------------------------"
echo "3.1.2 Ensure wireless interfaces are disabled (Automated)"
    if command -v nmcli >/dev/null 2>&1 ; then
        nmcli radio all off
    else
        if [ -n "$(find /sys/class/net/*/ -type d -name wireless)" ]; then
            mname=$(for driverdir in $(find /sys/class/net/*/ -type d -name
             wireless | xargs -0 dirname); do basename "$(readlink -f "$driverdir"/device/driver/module)";done | sort -u)
             for dm in $mname; do
                echo "install $dm /bin/true" >> /etc/modprobe.d/disable_wireless.conf
            done
        fi
    fi


echo "-----------------------------------------------------------------------"
echo "3.2.1 Ensure packet redirect sending is disabled (Automated)"
echo "net.ipv4.conf.all.send_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.send_redirects = 0" >> /etc/sysctl.conf


echo "-----------------------------------------------------------------------"
echo "3.2.2 Ensure IP forwarding is disabled (Automated)"
echo "net.ipv4.ip_forward = 0" >> /etc/sysctl.conf
echo "net.ipv4.route.flush = 1" >> /etc/sysctl.conf


echo "-----------------------------------------------------------------------"
echo "3.3.1 Ensure source routed packets are not accepted Scored"
echo "net.ipv4.conf.all.accept_source_route = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.accept_source_route = 0" >> /etc/sysctl.conf

echo "-----------------------------------------------------------------------"
echo "3.3.2 Ensure ICMP redirects are not accepted (Automated)"
echo "net.ipv4.conf.all.accept_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.accept_redirects = 0" >> /etc/sysctl.conf 

echo "-----------------------------------------------------------------------"
echo "3.3.3 Ensure secure ICMP redirects are not accepted (Automated)"
echo "net.ipv4.conf.all.secure_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.secure_redirects = 0" >> /etc/sysctl.conf 

echo "-----------------------------------------------------------------------"
echo "3.3.4 Ensure suspicious packets are logged (Automated)"
echo "net.ipv4.conf.all.log_martians = 1" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.log_martians = 1" >> /etc/sysctl.conf

echo "-----------------------------------------------------------------------"
echo "3.3.5 Ensure broadcast ICMP requests are ignored Scored"
echo "net.ipv4.icmp_echo_ignore_broadcasts = 1" >> /etc/sysctl.conf

echo "-----------------------------------------------------------------------"
echo "3.3.6 Ensure bogus ICMP responses are ignored (Automated)"
echo "net.ipv4.icmp_ignore_bogus_error_responses = 1" >> /etc/sysctl.conf

echo "-----------------------------------------------------------------------"
echo "3.3.7 Ensure Reverse Path Filtering is enabled (Automated)"
echo "net.ipv4.conf.all.rp_filter = 1" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.rp_filter = 1" >> /etc/sysctl.conf

echo "-----------------------------------------------------------------------"
echo "3.3.8 Ensure TCP SYN Cookies is enabled (Automated)"
echo "net.ipv4.tcp_syncookies = 1" >> /etc/sysctl.conf
# revised
echo "-----------------------------------------------------------------------"
echo "3.3.9 Ensure IPv6 router advertisements are not accepted (Automated)"
echo "net.ipv6.conf.all.accept_ra = 0" >> /etc/sysctl.conf
echo "net.ipv6.conf.default.accept_ra = 0" >> /etc/sysctl.conf



# revised
echo "-----------------------------------------------------------------------"
echo "3.5.1 Ensure DCCP is disabled (Automated)"
echo "install dccp /bin/true" >> /etc/modprobe.d/CIS.conf
# revised
echo "-----------------------------------------------------------------------"
echo "3.5.2 Ensure SCTP is disabled (Automated)"
echo "install sctp /bin/true" >> /etc/modprobe.d/CIS.conf

# revised
echo "-----------------------------------------------------------------------"
echo "3.5.3 Ensure RDS is disabled (Automated)"
echo "install rds /bin/true" >> /etc/modprobe.d/CIS.conf
# revised
echo "-----------------------------------------------------------------------"
echo "3.5.4 Ensure TIPC is disabled (Automated)"
echo "install tipc /bin/true" >> /etc/modprobe.d/CIS.conf

# revised
echo "-----------------------------------------------------------------------"
echo "3.6.1.1 Ensure Uncomplicated Firewall is installed  - Not applicable for container(Automated)"
echo "Skipped. Not applicable for containers."

echo "-----------------------------------------------------------------------"
echo "3.6.1.2 Ensure iptables-persistent is not installed - Not applicable for container(Automated)"
echo "Remove unecessary package"
apt purge -y iptables-persistent

echo "-----------------------------------------------------------------------"
echo "3.6.1.3 Ensure ufw service is enabled - Not applicable for container (Automated)"
echo "Skipped. Not applicable for containers."


echo "-----------------------------------------------------------------------"
echo "3.6.1.4 Ensure loopback traffic is configured (Automated) - It is managed by the orchestrator / kube-proxy for the access control"
echo "3.6.1.5 Ensure outbound and established connections are configured (Automated) - It is managed by the orchestrator / kube-proxy for the access control"
echo "3.6.1.6 Ensure firewall rules exist for all open ports (Automated) - It is managed by the orchestrator / kube-proxy for the access control"
echo "3.6.1.7 Ensure default firewall policy (Automated) - It is managed by the orchestrator / kube-proxy for the access control"
echo "Skipped. Not applicable for containers."

# revised
echo "-----------------------------------------------------------------------"
echo "3.6.2.1 Ensure nftables is installed (Automated) - It is managed by the orchestrator / kube-proxy for the access control"
echo "3.6.2.2 Ensure Uncomplicated Firewall is not installed or disabled (Automated) - It is managed by the orchestrator / kube-proxy for the access control"
echo "3.6.2.3 Ensure iptables are flushed  (Automated) - It is managed by the orchestrator / kube-proxy for the access control"
echo "3.6.2.4 Ensure a table exists (Automated) - It is managed by the orchestrator / kube-proxy for the access control"
echo "3.6.2.5 Ensure base chains exist (Automated) - It is managed by the orchestrator / kube-proxy for the access control"
echo "3.6.2.6 Ensure loopback traffic is configured  (Automated) - It is managed by the orchestrator / kube-proxy for the access control"
echo "3.6.2.7 Ensure outbound and established connections are configured  (Manual) - It is managed by the orchestrator / kube-proxy for the access control"
echo "3.6.2.8 Ensure default deny firewall policy (Automated) - It is managed by the orchestrator / kube-proxy for the access control"
echo "3.6.2.9 Ensure nftables service is enabled (Automated) - It is managed by the orchestrator / kube-proxy for the access control"
echo "3.6.2.10 Ensure nftables rules are permanent (Automated) - It is managed by the orchestrator / kube-proxy for the access control"
echo "3.6.3.1.1 Ensure iptables packages are installed (Automated) - It is managed by the orchestrator / kube-proxy for the access control"
echo "3.6.3.1.2 Ensure nftables is not installed (Automated)- It is managed by the orchestrator / kube-proxy for the access control"
echo "3.6.3.1.3 Ensure Uncomplicated Firewall is not installed or disabled(Automated) - It is managed by the orchestrator / kube-proxy for the access control"
echo "3.6.3.2.1 Ensure default deny firewall policy (Automated)(Automated) - It is managed by the orchestrator / kube-proxy for the access control"
echo "3.6.3.2.2 Ensure loopback traffic is configured (Automated) - It is managed by the orchestrator / kube-proxy for the access control"
echo "3.6.3.2.3 Ensure outbound and established connections are configured  - It is managed by the orchestrator / kube-proxy for the access control"
echo "3.6.3.2.4 Ensure firewall rules exist for all open ports (Automated) - It is managed by the orchestrator / kube-proxy for the access control"
echo "3.6.3.3.1 Ensure IPv6 default deny firewall policy (Automated) - It is managed by the orchestrator / kube-proxy for the access control"
echo "3.6.3.3.2 Ensure IPv6 loopback traffic is configured (Automated) - It is managed by the orchestrator / kube-proxy for the access control"
echo "3.6.3.3.3 Ensure IPv6 outbound and established connections are configured (Manual) - It is managed by the orchestrator / kube-proxy for the access control"
echo "3.6.3.3.4 Ensure IPv6 firewall rules exist for all open ports (Manual) - It is managed by the orchestrator / kube-proxy for the access control"
echo "Skipped. Not applicable for containers."




echo "-----------------------------------------------------------------------"
echo "4.1.1.1 Ensure auditd is installed (Automated) - Container is a child of the init system, thus system log is collected and managed in host level"
echo "4.1.1.2 Ensure auditd service is enabled (Automated) - Container is a child of the init system, thus system log is collected and managed in host level"
echo "4.1.1.3 Ensure auditing for processes that start prior to auditd is enabled (Automated) - Container is a child of the init system, thus system log is collected and managed in host level"
echo "4.1.1.4 Ensure audit_backlog_limit is sufficient (Automated) - Container is a child of the init system, thus system log is collected and managed in host level"
echo "4.1.2.1 Ensure audit log storage size is configured (Automated)- Container is a child of the init system, thus system log is collected and managed in host level"
echo "4.1.2.2 Ensure audit logs are not automatically deleted (Automated) - Container is a child of the init system, thus system log is collected and managed in host level"
echo "4.1.3 Ensure events that modify date and time information are collected (Automated) - Container is a child of the init system, thus system log is collected and managed in host level"
echo "4.1.4 Ensure events that modify user/group information are collected (Automated) - Container is a child of the init system, thus system log is collected and managed in host level"
echo "4.1.5 Ensure events that modify the system's network environment are collected (Automated) - Container is a child of the init system, thus system log is collected and managed in host level"
echo "4.1.6 Ensure events that modify the system's Mandatory Access Controls are collected (Automated) - Container is a child of the init system, thus system log is collected and managed in host level"
echo "4.1.7 Ensure login and logout events are collected (Automated) - Container is a child of the init system, thus system log is collected and managed in host level"
echo "4.1.8 Ensure session initiation information is collected (Automated) - Container is a child of the init system, thus system log is collected and managed in host level"
echo "4.1.9 Ensure discretionary access control permission modification events are collected (Automated) - Container is a child of the init system, thus system log is collected and managed in host level"
echo "4.1.10 Ensure unsuccessful unauthorized file access attempts is collected (Automated) - Container is a child of the init system, thus system log is collected and managed in host level"
echo "4.1.11 Ensure use of privileged commands is collected (Automated) - Container is a child of the init system, thus system log is collected and managed in host level"
echo "4.1.12 Ensure successful file system mounts are collected (Automated) - Container is a child of the init system, thus system log is collected and managed in host level"
echo "4.1.13 Ensure file deletion events by users are collected (Automated) - Container is a child of the init system, thus system log is collected and managed in host level"
echo "4.1.14 Ensure changes to system administration scope (sudoers) is collected (Automated) - Container is a child of the init system, thus system log is collected and managed in host level"
echo "4.1.15 Ensure system administrator command executions (sudo) are collected (Automated) - Container is a child of the init system, thus system log is collected and managed in host level"
echo "4.1.16 Ensure kernel module loading and unloading is collected (Automated) - Container is a child of the init system, thus system log is collected and managed in host level"
echo "4.1.17 Ensure the audit configuration is immutable (Automated) - Container is a child of the init system, thus system log is collected and managed in host level"
echo "Skipped. Not applicable for containers."



echo "-----------------------------------------------------------------------"
echo "4.2.1.1 Ensure rsyslog Service is installed (Automated)"
apt install -y rsyslog

echo "-----------------------------------------------------------------------"
echo "4.2.1.2 Ensure rsyslog Service is enabled (Automated)"
echo "Skipped. By default, rsyslog is enbaled"

echo "-----------------------------------------------------------------------"
echo "4.2.1.3 Ensure logging is configured (Manual)"
echo "4.2.1.4 Ensure rsyslog default file permissions configured (Automated)"
echo "4.2.1.5 Ensure rsyslog is configured to send logs to a remote log host (Automated)"
echo "4.2.1.6 Ensure remote rsyslog messages are only accepted on designated log hosts (Automated)"

touch /etc/rsyslog.d/50-default.conf
cat > /etc/rsyslog.d/50-default.conf << 'EOF'
*.emerg :omusrmsg:*
mail.* -/var/log/mail
mail.info -/var/log/mail.info
mail.warning -/var/log/mail.warn
mail.err /var/log/mail.err
news.crit -/var/log/news/news.crit
news.err -/var/log/news/news.err
news.notice -/var/log/news/news.notice
*.=warning;*.=err -/var/log/warn
*.crit /var/log/warn
*.*;mail.none;news.none -/var/log/messages
local0,local1.* -/var/log/localmessages
local2,local3.* -/var/log/localmessages
local4,local5.* -/var/log/localmessages
local6,local7.* -/var/log/localmessages
FileCreateMode 0640
#$ModLoad imtcp  # provides TCP syslog reception
#$TCPServerRun 10514 # start a TCP syslog server at port 10514
EOF
pkill -HUP rsyslogd
echo "FileCreateMode 0640" >> /etc/rsyslog.conf

# revised
echo "-----------------------------------------------------------------------"
echo "4.2.2.1 Ensure journald is configured to send logs to rsyslog (Automated)"
if ! grep -e ForwardToSyslog /etc/systemd/journald.conf; then
   echo "ForwardToSyslog=yes" >> /etc/systemd/journald.conf
fi
# revised
echo "-----------------------------------------------------------------------"
echo "4.2.2.2 Ensure journald is configured to compress large log files (Automated)"
if ! grep -e Compress /etc/systemd/journald.conf; then
   echo "compress=yes" >> /etc/systemd/journald.conf
fi
# revised
echo "-----------------------------------------------------------------------"
echo "4.2.2.3Ensure journald is configured to write logfiles to persistent disk (Automated)"
if ! grep -e storage /etc/systemd/journald.conf; then
   echo "storage=persistent" >> /etc/systemd/journald.conf
fi
# revised
echo "-----------------------------------------------------------------------"
echo "4.2.3 Ensure permissions on all logfiles are configured (Automated)"
find /var/log -type f -exec chmod g-wx,o-rwx "{}" + -o -type d -exec chmod g-w,o-rwx "{}" +

# revised
echo "-----------------------------------------------------------------------"
echo "4.3 Ensure logrotate is configured (Manual) "
    if (cat /etc/logrotate.d/* | grep rotate); then
        echo "Rotation is configured"
    else
        printf"/var/log/apt/term.log {
        rotate 12
        monthly
        compress
        missingok
        notifempty
        }

        /var/log/apt/history.log {
        rotate 12
        monthly
        compress
        missingok
        notifempty
        }" >> /etc/logrotate.d/rsyslog
    fi
    
# revised
echo "-----------------------------------------------------------------------"
echo "4.4 Ensure logrotate assigns appropriate permissions (Automated) "
    if (cat /etc/logrotate.d/* | grep rotate); then
        echo "Rotation is configured"
        echo "create 0640 root utmp" >> /etc/logrotate.conf
    fi




echo "-----------------------------------------------------------------------"
echo "5.1.1 Ensure cron daemon is enabled"
echo "Skipped. By default, cron daemon is enabled"

echo "-----------------------------------------------------------------------"
echo "5.1.2 Ensure permissions on /etc/crontab are configured"
chown root:root /etc/crontab
chmod og-rwx /etc/crontab

echo "-----------------------------------------------------------------------"
echo "5.1.3 Ensure permissions on /etc/cron.hourly are configured"
chown root:root /etc/cron.hourly
chmod og-rwx /etc/cron.hourly

echo "-----------------------------------------------------------------------"
echo "5.1.4 Ensure permissions on /etc/cron.daily are configured"
chown root:root /etc/cron.daily
chmod og-rwx /etc/cron.daily

echo "-----------------------------------------------------------------------"
echo "5.1.5 Ensure permissions on /etc/cron.weekly are configured"
chown root:root /etc/cron.weekly
chmod og-rwx /etc/cron.weekly

echo "-----------------------------------------------------------------------"
echo "5.1.6 Ensure permissions on /etc/cron.monthly are configured"
chown root:root /etc/cron.monthly
chmod og-rwx /etc/cron.monthly

echo "-----------------------------------------------------------------------"
echo "5.1.7 Ensure permissions on /etc/cron.d are configured"
chown root:root /etc/cron.d
chmod og-rwx /etc/cron.d

echo "-----------------------------------------------------------------------"
echo "5.1.8 Ensure at/cron is restricted to authorized users"
rm /etc/cron.deny
rm /etc/at.deny
touch /etc/cron.allow
touch /etc/at.allow
chmod og-rwx /etc/cron.allow
chmod og-rwx /etc/at.allow
chown root:root /etc/cron.allow
chown root:root /etc/at.allow





echo "-----------------------------------------------------------------------"
echo "5.2.1 Ensure permissions on /etc/ssh/sshd_config are configured (Automated) - remote access to base image should be restricted"
echo "5.2.2 Ensure permissions on SSH private host key files are configured (Automated) - remote access to base image should be restricted"
echo "5.2.3 Ensure permissions on SSH public host key files are configured (Automated) - remote access to base image should be restricted"
echo "5.2.4 Ensure SSH LogLevel is appropriate (Automated) - remote access to base image should be restricted"
echo "5.2.5 Ensure SSH X11 forwarding is disabled (Automated) - remote access to base image should be restricted"
echo "5.2.6 Ensure SSH MaxAuthTries is set to 4 or less (Automated) - remote access to base image should be restricted"
echo "5.2.7 Ensure SSH IgnoreRhosts is enabled (Automated) - remote access to base image should be restricted"
echo "5.2.8 Ensure SSH HostbasedAuthentication is disabled (Automated) - remote access to base image should be restricted"
echo "5.2.9 Ensure SSH root login is disabled (Automated) - remote access to base image should be restricted"
echo "5.2.10 Ensure SSH PermitEmptyPasswords is disabled (Automated) - remote access to base image should be restricted"
echo "5.2.11 Ensure SSH PermitUserEnvironment is disabled (Automated) - remote access to base image should be restricted"
echo "5.2.12 Ensure only strong Ciphers are used (Automated) - remote access to base image should be restricted"
echo "5.2.13 Ensure only strong MAC algorithms are used (Automated) - remote access to base image should be restricted"
echo "5.2.14 Ensure only strong Key Exchange algorithms are used (Automated) - remote access to base image should be restricted"
echo "5.2.15 Ensure SSH Idle Timeout Interval is configured (Automated) - remote access to base image should be restricted"
echo "5.2.16 Ensure SSH LoginGraceTime is set to one minute or less (Automated) - remote access to base image should be restricted"
echo "5.2.17 Ensure SSH access is limited (Automated) - remote access to base image should be restricted"
echo "5.2.18 Ensure SSH warning banner is configured (Automated) - remote access to base image should be restricted"
echo "5.2.19 Ensure SSH PAM is enabled (Automated) - remote access to base image should be restricted"
echo "5.2.20 Ensure SSH AllowTcpForwarding is disabled (Automated) - remote access to base image should be restricted"
echo "5.2.21 Ensure SSH MaxStartups is configured (Automated) - remote access to base image should be restricted"
echo "5.2.22 Ensure SSH MaxSessions is limited (Automated) - remote access to base image should be restricted"
echo "Remove sshd daemon"
apt remove --purge openssh-server -y





echo "-----------------------------------------------------------------------"
echo "5.3.1 Ensure password creation requirements are configured (Automated)"

apt install -y libpam-pwquality
#sudo cp /etc/pam.d/common-password /home/

cat > /etc/security/pwquality.conf << EOF
minlen = 14
minclass = 4
EOF


echo "-----------------------------------------------------------------------"
echo "5.3.2 Ensure lockout for failed password attempts is configured (Automated)"
echo "auth required pam_tally2.so onerr=fail audit silent deny=5 unlock_time=900" >>  /etc/pam.d/common-auth

echo "-----------------------------------------------------------------------"
echo "5.3.3 Ensure password reuse is limited (Automated)"
echo "password required pam_pwhistory.so remember=5" >> /etc/pam.d/common-password

echo "-----------------------------------------------------------------------"
echo "5.3.4 Ensure password hashing algorithm is SHA-512 (Automated)"
echo "password [success=1 default=ignore] pam_unix.so sha512" >> /etc/pam.d/common-password


echo "-----------------------------------------------------------------------"
echo "5.4.1.1 Ensure password expiration is 365 days or less (Automated)"
sed -i 's/PASS_MAX_DAYS\s99999/PASS_MAX_DAYS 365/g' /etc/login.defs

echo "-----------------------------------------------------------------------"
echo "5.4.1.2 Ensure minimum days between password changes is 7 or more (Automated)"
sed -i 's/PASS_MIN_DAYS\s0/PASS_MIN_DAYS 7/g' /etc/login.defs

echo "-----------------------------------------------------------------------"
echo "5.4.1.3 Ensure password expiration warning days is 7 or more (Automated)"
sed -i 's/PASS_WARN_AGE\s7/PASS_WARN_AGE 7/g' /etc/login.defs

echo "-----------------------------------------------------------------------"
echo "5.4.1.4 Ensure inactive password lock is 30 days or less (Automated)"
useradd -D -f 30


# revised
echo "-----------------------------------------------------------------------"
echo "5.4.1.5 Ensure all users last password change date is in the past (Automated)"
for usr in $(cut -d: -f1 /etc/shadow); do [[ $(chage --list $usr | grep '^Last password change' | cut -d: -f2) > $(date) ]] && echo "$usr :$(chage --list $usr | grep '^Last password change' | cut -d: -f2)" && echo "Please confirm if users is required to delete"; done 

# revised
echo "-----------------------------------------------------------------------"
echo "5.4.2 Ensure system accounts are secured (Automated)"
for usr in $(awk -F: '($1!="root" && $1!="sync" && $1!="shutdown" && $1!="halt" && $1!~/^\+/ && $3<'"$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)"' && $7!="'"$(which nologin)"'" && $7!="/bin/false") {print}' /etc/passwd | cut -f1 -d:); do usermod -s $(which nologin) $usr; done


echo "-----------------------------------------------------------------------"
echo "5.4.3 Ensure default group for the root account is GID 0 (Automated)"
usermod -g 0 root

echo "-----------------------------------------------------------------------"
echo "5.4.4 Ensure default user umask is 027 or more restrictive (Automated)"
sed -i 's/USERGROUPS_ENAB\syes/USERGROUPS_ENAB no/g' /etc/login.defs
sed -i 's/UMASK\s022/UMASK 027/g' /etc/login.defs
echo "session optional     pam_umask.so" >> /etc/pam.d/common-session

echo "-----------------------------------------------------------------------"
echo "5.4.5 Ensure default user shell timeout is 900 seconds or less (Automated)"
echo 'TMOUT=600' >> /etc/profile


echo "-----------------------------------------------------------------------"
echo "5.5 Ensure root login is restricted to system console (Manual)"
echo "remove interactive login shell"
sed -i -r 's#^(.*):[^:]*$#\1:/sbin/nologin#' /etc/passwd



echo "-----------------------------------------------------------------------"
echo "5.6 Ensure access to the su command is restricted (Automated)"
echo 'auth required pam_wheel.so use_uid' >> /etc/pam.d/su




echo "-----------------------------------------------------------------------"
echo "6.1.2 Ensure permissions on /etc/passwd are configured (Automated)"
chown root:root /etc/passwd
chmod 644 /etc/passwd


echo "-----------------------------------------------------------------------"
echo "6.1.3 Ensure permissions on /etc/passwd- are configured (Automated)"
chown root:root /etc/passwd-
chmod u-x,go-wx /etc/passwd-

echo "-----------------------------------------------------------------------"
echo "6.1.4 Ensure permissions on /etc/group are configured (Automated)"
chown root:root /etc/group
chmod 644 /etc/group

echo "-----------------------------------------------------------------------"
echo "6.1.5 Ensure permissions on /etc/group- are configured (Automated)"
chown root:root /etc/group-
chmod u-x,go-wx /etc/group-


echo "-----------------------------------------------------------------------"
echo "6.1.6 Ensure permissions on /etc/shadow are configured (Automated)"
chown root:shadow /etc/shadow
chmod o-rwx,g-wx /etc/shadow 

echo "-----------------------------------------------------------------------"
echo "6.1.7 Ensure permissions on /etc/shadow- are configured (Automated)"
chown root:root /etc/shadow-
chmod o-rwx,g-rw /etc/shadow-

echo "-----------------------------------------------------------------------"
echo "6.1.8 Ensure permissions on /etc/gshadow are configured (Automated)"
chown root:shadow /etc/gshadow
chmod o-rwx,g-rw /etc/gshadow


echo "-----------------------------------------------------------------------"
echo "6.1.9 Ensure permissions on /etc/gshadow- are configured (Automated)"
chown root:root /etc/gshadow-
chmod o-rwx,g-rw /etc/gshadow-

# revised 
echo "-----------------------------------------------------------------------"
echo "6.1.10 Ensure no world writable files exist (Automated)"
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f -perm -0002
echo "Remove world-writeable permissions except for /tmp/"
find / -xdev -type d -perm -0002 -exec chmod o-w {} + \
  && find / -xdev -type f -perm -0002 -exec chmod o-w {} + \
  && chmod 777 /tmp


echo "-----------------------------------------------------------------------"
echo "6.1.11 Ensure no unowned files or directories exist (Automated)"
file=$( df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nouser)
for f in file; do rm -f $f; done




echo "-----------------------------------------------------------------------"
echo "6.1.12 Ensure no ungrouped files or directories exist"
file=$( df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -nogroup )
for f in file; do rm -f $f; done

echo "-----------------------------------------------------------------------"
echo "6.1.13 Audit SUID executables (Not Scored)"
    suid=$(df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type f -perm -4000)
    check="sudo"
    result=$(echo $suid | rev | cut -f1 -d'/' | rev)
    if [ "$result"=="$check" ]; then
    echo "No extra SUID found"
    else
    echo "Unexpected SUID executables found. Please review."
    df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type f -perm -4000  
    exit 1
    fi


echo "-----------------------------------------------------------------------"
echo "6.1.14 Audit SGID executables (Not Scored)"
    sgid=$(df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type f -perm -2000)
    check="write"
    result=$(echo $sgid | rev | cut -f1 -d'/' | rev)
    if [ "$result"=="$check" ]; then
    echo "No extra SGID found"
    else
    echo "Unexpected SGID executables found. Please review."
    df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type f -perm -2000
    exit 1
    fi

# revised
echo "-----------------------------------------------------------------------"
echo "6.2.1 Ensure accounts in /etc/passwd use shadowed passwords (Automated)"
sed -e 's/^\([a-zA-Z0-9_]*\):[^:]*:/\1:x:/' -i /etc/passwd
echo "Disable passowrd login for additional security protection"
while IFS=: read -r username _; do passwd -l "$username"; done < /etc/passwd || true

echo "-----------------------------------------------------------------------"
echo "6.2.2 Ensure password fields are not empty (Automated)"
grep '^\+:' /etc/passwd
echo "Disable passowrd login for additional security protection"
while IFS=: read -r username _; do passwd -l "$username"; done < /etc/passwd || true

echo "-----------------------------------------------------------------------"
echo "6.2.3 Ensure all users' home directories exist (Automated)"
awk -F: '($1!~/(halt|sync|shutdown|nfsnobody)/ && $7!~/^(\/usr)?\/sbin\/nologin(\/)?$/ && $7!~/(\/usr)?\/bin\/false(\/)?$/) { print $1 " " $6 }' /etc/passwd | while read -r user dir; do
   if [ ! -d "$dir" ]; then
      mkdir "$dir" chmod g-w,o-wrx "$dir" chown "$user" "$dir"
   fi
done


echo "-----------------------------------------------------------------------"	
echo "6.2.4 Ensure users own their home directories (Automated)"
awk -F: '($1!~/(halt|sync|shutdown|nfsnobody)/ && $7!~/^(\/usr)?\/sbin\/nologin(\/)?$/ && $7!~/(\/usr)?\/bin\/false(\/)?$/) { print $1 " " $6 }' /etc/passwd | while read -r user dir; do
if [ ! -d "$dir" ]; then
echo "User: \"$user\" home directory: \"$dir\" does not exist, creating home directory" 
mkdir "$dir"
chmod g-w,o-rwx "$dir"
chown "$user" "$dir" else
owner=$(stat -L -c "%U" "$dir")
if [ "$owner" != "$user" ]; then
chmod g-w,o-rwx "$dir"
chown "$user" "$dir"
fi
fi
done


echo "-----------------------------------------------------------------------"
echo "6.2.5 Ensure users home directories permissions are 750 or more restrictive (Automated)"
awk -F: '($1!~/(halt|sync|shutdown)/ && $7!~/^(\/usr)?\/sbin\/nologin(\/)?$/ && $7!~/(\/usr)?\/bin\/false(\/)?$/) {print $6}' /etc/passwd | while read -r dir; do
 if [ -d "$dir" ]; then
          dirperm=$(stat -L -c "%A" "$dir")
           if [ "$(echo "$dirperm" | cut -c6)" != "-" ] || [ "$(echo "$dirperm" | 
                   cut -c8)" != "-" ] || [ "$(echo "$dirperm" | cut -c9)" != "-" ] || [ "$(echo "$dirperm" | cut -c10)" != "-" ]; then
                               chmod o-w,g-rwx
            fi
 fi
done




echo "-----------------------------------------------------------------------"
echo "6.2.6 Ensure users dot files are not group or world writable (Automated)"
cat /etc/passwd | egrep -v '^(root|halt|sync|shutdown)' | awk -F: '($7 != "/sbin/nologin" && $7 != "/bin/false") { print $1 " " $6 }' | while read user dir; do
if [ ! -d "$dir" ]; then
for file in "$dir"/.*; do
    if [ ! -h "$file" ] && [ -f "$file" ]; then
        fileperm=$(stat -L -c "%A" "$file")
        if [ "$(echo "$fileperm" | cut -c6)" != "-" ] || [ "$(echo "$fileperm" | cut -c9)" != "-" ]; then
            chmod go-w "$file"
        fi
     fi
done
fi
done


echo "-----------------------------------------------------------------------"
echo "6.2.7 Ensure no users have .netrc files (Automated)"
awk -F: '($1!~/(halt|sync|shutdown)/ && $7!~/^(\/usr)?\/sbin\/nologin(\/)?$/ && $7!~/(\/usr)?\/bin\/false(\/)?$/) { print $6 }' /etc/passwd | while read -r dir; do
 if [ -d "$dir" ]; then
          file="$dir/.netrc"
           [ ! -h "$file" ] && [ -f "$file" ] && rm -f "$file"
            fi
done


echo "-----------------------------------------------------------------------"
echo "6.2.8 Ensure no users have .forward files (Automated)"
awk -F: '($1!~/(halt|sync|shutdown)/ && $7!~/^(\/usr)?\/sbin\/nologin(\/)?$/ && $7!~/(\/usr)?\/bin\/false(\/)?$/) { print $6 }' /etc/passwd | while read -r dir; do
 if [ -d "$dir" ]; then
          file="$dir/.forward"
           [ ! -h "$file" ] && [ -f "$file" ] && rm -f "$file"
            fi
done
echo "-----------------------------------------------------------------------"
echo "6.2.9 Ensure no users have .rhosts files (Automated)"
awk -F: '($1!~/(halt|sync|shutdown)/ && $7!~/^(\/usr)?\/sbin\/nologin(\/)?$/ && $7!~/(\/usr)?\/bin\/false(\/)?$/) { print $6 }' /etc/passwd | while read -r dir; do
 if [ -d "$dir" ]; then
          file="$dir/.rhosts"
           [ ! -h "$file" ] && [ -f "$file" ] && rm -f "$file"
            fi
done


echo "-----------------------------------------------------------------------"
echo "6.2.10 Ensure root is the only UID 0 account (Automated)"
r=$(cat /etc/passwd | awk -F: '($3 == 0) { print $1 }' | wc -l )
if [ $r -gt 1 ]; then
            u=$(cat /etc/passwd | awk -F: '($3 == 0) { print $1 }')
                for user in $u; do
                            if ("$user" !="root"); then
                                userdel -rf $user
                            fi
                done
fi


echo "-----------------------------------------------------------------------"
echo "6.2.11 Ensure root PATH Integrity (Automated)"
if [ "`echo $PATH | grep :: `" != "" ]; then
 echo "Empty Directory in PATH (::)"
fi
if [ "`echo $PATH | grep :$`" != "" ]; then
echo "Trailing : in PATH"
fi
p=`echo $PATH | sed -e 's/::/:/' -e 's/:$//' -e 's/:/ /g'`
set -- $p
while [ "$1" != "" ]; do
if [ "$1" = "." ]; then
echo "PATH contains ."
shift
continue
fi
if [ -d $1 ]; then
 dirperm=`ls -ldH $1 | cut -f1 -d" "`
 if [ `echo $dirperm | cut -c6 ` != "-" ]; then
 echo "Group Write permission set on directory $1"
    dirown=`ls -ldH $1 | awk '{print $3}'`
  if [ "$dirown" != "root" ] ; then
    echo $1 is not owned by root
    rm -rf $1
  fi
 fi
 if [ `echo $dirperm | cut -c9 ` != "-" ]; then
 echo "Other Write permission set on directory $1"
    dirown=`ls -ldH $1 | awk '{print $3}'`
   if [ "$dirown" != "root" ] ; then
    echo $1 is not owned by root
    rm -rf $1
  fi
 fi
 
else
 echo $1 is not a directory
fi
shift
done



echo "-----------------------------------------------------------------------"
echo "6.2.12 Ensure all groups in /etc/passwd exist in /etc/group (Automated)"
echo
for i in $(cut -s -d: -f4 /etc/passwd | sort -u ); do grep -q -P "^.*?:[^:]*:$i:" /etc/group 
if [ $? -ne 0 ]; then  
   echo "Group $i is referenced by /etc/passwd but does not exist in /etc/group"
   groupdel -f $i
fi
done



echo "-----------------------------------------------------------------------"
echo "6.2.13 Ensure no duplicate UIDs exist (Automated)"
echo
cat /etc/passwd | cut -f3 -d":" | sort -n | uniq -c | while read x ; do
[ -z "${x}" ] && break
set - $x
if [ $1 -gt 1 ]; then
 users=`awk -F: '($3 == n) { print $1 }' n=$2 /etc/passwd | xargs`
 echo "Duplicate UID ($2): ${users}"
 echo "Duplicate UID can be only deleted manually "
 exit 1
fi
done



echo "-----------------------------------------------------------------------"
echo "6.2.14 Ensure no duplicate GIDs exist (Automated)"
echo
cut -d: -f1 /etc/group | sort | uniq -d | while read -r x; do
 echo "Duplicate group name $x in /etc/group"
 echo "Duplicate GID can be only deleted manually "
 exit 1
done

echo "-----------------------------------------------------------------------"
echo "6.2.15 Ensure no duplicate user names exist (Automated)"
cut -d: -f1 /etc/passwd | sort | uniq -d | while read -r x; do
 echo "Duplicate login name $x in /etc/passwd"
  echo "Duplicate user can be only deleted manually "
 exit 1
done


echo "-----------------------------------------------------------------------"
echo "6.2.16 Ensure no duplicate group names exist (Automated)"
echo
cat /etc/group | cut -f1 -d":" | sort -n | uniq -c | while read x ; do
[ -z "${x}" ] && break
set - $x
if [ $1 -gt 1 ]; then
 gids=`gawk -F: '($1 == n) { print $3 }' n=$2 /etc/group | xargs`
 echo "Duplicate Group Name ($2): ${gids}"
 echo "Duplicate Group Name can be only deleted manually"
 exit 1
fi
done



echo "-----------------------------------------------------------------------"
echo "6.2.17 Ensure shadow group is empty (Automated)"
grep ^shadow:[^:]*:[^:]*:[^:]+ /etc/group
u=$(awk -F: '($4 == "") { print }' /etc/passwd)
if [ -z "$u"]; then
    echo "shadow group is empty"
else
    for user in $u; do userdel -f $user; done 
fi
    

echo "-----------------------------------------------------------------------"
echo "CIS Section completed"
echo "-----------------------------------------------------------------------"

echo "Cleaning up packages..."
apt remove -y kmod

echo "-----------------------------------------------------------------------"
echo "Clean up by removing unneccessary and dangerous commands"
find /bin /etc /lib /sbin /usr -xdev \( \
  -iname hexdump -o \
  -iname chgrp -o \
  -iname ln -o \
  -iname od -o \
  -iname strings -o \
  -iname su -o \
  -iname sudo \
  \) -exec rm -rf {}  \;

echo "Clean up by removing root home dir"
rm -fr /root

echo "remove unnecessary package"
apt autoremove -y

echo "-----------------------------------------------------------------------"
echo "Hardening Completed"
echo "-----------------------------------------------------------------------"

fi
