#!/bin/bash
#
# This script will install the Citrix DaaS MCS software package.  Before deploying this terraform, the user must create
# an image that includes the Citrix software copied to /opt/ibm/citrix_daas.  The software can be downloaded by following these
# instructions: https://docs.citrix.com/en-us/linux-virtual-delivery-agent/current-release/installation-overview/create-domain-joined-vdas-using-easy-install#step-4-download-the-linux-vda-package
# Note: all the steps needed to install and configure the Citrix XenDesktopVDA/MCS software will be performed by this script.  
#
# The logging output from this script can be found in /var/log/cloud-init-output.log
#
CITRIX_DAAS=/opt/ibm/citrix_daas
INSTALLER_RPM=$(ls $CITRIX_DAAS/XenDesktopVDA*.el9_x.x86_64.rpm) # e.g. XenDesktopVDA-23.05.0.22-1.el9_x.x86_64.rpm
INSTALLER_GPG=$CITRIX_DAAS/GPG_Key.asc
NTP_SERVER=time.adn.networklayer.com
EPEL_KEY_URL=https://archive.fedoraproject.org/pub/epel/RPM-GPG-KEY-EPEL-9
EPEL_PACKAGE_URL=https://dl.fedoraproject.org/pub/epel/epel-release-latest-9.noarch.rpm
VDA_AD_INTEGRATION=winbind
VDI_MODE=N
DOWNLOAD_DIR=downloads
DNS_IP_ADDRESS=${ad_ip}

function write_log() {

    if [ $1 = "Warn" ]; then
        LevelValue="Warning"
    elif [ $1 = "Error" ]; then
        LevelValue="Error"
    else
        LevelValue="Information"
    fi

    Stamp=$(date +"%Y/%m/%d %H:%M:%S")
    sudo echo "$Stamp $LevelValue $2"
}

function write_environment() {
    write_log Info "----------------------------------------"
    write_log Info "Started executing $(dirname $(readlink -f $0))/$(basename $0)"
    write_log Info "----------------------------------------"
    write_log Info "Script Version: 2023.08.18"
    write_log Info "Current User: $(whoami)"
    write_log Info "Hostname: $(/usr/bin/hostname)"
    write_log Info "The OS Version is $(grep -E '^(VERSION|NAME)=' /etc/os-release)"
    write_log Info "System Information: $(uname -a)"
}

function install_packages
{
    write_log Info "install packages"

    mkdir $DOWNLOAD_DIR
    sudo dnf install -y dotnet-runtime-6.0
    curl $EPEL_KEY_URL --output $DOWNLOAD_DIR/epel-key
    rpmkeys --import $DOWNLOAD_DIR/epel-key
    dnf install $EPEL_PACKAGE_URL -y
    dnf install langpacks-en glibc-all-langpacks -y
    dnf install -y bind-utils

    localectl set-locale LANG=en_US.UTF-8
    yum install -y ipa-selinux
    sudo yum update
    yum install -y pkg-config
    wget https://rpmfind.net/linux/centos-stream/9-stream/BaseOS/x86_64/os/Packages/libsepol-3.4-3.el9.x86_64.rpm
    wget https://rpmfind.net/linux/centos-stream/9-stream/AppStream/x86_64/os/Packages/libsepol-devel-3.4-3.el9.x86_64.rpm
    rpm -Uvh libsepol-devel-3.4-3.el9.x86_64.rpm libsepol-3.4-3.el9.x86_64.rpm
    rpm -qa | grep libsepol

    # gnome
    sudo dnf groupinstall "Server with GUI" -y
    runlevel
    systemctl set-default graphical.target
    systemctl status graphical.target
    systemctl start graphical.target
    systemctl status graphical.target
    runlevel
    lsblk

    # XenDesktopVDA
    rpmkeys --import $INSTALLER_GPG
    rpm --checksig --verbose $INSTALLER_RPM
    sudo yum  -y localinstall $INSTALLER_RPM

}

function deploy_mcs
{
    write_log Info "deploy mcs"

    # force IPv4 stack
    sed -i.bak -e "s/# heap dump on OOM/echo -n \" -Djava.net.preferIPv4Stack=true\"/" /opt/Citrix/VDA/sbin/ctxjproxy

    if [[ "$VDA_AD_INTEGRATION" == "winbind" ]]; then
        sed -i.bak -e "s/dns_lookup_kdc = true/&\n    allow_weak_crypto = true\n/" /etc/xdl/ad_join/winbind_krb5.conf.tmpl
    fi

    if [[ "$VDA_AD_INTEGRATION" == "sssd" ]]; then
        sed -i.bak -e "s/dns_lookup_kdc = true/&\n    allow_weak_crypto = true\n/" /etc/xdl/ad_join/sssd_krb5.conf.tmpl
    fi

    sed -i.bak \
        -e "s/includedir/#&/" \
        -e "s/udp_preference_limit = 0/allow_weak_crypto = true\n#udp_preference_limit = 0/" \
        /etc/krb5.conf

    sed -i.bak \
        -e "s/Use_AD_Configuration_Files_Of_Current_VDA=/&\"N\"/" \
        -e "s/AD_INTEGRATION=/&\"$VDA_AD_INTEGRATION\"/" \
        -e "s/NTP_SERVER=/&\"$NTP_SERVER\"/" \
        -e "s/VDI_MODE=N/VDI_MODE=$VDI_MODE/" \
        -e "s/dns1=/&\"$DNS_IP_ADDRESS\"/" \
        /etc/xdl/mcs/mcs.conf

    sudo /opt/Citrix/VDA/sbin/deploymcs.sh

    # need to prevent a race condition between ad_join and cloud-init
    # this ensures that cloud-init is complete before ad_join processes the instruction/identity disk
    # note: log_info writes to /var/log/ad_join.log
    # restart NetworkManager to set DNS to the proper value via a script added by Citrix 
    # (/etc/NetworkManager/dispatcher.d/15-resolv with values stored in /etc/resolv.conf.custom)
    sed -i.bak -e "s#read_id_disk#    log_info \"\$(cloud-init status --wait)\"\nsystemctl restart NetworkManager;sleep 5;\n    &#" /var/xdl/mcs/ad_join.sh

}

function install_webcam
{
    # setup webcam - https://docs.citrix.com/en-us/linux-virtual-delivery-agent/current-release/configure/multimedia/hdx-webcam-video-compression.html
    sudo /opt/Citrix/VDA/sbin/ctxwcamcfg.sh
}

function main
{
    write_environment
    set -x

    write_log Info "Package check rpm: $INSTALLER_RPM gpg: $INSTALLER_GPG"
    if [[ (-z $INSTALLER_RPM) || (! -f $INSTALLER_GPG) ]]; then
        write_log Error "Required package and/or gpg key not found in $CITRIX_DAAS"; exit 1;
    fi

    install_packages
    deploy_mcs
    install_webcam

    write_log Info "MCS Installation Complete (cloud-init), rebooting... "

    # reboot to finish install
    shutdown -r now

}

main "$@"
