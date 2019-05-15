#!/bin/bash

function Welcome()
{
clear
echo -n "                      Local Time :   " && date "+%F [%T]       ";
echo "            ======================================================";
echo "            |                    serverSpeeder                   |";
echo "            |                                         for Linux  |";
echo "            |----------------------------------------------------|";
echo "            |                                       -- By .Vicer |";
echo "            ======================================================";
echo "";
rootness;
mkdir -p /tmp
cd /tmp
}

function rootness()
{
if [[ $EUID -ne 0 ]]; then
   echo "Error:This script must be run as root!" 1>&2
   exit 1
fi
}

function pause()
{
read -n 1 -p "Press Enter to Continue..." INP
if [ "$INP" != '' ] ; then
echo -ne '\b \n'
echo "";
fi
}

function Check()
{
echo 'Preparatory work...'
apt-get >/dev/null 2>&1
[ $? -le '1' ] && apt-get -y -qq install grep unzip ethtool >/dev/null 2>&1
yum >/dev/null 2>&1
[ $? -le '1' ] && yum -y -q install which sed grep awk unzip ethtool >/dev/null 2>&1
[ -f /etc/redhat-release ] && KNA=$(awk '{print $1}' /etc/redhat-release)
[ -f /etc/os-release ] && KNA=$(awk -F'[= "]' '/PRETTY_NAME/{print $3}' /etc/os-release)
[ -f /etc/lsb-release ] && KNA=$(awk -F'[="]+' '/DISTRIB_ID/{print $2}' /etc/lsb-release)
KNB=$(getconf LONG_BIT)
ifconfig >/dev/null 2>&1
[ $? -gt '1' ] && echo -ne "I can not run 'ifconfig' successfully! \nPlease check your system, and try again! \n\n" && exit 1;
[ ! -f /proc/net/dev ] && echo -ne "I can not find network device! \n\n" && exit 1;
[ -n "$(grep 'eth0:' /proc/net/dev)" ] && Eth=eth0 || Eth=`cat /proc/net/dev |awk -F: 'function trim(str){sub(/^[ \t]*/,"",str); sub(/[ \t]*$/,"",str); return str } NR>2 {print trim($1)}'  |grep -Ev '^lo|^sit|^stf|^gif|^dummy|^vmnet|^vir|^gre|^ipip|^ppp|^bond|^tun|^tap|^ip6gre|^ip6tnl|^teql|^venet' |awk 'NR==1 {print $0}'`
[ -z "$Eth" ] && echo "I can not find the server pubilc Ethernet! " && exit 1
URLKernel='https://raw.githubusercontent.com/0oVicero0/serverSpeeder_kernel/master/serverSpeeder.txt'
AcceVer=$(wget --no-check-certificate -qO- "$URLKernel" |grep "$KNA/" |grep "/x$KNB/" |grep "/$KNK/" |awk -F'/' '{print $NF}' |sort -n -k 2 -t '_' |tail -n 1)
MyKernel=$(wget --no-check-certificate -qO- "$URLKernel" |grep "$KNA/" |grep "/x$KNB/" |grep "/$KNK/" |grep "$AcceVer" |tail -n 1)
[ -z "$MyKernel" ] && echo -ne "Kernel not be matched! \nYou should change kernel manually, and try again! \n\nView the link to get detaits: \n"$URLKernel" \n\n\n" && exit 1
pause;
}

function SelectKernel()
{
KNN=$(echo $MyKernel |awk -F '/' '{ print $2 }') && [ -z "$KNN" ] && Uninstall && echo "Error,Not Matched! " && exit 1
KNV=$(echo $MyKernel |awk -F '/' '{ print $5 }') && [ -z "$KNV" ] && Uninstall && echo "Error,Not Matched! " && exit 1
wget --no-check-certificate -q -O "/tmp/appex/apxfiles/bin/acce-"$KNV"-["$KNA"_"$KNN"_"$KNK"]" "https://raw.githubusercontent.com/0oVicero0/serverSpeeder_kernel/master/$MyKernel"
[ ! -f "/tmp/appex/apxfiles/bin/acce-"$KNV"-["$KNA"_"$KNN"_"$KNK"]" ] && Uninstall && echo "Download Error,Not Found acce-$KNV-[$KNA_$KNN_$KNK]! " && exit 1
}

function Install()
{
Welcome;
Check;
ServerSpeeder;
dl-Lic;
bash /tmp/appex/install.sh
rm -rf /tmp/appex* >/dev/null 2>&1
clear
bash /appex/bin/serverSpeeder.sh status
exit 0
}

function Uninstall()
{
chattr -R -i /appex >/dev/null 2>&1
[ -d /etc/rc.d ] && rm -rf /etc/rc.d/init.d/serverSpeeder >/dev/null 2>&1
[ -d /etc/rc.d ] && rm -rf /etc/rc.d/rc*.d/*serverSpeeder >/dev/null 2>&1
[ -d /etc/rc.d ] && rm -rf /etc/rc.d/init.d/lotServer >/dev/null 2>&1
[ -d /etc/rc.d ] && rm -rf /etc/rc.d/rc*.d/*lotServer >/dev/null 2>&1
[ -d /etc/init.d ] && rm -rf /etc/init.d/serverSpeeder >/dev/null 2>&1
[ -d /etc/init.d ] && rm -rf /etc/rc*.d/*serverSpeeder >/dev/null 2>&1
[ -d /etc/init.d ] && rm -rf /etc/init.d/lotServer >/dev/null 2>&1
[ -d /etc/init.d ] && rm -rf /etc/rc*.d/*lotServer >/dev/null 2>&1
rm -rf /etc/lotServer.conf >/dev/null 2>&1
rm -rf /etc/serverSpeeder.conf >/dev/null 2>&1
[ -f /appex/bin/lotServer.sh ] && bash /appex/bin/lotServer.sh uninstall -f >/dev/null 2>&1
[ -f /appex/bin/serverSpeeder.sh ] && bash /appex/bin/serverSpeeder.sh uninstall -f >/dev/null 2>&1
rm -rf /appex >/dev/null 2>&1
rm -rf /tmp/appex* >/dev/null 2>&1
echo -ne 'serverSpeeder has been removed! \n\n\n'
exit 0
}

function dl-Lic()
{
chattr -R -i /appex >/dev/null 2>&1
rm -rf /appex >/dev/null 2>&1
mkdir -p /appex/etc
mkdir -p /appex/bin
MAC=$(ifconfig "$Eth" |awk '/HWaddr/{ print $5 }')
[ -z "$MAC" ] && MAC=$(ifconfig "$Eth" |awk '/ether/{ print $2 }')
[ -z "$MAC" ] && Uninstall && echo "Not Found MAC address! " && exit 1
wget --no-check-certificate -q -O "/appex/etc/apx.lic" "http://serverspeeder.azurewebsites.net/lic?mac=$MAC"
[ "$(du -b /appex/etc/apx.lic |awk '{ print $1 }')" -ne '152' ] && Uninstall && echo "Error! I can not generate the Lic for you, Please try again later! " && exit 1
echo "Lic generate success! "
[ -n $(which ethtool) ] && rm -rf /appex/bin/ethtool && cp -f $(which ethtool) /appex/bin
}

function ServerSpeeder()
{
[ ! -f /tmp/appex.zip ] && wget --no-check-certificate -q -O "/tmp/appex.zip" "https://raw.githubusercontent.com/0oVicero0/serverSpeeder_Install/master/appex.zip"
[ ! -f /tmp/appex.zip ] && Uninstall && echo "Error,Not Found appex.zip! " && exit 1
mkdir -p /tmp/appex
unzip -o -d /tmp/appex /tmp/appex.zip
SelectKernel;
APXEXE=$(ls -1 /tmp/appex/apxfiles/bin |grep 'acce-')
sed -i "s/^accif\=.*/accif\=\"$Eth\"/" /tmp/appex/apxfiles/etc/config
sed -i "s/^apxexe\=.*/apxexe\=\"\/appex\/bin\/$APXEXE\"/" /tmp/appex/apxfiles/etc/config
}

[ $# == '1' ] && [ "$1" == 'install' ] && KNK="$(uname -r)" && Install;
[ $# == '1' ] && [ "$1" == 'uninstall' ] && Welcome && pause && Uninstall;
[ $# == '2' ] && [ "$1" == 'install' ] && KNK="$2" && Install;
echo -ne "Usage:\n     bash $0 [install |uninstall |install '{serverSpeeder of Kernel Version}']\n"
