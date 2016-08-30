#!/bin/bash

RootDir=`pwd`

#[1]
echo "Start apt-install"
cd $RootDir/apt-depends
chmod +x apt-install.sh

./apt-install.sh 1>>/dev/null || exit 1

#[2]
echo "Start Install CA hardware pkcs11"
cd $RootDir/HW
chmod 777 *
cp lib* /usr/lib/
./install.sh
echo "Install FM Driver OK"


#[2-1]
#Set it to boot
cp $RootDir/HW /usr/app/HW -r || exit 1
sed -i /etc/init.d/rc.local  -e '/install_hw/d'
echo "bash /usr/app/HW/install_hw.sh" >> /etc/init.d/rc.local

#exit 1



#[3] Install libp11
cd $RootDir/app/libp11-master
chmod +x bootstrap
./bootstrap
./configure
make
make install

#[4] Install OpenSC
cd $RootDir/app/OpenSC-master
chmod +x bootstrap
./bootstrap
./configure
make
make install

#[5] Install engine_pkcs11
cd $RootDir/app/engine_pkcs11-master
chmod +x bootstrap
./bootstrap
./configure
make
make install

#[6] Set bashrc
sed -i /etc/profile  -e '/P11_MOD/d'
echo "export P11_MOD='/usr/lib/libfmpkcs11.so'" >> /etc/profile
source /etc/profile

#[7] cp config file
#cd $RootDir/openssl_cnf
#cp openssl.cnf.eng /etc/ssl/openssl.cnf
