1.联网安装加密卡相关程序
	运行脚本 apt-install.sh

1.安装加密卡驱动程序和P11库
	拷贝HW目录下libfm* 到 /usr/lib/目录
	HW目录下运行 install.sh


2.安装libp11库 app/libp11-master
	./bootstrap
	./config
	make 
	make install

3.安装opensc  app/OpenSC-master
	./bootstrap
	./config
	make
	make install
	
4.安装 engine_pkcs11  app/engine_pkcs11-master
	./bootstrap
	./config
	make 
	make install


5.手动修改openssl 配置文件，添加engine相关的选项 openssl_cnf
	（1）将openssl.conf.single中的内容添加到待使用的openssl配置文件中
		通过 openssl xxx -config ./openssl.cnf -engine pkcs11 调用
	（2）用openssl.cnf.eng 替换openssl 默认配置文件 /etc/ssl/openssl.cnf
		调用的时候不用指定配置文件
		openssl xxx -engine pkcs11
		

6.添加渔翁的加密库路径到环境变量
	echo "export P11_MOD='/usr/lib/libfmpkcs11.so" >> ~/.bashrc