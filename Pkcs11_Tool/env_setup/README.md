1.������װ���ܿ���س���
	���нű� apt-install.sh

1.��װ���ܿ����������P11��
	����HWĿ¼��libfm* �� /usr/lib/Ŀ¼
	HWĿ¼������ install.sh


2.��װlibp11�� app/libp11-master
	./bootstrap
	./config
	make 
	make install

3.��װopensc  app/OpenSC-master
	./bootstrap
	./config
	make
	make install
	
4.��װ engine_pkcs11  app/engine_pkcs11-master
	./bootstrap
	./config
	make 
	make install


5.�ֶ��޸�openssl �����ļ������engine��ص�ѡ�� openssl_cnf
	��1����openssl.conf.single�е�������ӵ���ʹ�õ�openssl�����ļ���
		ͨ�� openssl xxx -config ./openssl.cnf -engine pkcs11 ����
	��2����openssl.cnf.eng �滻openssl Ĭ�������ļ� /etc/ssl/openssl.cnf
		���õ�ʱ����ָ�������ļ�
		openssl xxx -engine pkcs11
		

6.������̵ļ��ܿ�·������������
	echo "export P11_MOD='/usr/lib/libfmpkcs11.so" >> ~/.bashrc