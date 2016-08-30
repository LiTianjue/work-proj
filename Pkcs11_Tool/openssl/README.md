
# 1.格式转换(format)
## 1.1 合成p12文件
	合成pkcs12文件	create_pfx.sh


## 1.2 PEM编码转DER编码
	证书格式转换	pem2der_cert.sh
	秘钥格式转换　　pem2der_key.sh


# 2.engineCA
	使用卡内秘钥生成证书请求		p11_req.sh
	使用卡内秘钥做自签名证书		engine_self_ca.sh
	使用卡内秘钥签名用户证书请求	sign_client.sh


