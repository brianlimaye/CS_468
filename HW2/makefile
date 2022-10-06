all: AES256_CBC_Enc AES256_CBC_Dec DES_ECB_Enc DES_ECB_Dec

DES_ECB_Enc: DES_ECB_Enc.c
	gcc -o DES_ECB_Enc -lcrypto -lssl DES_ECB_Enc.c

DES_ECB_Dec: DES_ECB_Dec.c
	gcc -o DES_ECB_Dec -lcrypto -lssl DES_ECB_Dec.c

AES256_CBC_Enc: AES256_CBC_Enc.c
	gcc -o AES256_CBC_Enc -lcrypto -lssl AES256_CBC_Enc.c

AES256_CBC_Dec: AES256_CBC_Dec.c
	gcc -o AES256_CBC_Dec -lcrypto -lssl AES256_CBC_Dec.c

clean:
	rm -rf DES_ECB_Enc DES_ECB_Dec AES256_CBC_Enc AES256_CBC_Dec CS468-HW2.mydesecb CS468-HW2-mydesecb.txt CS468-HW2.myaes256 CS468-HW2-myaes256.txt
