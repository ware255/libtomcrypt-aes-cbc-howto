# libtomcrypt-aes-cbc-howto
LibTomCryptoを使って分かりやすくコードを書きました。AES-256bitのCBCモードを使っています。

# 使い方
コンパイル
```
# gcc aes_cbc.c -o aes_cbc -Ilibtomcrypt/src/headers -Llibtomcrypt -ltomcrypt -Wall
```
