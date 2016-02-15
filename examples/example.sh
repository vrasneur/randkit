#!/bin/bash

echo "[*] reloading the module"
sudo rmmod randkit_xor128
sudo insmod ../xor128/randkit_xor128.ko

echo "[*] cleaning files from previous run"
rm -f mykey encrypted.enc decrypted.txt

echo "[*] generating 5KB of random numbers"
dd if=/dev/urandom of=/dev/null bs=5K count=1

echo "[*] generating the GPG symmetric key"
head -c 16 </dev/urandom >mykey

echo "[*] encrypting data"
cat mykey | gpg --symmetric --passphrase-fd 0 --cipher-algo AES256 --output encrypted.enc original.txt

echo "[*] deleting the key"
rm -f mykey

echo "[*] generating 5KB of random numbers again"
dd if=/dev/urandom of=/dev/null bs=5K count=1

echo "[*] decrypt the data by reversing the PRNG to retrieve the key"
echo "[*] this should take approx. 1280 iterations"
python unrandom.py encrypted.enc decrypted.txt

echo "[*] comparing the original and decrypted files:"
diff original.txt decrypted.txt

if (( $? == 0 )); then
    echo "[*] Success. Files are equal!"
else
    echo "[!] Failure. Files are not equal!"
fi
