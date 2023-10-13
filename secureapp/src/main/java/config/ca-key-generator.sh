

echo -e "Default passwords are 123456. "

echo -e "--------- Creating Self-Signed CA Certificate ---------"
keytool -genkeypair -keyalg RSA -keysize 2048 -validity 180 -alias ca -dname "CN=ZA, O=SUPER SECURE, C=IT" -keystore KeyStoreCA  -storepass 123456  -keypass 123456
keytool -exportcert -rfc -alias ca -keystore KeyStoreCA -storepass 123456 > ca.cer
echo -e "Created Self-Signed CA Certificate."

echo -e "--------- Creating Server's Certificate  ---------"
keytool -genkeypair -keyalg RSA -keysize 2048 -validity 180 -alias server -dname "CN=ZA, O=Security, C=IT" -keystore KeyStoreServer -storepass 123456  -keypass 123456
keytool -certreq -alias server -storepass 123456 -keystore KeyStoreServer | keytool  -gencert -alias ca -rfc -keystore KeyStoreCA -storepass 123456 > server.cer
cat ca.cer | keytool -importcert -alias ca -noprompt -keystore KeyStoreServer -storepass 123456
cat ca.cer server.cer | keytool -importcert -alias server -keystore KeyStoreServer -storepass 123456
echo -e "Created  Server's Certificate. "

echo -e "--------- Creating Alice's Certificate ---------"
keytool -genkeypair -keyalg RSA -keysize 2048 -validity 180 -alias alice-alias -dname "CN=ZA, O=WC, C=IT" -keystore KeyStoreAlice -storepass 123456  -keypass 123456
keytool -certreq -alias alice-alias -keystore KeyStoreAlice -storepass 123456 | keytool -gencert -alias ca -rfc -keystore KeyStoreCA -storepass 123456 > alice.cer
cat ca.cer | keytool -importcert -alias ca -noprompt -keystore KeyStoreAlice -storepass 123456
cat ca.cer alice.cer | keytool -importcert -alias alice-alias -keystore KeyStoreAlice -storepass 123456
echo -e "Created Alice's Certificate. "

echo -e "--------- Creating Bob's Certificate ---------"
keytool -genkeypair -keyalg RSA -keysize 2048 -validity 180 -alias bob-alias -dname "CN=ZA, O=WC, C=IT" -keystore KeyStoreBob -storepass 123456  -keypass 123456
keytool -certreq -alias bob-alias -keystore KeyStoreBob -storepass 123456 | keytool -gencert -alias ca -rfc -keystore KeyStoreCA -storepass 123456 > bob.cer
cat ca.cer | keytool -importcert -alias ca -noprompt -keystore KeyStoreBob -storepass 123456
cat ca.cer bob.cer | keytool -importcert -alias bob-alias -keystore KeyStoreBob -storepass 123456
echo -e "Created Bob's Certificate. "


echo -e "All certificates and keystores are created and saved. "