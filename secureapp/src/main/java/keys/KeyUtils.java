package keys;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jcajce.provider.asymmetric.X509;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;

public class KeyUtils {

//    public static KeyPair generateAndWriteRSAKeyPair(String name) throws Exception {
//
//
//        File currentDirectory = new File(".");
//
//        // Get a list of all files in the current directory.
//        File[] files = currentDirectory.listFiles();
//
//        // Iterate over the list of files and print out the name of each file.
//        for (File file : files) {
//            System.out.println(file.getName());
//        }
//
//        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
//        keyPairGenerator.initialize(2048);
//        KeyPair keyPair = keyPairGenerator.generateKeyPair();
//
//        // Write the public key to the file
//        FileWriter pubWriter = new FileWriter("./public/"+name+"_public.pem");
//        String encodedPublicKey = Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
//
//        // Write the public key to the file
//        pubWriter.write(encodedPublicKey);
//        pubWriter.close();
//
//        // Write the private key to the file
//        FileWriter privateWriter = new FileWriter("./private/"+name+"_private.pem");
//        String encodedPrivateKey = Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
//        privateWriter.write(encodedPrivateKey);
//        privateWriter.close();
//
//        return keyPair;
//    }

    public static PublicKey readPublicKey(String name) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {

        String publicKeyString = new String(Files.readAllBytes(Path.of("secureapp/src/main/java/keys/public/"+name+"_public_key"+".pem")));

        // Create a PEMParser object.
        PEMParser pemParser = new PEMParser(new StringReader(publicKeyString));

        // Read the public key from the PEMParser object.
        Object publicKeyObject = pemParser.readObject();

        // Convert the public key object to a Java PublicKey object.
        JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
        PublicKey publicKey = converter.getPublicKey((SubjectPublicKeyInfo) publicKeyObject);
        System.out.println(publicKey);

        return publicKey;
    }

    public static PrivateKey readPrivateKey(String name) throws IOException {

        String privateKeyString = new String(Files.readAllBytes(Path.of("secureapp/src/main/java/keys/private/"+name+"_private_key"+".pem")));

        // Create a PEMParser object.
        PEMParser pemParser = new PEMParser(new StringReader(privateKeyString));

        // Read the private key from the PEMParser object.
        Object privateKeyObject = pemParser.readObject();

        // Convert the private key object to a Java PrivateKey object.
        JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
        PrivateKey privateKey = converter.getPrivateKey((PrivateKeyInfo) privateKeyObject);

        System.out.println(privateKey);
        return privateKey;
    }

    public static X509Certificate readX509Certificate(String name) throws CertificateException, IOException {
        File certFile = new File("secureapp/src/main/java/keys/certificates/" + name+ "-cert.pem");
        CertificateFactory certFactory = null;
        X509Certificate outputCert = null;
        if (!certFile.exists()) {
            throw new FileNotFoundException("Certificate file not found");
        }
        try (FileInputStream fileInput = new FileInputStream(certFile)) {
            try {
                certFactory = CertificateFactory.getInstance("X.509", "BC");
                outputCert = (X509Certificate) certFactory.generateCertificate(fileInput);
            } catch (NoSuchProviderException e) {
                System.err.println(e.getMessage());;
            }
        }
        if (name == "alice") {
            System.out.println(outputCert.toString());
        }
        return outputCert;
    }
}
