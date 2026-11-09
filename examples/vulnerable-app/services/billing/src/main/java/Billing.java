import java.security.*;
import javax.crypto.Cipher;

public class Billing {
    KeyPair keys() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        return kpg.generateKeyPair();
    }

    byte[] encrypt(PublicKey pub, byte[] data) throws Exception {
        Cipher c = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        c.init(Cipher.ENCRYPT_MODE, pub);
        return c.doFinal(data);
    }

    byte[] sign(PrivateKey k, byte[] data) throws Exception {
        Signature s = Signature.getInstance("SHA256withECDSA");
        s.initSign(k);
        s.update(data);
        return s.sign();
    }

    byte[] fingerprint(byte[] data) throws Exception {
        return MessageDigest.getInstance("MD5").digest(data);
    }
}
