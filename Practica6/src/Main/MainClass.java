
package Main;
import RSA.RSA;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class MainClass {
     public static void main(String[] args) throws Exception{
        RSA h;
        //Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        byte[] input = new byte[] { (byte) 0xbe, (byte) 0xef };
        byte[] cifrado;
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.genKeyPair();
        Key pubKey = kp.getPublic();
        Key privKey = kp.getPrivate();
         try {//probar cifrado manual
            if(pubKey!=null){
                Cipher cipher = Cipher.getInstance("RSA");
                cipher.init(Cipher.ENCRYPT_MODE, pubKey);
                cifrado = cipher.doFinal(input);
            }
            else{
                System.out.println("The public key is no inicializated");
            }
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException ex) {
            Logger.getLogger(RSA.class.getName()).log(Level.SEVERE, null, ex);
        }
        System.out.printf("Cifrar: " + new String(input));
        System.out.printf("Cifrado: " + new String(cifrado));
        //System.out.println("Descifrado" + new String(res2));
    }
}
