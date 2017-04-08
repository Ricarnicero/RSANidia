package RSA;
import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.*;
import java.security.spec.*;
import java.util.logging.*;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/*
Atributos:
RSAPublicKey Guarda la llave pública.
RSAPrivateKey Guarda la llave privada.

Constructor:
    1.- Recibe el nombre (String) del archivo .key y genera las llaves. /
        (el archivo debe de tener en la primera linea el modulo y en
        la sagunda linea debede tener el exponente)
    2.- Recibe el modulo y el exponente para generar las llaves./
    3.- Recibe las llaves y las guarda. /
    4.- No recibe nada. Inicializa todo en null. /

Metodos:
-generatePublicKey recibe dos BigInteger; el modulo y el exponente. Retorna un RSAPublicKey.
-generatePrivateKey recibe dos BigInteger; el modulo y el exponente. Retorna un RSAPrivateKey.
-Cifrar recibe un arreglo de byte con el contenido a cifrar y retorna el contenido cifrado.
-Descifrar recibe un arreglo de bytes cifrados y retorna el contenido cifrado en un arreglo de bytes.
*/
public class RSA {
    private RSAPublicKey pubKey;
    private RSAPrivateKey privKey;
    
    public RSA(BigInteger modulus, BigInteger publicExponent){
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            RSAPublicKeySpec pubKeySpec = new RSAPublicKeySpec(modulus,publicExponent);
            RSAPrivateKeySpec privKeySpec = new RSAPrivateKeySpec(modulus,publicExponent);
            privKey = (RSAPrivateKey) keyFactory.generatePrivate(privKeySpec);
            pubKey = (RSAPublicKey) keyFactory.generatePublic(pubKeySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException ex) {
            Logger.getLogger(RSA.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    public RSA(String Archivo){
        BufferedReader br = null;
        String str;

        try {
            br = new BufferedReader (new FileReader (Archivo));
            str = br.readLine();
            BigInteger modulus = new BigInteger(str);
            str = br.readLine();
            BigInteger publicExponent = new BigInteger(str);
            pubKey = generatePublicKey(modulus,publicExponent);
            privKey = generatePrivateKey(modulus,publicExponent);
        } catch (FileNotFoundException ex) {
            Logger.getLogger(RSA.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(RSA.class.getName()).log(Level.SEVERE, null, ex);
        } finally {
            try {
                br.close();
            } catch (IOException ex) {
                Logger.getLogger(RSA.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
    }
    public RSA (RSAPublicKey pubKey, RSAPrivateKey privKey){
        this.pubKey = pubKey;
        this.privKey = privKey;
    }
    
    public RSA(){
        pubKey = null;
        privKey = null;
    }
    public final RSAPublicKey generatePublicKey(BigInteger modulus, BigInteger publicExponent){
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            RSAPublicKeySpec pubKeySpec = new RSAPublicKeySpec(modulus,publicExponent);
            pubKey = (RSAPublicKey) keyFactory.generatePublic(pubKeySpec);            
            return pubKey;            
        } catch (NoSuchAlgorithmException | InvalidKeySpecException ex) {
            Logger.getLogger(RSA.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }
    
    public final RSAPrivateKey generatePrivateKey(BigInteger modulus, BigInteger publicExponent){
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            RSAPrivateKeySpec privKeySpec = new RSAPrivateKeySpec(modulus,publicExponent);
            privKey = (RSAPrivateKey) keyFactory.generatePrivate(privKeySpec);
            return privKey;
        } catch (NoSuchAlgorithmException | InvalidKeySpecException ex) {
            Logger.getLogger(RSA.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }
    
    public byte[] Cifrar(byte[] texto){
        try {
            if(pubKey!=null){
                Cipher cipher = Cipher.getInstance("RSA");
                byte[] cifrado;
                cipher.init(Cipher.ENCRYPT_MODE, pubKey);
                cifrado = cipher.doFinal(texto);
                return cifrado;
            }
            else{
                System.out.println("The public key is no inicializated");
            }
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException ex) {
            Logger.getLogger(RSA.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }
    
    public byte[] Descifrar(byte[] texto){
        try {
            if(privKey!=null){
                Cipher cipher = Cipher.getInstance("RSA");
                byte[] descifrado;
                cipher.init(Cipher.DECRYPT_MODE, privKey);
                descifrado = cipher.doFinal(texto);
                return descifrado;
            }
            else{
                System.out.println("The private Key is not inicializated");
            }
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException ex) {
            Logger.getLogger(RSA.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }
}
