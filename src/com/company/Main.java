package com.company;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Enumeration;
import java.util.Scanner;

public class Main {

    public static void main(String[] args) throws Exception {

        ej1();
        ej2();
        ej2_clauEmbolcallada();

    }

    public static void ej1(){

        System.out.println("------------------- Se abre el telón -------------------");

        Scanner scanner = new Scanner(System.in);
        KeyPair keys = Xifrar.randomGenerate(1024);

        String miFrase = "Vivimos en una simulación";
        byte[] frase = miFrase.getBytes();
        byte[] fraseCifrada = Xifrar.encryptData(frase, keys.getPublic());
        byte[] fraseDescifrada = Xifrar.decryptData(fraseCifrada, keys.getPrivate());

        System.out.println("Frase encriptada: " + new String(fraseCifrada));
        System.out.println("Frase desencriptada: " + new String(fraseDescifrada));

        System.out.println("---------------- Siguiente ejercicio ----------------");

        keys.getPrivate();
        keys.getPublic();

        System.out.println();
        System.out.println("Introdueix el missatge a xifrar: ");
        String mensaje = scanner.nextLine();

        byte[] mensajeEncrypt = Xifrar.encryptData(mensaje.getBytes(),keys.getPublic());
        System.out.println("Encrypt: " + mensaje);

        byte[] mensajeDecrypt = Xifrar.decryptData(mensajeEncrypt,keys.getPrivate());
        String text = new String(mensajeDecrypt, StandardCharsets.UTF_8);
        System.out.println("Decrypt: " + text);

        System.out.println("---------------- Siguiente ejercicio ----------------");

        System.out.println();
        System.out.println("Utilizando getPublic: ");
        System.out.println(keys.getPublic().getAlgorithm());
        System.out.println(keys.getPublic().getEncoded());
        System.out.println(keys.getPublic().getClass());
        System.out.println("Utilizando getPrivate: ");
        System.out.println(keys.getPrivate().getAlgorithm());
        System.out.println(keys.getPrivate().getEncoded());
        System.out.println(keys.getPrivate().getClass());

        System.out.println("------------------- Se cierra el telón -------------------");

    }

    public static void ej2() throws Exception {

        System.out.println();
        System.out.println("------------------- Se abre el telón -------------------");
        KeyStore keyStore = Xifrar.loadKeyStore("C:\\Users\\Selvi\\Desktop\\M09\\keystore_elvis.ks", "usuario");

        // Tipus de keystore que és (JKS, JCEKS, PKCS12, ...)
        System.out.println("Tipos de keystore: " + keyStore.getType());

        // Mida del magatzem (quantes claus hi ha?)
        System.out.println("Tamaño: " + keyStore.size());

        // Àlies de totes les claus emmagatzemades
        System.out.print("Alies de les claus: ");

        Enumeration<String> alias = keyStore.aliases();

        while(alias.hasMoreElements()){
            System.out.print("\n" + alias.nextElement() + ",");
            System.out.println();
        }

        System.out.println("Certificado de una clau: " + keyStore.getCertificate("lamevaclaum9"));

        System.out.println("Algoritmo de 'lamevaclaum9' !!: " + keyStore.getCertificate("lamevaclaum9").getPublicKey().getAlgorithm());

        System.out.println();
        System.out.println("---------------- Siguiente ejercicio ----------------");

        SecretKey secretKey = Xifrar.keygenKeyGeneration(128);

        char[] contraseña = "usuario".toCharArray();
        KeyStore.SecretKeyEntry secretKeyEntry = new KeyStore.SecretKeyEntry(secretKey);
        KeyStore.ProtectionParameter protectionParameter = new KeyStore.PasswordProtection(contraseña);

        try {
            keyStore.setEntry("newKey",secretKeyEntry,protectionParameter);
            FileOutputStream fileOutputStream = new FileOutputStream("C:\\Users\\Selvi\\Desktop\\M09\\keystore_elvis.ks");
            keyStore.store(fileOutputStream,"usuario".toCharArray());
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        }

        // para comprobar que el ejercicio esta correcto y que realmente se ha creado "newKey" ->
        System.out.println("Listado: ");
        Enumeration<String> comprobador = keyStore.aliases();
        while(comprobador.hasMoreElements()){
            System.out.print(comprobador.nextElement() + " ");
            System.out.println();
        }

        System.out.println();
        System.out.println("---------------- Siguiente ejercicio ----------------");
        try {
            PublicKey publicKey = Xifrar.getPublicKey("C:\\Users\\Selvi\\Desktop\\M09\\jordi.cer");
            System.out.println(publicKey);
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (FileNotFoundException e) {
            System.out.println("FILE NOT FOUND");
        }

        System.out.println("---------------- Siguiente ejercicio ----------------");
        String path = "C:\\Users\\Selvi\\Desktop\\M09\\keystore_elvis.ks";
        String password = "usuario";
        try {
            KeyStore ks = Xifrar.loadKeyStore(path, password);
            System.out.println(Xifrar.getPublicKey(ks, "lamevaclaum9", password));
        } catch (Exception e) {
            e.printStackTrace();
        }
        System.out.println();
        System.out.println("---------------- Siguiente ejercicio ----------------");
        byte[] texto = "Buenas profe".getBytes();
        KeyPair keyPair = Xifrar.randomGenerate(1024);

        System.out.println("Firmado: ");
        System.out.println(new String(Xifrar.signData(texto, keyPair.getPrivate())));

        System.out.println();
        System.out.println("---------------- Siguiente ejercicio ----------------");
        KeyPair kp = Xifrar.randomGenerate(1024);
        byte[] datos = "BUENAS".getBytes();
        byte[] signatura = Xifrar.signData(datos, kp.getPrivate());

        //nos tiene que devolver o true o false

        boolean validacion = Xifrar.validateSignature(datos, signatura, kp.getPublic());
        System.out.println(validacion);
        System.out.println("------------------- Se cierra el telón -------------------");
    }

    public static void ej2_clauEmbolcallada(){
        System.out.println();
        System.out.println("------------------- Se abre el telón -------------------");
        System.out.println("Apartado de comentarios en el codigo -> ");
        System.out.println();
        System.out.println("encryptWrappedData Y decryptWrappedData");
        /*
        public static byte[][] encryptWrappedData(byte[] data, PublicKey pub){
            byte[][] encWrappedData = new byte[2][];
            //------------- Se cifran las datos -------------
            byte[][] encWrappedData = new byte[2][];
            try {
                //------------- Generamos una clave -------------
                KeyGenerator kgen = KeyGenerator.getInstance("AES");
                kgen.init(128);
                SecretKey sKey = kgen.generateKey();
                //------------- Con esa sKey se encripta el mensaje -------------
                //------------- Algoritmo de cifrado -------------
                Cipher cipher = Cipher.getInstance("AES");
                cipher.init(Cipher.ENCRYPT_MODE, sKey);
                byte[] encMsg = cipher.doFinal(data);
                //------------- Utilizamos la clave publica de la clave asimétrica de sKey -------------
                cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                cipher.init(Cipher.WRAP_MODE, pub);
                //------------- llave cifrada -------------
                byte[] encKey = cipher.wrap(sKey);
                //------------- datos cifrados -------------
                encWrappedData[0] = encMsg;
                encWrappedData[1] = encKey;
            } catch (Exception ex) {
                System.err.println("Ha succeït un error xifrant: " + ex);
            }
            //------------- return de encMsg (mensaje encriptado) y la secretkey -------------
            return encWrappedData;
        }

         */

        /*
        public static byte[][] decryptWrappedData(byte[][] data, PublicKey priv) {
            byte[] msgDes = null;
            try {
                //WRAPPED de la clave simetrica con la clave priv
                Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                cipher.init(Cipher.UNWRAP_MODE, priv);
                Key decryptKey = cipher.unwrap(data[1], "AES", Cipher.SECRET_KEY);

                //Desencriptamos el mensaje
                cipher = Cipher.getInstance("AES");
                cipher.init(Cipher.DECRYPT_MODE, decryptKey);
                msgDes = cipher.doFinal(data[0]);

            } catch (Exception ex) {
                System.err.println("Ha succeït un error desxifrant: " + ex);
            }
            //return del mensaje descifrado
            return msgDes;
        }
        */
        System.out.println("---------------- Siguiente ejercicio ----------------");

        KeyPair keyPairNew = Xifrar.randomGenerate(1024);

        String texto = "Mensaje";

        PrivateKey privatekey = keyPairNew.getPrivate();
        PublicKey publickey = keyPairNew.getPublic();

        byte [][] encWrappedData = Xifrar.encryptWrappedData(texto.getBytes(), publickey);
        System.out.println("ENCRYPT MNSJ: " + new String(encWrappedData[0]));
        System.out.println();
        byte[] decWrapedData = Xifrar.decryptWrappedData(encWrappedData, privatekey);
        System.out.println("ORIGINAL MNSJ: " + new String(decWrapedData));
        System.out.println();
        System.out.println("FINISHED");
        System.out.println("------------------- Se cierra el telón -------------------");
    }
}

