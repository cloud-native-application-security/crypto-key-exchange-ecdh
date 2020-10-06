package com.example.util;

import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import org.springframework.security.crypto.codec.Hex;

public class KeyExchange {

  private final KeyPair keyPair;

  public KeyExchange() {
    try {
      var keyPairGenerator = KeyPairGenerator.getInstance("EC");
      keyPairGenerator.initialize(256);
      this.keyPair = keyPairGenerator.generateKeyPair();
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    }
  }

  public String getPublicKey() {
    byte[] publicKey = keyPair.getPublic().getEncoded();
    return Base64.getUrlEncoder().encodeToString(publicKey);
  }

  public byte[] establishAes256bitKey(String peerPublicKeyInBase64Url) {
    try {
      KeyFactory keyFactory = KeyFactory.getInstance("EC");
      var peerPublicKeyBytes = Base64.getUrlDecoder().decode(peerPublicKeyInBase64Url);
      var publicKeySpec = new X509EncodedKeySpec(peerPublicKeyBytes);
      var publicKey = keyFactory.generatePublic(publicKeySpec);

      var keyAgreement = KeyAgreement.getInstance("ECDH");
      keyAgreement.init(keyPair.getPrivate());
      keyAgreement.doPhase(publicKey, true);
      var secret = keyAgreement.generateSecret();

      var secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
      var keySpec = new PBEKeySpec(new String(secret).toCharArray(), secret, 1024, 256);
      return secretKeyFactory.generateSecret(keySpec).getEncoded();

    } catch (NoSuchAlgorithmException | InvalidKeyException | InvalidKeySpecException e) {
      throw new RuntimeException(e);
    }
  }
}
