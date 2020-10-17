package com.example.util;

import static java.nio.charset.StandardCharsets.UTF_8;

import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public class NistP256KeyExchange {

  private final KeyPair keyPair;

  public NistP256KeyExchange() {
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

  public byte[] establishAes256bitKey(String peerPublicKey) {
    try {
      KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH");
      keyAgreement.init(keyPair.getPrivate());

      keyAgreement.doPhase(fromBase64(peerPublicKey), true);
      byte[] secret = keyAgreement.generateSecret();

      return deriveAES256bitKey(secret);
    } catch (NoSuchAlgorithmException | InvalidKeyException | InvalidKeySpecException e) {
      throw new RuntimeException(e);
    }
  }

  private byte[] deriveAES256bitKey(byte[] secret)
      throws NoSuchAlgorithmException, InvalidKeySpecException {
    var secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
    var password = new String(secret, UTF_8).toCharArray();
    var keySpec = new PBEKeySpec(password, secret, 1024, 256);
    return secretKeyFactory.generateSecret(keySpec).getEncoded();
  }

  private PublicKey fromBase64(String peerPublicKeyInBase64Url)
      throws NoSuchAlgorithmException, InvalidKeySpecException {
    KeyFactory keyFactory = KeyFactory.getInstance("EC");
    var peerPublicKeyBytes = Base64.getUrlDecoder().decode(peerPublicKeyInBase64Url);
    var publicKeySpec = new X509EncodedKeySpec(peerPublicKeyBytes);
    return keyFactory.generatePublic(publicKeySpec);
  }
}
