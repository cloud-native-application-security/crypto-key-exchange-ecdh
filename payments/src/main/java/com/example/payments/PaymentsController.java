package com.example.payments;

import com.example.util.CryptoUtils;
import com.example.util.KeyExchange;
import java.util.Base64;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

@RestController
public class PaymentsController {

  @GetMapping("/")
  public String processRefunds() {

    var keyExchange = new KeyExchange();
    var request = new ReportRequest();
    request.setPublicKey(keyExchange.getPublicKey());

    var restTemplate = new RestTemplate();
    var response =
        restTemplate.postForObject("http://localhost:8082/refunds", request, ReportResponse.class);
    var decryptionKey = keyExchange.establishAes256bitKey(response.getPublicKey());
    var refundsJson = CryptoUtils.decryptJwe(response.getReport(), decryptionKey);

    System.out.println(
        "Decrypted refunds with key: " + Base64.getUrlEncoder().encodeToString(decryptionKey));
    System.out.println("Processing Refunds for ...");
    System.out.println(refundsJson);
    return refundsJson;
  }
}
