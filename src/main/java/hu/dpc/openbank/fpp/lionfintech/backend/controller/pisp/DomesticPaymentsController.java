/*
 * This Source Code Form is subject to the terms of the Mozilla
 * Public License, v. 2.0. If a copy of the MPL was not distributed
 * with this file, You can obtain one at
 *
 * https://mozilla.org/MPL/2.0/.
 */

package hu.dpc.openbank.fpp.lionfintech.backend.controller.pisp;


import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import hu.dpc.common.http.HttpHelper;
import hu.dpc.common.http.HttpResponse;
import hu.dpc.common.http.HttpUtils;
import hu.dpc.openbank.apigateway.entities.accounts.UpdateConsentResponse;
import hu.dpc.openbank.exceptions.APICallException;
import hu.dpc.openbank.fpp.lionfintech.backend.controller.WSO2Controller;
import hu.dpc.openbank.fpp.lionfintech.backend.enity.bank.BankInfo;
import hu.dpc.openbank.fpp.lionfintech.backend.enity.bank.PaymentConsent;
import hu.dpc.openbank.fpp.lionfintech.backend.repository.BankConfigException;
import hu.dpc.openbank.fpp.lionfintech.backend.repository.PaymentConsentRepository;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import javax.annotation.CheckForNull;
import javax.annotation.Nonnull;
import javax.persistence.EntityNotFoundException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.User;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;
import uk.org.openbanking.v3_1_2.accounts.OBReadConsentResponse1;
import uk.org.openbanking.v3_1_2.accounts.OBReadConsentResponse1Data;
import uk.org.openbanking.v3_1_2.payments.OBWriteDomesticConsentResponse3;
import uk.org.openbanking.v3_1_2.payments.OBWriteDomesticResponse3;

@Slf4j
@RestController
@RequestMapping(path = "/pisp/v1/")
public class DomesticPaymentsController extends WSO2Controller {

  private final ObjectMapper mapper;
  private final PaymentConsentRepository paymentConsentRepository;


  public DomesticPaymentsController(final PaymentConsentRepository paymentConsentRepository, final ObjectMapper mapper) {
    this.paymentConsentRepository = paymentConsentRepository;
    this.mapper = mapper;
  }


  /**
   * Initialize payment and get payment details (eg. cost)
   */
  @CheckForNull
  private static OBWriteDomesticConsentResponse3 initializePayment(final BankInfo bankInfo, final String consentId, final String userName) {
    try {
      final Map<String, String> headers = new HashMap<>();
      headers.put("Accept", "application/json");
      headers.put("Content-Type", "application/json");
      headers.put("x-fapi-interaction-id", UUID.randomUUID().toString());
      headers.put("user-id", userName);
      headers.put("consent-id", consentId);
      // Init consent
      final HttpResponse initPaymentResult = HttpUtils.call(
          HttpMethod.POST,
          HttpResponse.class,
          bankInfo.getGatewayUrl() + "/pis-consents/" + consentId,
          headers,
          null);
      final int initPaymentResponseCode = initPaymentResult.getHttpResponseCode();
      if (initPaymentResponseCode < 200 || initPaymentResponseCode >= 300) {
        log.error("Payment initialisation error!");
        return null;
      }
      // Get consent
      return HttpUtils.doGET(OBWriteDomesticConsentResponse3.class, bankInfo
          .getGatewayUrl() + "/pis-consents/" + consentId, headers);
    } catch (final Exception e) {
      log.error("Something went wrong!", e);
    }

    return null;
  }


  /**
   * Update payment consent
   */
  private UpdateConsentResponse updateConsent(final BankInfo bankInfo, final String consentId, final String userName,
      final boolean accept) throws ResponseStatusException {
    final Map<String, String> headers = new HashMap<>();
    headers.put("Accept", "application/json");
    headers.put("Content-Type", "application/json");
    headers.put("x-fapi-interaction-id", UUID.randomUUID().toString());
    headers.put("user-id", userName);
    headers.put("consent-id", consentId);

    final OBReadConsentResponse1 updateConsentRequest = new OBReadConsentResponse1();
    final OBReadConsentResponse1Data data = new OBReadConsentResponse1Data();
    data.setConsentId(consentId);
    data.setAction(accept ? "Authorize" : "Reject");
    updateConsentRequest.setData(data);

    try {
      final String json = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(updateConsentRequest);
      return HttpUtils.call(
          HttpMethod.PUT,
          UpdateConsentResponse.class,
          bankInfo.getGatewayUrl() + "/pis-consents/" + consentId,
          headers,
          json);
    } catch (final JsonProcessingException e) {
      throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Error while producing JSON content", e);
    }
  }


  /**
   *
   */
  @PostMapping(path = "preparePayment", produces = MediaType.APPLICATION_JSON_VALUE)
  public ResponseEntity<OBWriteDomesticConsentResponse3> preparePayment(
      @RequestHeader(WSO2Controller.X_TPP_BANKID) final String bankId,
      @AuthenticationPrincipal final User user,
      @RequestBody final String body) {
    log.info("Called POST /pisp/v1/preparePayment");
    final OBWriteDomesticConsentResponse3 response = getConsentId(bankId, body);
    final String consentId = response.getData().getConsentId();

    final PaymentConsent paymentConsent = new PaymentConsent();
    paymentConsent.setBankId(bankId);
    paymentConsent.setConsentId(consentId);
    paymentConsent.setConsentResponse(response.getRawContent());
// Save consent to DB
    paymentConsentRepository.save(paymentConsent);

// Initialize payment
    final BankInfo bankInfo = getTokenManager(bankId).getOauthconfig().getBankInfo();
    final @CheckForNull OBWriteDomesticConsentResponse3 domesticConsentResponse3 = initializePayment(bankInfo, consentId, user
        .getUsername());

    if (null == domesticConsentResponse3) {
      throw new ResponseStatusException(HttpStatus.PRECONDITION_FAILED, "Error while initialize payment!");
    }

    final MultiValueMap<String, String> headers = new HttpHeaders();
    headers.add("x-tpp-consentid", consentId);
    return new ResponseEntity<>(domesticConsentResponse3, headers, HttpStatus.OK);
  }


  /**
   * Cancel prepared payment
   */
  @PostMapping(path = "cancelPayment/{ConsentId}", produces = MediaType.APPLICATION_JSON_VALUE)
  public ResponseEntity<String> cancelPayment(@RequestHeader(WSO2Controller.X_TPP_BANKID) final String bankId,
      @AuthenticationPrincipal final User user,
      @PathVariable(CONSENT_ID) final String consentId) {
    // TODO deny payment
    log.info("Called POST /pisp/v1/cancelPayment/{ConsentId} consentId={}", consentId);
    final BankInfo bankInfo = getTokenManager(bankId).getOauthconfig().getBankInfo();

    updateConsent(bankInfo, consentId, user.getUsername(), false);
// Because it's cancel the consent, we don't care about response status

    return new ResponseEntity<>("", HttpStatus.OK);
  }


  /**
   * Execute payment transaction
   */
  @PostMapping(path = "executePayment/{ConsentId}", produces = MediaType.APPLICATION_JSON_VALUE)
  public ResponseEntity<String> executePayment(@RequestHeader(WSO2Controller.X_TPP_BANKID) final String bankId,
      @AuthenticationPrincipal final User user,
      @PathVariable(CONSENT_ID) final String consentId) {
    log.info("Called POST /pisp/v1/executePayment/{ConsentId} consentId={}", consentId);
// TODO Authorize payment and execute payment
    final PaymentConsent paymentConsent;
    try {
      paymentConsent = paymentConsentRepository.getConsent(bankId, consentId);
      if (null == paymentConsent) {
        throw new EntityNotFoundException();
      }
    } catch (final EntityNotFoundException nfe) {
      throw new ResponseStatusException(HttpStatus.PRECONDITION_FAILED, "Consent not found in database!");
    }
    final String modifiedResponse;
    try {
      final OBWriteDomesticConsentResponse3 prevResponse = mapper
          .readValue(paymentConsent.getConsentResponse(), OBWriteDomesticConsentResponse3.class);
      prevResponse.getData().setStatus(null);
      prevResponse.getData().setCreationDateTime(null);
      prevResponse.getData().setStatusUpdateDateTime(null);
      modifiedResponse = mapper.writeValueAsString(prevResponse);
    } catch (final IOException e) {
      throw new ResponseStatusException(HttpStatus.PRECONDITION_FAILED, "Error while parsing saved consent request!");
    }

// Authorize payment
    final BankInfo bankInfo = getTokenManager(bankId).getOauthconfig().getBankInfo();
    final UpdateConsentResponse updateConsentResult = updateConsent(bankInfo, consentId, user.getUsername(), true);
    final int updateConsentResponseCode = updateConsentResult.getHttpResponseCode();
    if (updateConsentResponseCode < 200 || updateConsentResponseCode >= 300) {
      throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Error while authorize payment!");
    }

// Execute payment
    final ResponseEntity<String> result = handlePayments(HttpMethod.POST, bankId, user, "/domestic-payments", modifiedResponse,
        WSO2Controller.ACCESS_TOKEN_TYPE.USER);
    if (result.getStatusCode() == HttpStatus.CREATED) {
      final OBWriteDomesticResponse3 domesticResult;
      try {
        domesticResult = mapper.readValue(result.getBody(), OBWriteDomesticResponse3.class);
        paymentConsent.setPaymentId(domesticResult.getData().getDomesticPaymentId());
        paymentConsentRepository.save(paymentConsent);
      } catch (final IOException e) {
        throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Error while update consent datas.");
      }
    }

    return result;
  }


  /**
   * Get payment details
   */
  @GetMapping(path = "payment/{DomesticPaymentId}", produces = MediaType.APPLICATION_JSON_VALUE)
  public ResponseEntity<String> getPaymentDetails(@RequestHeader(WSO2Controller.X_TPP_BANKID) final String bankId,
      @AuthenticationPrincipal final User user,
      @PathVariable("DomesticPaymentId") final String domesticPaymentId) {
    log.info("Called /pisp/v1/payment/{DomesticPaymentId} DomesticPaymentId={}", domesticPaymentId);
    return handlePayments(HttpMethod.GET, bankId, user, "/domestic-payments/" + domesticPaymentId, null,
        WSO2Controller.ACCESS_TOKEN_TYPE.CLIENT);
  }


  /**
   * Get Payments ConsentId
   *
   * @return consentId if request it was not success return empty.
   */
  private OBWriteDomesticConsentResponse3 getConsentId(final @Nonnull String bankId, final String body) {
    final int tryCount = 3;
    boolean force = false;

    try {
      for (int ii = tryCount; 0 < ii--; ) {
        final String accessToken = getClientAccessToken(bankId, force);
        final BankInfo bankInfo = getTokenManager(bankId).getOauthconfig().getBankInfo();
        // Setup HTTP headers
        final Map<String, String> headers = new HashMap<>();
        headers.put("Authorization", "Bearer " + accessToken);
        headers.put("x-fapi-interaction-id", UUID.randomUUID().toString());

        // get ConsentID
        final HttpResponse httpResponse = HttpHelper.doAPICall(
            HttpMethod.POST,
            new URL(bankInfo.getPaymentsUrl() + "/domestic-payment-consents"),
            headers,
            body);

        // Sometimes WSO2 respond errors in xml
        final String content = httpResponse.getHttpRawContent();
        HttpHelper.checkWSO2Errors(content);
        final int respondCode = httpResponse.getHttpResponseCode();
        if (200 <= respondCode && 300 > respondCode) {
          log.info("Respond code {}; respond: [{}]", respondCode, content);
          final OBWriteDomesticConsentResponse3 result = mapper.readValue(content, OBWriteDomesticConsentResponse3.class);
          result.setRawContent(content);
          return result;
        }
        log.error("Respond code {}; respond: [{}]", respondCode, content);
        force = true;
      }

      throw new APICallException("ConsentID request fails!");
    } catch (final MalformedURLException mue) {
      log.error("URL problems!", mue);
      throw new BankConfigException(mue.getLocalizedMessage());
    } catch (final Exception e) {
      log.error("Process error!", e);
      throw new BankConfigException(e.getLocalizedMessage());
    }
  }

}
