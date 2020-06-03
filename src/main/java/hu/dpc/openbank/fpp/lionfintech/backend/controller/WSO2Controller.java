/*
 * This Source Code Form is subject to the terms of the Mozilla
 * Public License, v. 2.0. If a copy of the MPL was not distributed
 * with this file, You can obtain one at
 *
 * https://mozilla.org/MPL/2.0/.
 */

package hu.dpc.openbank.fpp.lionfintech.backend.controller;


import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import hu.dpc.common.http.HTTPCallExecutionException;
import hu.dpc.common.http.HttpHelper;
import hu.dpc.common.http.HttpResponse;
import hu.dpc.common.http.HttpUtils;
import hu.dpc.common.http.oauth2.OAuthAuthorizationRequiredException;
import hu.dpc.common.http.oauth2.TokenResponse;
import hu.dpc.openbank.apigateway.entities.accounts.AccountHeldResponse;
import hu.dpc.openbank.apigateway.entities.accounts.UpdateConsentResponse;
import hu.dpc.openbank.exceptions.APICallException;
import hu.dpc.openbank.fpp.lionfintech.backend.enity.aisp.AccountConsentPermissions;
import hu.dpc.openbank.fpp.lionfintech.backend.enity.aisp.Consents;
import hu.dpc.openbank.fpp.lionfintech.backend.enity.aisp.ConsentsRequest;
import hu.dpc.openbank.fpp.lionfintech.backend.enity.aisp.ConsentsResponse;
import hu.dpc.openbank.fpp.lionfintech.backend.enity.bank.AccessToken;
import hu.dpc.openbank.fpp.lionfintech.backend.enity.bank.AccountConsent;
import hu.dpc.openbank.fpp.lionfintech.backend.enity.bank.BankInfo;
import hu.dpc.openbank.fpp.lionfintech.backend.repository.AccessTokenRepository;
import hu.dpc.openbank.fpp.lionfintech.backend.repository.AccountConsentRepository;
import hu.dpc.openbank.fpp.lionfintech.backend.repository.BankConfigException;
import hu.dpc.openbank.fpp.lionfintech.backend.repository.BankIDNotFoundException;
import hu.dpc.openbank.fpp.lionfintech.backend.repository.BankRepository;
import hu.dpc.openbank.oauth2.OAuthConfig;
import hu.dpc.openbank.oauth2.TokenManager;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.sql.Timestamp;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import javax.annotation.CheckForNull;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.annotation.ParametersAreNonnullByDefault;
import javax.persistence.EntityNotFoundException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.User;
import uk.org.openbanking.v3_1_2.accounts.OBReadConsentResponse1;
import uk.org.openbanking.v3_1_2.accounts.OBReadConsentResponse1Data;

@Slf4j
@ParametersAreNonnullByDefault
public class WSO2Controller {

  public static final String X_TPP_BANKID = "x-tpp-bankid";
  public static final String ACCOUNT_ID = "AccountId";
  public static final String CONSENT_ID = "ConsentId";
  public static final String SCOPE_ACCOUNTS = "accounts";
  public static final String SCOPE_PAYMENTS = "payments";
  public static final String X_FAPI_INTERACTION_ID = "x-fapi-interaction-id";

  private static final HashMap<String, TokenManager> tokenManagerCache = new HashMap<>();
  private static final HashMap<String, AccessToken> clientAccessTokenCache = new HashMap<>();

  @Autowired
  private AccessTokenRepository accessTokenRepository;
  /**
   * Getting bank infomations.
   */
  @Autowired
  private BankRepository bankRepository;
  @Autowired
  private AccountConsentRepository accountConsentRepository;
  @Autowired
  private ObjectMapper mapper;


  /**
   * Authorize Account Consent
   */
  public UpdateConsentResponse authorizeAccountConsent(final BankInfo bankInfo, final String consentId, final String userName,
      final OBReadConsentResponse1 updateConsentRequest) throws HTTPCallExecutionException {
    try {
      final String json = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(updateConsentRequest);

      final Map<String, String> headers = new HashMap<>();
      headers.put("Accept", "application/json");
      headers.put("Content-Type", "application/json");
      headers.put("x-fapi-interaction-id", UUID.randomUUID().toString());
      headers.put("user-id", userName);
      headers.put("consent-id", consentId);

      return HttpUtils.call(
          HttpMethod.PUT,
          UpdateConsentResponse.class,
          bankInfo.getGatewayUrl() + "/consents/" + consentId,
          headers,
          json);
    } catch (final Exception e) {
      log.error("Error on updateConsent", e);
      throw new HTTPCallExecutionException(e);
    }
  }


  @CheckForNull
  public AccountHeldResponse getAccountsHeld(final BankInfo bankInfo, final String userName, final String consentId) {
    final Map<String, String> headers = new HashMap<>();
    headers.put("Accept", "application/json");
    headers.put("Content-Type", "application/json");
    headers.put("x-fapi-interaction-id", UUID.randomUUID().toString());
    headers.put("user-id", userName);
    headers.put("consent-id", consentId);

    // get ConsentID
    final HttpResponse httpResponse;
    try {
      httpResponse = HttpHelper.doAPICall(
          HttpMethod.GET,
          new URL(bankInfo.getGatewayUrl() + "/consents/" + consentId + "/accounts"),
          headers,
          null);
    } catch (final MalformedURLException e) {
      log.error("Error in URL", e);
      return null;
    }

    if (httpResponse.getHttpResponseCode() != HttpStatus.OK.value()) {
      return null;
    }

    final AccountHeldResponse result;
    try {
      result = mapper.readValue(httpResponse.getHttpRawContent(), AccountHeldResponse.class);
    } catch (final IOException e) {
      log.error("Error while JSON to Object convert", e);
      return null;
    }

    result.setHttpRawContent(httpResponse.getHttpRawContent());
    result.setHttpResponseCode(httpResponse.getHttpResponseCode());

    return result;
  }


  /**
   * Check user AccessToken is valid and not expired. If expired tries refresh.
   */
  public String userAccessTokenIsValid(final String bankId,
      final String userName) throws OAuthAuthorizationRequiredException {
    log.info("userAccessTokenIsValid: bankId {} userName {}", bankId, userName);
    AccessToken userAccessToken = getLatestUserAccessToken(userName, bankId, SCOPE_ACCOUNTS);
    if (null == userAccessToken) {
      log.info("No user AccessToken exists. OAuth authorization required!");
      throw new OAuthAuthorizationRequiredException("");
    }

    final TokenManager tokenManager = getTokenManager(bankId);
    if (userAccessToken.isExpired()) {
      log.info("User AccessToken is expired, trying refresh accessToken: [{}] refreshToken: [{}]", userAccessToken
          .getAccessToken(), userAccessToken.getRefreshToken());
      final TokenResponse refreshToken = tokenManager.refreshToken(userAccessToken.getRefreshToken());

      if (HttpURLConnection.HTTP_OK == refreshToken.getHttpResponseCode()) {
        userAccessToken = createAndSaveUserAccessToken(refreshToken, bankId, userName);
      } else {
        log.warn("Refresh token refreshing not succeeded. HTTP[{}] RAWResponse [{}]", refreshToken
            .getHttpResponseCode(), refreshToken.getHttpRawContent());
        log.info("No user AccessToken exists. OAuth authorization required!");
        throw new OAuthAuthorizationRequiredException("");
      }
    }

    return userAccessToken.getAccessToken();
  }


  /**
   * Check user AccessToken is valid and not expired.
   */
  public String userAccessTokenIsValidForPayments(final String bankId, final String userName) {
    log.info("userAccessTokenIsValid: bankId {} userName {}", bankId, userName);
    AccessToken userAccessToken = getLatestUserAccessToken(userName, bankId, SCOPE_PAYMENTS);
    if (null == userAccessToken) {
      throw new EntityNotFoundException("User access token not found for payments");
    }

    final TokenManager tokenManager = getTokenManager(bankId);
    if (userAccessToken.isExpired()) {
      log.info("User AccessToken is expired, trying refresh accessToken: [{}] refreshToken: [{}]", userAccessToken
          .getAccessToken(), userAccessToken.getRefreshToken());
      final TokenResponse refreshToken = tokenManager.refreshToken(userAccessToken.getRefreshToken());

      if (HttpURLConnection.HTTP_OK == refreshToken.getHttpResponseCode()) {
        userAccessToken = createAndSaveUserAccessToken(refreshToken, bankId, userName);
      } else {
        log.warn("Refresh token refreshing not succeeded. HTTP[{}] RAWResponse [{}]", refreshToken
            .getHttpResponseCode(), refreshToken.getHttpRawContent());
        throw new EntityNotFoundException("User access token not found for payments after refresh");
      }
    }

    return userAccessToken.getAccessToken();
  }


  /**
   * Get latest user AccessToken.
   */
  private AccessToken getLatestUserAccessToken(final String userId, final String bankId,
      @Deprecated final String scope) {
    log.info("getLatestUserAccessToken userId {} bankId {}", userId, bankId);
    final AccessToken accessToken = accessTokenRepository.getLatest(bankId, userId);
    log.info("AccessToken: {}", accessToken);
    return accessToken;
  }


  /**
   * Get Account consent from db or create a new one and authorize it.
   */
  public String getOrCreateAccountConsentId(final String bankId, String userName) {
    userName = userName.toUpperCase();
    final String accessToken = getClientAccessToken(bankId, false);
    final BankInfo bankInfo = getTokenManager(bankId).getOauthconfig().getBankInfo();
    AccountConsent accountConsent = accountConsentRepository.getConsent(bankId, userName);

    // If no consent exists for user
    if (null == accountConsent) {
      final ConsentsResponse consentsResponse = getAccountsConsentId(bankId, userName);
      if (200 <= consentsResponse.getHttpResponseCode() && 300 > consentsResponse.getHttpResponseCode()) {
        accountConsent = new AccountConsent();
        accountConsent.setBankId(bankId);
        accountConsent.setUserName(userName);
        final String consentId = consentsResponse.getConsents().getConsentId();
        accountConsent.setConsentId(consentId);
        accountConsent.setExpires(Timestamp.valueOf(consentsResponse.getConsents().getExpirationDateTime())
            .getTime());
        accountConsent.setConsentResponse(consentsResponse.getHttpRawContent());

        final AccountHeldResponse accountsHeld = getAccountsHeld(bankInfo, userName, consentId);
        if (null == accountsHeld) {
          return null;
        }

// Authorize Accounts Consent
        try {
          final OBReadConsentResponse1 updateConsentRequest = new OBReadConsentResponse1();
          final OBReadConsentResponse1Data obReadConsentResponse1Data = new OBReadConsentResponse1Data();
          obReadConsentResponse1Data.setConsentId(consentId);
          obReadConsentResponse1Data.setAction("Authorize");
          obReadConsentResponse1Data.setAccounts(accountsHeld.getAccounts().getAccount());
          obReadConsentResponse1Data.setPermissions(consentsResponse.getConsents().getPermissions());
          updateConsentRequest.setData(obReadConsentResponse1Data);
          authorizeAccountConsent(bankInfo, consentId, userName, updateConsentRequest);
        } catch (final HTTPCallExecutionException e) {
          log.error("Account consent update failed!", e);
          return null;
        }

        log.info("Found account consent in cache: {}", accountConsent.getConsentId());
        accountConsentRepository.saveAndFlush(accountConsent);
      } else {
        return null;
      }
    } else {
      log.info("Found account consent in cache: consentId={}", accountConsent.getConsentId());
    }

    return accountConsent.getConsentId();
  }


  /**
   * Get Accounts ConsentId
   *
   * @return Account Consent object. You must check responseCode to validate response.
   */
  private ConsentsResponse getAccountsConsentId(final String bankId, final String userName) {
    final int tryCount = 3;

    final BankInfo bankInfo = getTokenManager(bankId).getOauthconfig().getBankInfo();
    int respondCode = 0;
    String content = null;
    try {
      for (int ii = tryCount; 0 < ii--; ) {
        final String accessToken = getClientAccessToken(bankId, false);
        // Setup HTTP headers
        final HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(accessToken);
        headers.add(X_FAPI_INTERACTION_ID, UUID.randomUUID().toString());
        final Consents consents = new Consents();
        consents.setPermissions(new ArrayList<>(AccountConsentPermissions.PERMISSIONS));
        LocalDateTime exp = LocalDateTime.now();
        exp = exp.plusYears(10);
        consents.setExpirationDateTime(exp);
        consents.setTransactionFromDateTime(LocalDateTime.now());
        consents.setTransactionToDateTime(exp);
        final ConsentsRequest consentsRequest = new ConsentsRequest(consents);

        final String json;
        try {
          json = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(consentsRequest);
          log.info("Consent request: {}", json);
        } catch (final JsonProcessingException e) {
          throw new APICallException("Error creating JSON: " + e.getLocalizedMessage());
        }

        // Get ConsentID
        final HttpResponse httpResponse = HttpHelper.doAPICall(
            HttpMethod.POST,
            new URL(bankInfo.getAccountsUrl() + "/account-access-consents"),
            headers.toSingleValueMap(),
            json);

        // Sometimes WSO2 respond errors in xml
        content = httpResponse.getHttpRawContent();
        HttpHelper.checkWSO2Errors(content);
        respondCode = httpResponse.getHttpResponseCode();
        if (200 <= respondCode && 300 > respondCode) {
          log.info("Respond code {}; respond: [{}]", respondCode, content);
          final ConsentsResponse response = mapper.readValue(content, ConsentsResponse.class);
          response.setHttpResponseCode(respondCode);
          response.setHttpRawContent(content);
          return response;
        }
        log.error("Respond code {}; respond: [{}]", respondCode, content);
      }
      final ConsentsResponse response = new ConsentsResponse();
      response.setHttpResponseCode(respondCode);
      response.setHttpRawContent(content);
      return response;
    } catch (final MalformedURLException mue) {
      log.error("URL problems!", mue);
      throw new BankConfigException(mue.getLocalizedMessage());
    } catch (final Exception e) {
      log.error("Process error!", e);
      throw new BankConfigException(e.getLocalizedMessage());
    }
  }


  /**
   * Get&Cache TokenManager.
   */
  public TokenManager getTokenManager(final String bankId) {
    log.info("BankID: {}", bankId);

    TokenManager tokenManager = tokenManagerCache.get(bankId);
    if (null == tokenManager) {
      try {
        final BankInfo bankInfo = bankRepository.getOne(bankId);
        if (!bankId.equals(bankInfo.getBankId())) {
          // Testing result
          throw new BankIDNotFoundException(bankId);
        }
        final OAuthConfig oAuthConfig = new OAuthConfig(bankInfo);
        tokenManager = new TokenManager(oAuthConfig);
        tokenManagerCache.put(bankId, tokenManager);
      } catch (final EntityNotFoundException e) {
        // BankId not found
        log.error("Bank ID not found! [{}]", bankId);
        throw new BankIDNotFoundException(bankId);
      } catch (final MalformedURLException e) {
        log.error("Bank config error!", e);
        throw new BankConfigException(e.getLocalizedMessage());
      }
    }
    return tokenManager;
  }


  /**
   * Create and Save user AccessToken from TokenResponse (code exchange/refreshToken)
   */
  @Nonnull
  public AccessToken createAndSaveUserAccessToken(final TokenResponse refreshToken, final String bankId, final String userName) {
    final AccessToken userAccessToken = new AccessToken();
    userAccessToken.setAccessToken(refreshToken.getAccessToken());
    userAccessToken.setAccessTokenType("user");
    userAccessToken.setExpires(refreshToken.getJwtExpires());
    userAccessToken.setRefreshToken(refreshToken.getRefreshToken());
    userAccessToken.setBankId(bankId);
    userAccessToken.setUserName(userName);

    // Remove previous
    accessTokenRepository.remove(bankId, userName);
    accessTokenRepository.save(userAccessToken);

    return userAccessToken;
  }


  /**
   * Get or create client AccessToken
   */
  @Nonnull
  protected ResponseEntity<String> handleAccounts(final HttpMethod httpMethod, final String bankId, final User user, final String url,
      @Nullable final String jsonContent) {
    log.info("BankID: {} User {}", bankId, user);
    try {
      final String userAccessToken = userAccessTokenIsValid(bankId, user.getUsername());
      final BankInfo bankInfo = getTokenManager(bankId).getOauthconfig().getBankInfo();

      // (Get) or (create and init account consent)
      final String accountConsent = getOrCreateAccountConsentId(bankId, user.getUsername());
      if (null == accountConsent) {
        log.error("Account consent acquire is not success!");
        throw new OAuthAuthorizationRequiredException("");
      }

      // Setup HTTP headers
      final HttpHeaders headers = new HttpHeaders();
      headers.setBearerAuth(userAccessToken);
      headers.add(X_FAPI_INTERACTION_ID, UUID.randomUUID().toString());
      final URL apiURL = new URL(bankInfo.getAccountsUrl() + url);
      log.info("Call API: {}", apiURL);
      final HttpResponse httpResponse = HttpHelper.doAPICall(httpMethod, apiURL, headers
          .toSingleValueMap(), jsonContent);

      // Sometimes WSO2 respond errors in xml
      final String content = httpResponse.getHttpRawContent();
      HttpHelper.checkWSO2Errors(content);
      final int responseCode = httpResponse.getHttpResponseCode();
      if (responseCode < 200 || responseCode > 300) {
        log.error("Respond code {}; respond: [{}]", responseCode, content);
        // TODO Handle correctly if error will come processable
        // 500:java.lang.UnsupportedOperationException: User.....
        // 401:[{"fault":{"code":900901,"message":"Invalid Credentials","description":"Access failure for API: /open-banking/v3.1/aisp/v3.1.2, version: v3.1.2 status: (900901) - Invalid Credentials. Make sure you have given the correct access token"}}]
        // 403:[{"fault":{"code":900910,"message":"The access token does not allow you to access the requested resource","description":"Access failure for API: /open-banking/v3.1/aisp/v3.1.2, version: v3.1.2 status: (900910) - The access token does not allow you to access the requested resource"}}]
//                if ((HttpStatus.UNAUTHORIZED.value() == responseCode) || (HttpStatus.INTERNAL_SERVER_ERROR.value() == responseCode && content.startsWith("java.lang.UnsupportedOperationException: User"))) {
        throw new OAuthAuthorizationRequiredException("");
//                }
      }
      final HttpStatus httpStatus = HttpStatus.resolve(responseCode);
      return new ResponseEntity<>(content, null == httpStatus ? HttpStatus.BAD_REQUEST : httpStatus);
    } catch (final OAuthAuthorizationRequiredException oare) {
      log.warn("Something went wrong!", oare);

      final HttpHeaders responseHeaders = new HttpHeaders();
      responseHeaders.set("x-tpp-consentid", oare.getConsentId());
      return new ResponseEntity<>("Require authorize", responseHeaders, HttpStatus.PRECONDITION_REQUIRED);
    } catch (final Throwable e) {
      // Intended to catch Throwable
      log.error("Something went wrong!", e);
      return new ResponseEntity<>(e.getLocalizedMessage(), HttpStatus.BAD_REQUEST);
    }
  }


  @Nonnull
  protected ResponseEntity<String> handlePayments(final HttpMethod httpMethod, final String bankId, final User user, final String url,
      @Nullable final String jsonContent, final WSO2Controller.ACCESS_TOKEN_TYPE accessTokenType) {
    log.info("BankID: {} User {}", bankId, user);
    try {
      final String accessToken;
      switch (accessTokenType) {
        case CLIENT:
          accessToken = getClientAccessToken(bankId, true);
          break;
        case USER:
          accessToken = userAccessTokenIsValidForPayments(bankId, user.getUsername());
          break;
        default:
          throw new IllegalStateException("Unexpected value: " + accessTokenType);
      }
      final BankInfo bankInfo = getTokenManager(bankId).getOauthconfig().getBankInfo();

      // Setup HTTP headers
      final HttpHeaders headers = new HttpHeaders();
      headers.setBearerAuth(accessToken);
      headers.add(X_FAPI_INTERACTION_ID, UUID.randomUUID().toString());
      final URL apiURL = new URL(bankInfo.getPaymentsUrl() + url);
      log.info("Call API with {} accessToken: {}", accessTokenType.name(), apiURL);
      final HttpResponse httpResponse = HttpHelper.doAPICall(httpMethod, apiURL, headers
          .toSingleValueMap(), jsonContent);

      // Sometimes WSO2 respond errors in xml
      final String content = httpResponse.getHttpRawContent();
      HttpHelper.checkWSO2Errors(content);
      final int respondCode = httpResponse.getHttpResponseCode();
      if (!(200 <= respondCode && 300 > respondCode)) {
        log.error("Respond code {}; respond: [{}]", respondCode, content);
      }
      final HttpStatus httpStatus = HttpStatus.resolve(respondCode);
      return new ResponseEntity<>(content, null == httpStatus ? HttpStatus.BAD_REQUEST : httpStatus);
    } catch (final OAuthAuthorizationRequiredException oare) {
      log.warn("Something went wrong!", oare);

      final HttpHeaders responseHeaders = new HttpHeaders();
      responseHeaders.set("x-tpp-consentid", oare.getConsentId());
      return new ResponseEntity<>("Require authorize", responseHeaders, HttpStatus.PRECONDITION_REQUIRED);
    } catch (final Throwable e) {
      // Intended to catch Throwable
      log.error("Something went wrong!", e);
      return new ResponseEntity<>(e.getLocalizedMessage(), HttpStatus.BAD_REQUEST);
    }
  }


  /**
   * Get or create client AccessToken
   */
  protected String getClientAccessToken(final String bankId, final boolean force) {
    log.info("getClientAccessToken: bankId: {} force: {}", bankId, force);
    AccessToken accessToken = clientAccessTokenCache.get(bankId);
    log.info("Access token {} found in cache for bank {}", (null == accessToken ? "not" : ""), bankId);
    if (null != accessToken) {
      log.info("Cached Access ({}) token {} is expired {} expires {} current {}", bankId, accessToken
          .getAccessToken(), accessToken.isExpired(), accessToken.getExpires(), System.currentTimeMillis());
    }

    if (force || null == accessToken || accessToken.isExpired()) {
      final TokenManager tokenManager = getTokenManager(bankId);
      final TokenResponse tokenResponse = tokenManager
          .getAccessTokenWithClientCredential(); // new String[]{scope});
      final int respondeCode = tokenResponse.getHttpResponseCode();
      if (200 <= respondeCode && 300 > respondeCode) {

        final String accessTokenStr = tokenResponse.getAccessToken();
        log.debug("Client AccessToken: {}", accessTokenStr);

        // Save accessToken for later usage
        accessToken = new AccessToken();
        accessToken.setAccessToken(accessTokenStr);
        accessToken.setAccessTokenType("client");
        accessToken.setExpires(tokenResponse.getExpiresIn());
        accessToken.setBankId(bankId);

        log.info("New Access ({}) token {} is expired {} expires {} current {}", bankId, accessToken
            .getAccessToken(), accessToken.isExpired(), accessToken.getExpires(), System
            .currentTimeMillis());

        clientAccessTokenCache.put(bankId, accessToken);
      } else {
        throw new APICallException(tokenResponse.getHttpRawContent());
      }
    }

    return accessToken.getAccessToken();
  }


  public enum ACCESS_TOKEN_TYPE {
    /**
     * Client aka TPP.
     */
    CLIENT,
    /**
     * End user, logged in bank user who accepted consent.
     */
    USER
  }
}
