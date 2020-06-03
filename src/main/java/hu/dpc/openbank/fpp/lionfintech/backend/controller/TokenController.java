/*
 * This Source Code Form is subject to the terms of the Mozilla
 * Public License, v. 2.0. If a copy of the MPL was not distributed
 * with this file, You can obtain one at
 *
 * https://mozilla.org/MPL/2.0/.
 */

package hu.dpc.openbank.fpp.lionfintech.backend.controller;


import com.auth0.jwt.JWT;
import com.auth0.jwt.impl.JWTParser;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.Payload;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import hu.dpc.common.http.oauth2.OAuthAuthorizationRequiredException;
import hu.dpc.common.http.oauth2.TokenResponse;
import hu.dpc.openbank.fpp.lionfintech.backend.enity.bank.AccessToken;
import hu.dpc.openbank.fpp.lionfintech.backend.enity.bank.Authorities;
import hu.dpc.openbank.fpp.lionfintech.backend.enity.bank.Users;
import hu.dpc.openbank.fpp.lionfintech.backend.repository.AuthoritiesRepository;
import hu.dpc.openbank.fpp.lionfintech.backend.repository.UsersRepository;
import hu.dpc.openbank.oauth2.TokenManager;
import java.util.Base64;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@RequestMapping(path = "/token/v1/")
public class TokenController extends WSO2Controller {

  private final UsersRepository usersRepository;

  private final AuthoritiesRepository authoritiesRepository;

  private final ObjectMapper mapper;


  public TokenController(final UsersRepository usersRepository, final AuthoritiesRepository authoritiesRepository,
      final ObjectMapper mapper) {
    this.usersRepository = usersRepository;
    this.authoritiesRepository = authoritiesRepository;
    this.mapper = mapper;
  }


  @Transactional
  @GetMapping(path = "/code/{Code}", produces = MediaType.APPLICATION_JSON_VALUE)
  public String getTokenCodeForAccounts(@RequestHeader(X_TPP_BANKID) final String bankId,
      @PathVariable("Code") final String code) {
    log.info("Called GET /token/v1/code/{}    bankId={}", code, bankId);
    return exchangeToken(bankId, code);
  }


  private String exchangeToken(final String bankId, final String code) {
    final TokenManager tokenManager = getTokenManager(bankId);
    final TokenResponse accessTokenResponse = tokenManager.getAccessTokenFromCode(code);
    final int responseCode = accessTokenResponse.getHttpResponseCode();
    if (responseCode >= 200 && responseCode < 300) {
      // Extract username from id_token
      final DecodedJWT decodedJWT = JWT.decode(accessTokenResponse.getIdToken());
      final Payload payLoad = new JWTParser().parsePayload(new String(Base64.getDecoder()
          .decode(decodedJWT.getPayload())));
      final String userName = payLoad.getSubject();
      final AccessToken accessToken = createAndSaveUserAccessToken(accessTokenResponse, bankId, userName);

      // Create or update user account for reduce development while LionFintech derived from ACEFintech
      Users user = usersRepository.findByUserName(userName);
      final boolean isNewUser = (null == user);
      if (isNewUser) {
        user = new Users();
        user.setUserName(userName);
      }
      final PasswordEncoder encoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
      final String password = encoder.encode(accessToken.getAccessToken());
      user.setPassword(password);
      user.setEnabled(true);
      usersRepository.saveAndFlush(user);

      if (isNewUser) {
        final Authorities userAuthority = new Authorities();
        userAuthority.setUserName(userName);
        userAuthority.setAuthority("ROLE_USER");
        authoritiesRepository.saveAndFlush(userAuthority);
      }

      final String json;
      try {
        final Users returnUser = new Users();
        returnUser.setUserName(userName);
        returnUser.setPassword(accessToken.getAccessToken());
        json = mapper.writeValueAsString(returnUser);
      } catch (final JsonProcessingException e) {
        log.error("Object to JSON mapping error", e);
        throw new OAuthAuthorizationRequiredException("");
      }
      return json;
    }
    log.warn("Code exchange not succeeded. HTTP[{}] RAWResponse [{}]", responseCode, accessTokenResponse.getHttpRawContent());
    log.info("No user AccessToken exists. OAuth authorization required!");
    throw new OAuthAuthorizationRequiredException("");
  }

}
