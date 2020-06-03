/*
 * This Source Code Form is subject to the terms of the Mozilla
 * Public License, v. 2.0. If a copy of the MPL was not distributed
 * with this file, You can obtain one at
 *
 * https://mozilla.org/MPL/2.0/.
 */

package hu.dpc.openbank.fpp.lionfintech.backend.controller.aisp;


import hu.dpc.openbank.fpp.lionfintech.backend.controller.WSO2Controller;
import javax.annotation.Nonnull;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@RequestMapping(path = "/aisp/v1/")
public class AccountsController extends WSO2Controller {

  /**
   * GetAccounts
   */
  @GetMapping(path = "accounts", produces = MediaType.APPLICATION_JSON_VALUE)
  public ResponseEntity<String> getAccounts(@RequestHeader(WSO2Controller.X_TPP_BANKID) final @Nonnull String bankId,
      @AuthenticationPrincipal final @Nonnull User user) {
    log.info("Called GET /aisp/v1/accounts");
    return handleAccounts(HttpMethod.GET, bankId, user, "/accounts", null);
  }


  /**
   * Get one account
   */
  @GetMapping(path = "accounts/{AccountId}", produces = MediaType.APPLICATION_JSON_VALUE)
  public ResponseEntity<String> getAccount(@RequestHeader(WSO2Controller.X_TPP_BANKID) final @Nonnull String bankId,
      @AuthenticationPrincipal final @Nonnull User user, @PathVariable(ACCOUNT_ID) final String accountId) {
    log.info("Called GET /aisp/v1/accounts/{AccountId}  {}", accountId);
    return handleAccounts(HttpMethod.GET, bankId, user, "/accounts/" + accountId, null);
  }

}
