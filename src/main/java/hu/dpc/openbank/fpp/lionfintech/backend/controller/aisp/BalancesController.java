/*
 * This Source Code Form is subject to the terms of the Mozilla
 * Public License, v. 2.0. If a copy of the MPL was not distributed
 * with this file, You can obtain one at
 *
 * https://mozilla.org/MPL/2.0/.
 */

package hu.dpc.openbank.fpp.lionfintech.backend.controller.aisp;


import hu.dpc.openbank.fpp.lionfintech.backend.controller.WSO2Controller;
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
public class BalancesController extends WSO2Controller {

  /**
   * Get balances
   */
  @GetMapping(path = "balances", produces = MediaType.APPLICATION_JSON_VALUE)
  public ResponseEntity<String> getBalances(@RequestHeader(WSO2Controller.X_TPP_BANKID) final String bankId,
      @AuthenticationPrincipal final User user) {
    log.info("Called GET /aisp/v1/balances");
    return handleAccounts(HttpMethod.GET, bankId, user, "/balances", null);
  }


  /**
   * Get one account balance
   */
  @GetMapping(path = "accounts/{AccountId}/balances", produces = MediaType.APPLICATION_JSON_VALUE)
  public ResponseEntity<String> getAccountBalance(@RequestHeader(WSO2Controller.X_TPP_BANKID) final String bankId,
      @AuthenticationPrincipal final User user, @PathVariable(ACCOUNT_ID) final String accountId) {
    log.info("Called GET /aisp/v1/accounts/{AccountId}/balances  AccountId=[{}]", accountId);
    return handleAccounts(HttpMethod.GET, bankId, user, "/accounts/" + accountId + "/balances", null);
  }

}
