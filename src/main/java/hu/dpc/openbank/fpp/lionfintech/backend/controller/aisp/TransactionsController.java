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
import javax.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TransactionsController extends WSO2Controller {

  private static final Logger LOG = LoggerFactory.getLogger(TransactionsController.class);


  /**
   * Get transactions
   */
  @GetMapping(path = "/aisp/v1/transactions", produces = MediaType.APPLICATION_JSON_VALUE)
  public ResponseEntity<String> getTransactions(@RequestHeader(WSO2Controller.X_TPP_BANKID) final String bankId,
      @AuthenticationPrincipal final User user,
      @RequestParam(value = "fromBookingDateTime", required = false) final String fromBookingDateTime,
      @RequestParam(value = "toBookingDateTime", required = false) final String toBookingDateTime,
      final HttpServletRequest request) {
    LOG.info("Called GET /aisp/v1/transactions?fromBookingDateTime={}&toBookingDateTime={}", fromBookingDateTime, toBookingDateTime);
    return handleAccounts(HttpMethod.GET, bankId, user, "/transactions" + createParams(fromBookingDateTime, toBookingDateTime), null);
  }


  /**
   * Get Account Transactions
   */
  @GetMapping(path = "/aisp/v1/accounts/{AccountId}/transactions", produces = MediaType.APPLICATION_JSON_VALUE)
  public ResponseEntity<String> getAccountTransactions(
      @RequestHeader(WSO2Controller.X_TPP_BANKID) final String bankId, @AuthenticationPrincipal final User user,
      @PathVariable(ACCOUNT_ID) final String accountId,
      @RequestParam(name = "fromBookingDateTime", required = false) final String fromBookingDateTime,
      @RequestParam(name = "toBookingDateTime", required = false) final String toBookingDateTime) {
    LOG.info("Called GET /aisp/v1/accounts/{AccountId}/transactions?fromBookingDateTime={}&fromBookingDateTime={}", fromBookingDateTime,
        fromBookingDateTime);
    return handleAccounts(HttpMethod.GET, bankId, user,
        "/accounts/" + accountId + "/transactions" + createParams(fromBookingDateTime, toBookingDateTime), null);
  }


  @Nonnull
  private String createParams(final String fromBookingDateTime, final String toBookingDateTime) {
    String queryParams = "";
    if (null != fromBookingDateTime && !fromBookingDateTime.isEmpty()) {
      queryParams = "fromBookingDateTime=" + fromBookingDateTime;
    }
    if (null != toBookingDateTime && !toBookingDateTime.isEmpty()) {
      if (!queryParams.isEmpty()) {
        queryParams += '&';
      }
      queryParams += "toBookingDateTime=" + toBookingDateTime;
    }

    if (!queryParams.isEmpty()) {
      queryParams = '?' + queryParams;
    }
    return queryParams;
  }

}
