/*
 * This Source Code Form is subject to the terms of the Mozilla
 * Public License, v. 2.0. If a copy of the MPL was not distributed
 * with this file, You can obtain one at
 *
 * https://mozilla.org/MPL/2.0/.
 */

package hu.dpc.openbank.fpp.lionfintech.backend.controller;


import hu.dpc.openbank.fpp.lionfintech.backend.enity.bank.SupportedBanks;
import hu.dpc.openbank.fpp.lionfintech.backend.repository.BankRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@RequestMapping(path = "/user/v1/")
public class UserController {

  private final BankRepository bankRepository;


  public UserController(final BankRepository bankRepository) {
    this.bankRepository = bankRepository;
  }


  @GetMapping(path = "/banks", produces = MediaType.APPLICATION_JSON_VALUE)
  public SupportedBanks getSupportedBanks(@AuthenticationPrincipal final User user) {
    log.info("Called GET /user/v1/banks  {}", user.getUsername());
    final SupportedBanks supportedBanks = new SupportedBanks();
    supportedBanks.setBankInfoList(bankRepository.getUserConnectedBanks(user.getUsername()));
    return supportedBanks;
  }
}
