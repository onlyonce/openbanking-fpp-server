/*
 * This Source Code Form is subject to the terms of the Mozilla
 * Public License, v. 2.0. If a copy of the MPL was not distributed
 * with this file, You can obtain one at
 *
 * https://mozilla.org/MPL/2.0/.
 */

package hu.dpc.openbank.fpp.lionfintech.backend.repository;

import hu.dpc.openbank.fpp.lionfintech.backend.enity.bank.BankInfo;
import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

@Repository
public interface BankRepository extends JpaRepository<BankInfo, String> {

  /**
   * Get latest user level access token for a desired scope.
   */
  @Transactional(readOnly = true)
  @Query(value = "select *\n" +
      "from BANKS b\n" +
      "where b.id in (\n" +
      "    select distinct BANK_ID\n" +
      "    from ACCESS_TOKEN\n" +
      "    where USERNAME = :username)", nativeQuery = true)
  List<BankInfo> getUserConnectedBanks(@Param("username") String userName);
}
