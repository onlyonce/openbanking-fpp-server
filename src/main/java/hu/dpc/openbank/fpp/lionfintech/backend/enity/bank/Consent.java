/*
 * This Source Code Form is subject to the terms of the Mozilla
 * Public License, v. 2.0. If a copy of the MPL was not distributed
 * with this file, You can obtain one at
 *
 * https://mozilla.org/MPL/2.0/.
 */

package hu.dpc.openbank.fpp.lionfintech.backend.enity.bank;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Table;

@Entity
@Table(name="CONSENTS")
public class Consent {
    @Id
    @Column(name="ID")
    private int id;
    @Column(name="BANK_ID")
    private String bankId;
    @Column(name="CONSENTID")
    private String consentId;
    @Column(name="EXPIRES")
    private int expires;

    public int getId() {
        return id;
    }

    public void setId(final int id) {
        this.id = id;
    }

    public String getBankId() {
        return bankId;
    }

    public void setBankId(final String bankId) {
        this.bankId = bankId;
    }

    public String getConsentId() {
        return consentId;
    }

    public void setConsentId(final String consentId) {
        this.consentId = consentId;
    }

    public int getExpires() {
        return expires;
    }

    public void setExpires(final int expires) {
        this.expires = expires;
    }
}
