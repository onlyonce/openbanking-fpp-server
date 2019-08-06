/*
 * This Source Code Form is subject to the terms of the Mozilla
 * Public License, v. 2.0. If a copy of the MPL was not distributed
 * with this file, You can obtain one at
 *
 * https://mozilla.org/MPL/2.0/.
 */

package hu.dpc.openbank.fpp.lionfintech.backend.enity.bank;

import javax.persistence.*;

@Entity
@Table(name = "ACCESS_TOKEN")
public class AccessToken {
    @Id
    @Column(name = "ID")
    @GeneratedValue
    private int    id;
    @Column(name = "BANK_ID")
    private String bankId;
    @Column(name = "USERNAME")
    private String userName;
    @Column(name = "ACCESS_TOKEN")
    private String accessToken;
    @Column(name = "ACCESS_TOKEN_TYPE")
    private String accessTokenType;
    @Column(name = "EXPIRES")
    private long   expires;
    @Column(name = "REFRESH_TOKEN")
    private String refreshToken;

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

    public String getUserName() {
        return userName;
    }

    public void setUserName(final String userName) {
        this.userName = userName;
    }

    public String getAccessToken() {
        return accessToken;
    }

    public void setAccessToken(final String accessToken) {
        this.accessToken = accessToken;
    }

    public String getAccessTokenType() {
        return accessTokenType;
    }

    public void setAccessTokenType(final String accessTokenType) {
        this.accessTokenType = accessTokenType;
    }

    public long getExpires() {
        return expires;
    }

    public void setExpires(final long expires) {
        this.expires = expires;
    }

    public String getRefreshToken() {
        return refreshToken;
    }

    public void setRefreshToken(final String refreshToken) {
        this.refreshToken = refreshToken;
    }

    /**
     * Token is expired?
     *
     * @return
     */
    public boolean isExpired() {
        return (System.currentTimeMillis() - 3000L) > expires;
    }
}
