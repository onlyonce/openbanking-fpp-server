/*
 * This Source Code Form is subject to the terms of the Mozilla
 * Public License, v. 2.0. If a copy of the MPL was not distributed
 * with this file, You can obtain one at
 *
 * https://mozilla.org/MPL/2.0/.
 */

package hu.dpc.openbank.oauth2;

import hu.dpc.openbank.fpp.lionfintech.backend.enity.bank.BankInfo;

import java.net.MalformedURLException;
import java.net.URL;

public class OAuthConfig {
    private String apiKey;
    private String apiSecret;
    private String callbackURL;
    private URL tokenURL;
    private String subject;
    private BankInfo bankInfo;

    public OAuthConfig(final BankInfo bankInfo) throws MalformedURLException {
        this.bankInfo = bankInfo;
        apiKey = bankInfo.getClientId();
        apiSecret = bankInfo.getClientSecret();
        callbackURL = bankInfo.getCallBackUrl();
        tokenURL = new URL(bankInfo.getTokenUrl());
    }

    public OAuthConfig() {
    }

    public String getSubject() {
        return subject;
    }

    public void setSubject(final String subject) {
        this.subject = subject;
    }

    public String getApiSecret() {
        return apiSecret;
    }

    public void setApiSecret(final String apiSecret) {
        this.apiSecret = apiSecret;
    }

    public URL getTokenURL() {
        return tokenURL;
    }

    public void setTokenURL(final String tokenURL) throws MalformedURLException {
        this.tokenURL = new URL(tokenURL);
    }

    public String getApiKey() {
        return apiKey;
    }

    public void setApiKey(final String apiKey) {
        this.apiKey = apiKey;
    }

    public String getCallbackURL() {
        return callbackURL;
    }

    public void setCallbackURL(final String callbackURL) {
        this.callbackURL = callbackURL;
    }

    public BankInfo getBankInfo() {
        return bankInfo;
    }
}
