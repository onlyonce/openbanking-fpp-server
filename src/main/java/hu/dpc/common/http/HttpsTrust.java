/*
 * This Source Code Form is subject to the terms of the Mozilla
 * Public License, v. 2.0. If a copy of the MPL was not distributed
 * with this file, You can obtain one at
 *
 * https://mozilla.org/MPL/2.0/.
 */

package hu.dpc.common.http;

import java.net.HttpURLConnection;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

public class HttpsTrust {

  public static final HttpsTrust INSTANCE = new HttpsTrust(new HttpsTrust.Ssl());
  private final SSLSocketFactory socketFactory;
  private final HostnameVerifier hostnameVerifier;


  private HttpsTrust(final HttpsTrust.Ssl context) {
    socketFactory = createSocketFactory(context);
    hostnameVerifier = createHostnameVerifier();
  }


  /**
   * Trust all certificates
   */
  private static SSLSocketFactory createSocketFactory(final HttpsTrust.Ssl context) {
    try {
      return HttpsTrust.Ssl.newFactory(new HttpsTrust.AlwaysTrustManager());
    } catch (final Exception e) {
      throw new IllegalStateException("Fail to build SSL factory", e);
    }
  }


  /**
   * Trust all hosts
   */
  private static HostnameVerifier createHostnameVerifier() {
    return (hostname, session) -> true;
  }


  public void trust(final HttpURLConnection connection) {
    if (connection instanceof HttpsURLConnection) {
      final HttpsURLConnection httpsConnection = (HttpsURLConnection) connection;
      httpsConnection.setSSLSocketFactory(socketFactory);
      httpsConnection.setHostnameVerifier(hostnameVerifier);
    }
  }


  static class Ssl {

    static SSLSocketFactory newFactory(final TrustManager... managers) throws NoSuchAlgorithmException, KeyManagementException {
      final SSLContext context = SSLContext.getInstance("TLS");
      context.init(null, managers, new SecureRandom());
      return context.getSocketFactory();
    }
  }

  static class AlwaysTrustManager implements X509TrustManager {

    @Override
    public void checkClientTrusted(final X509Certificate[] chain, final String authType) {
      // Do not check
    }


    @Override
    public void checkServerTrusted(final X509Certificate[] chain, final String authType) {
      // Do not check
    }


    @Override
    public X509Certificate[] getAcceptedIssuers() {
      return new X509Certificate[0];
    }
  }
}
