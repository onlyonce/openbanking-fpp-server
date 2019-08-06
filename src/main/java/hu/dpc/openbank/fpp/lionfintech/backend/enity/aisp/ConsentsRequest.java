/*
 * This Source Code Form is subject to the terms of the Mozilla
 * Public License, v. 2.0. If a copy of the MPL was not distributed
 * with this file, You can obtain one at
 *
 * https://mozilla.org/MPL/2.0/.
 */

package hu.dpc.openbank.fpp.lionfintech.backend.enity.aisp;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;


@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ConsentsRequest {
    @JsonProperty("Data")
    private Consents consents;

    public ConsentsRequest(final Consents consents) {
        this.consents = consents;
    }

    public Consents getConsents() {
        return consents;
    }

    public void setConsents(final Consents consents) {
        this.consents = consents;
    }
}
