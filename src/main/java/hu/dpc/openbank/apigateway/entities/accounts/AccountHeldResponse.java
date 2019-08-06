package hu.dpc.openbank.apigateway.entities.accounts;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import hu.dpc.common.http.HttpResponse;
import uk.org.openbanking.v3_1_2.commons.Accounts;

@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
public class AccountHeldResponse extends HttpResponse {
    @JsonProperty("Data")
    private Accounts accounts;

    public Accounts getAccounts() {
        return accounts;
    }

    public void setAccounts(final Accounts accounts) {
        this.accounts = accounts;
    }
}
