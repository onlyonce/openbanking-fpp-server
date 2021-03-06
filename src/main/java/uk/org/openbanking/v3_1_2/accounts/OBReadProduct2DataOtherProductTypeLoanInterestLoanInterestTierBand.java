/*
 * Account and Transaction API Specification
 * Swagger for Account and Transaction API Specification
 *
 * OpenAPI spec version: v3.1.2
 * Contact: ServiceDesk@openbanking.org.uk
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


package uk.org.openbanking.v3_1_2.accounts;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonValue;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;

import javax.validation.constraints.Pattern;
import javax.validation.constraints.Size;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Tier Band Details
 */
@ApiModel(description = "Tier Band Details")
@javax.annotation.Generated(value = "org.openapitools.codegen.languages.JavaJerseyServerCodegen", date = "2019-07-10T09:14:46.696896+02:00[Europe/Budapest]")
public class OBReadProduct2DataOtherProductTypeLoanInterestLoanInterestTierBand {
    @JsonProperty("FixedVariableInterestRateType")
    private OBInterestFixedVariableType1Code fixedVariableInterestRateType = null;

    @JsonProperty("TierValueMaximum")
    private String                                                                          tierValueMaximum                  = null;
    @JsonProperty("MinTermPeriod")
    private MinTermPeriodEnum                                                               minTermPeriod                     = null;
    @JsonProperty("LoanInterestFeesCharges")
    private List<OBReadProduct2DataOtherProductTypeLoanInterestLoanInterestFeesCharges>     loanInterestFeesCharges           = null;
    @JsonProperty("LoanProviderInterestRateType")
    private LoanProviderInterestRateTypeEnum                                                loanProviderInterestRateType      = null;
    @JsonProperty("Identification")
    private String                                                                          identification                    = null;
    @JsonProperty("TierValueMinTerm")
    private Integer                                                                         tierValueMinTerm                  = null;
    @JsonProperty("TierValueMaxTerm")
    private Integer                                                                         tierValueMaxTerm                  = null;
    @JsonProperty("MaxTermPeriod")
    private MaxTermPeriodEnum                                                               maxTermPeriod                     = null;
    @JsonProperty("TierValueMinimum")
    private String                                                                          tierValueMinimum                  = null;
    @JsonProperty("RepAPR")
    private String                                                                          repAPR                            = null;
    @JsonProperty("OtherLoanProviderInterestRateType")
    private OBReadProduct2DataOtherProductTypeLoanInterestOtherLoanProviderInterestRateType otherLoanProviderInterestRateType = null;
    @JsonProperty("LoanProviderInterestRate")
    private String                                                                          loanProviderInterestRate          = null;
    @JsonProperty("Notes")
    private List<String>                                                                    notes                             = null;

    public OBReadProduct2DataOtherProductTypeLoanInterestLoanInterestTierBand fixedVariableInterestRateType(
            OBInterestFixedVariableType1Code fixedVariableInterestRateType) {
        this.fixedVariableInterestRateType = fixedVariableInterestRateType;
        return this;
    }

    /**
     * Get fixedVariableInterestRateType
     *
     * @return fixedVariableInterestRateType
     **/
    @JsonProperty("FixedVariableInterestRateType")
    @ApiModelProperty(value = "")
    public OBInterestFixedVariableType1Code getFixedVariableInterestRateType() {
        return fixedVariableInterestRateType;
    }

    public void setFixedVariableInterestRateType(OBInterestFixedVariableType1Code fixedVariableInterestRateType) {
        this.fixedVariableInterestRateType = fixedVariableInterestRateType;
    }

    public OBReadProduct2DataOtherProductTypeLoanInterestLoanInterestTierBand tierValueMaximum(String tierValueMaximum) {
        this.tierValueMaximum = tierValueMaximum;
        return this;
    }

    /**
     * Maximum loan value for which the loan interest tier applies.
     *
     * @return tierValueMaximum
     **/
    @JsonProperty("TierValueMaximum")
    @ApiModelProperty(value = "Maximum loan value for which the loan interest tier applies.")
    @Pattern(regexp = "^(-?\\\\d{1,14}){1}(\\\\.\\\\d{1,4}){0,1}$")
    public String getTierValueMaximum() {
        return tierValueMaximum;
    }

    public void setTierValueMaximum(String tierValueMaximum) {
        this.tierValueMaximum = tierValueMaximum;
    }

    public OBReadProduct2DataOtherProductTypeLoanInterestLoanInterestTierBand minTermPeriod(MinTermPeriodEnum minTermPeriod) {
        this.minTermPeriod = minTermPeriod;
        return this;
    }

    /**
     * The unit of period (days, weeks, months etc.) of the Minimum Term
     *
     * @return minTermPeriod
     **/
    @JsonProperty("MinTermPeriod")
    @ApiModelProperty(value = "The unit of period (days, weeks, months etc.) of the Minimum Term")
    public MinTermPeriodEnum getMinTermPeriod() {
        return minTermPeriod;
    }

    public void setMinTermPeriod(MinTermPeriodEnum minTermPeriod) {
        this.minTermPeriod = minTermPeriod;
    }

    public OBReadProduct2DataOtherProductTypeLoanInterestLoanInterestTierBand loanInterestFeesCharges(
            List<OBReadProduct2DataOtherProductTypeLoanInterestLoanInterestFeesCharges> loanInterestFeesCharges) {
        this.loanInterestFeesCharges = loanInterestFeesCharges;
        return this;
    }

    public OBReadProduct2DataOtherProductTypeLoanInterestLoanInterestTierBand addLoanInterestFeesChargesItem(OBReadProduct2DataOtherProductTypeLoanInterestLoanInterestFeesCharges loanInterestFeesChargesItem) {
        if (this.loanInterestFeesCharges == null) {
            this.loanInterestFeesCharges = new ArrayList<>();
        }
        this.loanInterestFeesCharges.add(loanInterestFeesChargesItem);
        return this;
    }

    /**
     * Get loanInterestFeesCharges
     *
     * @return loanInterestFeesCharges
     **/
    @JsonProperty("LoanInterestFeesCharges")
    @ApiModelProperty(value = "")
    public List<OBReadProduct2DataOtherProductTypeLoanInterestLoanInterestFeesCharges> getLoanInterestFeesCharges() {
        return loanInterestFeesCharges;
    }

    public void setLoanInterestFeesCharges(
            List<OBReadProduct2DataOtherProductTypeLoanInterestLoanInterestFeesCharges> loanInterestFeesCharges) {
        this.loanInterestFeesCharges = loanInterestFeesCharges;
    }

    public OBReadProduct2DataOtherProductTypeLoanInterestLoanInterestTierBand loanProviderInterestRateType(LoanProviderInterestRateTypeEnum loanProviderInterestRateType) {
        this.loanProviderInterestRateType = loanProviderInterestRateType;
        return this;
    }

    /**
     * Interest rate types, other than APR, which financial institutions may use to describe the annual interest rate payable for the SME Loan.
     *
     * @return loanProviderInterestRateType
     **/
    @JsonProperty("LoanProviderInterestRateType")
    @ApiModelProperty(value = "Interest rate types, other than APR, which financial institutions may use to describe the annual interest rate payable for the SME Loan.")
    public LoanProviderInterestRateTypeEnum getLoanProviderInterestRateType() {
        return loanProviderInterestRateType;
    }

    public void setLoanProviderInterestRateType(LoanProviderInterestRateTypeEnum loanProviderInterestRateType) {
        this.loanProviderInterestRateType = loanProviderInterestRateType;
    }

    public OBReadProduct2DataOtherProductTypeLoanInterestLoanInterestTierBand identification(String identification) {
        this.identification = identification;
        return this;
    }

    /**
     * Unique and unambiguous identification of a  Tier Band for a SME Loan.
     *
     * @return identification
     **/
    @JsonProperty("Identification")
    @ApiModelProperty(value = "Unique and unambiguous identification of a  Tier Band for a SME Loan.")
    @Size(min = 1, max = 35)
    public String getIdentification() {
        return identification;
    }

    public void setIdentification(String identification) {
        this.identification = identification;
    }

    public OBReadProduct2DataOtherProductTypeLoanInterestLoanInterestTierBand tierValueMinTerm(Integer tierValueMinTerm) {
        this.tierValueMinTerm = tierValueMinTerm;
        return this;
    }

    /**
     * Minimum loan term for which the loan interest tier applies.
     *
     * @return tierValueMinTerm
     **/
    @JsonProperty("TierValueMinTerm")
    @ApiModelProperty(value = "Minimum loan term for which the loan interest tier applies.")
    public Integer getTierValueMinTerm() {
        return tierValueMinTerm;
    }

    public void setTierValueMinTerm(Integer tierValueMinTerm) {
        this.tierValueMinTerm = tierValueMinTerm;
    }

    public OBReadProduct2DataOtherProductTypeLoanInterestLoanInterestTierBand tierValueMaxTerm(Integer tierValueMaxTerm) {
        this.tierValueMaxTerm = tierValueMaxTerm;
        return this;
    }

    /**
     * Maximum loan term for which the loan interest tier applies.
     *
     * @return tierValueMaxTerm
     **/
    @JsonProperty("TierValueMaxTerm")
    @ApiModelProperty(value = "Maximum loan term for which the loan interest tier applies.")
    public Integer getTierValueMaxTerm() {
        return tierValueMaxTerm;
    }

    public void setTierValueMaxTerm(Integer tierValueMaxTerm) {
        this.tierValueMaxTerm = tierValueMaxTerm;
    }

    public OBReadProduct2DataOtherProductTypeLoanInterestLoanInterestTierBand maxTermPeriod(MaxTermPeriodEnum maxTermPeriod) {
        this.maxTermPeriod = maxTermPeriod;
        return this;
    }

    /**
     * The unit of period (days, weeks, months etc.) of the Maximum Term
     *
     * @return maxTermPeriod
     **/
    @JsonProperty("MaxTermPeriod")
    @ApiModelProperty(value = "The unit of period (days, weeks, months etc.) of the Maximum Term")
    public MaxTermPeriodEnum getMaxTermPeriod() {
        return maxTermPeriod;
    }

    public void setMaxTermPeriod(MaxTermPeriodEnum maxTermPeriod) {
        this.maxTermPeriod = maxTermPeriod;
    }

    public OBReadProduct2DataOtherProductTypeLoanInterestLoanInterestTierBand tierValueMinimum(String tierValueMinimum) {
        this.tierValueMinimum = tierValueMinimum;
        return this;
    }

    /**
     * Minimum loan value for which the loan interest tier applies.
     *
     * @return tierValueMinimum
     **/
    @JsonProperty("TierValueMinimum")
    @ApiModelProperty(value = "Minimum loan value for which the loan interest tier applies.")
    @Pattern(regexp = "^(-?\\\\d{1,14}){1}(\\\\.\\\\d{1,4}){0,1}$")
    public String getTierValueMinimum() {
        return tierValueMinimum;
    }

    public void setTierValueMinimum(String tierValueMinimum) {
        this.tierValueMinimum = tierValueMinimum;
    }

    public OBReadProduct2DataOtherProductTypeLoanInterestLoanInterestTierBand repAPR(String repAPR) {
        this.repAPR = repAPR;
        return this;
    }

    /**
     * The annual equivalent rate (AER) is interest that is calculated under the assumption that any interest paid is combined with the original balance and the next interest payment will be based on the slightly higher account balance. Overall, this means that interest can be compounded several times in a year depending on the number of times that interest payments are made.  For SME Loan, this APR is the representative APR which includes any account fees.
     *
     * @return repAPR
     **/
    @JsonProperty("RepAPR")
    @ApiModelProperty(value = "The annual equivalent rate (AER) is interest that is calculated under the assumption that any interest paid is combined with the original balance and the next interest payment will be based on the slightly higher account balance. Overall, this means that interest can be compounded several times in a year depending on the number of times that interest payments are made.  For SME Loan, this APR is the representative APR which includes any account fees.")
    @Pattern(regexp = "^(-?\\\\d{1,3}){1}(\\\\.\\\\d{1,4}){0,1}$")
    public String getRepAPR() {
        return repAPR;
    }

    public void setRepAPR(String repAPR) {
        this.repAPR = repAPR;
    }

    public OBReadProduct2DataOtherProductTypeLoanInterestLoanInterestTierBand otherLoanProviderInterestRateType(
            OBReadProduct2DataOtherProductTypeLoanInterestOtherLoanProviderInterestRateType otherLoanProviderInterestRateType) {
        this.otherLoanProviderInterestRateType = otherLoanProviderInterestRateType;
        return this;
    }

    /**
     * Get otherLoanProviderInterestRateType
     *
     * @return otherLoanProviderInterestRateType
     **/
    @JsonProperty("OtherLoanProviderInterestRateType")
    @ApiModelProperty(value = "")
    public OBReadProduct2DataOtherProductTypeLoanInterestOtherLoanProviderInterestRateType getOtherLoanProviderInterestRateType() {
        return otherLoanProviderInterestRateType;
    }

    public void setOtherLoanProviderInterestRateType(
            OBReadProduct2DataOtherProductTypeLoanInterestOtherLoanProviderInterestRateType otherLoanProviderInterestRateType) {
        this.otherLoanProviderInterestRateType = otherLoanProviderInterestRateType;
    }

    public OBReadProduct2DataOtherProductTypeLoanInterestLoanInterestTierBand loanProviderInterestRate(
            String loanProviderInterestRate) {
        this.loanProviderInterestRate = loanProviderInterestRate;
        return this;
    }

    /**
     * Loan provider Interest for the SME Loan product
     *
     * @return loanProviderInterestRate
     **/
    @JsonProperty("LoanProviderInterestRate")
    @ApiModelProperty(value = "Loan provider Interest for the SME Loan product")
    @Pattern(regexp = "^(-?\\\\d{1,3}){1}(\\\\.\\\\d{1,4}){0,1}$")
    public String getLoanProviderInterestRate() {
        return loanProviderInterestRate;
    }

    public void setLoanProviderInterestRate(String loanProviderInterestRate) {
        this.loanProviderInterestRate = loanProviderInterestRate;
    }

    public OBReadProduct2DataOtherProductTypeLoanInterestLoanInterestTierBand notes(List<String> notes) {
        this.notes = notes;
        return this;
    }

    public OBReadProduct2DataOtherProductTypeLoanInterestLoanInterestTierBand addNotesItem(String notesItem) {
        if (this.notes == null) {
            this.notes = new ArrayList<>();
        }
        this.notes.add(notesItem);
        return this;
    }

    /**
     * Get notes
     *
     * @return notes
     **/
    @JsonProperty("Notes")
    @ApiModelProperty(value = "")
    public List<String> getNotes() {
        return notes;
    }

    public void setNotes(List<String> notes) {
        this.notes = notes;
    }

    @Override
    public int hashCode() {
        return Objects
                .hash(fixedVariableInterestRateType, tierValueMaximum, minTermPeriod, loanInterestFeesCharges, loanProviderInterestRateType, identification, tierValueMinTerm, tierValueMaxTerm, maxTermPeriod, tierValueMinimum, repAPR, otherLoanProviderInterestRateType, loanProviderInterestRate, notes);
    }

    @Override
    public boolean equals(java.lang.Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        OBReadProduct2DataOtherProductTypeLoanInterestLoanInterestTierBand obReadProduct2DataOtherProductTypeLoanInterestLoanInterestTierBand = (OBReadProduct2DataOtherProductTypeLoanInterestLoanInterestTierBand) o;
        return Objects
                .equals(this.fixedVariableInterestRateType, obReadProduct2DataOtherProductTypeLoanInterestLoanInterestTierBand.fixedVariableInterestRateType) &&
                Objects.equals(this.tierValueMaximum, obReadProduct2DataOtherProductTypeLoanInterestLoanInterestTierBand.tierValueMaximum) &&
                Objects.equals(this.minTermPeriod, obReadProduct2DataOtherProductTypeLoanInterestLoanInterestTierBand.minTermPeriod) &&
                Objects.equals(this.loanInterestFeesCharges, obReadProduct2DataOtherProductTypeLoanInterestLoanInterestTierBand.loanInterestFeesCharges) &&
                Objects.equals(this.loanProviderInterestRateType, obReadProduct2DataOtherProductTypeLoanInterestLoanInterestTierBand.loanProviderInterestRateType) &&
                Objects.equals(this.identification, obReadProduct2DataOtherProductTypeLoanInterestLoanInterestTierBand.identification) &&
                Objects.equals(this.tierValueMinTerm, obReadProduct2DataOtherProductTypeLoanInterestLoanInterestTierBand.tierValueMinTerm) &&
                Objects.equals(this.tierValueMaxTerm, obReadProduct2DataOtherProductTypeLoanInterestLoanInterestTierBand.tierValueMaxTerm) &&
                Objects.equals(this.maxTermPeriod, obReadProduct2DataOtherProductTypeLoanInterestLoanInterestTierBand.maxTermPeriod) &&
                Objects.equals(this.tierValueMinimum, obReadProduct2DataOtherProductTypeLoanInterestLoanInterestTierBand.tierValueMinimum) &&
                Objects.equals(this.repAPR, obReadProduct2DataOtherProductTypeLoanInterestLoanInterestTierBand.repAPR) &&
                Objects.equals(this.otherLoanProviderInterestRateType, obReadProduct2DataOtherProductTypeLoanInterestLoanInterestTierBand.otherLoanProviderInterestRateType) &&
                Objects.equals(this.loanProviderInterestRate, obReadProduct2DataOtherProductTypeLoanInterestLoanInterestTierBand.loanProviderInterestRate) &&
                Objects.equals(this.notes, obReadProduct2DataOtherProductTypeLoanInterestLoanInterestTierBand.notes);
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("class OBReadProduct2DataOtherProductTypeLoanInterestLoanInterestTierBand {\n");

        sb.append("    fixedVariableInterestRateType: ").append(toIndentedString(fixedVariableInterestRateType)).append("\n");
        sb.append("    tierValueMaximum: ").append(toIndentedString(tierValueMaximum)).append("\n");
        sb.append("    minTermPeriod: ").append(toIndentedString(minTermPeriod)).append("\n");
        sb.append("    loanInterestFeesCharges: ").append(toIndentedString(loanInterestFeesCharges)).append("\n");
        sb.append("    loanProviderInterestRateType: ").append(toIndentedString(loanProviderInterestRateType)).append("\n");
        sb.append("    identification: ").append(toIndentedString(identification)).append("\n");
        sb.append("    tierValueMinTerm: ").append(toIndentedString(tierValueMinTerm)).append("\n");
        sb.append("    tierValueMaxTerm: ").append(toIndentedString(tierValueMaxTerm)).append("\n");
        sb.append("    maxTermPeriod: ").append(toIndentedString(maxTermPeriod)).append("\n");
        sb.append("    tierValueMinimum: ").append(toIndentedString(tierValueMinimum)).append("\n");
        sb.append("    repAPR: ").append(toIndentedString(repAPR)).append("\n");
        sb.append("    otherLoanProviderInterestRateType: ").append(toIndentedString(otherLoanProviderInterestRateType)).append("\n");
        sb.append("    loanProviderInterestRate: ").append(toIndentedString(loanProviderInterestRate)).append("\n");
        sb.append("    notes: ").append(toIndentedString(notes)).append("\n");
        sb.append("}");
        return sb.toString();
    }

    /**
     * Convert the given object to string with each line indented by 4 spaces
     * (except the first line).
     */
    private String toIndentedString(java.lang.Object o) {
        if (o == null) {
            return "null";
        }
        return o.toString().replace("\n", "\n    ");
    }

    /**
     * The unit of period (days, weeks, months etc.) of the Minimum Term
     */
    public enum MinTermPeriodEnum {
        PACT("PACT"),

        PDAY("PDAY"),

        PHYR("PHYR"),

        PMTH("PMTH"),

        PQTR("PQTR"),

        PWEK("PWEK"),

        PYER("PYER");

        private String value;

        MinTermPeriodEnum(String value) {
            this.value = value;
        }

        @JsonCreator
        public static MinTermPeriodEnum fromValue(String text) {
            for (MinTermPeriodEnum b : MinTermPeriodEnum.values()) {
                if (String.valueOf(b.value).equals(text)) {
                    return b;
                }
            }
            throw new IllegalArgumentException("Unexpected value '" + text + "'");
        }

        @Override
        @JsonValue
        public String toString() {
            return String.valueOf(value);
        }
    }


    /**
     * Interest rate types, other than APR, which financial institutions may use to describe the annual interest rate payable for the SME Loan.
     */
    public enum LoanProviderInterestRateTypeEnum {
        INBB("INBB"),

        INFR("INFR"),

        INGR("INGR"),

        INLR("INLR"),

        INNE("INNE"),

        INOT("INOT");

        private String value;

        LoanProviderInterestRateTypeEnum(String value) {
            this.value = value;
        }

        @JsonCreator
        public static LoanProviderInterestRateTypeEnum fromValue(String text) {
            for (LoanProviderInterestRateTypeEnum b : LoanProviderInterestRateTypeEnum.values()) {
                if (String.valueOf(b.value).equals(text)) {
                    return b;
                }
            }
            throw new IllegalArgumentException("Unexpected value '" + text + "'");
        }

        @Override
        @JsonValue
        public String toString() {
            return String.valueOf(value);
        }
    }

    /**
     * The unit of period (days, weeks, months etc.) of the Maximum Term
     */
    public enum MaxTermPeriodEnum {
        PACT("PACT"),

        PDAY("PDAY"),

        PHYR("PHYR"),

        PMTH("PMTH"),

        PQTR("PQTR"),

        PWEK("PWEK"),

        PYER("PYER");

        private String value;

        MaxTermPeriodEnum(String value) {
            this.value = value;
        }

        @JsonCreator
        public static MaxTermPeriodEnum fromValue(String text) {
            for (MaxTermPeriodEnum b : MaxTermPeriodEnum.values()) {
                if (String.valueOf(b.value).equals(text)) {
                    return b;
                }
            }
            throw new IllegalArgumentException("Unexpected value '" + text + "'");
        }

        @Override
        @JsonValue
        public String toString() {
            return String.valueOf(value);
        }
    }
}

