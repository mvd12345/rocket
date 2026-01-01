package org.example.config;

import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;

import com.google.gson.annotations.SerializedName;

// Jackson
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.annotation.JsonSetter;
import com.fasterxml.jackson.annotation.Nulls;

@JsonIgnoreProperties(ignoreUnknown = true)
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public class TaintConfig {

    @SerializedName("interactive_mode")
    // primitive boolean already defaults to false when missing
    private boolean interactiveMode = false;

    @SerializedName("tainted_variables")
    @JsonSetter(nulls = Nulls.AS_EMPTY)
    private Set<String> taintedVariables = new LinkedHashSet<>();

    @SerializedName("untainted_variables")
    @JsonSetter(nulls = Nulls.AS_EMPTY)
    private Set<String> untaintedVariables = new LinkedHashSet<>();

    @SerializedName("secret_variables")
    @JsonSetter(nulls = Nulls.AS_EMPTY)
    private Set<String> secretVariables = new LinkedHashSet<>();

    @SerializedName("tainted_local_variables")
    @JsonSetter(nulls = Nulls.AS_EMPTY)
    private Set<String> taintedLocalVariables = new LinkedHashSet<>();

    @SerializedName("tainted_class_variables")
    @JsonSetter(nulls = Nulls.AS_EMPTY)
    private Set<String> taintedClassVariables = new LinkedHashSet<>();

    // --- Safe getters (never return null) ---
    public boolean isInteractiveMode() { return interactiveMode; }
    public void setInteractiveMode(boolean interactiveMode) { this.interactiveMode = interactiveMode; }

    public Set<String> getTaintedVariables() {
        return taintedVariables != null ? taintedVariables : Collections.emptySet();
    }
    public void setTaintedVariables(Set<String> taintedVariables) {
        this.taintedVariables = (taintedVariables != null) ? taintedVariables : new LinkedHashSet<>();
    }

    public Set<String> getUntaintedVariables() {
        return untaintedVariables != null ? untaintedVariables : Collections.emptySet();
    }
    public void setUntaintedVariables(Set<String> untaintedVariables) {
        this.untaintedVariables = (untaintedVariables != null) ? untaintedVariables : new LinkedHashSet<>();
    }

    public Set<String> getSecretVariables() {
        return secretVariables != null ? secretVariables : Collections.emptySet();
    }
    public void setSecretVariables(Set<String> secretVariables) {
        this.secretVariables = (secretVariables != null) ? secretVariables : new LinkedHashSet<>();
    }

    public Set<String> getTaintedLocalVariables() {
        return taintedLocalVariables != null ? taintedLocalVariables : Collections.emptySet();
    }
    public void setTaintedLocalVariables(Set<String> taintedLocalVariables) {
        this.taintedLocalVariables = (taintedLocalVariables != null) ? taintedLocalVariables : new LinkedHashSet<>();
    }

    public Set<String> getTaintedClassVariables() {
        return taintedClassVariables != null ? taintedClassVariables : Collections.emptySet();
    }
    public void setTaintedClassVariables(Set<String> taintedClassVariables) {
        this.taintedClassVariables = (taintedClassVariables != null) ? taintedClassVariables : new LinkedHashSet<>();
    }

    /** Optional belt-and-braces; call after parsing if you like */
    public void normalize() {
        if (taintedVariables == null) taintedVariables = new LinkedHashSet<>();
        if (untaintedVariables == null) untaintedVariables = new LinkedHashSet<>();
        if (secretVariables == null) secretVariables = new LinkedHashSet<>();
        if (taintedLocalVariables == null) taintedLocalVariables = new LinkedHashSet<>();
        if (taintedClassVariables == null) taintedClassVariables = new LinkedHashSet<>();
    }
}
