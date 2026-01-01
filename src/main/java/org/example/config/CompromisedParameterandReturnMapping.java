package org.example.config;

import java.util.Map;

public class CompromisedParameterandReturnMapping {
    private Map<Integer, String> taintedParametermapping;
    private final boolean markReturnTainted;
    private boolean returnDeclassifiedByUntrigger;

    public CompromisedParameterandReturnMapping(Map<Integer, String> mapping, boolean markReturnTainted) {
        this.taintedParametermapping = mapping;
        this.markReturnTainted = markReturnTainted;
        this.returnDeclassifiedByUntrigger = false;
    }

    public Map<Integer, String> gettaintedParametermapping() {
        return taintedParametermapping;
    }
    public boolean isMarkReturnTainted() {
        return markReturnTainted;
    }

    public void setMapping(Map<Integer, String> mapping) {
        this.taintedParametermapping = mapping;
    }

    public boolean isReturnDeclassifiedByUntrigger() {
        return returnDeclassifiedByUntrigger;
    }

    public void setReturnDeclassifiedByUntrigger(boolean returnDeclassifiedByUntrigger) {
        this.returnDeclassifiedByUntrigger = returnDeclassifiedByUntrigger;
    }
}
