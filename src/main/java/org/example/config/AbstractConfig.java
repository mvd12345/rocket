package org.example.config;

import com.google.gson.annotations.SerializedName;

import java.util.*;
public class AbstractConfig {
    @SerializedName("classImplMapping")
    private Map<String, String> classImplMapping;

    public Map<String, String> getClassImplMapping() {
        return classImplMapping;
    }

    public void setClassImplMapping(Map<String, String> classImplMapping) {
        this.classImplMapping = classImplMapping;
    }
}
