package org.example.config;

import com.google.gson.annotations.SerializedName;

import java.util.ArrayList;
import java.util.List;

public class JdkMethodTaintConfig {
    @SerializedName("pkgName")
    private String pkgName;

    @SerializedName("className")
    private String className;

    @SerializedName("method")
    private String methodName;

    @SerializedName("taintIndices")
    private String taintIndices;

    private List<Integer> indicesList;

    public String getPkgName() {
        return pkgName;
    }

    public String getMethodName() {
        return methodName;
    }

    public List<Integer> getTaintIndices() {
        if (indicesList == null) {
            String[] indicies = taintIndices.split(",");
            indicesList = new ArrayList<>();
            for (String index : indicies) {
                indicesList.add(Integer.parseInt(index));
            }
        }
        return indicesList;
    }

    public String getClassName() {
        return className;
    }
}
