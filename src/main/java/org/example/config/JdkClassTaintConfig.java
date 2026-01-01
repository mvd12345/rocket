package org.example.config;

import com.google.gson.annotations.SerializedName;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class JdkClassTaintConfig {
    @SerializedName("methodList")
    private List<JdkMethodTaintConfig> jdkMethodTaintConfigList;

    private Map<String, JdkMethodTaintConfig> jdkMethodTaintConfigMap;

    public JdkClassTaintConfig() {
    }
    public JdkMethodTaintConfig getJdkMethodTaintConfig(String pkgName, String className, String methodName) {

        if (jdkMethodTaintConfigMap == null) {
            jdkMethodTaintConfigMap = new HashMap<>();
            for (JdkMethodTaintConfig jdkMethodTaintConfig : jdkMethodTaintConfigList){
                jdkMethodTaintConfigMap
                        .put(generateKey(jdkMethodTaintConfig.getPkgName(), jdkMethodTaintConfig.getClassName(), jdkMethodTaintConfig.getMethodName()), jdkMethodTaintConfig);
            }
        }
        String key = generateKey(pkgName, className, methodName);
        return jdkMethodTaintConfigMap.get(key);
    }

    private String  generateKey(String pkgName, String className, String methodName) {
        //java.lang.System#arrayCopy,
        return className + "#" + methodName;
    }
}
