package org.example.config;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import sootup.core.model.Position;
import sootup.core.signatures.PackageName;
import sootup.core.types.ClassType;
import sootup.core.types.PrimitiveType;
import sootup.core.types.Type;
import sootup.core.types.VoidType;
import sootup.java.core.types.JavaClassType;

import java.io.File;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class MethodSignatureConfigLoader
{
    private static final String SEP = "#";

    // Assuming you have a class to represent the JSON structure
    public static class MethodConfig
    {
        public String className;
        public String methodName;
        public List<ParameterConfig> parameters;
        public ParameterConfig returnType; // New field for return type
        public TaintConfig taintConfig;
        public List<String> fullyQualifiedMethods;
        public List<MutedRange> mutedRanges = new ArrayList<>();
    }


    public static class MutedRange
    {
        @JsonProperty("class")
        public String clasName;
        @JsonProperty("method")
        public String method;

        public int lineFrom;
        public int lineTo;
        public Integer columnFrom = -1;
        public Integer columnTo = -1;
        public String suppress;
        public String reason;

        public boolean positionEquals(Position position)
        {
            int firstLine = position.getFirstLine();
            int lastLine = position.getLastLine();
            int firstCol = position.getFirstCol();
            int lastCol = position.getLastCol();

            boolean columnInfoRequested = columnFrom != null && columnTo != null && columnFrom >= 0 && columnTo >= 0;
            boolean columnInfoAvailable = lastCol != -1 && lastCol != Integer.MAX_VALUE && firstCol != Integer.MAX_VALUE;

            if (columnInfoRequested && columnInfoAvailable)
            {
                return firstLine == lineFrom && lastLine == lineTo
                        && firstCol == columnFrom && lastCol == columnTo;
            }

            return firstLine == lineFrom && lastLine == lineTo;
        }

    }

    public static class ParameterConfig
    {
        public String type;
        public int dimension; // Used for arrays
        public String packageName; // Used for class types
        public String className; // Used for class types
    }

    public static MethodConfig parseConfig(String jsonFilePath) throws Exception
    {
        ObjectMapper objectMapper = new ObjectMapper()
                .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        return objectMapper.readValue(new File(jsonFilePath), MethodConfig.class);
    }

    public static Map<String, Integer> buildIndex(MethodConfig cfg)
    {
        Map<String, Integer> idx = new LinkedHashMap<>();
        int i = 0;
        if (cfg != null && cfg.fullyQualifiedMethods != null)
        {
            for (String raw : cfg.fullyQualifiedMethods)
            {
                if (raw == null) continue;
                raw = raw.trim();
                if (raw.isEmpty()) continue;

                String[] parts = splitFqm(raw); // [0]=class, [1]=method
                String key = toKey(parts[0], parts[1]);

                // assign stable index in insertion order; ignore duplicates
                if (idx.putIfAbsent(key, i) == null)
                {
                    i++;
                }
            }
        }
        return idx;
    }

    private static String[] splitFqm(String s)
    {
        int pos = s.lastIndexOf("::");
        if (pos <= 0 || pos == s.length() - 2)
        {
            throw new IllegalArgumentException("Cannot parse fullyQualifiedMethod (expected Class::method): " + s);
        }
        String cls = s.substring(0, pos);
        String mtd = s.substring(pos + 2);
        return new String[]{cls, mtd};
    }

    public static String toKey(String className, String methodName)
    {
        return className + SEP + methodName;
    }

    public static List<Type> createParameterTypes(MethodConfig methodConfig)
    {
        List<Type> parameterTypes = new ArrayList<>();
        if (methodConfig.parameters == null || methodConfig.parameters.isEmpty())
        {
            return parameterTypes; // This will be an empty List<Type>
        }
        // Logic to create parameter types based on MethodConfig
        for (ParameterConfig param : methodConfig.parameters)
        {
            switch (param.type)
            {
                case "byte":
                    parameterTypes.add(PrimitiveType.getByte());
                    break;
                case "short":
                    parameterTypes.add(PrimitiveType.getShort());
                    break;
                case "int":
                    parameterTypes.add(PrimitiveType.getInt());
                    break;
                case "long":
                    parameterTypes.add(PrimitiveType.getLong());
                    break;
                case "float":
                    parameterTypes.add(PrimitiveType.getFloat());
                    break;
                case "double":
                    parameterTypes.add(PrimitiveType.getDouble());
                    break;
                case "char":
                    parameterTypes.add(PrimitiveType.getChar());
                    break;
                case "boolean":
                    parameterTypes.add(PrimitiveType.getBoolean());
                    break;
                case "byte[]":
                    parameterTypes.add(Type.createArrayType(PrimitiveType.getByte(), param.dimension));
                    break;
                case "short[]":
                    parameterTypes.add(Type.createArrayType(PrimitiveType.getShort(), param.dimension));
                    break;
                case "int[]":
                    parameterTypes.add(Type.createArrayType(PrimitiveType.getInt(), param.dimension));
                    break;
                case "long[]":
                    parameterTypes.add(Type.createArrayType(PrimitiveType.getLong(), param.dimension));
                    break;
                case "float[]":
                    parameterTypes.add(Type.createArrayType(PrimitiveType.getFloat(), param.dimension));
                    break;
                case "double[]":
                    parameterTypes.add(Type.createArrayType(PrimitiveType.getDouble(), param.dimension));
                    break;
                case "char[]":
                    parameterTypes.add(Type.createArrayType(PrimitiveType.getChar(), param.dimension));
                    break;
                case "boolean[]":
                    parameterTypes.add(Type.createArrayType(PrimitiveType.getBoolean(), param.dimension));
                    break;
                case "class":
                    PackageName packageName = new PackageName(param.packageName);
                    ClassType classType = new JavaClassType(param.className, packageName);
                    parameterTypes.add(classType);
                    break;
                // Add other cases as needed
            }
        }
        return parameterTypes;
    }

    public static Type createReturnType(MethodConfig methodConfig)
    {
        ParameterConfig returnParam = methodConfig.returnType;
        return createType(returnParam);
    }

    private static Type createType(ParameterConfig param)
    {
        switch (param.type)
        {
            case "byte":
                return PrimitiveType.ByteType.getInstance();
            case "short":
                return PrimitiveType.ShortType.getInstance();
            case "int":
                return PrimitiveType.IntType.getInstance();
            case "long":
                return PrimitiveType.LongType.getInstance();
            case "float":
                return PrimitiveType.FloatType.getInstance();
            case "double":
                return PrimitiveType.DoubleType.getInstance();
            case "char":
                return PrimitiveType.CharType.getInstance();
            case "boolean":
                return PrimitiveType.BooleanType.getInstance();
            case "byte[]":
                return Type.createArrayType(PrimitiveType.getByte(), param.dimension);
            case "short[]":
                return Type.createArrayType(PrimitiveType.getShort(), param.dimension);
            case "int[]":
                return Type.createArrayType(PrimitiveType.getInt(), param.dimension);
            case "long[]":
                return Type.createArrayType(PrimitiveType.getLong(), param.dimension);
            case "float[]":
                return Type.createArrayType(PrimitiveType.getFloat(), param.dimension);
            case "double[]":
                return Type.createArrayType(PrimitiveType.getDouble(), param.dimension);
            case "char[]":
                return Type.createArrayType(PrimitiveType.getChar(), param.dimension);
            case "boolean[]":
                return Type.createArrayType(PrimitiveType.getBoolean(), param.dimension);
            case "class":
                PackageName packageName = new PackageName(param.packageName);
                ClassType classType = new JavaClassType(param.className, packageName);
                return classType;
            // add additional cases
            case "class[]":
                PackageName classPackageName = new PackageName(param.packageName);
                ClassType classArrayType = new JavaClassType(param.className, classPackageName);
                return Type.createArrayType(classArrayType, param.dimension);
            case "void":
                return VoidType.getInstance();
            default:
                throw new IllegalArgumentException("Unsupported type: " + param.type);
        }
    }

}
