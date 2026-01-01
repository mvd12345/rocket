package org.example.bytecode;

import org.apache.bcel.classfile.ClassParser;
import org.apache.bcel.classfile.JavaClass;
import org.apache.bcel.classfile.LineNumber;
import org.apache.bcel.classfile.LineNumberTable;
import org.apache.bcel.classfile.LocalVariable;
import org.apache.bcel.classfile.LocalVariableTable;
import org.apache.commons.lang3.StringUtils;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Utility for resolving source-level local variable names based on bytecode metadata.
 *
 * This class reads the {@code LineNumberTable} and {@code LocalVariableTable} entries of compiled
 * class files (when debug information is available) to infer which Java locals are live at a given
 * source line. The goal is to enrich diagnostics without mutating the core analysis pipeline.
 */
public final class LocalVariableResolver
{
    private static final Map<String, JavaClass> CLASS_CACHE = new ConcurrentHashMap<>();

    private LocalVariableResolver()
    {
    }

    /**
     * Attempts to resolve the set of local variable names that are live for the specified method
     * and source line. Returns an empty set when the information is unavailable.
     *
     * @param classesRoot directory containing the compiled class files
     * @param className   fully qualified class name
     * @param methodName  simple method name
     * @param lineNumber  1-based Java source line number
     * @return set of candidate variable names (may be empty)
     */
    public static Set<String> resolve(String classesRoot, String className, String methodName, int lineNumber)
    {
        if (StringUtils.isBlank(classesRoot) || StringUtils.isBlank(className) || StringUtils.isBlank(methodName) || lineNumber < 1)
        {
            return Collections.emptySet();
        }

        JavaClass javaClass = loadClass(classesRoot, className);
        if (javaClass == null)
        {
            return Collections.emptySet();
        }

        Set<String> candidates = new LinkedHashSet<>();
        for (org.apache.bcel.classfile.Method method : javaClass.getMethods())
        {
            if (!methodName.equals(method.getName()))
            {
                continue;
            }

            LineNumberTable lineNumberTable = method.getLineNumberTable();
            LocalVariableTable localVariableTable = method.getLocalVariableTable();
            if (lineNumberTable == null || localVariableTable == null)
            {
                continue;
            }

            Map<Integer, Integer> pcToLine = buildPcToLineMap(lineNumberTable);
            List<Integer> programCounters = pcsForLine(pcToLine, lineNumber);
            if (programCounters.isEmpty())
            {
                continue;
            }

            LocalVariable[] variables = localVariableTable.getLocalVariableTable();
            if (variables == null)
            {
                continue;
            }

            for (LocalVariable localVariable : variables)
            {
                if (localVariable == null)
                {
                    continue;
                }
                String name = localVariable.getName();
                if (StringUtils.isBlank(name) || "this".equals(name))
                {
                    continue;
                }

                int startPc = localVariable.getStartPC();
                int endPc = startPc + localVariable.getLength();
                if (programCounters.stream().anyMatch(pc -> pc >= startPc && pc < endPc))
                {
                    candidates.add(name);
                }
            }

            if (!candidates.isEmpty())
            {
                break; // prefer the first matching overload
            }
        }

        return candidates;
    }

    /**
     * Indicates whether any {@code LocalVariableTable} metadata is available for the supplied class.
     * This is a proxy for "javac was invoked with debugging symbols".
     */
    public static boolean hasLocalVariableMetadata(String classesRoot, String className)
    {
        if (StringUtils.isBlank(classesRoot) || StringUtils.isBlank(className))
        {
            return false;
        }
        JavaClass javaClass = loadClass(classesRoot, className);
        if (javaClass == null)
        {
            return false;
        }
        for (org.apache.bcel.classfile.Method method : javaClass.getMethods())
        {
            if (method.getLocalVariableTable() != null)
            {
                return true;
            }
        }
        return false;
    }

    /**
     * Indicates whether any {@code LineNumberTable} metadata is available for the supplied class.
     */
    public static boolean hasLineNumberMetadata(String classesRoot, String className)
    {
        if (StringUtils.isBlank(classesRoot) || StringUtils.isBlank(className))
        {
            return false;
        }
        JavaClass javaClass = loadClass(classesRoot, className);
        if (javaClass == null)
        {
            return false;
        }
        for (org.apache.bcel.classfile.Method method : javaClass.getMethods())
        {
            if (method.getLineNumberTable() != null)
            {
                return true;
            }
        }
        return false;
    }

    private static JavaClass loadClass(String classesRoot, String className)
    {
        String cacheKey = classesRoot + "::" + className;
        return CLASS_CACHE.computeIfAbsent(cacheKey, key -> {
            Path classFile = Path.of(classesRoot).resolve(className.replace('.', '/') + ".class");
            if (!Files.exists(classFile))
            {
                return null;
            }
            try
            {
                return new ClassParser(classFile.toString()).parse();
            }
            catch (IOException ex)
            {
                return null;
            }
        });
    }

    private static Map<Integer, Integer> buildPcToLineMap(LineNumberTable table)
    {
        Map<Integer, Integer> mapping = new TreeMap<>();
        LineNumber[] entries = table.getLineNumberTable();
        if (entries == null || entries.length == 0)
        {
            return mapping;
        }

        for (LineNumber entry : entries)
        {
            mapping.put(entry.getStartPC(), entry.getLineNumber());
        }
        return mapping;
    }

    private static List<Integer> pcsForLine(Map<Integer, Integer> pcToLine, int lineNumber)
    {
        List<Integer> pcs = new ArrayList<>();
        if (pcToLine.isEmpty())
        {
            return pcs;
        }

        int lastMatchPc = -1;
        for (Map.Entry<Integer, Integer> entry : pcToLine.entrySet())
        {
            int pc = entry.getKey();
            int line = entry.getValue();

            if (line == lineNumber)
            {
                pcs.add(pc);
                lastMatchPc = pc;
            }
            else if (line > lineNumber && lastMatchPc >= 0)
            {
                // stop once we've stepped past the desired line and already recorded at least one pc
                break;
            }
        }

        if (pcs.isEmpty())
        {
            // fall back to predecessor entry (largest line less than requested)
            int candidatePc = -1;
            for (Map.Entry<Integer, Integer> entry : pcToLine.entrySet())
            {
                if (entry.getValue() < lineNumber)
                {
                    candidatePc = entry.getKey();
                }
                else
                {
                    break;
                }
            }
            if (candidatePc >= 0)
            {
                pcs.add(candidatePc);
            }
        }
        return pcs;
    }
}
