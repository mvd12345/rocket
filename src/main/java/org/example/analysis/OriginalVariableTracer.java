package org.example.analysis;

import org.apache.commons.lang3.StringUtils;
import sootup.core.jimple.basic.Immediate;
import sootup.core.jimple.basic.LValue;
import sootup.core.jimple.basic.Local;
import sootup.core.jimple.basic.Value;
import sootup.core.jimple.common.expr.AbstractInvokeExpr;
import sootup.core.jimple.common.expr.AbstractUnopExpr;
import sootup.core.jimple.common.expr.AbstractInstanceInvokeExpr;
import sootup.core.jimple.common.ref.JArrayRef;
import sootup.core.jimple.common.ref.JFieldRef;
import sootup.core.jimple.common.ref.JCaughtExceptionRef;
import sootup.core.jimple.common.ref.JParameterRef;
import sootup.core.jimple.common.ref.JThisRef;
import sootup.core.jimple.common.stmt.JAssignStmt;
import sootup.core.jimple.common.stmt.JIdentityStmt;
import sootup.core.jimple.common.stmt.Stmt;
import sootup.core.model.Body;

import java.util.*;
import java.util.stream.Stream;

/**
 * Best-effort resolver that attempts to map Jimple temporaries (e.g. {@code $stack23}) back to
 * user-declared local variables by chasing their definition chain within a method {@link Body}.
 *
 * This intentionally lives outside the main analysis pipeline so that refined reports can surface
 * probable source identifiers without influencing taint propagation.
 */
public final class OriginalVariableTracer
{
    private OriginalVariableTracer()
    {
    }

    /**
     * Resolve a Jimple variable name to probable source-level identifiers.
     *
     * @param body        method body providing locals/definitions
     * @param variable    Jimple variable name (e.g. {@code $stack17} or {@code idx2})
     * @return ordered set of candidate source identifiers
     */
    public static Set<String> trace(Body body, String variable)
    {
        if (body == null || StringUtils.isBlank(variable))
        {
            return Collections.emptySet();
        }

        String baseName = normaliseVariableName(variable);
        Local local = findLocal(body, baseName);
        if (local == null)
        {
            return Collections.emptySet();
        }

        if (!isSynthetic(local))
        {
            return Set.of(local.getName());
        }

        Map<LValue, Collection<Stmt>> defs = Body.collectDefs(body.getStmts());
        IdentityHashMap<Local, Set<String>> cache = new IdentityHashMap<>();
        return resolveLocal(local, body, defs, cache, new HashSet<Local>());
    }

    private static Set<String> resolveLocal(Local local,
                                            Body body,
                                            Map<LValue, Collection<Stmt>> defs,
                                            IdentityHashMap<Local, Set<String>> cache,
                                            Set<Local> visiting)
    {
        if (!isSynthetic(local))
        {
            return Set.of(local.getName());
        }

        if (!visiting.add(local))
        {
            return Collections.emptySet();
        }

        if (cache.containsKey(local))
        {
            return cache.get(local);
        }

        Collection<Stmt> definitionStmts = defs.getOrDefault(local, Collections.emptyList());
        if (definitionStmts.isEmpty())
        {
            cache.put(local, Collections.emptySet());
            return Collections.emptySet();
        }

        LinkedHashSet<String> resolvedNames = new LinkedHashSet<>();
        for (Stmt stmt : definitionStmts)
        {
            if (stmt instanceof JAssignStmt assign)
            {
                collectFromValueStream(assign.getUses(), body, defs, cache, visiting, resolvedNames);
                collectFromValue(assign.getRightOp(), body, defs, cache, visiting, resolvedNames);
            }
            else if (stmt instanceof JIdentityStmt identity)
            {
                collectFromValue(identity.getRightOp(), body, defs, cache, visiting, resolvedNames);
            }
        }

        visiting.remove(local);
        cache.put(local, resolvedNames);
        return resolvedNames;
    }

    private static void collectFromValue(Value value,
                                         Body body,
                                         Map<LValue, Collection<Stmt>> defs,
                                         IdentityHashMap<Local, Set<String>> cache,
                                         Set<Local> visiting,
                                         Set<String> resolvedNames)
    {
        if (value == null)
        {
            return;
        }
        if (value instanceof Local nestedLocal)
        {
            resolvedNames.addAll(resolveLocal(nestedLocal, body, defs, cache, visiting));
        }
        else if (value instanceof JArrayRef arrayRef)
        {
            collectFromValue(arrayRef.getBase(), body, defs, cache, visiting, resolvedNames);
            collectFromValue(arrayRef.getIndex(), body, defs, cache, visiting, resolvedNames);
        }
        else if (value instanceof AbstractInvokeExpr invokeExpr)
        {
            for (Immediate arg : invokeExpr.getArgs())
            {
                collectFromValue((Value) arg, body, defs, cache, visiting, resolvedNames);
            }
            if (invokeExpr instanceof AbstractInstanceInvokeExpr instanceInvokeExpr)
            {
                collectFromValue(instanceInvokeExpr.getBase(), body, defs, cache, visiting, resolvedNames);
            }
        }
        else if (value instanceof AbstractUnopExpr unopExpr)
        {
            collectFromValue(unopExpr.getOp(), body, defs, cache, visiting, resolvedNames);
        }
        else if (value instanceof JFieldRef fieldRef)
        {
            if (fieldRef instanceof sootup.core.jimple.common.ref.JInstanceFieldRef instanceFieldRef)
            {
                collectFromValue(instanceFieldRef.getBase(), body, defs, cache, visiting, resolvedNames);
            }
        }
        else if (value instanceof JParameterRef parameterRef)
        {
            int index = parameterRef.getIndex();
            try
            {
                Local paramLocal = body.getParameterLocal(index);
                if (paramLocal != null)
                {
                    resolvedNames.add(paramLocal.getName());
                }
            }
            catch (IllegalArgumentException ignored)
            {
                // fall through
            }
        }
        else if (value instanceof JThisRef)
        {
            resolvedNames.add("this");
        }
        else if (value instanceof JCaughtExceptionRef)
        {
            resolvedNames.add("@exception");
        }
    }

    private static void collectFromValueStream(Stream<Value> stream,
                                               Body body,
                                               Map<LValue, Collection<Stmt>> defs,
                                               IdentityHashMap<Local, Set<String>> cache,
                                               Set<Local> visiting,
                                               Set<String> resolvedNames)
    {
        if (stream == null)
        {
            return;
        }
        stream.forEach(value -> collectFromValue(value, body, defs, cache, visiting, resolvedNames));
    }

    private static Local findLocal(Body body, String name)
    {
        if (StringUtils.isBlank(name))
        {
            return null;
        }
        return body.getLocals().stream()
                .filter(local -> name.equals(local.getName()))
                .findFirst()
                .orElse(null);
    }

    private static boolean isSynthetic(Local local)
    {
        String name = local.getName();
        return name.startsWith("$") || name.startsWith("tmp") || name.startsWith("stack");
    }

    private static String normaliseVariableName(String variable)
    {
        int bracketIndex = variable.indexOf('[');
        if (bracketIndex > 0)
        {
            return variable.substring(0, bracketIndex);
        }
        int spaceIdx = variable.indexOf(' ');
        if (spaceIdx > 0)
        {
            return variable.substring(0, spaceIdx);
        }
        return variable;
    }
}
