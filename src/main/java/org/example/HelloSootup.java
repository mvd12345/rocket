package org.example;

import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import lombok.extern.slf4j.Slf4j;
import org.apache.bcel.classfile.ClassParser;
import org.apache.bcel.classfile.JavaClass;
import org.apache.commons.cli.*;
import org.apache.commons.lang3.StringUtils;
import org.example.analysis.OriginalVariableTracer;
import org.example.config.*;
import org.example.bytecode.LocalVariableResolver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import sootup.core.inputlocation.AnalysisInputLocation;
import sootup.core.jimple.basic.*;
import sootup.core.jimple.common.constant.Constant;
import sootup.core.jimple.common.constant.NullConstant;
import sootup.core.jimple.common.expr.*;
import sootup.core.jimple.common.ref.JArrayRef;
import sootup.core.jimple.common.ref.JInstanceFieldRef;
import sootup.core.jimple.common.ref.JParameterRef;
import sootup.core.jimple.common.stmt.*;
import sootup.core.model.*;
import sootup.core.signatures.FieldSignature;
import sootup.core.signatures.MethodSignature;
import sootup.core.types.ClassType;
import sootup.core.types.PrimitiveType;
import sootup.core.types.ReferenceType;
import sootup.core.types.Type;
import sootup.java.bytecode.inputlocation.JavaClassPathAnalysisInputLocation;
import sootup.java.core.*;
import sootup.java.core.language.JavaLanguage;
import sootup.java.core.types.JavaClassType;
import sootup.java.core.views.JavaView;

import java.io.*;
import java.lang.annotation.Annotation;
import java.lang.reflect.Field;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.time.LocalDate;
import java.util.*;
import java.util.stream.Collectors;

@Slf4j
public class HelloSootup
{


    private static final boolean RUN_PACKAGE = false;

    private static int lineOfCode = 0;
    public static String SOURCE_DIRECTORY = System.getProperty("user.dir") + File.separator + "crypto";

    public static String TAINT_DIRECTORY = System.getProperty("user.dir") + File.separator + "crypto" + File.separator + "taintpkg";

    public static String[] TAINT_DIRECTORY_CLASSES_SKIP = new String[]{"Taint$Parameters", "Taint$Untrigger", "Taint$Trigger", "Taint"};

    // Example compiled class root (set via CLI or config as needed).
    public static String OUTPUT_DIRECTORY =
            Paths.get(System.getProperty("user.dir"), "target", "test-classes").toString();

    public static String OUTPUT_FILE_DIRECTORY =
            Paths.get(System.getProperty("user.dir"), "src", "test", "java").toString();

    public static String CONFIG_DIRECTORY =
            System.getProperty("user.dir") + File.separator + "demo" + File.separator + "config";

    public static String CLASS_NAME = "org.bouncycastle.pqc.crypto.picnic.PicnicEngine";
    public static String METHOD_NAME = "sign_picnic3";

    public static String PKG_NAME = "org.bouncycastle.pqc.crypto.picnic.PicnicEngine";

    private static final String CLASS_PATH_OPTION = "sd";

    private static final String CLASS_OPTION = "c";

    private static final String METHOD_OPTION = "m";

    private static final String INPUT_OPTIONS = "i";

    private static final String OUTPUT_OPTIONS = "o";

    private static boolean PROMPT_REQUIRED = true;

    private static boolean TAINT_UNTRIGGER = false;
    private static boolean TAINT_TRIGGER = false; // annotation verification

    private static boolean ENABLE_TRIGGER_AUTOSCAN = false;

    protected static final Options COMMAND_LINE_OPTIONS = new Options();

    private static final Set<String> LOADED_CLASSES = new HashSet<>();

    private static Set<sootup.core.jimple.common.stmt.Stmt> STMT_SET_STATIC_ERRORS;
    private static Set<Stmt> STMT_SET_ERRORS_METHOD;

    private static List<String> TAINTED_VARIABLES;

    private static List<String> UNTAINTED_VARIABLES;

    private static List<String> TAINTED_CLASS_VARIABLES;

    private static List<String> TAINTED_LOCAL_VARIABLES;

    private static TaintConfig TAINT_CONFIG = null;

    private static AbstractConfig ABSTRACT_CONFIG = null;

    private static JdkClassTaintConfig JDK_CLASS_TAINT_CONFIG = null;

    private static boolean TAINT_CONFIG_TO_BE_SET = true;

    private static Set<Output> OUTPUT_LIST;
    private static Set<MethodVisitStatus> methodVisitStatusSet;

    private static final java.util.concurrent.ConcurrentMap<String, Map<String, AnnotationState>>
            FIELD_TAG_CACHE = new java.util.concurrent.ConcurrentHashMap<>();

    private enum AnnotationState
    {TRIGGER, UNTRIGGER, BOTH, NONE}

    private static final String ANN_TRIGGER = "com.example.myapp.Tests.Taint$Trigger";
    private static final String ANN_UNTRIGGER = "com.example.myapp.Tests.Taint$Untrigger";

    private static int problems = 0;
    private static int supressedProblems = 0;


    /**
     * We skip the following java libraries.
     */
    private static String[] ignored_packages = {
            "java.", "javax.", "sun.", "sootup"
    };

    private static Logger logger = LoggerFactory.getLogger(HelloSootup.class);
    private static Set<String> JAVA_PKG_LIST = new LinkedHashSet<>();
    private Object sootClassObject;

    private static JavaView javaProject;

    public static String JSON_FILE_PATH;

    private static MethodSignatureConfigLoader.MethodConfig methodConfig;

    public static Map<String, Integer> TARGET_FQM_INDEX = new LinkedHashMap<>();

    private static List<Stmt> scannedIfStmts = new ArrayList<>();
    private static List<Stmt> scannedElseStmts = new ArrayList<>();

    private static final List<SubclassErrorEntry> SUBCLASS_ERR_LIST = new ArrayList<>();

    /**
     * Constructor to initialise the static variables
     */

    protected HelloSootup()
    {
        initialize();
    }

    private static void initialize()
    {
        methodVisitStatusSet = new LinkedHashSet<>();
        OUTPUT_LIST = new LinkedHashSet<>();
        STMT_SET_STATIC_ERRORS = new LinkedHashSet<>();
        STMT_SET_ERRORS_METHOD = new LinkedHashSet<>();
        TAINTED_VARIABLES = new LinkedList<>();
        UNTAINTED_VARIABLES = new LinkedList<>();
        TAINTED_CLASS_VARIABLES = new LinkedList<>();
        TAINTED_LOCAL_VARIABLES = new LinkedList<>();
    }

    private static void initializeCommandLineOptions()
    {

        Option sd = Option.builder(CLASS_PATH_OPTION).longOpt(CLASS_PATH_OPTION)
                .argName(CLASS_PATH_OPTION)
                .hasArg()
                .required(false)
                .desc("location of class file").build();
        Option className = Option.builder(CLASS_OPTION).longOpt(CLASS_OPTION)
                .argName(CLASS_OPTION)
                .hasArg()
                .required(false)
                .desc("name of the class file").build();
        Option methodName = Option.builder(METHOD_OPTION).longOpt(METHOD_OPTION)
                .argName(METHOD_OPTION)
                .hasArg()
                .required(false)
                .desc("method name of the class").build();
        Option taintConfigFile = Option.builder(INPUT_OPTIONS).longOpt(INPUT_OPTIONS)
                .argName(INPUT_OPTIONS)
                .hasArg()
                .required(true)
                .desc("input json file with secret values").build();
        Option outputFileDirectory = Option.builder(OUTPUT_OPTIONS).longOpt(OUTPUT_OPTIONS)
                .argName(OUTPUT_OPTIONS)
                .hasArg()
                .required(true)
                .desc("output file directory for Compromised variable list").build();
        COMMAND_LINE_OPTIONS.addOption(sd).addOption(className).addOption(methodName).addOption(taintConfigFile).addOption(outputFileDirectory);

    }

    /**
     * Resolve path against current working directory if relative.
     */
    private static Path resolveAgainstCwd(String p)
    {
        Path path = Paths.get(p);
        return path.isAbsolute()
                ? path.normalize()
                : Paths.get(System.getProperty("user.dir")).resolve(path).normalize();
    }

    /**
     * Copy a single classpath resource to the target file.
     */
    private static void copyResource(String resource, Path target) throws IOException
    {
        try (InputStream in = HelloSootup.class.getClassLoader().getResourceAsStream(resource))
        {
            if (in == null)
            {
                throw new FileNotFoundException("Missing resource on classpath: " + resource);
            }
            Files.createDirectories(target.getParent());
            Files.copy(in, target, StandardCopyOption.REPLACE_EXISTING);
        }
    }

    /**
     * Provision default config dir from classpath /config using config/_files.txt.
     * Returns the temp directory containing materialized config files.
     */
    private static Path provisionDefaultConfigFromClasspath() throws IOException
    {
        // temp dir unique per run
        Path tmp = Files.createTempDirectory("robustaplus-config-");
        tmp.toFile().deleteOnExit();

        // read index of files
        String indexRes = "config/_files.txt";
        try (InputStream in = HelloSootup.class.getClassLoader().getResourceAsStream(indexRes))
        {
            if (in == null)
            {
                throw new FileNotFoundException("Missing " + indexRes + " in resources. " +
                        "Add it with one filename per line.");
            }
            List<String> names = new ArrayList<>();
            try (BufferedReader br = new BufferedReader(new InputStreamReader(in)))
            {
                String line;
                while ((line = br.readLine()) != null)
                {
                    line = line.trim();
                    if (!line.isEmpty() && !line.startsWith("#")) names.add(line);
                }
            }
            if (names.isEmpty())
            {
                throw new IllegalStateException(indexRes + " is empty.");
            }
            // copy each resource under config/
            for (String name : names)
            {
                copyResource("config/" + name, tmp.resolve(name));
            }
        }
        return tmp;
    }

    /**
     * Convenience: ensure a dir exists or throw a helpful error.
     */
    private static void requireDir(Path dir, String label)
    {
        if (!Files.isDirectory(dir))
        {
            throw new IllegalArgumentException(label + " not found: " + dir.toAbsolutePath());
        }
    }

    /**
     * Convenience: ensure a file exists or throw a helpful error.
     */
    private static void requireFile(Path file, String label)
    {
        if (!Files.isRegularFile(file))
        {
            throw new IllegalArgumentException(label + " not found: " + file.toAbsolutePath());
        }
    }

    private static String buildMethodKey(String className, String methodName, List<Type> parameterTypes)
    {
        String params = parameterTypes == null
                ? "()"
                : parameterTypes.stream()
                .map(Type::toString)
                .collect(Collectors.joining(",", "(", ")"));
        return className + "::" + methodName + params;
    }

    public static void main(String[] args)
    {
        long startTime = System.nanoTime();
        CommandLineParser parser = new DefaultParser();
        // Create the Options
        Options options = new Options();
        options.addOption("cli", false, "Enable CLI mode");
        options.addOption("o", true, "Output directory path");
        options.addOption("j", true, "JSON file path");
        options.addOption("c", true, "Config folder path");
        try {
            CommandLine line = new DefaultParser().parse(options, args);

            boolean cli = line.hasOption("cli");

            // ---------- OUTPUT_DIRECTORY ----------
            String defaultOutputDir = Paths.get("target", "test-classes").toString();
            Path demoOutputDir = Paths.get("demo", "HelloSootup");
            if (cli) {
                String oVal = line.getOptionValue("o", defaultOutputDir);
                OUTPUT_DIRECTORY = resolveAgainstCwd(oVal).toString();
            } else {
                // Prefer demo/HelloSootup if present, otherwise fall back to target/test-classes
                Path resolvedDemoDir = resolveAgainstCwd(demoOutputDir.toString());
                if (Files.exists(resolvedDemoDir) && Files.isDirectory(resolvedDemoDir)) {
                    OUTPUT_DIRECTORY = resolvedDemoDir.toString();
                } else {
                    OUTPUT_DIRECTORY = resolveAgainstCwd(defaultOutputDir).toString();
                }
            }

            // ---------- CONFIG_DIRECTORY & JSON_FILE_PATH ----------
            Path configDirPath;
            Path jsonPath;

            if (cli)
            {
                String cVal = line.getOptionValue("c", null);
                if (cVal != null && !cVal.isBlank())
                {
                    // user provided -c: use that (relative paths OK)
                    configDirPath = resolveAgainstCwd(cVal);
                    requireDir(configDirPath, "CONFIG_DIRECTORY");
                }
                else
                {
                    // no -c: use defaults from classpath
                    configDirPath = provisionDefaultConfigFromClasspath();
                }

                String jVal = line.getOptionValue("j", null);
                if (jVal != null && !jVal.isBlank())
                {
                    jsonPath = resolveAgainstCwd(jVal);
                    requireFile(jsonPath, "JSON_FILE_PATH");
                }
                else
                {
                    // no -j: fall back to default methodConfig.json from classpath we just provisioned
                    jsonPath = configDirPath.resolve("methodConfig.json");
                    requireFile(jsonPath, "Default JSON_FILE_PATH (from classpath)");
                }
            }
            else
            {
                // Non-CLI: always use embedded defaults for configs + methodConfig.json
                configDirPath = provisionDefaultConfigFromClasspath();
                jsonPath = configDirPath.resolve("methodConfig.json");
                requireFile(jsonPath, "Default JSON_FILE_PATH (from classpath)");
            }

            CONFIG_DIRECTORY = configDirPath.toString();
            JSON_FILE_PATH = jsonPath.toString();

            // Optional: show resolved paths to help users
            System.out.println("Resolved paths:\n  OUTPUT_DIRECTORY = " + OUTPUT_DIRECTORY +
                    "\n  CONFIG_DIRECTORY = " + CONFIG_DIRECTORY +
                    "\n  JSON_FILE_PATH   = " + JSON_FILE_PATH);

        }
        catch (ParseException e)
        {
            System.err.println("Parsing failed. Reason: " + e.getMessage());
            return;
        }
        catch (Exception e)
        {
            System.err.println("Startup validation failed: " + e.getMessage());
            return;
        }
        //new HelloSootup().setSootUp();
        HelloSootup instance = new HelloSootup();
        javaProject = initializeSootUpFramework(OUTPUT_DIRECTORY);
        // String jsonFilePath = "/path/to/methodConfig.json";
        //MethodSignatureConfigLoader.MethodConfig methodConfig;
        try
        {
            methodConfig = MethodSignatureConfigLoader.parseConfig(JSON_FILE_PATH);
        }
        catch (Exception e)
        {
            throw new RuntimeException(e);
        }
        List<Type> parameterTypes = MethodSignatureConfigLoader.createParameterTypes(methodConfig);
        //displaySootClassAndMethod(javaProject, methodConfig.className, methodConfig.methodName, parameterTypes);
        SecretVerticesWrapper.FunctionStack functionStack = new SecretVerticesWrapper.FunctionStack(methodConfig.methodName, methodConfig.className, new LinkedHashMap<>());
        //Type returnType = ArrayType.createArrayType(PrimitiveType.ByteType.getInstance(),1);
        Type returnType = MethodSignatureConfigLoader.createReturnType(methodConfig);

        Set<String> processedMethodKeys = new LinkedHashSet<>();
        processedMethodKeys.add(buildMethodKey(methodConfig.className, methodConfig.methodName, parameterTypes));

        processSootMethod(null, methodConfig.className, methodConfig.methodName, parameterTypes, new SecretVerticesWrapper(functionStack), returnType, FunctionState.START, null);

        if (ENABLE_TRIGGER_AUTOSCAN)
        {
            Map<String, List<ProjectMethodAnnotationIndexer.MethodAnnoEntry>> methodAnnotationIndex =
                    ProjectMethodAnnotationIndexer.buildMethodAnnotationIndex(javaProject);

            for (Map.Entry<String, List<ProjectMethodAnnotationIndexer.MethodAnnoEntry>> classEntry : methodAnnotationIndex.entrySet())
            {
                String className = classEntry.getKey();
                for (ProjectMethodAnnotationIndexer.MethodAnnoEntry methodEntry : classEntry.getValue())
                {
                    if (methodEntry.tag != ProjectMethodAnnotationIndexer.MethodAnnoTag.FUN_TRIGGER) continue;

                    JavaSootMethod triggerMethod = methodEntry.method;
                    if (triggerMethod == null || !triggerMethod.hasBody()) continue;

                    List<Type> triggerParameterTypes = new ArrayList<>(methodEntry.parameterTypes);
                    String key = buildMethodKey(className, methodEntry.name, triggerParameterTypes);
                    if (!processedMethodKeys.add(key)) continue;

                    Type triggerReturnType = methodEntry.returnType;
                    SecretVerticesWrapper.FunctionStack triggerStack =
                            new SecretVerticesWrapper.FunctionStack(methodEntry.name, className, new LinkedHashMap<>());
                    processSootMethod(
                            null,
                            className,
                            methodEntry.name,
                            triggerParameterTypes,
                            new SecretVerticesWrapper(triggerStack),
                            triggerReturnType,
                            FunctionState.START,
                            null
                    );
                }
            }
        }

        printErrorStmts();
        printSubclassErrors();
        printOutputList(methodConfig);
        printRelevantOutput(methodConfig);
        printRefinedOutputWithOriginalVariables(methodConfig);
        printRefinedOutputList(methodConfig);
        printJavaPkgs();
        long endTime = System.nanoTime();
        long cpuTime = endTime - startTime;
        System.out.println("CPU time in nanoseconds: " + cpuTime);

        System.out.println("Problems:            " + problems);
        System.out.println("Suppressed Problems: " + supressedProblems);

        if (problems != supressedProblems)
        {
            System.out.println("FAILED");
            System.exit(1);
        }

        System.out.println("OK");
        System.exit(0);

    }

    private static void printJavaPkgs()
    {
        for (String pkg : JAVA_PKG_LIST)
        {
            System.out.println(pkg);
        }
    }

    private static void printRefinedOutputList(MethodSignatureConfigLoader.MethodConfig methodConfig)
    {
        String outputFile = OUTPUT_FILE_DIRECTORY + "/" + LocalDate.now() + "_" + methodConfig.className + "_" + methodConfig.methodName + "_leaks.txt";
        Path path = Paths.get(outputFile);
        try
        {
            Path parentDir = path.getParent();
            if (parentDir != null)
            {
                // Ensure directory exists or create it
                Files.createDirectories(parentDir);
            }
            if (Files.exists(path))
            {
                Files.delete(path);
            }
            path = Files.createFile(path);
            FileWriter fileWriter = new FileWriter(new File(path.toUri()));
            StringBuilder outputBuilder = new StringBuilder();
            printStaticTextForReportingInBegining(outputBuilder, methodConfig);
            Set<Output> refinedOutputList = new LinkedHashSet<>();
            for (Output output : OUTPUT_LIST)
            {
                Output refined = refineBranchingAndArrayStmts(output);
                if (!refined.getVariables().isEmpty())
                {
                    refinedOutputList.add(refined);
                    outputBuilder.append(refined);
                    outputBuilder.append("\n");
                }
            }
            printStaticTextForReportingInEnd(outputBuilder, refinedOutputList, methodConfig);
            fileWriter.write(outputBuilder.toString());
            fileWriter.close();
        }
        catch (IOException e)
        {
            throw new RuntimeException(e);
        }

    }

    private static void printRelevantOutput(MethodSignatureConfigLoader.MethodConfig methodConfig)
    {
        problems = 0;
        supressedProblems = 0;

        String outputFile = OUTPUT_FILE_DIRECTORY + "/" + LocalDate.now() + "_" + methodConfig.className + "_" + methodConfig.methodName + "_refined_issues.txt";
        Path path = Paths.get(outputFile);
        try
        {
            Path parentDir = path.getParent();
            if (parentDir != null)
            {
                Files.createDirectories(parentDir);
            }
            if (Files.exists(path))
            {
                Files.delete(path);
            }
            path = Files.createFile(path);
            FileWriter fileWriter = new FileWriter(new File(path.toUri()));
            StringBuilder outputBuilder = new StringBuilder();
            printStaticTextForReportingInBegining(outputBuilder, methodConfig);

            StringBuilder issuesBuilder = new StringBuilder();
            StringBuilder noIssuesBuilder = new StringBuilder();

            for (Output output : OUTPUT_LIST)
            {
                Output refined = refineBranchingAndArrayStmts(output);
                if (!methodConfig.className.equals(refined.getClassName()) &&
                        !output.stackContains(methodConfig.className, methodConfig.methodName))
                {
                    continue;
                }

                if (refined.getVariables().isEmpty())
                {
                    noIssuesBuilder.append("Method '").append(refined.getMethodName()).append("':\n");
                    noIssuesBuilder.append(String.format("  Reference: %s#%s -- No Issues Found%n",
                            refined.getClassName(), refined.getMethodName()));
                    noIssuesBuilder.append("\n");
                    continue;
                }

                problems++;

                issuesBuilder.append("Method '").append(refined.getMethodName()).append("':\n");
                issuesBuilder.append(String.format("  Reference: %s#%s%n",
                        refined.getClassName(), refined.getMethodName()));

                if (!refined.getTaintedInputs().isEmpty())
                {
                    issuesBuilder.append("  Tainted Variables: ");
                    issuesBuilder.append(String.join(", ", refined.getTaintedInputs()));
                    issuesBuilder.append("\n");
                }

                if (!refined.getFunctionStackList().isEmpty())
                {
                    issuesBuilder.append("  Function Stacks:\n");
                    for (SecretVerticesWrapper.FunctionStack functionStack : refined.getFunctionStackList())
                    {
                        issuesBuilder.append(String.format("    %s#%s%n",
                                functionStack.getClassName(), functionStack.getFunction()));
                    }
                }

                issuesBuilder.append("  Possible Issues Found:\n");
                StringBuilder suppressions = new StringBuilder();

                for (TaintedVariable var : refined.getVariables())
                {
                    issuesBuilder.append(formatFindingLine(var)).append("\n");

                    if (methodConfig.mutedRanges != null)
                    {
                        Position stmtPosition = null;
                        if (var.getStmt() != null && var.getStmt().getPositionInfo() != null)
                        {
                            stmtPosition = var.getStmt().getPositionInfo().getStmtPosition();
                        }
                        if (stmtPosition == null)
                        {
                            continue;
                        }

                        for (MethodSignatureConfigLoader.MutedRange range : methodConfig.mutedRanges)
                        {
                            if (range.positionEquals(stmtPosition)
                                    && Objects.equals(var.getClassName(), range.clasName)
                                    && Objects.equals(var.getMethodName(), range.method)
                                    && Objects.equals(range.suppress, var.getIssueAsString()))
                            {
                                suppressions.append("  Suppressed: ").append(var.getIssueAsString()).append("\n");
                                if (StringUtils.isNotBlank(range.reason))
                                {
                                    suppressions.append("    Reason: ").append(range.reason).append("\n");
                                }
                                supressedProblems++;
                                break;
                            }
                        }
                    }
                }

                if (suppressions.length() > 0)
                {
                    issuesBuilder.append(suppressions);
                }

                issuesBuilder.append("\n");
            }

            boolean hasIssues = issuesBuilder.length() > 0;
            if (hasIssues)
            {
                outputBuilder.append("Issues:\n");
                outputBuilder.append(issuesBuilder);
            }

            if (noIssuesBuilder.length() > 0)
            {
                if (hasIssues)
                {
                    outputBuilder.append("\n\n");
                }
                outputBuilder.append(noIssuesBuilder);
            }

            fileWriter.write(outputBuilder.toString());
            fileWriter.close();
        }
        catch (IOException e)
        {
            throw new RuntimeException(e);
        }
    }

    private static void printRefinedOutputWithOriginalVariables(MethodSignatureConfigLoader.MethodConfig methodConfig) {
        record DebugMetadata(boolean hasLineNumbers, boolean hasLocalVariables) {}

        Map<String, DebugMetadata> debugMetadataCache = new HashMap<>();

        String outputFile = OUTPUT_FILE_DIRECTORY + "/" + LocalDate.now() + "_" + methodConfig.className + "_" + methodConfig.methodName + "_refined_original.txt";
        Path path = Paths.get(outputFile);
        try {
            Path parentDir = path.getParent();
            if (parentDir != null) {
                Files.createDirectories(parentDir);
            }
            if (Files.exists(path)) {
                Files.delete(path);
            }
            path = Files.createFile(path);
            FileWriter fileWriter = new FileWriter(new File(path.toUri()));
            StringBuilder outputBuilder = new StringBuilder();
            printStaticTextForReportingInBegining(outputBuilder, methodConfig);
            Set<Output> relevantOutputs = new LinkedHashSet<>();
            for (Output output : OUTPUT_LIST) {
                Output refined = refineBranchingAndArrayStmts(output);
                if (!methodConfig.className.equals(refined.getClassName()) &&
                        !output.stackContains(methodConfig.className, methodConfig.methodName)) {
                    continue;
                }

                // Only keep methods that actually have reported issues, matching refined_issues.txt
                if (refined.getVariables().isEmpty()) {
                    continue;
                }

                relevantOutputs.add(refined);
                outputBuilder.append("Method '").append(refined.getMethodName()).append("':\n");
                outputBuilder.append(String.format("  Reference: %s#%s%n", refined.getClassName(), refined.getMethodName()));

                if (!refined.getTaintedInputs().isEmpty()) {
                    outputBuilder.append("  Tainted Variables: ");
                    outputBuilder.append(String.join(", ", refined.getTaintedInputs()));
                    outputBuilder.append("\n");
                }

                if (!refined.getFunctionStackList().isEmpty()) {
                    outputBuilder.append("  Function Stacks:\n");
                    for (SecretVerticesWrapper.FunctionStack functionStack : refined.getFunctionStackList()) {
                        outputBuilder.append(String.format("    %s#%s%n", functionStack.getClassName(), functionStack.getFunction()));
                    }
                }

                if (!refined.getVariables().isEmpty()) {
                    outputBuilder.append("  Possible Issues Found:\n");
                    for (TaintedVariable var : refined.getVariables()) {
                        outputBuilder.append(formatFindingLine(var));
                        outputBuilder.append("\n");

                        String normalizedClassName = normalizeClassName(var.getClassName());

                        Set<String> tracedCandidates = var.getTracedSourceCandidates();
                        Set<String> lineCandidates = var.getLineTableSourceCandidates();

                        if (!tracedCandidates.isEmpty()) {
                            outputBuilder.append("      Source candidates (dataflow): ");
                            outputBuilder.append(String.join(", ", tracedCandidates));
                            outputBuilder.append("\n");
                        }

                        if (!lineCandidates.isEmpty()) {
                            outputBuilder.append("      Source candidates (bytecode): ");
                            outputBuilder.append(String.join(", ", lineCandidates));
                            outputBuilder.append("\n");
                        }

                        if (tracedCandidates.isEmpty() && lineCandidates.isEmpty()) {
                            if (StringUtils.isBlank(normalizedClassName)) {
                                outputBuilder.append("      Source candidates: (class metadata unavailable)\n");
                            } else {
                                DebugMetadata metadata = debugMetadataCache.computeIfAbsent(normalizedClassName, name ->
                                        new DebugMetadata(
                                                LocalVariableResolver.hasLineNumberMetadata(OUTPUT_DIRECTORY, name),
                                                LocalVariableResolver.hasLocalVariableMetadata(OUTPUT_DIRECTORY, name)));

                                if (!metadata.hasLineNumbers()) {
                                    outputBuilder.append("      Source candidates: (no LineNumberTable; recompile with -g)\n");
                                } else if (!metadata.hasLocalVariables()) {
                                    outputBuilder.append("      Source candidates: (no LocalVariableTable; recompile with -g)\n");
                                } else {
                                    outputBuilder.append("      Source candidates: (no locals matched the reported line)\n");
                                }
                            }
                        }
                    }
                } else {
                    outputBuilder.append("  No Issues Found.\n");
                }

                outputBuilder.append("\n");
            }

            printStaticTextForReportingInEnd(outputBuilder, relevantOutputs, methodConfig);
            fileWriter.write(outputBuilder.toString());
            fileWriter.close();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private static String formatFindingLine(TaintedVariable var)
    {
        StringBuilder builder = new StringBuilder("    ");

        Position stmtPosition = null;
        if (var.getStmt() != null && var.getStmt().getPositionInfo() != null)
        {
            stmtPosition = var.getStmt().getPositionInfo().getStmtPosition();
            if (stmtPosition != null)
            {
                builder.append(String.format("%s %s: ", var.getMethodName(), formatPosition(stmtPosition)));
            }
        }

        int displayLine = deriveSourceLine(var);

        if (var.isIfStmt())
        {
            builder.append(String.format("Control Flow: %s, line %d, %s, %s",
                    var.getVariable(), displayLine, var.getType(), var.getVariableChaining()));
        }
        else if (var.isArray())
        {
            builder.append(String.format("Memory Access: %s, line %d, %s, %s",
                    var.getVariable(), displayLine, var.getType(), var.getVariableChaining()));
        }
        else if (var.isMulDiv())
        {
            builder.append(String.format("Arithmetic Operation: %s, line %d, %s, %s",
                    var.getVariable(), displayLine, var.getType(), var.getVariableChaining()));
        }
        else if (var.isVulLib())
        {
            builder.append(String.format("Library Call: %s, line %d, %s, %s",
                    var.getVariable(), displayLine, var.getType(), var.getVariableChaining()));
        }
        else
        {
            builder.append(String.format("%s, line %d, %s, %s",
                    var.getVariable(), displayLine, var.getType(), var.getVariableChaining()));
        }

        return builder.toString();
    }

    private static String formatPosition(Position stmtPosition)
    {
        if (stmtPosition == null)
        {
            return "[unknown]";
        }

        int lastCol = stmtPosition.getLastCol();
        if (lastCol == -1 || lastCol == Integer.MAX_VALUE)
        {
            return String.format("line %d to %d", stmtPosition.getFirstLine(), stmtPosition.getLastLine());
        }

        return String.format("line %d:%d to %d:%d",
                stmtPosition.getFirstLine(),
                stmtPosition.getFirstCol(),
                stmtPosition.getLastLine(),
                stmtPosition.getLastCol());
    }

    private static Output refineBranchingAndArrayStmts(Output output) {
        Set<TaintedVariable> taintedVariables = output.getVariables();
        Set<TaintedVariable> branchingTaintedVariables = taintedVariables.stream()
                .filter((taintedVariable)->
                        (taintedVariable.isIfStmt()  || taintedVariable.isMulDiv() || taintedVariable.isVulLib())
                                || isVariableAnArray(taintedVariable, taintedVariables)).collect(Collectors.toSet());
        return new Output(output.getClassName(), output.getMethodName(), output.getTaintedInputs(), output.getFunctionStackList(), branchingTaintedVariables, output.getPosition());
    }

    private static boolean isVariableAnArray(TaintedVariable taintedVariable, Set<TaintedVariable> taintedVariables) {
        String type = taintedVariable.getType();
        String variable = taintedVariable.getVariable();  // g[i], 56
        if (type != null && variable != null && variable.length() > 3) {
            String index = variable.substring(variable.length() - 3);
            if (index.charAt(0) == '[' && index.charAt(2) == ']' && isIndexTaintedVariable(index.charAt(1), taintedVariable.getLineNumber(), taintedVariables)) {
                return true;
            }
        }
        if (taintedVariable.isArray() && taintedVariable.getArrayTaintedVariable() != null) {
            return true;
        }
        return false;
    }

    private static String normalizeClassName(String className) {
        if (StringUtils.isBlank(className)) {
            return className;
        }
        String normalized = className.trim();
        if (normalized.startsWith("L") && normalized.endsWith(";")) {
            normalized = normalized.substring(1, normalized.length() - 1);
        }
        normalized = normalized.replace('/', '.');
        return normalized;
    }

    private static int deriveSourceLine(TaintedVariable var) {
        if (var.getStmt() != null && var.getStmt().getPositionInfo() != null) {
            Position pos = var.getStmt().getPositionInfo().getStmtPosition();
            if (pos != null && pos.getFirstLine() > 0) {
                return pos.getFirstLine();
            }
        }
        return var.getLineNumber();
    }

    private static int deriveSourceLine(Result result) {
        if (result.stmt != null && result.stmt.getPositionInfo() != null) {
            Position pos = result.stmt.getPositionInfo().getStmtPosition();
            if (pos != null && pos.getFirstLine() > 0) {
                return pos.getFirstLine();
            }
        }
        return result.lineNumber;
    }

    private static boolean isIndexTaintedVariable(char index, int lineNumber, Set<TaintedVariable> taintedVariables) {
        String indexString = index + "";
        for (TaintedVariable taintedVariable : taintedVariables){
            if (indexString.equals(taintedVariable.getVariable()) && taintedVariable.getLineNumber() <= lineNumber){
                return true;
            }
        }
        //return false;
        return true;
    }
    private static void printOutputList(MethodSignatureConfigLoader.MethodConfig methodConfig) {
        String outputFile = OUTPUT_FILE_DIRECTORY + "/" + LocalDate.now() + "_" + methodConfig.className + "_" + methodConfig.methodName + "_output.txt";
        Path path = Paths.get(outputFile);
        try {
            Path parentDir = path.getParent();
            if (parentDir != null) {
                // Ensure directory exists or create it
                Files.createDirectories(parentDir);
            }
            if (Files.exists(path)) {
                Files.delete(path);
            }
            path = Files.createFile(path);
            FileWriter fileWriter = new FileWriter(new File(path.toUri()));
            StringBuilder outputBuilder = new StringBuilder();
            printStaticTextForReportingInBegining(outputBuilder, methodConfig);
            for (Output output : OUTPUT_LIST) {
                outputBuilder.append(output);
                outputBuilder.append("\n");
            }
            printStaticTextForReportingInEnd(outputBuilder, OUTPUT_LIST, methodConfig);
            fileWriter.write(outputBuilder.toString());
            fileWriter.close();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

    }
    private static void printStaticTextForReportingInEnd(StringBuilder outputBuilder, Set<Output> outputList, MethodSignatureConfigLoader.MethodConfig methodConfig) {
        outputBuilder.append("\n");
        outputBuilder.append("*************Final tainted argument list for " + methodConfig.className + " Class. Method " + methodConfig.methodName + "*************");
        outputBuilder.append("\n");
        for (Output output : outputList) {
            if (output.getClassName().equals(methodConfig.className) && output.getMethodName().equals(methodConfig.methodName)){
                outputBuilder.append("Tainted variables : " + output.getVariables());
                break;
            }
        }
    }

    private static void printStaticTextForReportingInBegining(StringBuilder outputBuilder, MethodSignatureConfigLoader.MethodConfig methodConfig) {
        HashSet<String> initiallyTaintedVariables = new LinkedHashSet<>();
        if (TAINT_CONFIG != null) {
            initiallyTaintedVariables.addAll(TAINT_CONFIG.getTaintedVariables());
            initiallyTaintedVariables.addAll(TAINT_CONFIG.getSecretVariables());
        }
        outputBuilder.append("Analysed Post quantum scheme:");
        outputBuilder.append("\n");
        outputBuilder.append("Total Line of Jimple code scanned:" + lineOfCode);
        outputBuilder.append("\n");
        outputBuilder.append("Package Name : " + methodConfig.className);
        outputBuilder.append("\n");
        outputBuilder.append("Class Name : " + methodConfig.className);
        outputBuilder.append("\n");
        outputBuilder.append("Method Name : " + methodConfig.methodName);
        outputBuilder.append("\n");
        if (!initiallyTaintedVariables.isEmpty())
        {
            outputBuilder.append("Tainted arguments : " + initiallyTaintedVariables);
        }
        else
        {
            outputBuilder.append("Tainted arguments : none");
        }
        outputBuilder.append("\n\n");

    }

    private static void printErrorStmts()
    {
        for (Stmt stmt : STMT_SET_STATIC_ERRORS)
        {
            System.out.println("Skipping analysis for this method due to internal java api's = " + stmt);
        }
        for (Stmt stmt : STMT_SET_ERRORS_METHOD)
        {
            System.out.println("May be runtime polymorphism methods = " + stmt);
        }
    }

    public static JavaView initializeSootUpFramework(String path)
    {
        AnalysisInputLocation inputLocation = new JavaClassPathAnalysisInputLocation(path);
        JavaLanguage javaLanguage = new JavaLanguage(21);
        javaProject = new JavaView(inputLocation);
        return javaProject;
    }


    public static void displaySootClassAndMethod(JavaView javaProject, String className, String methodName, List<Type> parameterTypes)
    {
        //JavaView fullView = javaProject.createFullView();

        ClassType classType = javaProject.getIdentifierFactory().getClassType(className);
        JavaSootClass javaSootClass = javaProject.getClass(classType).get();
        System.out.println("SootClass: " + javaSootClass);
        MethodSignature methodSignature = javaProject.getIdentifierFactory().getMethodSignature(
                classType,
                JavaIdentifierFactory.getInstance().getMethodSubSignature(methodName, PrimitiveType.BooleanType.getInstance(), parameterTypes));

        SootMethod sootMethod = javaProject.getMethod(methodSignature).get();
        System.out.println("Method Signature: " + sootMethod);

        // List the statements
        List<Stmt> stmts = sootMethod.getBody().getStmts();
        for (Stmt stmt : stmts)
        {
            System.out.println(stmt);
        }
        System.out.println("-----------------------------------------");
        System.out.println("Branch Statements:");
        for (Stmt stmt : stmts)
        {
            if (stmt instanceof JIfStmt)
            {
                System.out.println(stmt);
            }
        }
        Body body = sootMethod.getBody();
    }

    private static CompromisedParameterandReturnMapping findCompromisedStmts(Body body, Set<VertexValue> allCompromisedVertexNames, Set<Result> compromisedVertices,
                                                                             Set<VertexValue> vertices, SecretVerticesWrapper secretVerticesWrapper, Set<String> taintedInputs, Trie root, String className, String methodName,
                                                                             MethodVisitStatus methodVisitStatus)
    {
        int lineNumber = 0;
        List<Stmt> stackVariablesList = new LinkedList<>();
        Map<String, List<String>> mappingOfStackVariables = new LinkedHashMap<>();
        Set<Value> aliasingSet = new HashSet<>();
        Map<StmtPositionInfoWrapper, LabelTaintStatus> labelTaintStatusMap = new LinkedHashMap<>(); // For internal tracking
        Map<StmtPositionInfoWrapper, IfTaintStatus> ifTaintStatusMap = new LinkedHashMap<>();
        Map<String, List<String>> objectMemoryMap = new LinkedHashMap<>();
        Map<String, String> PrimitiveDataTypeVariableSet = new HashMap<>();
        PrimitiveDataTypeVariableSet = checkAndStorePrimitiveTypes(body);
        Set<Value> returnVariablesList = new HashSet<>();
        for (Stmt stmts : body.getStmts())
        {
            lineOfCode++;
            Stmt stmt = stmts;
            if (stmt.toString().equals("$stack11 = vec instanceof org.bouncycastle.pqc.legacy.math.linearalgebra.GF2Vector"))
            {
                // ((JAssignStmt) stmt).getLeftOp().getUseBoxes().get(1).getValue()
                //((JAssignStmt) stmt).getLeftOp() instanceof JArrayRef
                System.out.println();
            }
            if (stmt.toString().equals("$stack50 = staticinvoke <org.bouncycastle.pqc.crypto.Taint: java.lang.Object taint(java.lang.Object)>($stack49)"))
            {
                // ((JAssignStmt) stmt).getLeftOp().getUseBoxes().get(1).getValue()
                //((JAssignStmt) stmt).getLeftOp() instanceof JArrayRef
                System.out.println();
            }

            // stmt.getUseBoxes().iterator().next().getValue() instanceof JMulExpr ||  stmt.getUseBoxes().iterator().next().getValue() instanceof JDivExpr

            if ((stmt instanceof JAssignStmt) && ((JAssignStmt) stmt).getLeftOp().getType() instanceof ReferenceType)
            {
                Value leftValue = ((JAssignStmt) stmt).getLeftOp();
                Value rightValue = ((JAssignStmt) stmt).getRightOp();
                if (!leftValue.toString().startsWith("$"))
                {
                    aliasingSet.add(leftValue);
                }
                if (!rightValue.toString().startsWith("$") && rightValue.getType() instanceof ReferenceType && aliasingSet.contains(rightValue))
                {
                    System.out.println("alias present. leftValue = " + leftValue + " rightValue = " + rightValue);
                }
            }


            if (allCompromisedVertexNames.contains(new VertexValue("$stack37")))
            {
                System.out.println();
            }

            updateMappingOfStackVariables(stmt, mappingOfStackVariables, allCompromisedVertexNames, PrimitiveDataTypeVariableSet);
            if (stmt.getDef().isPresent() && stmt.getDef().get().toString().contains("$stack"))
            {
                if (!allCompromisedVertexNames.contains(new VertexValue(stmt.getDef().get().toString())))
                {
                    if (stmt.containsInvokeExpr() && stmt.getInvokeExpr() instanceof JVirtualInvokeExpr)
                    {
                        stackVariablesList.add(stmt);
                    }
                }
            }

            if (body.isStmtBranchTarget(stmt))
            {
                StmtPositionInfo labelPosition = stmt.getPositionInfo(); // Retrieve position info
                StmtPositionInfoWrapper labelPositionWrapper = new StmtPositionInfoWrapper(labelPosition);

                if (labelTaintStatusMap.containsKey(labelPositionWrapper))
                {
                    // If the label is already in the map, update the compromised vertices
                    LabelTaintStatus existingLabelTaintStatus = labelTaintStatusMap.get(labelPositionWrapper);
                    Set<VertexValue> updatedCompromisedVertices = new HashSet<>(existingLabelTaintStatus.getCompromisedVertices());
                    updatedCompromisedVertices.addAll(allCompromisedVertexNames); // Logical OR operation
                    existingLabelTaintStatus.setCompromisedVertices(updatedCompromisedVertices);
                    labelTaintStatusMap.put(labelPositionWrapper, existingLabelTaintStatus); // Update the map
                    allCompromisedVertexNames.addAll(updatedCompromisedVertices);
                }
                else
                {
                    // If the label is not in the map, add a new entry
                    LabelTaintStatus labelTaintStatus = new LabelTaintStatus(methodName, className, allCompromisedVertexNames, stmt, labelPosition);
                    labelTaintStatusMap.put(labelPositionWrapper, labelTaintStatus); // Update for internal tracking
                }
            }

            if (stmt instanceof JIfStmt)
            {
                //StmtPositionInfo ifPosition = stmt.getPositionInfo();
                //StmtPositionInfoWrapper ifPositionWrapper = new StmtPositionInfoWrapper(ifPosition);

                List<Stmt> targetStmts = ((JIfStmt) stmt).getTargetStmts(body);
                if (!targetStmts.isEmpty())
                {
                    Stmt targetStmt = targetStmts.get(0); // Retrieve the target statement

                    StmtPositionInfo targetPosition = targetStmt.getPositionInfo();
                    StmtPositionInfoWrapper targetPositionWrapper = new StmtPositionInfoWrapper(targetPosition);

                    if (labelTaintStatusMap.containsKey(targetPositionWrapper))
                    {
                        // If the target statement is already in the map, update the compromised vertices
                        LabelTaintStatus existingLabelTaintStatus = labelTaintStatusMap.get(targetPositionWrapper);
                        Set<VertexValue> updatedCompromisedVertices = new HashSet<>(existingLabelTaintStatus.getCompromisedVertices());
                        updatedCompromisedVertices.addAll(allCompromisedVertexNames); // Logical OR operation
                        existingLabelTaintStatus.setCompromisedVertices(updatedCompromisedVertices);
                        labelTaintStatusMap.put(targetPositionWrapper, existingLabelTaintStatus); // Update the map
                    }
                    else
                    {
                        // If the target statement is not in the map, create a new entry
                        LabelTaintStatus newLabelTaintStatus = new LabelTaintStatus(methodName, className, allCompromisedVertexNames, targetStmt, targetPosition);
                        labelTaintStatusMap.put(targetPositionWrapper, newLabelTaintStatus); // Add new entry to the map
                    }
                }
            }

            if (stmt instanceof JGotoStmt)
            {
                List<Stmt> targetStmts = ((JGotoStmt) stmt).getTargetStmts(body);
                if (!targetStmts.isEmpty())
                {
                    Stmt targetStmt = targetStmts.get(0); // Retrieve the target statement

                    StmtPositionInfo targetPosition = targetStmt.getPositionInfo();
                    StmtPositionInfoWrapper targetPositionWrapper = new StmtPositionInfoWrapper(targetPosition);

                    if (labelTaintStatusMap.containsKey(targetPositionWrapper))
                    {
                        // If the target statement is already in the map, update the compromised vertices
                        LabelTaintStatus existingLabelTaintStatus = labelTaintStatusMap.get(targetPositionWrapper);
                        Set<VertexValue> updatedCompromisedVertices = new HashSet<>(existingLabelTaintStatus.getCompromisedVertices());
                        updatedCompromisedVertices.addAll(allCompromisedVertexNames); // Logical OR operation
                        existingLabelTaintStatus.setCompromisedVertices(updatedCompromisedVertices);
                        labelTaintStatusMap.put(targetPositionWrapper, existingLabelTaintStatus); // Update the map
                    }
                    else
                    {
                        // If the target statement is not in the map, create a new entry
                        LabelTaintStatus newLabelTaintStatus = new LabelTaintStatus(methodName, className, allCompromisedVertexNames, targetStmt, targetPosition);
                        labelTaintStatusMap.put(targetPositionWrapper, newLabelTaintStatus); // Add new entry to the map
                    }
                }
            }


            if (stmt instanceof JIfStmt)
            {
                StmtPositionInfo ifPosition = stmt.getPositionInfo();
                StmtPositionInfoWrapper ifPositionWrapper = new StmtPositionInfoWrapper(ifPosition);
                IfTaintStatus ifTaintStatus = new IfTaintStatus(methodName, className, allCompromisedVertexNames, stmt, ifPosition);
                ifTaintStatusMap.put(ifPositionWrapper, ifTaintStatus);
            }

            findCompromisedStmtsFromDefBoxes(stmt, className, allCompromisedVertexNames, compromisedVertices, vertices, lineNumber, root, methodVisitStatus);
            findCompromisedIfStmts(stmt, allCompromisedVertexNames, compromisedVertices, vertices, lineNumber, root);
            //findTaintedVariablesInIfElseBlocks(body, stmt, className, allCompromisedVertexNames, compromisedVertices, vertices, stackVariablesList, secretVerticesWrapper,mappingOfStackVariables, root, ifTaintStatusMap, labelTaintStatusMap);
            findTaintedVaraiblesInLoops(body, stmt, className, allCompromisedVertexNames, compromisedVertices, vertices, stackVariablesList, secretVerticesWrapper, mappingOfStackVariables, root, labelTaintStatusMap, PrimitiveDataTypeVariableSet, methodVisitStatus);
            //findCompromisedLoopStmts(body, stmt, allCompromisedVertexNames, compromisedVertices, vertices, stackVariablesList, secretVerticesWrapper,mappingOfStackVariables, root);
            findInvokeExpression(body, stmt, allCompromisedVertexNames, compromisedVertices, stackVariablesList, vertices, lineNumber, secretVerticesWrapper, mappingOfStackVariables, root, PrimitiveDataTypeVariableSet);
            updateOrignialVariablesFromTaintedStackVariables(mappingOfStackVariables, stmt, lineNumber, allCompromisedVertexNames, compromisedVertices, root);
            if (allCompromisedVertexNames.contains(new VertexValue("$stack43")))
            {
                System.out.println();
            }
            temporarystacktoobjectmappingandtainting(stmts, allCompromisedVertexNames, compromisedVertices, secretVerticesWrapper, objectMemoryMap, root);
            updateCompromisedVertexNmaesfromObjectMemoryMap(allCompromisedVertexNames, objectMemoryMap, root, stmt, lineNumber, compromisedVertices);
            if (stmt instanceof JReturnStmt)
            {
                Value temp = ((JReturnStmt) stmt).getOp();
                if (!(temp instanceof Constant))
                {
                    returnVariablesList.add(temp);
                    System.out.println("debug");
                }
            }
            lineNumber++;
        }
        resetScannedStmts();
        System.out.println("Compromised vertices for class name = " + className + " and method name = "
                + methodName + " : " + compromisedVertices);
        addToOutput(body.getMethodSignature().getDeclClassType().toString(),
                body.getMethodSignature().getName(),
                body,
                compromisedVertices,
                secretVerticesWrapper,
                taintedInputs,
                body.getPosition());
        secretVerticesWrapper.removeTop();
        List<Local> classLocals =
                body.getLocals().stream()
                        .filter(l -> l.getType() instanceof JavaClassType)
                        .toList();
        // Local implements Value
        returnVariablesList.addAll(classLocals);
        List<Local> parameterLocals = new ArrayList<>();
        int parameterCount = (int) body.getMethodSignature().getParameterTypes().stream().count();
        for (int i = 0; i < parameterCount; i++)
        {
            try
            {
                Local param = body.getParameterLocal(i);
                parameterLocals.add(param);
            }
            catch (IllegalArgumentException e)
            {
                // Handle exception if needed
                break; // Exit loop if index is out of bounds
            }
        }
        //!(body.getStmts().getLast() instanceof JReturnVoidStmt)
        if (body.getStmts().getLast() instanceof JReturnStmt)
        {
            List<Value> usedValues = body.getStmts().getLast().getUses().toList();
        }
        else
        {
            System.out.println("debug");
        }
        //body.getStmts().getLast() instanceof JReturnStmt
        //body.getStmts().getLast().getUses().toList().getLast().toString()
        //body.getMethodSignature().getParameterTypes().stream().count()
        CompromisedParameterandReturnMapping mapOfCompromisedVariablesWithMethodParametersAndReturnTaintStatus = mappingOfCompromisedVariablesWithMethodParameters(allCompromisedVertexNames, parameterLocals, returnVariablesList);
        return mapOfCompromisedVariablesWithMethodParametersAndReturnTaintStatus;
        //return  new HashMap<>();
    }
    private static String simpleAnnotationName(String fqcn)
    {
        if (fqcn == null) return "";

        // Replace inner class $ with .
        String normalized = fqcn.replace('$', '.');

        // Simple name is everything after last '.'
        int idx = normalized.lastIndexOf('.');
        return (idx >= 0) ? normalized.substring(idx + 1) : normalized;
    }

    private static AnnotationState toState(Set<String> names)
    {
        boolean hasTrigger = false;
        boolean hasUntrigger = false;

        for (String n : names)
        {
            String simple = simpleAnnotationName(n);

            if (simple.equalsIgnoreCase("Trigger")) {
                hasTrigger = true;
            }
            if (simple.equalsIgnoreCase("Untrigger")) {
                hasUntrigger = true;
            }
        }

        if (hasTrigger && hasUntrigger) return AnnotationState.BOTH;
        if (hasTrigger) return AnnotationState.TRIGGER;
        if (hasUntrigger) return AnnotationState.UNTRIGGER;

        return AnnotationState.NONE;
    }

    private static Map<String, AnnotationState> getOrLoadFieldTagMapForClass(String classFqcn)
    {
        // Fast path
        Map<String, AnnotationState> cached = FIELD_TAG_CACHE.get(classFqcn);
        if (cached != null) return cached;
        if (classFqcn.equals("org.bouncycastle.pqc.crypto.lms.LMOtsPrivateKey")){
            System.out.println("debug");
        }
        // Resolve class via SootUp
        var idf = javaProject.getIdentifierFactory();
        var classType = idf.getClassType(classFqcn);
        var sc = javaProject.getClass(classType)
                .orElseThrow(() -> new IllegalStateException("Class not found: " + classFqcn));

        // 1) Collect names via SootUp (may be empty for fields on some builds)
        Map<String, java.util.Set<String>> byFieldNames = new java.util.LinkedHashMap<>();
        var viewOpt = java.util.Optional.of(javaProject);

        for (sootup.java.core.JavaSootField f : sc.getFields())
        {
            String simple = f.getName();
            java.util.LinkedHashSet<String> names = new java.util.LinkedHashSet<>();
            try
            {
                for (sootup.java.core.AnnotationUsage au : f.getAnnotations(viewOpt))
                {
                    names.add(au.getAnnotation().getClassName());
                }
            }
            catch (Throwable ignored)
            { /* fallback will fill */ }
            byFieldNames.put(simple, names);
        }

        // 2) Merge in bytecode/reflect fallback
        Map<String, java.util.Set<String>> fb = loadFieldAnnotationsFromBytecode(classFqcn);
        fb.forEach((simple, anns) ->
                byFieldNames.computeIfAbsent(simple, k -> new java.util.LinkedHashSet<>()).addAll(anns));

        // 3) Convert to single-state map; ensure all known fields have at least NONE
        Map<String, AnnotationState> states = new java.util.LinkedHashMap<>();
        for (var f : sc.getFields())
        {
            states.put(f.getName(), toState(byFieldNames.getOrDefault(f.getName(), java.util.Set.of())));
        }
        // Also include any fallback-only fields (if any)
        for (String simple : fb.keySet())
        {
            states.putIfAbsent(simple, toState(byFieldNames.getOrDefault(simple, java.util.Set.of())));
        }

        // Publish to cache (read-only view)
        FIELD_TAG_CACHE.putIfAbsent(classFqcn, java.util.Collections.unmodifiableMap(states));
        return FIELD_TAG_CACHE.get(classFqcn);
    }

    public static Optional<AnnotationState> lookupRightOpFieldTag(Stmt stmt)
    {
        if (!(stmt instanceof JAssignStmt as)) {
            return Optional.empty();
        }

        return findFieldTagInValue(as.getRightOp());
    }

    private static Optional<AnnotationState> findFieldTagInValue(Value v)
    {
        // 1) Direct instance field?
        if (v instanceof JInstanceFieldRef ifr) {
            FieldSignature fsig = ifr.getFieldSignature();

            String classFqcn;
            try {
                classFqcn = fsig.getDeclClassType().getFullyQualifiedName();
            } catch (Throwable ignore) {
                classFqcn = fsig.getDeclClassType().toString();
            }

            String fieldName = fsig.getName();
            Map<String, AnnotationState> map = getOrLoadFieldTagMapForClass(classFqcn);
            return Optional.ofNullable(map.get(fieldName));
        }

        // 2) Otherwise, recurse into its sub-values (uses)
        //    Exact API depends on SootUp; this is just the idea.
        var uses = v.getUses();
        var it = uses.iterator();
        while (it.hasNext())
        {
            Value child = it.next();
            Optional<AnnotationState> sub = findFieldTagInValue(child);
            if (sub.isPresent())
            {
                return sub;
            }
        }

        return Optional.empty();
    }



    private static Map<String, String> checkAndStorePrimitiveTypes(Body body)
    {
        Map<String, String> PrimitiveDataTypeVariableSet = new HashMap<>();
        List<Local> locals = body.getLocals().stream().toList();
        for (Local local : locals)
        {
            // Check if the type of the local variable is a primitive type
            if (local.getType() instanceof PrimitiveType)
            {
                // Add the local variable and its type to the map
                PrimitiveDataTypeVariableSet.put(local.getName(), local.getType().toString());
            }
        }
        return PrimitiveDataTypeVariableSet;
    }

    private static void updateCompromisedVertexNmaesfromObjectMemoryMap(Set<VertexValue> allCompromisedVertexNames, Map<String, List<String>> objectMemoryMap, Trie root, Stmt stmt, int lineNumber, Set<Result> compromisedVertices)
    {
        for (Map.Entry<String, List<String>> entry : objectMemoryMap.entrySet())
        {
            String key = entry.getKey();
            List<String> values = entry.getValue();
            // Check if the key or any value is in allCompromisedVertexNames
            boolean isCompromised = allCompromisedVertexNames.stream().anyMatch(vertex -> vertex.toString().equals(key)) ||
                    values.stream().anyMatch(value -> allCompromisedVertexNames.stream().anyMatch(vertex -> vertex.toString().equals(value)));
            // If compromised, add the key and all values to allCompromisedVertexNames
            if (isCompromised)
            {
                allCompromisedVertexNames.add(new VertexValue(key));
                root.insert(key, values.get(0));
                compromisedVertices.add(new Result(lineNumber, key, stmt, false, root.getVariableChaining(key)));
                for (String value : values)
                {
                    if (!value.startsWith("new"))
                    {
                        allCompromisedVertexNames.add(new VertexValue(value));
                    }
                }
            }
        }
    }

    private static void temporarystacktoobjectmappingandtainting(Stmt stmt, Set<VertexValue> allCompromisedVertexNames, Set<Result> compromisedVertices,
                                                                 SecretVerticesWrapper secretVerticesWrapper, Map<String, List<String>> objectMemoryMap, Trie root)
    {

        if (stmt instanceof JAssignStmt && ((JAssignStmt) stmt).getRightOp() instanceof JNewExpr)
        {
            if (stmt.toString().contains("$stack") && !stmt.getDef().isEmpty())
            {
                String leftVariable = ((JAssignStmt) stmt).getLeftOp().getUses().toList().isEmpty() ?
                        ((JAssignStmt) stmt).getLeftOp().toString() :
                        ((JAssignStmt) stmt).getLeftOp().getUses().findFirst().get().toString();

                List<String> rightVariables = new ArrayList<>();
                Value rightOp = ((JAssignStmt) stmt).getRightOp();
                if (rightOp.getUses().toList().isEmpty())
                {
                    rightVariables.add(rightOp.toString());
                }
                else if (rightOp.getUses().count() == 2 && rightOp instanceof JArrayRef)
                {
                    rightVariables.add(rightOp.getUses().findFirst().get().toString());
                }
                else
                {
                    for (Value box : rightOp.getUses().toList())
                    {
                        if (!box.toString().equals("this"))
                        {
                            rightVariables.add(box.toString());
                        }
                    }
                }
                objectMemoryMap.put(leftVariable, rightVariables);
            }
        }
        if (stmt instanceof JAssignStmt)
        {
            if (stmt.toString().contains("$stack") && !stmt.getDef().isEmpty())
            {
                String leftVariable = ((JAssignStmt) stmt).getLeftOp().getUses().toList().isEmpty() ?
                        ((JAssignStmt) stmt).getLeftOp().toString() :
                        ((JAssignStmt) stmt).getLeftOp().getUses().findFirst().get().toString();
                List<String> rightVariables = new ArrayList<>();
                Value rightOp = ((JAssignStmt) stmt).getRightOp();

                if (rightOp.getUses().toList().isEmpty())
                {
                    rightVariables.add(rightOp.toString());
                }
                else if (rightOp.getUses().count() == 2 && rightOp instanceof JArrayRef)
                {
                    rightVariables.add(rightOp.getUses().findFirst().get().toString());
                }
                else
                {
                    for (Value box : rightOp.getUses().toList())
                    {
                        if (!box.toString().equals("this"))
                        {
                            rightVariables.add(box.toString());
                        }
                    }
                }
                if (stmt.containsInvokeExpr())
                {
                    if (stmt.getInvokeExpr() instanceof JVirtualInvokeExpr)
                    {
                        rightVariables.clear();
                        rightVariables.add(((JVirtualInvokeExpr) stmt.getInvokeExpr()).getBase().toString());
                    }
                    else if (stmt.getInvokeExpr() instanceof JSpecialInvokeExpr)
                    {
                        rightVariables.clear();
                        rightVariables.add(((JSpecialInvokeExpr) stmt.getInvokeExpr()).getBase().toString());
                    }
                    else if (rightOp.getUses().count() > 0)
                    {
                        rightVariables.add(rightOp.getUses().findFirst().get().toString());
                    }
                }
                else if (rightOp.toString().contains("lengthof"))
                {
                    rightVariables.clear();
                    rightVariables.add(rightOp.toString());
                }

                for (String rightVariable : rightVariables)
                {
                    if (objectMemoryMap.containsKey(rightVariable))
                    {
                        objectMemoryMap.get(rightVariable).add(leftVariable);
                        if (allCompromisedVertexNames.contains(leftVariable))
                        {
                            allCompromisedVertexNames.add(new VertexValue(rightVariable));
                            root.insert(leftVariable, rightVariable);
                            for (String value : objectMemoryMap.get(rightVariable))
                            {
                                if (!value.startsWith("new"))
                                {
                                    allCompromisedVertexNames.add(new VertexValue(value));
                                }
                            }
                            root.insert(rightVariable, objectMemoryMap.get(rightVariable).get(0));
                        }
                    }
                }
            }

        }
    }

    public static void resetScannedStmts()
    {
        scannedIfStmts.clear();
        scannedElseStmts.clear();
    }

    private static void addToOutput(String className,
                                    String methodName,
                                    Body body,
                                    Set<Result> compromisedVertices,
                                    SecretVerticesWrapper secretVerticesWrapper,
                                    Set<String> taintedInputs,
                                    Position position)
    {
        Output output = new Output(className, methodName, taintedInputs, secretVerticesWrapper.getFunctionStackList(), position);
        for (Result result : compromisedVertices)
        {
            boolean shouldRecord = !result.value.startsWith("$stack")
                    || (result.value.startsWith("$stack") && (result.isIfStmt || result.isArray || result.isMulDiv || result.isVul_Lib));
            if (shouldRecord)
            {
                String type = getType(result);

                int sourceLine = deriveSourceLine(result);
                Set<String> tracedCandidates = OriginalVariableTracer.trace(body, result.value);
                Set<String> lineCandidates = Collections.emptySet();
                if (sourceLine > 0 && StringUtils.isNotBlank(className)) {
                    String normalizedClass = normalizeClassName(className);
                    lineCandidates = LocalVariableResolver.resolve(
                            OUTPUT_DIRECTORY,
                            normalizedClass,
                            methodName,
                            sourceLine);
                }

                TaintedVariable taintedVariable = new TaintedVariable(
                        className,
                        methodName,
                        result.value,
                        type,
                        result.isIfStmt,
                        result.lineNumber,
                        result.variableChaining,
                        result.isArray,
                        result.arrayTaintedVariable,
                        result.isMulDiv,
                        result.stmt,
                        result.isVul_Lib,
                        tracedCandidates,
                        lineCandidates);
                output.getVariables().add(taintedVariable);
            }
        }
        OUTPUT_LIST.add(output);
    }

    private static String getType(Result result)
    {
        if (result.stmt == null)
        {
            return null;
        }
        for (Value valueBox : result.stmt.getUsesAndDefs().toList())
        {
            if (valueBox.toString().equals(result.value))
            {
                return valueBox.getType().toString();
            }
        }

        for (Value valueBox : result.stmt.getUsesAndDefs().toList())
        {
            if (valueBox.toString().equals(result.value))
            {
                return valueBox.getType().toString();
            }
        }
        return null;
    }


    private static void updateOrignialVariablesFromTaintedStackVariables(Map<String, List<String>> mappingOfStackVariables, Stmt stmt, int lineNumber,
                                                                         Set<VertexValue> allCompromisedVertexNames, Set<Result> compromisedVertices, Trie root)
    {
        for (Value valueBox : stmt.getUsesAndDefs().toList())
        {
            if (valueBox.toString().contains("$stack"))
            {
                VertexValue vertexValue = getVertexValue(valueBox);
                if (allCompromisedVertexNames.contains(vertexValue) && mappingOfStackVariables.get(vertexValue.value) != null)
                {
                    String originalVariable = getOriginalVariableCorrespondingToStackVariable(mappingOfStackVariables, vertexValue.value, new LinkedHashSet<>(), allCompromisedVertexNames);
                    if (originalVariable == null || originalVariable.contains("$stack"))
                    {
                        return;
                    }
                    /*
                                stmt1
                                var1 - untainted.
                                var2 - tainted.
                                stack1 - untainted.(var1)
                                stack1 - var2.

                                var3 = var1
                     */
                    boolean isStackVariableIfStmt = findStackVariableBranchingStatus(compromisedVertices, vertexValue.value, lineNumber, stmt, root);
                    if (!originalVariable.equals("$length") && !UNTAINTED_VARIABLES.contains(originalVariable))
                    {
                        root.insert(vertexValue.toString(), originalVariable);
                        allCompromisedVertexNames.add(new VertexValue(originalVariable));
                        //TODO: passing empty variableChaining intentionally.
                        compromisedVertices.add(new Result(lineNumber, originalVariable, stmt, isStackVariableIfStmt, root.getVariableChaining(originalVariable)));
                    }

                }
            }
        }
    }

    private static boolean findStackVariableBranchingStatus(Set<Result> compromisedVertices, String value, int lineNumber, Stmt stmt, Trie root)
    {
        //  //TODO: passing empty variableChaining intentionally.
        Result resultWithBranchingTrueDummyRecord = new Result(lineNumber, value, stmt, true, root.getVariableChaining(value));
        return compromisedVertices.contains(resultWithBranchingTrueDummyRecord);
    }

    private static void findInvokeExpression(Body body, Stmt stmt, Set<VertexValue> allCompromisedVertexNames, Set<Result> compromisedVertices,
                                             List<Stmt> stackVariablesList, Set<VertexValue> vertices, int lineNumber,
                                             SecretVerticesWrapper secretVerticesWrapper, Map<String, List<String>> mappingOfStackVariables, Trie root, Map<String, String> PrimitiveDataTypeVariableSet)
    {

        if (stmt.containsInvokeExpr())
        {
            String className = null;
            String methodName = null;
            List<Type> types = new LinkedList<>();
            List<Immediate> values = new LinkedList<>();
            String packageName = null;
            try
            {
                if (stmt.getInvokeExpr() instanceof JStaticInvokeExpr)
                {
                    className = ((JStaticInvokeExpr) stmt.getInvokeExpr()).getMethodSignature().getDeclClassType().toString();
                    packageName = String.valueOf(((JStaticInvokeExpr) stmt.getInvokeExpr()).getMethodSignature().getDeclClassType().getPackageName());
                    methodName = ((JStaticInvokeExpr) stmt.getInvokeExpr()).getMethodSignature().getName();
                    values = ((JStaticInvokeExpr) stmt.getInvokeExpr()).getArgs();
                    types = ((JStaticInvokeExpr) stmt.getInvokeExpr()).getMethodSignature().getParameterTypes();

                    // Variables removing and adding based on classfied and declassified in Taint Class.
                    if (isVariableClassified(className, packageName, methodName))
                    {
                        addClassifiedVariablesToAllCompromisedVertexNames(values, allCompromisedVertexNames, mappingOfStackVariables);
                        return;
                    }

                    if (isVariableDeclassified(className, packageName, methodName))
                    {
                        removeDeclassifiedVariablesToAllCompromisedVertexNames(values, allCompromisedVertexNames, mappingOfStackVariables);
                        return;
                    }
                }
                else if (stmt.getInvokeExpr() instanceof JSpecialInvokeExpr)
                {
                    className = ((JSpecialInvokeExpr) stmt.getInvokeExpr()).getMethodSignature().getDeclClassType().toString();
                    packageName = String.valueOf(((JSpecialInvokeExpr) stmt.getInvokeExpr()).getMethodSignature().getDeclClassType().getPackageName());
                    methodName = ((JSpecialInvokeExpr) stmt.getInvokeExpr()).getMethodSignature().getName();
                    values = ((JSpecialInvokeExpr) stmt.getInvokeExpr()).getArgs();
                    types = ((JSpecialInvokeExpr) stmt.getInvokeExpr()).getMethodSignature().getParameterTypes();
                }
                else if (stmt.getInvokeExpr() instanceof JInterfaceInvokeExpr)
                {
                    className = ((JInterfaceInvokeExpr) stmt.getInvokeExpr()).getMethodSignature().getDeclClassType().toString();
                    packageName = String.valueOf(((JInterfaceInvokeExpr) stmt.getInvokeExpr()).getMethodSignature().getDeclClassType().getPackageName());
                    methodName = ((JInterfaceInvokeExpr) stmt.getInvokeExpr()).getMethodSignature().getName();
                    values = ((JInterfaceInvokeExpr) stmt.getInvokeExpr()).getArgs();
                    types = ((JInterfaceInvokeExpr) stmt.getInvokeExpr()).getMethodSignature().getParameterTypes();
                }
                else if (stmt.getInvokeExpr() instanceof JDynamicInvokeExpr)
                {
                    className = ((JDynamicInvokeExpr) stmt.getInvokeExpr()).getMethodSignature().getDeclClassType().toString();
                    packageName = String.valueOf(((JDynamicInvokeExpr) stmt.getInvokeExpr()).getMethodSignature().getDeclClassType().getPackageName());
                    methodName = ((JDynamicInvokeExpr) stmt.getInvokeExpr()).getMethodSignature().getName();
                    values = ((JDynamicInvokeExpr) stmt.getInvokeExpr()).getArgs();
                    types = ((JDynamicInvokeExpr) stmt.getInvokeExpr()).getMethodSignature().getParameterTypes();
                }
                else
                {
                    className = ((JVirtualInvokeExpr) stmt.getInvokeExpr()).getMethodSignature().getDeclClassType().toString();
                    packageName = String.valueOf(((JVirtualInvokeExpr) stmt.getInvokeExpr()).getMethodSignature().getDeclClassType().getPackageName());
                    methodName = ((JVirtualInvokeExpr) stmt.getInvokeExpr()).getMethodSignature().getName();
                    values = ((JVirtualInvokeExpr) stmt.getInvokeExpr()).getArgs();
                    types = ((JVirtualInvokeExpr) stmt.getInvokeExpr()).getMethodSignature().getParameterTypes();

                }
            }
            catch (Exception e)
            {
                System.out.println("SPECIAL INVOKE ERROR");
                e.printStackTrace();
            }


            Map<Integer, VertexValue> secretVertices = new LinkedHashMap<>();
            int i = 0;
            for (Value value : values)
            {
                ++i;
                String valueString = value.toString();
                if (valueString.contains("#"))
                {
                    valueString = removeHash(valueString);
                }
                VertexValue vertexValue = new VertexValue(valueString);
                if (allCompromisedVertexNames.contains(vertexValue))
                {
                    secretVertices.put(i, vertexValue);
                }
            }
            if (className.contains("Taint") & methodName.equals("taint"))
            {
                String returnValue = stmt.getDef().get().toString();
                allCompromisedVertexNames.add(new VertexValue(returnValue));
                String variableCausingOtherVariablesTainted
                        = stmt.getInvokeExpr().getArgs().stream().iterator().next().toString();
                root.insert(variableCausingOtherVariablesTainted, returnValue);
                return;
            }
            if (className.contains("Taint") & methodName.equals("untaint")){
                return;
            }
            processIfTarget(className, methodName, allCompromisedVertexNames, compromisedVertices, stmt, secretVertices, root, lineNumber);
            if (skipProcessingIfJavaPkg(packageName))
            {
                // Add tainted variable as per provided JdkClassTaintConfig
                JdkMethodTaintConfig jdkMethodTaintConfig = JDK_CLASS_TAINT_CONFIG.getJdkMethodTaintConfig(packageName, className, methodName);
                if (jdkMethodTaintConfig != null)
                {
                    addTaintVariablesOfJdkClassTaintConfig(jdkMethodTaintConfig, values, lineNumber, stmt, allCompromisedVertexNames, compromisedVertices, root);
                }
                if (!secretVertices.isEmpty())
                {
                    if (stmt.getInvokeExpr() instanceof JVirtualInvokeExpr && !values.isEmpty())
                    {
                        if (!UNTAINTED_VARIABLES.contains(((JVirtualInvokeExpr) stmt.getInvokeExpr()).getBase().toString()))
                        {
                            allCompromisedVertexNames.add(new VertexValue(((JVirtualInvokeExpr) stmt.getInvokeExpr()).getBase().toString()));
                            //TODO: passing empty variableChaining intentionally.
                            String variable = ((JVirtualInvokeExpr) stmt.getInvokeExpr()).getBase().toString();
                            Map.Entry<Integer, VertexValue> firstEntry = secretVertices.entrySet().iterator().next();
                            VertexValue firstVertexValue = firstEntry.getValue();
                            root.insert(firstVertexValue.toString(), variable);
                            compromisedVertices.add(new Result(lineNumber, variable, stmt, false, root.getVariableChaining(variable)));
                        }

                    }
                    else if (stmt.getInvokeExpr() instanceof JSpecialInvokeExpr && !values.isEmpty())
                    {
                        if (!UNTAINTED_VARIABLES.contains(((JSpecialInvokeExpr) stmt.getInvokeExpr()).getBase().toString()))
                        {
                            allCompromisedVertexNames.add(new VertexValue(((JSpecialInvokeExpr) stmt.getInvokeExpr()).getBase().toString()));
                            //TODO: passing empty variableChaining intentionally.
                            String variable = ((JSpecialInvokeExpr) stmt.getInvokeExpr()).getBase().toString();
                            Map.Entry<Integer, VertexValue> firstEntry = secretVertices.entrySet().iterator().next();
                            VertexValue firstVertexValue = firstEntry.getValue();
                            root.insert(firstVertexValue.toString(), variable);
                            compromisedVertices.add(new Result(lineNumber, variable, stmt, false, root.getVariableChaining(variable)));
                        }

                    }

                }
                return;
            }

            //Secretvertices Map Key index starts from 1 not 0



            MethodVisitStatus methodVisitStatus = new MethodVisitStatus(packageName, className, methodName, types, secretVertices, values);

        if (methodVisitStatusSet.contains(methodVisitStatus))
        {
            MethodVisitStatus existingStatus = methodVisitStatusSet.stream().filter(status -> status.equals(methodVisitStatus)).findFirst().orElse(null);
            if (existingStatus != null && stmt instanceof JAssignStmt)
            {
                boolean markReturnTainted = existingStatus.isMethodReturnStatus();
                boolean returnDeclassifiedByUntrigger = existingStatus.isReturnDeclassifiedByUntrigger();
                Map<Integer, String> storedParamMapping = existingStatus.getMethodParameterMapping();
                handleInvokeAssignmentTainting(stmt, lineNumber, allCompromisedVertexNames, compromisedVertices, root,
                        existingStatus, markReturnTainted, returnDeclassifiedByUntrigger, values);
                addMapOfCompromisedVariablesWithMethodParametersToCompromisedVariables(
                        storedParamMapping,
                        values,
                        allCompromisedVertexNames,
                        compromisedVertices,
                        stmt,
                        lineNumber,
                        root,
                        PrimitiveDataTypeVariableSet);
            } else if (existingStatus != null && !existingStatus.getMethodParameterMapping().isEmpty()) {
                Map<Integer, String> storedParamMapping = existingStatus.getMethodParameterMapping();
                addMapOfCompromisedVariablesWithMethodParametersToCompromisedVariables(
                        storedParamMapping,
                        values,
                        allCompromisedVertexNames,
                        compromisedVertices,
                        stmt,
                        lineNumber,
                        root,
                        PrimitiveDataTypeVariableSet);
            }
            return; // Skip reanalysis if previously analyzed with identical taint positions
        }


            methodVisitStatusSet.add(methodVisitStatus);
            if (TAINT_TRIGGER || !secretVertices.isEmpty() || true)
            {
                String variable = null;
                boolean isreprocessRequired = false;
                if (stmt.getInvokeExpr() instanceof JVirtualInvokeExpr && !values.isEmpty() && !allCompromisedVertexNames.isEmpty() && !((JVirtualInvokeExpr) stmt.getInvokeExpr()).getBase().toString().equals("$this") && !secretVertices.isEmpty() && !secretVertices.containsValue(new VertexValue("this")))
                {
                    // if (allCompromisedVertexNames.contains(new VertexValue(variable)))
                    variable = ((JVirtualInvokeExpr) stmt.getInvokeExpr()).getBase().toString();
                    if (!UNTAINTED_VARIABLES.contains(variable))
                    {
                        allCompromisedVertexNames.add(new VertexValue(((JVirtualInvokeExpr) stmt.getInvokeExpr()).getBase().toString()));
                        Map.Entry<Integer, VertexValue> firstEntry = secretVertices.entrySet().iterator().next();
                        VertexValue firstVertexValue = firstEntry.getValue();
                        root.insert(firstVertexValue.toString(), variable);
                        compromisedVertices.add(new Result(lineNumber, variable, stmt, false, root.getVariableChaining(variable)));
                        isreprocessRequired = true;
                    }


                }
                else if (stmt.getInvokeExpr() instanceof JSpecialInvokeExpr && !values.isEmpty() && !allCompromisedVertexNames.isEmpty() && !((JSpecialInvokeExpr) stmt.getInvokeExpr()).getBase().toString().equals("$this") && !secretVertices.isEmpty())
                {

                    variable = ((JSpecialInvokeExpr) stmt.getInvokeExpr()).getBase().toString();
                    if (!UNTAINTED_VARIABLES.contains(variable))
                    {
                        allCompromisedVertexNames.add(new VertexValue(((JSpecialInvokeExpr) stmt.getInvokeExpr()).getBase().toString()));
                        Map.Entry<Integer, VertexValue> firstEntry = secretVertices.entrySet().iterator().next();
                        VertexValue firstVertexValue = firstEntry.getValue();
                        root.insert(firstVertexValue.toString(), variable);
                        compromisedVertices.add(new Result(lineNumber, variable, stmt, false, root.getVariableChaining(variable)));
                        isreprocessRequired = true;
                    }
                }
                if (isreprocessRequired)
                {
                    //TODO: figure out predecessor.
                    if (checkTempStackTaintStatus(stackVariablesList, allCompromisedVertexNames))
                    {
                        // it is called to mark object taint status based on temp variables.
                        reprocess(stackVariablesList, allCompromisedVertexNames, compromisedVertices, root);
                    }
                }

                //Debug statement to check the state sharing
                //secretVerticesWrapper = new SecretVerticesWrapper(secretVertices);

                if (className.equals("org.bouncycastle.pqc.legacy.math.linearalgebra.GF2Vector") && methodName.equals("add"))
                {
                    System.out.println("testing");
                }
                SecretVerticesWrapper.FunctionStack functionStack = new SecretVerticesWrapper.FunctionStack(methodName, className, secretVertices);

                if (body.getMethodSignature().getName().equals(methodName) && body.getMethodSignature().getDeclClassType().toString().equals(className)
                        && body.getMethodSignature().getParameterTypes().equals(types))
                {
                    secretVerticesWrapper.add(functionStack);  // 1->2->3
                    if (secretVerticesWrapper.getSizeOfCallingFunctionCurrentSecretVertices() > secretVerticesWrapper.getSizeOfCallingFunctionPreviousSecretVertices())
                    {
                        CompromisedParameterandReturnMapping mapOfCompromisedVariablesWithMethodParametersAndReturnTaintStatus =
                                processSootMethod(stmt, className, methodName, types, secretVerticesWrapper, stmt.getInvokeExpr().getType(), FunctionState.IN_PROGRESS, methodVisitStatus);
                        Map<Integer, String> mapOfCompromisedVariablesWithMethodParameters = mapOfCompromisedVariablesWithMethodParametersAndReturnTaintStatus.gettaintedParametermapping();
                        boolean markReturnTainted = mapOfCompromisedVariablesWithMethodParametersAndReturnTaintStatus.isMarkReturnTainted();
                        boolean returnDeclassifiedByUntrigger = mapOfCompromisedVariablesWithMethodParametersAndReturnTaintStatus.isReturnDeclassifiedByUntrigger();
                        methodVisitStatus.setMethodReturnStatus(markReturnTainted);
                        methodVisitStatus.setReturnDeclassifiedByUntrigger(returnDeclassifiedByUntrigger);
                        methodVisitStatus.setMethodParameterMapping(mapOfCompromisedVariablesWithMethodParameters);
                        handleInvokeAssignmentTainting(stmt, lineNumber, allCompromisedVertexNames, compromisedVertices, root,
                                methodVisitStatus, markReturnTainted, returnDeclassifiedByUntrigger, values);
                        //Map<Integer, String> mapOfCompromisedVariablesWithMethodParameters = mapOfCompromisedVariablesWithMethodParametersAndReturnTaintStatus.gettaintedParametermapping();
                        //CompromisedParameterandReturnMapping mapOfCompromisedVariablesWithMethodParametersAndReturnTaintStatus
                        // variable names with index - function 2 - tainted one's
                        // variable names with index function 1  -
                        // intersection of 1st list and 2st list - add  to all compromisedvertexnames, compromised vartices. - line number we don't need.
                        //
                        addMapOfCompromisedVariablesWithMethodParametersToCompromisedVariables(mapOfCompromisedVariablesWithMethodParameters, values,
                                allCompromisedVertexNames, compromisedVertices, stmt, lineNumber, root, PrimitiveDataTypeVariableSet);
                    }
                    //TODO: Doubl click on clearing state of secret vetices.
                    // secretVerticesWrapper.setPreviousSecretVertices(null);
                    // call recursive once.
                }
                else
                {
                    //func1 - it has tainted variabled x,y,x  it called func2 it has tainted variable a,b,
                    secretVerticesWrapper.add(functionStack);
                    CompromisedParameterandReturnMapping mapOfCompromisedVariablesWithMethodParametersAndReturnTaintStatus =
                            processSootMethod(stmt, className, methodName, types, secretVerticesWrapper, stmt.getInvokeExpr().getType(), FunctionState.IN_PROGRESS, methodVisitStatus);
                    Map<Integer, String> mapOfCompromisedVariablesWithMethodParameters = mapOfCompromisedVariablesWithMethodParametersAndReturnTaintStatus.gettaintedParametermapping();
                    boolean markReturnTainted = mapOfCompromisedVariablesWithMethodParametersAndReturnTaintStatus.isMarkReturnTainted();
                    boolean returnDeclassifiedByUntrigger = mapOfCompromisedVariablesWithMethodParametersAndReturnTaintStatus.isReturnDeclassifiedByUntrigger();
                    methodVisitStatus.setMethodReturnStatus(markReturnTainted);
                    methodVisitStatus.setReturnDeclassifiedByUntrigger(returnDeclassifiedByUntrigger);
                    methodVisitStatus.setMethodParameterMapping(mapOfCompromisedVariablesWithMethodParameters);
                    // variable names with index - function 2 - tainted one's
                    // variable names with index function 1  -
                    // intersection of 1st list and 2st list - add  to all compromisedvertexnames, compromised vartices. - line number we don't need.
                    //
                    handleInvokeAssignmentTainting(stmt, lineNumber, allCompromisedVertexNames, compromisedVertices, root,
                            methodVisitStatus, markReturnTainted, returnDeclassifiedByUntrigger, values);
                    addMapOfCompromisedVariablesWithMethodParametersToCompromisedVariables(mapOfCompromisedVariablesWithMethodParameters, values,
                            allCompromisedVertexNames, compromisedVertices, stmt, lineNumber, root, PrimitiveDataTypeVariableSet);

                }

            }
        }
    }

    public static void processIfTarget(String fullyQualifiedClassName, String simpleMethodName, Set<VertexValue> allCompromisedVertexNames,
                                       Set<Result> compromisedVertices, Stmt stmt, Map<Integer, VertexValue> secretVertices,
                                       Trie root, int lineNumber)
    {
        String key = fullyQualifiedClassName + "#" + simpleMethodName; // hardcoded '#'
        if (TARGET_FQM_INDEX.containsKey(key))
        {
            // MATCH FOUND — implement your further logic here
            // e.g., inspect argument types, etc.
            if (!secretVertices.isEmpty() && !secretVertices.isEmpty())
            {
                Map.Entry<Integer, VertexValue> first = secretVertices.entrySet().iterator().next();
                VertexValue vv = first.getValue();
                String secret = vv.value;
                compromisedVertices.add(new Result(lineNumber, secret, stmt, false, root.getVariableChaining(secret), false, true));
            }
        }
    }

    private static void handleInvokeAssignmentTainting(Stmt stmt,
                                                       int lineNumber,
                                                       Set<VertexValue> allCompromisedVertexNames,
                                                       Set<Result> compromisedVertices,
                                                       Trie root,
                                                       MethodVisitStatus methodVisitStatus,
                                                       boolean markReturnTainted,
                                                       boolean returnDeclassifiedByUntrigger, List<Immediate> values)
    {
        if (!(stmt instanceof JAssignStmt) || !stmt.containsInvokeExpr() || stmt.getDef().isEmpty())
        {
            return;
        }

        String leftOp = stmt.getDef().get().toString();
        VertexValue lhsVertex = new VertexValue(leftOp);

        Value baseValue = null;
        if (stmt.getInvokeExpr() instanceof JVirtualInvokeExpr virtualInvokeExpr)
        {
            baseValue = virtualInvokeExpr.getBase();
        }
        else if (stmt.getInvokeExpr() instanceof JSpecialInvokeExpr specialInvokeExpr)
        {
            baseValue = specialInvokeExpr.getBase();
        }
        else if (stmt.getInvokeExpr() instanceof JInterfaceInvokeExpr interfaceInvokeExpr)
        {
            baseValue = interfaceInvokeExpr.getBase();
        }

        boolean baseIsTainted = false;
        if (baseValue != null)
        {
            VertexValue baseVertex = new VertexValue(baseValue.toString());
            baseIsTainted = allCompromisedVertexNames.contains(baseVertex);
        }

        if (markReturnTainted && methodVisitStatus != null)
        {
            methodVisitStatus.setMethodReturnStatus(true);
        }

        if (baseIsTainted )
        {
            if (returnDeclassifiedByUntrigger && allCompromisedVertexNames.contains(lhsVertex))
            {
                allCompromisedVertexNames.remove(lhsVertex);
            }
            else if (!UNTAINTED_VARIABLES.contains(lhsVertex.value) && markReturnTainted)
            {
                allCompromisedVertexNames.add(lhsVertex);
                compromisedVertices.add(new Result(lineNumber, leftOp, stmt, false, root.getVariableChaining(leftOp)));
            }
        }
        else
        {
            if (markReturnTainted && !returnDeclassifiedByUntrigger)
            {
                if (!UNTAINTED_VARIABLES.contains(lhsVertex.value))
                {
                    allCompromisedVertexNames.add(lhsVertex);
                    compromisedVertices.add(new Result(lineNumber, leftOp, stmt, false, root.getVariableChaining(leftOp)));
                }
            }
            else
            {
                allCompromisedVertexNames.remove(lhsVertex);
            }
        }
    }

    private static void addMapOfCompromisedVariablesWithMethodParametersToCompromisedVariables(Map<Integer, String> mapOfCompromisedVariablesWithMethodParameters,
                                                                                               List<Immediate> values, Set<VertexValue> allCompromisedVertexNames,
                                                                                               Set<Result> compromisedVertices, Stmt stmt, int lineNumber, Trie root, Map<String, String> PrimitiveDataTypeVariableSet)
    {
        //TODO: variable mapping from previous method to current method variables.
        for (int i = 0; i < values.size(); i++)
        {
            if (mapOfCompromisedVariablesWithMethodParameters.containsKey(i))
            {
                Value value = values.get(i);
                String valueString = value.toString();
                if (valueString.contains("#"))
                {
                    valueString = removeHash(valueString);
                }
                if (!PrimitiveDataTypeVariableSet.containsKey(valueString) && !(value instanceof Constant))
                {
                    System.out.println("TODO: variable mapping from previous method to current method variables");
                    VertexValue vertexValue = new VertexValue(valueString);
                    allCompromisedVertexNames.add(vertexValue);
                    //TODO: passing empty variableChaining intentionally.
                    compromisedVertices.add(new Result(lineNumber, valueString, stmt, false, root.getVariableChaining(valueString)));
                }

            }
        }
    }


    private static void reprocess(List<Stmt> stackVariablesList, Set<VertexValue> allCompromisedVertexNames,
                                  Set<Result> compromisedVertices, Trie root)
    {
        for (int i = stackVariablesList.size() - 1; i >= 0; i--)
        {
            Stmt stmt = stackVariablesList.get(i);
            String variable = stmt.getDef().get().toString();

            if (allCompromisedVertexNames.contains(new VertexValue(variable)))
            {
                String objectVariable = stmt.getUses().toList().getLast().toString();
                //String objectVariable = stmt.getUses().get(stmt.getUses().count() - 1).toString();

                allCompromisedVertexNames.add(new VertexValue(objectVariable));
                // line number needs to be corrected. - Dummy line number.
                root.insert(variable, objectVariable);
                compromisedVertices.add(new Result(0, objectVariable, stmt, false, root.getVariableChaining(objectVariable)));
            }
        }
        // findCompromisedStmts(body, allCompromisedVertexNames, compromisedVertices, vertices);
    }

    private static boolean checkTempStackTaintStatus(List<Stmt> stackVariablesList, Set<VertexValue> allCompromisedVertexNames)
    {
        List<Stmt> stackVariablesListCopy = new ArrayList<>(stackVariablesList);
        for (Stmt stmt : stackVariablesListCopy)
        {
            String variable = stmt.getDef().get().toString();
            if (allCompromisedVertexNames.contains(new VertexValue(variable)))
            {
                return true;
            }
            else
            {
                stackVariablesList.remove(stmt);
            }
        }
        return !stackVariablesList.isEmpty();
    }

    private static void addTaintVariablesOfJdkClassTaintConfig(JdkMethodTaintConfig jdkMethodTaintConfig, List<Immediate> values, int lineNumber,
                                                               Stmt stmt, Set<VertexValue> allCompromisedVertexNames, Set<Result> compromisedVertices, Trie root)
    {
        boolean isTaintVariableExist = false;
        String variableCausingOtherVariablesTained = null;
        for (int index : jdkMethodTaintConfig.getTaintIndices())
        {
            String valueString = values.get(index).toString();
            if (valueString.contains("#"))
            {
                valueString = removeHash(valueString);
            }
            VertexValue vertexValue = new VertexValue(valueString);
            if (allCompromisedVertexNames.contains(vertexValue))
            {
                isTaintVariableExist = true;
                variableCausingOtherVariablesTained = valueString;
                break;
            }
        }
        if (isTaintVariableExist)
        {
            for (int index : jdkMethodTaintConfig.getTaintIndices())
            {
                String valueString = values.get(index).toString();
                if (valueString.contains("#"))
                {
                    valueString = removeHash(valueString);
                }
                VertexValue vertexValue = new VertexValue(valueString);
                allCompromisedVertexNames.add(vertexValue);
                if (!variableCausingOtherVariablesTained.equals(valueString))
                {
                    root.insert(variableCausingOtherVariablesTained, valueString);
                }
                if (stmt.getInvokeExpr() instanceof JStaticInvokeExpr && stmt instanceof JAssignStmt)
                {
                    String returnValue = stmt.getDef().get().toString();
                    allCompromisedVertexNames.add(new VertexValue(returnValue));
                    root.insert(variableCausingOtherVariablesTained, returnValue);
                    compromisedVertices.add(new Result(lineNumber, returnValue, stmt, false, root.getVariableChaining(returnValue)));
                }
                compromisedVertices.add(new Result(lineNumber, valueString, stmt, false, root.getVariableChaining(valueString)));
            }
        }
    }

    private static boolean skipProcessingIfJavaPkg(String packageName)
    {
        if (packageName != null)
        {
            for (String pkgName : ignored_packages)
            {
                if (packageName.startsWith(pkgName))
                {
                    JAVA_PKG_LIST.add(packageName);
                    return true;
                }
            }
        }
        return false;
    }

    private static void removeDeclassifiedVariablesToAllCompromisedVertexNames(List<Immediate> values, Set<VertexValue> allCompromisedVertexNames, Map<String, List<String>> mappingOfStackVariables)
    {
        for (Value value : values)
        {
            String valueString = value.toString();
            if (valueString.contains("#"))
            {
                valueString = removeHash(valueString);
            }
            VertexValue vertexValue = new VertexValue(valueString);
            String originalVariable = getOriginalVariableCorrespondingToStackVariable(mappingOfStackVariables, String.valueOf(vertexValue), new LinkedHashSet<>(), allCompromisedVertexNames);
            allCompromisedVertexNames.add(new VertexValue((originalVariable)));
            allCompromisedVertexNames.add(vertexValue);
        }
    }

    private static boolean isVariableDeclassified(String className, String packageName, String methodName)
    {
        return className.equals("Taint") && packageName.equals("org.example.sootaug") && methodName.equals("classify");
    }


    private static void addClassifiedVariablesToAllCompromisedVertexNames(List<Immediate> values, Set<VertexValue> allCompromisedVertexNames, Map<String, List<String>> mappingOfStackVariables)
    {
        for (Value value : values)
        {
            String valueString = value.toString();
            if (valueString.contains("#"))
            {
                valueString = removeHash(valueString);
            }
            VertexValue vertexValue = new VertexValue(valueString);
            String originalVariable = getOriginalVariableCorrespondingToStackVariable(mappingOfStackVariables, String.valueOf(vertexValue), new LinkedHashSet<>(), allCompromisedVertexNames);
            allCompromisedVertexNames.add(new VertexValue((originalVariable)));
            allCompromisedVertexNames.add(vertexValue);
        }
    }

    private static String getOriginalVariableCorrespondingToStackVariable(Map<String, List<String>> mappingOfStackVariables, String value, Set<String> isVisited, Set<VertexValue> allCompromisedVertexNames)
    {
        isVisited.add(value);
        List<String> possibleOriginalVariables = mappingOfStackVariables.get(value);
        if (possibleOriginalVariables == null || possibleOriginalVariables.isEmpty())
        {
            return null;
        }
        String selectedOriginalVariable = null;
        boolean containsStackVariable = possibleOriginalVariables.stream().anyMatch(var -> var.contains("$stack"));
        for (String originalVariable : possibleOriginalVariables)
        {
            if (StringUtils.isNumeric(originalVariable))
            {
                continue;
            }
            if (allCompromisedVertexNames.contains(new VertexValue(originalVariable)))
            {
                selectedOriginalVariable = originalVariable;
                break;
            }
            else if (!originalVariable.contains("$stack") && !containsStackVariable)
            {
                selectedOriginalVariable = originalVariable;
                break;
            }
            if (selectedOriginalVariable == null)
            {
                selectedOriginalVariable = originalVariable;
            }
        }
        //String originalVariable = mappingOfStackVariables.get(value);
        if (selectedOriginalVariable != null && selectedOriginalVariable.contains("$stack") && !isVisited.contains(selectedOriginalVariable))
        {
            return getOriginalVariableCorrespondingToStackVariable(mappingOfStackVariables, selectedOriginalVariable, isVisited, allCompromisedVertexNames);
        }
        return selectedOriginalVariable;
    }

    private static boolean isVariableClassified(String className, String packageName, String methodName)
    {
        return className.equals("Taint") && packageName.equals("org.example.sootaug") && methodName.equals("classify");
    }

    private static void labelTaintStatusUpdater(Body body, Stmt stmt, String className,
                                                Set<VertexValue> allCompromisedVertexNames,
                                                Set<Result> compromisedVertices,
                                                Set<VertexValue> vertices,
                                                List<Stmt> stackVariablesList,
                                                SecretVerticesWrapper secretVerticesWrapper,
                                                Map<String, List<String>> mappingOfStackVariables,
                                                Trie root,
                                                Map<StmtPositionInfoWrapper, IfTaintStatus> ifTaintStatusMap, Map<StmtPositionInfoWrapper, LabelTaintStatus> labelTaintStatusMap)
    {

    }

    private static void findTaintedVariablesInIfElseBlocks(Body body, Stmt stmt, String className,
                                                           Set<VertexValue> allCompromisedVertexNames,
                                                           Set<Result> compromisedVertices,
                                                           Set<VertexValue> vertices,
                                                           List<Stmt> stackVariablesList,
                                                           SecretVerticesWrapper secretVerticesWrapper,
                                                           Map<String, List<String>> mappingOfStackVariables,
                                                           Trie root,
                                                           Map<StmtPositionInfoWrapper, IfTaintStatus> ifTaintStatusMap, Map<StmtPositionInfoWrapper, LabelTaintStatus> labelTaintStatusMap,
                                                           MethodVisitStatus methodVisitStatus)
    {
        // return if not IF stmt
        if (!(stmt instanceof JIfStmt))
        {
            return;
        }

        // retrieve the taint value associted with the IF statament based on
        // its location in the body
        StmtPositionInfoWrapper ifStmtPositionWrapper = new StmtPositionInfoWrapper(stmt.getPositionInfo());

        // save the taint status at the starting of the IF stmt
        Set<VertexValue> savedTaintedVariable;
        if (ifTaintStatusMap.containsKey(ifStmtPositionWrapper))
        {
            savedTaintedVariable = new HashSet<>(ifTaintStatusMap.get(ifStmtPositionWrapper).getCompromisedVertices());
        }
        else
        {
            savedTaintedVariable = new HashSet<>(allCompromisedVertexNames);
        }
        // keep track of the stmts scanned in the analysis
        //List<Stmt> scannedIfStmts = new ArrayList<>();
        //List<Stmt> scannedElseStmts = new ArrayList<>();
        Stmt targetStmt = null;
        Stmt elseExittargetStmt = null;
        // find the target stmt of the given If stmt
        List<Stmt> targetStmts = ((JIfStmt) stmt).getTargetStmts(body);
        if (!targetStmts.isEmpty())
        {
            targetStmt = targetStmts.get(0);
        }

        // booleans to control loop
        boolean isIf = false;
        boolean isElse = false;
        boolean elseTrigger = false;

        // to keep track of the tainted  varaibles inside the if block
        Set<VertexValue> ifblockTaintStatus = new HashSet<>();
        Set<VertexValue> elseblockTaintStatus = new HashSet<>();
        Set<VertexValue> finalIfElseTaintStatus = new HashSet<>(ifblockTaintStatus);
        int lineNumber = 0;

        // scan the method body from start
        for (Stmt scannedStmt : body.getStmts())
        {

            // trigger if loop analysis if the stmt currently scanned is equal to the if stmt
            // two factors considered position and if stmt to avoid if stmt duplicacy
            if (scannedStmt.equals(stmt) && scannedStmt.getPositionInfo().equals(stmt.getPositionInfo()))
            {
                ifblockTaintStatus.addAll(savedTaintedVariable);
                isIf = true;
            }

            // Once analysis hits if stmt start the anlysis CORE
            if (isIf)
            {
                findCompromisedStmtsFromDefBoxes(scannedStmt, className, ifblockTaintStatus,
                        compromisedVertices, vertices, lineNumber, root, methodVisitStatus);
                findCompromisedIfStmts(scannedStmt, ifblockTaintStatus, compromisedVertices,
                        vertices, lineNumber, root);
                /*findInvokeExpression(body, scannedStmt, ifblockTaintStatus, compromisedVertices,
                        stackVariablesList, vertices, lineNumber,
                        secretVerticesWrapper, mappingOfStackVariables, root);*/
                // add the stmts part of if block
                scannedIfStmts.add(scannedStmt);
            }

            if (!scannedStmt.equals(stmt) && body.isStmtBranchTarget(scannedStmt) && scannedStmt.getPositionInfo().equals(targetStmt.getPositionInfo()))
            {
                isElse = false;
                break;
            }

            // identify end of else part based on goTo stmt
            if (scannedStmt instanceof JGotoStmt)
            {
                // track target stmt for the goTo stmt and if it is not already scanned confrim
                // else body.
                targetStmts = ((JGotoStmt) scannedStmt).getTargetStmts(body);
                if (!targetStmts.isEmpty() && !targetStmts.contains(scannedStmt))
                {
                    elseExittargetStmt = targetStmts.get(0);
                    isElse = true;
                    break;
                }
                // or no else part exit if target stmt of the if stmt is reached
            }

            //ifblockTaintStatus.addAll(allCompromisedVertexNames);
            lineNumber++;
        }

        if (isElse)
        {
            for (Stmt elseStmt : body.getStmts())
            {

                if (elseStmt.equals(elseExittargetStmt) && elseStmt.getPositionInfo().equals(elseExittargetStmt.getPositionInfo()))
                {
                    elseTrigger = false;
                    isElse = false;
                    break;
                }
                if (elseStmt.equals(targetStmt) && elseStmt.getPositionInfo().equals(targetStmt.getPositionInfo()))
                {
                    elseblockTaintStatus.addAll(savedTaintedVariable);
                    elseTrigger = true;
                }
                if (elseTrigger)
                {
                    findCompromisedStmtsFromDefBoxes(elseStmt, className, elseblockTaintStatus,
                            compromisedVertices, vertices, lineNumber, root, methodVisitStatus);
                    findCompromisedIfStmts(elseStmt, elseblockTaintStatus, compromisedVertices,
                            vertices, lineNumber, root);
                    /*findInvokeExpression(body, elseStmt, elseblockTaintStatus, compromisedVertices,
                            stackVariablesList, vertices, lineNumber,
                            secretVerticesWrapper, mappingOfStackVariables, root);*/
                    scannedElseStmts.add(elseStmt);
                }
                //elseblockTaintStatus.addAll(elseblockTaintStatus);

            }
        }
        finalIfElseTaintStatus.addAll(elseblockTaintStatus);
        savedTaintedVariable.addAll(finalIfElseTaintStatus);
        allCompromisedVertexNames.addAll(savedTaintedVariable);
        StmtPositionInfoWrapper elseKey;
        StmtPositionInfoWrapper ifKey;
        // Check if elseExittargetStmt is not null before allocation
        if (elseExittargetStmt != null)
        {
            elseKey = new StmtPositionInfoWrapper(elseExittargetStmt.getPositionInfo());

            // Further processing using elseKey...
            // For example, using elseKey to access or modify the labelTaintStatusMap
            if (labelTaintStatusMap.containsKey(elseKey))
            {
                LabelTaintStatus labelTaintStatus = labelTaintStatusMap.get(elseKey);
                labelTaintStatus.setCompromisedVertices(savedTaintedVariable);
                labelTaintStatusMap.put(elseKey, labelTaintStatus);
            }
            else
            {
                String methodName = body.getMethodSignature().getName();
                StmtPositionInfo labelPosition = elseExittargetStmt.getPositionInfo(); // Or however you obtain this
                LabelTaintStatus newLabelTaintStatus = new LabelTaintStatus(methodName, className, savedTaintedVariable, elseExittargetStmt, labelPosition);
                labelTaintStatusMap.put(elseKey, newLabelTaintStatus);
            }
        }
        else if (targetStmt != null)
        {
            // Handle the case where elseExittargetStmt is null
            // For example, log an error or throw an exception
            ifKey = new StmtPositionInfoWrapper(targetStmt.getPositionInfo());
            if (labelTaintStatusMap.containsKey(ifKey))
            {
                LabelTaintStatus labelTaintStatus = labelTaintStatusMap.get(ifKey);
                labelTaintStatus.setCompromisedVertices(savedTaintedVariable);
                labelTaintStatusMap.put(ifKey, labelTaintStatus);
            }
            else
            {
                String methodName = body.getMethodSignature().getName();
                StmtPositionInfo labelPosition = targetStmt.getPositionInfo(); // Or however you obtain this
                LabelTaintStatus newLabelTaintStatus = new LabelTaintStatus(methodName, className, savedTaintedVariable, targetStmt, labelPosition);
                labelTaintStatusMap.put(ifKey, newLabelTaintStatus);
            }
        }

    }

    private static void findTaintedVaraiblesInLoops(Body body, Stmt stmt, String className, Set<VertexValue> allCompromisedVertexNames, Set<Result> compromisedVertices, Set<VertexValue> vertices,
                                                    List<Stmt> stackVariablesList, SecretVerticesWrapper secretVerticesWrapper, Map<String, List<String>> mappingOfStackVariables,
                                                    Trie root, Map<StmtPositionInfoWrapper, LabelTaintStatus> labelTaintStatusMap, Map<String, String> findTaintedVariablesInIfElseBlocks,
                                                    MethodVisitStatus methodVisitStatus)
    {
        if (stmt instanceof JGotoStmt)
        {
            StmtPositionInfo goToPosition = stmt.getPositionInfo();
            Stmt targetStmt = null;
            List<Stmt> targetStmts = ((JGotoStmt) stmt).getTargetStmts(body);
            if (!targetStmts.isEmpty())
            {
                targetStmt = targetStmts.get(0); // Take the first target statement
            }
            StmtPositionInfoWrapper targetStmtPositionWrapper = new StmtPositionInfoWrapper(targetStmt.getPositionInfo());
            List<Stmt> scannedStmts = new ArrayList<>();
            boolean isLoop = false;
            boolean triggerLoop = false;
            int lineNumber = 0;
            Set<VertexValue> savedTaintedVariable = new HashSet<>();
            for (Stmt scannedStmt : body.getStmts())
            {
                if (scannedStmt.equals(stmt) && scannedStmt.getPositionInfo().equals(goToPosition))
                {
                    break; // Exits only this for-loop
                }
                scannedStmts.add(scannedStmt);

                // Check if targetStmt is in scannedStmts
                if (scannedStmt.equals(targetStmt) && scannedStmt.getPositionInfo().equals(targetStmt.getPositionInfo()))
                {
                    isLoop = true;
                    if (labelTaintStatusMap.containsKey(targetStmtPositionWrapper))
                    {
                        savedTaintedVariable = new HashSet<>(labelTaintStatusMap.get(targetStmtPositionWrapper).getCompromisedVertices());
                    }
                    else
                    {
                        savedTaintedVariable = new HashSet<>(allCompromisedVertexNames);
                    }
                }
            }

            while (isLoop)
            {
                lineNumber = 0;
                //targetStmt.getPositionInfo()
                // Save the current state
                for (Stmt currStmt : body.getStmts())
                {
                    if (currStmt.getPositionInfo().equals(goToPosition))
                    {
                        if (savedTaintedVariable.equals(allCompromisedVertexNames))
                        {
                            if (labelTaintStatusMap.containsKey(targetStmtPositionWrapper))
                            {
                                // If the target statement is already in the map, update the compromised vertices
                                LabelTaintStatus existingLabelTaintStatus = labelTaintStatusMap.get(targetStmtPositionWrapper);
                                Set<VertexValue> updatedCompromisedVertices = new HashSet<>(existingLabelTaintStatus.getCompromisedVertices());
                                updatedCompromisedVertices.addAll(savedTaintedVariable); // Logical OR operation
                                existingLabelTaintStatus.setCompromisedVertices(updatedCompromisedVertices);
                                labelTaintStatusMap.put(targetStmtPositionWrapper, existingLabelTaintStatus); // Update the map
                            }
                            /*
                            Stmt nextStmt = body.getStmts().get(lineNumber+1);
                            if (body.isStmtBranchTarget(nextStmt)){
                                StmtPositionInfo labelPosition = nextStmt.getPositionInfo(); // Retrieve position info
                                StmtPositionInfoWrapper labelPositionWrapper = new StmtPositionInfoWrapper(labelPosition);

                                if (labelTaintStatusMap.containsKey(labelPositionWrapper)) {
                                    LabelTaintStatus existingLabelTaintStatus = labelTaintStatusMap.get(labelPositionWrapper);
                                    Set<VertexValue> updatedCompromisedVertices = new HashSet<>(existingLabelTaintStatus.getCompromisedVertices());
                                    allCompromisedVertexNames.clear();
                                    allCompromisedVertexNames.addAll(updatedCompromisedVertices);
                                }
                                System.out.println("next line ");
                            } */
                            isLoop = false;
                            return;// Exit the entire analyzeMethod function
                        }
                        savedTaintedVariable = new HashSet<>(allCompromisedVertexNames); // Update for next iteration
                        triggerLoop = false;
                        break;
                    }
                    if (currStmt.equals(targetStmt))
                    {
                        triggerLoop = true;
                    }
                    if (triggerLoop)
                    {
                        findCompromisedStmtsFromDefBoxes(currStmt, className, allCompromisedVertexNames, compromisedVertices, vertices, lineNumber, root, methodVisitStatus);
                        findCompromisedIfStmts(currStmt, allCompromisedVertexNames, compromisedVertices, vertices, lineNumber, root);
                        findInvokeExpression(body, currStmt, allCompromisedVertexNames, compromisedVertices, stackVariablesList, vertices, lineNumber, secretVerticesWrapper, mappingOfStackVariables, root, findTaintedVariablesInIfElseBlocks);
                    }
                    lineNumber++;
                }
            }

        }

    }


    private static void findCompromisedLoopStmts(Body body, Stmt stmt, Set<VertexValue> allCompromisedVertexNames,
                                                 Set<Result> compromisedVertices, Set<VertexValue> vertices, List<Stmt> stackVariablesList,
                                                 SecretVerticesWrapper secretVerticesWrapper, Map<String, List<String>> mappingOfStackVariables, Trie root,
                                                 MethodVisitStatus methodVisitStatus)
    {
        if (stmt instanceof JGotoStmt)
        {
            Stmt goToStmt = null;
            List<Stmt> goToStmts = ((JGotoStmt) stmt).getTargetStmts(body);
            if (!goToStmts.isEmpty())
            {
                goToStmt = goToStmts.get(0);
            }
            int lineNumber = 0;
            boolean isTraversalRequired = false;
            for (Stmt unit : body.getStmts())
            {
                Stmt currStmt = (Stmt) unit;
                if (currStmt.toString().equals(stmt.toString()))
                {
                    if (((JGotoStmt) stmt).getTargetStmts(body).toString().equals(((JGotoStmt) unit).getTargetStmts(body).toString()))
                    {
                        break;
                    }
                    else if (((JGotoStmt) stmt).getTargetStmts(body).toString().equals(((JGotoStmt) unit).getTargetStmts(body).toString()))
                    {
                        break;
                    }
                }
                if (currStmt.toString().equals("staticinvoke <java.lang.System: void arraycopy(java.lang.Object,int,java.lang.Object,int,int)>($stack48, 0, $outSig, 0, $stack47)"))
                {
                    System.out.println("test");
                }
                if (currStmt.toString().equals(goToStmt.toString()))
                {
                    isTraversalRequired = true;
                }
                if (isTraversalRequired)
                {
                    findCompromisedStmtsFromDefBoxes(currStmt, body.getMethodSignature().getDeclClassType().getClassName(), allCompromisedVertexNames, compromisedVertices, vertices, lineNumber, root, methodVisitStatus);
                    findCompromisedIfStmts(currStmt, allCompromisedVertexNames, compromisedVertices, vertices, lineNumber, root);
                    //findInvokeExpression(body, currStmt, allCompromisedVertexNames, compromisedVertices, stackVariablesList, vertices, lineNumber, secretVerticesWrapper, mappingOfStackVariables, root, PrimitiveDataTypeVariableSet);
                }
                lineNumber++;
            }
        }
    }


    private static void findCompromisedIfStmts(Stmt stmt, Set<VertexValue> allCompromisedVertexNames, Set<Result> compromisedVertices, Set<VertexValue> vertices, int lineNumber, Trie root)
    {
        if (stmt instanceof JIfStmt)
        {

            if (stmt.getUses().toList().stream().anyMatch(u -> u instanceof NullConstant))
            {
                System.out.println("debug");
            }
            if (!stmt.getUses().toList().stream().anyMatch(u -> u instanceof NullConstant))
            {
                List<Value> conditionBoxes = ((JIfStmt) stmt).getCondition().getUses().toList();
                String leftValueBox = conditionBoxes.get(0).toString();
                String rightValueBox = conditionBoxes.get(1).toString();
                if (leftValueBox.contains("#"))
                {
                    leftValueBox = removeHash(leftValueBox);
                }
                if (rightValueBox.contains("#"))
                {
                    rightValueBox = removeHash(rightValueBox);
                }
                VertexValue leftVertexValue = new VertexValue(leftValueBox);
                VertexValue rightVertexValue = new VertexValue(rightValueBox);

                if (allCompromisedVertexNames.contains(leftVertexValue)
                        || allCompromisedVertexNames.contains(rightVertexValue))
                {
                    if (vertices.contains(rightVertexValue))
                    {

                        //TODO: passing empty variableChaining intentionally.
                        compromisedVertices.add(new Result(lineNumber, rightValueBox, stmt, true, root.getVariableChaining(rightValueBox)));
                    }
                    if (vertices.contains(leftVertexValue))
                    {
                        //TODO: passing empty variableChaining intentionally.
                        compromisedVertices.add(new Result(lineNumber, leftValueBox, stmt, true, root.getVariableChaining(leftValueBox)));
                    }
                }
            }

        }
    }

    private static void findCompromisedStmtsFromDefBoxes(Stmt stmt, String className, Set<VertexValue> allCompromisedVertexNames, Set<Result> compromisedVertices,
                                                         Set<VertexValue> vertices, int lineNumber, Trie root, MethodVisitStatus methodVisitStatus)
    {
        List<LValue> leftOp = stmt.getDef().stream().toList();
        List<Value> rightOp = stmt.getUses().toList();

        // ignoring lengthof stmts for taints as they may be false positives.
        //|| stmt.containsInvokeExpr()
        if (leftOp.isEmpty() || (!rightOp.isEmpty() && rightOp.get(0).toString().contains("lengthof")) || scannedIfStmts.contains(stmt)
                || scannedElseStmts.contains(stmt))
        {
            return;
        }
        if (stmt instanceof JAssignStmt) {
            Value rhs = ((JAssignStmt) stmt).getRightOp();

            if (rhs instanceof JInstanceOfExpr) {
                return;
            }
        }

        if (stmt instanceof JAssignStmt as && as.getRightOp() instanceof JInstanceFieldRef)
        {
            var stateOpt = lookupRightOpFieldTag(stmt);

            if (stateOpt.isPresent())
            {
                AnnotationState st = stateOpt.get();

                switch (st)
                {
                    case UNTRIGGER ->
                    {
                        if (methodVisitStatus != null)
                        {
                            methodVisitStatus.setReturnDeclassifiedByUntrigger(true);
                        }
                        return;
                    }
                    case TRIGGER->
                    {

                        allCompromisedVertexNames.add(new VertexValue(leftOp.iterator().next().toString()));
                    }
                    case NONE ->
                    {
                        break;
                    }
                }
            }
            else
            {
                // Not an InstanceFieldRef or class/field unknown; keep default behavior
            }
        }


        if (stmt.containsInvokeExpr())
        {
            if (stmt.getInvokeExpr() instanceof JVirtualInvokeExpr)
            {

                if (!allCompromisedVertexNames.contains(new VertexValue(((JVirtualInvokeExpr) stmt.getInvokeExpr()).getBase().toString())) )//|| stmt.getInvokeExpr().getArgs().isEmpty()
                {
                    return;
                }
            }
            else if (stmt.getInvokeExpr() instanceof JSpecialInvokeExpr)
            {
                if (!allCompromisedVertexNames.contains(new VertexValue(((JSpecialInvokeExpr) stmt.getInvokeExpr()).getBase().toString())))
                {
                    return;
                }
            }
            else if (stmt.getInvokeExpr() instanceof JInterfaceInvokeExpr)
            {
                if (!allCompromisedVertexNames.contains(new VertexValue(((JInterfaceInvokeExpr) stmt.getInvokeExpr()).getBase().toString())))
                {
                    return;
                }
            }
            else if (stmt.getInvokeExpr() instanceof JStaticInvokeExpr)
            {
                List<Value> usesList = stmt.getInvokeExpr().getUses().toList();
                boolean containsRandom = false;
                for (Value value : usesList)
                {
                    if (value instanceof Local)
                    {
                        Local local = (Local) value;
                        if ("random".equals(local.getName()))
                        {
                            containsRandom = true;
                        }

                    }
                }
                if (!containsRandom)
                {
                    return;
                }
            }
        }


        if (stmt.toString().equals("count = $stack25 % $stack24"))
        {
            System.out.println();
        }


        String leftValueBox = leftOp.iterator().next().toString();


        if (leftOp.get(0).getUses().count() > 0)
        {
            System.out.println("debug");
            leftValueBox = leftOp.iterator().next().getUses().findFirst().get().toString();
        }


        if (allCompromisedVertexNames.contains(new VertexValue("length")))
        {
            allCompromisedVertexNames.remove(new VertexValue("length"));
        }
        if (allCompromisedVertexNames.isEmpty())
        {
            return;
        }
        VertexValue leftVertexValue = new VertexValue(leftValueBox);
        if (vertices.contains(leftVertexValue))
        {
            for (Value valueBox : stmt.getUses().toList())
            {
                String valueBoxString = valueBox.toString();
                if (valueBoxString.contains("#"))
                {
                    valueBoxString = removeHash(valueBoxString);
                }
                VertexValue vertexValue = new VertexValue(valueBoxString);

                if (allCompromisedVertexNames.contains(leftVertexValue)
                        && stmt.getUses().count() == 1
                        && rightOp.getFirst() instanceof Constant)
                {
                    allCompromisedVertexNames.remove(leftVertexValue);
                    break;
                }

                if (vertices.contains(vertexValue) && allCompromisedVertexNames.contains(vertexValue) && !(leftOp.iterator().next() instanceof JArrayRef))
                {
                    if (!(rightOp.iterator().next() instanceof JArrayRef))
                    {
                        if (!UNTAINTED_VARIABLES.contains(leftVertexValue.value))
                        {
                            root.insert(vertexValue.value, leftVertexValue.value);
                            allCompromisedVertexNames.add(leftVertexValue);
                            compromisedVertices.add(new Result(lineNumber, leftVertexValue.value, stmt, false, root.getVariableChaining(leftVertexValue.value)));
                        }
                    }
                    else if (rightOp.iterator().next() instanceof JArrayRef)
                    {
                        if (!UNTAINTED_VARIABLES.contains(leftVertexValue.value) && !(vertexValue.equals(new VertexValue(((JAssignStmt) stmt).getArrayRef().getIndex().toString()))))
                        {
                            root.insert(vertexValue.value, leftVertexValue.value);
                            allCompromisedVertexNames.add(leftVertexValue);
                            compromisedVertices.add(new Result(lineNumber, leftVertexValue.value, stmt, false, root.getVariableChaining(leftVertexValue.value)));
                        }
                        else if (!UNTAINTED_VARIABLES.contains(leftVertexValue.value) && allCompromisedVertexNames.contains(new VertexValue(rightOp.get(2).toString())))
                        {
                            // rightOp.get(2).getValue().toString()
                            String rightValueBox = rightOp.iterator().next().getUses().findFirst().get().toString();
                            ArrayTaintedVariable arrayTaintedVariable = new ArrayTaintedVariable(new VertexValue(rightOp.get(2).toString()).value, rightValueBox, rightOp.iterator().next().toString());
                            compromisedVertices.add(new Result(lineNumber, rightOp.iterator().next().toString(), stmt, false,
                                    root.getVariableChaining(vertexValue.value), true, arrayTaintedVariable));

                        }
                    }

                }
                //  if (stmt.getUseBoxes().iterator().next().getValue() instanceof JMulExpr ||  stmt.getUseBoxes().iterator().next().getValue() instanceof JDivExpr)
                if (stmt.getUses().iterator().next() instanceof JDivExpr || stmt.getUses().iterator().next() instanceof JRemExpr)
                {
                    if (vertices.contains(vertexValue) && allCompromisedVertexNames.contains(vertexValue))
                    {
                        compromisedVertices.add(new Result(lineNumber, vertexValue.value, stmt, false, root.getVariableChaining(vertexValue.value), true, false));
                        System.out.println("Mul or Div");
                        System.out.println("Arithemetic Compromised vertices:" + vertexValue.value.toString());
                    }
                }


                if (leftOp.iterator().next() instanceof JArrayRef)
                {
                    if (allCompromisedVertexNames.contains(new VertexValue(((JAssignStmt) stmt).getArrayRef().getIndex().toString())) && leftOp.iterator().next() instanceof JArrayRef)
                    {
                        ArrayTaintedVariable arrayTaintedVariable = new ArrayTaintedVariable(new VertexValue(((JAssignStmt) stmt).getArrayRef().getIndex().toString()).value, leftValueBox, leftOp.iterator().next().toString());
                        compromisedVertices.add(new Result(lineNumber, leftOp.iterator().next().toString(), stmt, false,
                                root.getVariableChaining(vertexValue.value), true, arrayTaintedVariable));
                    }
                    else if (vertices.contains(vertexValue) && allCompromisedVertexNames.contains(vertexValue) && !(vertexValue.equals(new VertexValue(((JAssignStmt) stmt).getArrayRef().getIndex().toString()))))
                    {
                        if (!UNTAINTED_VARIABLES.contains(leftVertexValue.value))
                        {
                            root.insert(vertexValue.value, leftVertexValue.value);
                            allCompromisedVertexNames.add(leftVertexValue);
                            compromisedVertices.add(new Result(lineNumber, leftVertexValue.value, stmt, false, root.getVariableChaining(leftVertexValue.value)));
                        }
                    }
                }


                if (stmtHasFieldRef(stmt))
                {
                    String frv = stmt.getFieldRef().getFieldSignature().getName();
                    ClassVariable classVariable = new ClassVariable(className, frv);
                    VertexValue vertexValueRef = new VertexValue(classVariable.toString());
                    if (vertices.contains(vertexValueRef) && allCompromisedVertexNames.contains(vertexValueRef))
                    {
                        if (!UNTAINTED_VARIABLES.contains(leftVertexValue.value))
                        {
                            root.insert(vertexValueRef.value, leftVertexValue.value);
                            allCompromisedVertexNames.add(leftVertexValue);
                            compromisedVertices.add(new Result(lineNumber, leftVertexValue.value, stmt, false, root.getVariableChaining(leftVertexValue.value)));
                            if (leftOp.iterator().next() instanceof JArrayRef)
                            {
                                allCompromisedVertexNames.add(new VertexValue(leftOp.iterator().next().toString()));
                                compromisedVertices.add(new Result(lineNumber, leftOp.iterator().next().toString(), stmt, false,
                                        root.getVariableChaining(leftVertexValue.value)));

                            }
                        }
                    }
                }
            }
        }
    }

    private static boolean stmtHasFieldRef(Stmt stmt)
    {
        boolean isFieldRef = false;
        try
        {
            stmt.getFieldRef();
            isFieldRef = true;
        }
        catch (Exception ex)
        {

        }
        return isFieldRef;
    }

    private static CompromisedParameterandReturnMapping mappingOfCompromisedVariablesWithMethodParameters(Set<VertexValue> allCompromisedVertexNames, List<Local> parameterLocals, Set<Value> returnVariablesList)
    {
        Map<Integer, String> mapping = new LinkedHashMap<>();
        boolean markReturnTainted = false;
        for (int i = 0; i < parameterLocals.size(); i++)
        {
            Local local = parameterLocals.get(i);
            String normalizedLocalName = normalizeName(local.getName());
            //! (local.getType() instanceof PrimitiveType)
            if (containsNormalized(allCompromisedVertexNames, normalizedLocalName))
            {
                mapping.put(i, local.getName());
            }
        }
        for (Value returnVar : returnVariablesList)
        {
            String returnVarName = returnVar.toString();
            if (containsNormalized(allCompromisedVertexNames, returnVarName))
            {
                markReturnTainted = true;
                break;  // No need to check further once we know a return variable is tainted
            }
        }

        return new CompromisedParameterandReturnMapping(mapping, markReturnTainted);
    }

    private static boolean containsNormalized(Set<VertexValue> set, String normalizedValue)
    {
        for (VertexValue value : set)
        {
            if (normalizeName(value.value).equals(normalizeName(normalizedValue)))
            {
                return true;
            }
        }
        return false;
    }

    private static String normalizeName(String name)
    {
        return name.replaceAll("#\\d+", "");
    }

   /*
    }*/

    private static VertexValue getVertexValue(Value valueBox)
    {
        return new VertexValue(getValue(valueBox));
    }


    private static String getValue(Value valueBox)
    {
        String valueString = valueBox.toString();
        if (valueString.contains("#"))
        {
            valueString = removeHash(valueString);
        }
        return valueString;
    }

    //  Earlier it was coded with an understanding that same variable is mapped to var, var#1,var#2 in successive statements.
    //  Currently this behaviour is not encouterede with bouncyCastle hence, we are commenting logic to remove # from variable.
    //  TODO: understand soot jimple variable name generation logic.
    private static String removeHash(String valueBoxString)
    {
        return valueBoxString;
        // return valueBoxString.split("#")[0];
    }

    /*
     */

    private static void annotationManager(JavaSootMethod jMethod, JavaSootClass sc)
    {
        Optional<JavaView> viewOpt = Optional.ofNullable(javaProject);

        for (AnnotationUsage au : jMethod.getAnnotations(viewOpt))
        {
            String at = au.getAnnotation().getClassName();
            System.out.println("[ANN][METHOD] " + at + " values=" + au.getValues());
        }

        Map<String, Set<String>> collected = new LinkedHashMap<>();
        for (JavaSootField field : sc.getFields())
        {
            String fieldName = field.getSignature().getName();
            Set<String> names = new LinkedHashSet<>();
            field.getAnnotations(viewOpt).forEach(au -> names.add(au.getAnnotation().getClassName()));
            if (!names.isEmpty())
            {
                names.forEach(name -> System.out.println("[ANN][FIELD] " + field.getSignature() + " -> " + name));
            }
            collected.put(fieldName, names);
        }

        Map<String, Set<String>> fallback = loadFieldAnnotationsFromBytecode(sc.getType().getFullyQualifiedName());
        fallback.forEach((simpleName, annNames) ->
        {
            Set<String> already = collected.computeIfAbsent(simpleName, k -> new LinkedHashSet<>());
            for (String annName : annNames)
            {
                if (already.add(annName))
                {
                    System.out.println("[ANN][FIELD] " + sc.getType().getFullyQualifiedName()
                            + "." + simpleName + " -> " + annName);
                }
            }
        });
    }

    private static CompromisedParameterandReturnMapping processSootMethod(Stmt stmt, String className, String methodName, List<Type> parameterTypes,
                                                                          SecretVerticesWrapper secretVerticesWrapper, Type returnType, FunctionState functionState,
                                                                          MethodVisitStatus methodVisitStatus)
    {

        System.out.println("method name = " + methodName);

        System.out.println("returnType = " + returnType.toString());
        ClassType classType = javaProject.getIdentifierFactory().getClassType(className);

        JavaClassType yourClassType = JavaIdentifierFactory.getInstance().getClassType(className);

        JavaSootClass sc = javaProject.getClass(classType).get();
        System.out.println("SootClass: " + sc);

        SootMethod sm;
        Body body;
        try
        {
            sm = sc.getMethod(JavaIdentifierFactory.getInstance().getMethodSubSignature(methodName, returnType, parameterTypes)).get();
            System.out.println("Method Signature: " + sm);
            JavaSootMethod jMethod = (JavaSootMethod) sm;
            //annotationManager(jMethod, sc);
            body = sm.getBody();

        }
        catch (Exception e)
        {
            //Run time polymorhism handling.
            STMT_SET_ERRORS_METHOD.add(stmt);
            if (sc.isAbstract())
            {
                System.out.println("debug");
            }
            if (sc.hasSuperclass())
            {
                System.out.println("debug");
            }
            if (sc.isInterface())
            {
                System.out.println("debug");
            }
            //if(sc.isAbstract() || sc.isInterface() || sc.hasSuperclass())
            if (sc.isAbstract() || sc.isInterface() || sc.hasSuperclass())
            {
                return analyseMethodwithMissedBody(classType, yourClassType, methodName, parameterTypes, returnType, stmt, secretVerticesWrapper, methodVisitStatus);
            }
            else if (sc.hasSuperclass())
            {
                if (!sc.getSuperclass().get().toString().contains("java.lang.Object"))
                {
                    className = sc.getSuperclass().get().toString();
                    processSootMethod(stmt, className, methodName, parameterTypes, secretVerticesWrapper, returnType, FunctionState.IN_PROGRESS,
                            methodVisitStatus);
                    STMT_SET_ERRORS_METHOD.remove(stmt);
                    subclassTester(yourClassType, className, methodName, parameterTypes, returnType); // Call subclassTester
                }
            }
            else
            {
                STMT_SET_ERRORS_METHOD.add(stmt);
            }

            return new CompromisedParameterandReturnMapping(new LinkedHashMap<>(), false);
        }

        System.out.println("Method Signature: " + sm);

        List<String> allSources = new LinkedList<>();

        // source map- input param passed;
        Map<String, Type> inputSourceMap = getInputSourceMap(body, sm, allSources, secretVerticesWrapper.getCallingFunctionCurrentSecretVertices());
        secretVerticesWrapper.addCalledFunctionSecretVerticesToTop(inputSourceMap.keySet());
        Set<VertexValue> allCompromisedVertexNames = new LinkedHashSet<>();
        addClassVariablesToAllCompromisedVertexNamesFirstTimeOnly(sc, sm, className, allCompromisedVertexNames, secretVerticesWrapper);
        System.out.println("The inputs detected are:" + inputSourceMap.keySet());
        Trie root = new Trie();
        loadInputSourceMapToTrieAtRoot(root, inputSourceMap.keySet());

        //    allSources.addAll(inputSourceMap.keySet());

        printUnits(body, inputSourceMap, allSources);
        System.out.println("--------------");


        // Print statements that have branch conditions
        System.out.println("Branch Statements:");
        Map<String, String> branchDependentOnSource = new LinkedHashMap<>();
        Map<Integer, String> branchLocation = new LinkedHashMap<>();
        printBranchingStatements(body, branchDependentOnSource, branchLocation, allSources);
        System.out.println("--------------");

        Set<VertexValue> vertices = new LinkedHashSet<>();
        createVertices(body, sc, sm, className, vertices, secretVerticesWrapper);
        Set<Result> compromisedVertices = new LinkedHashSet<>();
        addInputSecretsToCompromisedVertices(body, compromisedVertices, allCompromisedVertexNames, inputSourceMap, root);
        if (className.equals("org.bouncycastle.crypto.constraints.LegacyBitsOfSecurityConstraint") & methodName.equals("check"))
        {
            System.out.println("testing");
        }
        CompromisedParameterandReturnMapping mapOfCompromisedVariablesWithMethodParametersAndReturnTaintStatus =
                findCompromisedStmts(body, allCompromisedVertexNames, compromisedVertices, vertices, secretVerticesWrapper, inputSourceMap.keySet(), root, className, methodName, methodVisitStatus);
        if (methodVisitStatus != null)
        {
            mapOfCompromisedVariablesWithMethodParametersAndReturnTaintStatus
                    .setReturnDeclassifiedByUntrigger(methodVisitStatus.isReturnDeclassifiedByUntrigger());
        }
        return mapOfCompromisedVariablesWithMethodParametersAndReturnTaintStatus;

    }


    private static Map<String, Set<String>> loadFieldAnnotationsFromBytecode(String className)
    {
        if (OUTPUT_DIRECTORY == null) return Map.of();
        Path baseDir = Paths.get(OUTPUT_DIRECTORY);
        if (!Files.isDirectory(baseDir)) return Map.of();

        try (URLClassLoader loader = new URLClassLoader(
                new URL[]{baseDir.toUri().toURL()},
                HelloSootup.class.getClassLoader())
        )
        {
            Class<?> clazz = Class.forName(className, false, loader);
            Map<String, Set<String>> result = new LinkedHashMap<>();
            for (Field field : clazz.getDeclaredFields())
            {
                Annotation[] annotations = field.getDeclaredAnnotations();
                if (annotations.length == 0) continue;
                Set<String> names = new LinkedHashSet<>();
                for (Annotation annotation : annotations)
                {
                    names.add(annotation.annotationType().getName());
                }
                result.put(field.getName(), names);
            }
            return result;
        }
        catch (MalformedURLException | ClassNotFoundException e)
        {
            System.err.println("Failed to load field annotations for " + className + ": " + e.getMessage());
        }
        catch (IOException e)
        {
            System.err.println("I/O error while loading field annotations for " + className + ": " + e.getMessage());
        }
        return Map.of();
    }

    private static CompromisedParameterandReturnMapping analyseMethodwithMissedBody(ClassType classType, JavaClassType yourClassType, String methodName, List<Type> parameterTypes, Type returnType, Stmt stmt, SecretVerticesWrapper secretVerticesWrapper, MethodVisitStatus methodVisitStatus)
    {

        boolean isSuperClass = false;
        // Check if the passed Soot class is of interface type
        if (javaProject.getTypeHierarchy().isInterface(yourClassType))
        {
            List<ClassType> implementations = javaProject.getTypeHierarchy().implementersOf(yourClassType).toList();
            Map<Integer, String> mapOfCompromisedVariablesWithMethodParameters = new HashMap<>();
            Map<Integer, String> tempMap = new HashMap<>();
            Map<Integer, VertexValue> tempMap1 = new HashMap<>();
            Map<Integer, VertexValue> convertedMap = new HashMap<>();
            Map<Integer, VertexValue> incrementedMap = new HashMap<>();
            CompromisedParameterandReturnMapping mapOfCompromisedVariablesWithMethodParametersAndReturnTaintStatus = new CompromisedParameterandReturnMapping(new LinkedHashMap<>(), false);
            for (ClassType implementation : implementations)
            {
                try
                {
                    JavaSootClass sc = javaProject.getClass(implementation).get();
                    SootMethod sm = sc.getMethod(JavaIdentifierFactory.getInstance().getMethodSubSignature(methodName, returnType, parameterTypes)).get();

                    if (sc.getMethods().contains(sm))
                    {
                        // Retrieve the class name
                        String implClassName = implementation.getFullyQualifiedName();

                        // Process the Soot method
                        tempMap1 = secretVerticesWrapper.getCallingFunctionCurrentSecretVertices();
                        SecretVerticesWrapper.FunctionStack functionStack = new SecretVerticesWrapper.FunctionStack(methodName, implClassName, tempMap1);
                        secretVerticesWrapper.add(functionStack);
                        mapOfCompromisedVariablesWithMethodParametersAndReturnTaintStatus = processSootMethod(stmt, implClassName, methodName, parameterTypes, secretVerticesWrapper, returnType, FunctionState.IN_PROGRESS, methodVisitStatus);
                        mapOfCompromisedVariablesWithMethodParameters = mapOfCompromisedVariablesWithMethodParametersAndReturnTaintStatus.gettaintedParametermapping();


                        // Update temporary map if it has fewer entries
                        if (mapOfCompromisedVariablesWithMethodParameters.size() > tempMap.size())
                        {
                            tempMap.clear();
                            tempMap.putAll(mapOfCompromisedVariablesWithMethodParameters);
                            convertedMap = convertMap(tempMap);
                            incrementedMap = incrementKeys(convertedMap);
                            /*
                            SecretVerticesWrapper.FunctionStack functionStack = new SecretVerticesWrapper.FunctionStack(methodName, implClassName, incrementedMap);
                            secretVerticesWrapper.add(functionStack);

                             */
                        }
                        else
                        {
                            convertedMap = convertMap(tempMap);
                            incrementedMap = incrementKeys(convertedMap);
                            /*
                            SecretVerticesWrapper.FunctionStack functionStack = new SecretVerticesWrapper.FunctionStack(methodName, implClassName, incrementedMap);
                            secretVerticesWrapper.add(functionStack);
                             */
                        }

                    }
                }
                catch (Exception e)
                {
                    // Handle exceptions if method not found
                    STMT_SET_ERRORS_METHOD.add(stmt);
                }

            }
            mapOfCompromisedVariablesWithMethodParameters.clear();
            mapOfCompromisedVariablesWithMethodParameters.putAll(tempMap);
            // Remove the top entry after processing
            secretVerticesWrapper.removeTop();
            // Return the highest state achieved map
            mapOfCompromisedVariablesWithMethodParametersAndReturnTaintStatus.setMapping(mapOfCompromisedVariablesWithMethodParameters);
            return mapOfCompromisedVariablesWithMethodParametersAndReturnTaintStatus;
        }
        else if (javaProject.getClass(classType).get().isAbstract())
        {
            // To be implemented later for abstract classes

            List<ClassType> implementations = javaProject.getTypeHierarchy().directSubtypesOf(yourClassType).toList();
            Map<Integer, String> mapOfCompromisedVariablesWithMethodParameters = new HashMap<>();
            Map<Integer, String> tempMap = new HashMap<>();
            Map<Integer, VertexValue> tempMap1 = new HashMap<>();
            Map<Integer, VertexValue> convertedMap = new HashMap<>();
            Map<Integer, VertexValue> incrementedMap = new HashMap<>();
            CompromisedParameterandReturnMapping mapOfCompromisedVariablesWithMethodParametersAndReturnTaintStatus = new CompromisedParameterandReturnMapping(new LinkedHashMap<>(), false);
            for (ClassType implementation : implementations)
            {
                try
                {
                    System.out.println("debug");
                    JavaSootClass sc = javaProject.getClass(implementation).get();
                    SootMethod sm = sc.getMethod(JavaIdentifierFactory.getInstance().getMethodSubSignature(methodName, returnType, parameterTypes)).get();
                    if (sc.getMethods().contains(sm))
                    {
                        String implClassName = implementation.getFullyQualifiedName();
                        // Process the Soot method
                        tempMap1 = secretVerticesWrapper.getCallingFunctionCurrentSecretVertices();
                        SecretVerticesWrapper.FunctionStack functionStack = new SecretVerticesWrapper.FunctionStack(methodName, implClassName, tempMap1);
                        secretVerticesWrapper.add(functionStack);
                        mapOfCompromisedVariablesWithMethodParametersAndReturnTaintStatus = processSootMethod(stmt, implClassName, methodName, parameterTypes, secretVerticesWrapper, returnType, FunctionState.IN_PROGRESS, methodVisitStatus);
                        mapOfCompromisedVariablesWithMethodParameters = mapOfCompromisedVariablesWithMethodParametersAndReturnTaintStatus.gettaintedParametermapping();

                        // Update temporary map if it has fewer entries
                        if (mapOfCompromisedVariablesWithMethodParameters.size() > tempMap.size())
                        {
                            tempMap.clear();
                            tempMap.putAll(mapOfCompromisedVariablesWithMethodParameters);
                            convertedMap = convertMap(tempMap);
                        }
                        else
                        {
                            convertedMap = convertMap(tempMap);
                        }
                    }
                }
                catch (Exception e)
                {
                    STMT_SET_ERRORS_METHOD.add(stmt);
                }
            }
            mapOfCompromisedVariablesWithMethodParameters.clear();
            mapOfCompromisedVariablesWithMethodParameters.putAll(tempMap);
            // Remove the top entry after processing
            secretVerticesWrapper.removeTop();
            // Return the highest state achieved map
            mapOfCompromisedVariablesWithMethodParametersAndReturnTaintStatus.setMapping(mapOfCompromisedVariablesWithMethodParameters);
            return mapOfCompromisedVariablesWithMethodParametersAndReturnTaintStatus;

        }
        else if (javaProject.getClass(classType).get().hasSuperclass() && !javaProject.getClass(classType).get().getSuperclass().get().toString().equals("java.lang.Object"))
        {
            CompromisedParameterandReturnMapping mapOfCompromisedVariablesWithMethodParametersAndReturnTaintStatus = new CompromisedParameterandReturnMapping(new LinkedHashMap<>(), false);
            // To be implemented later for classes with a superclass
            // (javaProject.getClass(((javaProject.getClass(javaProject.getIdentifierFactory().getClassType(className)).get()).getSuperclass().get())).get()).getSuperclass().get()
            try
            {
                System.out.println("debug");
                JavaSootClass currentSootClass = javaProject.getClass(classType).get();
//                //ClassType superClass = currentSootClass.getSuperclass().get();
//                String tempClassName = superClass.toString();
//
//                JavaSootClass currentSuperClass = ((javaProject.getClass(javaProject.getIdentifierFactory().getClassType(tempClassName)).get()));
//                superClass = currentSuperClass.getSuperclass().get();
//                tempClassName = superClass.toString();
//
//                JavaSootClass presentSuperClass = ((javaProject.getClass(javaProject.getIdentifierFactory().getClassType(tempClassName)).get()));
//                superClass = presentSuperClass.getSuperclass().get();

                // SootMethod sm = currentSootClass.getMethod(JavaIdentifierFactory.getInstance().getMethodSubSignature(methodName, returnType, parameterTypes)).get();
                while (currentSootClass != null)
                {
                    try
                    {
                        SootMethod sm = currentSootClass.getMethod(JavaIdentifierFactory.getInstance().getMethodSubSignature(methodName, returnType, parameterTypes)).get();
                        String implClassName = currentSootClass.toString();
                        mapOfCompromisedVariablesWithMethodParametersAndReturnTaintStatus = processSootMethod(stmt, implClassName, methodName, parameterTypes, secretVerticesWrapper, returnType, FunctionState.IN_PROGRESS, methodVisitStatus);
                        isSuperClass = true;
                        break;
                    }
                    catch (Exception e)
                    {
                        try
                        {
                            ClassType superClass = currentSootClass.getSuperclass().orElse(null);
                            if (superClass == null)
                            {
                                break;
                            }
                            currentSootClass = javaProject.getClass(superClass).get();
                        }
                        catch (Exception ex)
                        {
                            break;
                        }
                    }
                }
                return mapOfCompromisedVariablesWithMethodParametersAndReturnTaintStatus;
            }
            catch (Exception e)
            {

            }

        }
        else
        {
            // Log error and return an empty map
            STMT_SET_ERRORS_METHOD.add(stmt);
            return new CompromisedParameterandReturnMapping(new LinkedHashMap<>(), false);
        }
        if (!isSuperClass)
        {
            secretVerticesWrapper.removeTop();
        }
        return new CompromisedParameterandReturnMapping(new LinkedHashMap<>(), false);
        //Map<Integer, String> mapOfCompromisedVariablesWithMethodParameters = mapOfCompromisedVariablesWithMethodParametersAndReturnTaintStatus.gettaintedParametermapping();
        //CompromisedParameterandReturnMapping mapOfCompromisedVariablesWithMethodParametersAndReturnTaintStatus
    }

    public static Map<Integer, VertexValue> incrementKeys(Map<Integer, VertexValue> inputMap)
    {
        Map<Integer, VertexValue> incrementedMap = new LinkedHashMap<>();
        for (Map.Entry<Integer, VertexValue> entry : inputMap.entrySet())
        {
            incrementedMap.put(entry.getKey() + 1, entry.getValue());
        }
        return incrementedMap;
    }

    private static Map<Integer, VertexValue> convertMap(Map<Integer, String> inputMap)
    {
        Map<Integer, VertexValue> convertedMap = new HashMap<>();
        for (Map.Entry<Integer, String> entry : inputMap.entrySet())
        {
            convertedMap.put(entry.getKey(), new VertexValue(entry.getValue()));
        }
        return convertedMap;
    }

    private static void subclassTester(JavaClassType yourClassType, String className, String methodName, List<Type> parameterTypes, Type returnType)
    {
        List<ClassType> subclasses = javaProject.getTypeHierarchy().subclassesOf(yourClassType).toList();
        boolean methodImplemented = false;
        SubclassErrorEntry errorEntry = new SubclassErrorEntry(className, yourClassType.toString(), subclasses, methodName);
        for (ClassType subclass : subclasses)
        {
            try
            {
                ClassType classType = javaProject.getIdentifierFactory().getClassType(subclass.getClassName());
                JavaSootClass sc = javaProject.getClass(classType).get();
                SootMethod sm = sc.getMethod(JavaIdentifierFactory.getInstance().getMethodSubSignature(methodName, returnType, parameterTypes)).get();
                errorEntry.addMethod(sm);
                Body body = sm.getBody();
                methodImplemented = true;
                break; // If method is implemented in any subclass, exit the loop
            }
            catch (Exception e)
            {
                // Method not found in this subclass, continue checking next subclass
            }
        }

        if (!methodImplemented)
        {
            // Log the error if the method is not implemented in any subclass
            SUBCLASS_ERR_LIST.add(errorEntry);
        }
    }

    public static void printSubclassErrors()
    {
        if (SUBCLASS_ERR_LIST.isEmpty())
        {
            System.out.println("No subclass errors found.");
            return;
        }

        System.out.println("Subclass Errors:");
        for (SubclassErrorEntry entry : SUBCLASS_ERR_LIST)
        {
            System.out.println("Super Class: " + entry.getSuperClassType());
            System.out.println("Class Name: " + entry.getClassName());
            System.out.println("Subclasses:");
            for (ClassType subclass : entry.getSubclasses())
            {
                System.out.println("  - " + subclass.getClassName());
            }
            System.out.println("Method_Name: " + entry.getMethodName());
            System.out.println("Methods:");
            for (SootMethod method : entry.getMethods())
            {
                System.out.println("  - " + method.getSignature());
            }
        }
    }


    private static void addInputSecretsToCompromisedVertices(Body body, Set<Result> compromisedVertices, Set<VertexValue> allCompromisedVertexNames,
                                                             Map<String, Type> sourceMap, Trie root)
    {
        int lineNumber = 0;
        for (Stmt unit : body.getStmts())
        {
            Stmt stmt = unit;
            for (Value valueBox : stmt.getUsesAndDefs().toList())
            {
                String value = valueBox.toString();
                if (sourceMap.containsKey(value) && !UNTAINTED_VARIABLES.contains(value))
                {
                    allCompromisedVertexNames.add(new VertexValue(value));
                    //  //TODO: passing empty variableChaining intentionally.
                    Result result = new Result(lineNumber, value, stmt, false, root.getVariableChaining(value));
                    compromisedVertices.add(result);
                }
                else if (TAINTED_VARIABLES.contains(value))
                {
                    allCompromisedVertexNames.add(new VertexValue(value));
                    //TODO: passing empty variableChaining intentionally.
                    Result result = new Result(lineNumber, value, stmt, false, root.getVariableChaining(value));
                    compromisedVertices.add(result);
                }
            }
            ++lineNumber;
        }
    }


    private static void printBranchingStatements(Body body, Map<String, String> branchDependentOnSource, Map<Integer, String> branchLocation, List<String> allSources)
    {
        int d = 1;
        for (Stmt u : body.getStmts())
        {
            if (u instanceof JIfStmt)
            {
                List<Value> valueBoxes = ((JIfStmt) u).getCondition().getUses().toList();
                for (Value valueBox : valueBoxes)
                {
                    if (allSources.contains(valueBox.toString()))
                    {
                        branchDependentOnSource.put(valueBox.toString(), u.toString());
                        branchLocation.put(d, u.toString());
                    }
                }
                System.out.println(u);
            }
            d++;
        }
    }

    private static Map<String, String> printUnits(Body body, Map<String, Type> sourceMap, List<String> allSources)
    {
        System.out.println("Units:");

        int lineNumber = 0;
        // source depended map statemnts driven by the orginal sources
        // any statemnt other than if will be recorded in to source depn map

        Map<String, String> sourceDependent = new LinkedHashMap<>();
        for (Stmt u : body.getStmts())
        {
            if (u.toString().equals("in_range = 0"))
            {
                System.out.println("debug");
            }
            //((JAssignStmt) u).getLeftOpBox().getValue() instanceof JArrayRef
            if (u.toString().equals("out[j] = $stack16"))
            {
                System.out.println("debug");
            }
            // arrayType
            if (u instanceof JAssignStmt)
            {
                String leftOperand = ((JAssignStmt) u).getLeftOp().toString();
                if (!sourceMap.containsKey(leftOperand))
                {
                    String rightOperand = ((JAssignStmt) u).getRightOp().toString();
                    if (checkIfRightOperandInSources(rightOperand, allSources))
                    {
                        allSources.add(leftOperand);
                        sourceDependent.put(leftOperand, rightOperand);
                    }
                }
            }
            System.out.println("(" + lineNumber + ") " + u.toString());
            lineNumber++;
        }
        return sourceDependent;
    }

    private static boolean checkIfRightOperandInSources(String rightOperand, List<String> allSources)
    {
        for (String sourceKey : allSources)
        {
            if (rightOperand.contains(sourceKey))
            {
                return true;
            }
        }
        return false;
    }

    private static Map<String, Type> getInputSourceMap(Body body, SootMethod sm, List<String> allSources, Map<Integer, VertexValue> secretVertices)
    {
        Map<String, Type> inputSourceMap = new LinkedHashMap<>();
        if (TAINT_CONFIG_TO_BE_SET)
        {
            if (methodConfig.taintConfig != null)
            {
                TAINT_CONFIG = methodConfig.taintConfig;
            }
            else
            {
                parseTaintConfig();
            }
            TARGET_FQM_INDEX = MethodSignatureConfigLoader.buildIndex(methodConfig);
            parseAbstractConfig();
            parseJdkClassTaintConfig();
            setTaintConfig(body, sm, inputSourceMap, allSources);
        }

        String isUserInputRequried = "no";
        Scanner scanner = new Scanner(System.in);
        if (PROMPT_REQUIRED)
        {
            System.out.println("Do you want to choose secret variables, Enter yes or no");
            isUserInputRequried = scanner.next();
            forceTaintedVariables(scanner);
        }

        int i = 0;
        for (Local l : getParameterLocals(sm))
        {
            ++i;
            String name = removeDollar(l.getName());
            if ("yes".equals(isUserInputRequried))
            {
                System.out.println("Do you want " + name + " to be secret, Enter yes or no");
                String secret = scanner.next();
                if ("yes".equals(secret))
                {
                    if (secretVertices != null)
                    {
                        if (secretVertices.containsKey(i))
                        {
                            inputSourceMap.put(name, l.getType());
                            allSources.add(name);
                        }
                    }
                    else
                    {
                        if (!UNTAINTED_VARIABLES.contains(name))
                        {
                            inputSourceMap.put(name, l.getType());
                            allSources.add(name);
                        }
                    }
                }
                else if (TAINTED_VARIABLES.contains(name) && !UNTAINTED_VARIABLES.contains(l.getName()))
                {
                    inputSourceMap.put(name, l.getType());
                    allSources.add(l.getName());
                }
            }
            else if (!TAINT_CONFIG_TO_BE_SET)
            {
                if (secretVertices != null)
                {
                    if (secretVertices.containsKey(i))
                    {
                        inputSourceMap.put(name, l.getType());
                        allSources.add(name);
                    }
                }
                else
                {
                    inputSourceMap.put(name, l.getType());
                    allSources.add(name);
                }
            }
        }
        PROMPT_REQUIRED = false;
        TAINT_CONFIG_TO_BE_SET = false;
        return inputSourceMap;
    }

    private static String removeDollar(String name)
    {
        if (name.startsWith("$"))
        {
            return name.substring(0);
        }
        return name;
    }

    /*
        dollar is coming with variables. we are removing it with function
     */
    public static List<Local> getParameterLocals(SootMethod sm)
    {
        int numParams = sm.getParameterCount();
        List<Local> retVal = new ArrayList(numParams);
        Iterator var3 = sm.getBody().getStmts().iterator();

        while (var3.hasNext())
        {
            Stmt u = (Stmt) var3.next();
            if (u instanceof JIdentityStmt)
            {
                JIdentityStmt is = (JIdentityStmt) u;
                if (is.getRightOp() instanceof JParameterRef)
                {
                    JParameterRef pr = (JParameterRef) is.getRightOp();
                    retVal.add(pr.getIndex(), (Local) is.getLeftOp());
                }
            }
        }

        if (retVal.size() != numParams)
        {
            throw new RuntimeException("couldn't find parameterref! in " + sm);
        }
        else
        {
            return retVal;
        }
    }


    private static void addClassVariablesToAllCompromisedVertexNamesFirstTimeOnly(SootClass sc, SootMethod sm, String className, Set<VertexValue> vertexValues,
                                                                                  SecretVerticesWrapper secretVerticesWrapper)
    {
        if (className.equals(methodConfig.className) && sm.getSignature().getName().equals(methodConfig.methodName))
        {
            Set<String> calledFunctionSecretVertices = new LinkedHashSet<>();
            LinkedList<String> newTaintedVariables = new LinkedList<>();
            LinkedList<String> taintedLocals = new LinkedList<>();
            for (String variable : TAINTED_VARIABLES)
            {
                newTaintedVariables.add(variable.replace("$", ""));
            }
            for (String variable : TAINTED_CLASS_VARIABLES)
            {
                newTaintedVariables.add(variable.replace("$", ""));
            }
            for (String variable : TAINTED_LOCAL_VARIABLES)
            {
                taintedLocals.add(variable.replace("$", ""));
            }
            //javaProject.getClass(sc.getSuperclass().get()).get().getFields()
            for (Object sf : sc.getFields())
            {
                if (newTaintedVariables.contains(((SootField) sf).getName()))
                {
                    ClassVariable classVariable = new ClassVariable(className, ((SootField) sf).getName());
                    String classVariableString = classVariable.toString();
                    vertexValues.add(new VertexValue(classVariableString));
                    calledFunctionSecretVertices.add(((SootField) sf).getName());
                }
            }
            if (sc.hasSuperclass() && !sc.getSuperclass().get().toString().contains("java.lang.Object"))
            {
                for (Object sf : javaProject.getClass(sc.getSuperclass().get()).get().getFields())
                {
                    if (newTaintedVariables.contains(((SootField) sf).getName()))
                    {
                        ClassVariable classVariable = new ClassVariable(className, ((SootField) sf).getName());
                        String classVariableString = classVariable.toString();
                        vertexValues.add(new VertexValue(classVariableString));
                        calledFunctionSecretVertices.add(((SootField) sf).getName());
                    }
                }
            }
            Body body = sm.getBody();
            for (Local local : body.getLocals())
            {
                if (local.getName().equals("E#1"))
                {
                    System.out.println("debug");
                }
                String localName = local.getName();
                String prefix = localName.split("#")[0];
                if (taintedLocals.contains(prefix))
                {
                    vertexValues.add(new VertexValue(local.getName()));
                    calledFunctionSecretVertices.add(local.getName());
                }
            }
            secretVerticesWrapper.addCalledFunctionSecretVerticesToTop(calledFunctionSecretVertices);
        }


        else
        {
            Set<String> calledFunctionSecretVertices = new LinkedHashSet<>();
            LinkedList<String> newTaintedVariables = new LinkedList<>();
            for (String variable : TAINTED_VARIABLES)
            {
                newTaintedVariables.add(variable.replace("$", ""));
            }
            for (Object sf : sc.getFields())
            {
                if (newTaintedVariables.contains(((SootField) sf).getName()))
                {
                    ClassVariable classVariable = new ClassVariable(className, ((SootField) sf).getName());
                    String classVariableString = classVariable.toString();
                    vertexValues.add(new VertexValue(classVariableString));
                    calledFunctionSecretVertices.add(((SootField) sf).getName());
                }
            }
            if (sc.hasSuperclass() && !sc.getSuperclass().get().toString().contains("java.lang.Object") && javaProject.getClass(sc.getSuperclass().get()).isPresent())
            {
                for (Object sf : javaProject.getClass(sc.getSuperclass().get()).get().getFields())
                {
                    if (newTaintedVariables.contains(((SootField) sf).getName()))
                    {
                        ClassVariable classVariable = new ClassVariable(className, ((SootField) sf).getName());
                        String classVariableString = classVariable.toString();
                        vertexValues.add(new VertexValue(classVariableString));
                        calledFunctionSecretVertices.add(((SootField) sf).getName());
                    }
                }
            }
            //secretVerticesWrapper.addCalledFunctionSecretVerticesToTop(calledFunctionSecretVertices);
        }


    }

   /*
    }*/

    /*
    }*/
    private static void loadInputSourceMapToTrieAtRoot(Trie root, Set<String> keySet)
    {
        for (String key : keySet)
        {
            root.insert(key);
        }
    }
    /*
     */

    private static void createVertices(Body body, SootClass sc, SootMethod sm, String className, Set<VertexValue> vertices, SecretVerticesWrapper secretVerticesWrapper)
    {
        // adding tainted classes variables defined in taint config.json to vertices. so that it can help in adding fields to allCompromisedVertexNames in function findcompromiseddefboxes
        addClassVariablesToAllCompromisedVertexNamesFirstTimeOnly(sc, sm, className, vertices, secretVerticesWrapper);

        for (Local local : body.getLocals())
        {
            String vertexName = local.getName();
            try
            {
                try
                {
                    if (vertexName.equals(body.getThisLocal().getName()))
                    {
                        continue;
                    }
                }
                catch (RuntimeException runtimeException)
                {
                    // System.out.println("body doesn't have this local variables ignore the exception");
                }
                if (vertexName.contains("$"))
                {
                    vertexName = removeDollar(vertexName);
                }

                //  if (!vertexName.startsWith("$stack")) {
                vertices.add(new VertexValue(vertexName));
                //}
            }
            catch (RuntimeException runtimeException)
            {
                System.out.println();
            }
        }
    }

   /*
    }*/

    private static void parseTaintConfig()
    {
        try
        {
            File root = new File(CONFIG_DIRECTORY);
            File[] files = root.listFiles();
            for (File file : files)
            {
                if (file.getName().equals("TaintConfig.json"))
                {
                    String jsonString = new String(Files.readAllBytes(Paths.get(file.getAbsolutePath())));
                    JsonElement jsonElement = JsonParser.parseString(jsonString);
                    TAINT_CONFIG = new Gson().fromJson(jsonElement.getAsJsonObject(), TaintConfig.class);
                    break;
                }
            }
        }
        catch (Exception ex)
        {
            ex.printStackTrace();
        }

    }

    private static void parseAbstractConfig()
    {
        try
        {
            File root = new File(CONFIG_DIRECTORY);
            File[] files = root.listFiles();
            for (File file : files)
            {
                if (file.getName().equals("AbstractConfig.json"))
                {
                    String jsonString = new String(Files.readAllBytes(Paths.get(file.getAbsolutePath())));
                    JsonElement jsonElement = JsonParser.parseString(jsonString);
                    ABSTRACT_CONFIG = new Gson().fromJson(jsonElement.getAsJsonObject(), AbstractConfig.class);
                    break;
                }
            }
        }
        catch (Exception ex)
        {
            ex.printStackTrace();
        }
    }


    private static void parseJdkClassTaintConfig()
    {
        try
        {
            File root = new File(CONFIG_DIRECTORY);
            File[] files = root.listFiles();
            for (File file : files)
            {
                if (file.getName().equals("JdkClassTaintConfig.json"))
                {
                    String jsonString = new String(Files.readAllBytes(Paths.get(file.getAbsolutePath())));
                    JsonElement jsonElement = JsonParser.parseString(jsonString);
                    JDK_CLASS_TAINT_CONFIG = new Gson().fromJson(jsonElement.getAsJsonObject(), JdkClassTaintConfig.class);
                    break;
                }
            }
        }
        catch (Exception ex)
        {
            ex.printStackTrace();
        }
    }

    private static void setTaintConfig(Body body, SootMethod sm, Map<String, Type> inputSourceMap, List<String> allSources)
    {
        if (TAINT_CONFIG != null)
        {
            if (!TAINT_CONFIG.isInteractiveMode())
            {
                PROMPT_REQUIRED = false;
            }
            for (String taintVariable : TAINT_CONFIG.getTaintedVariables())
            {
                TAINTED_VARIABLES.add(taintVariable);
            }
            for (String untaintVariable : TAINT_CONFIG.getUntaintedVariables())
            {
                UNTAINTED_VARIABLES.add(untaintVariable);
            }
            for (String taintedClassVariable : TAINT_CONFIG.getTaintedClassVariables())
            {
                TAINTED_CLASS_VARIABLES.add(taintedClassVariable);
            }
            for (String taintedLocalVariable : TAINT_CONFIG.getTaintedLocalVariables())
            {
                TAINTED_LOCAL_VARIABLES.add(taintedLocalVariable);
            }

            setInputSourceMapAndAllSources(body, sm, inputSourceMap, allSources);
        }
    }

    private static void setInputSourceMapAndAllSources(Body body, SootMethod sm, Map<String, Type> inputSourceMap, List<String> allSources)
    {
        for (Local l : getParameterLocals(sm))
        {
            String name = removeDollar(l.getName());
            if (TAINT_CONFIG.getSecretVariables().contains(name) || TAINTED_VARIABLES.contains(name))
            {
                if (!UNTAINTED_VARIABLES.contains(name))
                {
                    inputSourceMap.put(name, l.getType());
                    allSources.add(l.getName());
                }
            }
        }
    }

    private static void forceTaintedVariables(Scanner scanner)
    {
        scanner = new Scanner(System.in);
        System.out.println("Enter the variables , Kindly follow the syntax as described here: a,b,c,d where a,b,c & d are the added tainted variables");
        String taintedVariables = scanner.nextLine();
        System.out.println("Enter the variables , Kindly follow the syntax as described here: a,b,c,d where a,b,c & d are the added forced untainted variables");
        String untaintedVariables = scanner.nextLine();
        String taintedArray[] = taintedVariables.split(",");
        String untaintedArray[] = untaintedVariables.split(",");
        for (String taintVariable : taintedArray)
        {
            TAINTED_VARIABLES.add(taintVariable);
        }
        for (String untaintVariable : untaintedArray)
        {
            UNTAINTED_VARIABLES.add(untaintVariable);
        }
        System.out.println(taintedVariables);
        System.out.println(untaintedVariables);
    }

    private static void updateMappingOfStackVariables(Stmt stmt, Map<String, List<String>> mappingOfStackVariables, Set<VertexValue> allCompromisedVertexNames, Map<String, String> PrimitiveDataTypeVariableSet)
    {

        // Debugging statements need to be removed.
        if (stmt.toString().equals("$stack9 = lengthof A") || stmt.toString().equals("$stack35 = $stack34[i]")
                || stmt.toString().equals("$stack51 -> $r7.<org.bouncycastle.pqc.crypto.rainbow.RainbowSigner: org.bouncycastle.pqc.crypto.rainbow.RainbowKeyParameters key>")
                || stmt.toString().equals("$stack63 = virtualinvoke $stack62.<org.bouncycastle.pqc.crypto.rainbow.RainbowParameters: org.bouncycastle.crypto.Digest getHash_algo()>()"))
        {
            System.out.println("debug");
        }

        if (stmt instanceof JIdentityStmt)
        {
            System.out.println("stmt_debug" + stmt);
            return;
        }

        // identity statement not passed stmt - $stack43 := @caughtexception
        if (stmt.toString().contains("caughtexception"))
        {
            return;
        }


        // interface invoke is skipped. "interfaceinvoke $stack36.<org.bouncycastle.crypto.Digest: void update(byte[],int,int)>(message, 0, $stack35)"
        if (stmt.toString().contains("$stack") && !stmt.getDef().isEmpty())
        {
            String leftVariable = ((JAssignStmt) stmt).getLeftOp().getUses().toList().isEmpty() ?
                    ((JAssignStmt) stmt).getLeftOp().toString() :
                    ((JAssignStmt) stmt).getLeftOp().getUses().findFirst().get().toString();
            if (PrimitiveDataTypeVariableSet.containsKey(leftVariable))
            {
                return;
            }
            //*  stmt.getDefBoxes().get(0).getValue().getUseBoxes().isEmpty()
            //? stmt.getDefBoxes().get(0).getValue().toString() :stmt.getDefs().get(0).getValue().getUseBoxes().get(0).getValue().toString();*//*
            //*String rightVariable =((JAssignStmt) stmt).getRightOp().getUseBoxes().isEmpty()  ?
            //    ((JAssignStmt) stmt).getRightOp().toString() : getTaintedVariable(stmt, allCompromisedVertexNames);*//*
            // the above tstament was induced during trigger annotation mapping but it was
            // chnaged bcoz of the eror in analysis of bouncy castle GemsEngine class
            // sign_pierstn fn..
            if (((JAssignStmt) stmt).getRightOp().getUses().toList().isEmpty())
            {
                System.out.println("debug");
            }

            //String rightVariable = ((JAssignStmt) stmt).getRightOp().getUseBoxes().isEmpty() ?
            //((JAssignStmt) stmt).getRightOp().toString() : ((JAssignStmt) stmt).getRightOp().getUseBoxes().get(0).getValue().toString();
            //((JAssignStmt) stmt).getRightOp().getUseBoxes().size() == 2 && ((JAssignStmt) stmt).getRightOp() instanceof JArrayRef
            List<String> rightVariables = new ArrayList<>();
            if (((JAssignStmt) stmt).getRightOp().getUses().toList().isEmpty() && !((JAssignStmt) stmt).getRightOp().toString().startsWith("new"))
            {
                rightVariables.add(((JAssignStmt) stmt).getRightOp().toString());
            }
            else if (((JAssignStmt) stmt).getRightOp().getUses().count() == 2 && ((JAssignStmt) stmt).getRightOp() instanceof JArrayRef)
            {
                rightVariables.add(((JAssignStmt) stmt).getRightOp().getUses().findFirst().get().toString());
            }
            else
            {
                for (Value box : ((JAssignStmt) stmt).getRightOp().getUses().toList())
                {
                    //((JAssignStmt) stmt).getRightOp() instanceof JInstanceFieldRef
                    //((JInstanceFieldRef) ((JAssignStmt) stmt).getRightOp()).getFieldSignature().subSignature.name
                    if (!box.toString().equals("this") && !PrimitiveDataTypeVariableSet.containsKey(box.toString()))
                    {
                        rightVariables.add(box.toString());
                    }
                }
            }
            // ((JSpecialInvokeExpr) stmt.getInvokeExprBox().getValue()).getBaseBox().getValue()
            if (stmt.containsInvokeExpr())
            {
                if (stmt.getInvokeExpr() instanceof JVirtualInvokeExpr)
                {
                    rightVariables.clear();
                    rightVariables.add(((JVirtualInvokeExpr) stmt.getInvokeExpr()).getBase().toString());
                }
                else if (stmt.getInvokeExpr() instanceof JSpecialInvokeExpr)
                {
                    rightVariables.clear();
                    rightVariables.add(((JSpecialInvokeExpr) stmt.getInvokeExpr()).getBase().toString());
                }
                else if ((((JAssignStmt) stmt).getRightOp().getUses().count() > 0))
                {
                    rightVariables.add(((JAssignStmt) stmt).getRightOp().getUses().findFirst().get().toString());
                }
            }
            else if (((JAssignStmt) stmt).getRightOp().toString().contains("lengthof"))
            {
                rightVariables.clear();
                rightVariables.add(((JAssignStmt) stmt).getRightOp().toString());
            }
            // (((JAssignStmt) stmt).getRightOp().getUseBoxes()).size() > 0
            //TODO: need to find out some other way to handle such conditions.
            if (!rightVariables.isEmpty())
            {
                if (!mappingOfStackVariables.containsKey(leftVariable))
                {
                    mappingOfStackVariables.put(leftVariable, new ArrayList<>());
                }
                mappingOfStackVariables.get(leftVariable).addAll(rightVariables);
            }

            //* stmt.getUseBoxes().get(0).getValue().getUseBoxes().isEmpty()
            // ? stmt.getUseBoxes().get(0).getValue().toString() : stmt.getUseBoxes().get(0).getValue().getUseBoxes().get(0).getValue().toString();*//*
        }

    }

    public void setSootUp()
    {
        String path = OUTPUT_DIRECTORY;
        List<File> classFiles = getClassFiles(new File(path));

        for (File file : classFiles)
        {
            try
            {
                String filePath = file.getAbsolutePath();
                JavaClass cls = new ClassParser(filePath).parse();
                System.out.println(filePath + " was compiled with Java version " + cls.getMajor() + "." + cls.getMinor());
            }
            catch (IOException e)
            {
                System.out.println("Error parsing class: " + file);
                e.printStackTrace();
            }
        }
        /*AnalysisInputLocation<JavaSootClass> inputLocation = new JavaClassPathAnalysisInputLocation(path);
        JavaLanguage javaLanguage = new JavaLanguage(21);
        JavaProject javaProject = JavaProject.builder(javaLanguage).addInputLocation(inputLocation).build();

        JavaView fullView = javaProject.createFullView();
        log.info("fullView: {}", fullView);


        ClassType classType = javaProject.getIdentifierFactory().getClassType("org.bouncycastle.pqc.crypto.picnic.PicnicEngine");


        JavaSootClass javaSootClass = fullView.getClass(classType).get();
        System.out.println("SootClass: " +javaSootClass);

        // parameter type declarations
        Type intArrayType = Type.createArrayType(PrimitiveType.IntType.getInstance(), 1);
        Type byteArrayType = Type.createArrayType(PrimitiveType.ByteType.getInstance(), 1);
        PackageName signature2PackageName = new PackageName("org.bouncycastle.pqc.crypto.picnic");
        ClassType signature2Type = new JavaClassType("Signature2", signature2PackageName);

        // For primitive data type functions
        List<Type> parameterTypes = Arrays.asList(intArrayType, intArrayType,intArrayType, byteArrayType,signature2Type);

        MethodSignature methodSignature = javaProject.getIdentifierFactory().getMethodSignature(
                classType,
                JavaIdentifierFactory.getInstance().getMethodSubSignature("sign_picnic3", PrimitiveType.BooleanType.getInstance(), parameterTypes));

        SootMethod sootMethod = fullView.getMethod(methodSignature).get();

        System.out.println("Method Signature: " + sootMethod);

        // List the statements
        List<Stmt> stmts = sootMethod.getBody().getStmts();
        for (Stmt stmt : stmts) {
            System.out.println(stmt);
        }

        // Non-primitive data type handling
        classType = javaProject.getIdentifierFactory().getClassType("com.example.myapp.Tests.MyClass");
        signature2PackageName = new PackageName("org.example.TestClasses");
        signature2Type = new JavaClassType("MyClass.Signature2", signature2PackageName);
        parameterTypes = Arrays.asList(intArrayType, intArrayType, signature2Type);
        methodSignature = javaProject.getIdentifierFactory().getMethodSignature(
                classType,
                JavaIdentifierFactory.getInstance().getMethodSubSignature("sign_picnic2", PrimitiveType.BooleanType.getInstance(), parameterTypes));
        sootMethod = fullView.getMethod(methodSignature).get();
        System.out.println("Method Signature: " + sootMethod);

        // List the statements
        stmts = sootMethod.getBody().getStmts();
        for (Stmt stmt : stmts) {
            System.out.println(stmt);
        }
*/
    }

    private static List<File> getClassFiles(File dir)
    {
        if (dir.isDirectory())
        {
            return Arrays.stream(dir.listFiles())
                    .flatMap(file -> getClassFiles(file).stream())
                    .collect(Collectors.toList());
        }
        else
        {
            return dir.getName().endsWith(".class") ? Arrays.asList(dir) : Arrays.asList();
        }
    }

    static class Result
    {
        String value;
        Stmt stmt;
        boolean isIfStmt;
        int lineNumber;

        boolean isArray;

        boolean isMulDiv;

        boolean isVul_Lib;

        ArrayTaintedVariable arrayTaintedVariable;

        private String variableChaining;

        public Result(int lineNumber, String value, Stmt stmt, boolean isIfStmt, String variableChaining)
        {
            this.value = value;
            this.stmt = stmt;
            this.isIfStmt = isIfStmt;
            this.lineNumber = lineNumber;
            this.variableChaining = variableChaining;
        }

        public Result(int lineNumber, String value, Stmt stmt, boolean isIfStmt, String variableChaining, boolean isMulDiv, boolean isVul_Lib)
        {
            this.value = value;
            this.stmt = stmt;
            this.isIfStmt = isIfStmt;
            this.lineNumber = lineNumber;
            this.variableChaining = variableChaining;
            this.isMulDiv = isMulDiv;
            this.isVul_Lib = isVul_Lib;
        }

        public Result(int lineNumber, String value, Stmt stmt, boolean isIfStmt, String variableChaining, boolean isArray, ArrayTaintedVariable arrayTaintedVariable)
        {
            this.value = value;
            this.stmt = stmt;
            this.isIfStmt = isIfStmt;
            this.lineNumber = lineNumber;
            this.variableChaining = variableChaining;
            this.isArray = isArray;
            this.arrayTaintedVariable = arrayTaintedVariable;
        }

        @Override
        public boolean equals(Object o)
        {
            if (this == o) return true;
            if (!(o instanceof Result)) return false;
            Result result = (Result) o;
            return isIfStmt == result.isIfStmt && lineNumber == result.lineNumber && isArray == result.isArray && isMulDiv == result.isMulDiv && Objects.equals(value, result.value) && Objects.equals(stmt, result.stmt) && Objects.equals(arrayTaintedVariable, result.arrayTaintedVariable) && Objects.equals(variableChaining, result.variableChaining);
        }

        @Override
        public int hashCode()
        {
            return Objects.hash(value, stmt, isIfStmt, lineNumber, isArray, isMulDiv, arrayTaintedVariable, variableChaining);
        }

        @Override
        public String toString()
        {
            return "Result{" +
                    "value='" + value + '\'' +
                    ", stmt=" + stmt +
                    ", isIfStmt=" + isIfStmt +
                    ", lineNumber=" + lineNumber +
                    ", isArray=" + isArray +
                    ", isMulDiv=" + isMulDiv +
                    ", arrayTaintedVariable=" + arrayTaintedVariable +
                    ", variableChaining='" + variableChaining + '\'' +
                    '}';
        }
    }

}
