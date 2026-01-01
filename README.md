# RobustaPlus (Artifact Overview)

RobustaPlus is a static analysis tool that inspects compiled Java bytecode to report constant-time and information-leak issues. It analyzes compiled artifacts (`.class` files), not source code, and relies on a config file to identify the analysis entry point and initial taint state.

## Prerequisites
- Java 21+ available on PATH
- Maven build (tested with IntelliJ IDEA)
- External dependencies (including SootUp) are prepackaged in lib folder
- Logging note: SLF4J may warn about a missing provider; this is harmless

## Project Structure
- Entry point: `src/main/java/org/example/HelloSootup.java`
- Default config: `src/main/resources/config/methodConfig.json`
- Output folder (default): `demo/output`

## Configuration: methodConfig.json
Key fields:
- `className`: fully qualified class name
- `methodName`: entry method name
- `parameters`: parameter types
- `returnType`: return type

Taint keys:
- `tainted_variables`, `untainted_variables`, `secret_variables`
- `tainted_local_variables`, `tainted_class_variables`
- `fullyQualifiedMethods` can list known leaky library methods

## Run from IDE (IntelliJ)
1) Place compiled target bytecode in the expected target directory.
2) Open the Maven project in IntelliJ.
3) Run `org.example.HelloSootup`.

## Run from CLI
Flags:
```
-cli                 Enable CLI mode
-o <path>            REQUIRED. Path to compiled classes or jars
-j <path>            Optional. Path to methodConfig.json (default is embedded)
```
Example:
```bash
java -jar RobustaPlus-1.0-SNAPSHOT-shaded.jar -cli -o /path/to/target/classes -j /path/to/methodConfig.json
```
By default, outputs are written to `demo/output`.

## Outputs
Two files are produced by default: one ending with `leaks.txt` and one with `output.txt`. The `leaks.txt` file is the primary report and lists vulnerable code segments (e.g., secret-dependent control flow, memory access, arithmetic). Each entry includes Jimple IR locations and line numbers to map back to source.

## Self Check
Use `./scripts/self_check.sh` to build, run tests, and execute a local analysis against `target/test-classes`.

