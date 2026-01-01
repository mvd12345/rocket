# Reproduce the Artifact

## Prerequisites
- Java 21+ on PATH
- Maven 3.8+

## Build the Artifact
1) Build the shaded JAR (no tests):
   ```bash
   mvn -q -DskipTests package
   ```
2) Run the test suite:
   ```bash
   mvn -q test
   ```

## Run the CLI Tool
The tool analyzes compiled bytecode (`.class` or `.jar`), not source.

```bash
java -jar target/RobustaPlus-1.0-SNAPSHOT-shaded.jar \
  -cli \
  -o /path/to/compiled/classes-or-jars \
  -j /path/to/methodConfig.json
```

- `-o` must point to compiled classes (e.g., `target/test-classes`) or a directory of JARs.
- `-j` is optional; if omitted, the default config in `src/main/resources/config/methodConfig.json` is used.
- Output files are written to `demo/output` by default.

## Self-Check (Recommended)
Run the provided script to build, test, and execute a local analysis against `target/test-classes`:
```bash
./scripts/self_check.sh
```

This uses `demo/config/methodConfig.toy.json`, which targets a method in the local test fixtures.
