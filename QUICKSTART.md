# Quickstart

```bash
mvn -q -DskipTests package
java -jar target/RobustaPlus-1.0-SNAPSHOT-shaded.jar -cli -o target/test-classes -j demo/config/methodConfig.toy.json
```

Notes:
- The tool analyzes compiled bytecode, not source.
- Results are written to `demo/output` by default.
