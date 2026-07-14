# Authorized Workflow

1. Confirm written authority, consent, policy basis, or legal order.
2. Enable USB debugging only when authorized.
3. Create a case:

```bash
droidforensicx init --case BN-CASE-001 --examiner "Hashcode"
```

4. Check device and acquire logical evidence:

```bash
droidforensicx check-device --case BN-CASE-001
droidforensicx acquire-basic --case BN-CASE-001
droidforensicx bugreport --case BN-CASE-001
```

5. Analyze:

```bash
droidforensicx app-inventory --case BN-CASE-001
droidforensicx app-lifecycle --case BN-CASE-001
droidforensicx indicators --case BN-CASE-001
droidforensicx timeline --case BN-CASE-001
```

6. Hash and report:

```bash
droidforensicx hash --case BN-CASE-001
droidforensicx report --case BN-CASE-001
```

7. After acquisition, document cleanup and revoke USB debugging if policy requires it.

