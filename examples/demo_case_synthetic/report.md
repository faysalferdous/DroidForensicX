# DroidForensicX Forensic Triage Report

Case: `DEMO-ANDROID-FORENSIC`
Tool version: `0.1.0`

## 1. Executive Summary

This case was processed with DroidForensicX for authorized Android logical forensic triage. The workflow organizes raw evidence, hashes outputs, identifies app lifecycle traces, generates suspicious indicators, creates a unified timeline, and produces redacted professional reports.

| Metric | Value |
| --- | ---: |
| Risk level | HIGH |
| Apps parsed | 2 |
| Uninstalled app leads | 1 |
| Suspicious indicators | 6 |
| Risky permissions | 6 |
| Credential rows, redacted | 3 |
| Timeline events | 9 |
| Hashed files | 48 |

## 2. Authorization Note

This framework is for authorized DFIR, SOC, incident response, and defence investigation use only. It does not exploit, root, bypass, dump, decrypt, or steal passwords.

## 3. Device Identity

- `ro.build.fingerprint`: `google/demo/demo:16/SYNTHETIC:user/release-keys`
- `ro.build.version.release`: `16`
- `ro.product.manufacturer`: `Google`
- `ro.product.model`: `Pixel Synthetic Demo`

## 4. Acquisition Method

Logical ADB-safe collection and lawful imported artifacts. Destructive commands are not used. Logs are not cleared. Device settings are not changed.

## 5. Tool Versions

- `adb`: missing 
- `androidqf`: missing 
- `mvt-android`: missing 
- `aleapp`: missing 
- `exiftool`: available /bin/exiftool
- `mediainfo`: missing 
- `photorec`: missing 
- `testdisk`: missing 
- `hashdeep`: available /bin/hashdeep

## 6. Evidence Integrity

Hashed files: 48

## 7. Installed Apps

- `com.android.chrome` installer=`com.android.vending` version=`126.0`
- `com.fake.calculator.vault` installer=`unknown.installer` version=`2.4`

## 8. Uninstalled App Traces

Android does not guarantee permanent uninstall history. Confidence levels reflect trace strength.

- `com.shortlived.proxy` — `CONFIRMED_UNINSTALLED_TRACE` — pm list packages -u trace

## 9. Risky Permissions

- `com.android.chrome` requested `android.permission.CAMERA`
- `com.android.chrome` requested `android.permission.ACCESS_FINE_LOCATION`
- `com.fake.calculator.vault` requested `android.permission.READ_SMS`
- `com.fake.calculator.vault` requested `android.permission.READ_CONTACTS`
- `com.fake.calculator.vault` requested `android.permission.SYSTEM_ALERT_WINDOW`
- `com.fake.calculator.vault` requested `android.permission.CAMERA`

## 10. Suspicious Indicators

- **HIGH** `ADB over TCP indicator`: settings_global contains adb tcp references (score 30)
- **MEDIUM** `Developer options or ADB enabled`: settings indicate development/ADB enabled (score 15)
- **MEDIUM** `Unknown/non-store installer`: com.fake.calculator.vault installer=unknown.installer (score 10)
- **MEDIUM** `Suspicious app naming keyword`: com.fake.calculator.vault (score 10)
- **MEDIUM** `Multiple dangerous permissions`: com.fake.calculator.vault dangerous_permissions=4 (score 12)
- **LOW** `Recently installed/removed app trace candidate`: com.shortlived.proxy CONFIRMED_UNINSTALLED_TRACE (score 5)

## 11. User Goal / Intent Analysis

Goal indicators are conservative and are based only on lawful imports and visible artifact names. They are leads, not conclusions.

## 12. Browser/Web Artifacts

Browser and web artifacts are included only when lawfully imported or visible from logical shared storage outputs.

## 13. Credential Evidence, Redacted

DroidForensicX does not extract, decrypt, dump, or bypass passwords. It only imports lawfully provided credential exports and redacts secrets by default.

Credential records imported: 3

- `mail.example.test` user=`analyst@example.test` password=`********`
- `cloud.example.test` user=`analyst@example.test` password=`********`
- `bank.example.test` user=`user@example.test` password=`********`

## 14. Social Media Imported Artifacts

Social artifact files: 1. Private app database bypass was not performed.

## 15. Media Findings

Media files indexed: 2

## 16. Deleted Media / External SD Notes

No-root logical triage cannot guarantee recovery of deleted internal Android files. External SD or shared storage recovery requires lawful access and separate specialist workflow.

## 17. Timeline

- `` **credentials_import** credential_domain_present mail.example.test
- `` **credentials_import** credential_domain_present cloud.example.test
- `` **credentials_import** credential_domain_present bank.example.test
- `07-12 10:22:01.123` **app_lifecycle** PACKAGE_REMOVED com.shortlived.proxy
- `12/07/2026, 10:01` **social** chat_message 
- `12/07/2026, 10:05` **social** chat_message 
- `1784022041` **media** file_mtime cases/DEMO-ANDROID-FORENSIC/07_media/synthetic_shared_storage/Download suspicious-vault.apk
- `1784022041` **media** file_mtime cases/DEMO-ANDROID-FORENSIC/07_media/synthetic_shared_storage/Documents case-notes.txt
- `2026-07-12T10:20:00Z` **app_lifecycle** lastTimeUsed com.shortlived.proxy

## 18. Limitations

- DroidForensicX performs authorized logical triage only and does not bypass Android security controls.
- No-root ADB cannot access most app-private databases or guarantee complete deleted-file recovery.
- Android does not guarantee a permanent uninstall history; uninstalled app results are confidence-scored traces.
- Credential handling imports lawful official exports only and redacts password values by default.
- Absence of evidence in this report is not evidence of absence.

## 19. Hash Appendix

```text
e1ac3cd26f7f65e9745b120adf68902788de2c8abd0e0024aa4ea8f229054291  00_case/case_manifest.json
bd1443e84ad2c7bde6bd622e40a547e41bef84696a7c5f15c5c0ec12b9b46e22  00_case/case_notes.md
70232e7063ad4459da3a561573f2c12e19494a1dfd7b1c2802359e496ae3a177  00_case/chain_of_custody.md
29405fc188dcd461f614bbd46630a73f8f59d93ad1c9aa0bcc02636854e94fe4  00_case/tool_versions.txt
58fbe6ce8e9709b12005c86b1a3e242b2c0792782106b6125c7bc0a6f01a7914  01_raw_adb/device_identity.json
9cb8e23528fa1b3f1b9e4a7b52273c1b091a70003f1dc39bd75ceda92b7fa8b8  01_raw_adb/dumpsys_package.txt
8b33ad415f7497f4cd0476094f45b1f9cac0152ca1df9ecc57713933c8635b41  01_raw_adb/dumpsys_usagestats.txt
25957634348896951832c1e620f33c0058b213862393c7ac3c4ea222d90bc7d1  01_raw_adb/logcat_d.txt
df9430e76d4fbdc38b41952e3212bacf1bbf67af60bbeb24527e6f3db98caecb  01_raw_adb/pm_list_packages.txt
4781188be2e7c0c9d22a4e0d40a52572d256e7d94884d92f333af6f7ca4e2c5c  01_raw_adb/pm_list_packages_u.txt
f300285d0e8672f9b2169aa886119f88be23a02f4f70d7a7ec8118d92eb69371  01_raw_adb/settings_global.txt
962315ccb80241b2a79344f49c6eac45640274760d0bfe01b1ae5c549e38623c  01_raw_adb/settings_secure.txt
9143c9f868fcb60d1bbe66e0703c6bda7971e5279ddb12e0126628915489db6b  06_apps/apps_current.csv
820948edc0a2e9987b2678bd5f5965cd9a3cb31c178aee78737d7e6f2bd629bd  06_apps/apps_dangerous_permissions.csv
54191407bfd537e6a5e9f0fba713b69074553642e42570290eb76efa95741c0c  06_apps/apps_lifecycle.csv
d6f960fb7ced3ab7f1c9dd9b283e977021fbc0130780af83ba03fffa379f96da  06_apps/apps_lifecycle_summary.json
93638cc7ca9cfd3b759553ed866417c1ea75732d5c1245cbdd7d5305ec83b096  06_apps/apps_lifecycle_timeline.csv
820948edc0a2e9987b2678bd5f5965cd9a3cb31c178aee78737d7e6f2bd629bd  06_apps/apps_permissions.csv
86506e35c73d9da95e175cd9e487a2dec9b620ceeae9f0c54d16d12d72f26e46  06_apps/apps_summary.json
82d5ab44b5b822026859d5eb7d85f4beea2f04fb9149affe14e26c60250616da  06_apps/apps_uninstalled_candidates.csv
450fe30f32bc116ec9c6792ce33e672fe3889bd1f3c39825f60c645487303a3d  07_media/media_duplicates.csv
77bcbb8ec42d5a1441365d49198807ffe6c870b9059045139fd04e43af2dda9c  07_media/media_exif.csv
13cf2c90a767e1e63684b1a8fbb5badd2e00c8223b9d0e0c536251cfb3913d0e  07_media/media_index.csv
18a95239eff255e0204701fea299a2e22db6d5c4a2c49c684d1719deb8c8059d  07_media/media_summary.json
35f049962adb181f8ff067716a384a8bd9b494c571563c8d2f8b37aecab4cbc9  07_media/media_timeline.csv
81ad8f7dcb6b51301bc327285b5edd484c9c05d2e1c0cabd17ba845f4a9c9a39  07_media/synthetic_shared_storage/Documents case-notes.txt
8542ca4bb3af25f89e5f3fa4bee8ee7e9a2a17aa5796518a85cda2fafcd38ee3  07_media/synthetic_shared_storage/Download suspicious-vault.apk
08676cc19ea1fc56dd414ab1cdbc930ca068a7b2eaeebe4cbbd4b2a34635d6b5  08_credentials_sensitive/synthetic_credentials.csv
0c1c69f78ca4eab582727fef8ce665628dfa78d5334221eed438347737c6d7cf  09_credentials_redacted/credential_domains.csv
48dc21e54d4779b35be2f0a91abbd994baba6d13a3894637812f5b082a6fc20b  09_credentials_redacted/credential_goal_indicators.csv
893d5fe31d6892407ef3f82312f1dbaab9cb1c1d0b1452d683c827e1443db060  09_credentials_redacted/credential_reuse_groups.csv
c01362ba45afec65344a045d54d3351beaf79169a9640432365e8801c8569e75  09_credentials_redacted/credential_risk_summary.json
812bf6b6f0be7dabfb96c1f804c39f42e60f85c4a6c8af598d4bc76478fadaf9  09_credentials_redacted/credential_sensitive_domains.csv
e82b62fcc391b06bdb4518b57341a57bdf2df228aafab320d74eae80b99194b7  09_credentials_redacted/credential_usernames.csv
8d58f5f2e51b44fdff763eeca6267f3c217d0865883b982b17117ea891a1bb2f  09_credentials_redacted/credential_weak_password_indicators.csv
a3e953bb3a014656dfcaf434d301ce9fe1050ab126e2cdfe994572605baf4472  09_credentials_redacted/credentials_redacted.csv
135b4bc2121216f0cc9ca873136ee8a052585c0443ad3aafe01279a2ddd09044  10_social_imports/chat_timeline.csv
aca0bb28682cd10658d84706a922f3ec1f73b93cb0edaa0bbc27ccd9216c1b56  10_social_imports/contacts_mentions.csv
e4f196112b17b35152fc9115411f436746a6f4e52b927a2844ba870a355d07bc  10_social_imports/social_import_index.csv
4af7486d98571cb07df4a5960fe4a4f72f84d42dfffe01cb38d727098d69343c  10_social_imports/social_report.json
882bfb2bb13101cc128af6f49e2676400aa51b9a61fa6b7e8ebcdefcaeb2ab58  10_social_imports/synthetic_whatsapp_export.txt
99bc87b43071e5f271922082e462269a1d6eb296149749add5f0fcb6808158d4  11_indicators/app_risk_score.json
113fd2a8f76496943203ed2c3a5555d0f871a09c5e9bc7119157781a1f0177a4  11_indicators/risk_summary.json
e09ebfd19ab4e3e08b8c7713ad3060a3a939d1887d28b5b22c959c63b5d608ed  11_indicators/suspicious_indicators.csv
bd2bf16d77c434bca1c923ba59dc1e8b867bed343ed9b06767012edfb11b74aa  12_timeline/timeline.csv
edb0dff2dafc9735d901c89d8f96194f6c75e09c06bd4a17e5bc43d6f08e9ebc  12_timeline/timeline.html
b292ef8e2f93963b2534589c11fcd5bdfddd749199c30e9e0a6e7e7358143d15  12_timeline/timeline.md
ade54b69fbd2d1a14f8739710ede75e1b58b87b9908282d18e15e461244d6072  12_timeline/timeline_summary.json

```