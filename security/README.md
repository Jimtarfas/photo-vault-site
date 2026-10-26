# My Vault: security source

This folder publishes the parts of **My Vault: Secret Photo Locker** (iOS) that protect your files, so anyone can verify how they work. The full design is explained in plain language at https://jimtarfas.github.io/photo-vault-site/security.html.

| File | What it does |
|---|---|
| `VaultCrypto.swift` | PBKDF2-HMAC-SHA256 pattern keys (210,000 iterations), HKDF per-file keys, and chunked AES-256-GCM file encryption with authenticated chunk order |
| `VaultStorage.swift` | On-disk layout, the encrypted album/item index, and separate vault spaces (real and decoy) |
| `BiometricKeyStore.swift` | Optional Face ID unlock: Keychain item with `biometryCurrentSet` and `WhenPasscodeSetThisDeviceOnly` |
| `SensitiveScanner.swift` | On-device "Find Exposed Photos" scan using Apple Vision text recognition and rule-based classification (Luhn-checked card numbers, passport MRZ, IDs, passwords, bank details, SSNs) |

These files are copied from the app's source for each release.

Security questions or reports: nouhe.tarfas@gmail.com
