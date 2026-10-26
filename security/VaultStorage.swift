import Foundation
import CryptoKit

/// The independent vaults the app can hold. Each one has its own pattern, master key and files.
enum VaultSpace: String, CaseIterable {
    case primary = "Vault"
    /// Opened by a second pattern, for when someone forces the owner to unlock the app.
    case decoy = "Decoy"
}

/// On-disk layout, per vault space under Application Support/<space>:
/// `vault.json` (salt + wrapped key), `index.enc` (albums and items), `files/` and `thumbs/` (encrypted media).
/// Decrypted copies for playback or sharing live in tmp and are wiped on every lock.
enum VaultStorage {
    private static let fileManager = FileManager.default
    private static let indexAAD = Data("MyVault.index.v1".utf8)

    /// The space that is unlocked right now. Reset to `.primary` on every lock.
    static var activeSpace: VaultSpace = .primary

    static func root(_ space: VaultSpace = activeSpace) -> URL {
        fileManager.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent(space.rawValue, isDirectory: true)
    }
    static func configURL(_ space: VaultSpace = activeSpace) -> URL { root(space).appendingPathComponent("vault.json") }
    static func indexURL(_ space: VaultSpace = activeSpace) -> URL { root(space).appendingPathComponent("index.enc") }
    static func filesDirectory(_ space: VaultSpace = activeSpace) -> URL { root(space).appendingPathComponent("files", isDirectory: true) }
    static func thumbnailsDirectory(_ space: VaultSpace = activeSpace) -> URL { root(space).appendingPathComponent("thumbs", isDirectory: true) }
    static var temporaryDirectory: URL {
        fileManager.temporaryDirectory.appendingPathComponent("vault-temp", isDirectory: true)
    }
    static var stagingDirectory: URL { temporaryDirectory.appendingPathComponent("staging", isDirectory: true) }
    static var exportDirectory: URL { temporaryDirectory.appendingPathComponent("export", isDirectory: true) }

    static func exists(_ space: VaultSpace) -> Bool { fileManager.fileExists(atPath: configURL(space).path) }
    static var hasVault: Bool { exists(.primary) }

    static func prepareDirectories(_ space: VaultSpace = activeSpace) throws {
        for directory in [root(space), filesDirectory(space), thumbnailsDirectory(space), stagingDirectory, exportDirectory] {
            try fileManager.createDirectory(at: directory, withIntermediateDirectories: true)
        }
    }

    static func fileURL(for id: UUID, in space: VaultSpace = activeSpace) -> URL {
        filesDirectory(space).appendingPathComponent(id.uuidString + ".enc")
    }

    static func thumbnailURL(for id: UUID, in space: VaultSpace = activeSpace) -> URL {
        thumbnailsDirectory(space).appendingPathComponent(id.uuidString + ".enc")
    }

    static func newStagingURL(pathExtension: String) throws -> URL {
        try fileManager.createDirectory(at: stagingDirectory, withIntermediateDirectories: true)
        let url = stagingDirectory.appendingPathComponent(UUID().uuidString)
        return pathExtension.isEmpty ? url : url.appendingPathExtension(pathExtension)
    }

    // MARK: Config and index

    static func readConfig(_ space: VaultSpace = activeSpace) throws -> VaultConfig {
        try JSONDecoder().decode(VaultConfig.self, from: Data(contentsOf: configURL(space)))
    }

    static func writeConfig(_ config: VaultConfig, in space: VaultSpace = activeSpace) throws {
        try JSONEncoder().encode(config).write(to: configURL(space), options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
    }

    static func readIndex(master: SymmetricKey, in space: VaultSpace = activeSpace) throws -> VaultIndex {
        let sealed = try Data(contentsOf: indexURL(space))
        let plain = try VaultCrypto.open(sealed, key: VaultCrypto.subkey(master, purpose: "index"), aad: indexAAD)
        return try JSONDecoder().decode(VaultIndex.self, from: plain)
    }

    static func writeIndex(_ index: VaultIndex, master: SymmetricKey, in space: VaultSpace = activeSpace) throws {
        let plain = try JSONEncoder().encode(index)
        let sealed = try VaultCrypto.seal(plain, key: VaultCrypto.subkey(master, purpose: "index"), aad: indexAAD)
        try sealed.write(to: indexURL(space), options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
    }

    // MARK: Cleanup

    static func removeFiles(for id: UUID, in space: VaultSpace = activeSpace) {
        try? fileManager.removeItem(at: fileURL(for: id, in: space))
        try? fileManager.removeItem(at: thumbnailURL(for: id, in: space))
    }

    /// Deletes encrypted files that no index entry points to, e.g. from an import cut short by locking.
    static func removeOrphans(keeping ids: Set<UUID>, in space: VaultSpace) {
        for directory in [filesDirectory(space), thumbnailsDirectory(space)] {
            let names = (try? fileManager.contentsOfDirectory(atPath: directory.path)) ?? []
            for name in names {
                let stem = (name as NSString).deletingPathExtension
                if let id = UUID(uuidString: stem), !ids.contains(id) {
                    try? fileManager.removeItem(at: directory.appendingPathComponent(name))
                }
            }
        }
    }

    static func clearTemporaryFiles() {
        try? fileManager.removeItem(at: temporaryDirectory)
    }

    static func erase(_ space: VaultSpace) {
        try? fileManager.removeItem(at: root(space))
    }

    static func eraseEverything() {
        VaultSpace.allCases.forEach(erase)
        clearTemporaryFiles()
    }
}
