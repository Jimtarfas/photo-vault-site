import Foundation
import CryptoKit
import CommonCrypto
import Security

enum VaultCryptoError: Error {
    case keyDerivationFailed
    case invalidFormat
    case truncated
}

/// AES-256-GCM encryption for everything the vault stores.
///
/// Files are written in 1 MiB chunks so large videos never have to sit in memory:
/// `"MVE1"` then, per chunk, `[final flag: 1 byte][length: UInt32 BE][nonce | ciphertext | tag]`.
/// The chunk index and final flag are authenticated, so chunks can't be reordered or dropped.
enum VaultCrypto {
    static let defaultIterations: UInt32 = 210_000
    static let chunkSize = 1 << 20
    static let masterKeyAAD = Data("MyVault.master-key.v1".utf8)
    private static let magic = Data("MVE1".utf8)

    static func randomBytes(_ count: Int) -> Data {
        var data = Data(count: count)
        let status = data.withUnsafeMutableBytes { buffer in
            SecRandomCopyBytes(kSecRandomDefault, count, buffer.baseAddress!)
        }
        precondition(status == errSecSuccess, "Secure random generation failed")
        return data
    }

    /// PBKDF2-HMAC-SHA256. Deliberately slow; call it off the main thread.
    static func deriveKey(from secret: String, salt: Data, iterations: UInt32) throws -> SymmetricKey {
        var derived = [UInt8](repeating: 0, count: 32)
        let status = salt.withUnsafeBytes { saltBuffer in
            CCKeyDerivationPBKDF(
                CCPBKDFAlgorithm(kCCPBKDF2),
                secret, secret.utf8.count,
                saltBuffer.bindMemory(to: UInt8.self).baseAddress, salt.count,
                CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
                iterations,
                &derived, derived.count
            )
        }
        guard status == Int32(kCCSuccess) else { throw VaultCryptoError.keyDerivationFailed }
        return SymmetricKey(data: derived)
    }

    static func subkey(_ master: SymmetricKey, purpose: String) -> SymmetricKey {
        HKDF<SHA256>.deriveKey(
            inputKeyMaterial: master,
            salt: Data("MyVault.v1".utf8),
            info: Data(purpose.utf8),
            outputByteCount: 32
        )
    }

    static func fileKey(_ master: SymmetricKey, id: UUID) -> SymmetricKey {
        subkey(master, purpose: "file:\(id.uuidString)")
    }

    static func thumbnailKey(_ master: SymmetricKey, id: UUID) -> SymmetricKey {
        subkey(master, purpose: "thumbnail:\(id.uuidString)")
    }

    static func seal(_ data: Data, key: SymmetricKey, aad: Data = Data()) throws -> Data {
        guard let combined = try AES.GCM.seal(data, using: key, authenticating: aad).combined else {
            throw VaultCryptoError.invalidFormat
        }
        return combined
    }

    static func open(_ data: Data, key: SymmetricKey, aad: Data = Data()) throws -> Data {
        let box = try AES.GCM.SealedBox(combined: data)
        return try AES.GCM.open(box, using: key, authenticating: aad)
    }

    // MARK: Chunked files

    static func encryptFile(from source: URL, to destination: URL, key: SymmetricKey) throws {
        let input = try FileHandle(forReadingFrom: source)
        defer { try? input.close() }
        try writeChunks(to: destination, key: key) {
            try input.read(upToCount: chunkSize) ?? Data()
        }
    }

    static func encrypt(_ data: Data, to destination: URL, key: SymmetricKey) throws {
        var offset = 0
        try writeChunks(to: destination, key: key) {
            let end = min(offset + chunkSize, data.count)
            defer { offset = end }
            return data.subdata(in: offset..<end)
        }
    }

    static func decryptData(at source: URL, key: SymmetricKey) throws -> Data {
        var output = Data()
        try readChunks(from: source, key: key) { output.append($0) }
        return output
    }

    static func decryptFile(at source: URL, to destination: URL, key: SymmetricKey) throws {
        FileManager.default.createFile(atPath: destination.path, contents: nil)
        let handle = try FileHandle(forWritingTo: destination)
        defer { try? handle.close() }
        do {
            try readChunks(from: source, key: key) { try handle.write(contentsOf: $0) }
        } catch {
            try? FileManager.default.removeItem(at: destination)
            throw error
        }
    }

    private static func chunkAAD(index: UInt64, isFinal: Bool) -> Data {
        var bigEndianIndex = index.bigEndian
        var aad = Data(bytes: &bigEndianIndex, count: 8)
        aad.append(isFinal ? 1 : 0)
        return aad
    }

    /// `next` returns the following plaintext chunk, or empty data once the source is exhausted.
    private static func writeChunks(to destination: URL, key: SymmetricKey, next: () throws -> Data) throws {
        FileManager.default.createFile(atPath: destination.path, contents: nil)
        let output = try FileHandle(forWritingTo: destination)
        defer { try? output.close() }
        do {
            try output.write(contentsOf: magic)
            var index: UInt64 = 0
            var chunk = try next()
            while true {
                let isFinal = try autoreleasepool { () -> Bool in
                    let following = try next()
                    let isFinal = following.isEmpty
                    let sealed = try seal(chunk, key: key, aad: chunkAAD(index: index, isFinal: isFinal))
                    var header = Data([isFinal ? 1 : 0])
                    var length = UInt32(sealed.count).bigEndian
                    header.append(Data(bytes: &length, count: 4))
                    try output.write(contentsOf: header)
                    try output.write(contentsOf: sealed)
                    chunk = following
                    return isFinal
                }
                if isFinal { break }
                index += 1
            }
        } catch {
            try? output.close()
            try? FileManager.default.removeItem(at: destination)
            throw error
        }
    }

    private static func readChunks(from source: URL, key: SymmetricKey, consume: (Data) throws -> Void) throws {
        let input = try FileHandle(forReadingFrom: source)
        defer { try? input.close() }
        guard try input.read(upToCount: magic.count) == magic else { throw VaultCryptoError.invalidFormat }
        var index: UInt64 = 0
        while true {
            let isFinal = try autoreleasepool { () -> Bool in
                guard let header = try input.read(upToCount: 5), header.count == 5 else {
                    throw VaultCryptoError.truncated
                }
                let isFinal = header[header.startIndex] == 1
                let length = header.dropFirst().reduce(0) { ($0 << 8) | Int($1) }
                guard length > 0, length <= chunkSize + 64,
                      let sealed = try input.read(upToCount: length), sealed.count == length else {
                    throw VaultCryptoError.truncated
                }
                try consume(try open(sealed, key: key, aad: chunkAAD(index: index, isFinal: isFinal)))
                return isFinal
            }
            if isFinal { return }
            index += 1
        }
    }
}

extension SymmetricKey {
    var rawData: Data { withUnsafeBytes { Data($0) } }
}
