import Photos
import UIKit
import Vision

/// Kinds of personal documents the scan looks for in the photo library.
enum SensitiveKind: String, CaseIterable, Identifiable {
    case card
    case idDocument
    case passport
    case password
    case bank
    case ssn

    var id: String { rawValue }

    var title: String {
        switch self {
        case .card: return "Bank cards"
        case .idDocument: return "IDs & licenses"
        case .passport: return "Passports"
        case .password: return "Passwords & codes"
        case .bank: return "Bank details"
        case .ssn: return "Social Security numbers"
        }
    }

    var symbol: String {
        switch self {
        case .card: return "creditcard.fill"
        case .idDocument: return "person.text.rectangle.fill"
        case .passport: return "globe.europe.africa.fill"
        case .password: return "key.fill"
        case .bank: return "building.columns.fill"
        case .ssn: return "number.square.fill"
        }
    }
}

/// Decides from recognized text whether a photo shows a sensitive document.
/// Rules favour clear signals (a valid card number, MRZ lines, "password:") over single loose words.
enum SensitiveTextClassifier {
    static func classify(_ lines: [String]) -> Set<SensitiveKind> {
        let text = lines.joined(separator: "\n").uppercased()
        guard !text.isEmpty else { return [] }
        var kinds = Set<SensitiveKind>()
        if hasCardNumber(text) { kinds.insert(.card) }
        if matches(text, #"\b(PASSPORT|PASSEPORT|PASAPORTE|REISEPASS|PASSAPORTO)\b"#) || matches(text, #"P<[A-Z]{3}"#) || matches(text, #"[A-Z0-9<]{25,}<<"#) {
            kinds.insert(.passport)
        }
        if matches(text, #"DRIVER'?S? LICEN[CS]E|DRIVING LICEN[CS]E|IDENTI(TY|FICATION) CARD|NATIONAL ID|\bID CARD\b|RESIDENCE PERMIT|PERMIS DE CONDUIRE|CARTE NATIONALE|PERSONALAUSWEIS|FÜHRERSCHEIN|CARTA D'IDENTIT"#)
            || (matches(text, #"\b(DOB|DATE OF BIRTH)\b"#) && matches(text, #"\b(EXP|EXPIRES|ISS|SEX|HGT|CLASS)\b"#)) {
            kinds.insert(.idDocument)
        }
        if matches(text, #"(PASSWORD|PASSCODE|PASSWD|\bPIN\b)\s*(:|=|IS\b)|RECOVERY (CODE|KEY|PHRASE)|BACKUP CODES?|VERIFICATION CODE|SEED PHRASE|SECRET (PHRASE|KEY)|PRIVATE KEY|MOT DE PASSE|CONTRASEÑA|SENHA\s*:|PASSWORT\s*:"#) {
            kinds.insert(.password)
        }
        if matches(text, #"\bIBAN\b|ROUTING (NUMBER|NO)|ACCOUNT (NUMBER|NO)\b|SORT CODE|\bSWIFT\b|\bBIC\b"#) {
            kinds.insert(.bank)
        }
        if matches(text, #"\b\d{3}-\d{2}-\d{4}\b"#) || text.contains("SOCIAL SECURITY") {
            kinds.insert(.ssn)
        }
        return kinds
    }

    private static func matches(_ text: String, _ pattern: String) -> Bool {
        text.range(of: pattern, options: .regularExpression) != nil
    }

    /// A Luhn-valid 13–19 digit number, either grouped like a card (4-4-4-4) or next to card wording.
    private static func hasCardNumber(_ text: String) -> Bool {
        let cardWords = matches(text, #"\b(VISA|MASTERCARD|AMEX|AMERICAN EXPRESS|DISCOVER|DEBIT|CREDIT|VALID|THRU|EXPIRES|CARDHOLDER|CVV|CVC)\b"#)
        guard let regex = try? NSRegularExpression(pattern: #"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)"#) else { return false }
        let range = NSRange(text.startIndex..., in: text)
        for match in regex.matches(in: text, range: range) {
            guard let swiftRange = Range(match.range, in: text) else { continue }
            let candidate = String(text[swiftRange])
            let digits = candidate.compactMap(\.wholeNumberValue)
            guard (13...19).contains(digits.count), Set(digits).count > 1, luhn(digits) else { continue }
            let grouped = candidate.range(of: #"^\d{4}[ -]\d{4}[ -]\d{4}[ -]\d{1,4}"#, options: .regularExpression) != nil
            if grouped || cardWords { return true }
        }
        return false
    }

    static func luhn(_ digits: [Int]) -> Bool {
        var sum = 0
        for (offset, digit) in digits.reversed().enumerated() {
            if offset % 2 == 1 {
                let doubled = digit * 2
                sum += doubled > 9 ? doubled - 9 : doubled
            } else {
                sum += digit
            }
        }
        return sum % 10 == 0
    }
}

/// Scans recent library photos on-device with Vision text recognition. Nothing leaves the phone.
@MainActor
final class SensitiveScanModel: ObservableObject {
    enum State: Equatable {
        case intro
        case denied
        case scanning
        case finished
    }

    struct Finding: Identifiable {
        let asset: PHAsset
        let kinds: Set<SensitiveKind>
        var id: String { asset.localIdentifier }
    }

    static let photoLimit = 1000

    @Published private(set) var state: State = .intro
    @Published private(set) var checked = 0
    @Published private(set) var total = 0
    @Published private(set) var findings: [Finding] = []
    @Published var selected = Set<String>()
    @Published private(set) var limitedAccess = false

    private var task: Task<Void, Never>?

    func start() {
        task?.cancel()
        task = Task {
            let status = await PHPhotoLibrary.requestAuthorization(for: .readWrite)
            guard status == .authorized || status == .limited else {
                state = .denied
                return
            }
            limitedAccess = status == .limited
            let assets = Self.recentPhotos()
            total = assets.count
            checked = 0
            findings = []
            selected = []
            state = .scanning
            for asset in assets {
                if Task.isCancelled { break }
                let kinds = await Self.analyze(asset)
                checked += 1
                if !kinds.isEmpty {
                    findings.append(Finding(asset: asset, kinds: kinds))
                    selected.insert(asset.localIdentifier)
                }
            }
            state = .finished
        }
    }

    func stop() {
        task?.cancel()
    }

    var selectedAssets: [PHAsset] {
        findings.filter { selected.contains($0.id) }.map(\.asset)
    }

    private static func recentPhotos() -> [PHAsset] {
        let options = PHFetchOptions()
        options.sortDescriptors = [NSSortDescriptor(key: "creationDate", ascending: false)]
        options.predicate = NSPredicate(format: "mediaType == %d", PHAssetMediaType.image.rawValue)
        options.fetchLimit = photoLimit
        var assets: [PHAsset] = []
        PHAsset.fetchAssets(with: options).enumerateObjects { asset, _, _ in assets.append(asset) }
        return assets
    }

    private static func analyze(_ asset: PHAsset) async -> Set<SensitiveKind> {
        guard let image = await image(for: asset) else { return [] }
        return await Task.detached(priority: .userInitiated) { recognize(image) }.value
    }

    /// A local, screen-sized copy. iCloud-only originals are skipped rather than downloaded.
    private static func image(for asset: PHAsset) async -> CGImage? {
        let options = PHImageRequestOptions()
        options.isNetworkAccessAllowed = false
        options.deliveryMode = .highQualityFormat
        options.resizeMode = .fast
        return await withCheckedContinuation { continuation in
            var resumed = false
            PHImageManager.default().requestImage(
                for: asset, targetSize: CGSize(width: 1600, height: 1600), contentMode: .aspectFit, options: options
            ) { image, _ in
                guard !resumed else { return }
                resumed = true
                continuation.resume(returning: image?.cgImage)
            }
        }
    }

    nonisolated private static func recognize(_ image: CGImage) -> Set<SensitiveKind> {
        let request = VNRecognizeTextRequest()
        request.recognitionLevel = .accurate
        request.usesLanguageCorrection = false
        try? VNImageRequestHandler(cgImage: image).perform([request])
        let lines = (request.results ?? []).compactMap { $0.topCandidates(1).first?.string }
        return SensitiveTextClassifier.classify(lines)
    }
}
