import Foundation

public struct FileSignature: Sendable {
    public let type: String
    public let category: FileCategory
    public let fileExtension: String
    public let magic: [UInt8]
    public let finder: @Sendable (Data, Int) -> (length: Int, status: ValidationStatus, confidence: Double)?
}

public enum SignatureRegistry {
    public static let signatures: [FileSignature] = [
        jpegSignature,
        pngSignature,
        gifSignature,
        pdfSignature,
        zipSignature,
        mp3Signature,
        mp4Signature,
        movSignature,
        tgzSignature,
        tbz2Signature,
        txzSignature
    ]

    public static let signatureMap: [String: FileSignature] = Dictionary(uniqueKeysWithValues: signatures.map { ($0.type, $0) })

    public static func detect(in data: Data, offset: Int) -> [FoundItem] {
        signatures.compactMap { sig in
            guard offset + sig.magic.count <= data.count else { return nil }
            let matches = data[offset..<(offset + sig.magic.count)].elementsEqual(sig.magic)
            guard matches, let result = sig.finder(data, offset) else { return nil }
            return FoundItem(
                sourcePath: "",
                offset: offset,
                length: result.length,
                detectedType: sig.type,
                category: sig.category,
                fileExtension: sig.fileExtension,
                confidence: result.confidence,
                validationStatus: result.status
            )
        }
    }

    static let jpegSignature = FileSignature(type: "jpeg", category: .images, fileExtension: "jpg", magic: [0xFF, 0xD8, 0xFF]) { data, offset in
        guard let end = data.range(of: Data([0xFF, 0xD9]), options: [], in: offset..<data.count)?.upperBound else {
            return (min(512_000, data.count - offset), .uncertain, 0.45)
        }
        return (end - offset, .valid, 0.96)
    }

    static let pngSignature = FileSignature(type: "png", category: .images, fileExtension: "png", magic: [0x89, 0x50, 0x4E, 0x47]) { data, offset in
        let iend = Data([0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82])
        guard let end = data.range(of: iend, options: [], in: offset..<data.count)?.upperBound else {
            return (min(512_000, data.count - offset), .partial, 0.7)
        }
        return (end - offset, .valid, 0.99)
    }

    static let gifSignature = FileSignature(type: "gif", category: .images, fileExtension: "gif", magic: [0x47, 0x49, 0x46, 0x38]) { data, offset in
        guard let trailer = data[offset..<data.count].lastIndex(of: 0x3B) else {
            return (min(512_000, data.count - offset), .partial, 0.7)
        }
        return (trailer - offset + 1, .valid, 0.9)
    }

    static let pdfSignature = FileSignature(type: "pdf", category: .text, fileExtension: "pdf", magic: [0x25, 0x50, 0x44, 0x46]) { data, offset in
        guard let end = data.range(of: Data("%%EOF".utf8), options: .backwards, in: offset..<data.count)?.upperBound else {
            return (min(2_000_000, data.count - offset), .partial, 0.72)
        }
        return (end - offset, .valid, 0.9)
    }

    static let zipSignature = FileSignature(type: "zip", category: .archives, fileExtension: "zip", magic: [0x50, 0x4B, 0x03, 0x04]) { data, offset in
        let eocd = Data([0x50, 0x4B, 0x05, 0x06])
        guard let endMarker = data.range(of: eocd, options: [], in: offset..<data.count)?.upperBound else {
            return (min(4_000_000, data.count - offset), .uncertain, 0.6)
        }
        return (endMarker - offset, .valid, 0.88)
    }

    static let mp3Signature = FileSignature(type: "mp3", category: .audio, fileExtension: "mp3", magic: [0x49, 0x44, 0x33]) { data, offset in
        (min(6_000_000, data.count - offset), .partial, 0.78)
    }

    static let mp4Signature = FileSignature(type: "mp4", category: .video, fileExtension: "mp4", magic: [0x00, 0x00, 0x00]) { data, offset in
        guard offset + 8 < data.count else { return nil }
        let brand = String(data: data[(offset + 4)...(offset + 7)], encoding: .ascii) ?? ""
        guard ["ftyp", "moov"].contains(brand) else { return nil }
        return (min(24_000_000, data.count - offset), .partial, 0.74)
    }

    static let movSignature = FileSignature(type: "mov", category: .video, fileExtension: "mov", magic: [0x00, 0x00, 0x00]) { data, offset in
        guard offset + 11 < data.count else { return nil }
        let brand = String(data: data[(offset + 4)...(offset + 7)], encoding: .ascii) ?? ""
        let profile = String(data: data[(offset + 8)...(offset + 11)], encoding: .ascii) ?? ""
        guard brand == "ftyp", profile.lowercased().contains("qt") else { return nil }
        return (min(24_000_000, data.count - offset), .partial, 0.7)
    }

    static let tgzSignature = FileSignature(type: "tgz", category: .archives, fileExtension: "tgz", magic: [0x1F, 0x8B]) { data, offset in
        // Alias for .tar.gz
        return (min(32_000_000, data.count - offset), .partial, 0.8)
    }

    static let tbz2Signature = FileSignature(type: "tbz2", category: .archives, fileExtension: "tbz2", magic: [0x42, 0x5A, 0x68]) { data, offset in
        // Alias for .tar.bz2
        return (min(32_000_000, data.count - offset), .partial, 0.78)
    }

    static let txzSignature = FileSignature(type: "txz", category: .archives, fileExtension: "txz", magic: [0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00]) { data, offset in
        // Alias for .tar.xz
        return (min(32_000_000, data.count - offset), .partial, 0.82)
    }
}
