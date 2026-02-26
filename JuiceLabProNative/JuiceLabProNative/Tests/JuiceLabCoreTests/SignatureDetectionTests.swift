import XCTest
@testable import JuiceLabCore

final class SignatureDetectionTests: XCTestCase {
    func testDetectsJPEGAndValidEOI() {
        let bytes: [UInt8] = [0x00, 0xFF, 0xD8, 0xFF, 0xAA, 0xBB, 0xFF, 0xD9]
        let matches = SignatureRegistry.detect(in: Data(bytes), offset: 1)
        XCTAssertEqual(matches.first?.detectedType, "jpeg")
        XCTAssertEqual(matches.first?.validationStatus, .valid)
    }

    func testDetectsPNGWithIEND() {
        var bytes: [UInt8] = [0x89, 0x50, 0x4E, 0x47]
        bytes += Array(repeating: 0x00, count: 12)
        bytes += [0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82]
        let matches = SignatureRegistry.detect(in: Data(bytes), offset: 0)
        XCTAssertEqual(matches.first?.detectedType, "png")
        XCTAssertEqual(matches.first?.validationStatus, .valid)
    }

    func testDetectsPDFEOF() {
        let bytes = Array("%PDF-1.4\n1 0 obj\n%%EOF".utf8)
        let matches = SignatureRegistry.detect(in: Data(bytes), offset: 0)
        XCTAssertEqual(matches.first?.detectedType, "pdf")
    }

    func testDetectsZIPCentralDirectoryMarker() {
        let bytes: [UInt8] = [0x50, 0x4B, 0x03, 0x04, 0x01, 0x02, 0x03, 0x50, 0x4B, 0x05, 0x06]
        let matches = SignatureRegistry.detect(in: Data(bytes), offset: 0)
        XCTAssertEqual(matches.first?.detectedType, "zip")
        XCTAssertEqual(matches.first?.validationStatus, .valid)
    }

    func testDetectsMP3ID3Header() {
        let bytes: [UInt8] = [0x49, 0x44, 0x33, 0x03, 0x00, 0x00]
        let matches = SignatureRegistry.detect(in: Data(bytes), offset: 0)
        XCTAssertEqual(matches.first?.detectedType, "mp3")
    }
}
