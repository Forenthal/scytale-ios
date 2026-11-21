import XCTest
@testable import Scytale

final class CoreTests: XCTestCase {
    func testCoreSelfTestPasses() {
        XCTAssertEqual(CoreSelfTest.run(), 0)
    }
}
