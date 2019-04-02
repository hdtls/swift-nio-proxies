import XCTest
@testable import Netbot

final class NetbotTests: XCTestCase {
    func testExample() {
        // This is an example of a functional test case.
        // Use XCTAssert and related functions to verify your tests produce the correct
        // results.
        XCTAssertEqual(Netbot().text, "Hello, World!")
    }

    static var allTests = [
        ("testExample", testExample),
    ]
}
