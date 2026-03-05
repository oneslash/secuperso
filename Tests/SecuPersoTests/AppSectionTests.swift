import XCTest
import SecuPersoFeatures

final class AppSectionTests: XCTestCase {
    func testPrimaryAndUtilityCasesMatchNavigationModel() {
        XCTAssertEqual(AppSection.primaryCases, [.overview, .activity, .exposure, .integrations])
        XCTAssertEqual(AppSection.utilityCases, [])
    }

    func testSectionTitlesAndSymbolsAreStable() {
        XCTAssertEqual(AppSection.overview.title, "Overview")
        XCTAssertEqual(AppSection.overview.symbol, "shield.lefthalf.filled")

        XCTAssertEqual(AppSection.activity.title, "Activity")
        XCTAssertEqual(AppSection.activity.symbol, "clock.arrow.trianglehead.counterclockwise.rotate.90")

        XCTAssertEqual(AppSection.exposure.title, "Exposure")
        XCTAssertEqual(AppSection.exposure.symbol, "envelope.badge.shield.half.filled")

        XCTAssertEqual(AppSection.integrations.title, "Integrations")
        XCTAssertEqual(AppSection.integrations.symbol, "link.badge.plus")
    }
}
