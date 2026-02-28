import XCTest
import SecuPersoFeatures

final class AppSectionTests: XCTestCase {
    func testPrimaryAndUtilityCasesMatchSimplifiedNavigationModel() {
        XCTAssertEqual(AppSection.primaryCases, [.overview, .exposure, .activity])
        XCTAssertEqual(AppSection.utilityCases, [.settings])
    }

    func testSectionTitlesAndSymbolsAreStable() {
        XCTAssertEqual(AppSection.overview.title, "Overview")
        XCTAssertEqual(AppSection.overview.symbol, "shield.lefthalf.filled")

        XCTAssertEqual(AppSection.exposure.title, "Exposure")
        XCTAssertEqual(AppSection.exposure.symbol, "envelope.badge.shield.half.filled")

        XCTAssertEqual(AppSection.activity.title, "Activity")
        XCTAssertEqual(AppSection.activity.symbol, "clock.arrow.trianglehead.counterclockwise.rotate.90")

        XCTAssertEqual(AppSection.settings.title, "Settings")
        XCTAssertEqual(AppSection.settings.symbol, "gearshape")
    }
}
