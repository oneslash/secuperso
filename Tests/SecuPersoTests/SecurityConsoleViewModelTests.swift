import XCTest
import SecuPersoDomain
import SecuPersoFeatures

@MainActor
final class SecurityConsoleViewModelTests: XCTestCase {
    func testTimelineCacheRebuildsDuringRefresh() async {
        let exposure = ExposureRecord(
            id: UUID(),
            email: "owner@example.com",
            source: "Breach",
            foundAt: Date(timeIntervalSince1970: 100),
            severity: .high,
            status: .open,
            remediation: "Rotate"
        )
        let login = LoginEvent(
            id: UUID(),
            provider: .google,
            occurredAt: Date(timeIntervalSince1970: 300),
            device: "Mac",
            ipAddress: "203.0.113.8",
            location: "US",
            reason: "Expected",
            suspicious: false,
            expected: true
        )
        let incident = IncidentCase(
            id: UUID(),
            title: "Incident",
            severity: .medium,
            createdAt: Date(timeIntervalSince1970: 200),
            status: .open,
            linkedLoginEventID: login.id,
            notes: "note",
            resolvedAt: nil
        )

        let exposureService = StubExposureService(refreshResult: .success([exposure]))
        let loginService = StubLoginActivityService(refreshResult: .success([login]))
        let incidentService = StubIncidentService(incidents: [incident])
        let providerService = StubProviderConnectionService()

        let viewModel = SecurityConsoleViewModel(
            exposureService: exposureService,
            loginActivityService: loginService,
            incidentService: incidentService,
            incidentReadableService: incidentService,
            providerConnectionService: providerService,
            providerConnectionReadableService: providerService
        )

        await viewModel.refreshAll()

        XCTAssertEqual(viewModel.timelineEvents.count, 3)
        XCTAssertEqual(viewModel.timelineEvents.map(\.kind), [.login, .incident, .exposure])
        XCTAssertEqual(viewModel.timelineEvents.first?.title, "Google sign-in")
    }

    func testRefreshAllCoalescesRiskRecomputeIntoSinglePass() async {
        let recomputeCounter = RiskRecomputeCounter()

        let exposure = ExposureRecord(
            id: UUID(),
            email: "owner@example.com",
            source: "Breach",
            foundAt: Date(timeIntervalSince1970: 100),
            severity: .high,
            status: .open,
            remediation: "Rotate"
        )
        let login = LoginEvent(
            id: UUID(),
            provider: .outlook,
            occurredAt: Date(timeIntervalSince1970: 200),
            device: "Windows",
            ipAddress: "198.51.100.44",
            location: "Unknown",
            reason: "Risky",
            suspicious: true,
            expected: false
        )
        let incident = IncidentCase(
            id: UUID(),
            title: "Open incident",
            severity: .high,
            createdAt: Date(timeIntervalSince1970: 150),
            status: .open,
            linkedLoginEventID: login.id,
            notes: "note",
            resolvedAt: nil
        )

        let exposureService = StubExposureService(refreshResult: .success([exposure]))
        let loginService = StubLoginActivityService(refreshResult: .success([login]))
        let incidentService = StubIncidentService(incidents: [incident])
        let providerService = StubProviderConnectionService()

        let viewModel = SecurityConsoleViewModel(
            exposureService: exposureService,
            loginActivityService: loginService,
            incidentService: incidentService,
            incidentReadableService: incidentService,
            providerConnectionService: providerService,
            providerConnectionReadableService: providerService,
            onRiskRecomputed: { _ in
                recomputeCounter.increment()
            }
        )

        await viewModel.refreshAll()

        XCTAssertEqual(recomputeCounter.count, 1)
    }

    func testRefreshAllCoalescesProjectionAndTimelineRebuildIntoSinglePass() async {
        let projectionCounter = EventCounter()
        let timelineCounter = EventCounter()

        let exposure = ExposureRecord(
            id: UUID(),
            email: "owner@example.com",
            source: "Breach",
            foundAt: Date(timeIntervalSince1970: 100),
            severity: .high,
            status: .open,
            remediation: "Rotate"
        )
        let login = LoginEvent(
            id: UUID(),
            provider: .outlook,
            occurredAt: Date(timeIntervalSince1970: 200),
            device: "Windows",
            ipAddress: "198.51.100.44",
            location: "Unknown",
            reason: "Risky",
            suspicious: true,
            expected: false
        )
        let incident = IncidentCase(
            id: UUID(),
            title: "Open incident",
            severity: .high,
            createdAt: Date(timeIntervalSince1970: 150),
            status: .open,
            linkedLoginEventID: login.id,
            notes: "note",
            resolvedAt: nil
        )

        let exposureService = StubExposureService(refreshResult: .success([exposure]))
        let loginService = StubLoginActivityService(refreshResult: .success([login]))
        let incidentService = StubIncidentService(incidents: [incident])
        let providerService = StubProviderConnectionService(connections: [
            ProviderConnection(id: .outlook, state: .connected, lastUpdatedAt: Date())
        ])

        let viewModel = SecurityConsoleViewModel(
            exposureService: exposureService,
            loginActivityService: loginService,
            incidentService: incidentService,
            incidentReadableService: incidentService,
            providerConnectionService: providerService,
            providerConnectionReadableService: providerService,
            onViewProjectionsRebuilt: {
                projectionCounter.increment()
            },
            onTimelineRebuilt: {
                timelineCounter.increment()
            }
        )

        await viewModel.refreshAll()

        XCTAssertEqual(projectionCounter.count, 1)
        XCTAssertEqual(timelineCounter.count, 1)
    }

    func testRefreshAllMapsTypedErrorContext() async {
        let expected = StubError(message: "refresh failed")

        let exposureService = StubExposureService(refreshResult: .failure(expected))
        let loginService = StubLoginActivityService(refreshResult: .success([]))
        let incidentService = StubIncidentService(incidents: [])
        let providerService = StubProviderConnectionService()

        let viewModel = SecurityConsoleViewModel(
            exposureService: exposureService,
            loginActivityService: loginService,
            incidentService: incidentService,
            incidentReadableService: incidentService,
            providerConnectionService: providerService,
            providerConnectionReadableService: providerService
        )

        await viewModel.refreshAll()

        XCTAssertEqual(viewModel.presentedError?.context, .refreshAll)
        XCTAssertEqual(viewModel.errorMessage, expected.message)
    }

    func testResolveIncidentMapsTypedErrorContext() async {
        let expected = StubError(message: "resolve failed")

        let exposureService = StubExposureService(refreshResult: .success([]))
        let loginService = StubLoginActivityService(refreshResult: .success([]))
        let incidentService = StubIncidentService(incidents: [], resolveError: expected)
        let providerService = StubProviderConnectionService()

        let viewModel = SecurityConsoleViewModel(
            exposureService: exposureService,
            loginActivityService: loginService,
            incidentService: incidentService,
            incidentReadableService: incidentService,
            providerConnectionService: providerService,
            providerConnectionReadableService: providerService
        )

        let incident = IncidentCase(
            id: UUID(),
            title: "Needs resolution",
            severity: .medium,
            createdAt: Date(),
            status: .open,
            linkedLoginEventID: UUID(),
            notes: "note",
            resolvedAt: nil
        )

        viewModel.resolveIncident(incident)

        let error = await waitForPresentedError(on: viewModel)
        XCTAssertEqual(error?.context, .resolveIncident)
        XCTAssertEqual(error?.message, expected.message)
    }

    func testBeginConnectFlowUsesStreamedProviderMessage() async {
        let exposureService = StubExposureService(refreshResult: .success([]))
        let loginService = StubLoginActivityService(refreshResult: .success([]))
        let incidentService = StubIncidentService(incidents: [])
        let providerService = StubProviderConnectionService(
            connections: [ProviderConnection(id: .outlook, state: .connected, lastUpdatedAt: Date())],
            connectUpdates: [
                ProviderConnectionUpdate(state: .connecting, message: "Opening Microsoft sign-in..."),
                ProviderConnectionUpdate(state: .connected, message: "Microsoft account connected.")
            ]
        )

        let viewModel = SecurityConsoleViewModel(
            exposureService: exposureService,
            loginActivityService: loginService,
            incidentService: incidentService,
            incidentReadableService: incidentService,
            providerConnectionService: providerService,
            providerConnectionReadableService: providerService
        )

        viewModel.beginConnectFlow(for: .outlook)

        let didReachConnected = await waitForCondition {
            viewModel.oauthState == .connected
                && viewModel.oauthStatusText == "Microsoft account connected."
                && viewModel.providerStates[.outlook] == .connected
        }

        XCTAssertTrue(didReachConnected)
    }

    func testNextActionPrioritizesHighRiskExposure() async {
        let highExposure = ExposureRecord(
            id: UUID(),
            email: "owner@example.com",
            source: "Critical leak",
            foundAt: Date(timeIntervalSince1970: 400),
            severity: .critical,
            status: .open,
            remediation: "Rotate"
        )
        let suspiciousLogin = LoginEvent(
            id: UUID(),
            provider: .google,
            occurredAt: Date(timeIntervalSince1970: 500),
            device: "Unknown",
            ipAddress: "198.51.100.1",
            location: "Unknown",
            reason: "Risky",
            suspicious: true,
            expected: false
        )
        let openIncident = IncidentCase(
            id: UUID(),
            title: "Open incident",
            severity: .high,
            createdAt: Date(timeIntervalSince1970: 450),
            status: .open,
            linkedLoginEventID: suspiciousLogin.id,
            notes: "note",
            resolvedAt: nil
        )

        let exposureService = StubExposureService(refreshResult: .success([highExposure]))
        let loginService = StubLoginActivityService(refreshResult: .success([suspiciousLogin]))
        let incidentService = StubIncidentService(incidents: [openIncident])
        let providerService = StubProviderConnectionService(connections: [
            ProviderConnection(id: .google, state: .disconnected, lastUpdatedAt: Date())
        ])

        let viewModel = SecurityConsoleViewModel(
            exposureService: exposureService,
            loginActivityService: loginService,
            incidentService: incidentService,
            incidentReadableService: incidentService,
            providerConnectionService: providerService,
            providerConnectionReadableService: providerService
        )

        await viewModel.refreshAll()

        guard case let .reviewHighRiskExposure(exposureID) = viewModel.nextAction.kind else {
            XCTFail("Expected high-risk exposure action")
            return
        }

        XCTAssertEqual(exposureID, highExposure.id)
        XCTAssertEqual(viewModel.nextAction.destinationSection, .exposure)
        XCTAssertEqual(viewModel.nextAction.buttonTitle, "Review exposure")
    }

    func testNextActionFallsBackToSecurityCheckWhenEverythingLooksGood() async {
        let exposure = ExposureRecord(
            id: UUID(),
            email: "owner@example.com",
            source: "Historical",
            foundAt: Date(timeIntervalSince1970: 100),
            severity: .low,
            status: .resolved,
            remediation: "None"
        )
        let expectedLogin = LoginEvent(
            id: UUID(),
            provider: .google,
            occurredAt: Date(timeIntervalSince1970: 200),
            device: "Mac",
            ipAddress: "203.0.113.8",
            location: "US",
            reason: "Expected",
            suspicious: false,
            expected: true
        )

        let allConnected = ProviderID.allCases.map {
            ProviderConnection(id: $0, state: .connected, lastUpdatedAt: Date())
        }

        let exposureService = StubExposureService(refreshResult: .success([exposure]))
        let loginService = StubLoginActivityService(refreshResult: .success([expectedLogin]))
        let incidentService = StubIncidentService(incidents: [])
        let providerService = StubProviderConnectionService(connections: allConnected)

        let viewModel = SecurityConsoleViewModel(
            exposureService: exposureService,
            loginActivityService: loginService,
            incidentService: incidentService,
            incidentReadableService: incidentService,
            providerConnectionService: providerService,
            providerConnectionReadableService: providerService
        )

        await viewModel.refreshAll()

        XCTAssertEqual(viewModel.nextAction.kind, .runSecurityCheck)
        XCTAssertEqual(viewModel.nextAction.destinationSection, .overview)
        XCTAssertEqual(viewModel.nextAction.buttonTitle, "Run check")
    }

    func testOverviewSummaryUsesStableSemanticsForLowRisk() async {
        let resolvedExposure = ExposureRecord(
            id: UUID(),
            email: "owner@example.com",
            source: "Historical",
            foundAt: Date(timeIntervalSince1970: 100),
            severity: .low,
            status: .resolved,
            remediation: "none"
        )
        let expectedLogin = LoginEvent(
            id: UUID(),
            provider: .google,
            occurredAt: Date(timeIntervalSince1970: 200),
            device: "Mac",
            ipAddress: "203.0.113.8",
            location: "US",
            reason: "Expected",
            suspicious: false,
            expected: true
        )

        let exposureService = StubExposureService(refreshResult: .success([resolvedExposure]))
        let loginService = StubLoginActivityService(refreshResult: .success([expectedLogin]))
        let incidentService = StubIncidentService(incidents: [])
        let providerService = StubProviderConnectionService()

        let viewModel = SecurityConsoleViewModel(
            exposureService: exposureService,
            loginActivityService: loginService,
            incidentService: incidentService,
            incidentReadableService: incidentService,
            providerConnectionService: providerService,
            providerConnectionReadableService: providerService
        )

        await viewModel.refreshAll()

        XCTAssertEqual(viewModel.overviewSummary.riskLevel, .low)
        XCTAssertEqual(viewModel.overviewSummary.stateLabel, "Stable")
        XCTAssertEqual(viewModel.overviewSummary.headline, "No critical risks detected")
    }

    func testOverviewSummaryUsesNeedsAttentionSemanticsForMediumRisk() async {
        let exposure = ExposureRecord(
            id: UUID(),
            email: "owner@example.com",
            source: "Forum leak",
            foundAt: Date(timeIntervalSince1970: 100),
            severity: .high,
            status: .open,
            remediation: "rotate"
        )
        let suspiciousLogin = LoginEvent(
            id: UUID(),
            provider: .outlook,
            occurredAt: Date(timeIntervalSince1970: 300),
            device: "Unknown",
            ipAddress: "198.51.100.2",
            location: "Unknown",
            reason: "Risky",
            suspicious: true,
            expected: false
        )

        let exposureService = StubExposureService(refreshResult: .success([exposure]))
        let loginService = StubLoginActivityService(refreshResult: .success([suspiciousLogin]))
        let incidentService = StubIncidentService(incidents: [])
        let providerService = StubProviderConnectionService()

        let viewModel = SecurityConsoleViewModel(
            exposureService: exposureService,
            loginActivityService: loginService,
            incidentService: incidentService,
            incidentReadableService: incidentService,
            providerConnectionService: providerService,
            providerConnectionReadableService: providerService
        )

        await viewModel.refreshAll()

        XCTAssertEqual(viewModel.overviewSummary.riskLevel, .medium)
        XCTAssertEqual(viewModel.overviewSummary.stateLabel, "Needs attention")
        XCTAssertEqual(viewModel.overviewSummary.headline, "Review pending security signals")
    }

    func testOverviewSummaryUsesAtRiskSemanticsForHighRisk() async {
        let exposure = ExposureRecord(
            id: UUID(),
            email: "owner@example.com",
            source: "Critical leak",
            foundAt: Date(),
            severity: .critical,
            status: .open,
            remediation: "rotate"
        )
        let firstSuspiciousLogin = LoginEvent(
            id: UUID(),
            provider: .google,
            occurredAt: Date(),
            device: "Unknown",
            ipAddress: "198.51.100.10",
            location: "Unknown",
            reason: "Risky",
            suspicious: true,
            expected: false
        )
        let secondSuspiciousLogin = LoginEvent(
            id: UUID(),
            provider: .outlook,
            occurredAt: Date().addingTimeInterval(-60),
            device: "Unknown",
            ipAddress: "198.51.100.11",
            location: "Unknown",
            reason: "Risky",
            suspicious: true,
            expected: false
        )
        let incident = IncidentCase(
            id: UUID(),
            title: "Open incident",
            severity: .high,
            createdAt: Date(),
            status: .open,
            linkedLoginEventID: firstSuspiciousLogin.id,
            notes: "note",
            resolvedAt: nil
        )

        let exposureService = StubExposureService(refreshResult: .success([exposure]))
        let loginService = StubLoginActivityService(refreshResult: .success([firstSuspiciousLogin, secondSuspiciousLogin]))
        let incidentService = StubIncidentService(incidents: [incident])
        let providerService = StubProviderConnectionService()

        let viewModel = SecurityConsoleViewModel(
            exposureService: exposureService,
            loginActivityService: loginService,
            incidentService: incidentService,
            incidentReadableService: incidentService,
            providerConnectionService: providerService,
            providerConnectionReadableService: providerService
        )

        await viewModel.refreshAll()

        XCTAssertEqual(viewModel.overviewSummary.riskLevel, .high)
        XCTAssertEqual(viewModel.overviewSummary.stateLabel, "At risk")
        XCTAssertEqual(viewModel.overviewSummary.headline, "Immediate review required")
    }

    func testNextActionUsesNormalizedButtonTitles() async {
        let suspiciousLogin = LoginEvent(
            id: UUID(),
            provider: .google,
            occurredAt: Date(),
            device: "Unknown",
            ipAddress: "198.51.100.1",
            location: "Unknown",
            reason: "Risky",
            suspicious: true,
            expected: false
        )
        let loginViewModel = SecurityConsoleViewModel(
            exposureService: StubExposureService(refreshResult: .success([])),
            loginActivityService: StubLoginActivityService(refreshResult: .success([suspiciousLogin])),
            incidentService: StubIncidentService(incidents: []),
            incidentReadableService: StubIncidentService(incidents: []),
            providerConnectionService: StubProviderConnectionService(),
            providerConnectionReadableService: StubProviderConnectionService()
        )
        await loginViewModel.refreshAll()
        XCTAssertEqual(loginViewModel.nextAction.buttonTitle, "Review sign-in")

        let incident = IncidentCase(
            id: UUID(),
            title: "Open incident",
            severity: .high,
            createdAt: Date(),
            status: .open,
            linkedLoginEventID: UUID(),
            notes: "note",
            resolvedAt: nil
        )
        let incidentService = StubIncidentService(incidents: [incident])
        let incidentViewModel = SecurityConsoleViewModel(
            exposureService: StubExposureService(refreshResult: .success([])),
            loginActivityService: StubLoginActivityService(refreshResult: .success([])),
            incidentService: incidentService,
            incidentReadableService: incidentService,
            providerConnectionService: StubProviderConnectionService(),
            providerConnectionReadableService: StubProviderConnectionService()
        )
        await incidentViewModel.refreshAll()
        XCTAssertEqual(incidentViewModel.nextAction.buttonTitle, "Resolve incident")

        let providerViewModel = SecurityConsoleViewModel(
            exposureService: StubExposureService(refreshResult: .success([])),
            loginActivityService: StubLoginActivityService(refreshResult: .success([])),
            incidentService: StubIncidentService(incidents: []),
            incidentReadableService: StubIncidentService(incidents: []),
            providerConnectionService: StubProviderConnectionService(connections: [
                ProviderConnection(id: .google, state: .connected, lastUpdatedAt: Date()),
                ProviderConnection(id: .outlook, state: .disconnected, lastUpdatedAt: Date()),
                ProviderConnection(id: .other, state: .connected, lastUpdatedAt: Date())
            ]),
            providerConnectionReadableService: StubProviderConnectionService(connections: [
                ProviderConnection(id: .google, state: .connected, lastUpdatedAt: Date()),
                ProviderConnection(id: .outlook, state: .disconnected, lastUpdatedAt: Date()),
                ProviderConnection(id: .other, state: .connected, lastUpdatedAt: Date())
            ])
        )
        await providerViewModel.refreshAll()
        XCTAssertEqual(providerViewModel.nextAction.buttonTitle, "Connect provider")
        XCTAssertEqual(providerViewModel.nextAction.destinationSection, .integrations)
        XCTAssertEqual(providerViewModel.handleNextActionTap(), .integrations)
    }

    func testOverviewActivityPreviewItemsAreAttentionFirstAndCapped() async {
        let openExposure = ExposureRecord(
            id: UUID(),
            email: "owner@example.com",
            source: "Old leak",
            foundAt: Date(timeIntervalSince1970: 100),
            severity: .high,
            status: .open,
            remediation: "rotate"
        )
        let resolvedExposure = ExposureRecord(
            id: UUID(),
            email: "owner@example.com",
            source: "Resolved leak",
            foundAt: Date(timeIntervalSince1970: 400),
            severity: .low,
            status: .resolved,
            remediation: "none"
        )
        let suspiciousLogin = LoginEvent(
            id: UUID(),
            provider: .google,
            occurredAt: Date(timeIntervalSince1970: 300),
            device: "Unknown",
            ipAddress: "198.51.100.1",
            location: "Unknown",
            reason: "Risky",
            suspicious: true,
            expected: false
        )
        let expectedLogin = LoginEvent(
            id: UUID(),
            provider: .outlook,
            occurredAt: Date(timeIntervalSince1970: 500),
            device: "Known",
            ipAddress: "198.51.100.2",
            location: "US",
            reason: "Expected",
            suspicious: false,
            expected: true
        )
        let incident = IncidentCase(
            id: UUID(),
            title: "Open incident",
            severity: .medium,
            createdAt: Date(timeIntervalSince1970: 200),
            status: .open,
            linkedLoginEventID: suspiciousLogin.id,
            notes: "note",
            resolvedAt: nil
        )

        let exposureService = StubExposureService(refreshResult: .success([openExposure, resolvedExposure]))
        let loginService = StubLoginActivityService(refreshResult: .success([suspiciousLogin, expectedLogin]))
        let incidentService = StubIncidentService(incidents: [incident])
        let providerService = StubProviderConnectionService()

        let viewModel = SecurityConsoleViewModel(
            exposureService: exposureService,
            loginActivityService: loginService,
            incidentService: incidentService,
            incidentReadableService: incidentService,
            providerConnectionService: providerService,
            providerConnectionReadableService: providerService
        )

        await viewModel.refreshAll()

        XCTAssertEqual(viewModel.overviewActivityPreviewItems.count, 3)
        XCTAssertEqual(viewModel.overviewActivityPreviewItems.map(\.id), [
            "login-\(suspiciousLogin.id.uuidString)",
            "incident-\(incident.id.uuidString)",
            "exposure-\(openExposure.id.uuidString)"
        ])
        XCTAssertTrue(viewModel.overviewActivityPreviewItems.prefix(3).allSatisfy(\.needsAttention))
    }

    func testPrecomputedOverviewSignalsAndExposureFindingRowsStayConsistent() async {
        let firstExposure = ExposureRecord(
            id: UUID(),
            email: "a@example.com",
            source: "Breach-A",
            foundAt: Date(timeIntervalSince1970: 200),
            severity: .high,
            status: .open,
            remediation: "Rotate"
        )
        let secondExposure = ExposureRecord(
            id: UUID(),
            email: "b@example.com",
            source: "Breach-B",
            foundAt: Date(timeIntervalSince1970: 100),
            severity: .medium,
            status: .open,
            remediation: "Enable MFA"
        )
        let suspiciousLogin = LoginEvent(
            id: UUID(),
            provider: .google,
            occurredAt: Date(timeIntervalSince1970: 300),
            device: "Unknown",
            ipAddress: "198.51.100.1",
            location: "Unknown",
            reason: "Risky",
            suspicious: true,
            expected: false
        )
        let openIncident = IncidentCase(
            id: UUID(),
            title: "Open incident",
            severity: .high,
            createdAt: Date(timeIntervalSince1970: 250),
            status: .open,
            linkedLoginEventID: suspiciousLogin.id,
            notes: "note",
            resolvedAt: nil
        )

        let exposureService = StubExposureService(refreshResult: .success([firstExposure, secondExposure]))
        let loginService = StubLoginActivityService(refreshResult: .success([suspiciousLogin]))
        let incidentService = StubIncidentService(incidents: [openIncident])
        let providerService = StubProviderConnectionService(connections: [
            ProviderConnection(id: .google, state: .connected, lastUpdatedAt: Date()),
            ProviderConnection(id: .outlook, state: .disconnected, lastUpdatedAt: Date()),
            ProviderConnection(id: .other, state: .connected, lastUpdatedAt: Date())
        ])

        let viewModel = SecurityConsoleViewModel(
            exposureService: exposureService,
            loginActivityService: loginService,
            incidentService: incidentService,
            incidentReadableService: incidentService,
            providerConnectionService: providerService,
            providerConnectionReadableService: providerService
        )

        await viewModel.refreshAll()

        XCTAssertEqual(viewModel.overviewSignals.suspiciousSignInCount, 1)
        XCTAssertEqual(viewModel.overviewSignals.openIncidentCount, 1)
        XCTAssertEqual(viewModel.overviewSignals.connectedProviderCount, 2)
        XCTAssertEqual(viewModel.overviewSignals.totalProviderCount, 3)

        XCTAssertEqual(viewModel.exposureFindingRows.count, 2)
        XCTAssertEqual(viewModel.exposureFindingRows.map(\.email), ["a@example.com", "b@example.com"])
    }

    func testActivityFeedIsSortedAndNeedsAttentionFilterIsDefault() async {
        let exposure = ExposureRecord(
            id: UUID(),
            email: "owner@example.com",
            source: "Forum leak",
            foundAt: Date(timeIntervalSince1970: 100),
            severity: .high,
            status: .open,
            remediation: "Rotate"
        )
        let expectedLogin = LoginEvent(
            id: UUID(),
            provider: .google,
            occurredAt: Date(timeIntervalSince1970: 300),
            device: "Mac",
            ipAddress: "203.0.113.8",
            location: "US",
            reason: "Expected",
            suspicious: false,
            expected: true
        )
        let suspiciousLogin = LoginEvent(
            id: UUID(),
            provider: .outlook,
            occurredAt: Date(timeIntervalSince1970: 350),
            device: "Unknown",
            ipAddress: "198.51.100.2",
            location: "Unknown",
            reason: "Risky",
            suspicious: true,
            expected: false
        )

        let exposureService = StubExposureService(refreshResult: .success([exposure]))
        let loginService = StubLoginActivityService(refreshResult: .success([expectedLogin, suspiciousLogin]))
        let incidentService = StubIncidentService(incidents: [])
        let providerService = StubProviderConnectionService()

        let viewModel = SecurityConsoleViewModel(
            exposureService: exposureService,
            loginActivityService: loginService,
            incidentService: incidentService,
            incidentReadableService: incidentService,
            providerConnectionService: providerService,
            providerConnectionReadableService: providerService
        )

        await viewModel.refreshAll()

        XCTAssertEqual(viewModel.activityFeed.map(\.id), [
            "login-\(suspiciousLogin.id.uuidString)",
            "login-\(expectedLogin.id.uuidString)",
            "exposure-\(exposure.id.uuidString)"
        ])

        XCTAssertEqual(viewModel.activityFilter, .needsAttention)
        XCTAssertEqual(viewModel.filteredActivityFeed.count, 2)
        XCTAssertTrue(viewModel.filteredActivityFeed.allSatisfy(\.needsAttention))
    }

    func testAccountCardsAggregateSuspiciousCountsAndConnectionState() async throws {
        let googleLogin = LoginEvent(
            id: UUID(),
            provider: .google,
            occurredAt: Date(timeIntervalSince1970: 300),
            device: "Mac",
            ipAddress: "203.0.113.8",
            location: "US",
            reason: "Expected",
            suspicious: false,
            expected: true
        )
        let outlookLogin = LoginEvent(
            id: UUID(),
            provider: .outlook,
            occurredAt: Date(timeIntervalSince1970: 320),
            device: "Unknown",
            ipAddress: "198.51.100.2",
            location: "Unknown",
            reason: "Risky",
            suspicious: true,
            expected: false
        )

        let connections: [ProviderConnection] = [
            ProviderConnection(id: .google, state: .connected, lastUpdatedAt: Date()),
            ProviderConnection(id: .outlook, state: .disconnected, lastUpdatedAt: Date()),
            ProviderConnection(id: .other, state: .connected, lastUpdatedAt: Date())
        ]

        let exposureService = StubExposureService(refreshResult: .success([]))
        let loginService = StubLoginActivityService(refreshResult: .success([googleLogin, outlookLogin]))
        let incidentService = StubIncidentService(incidents: [])
        let providerService = StubProviderConnectionService(connections: connections)

        let viewModel = SecurityConsoleViewModel(
            exposureService: exposureService,
            loginActivityService: loginService,
            incidentService: incidentService,
            incidentReadableService: incidentService,
            providerConnectionService: providerService,
            providerConnectionReadableService: providerService
        )

        await viewModel.refreshAll()

        let googleCard = try XCTUnwrap(viewModel.accountCards.first(where: { $0.providerID == .google }))
        XCTAssertEqual(googleCard.connectionState, .connected)
        XCTAssertEqual(googleCard.suspiciousLoginCount, 0)
        XCTAssertFalse(googleCard.needsAttention)

        let outlookCard = try XCTUnwrap(viewModel.accountCards.first(where: { $0.providerID == .outlook }))
        XCTAssertEqual(outlookCard.connectionState, .disconnected)
        XCTAssertEqual(outlookCard.suspiciousLoginCount, 1)
        XCTAssertTrue(outlookCard.needsAttention)
    }

    func testPendingConfirmationLifecycleMarksLoginAsExpectedAfterConfirm() async throws {
        let suspiciousLogin = LoginEvent(
            id: UUID(),
            provider: .outlook,
            occurredAt: Date(timeIntervalSince1970: 300),
            device: "Unknown",
            ipAddress: "198.51.100.2",
            location: "Unknown",
            reason: "Risky",
            suspicious: true,
            expected: false
        )

        let exposureService = StubExposureService(refreshResult: .success([]))
        let loginService = StubLoginActivityService(refreshResult: .success([suspiciousLogin]))
        let incidentService = StubIncidentService(incidents: [])
        let providerService = StubProviderConnectionService()

        let viewModel = SecurityConsoleViewModel(
            exposureService: exposureService,
            loginActivityService: loginService,
            incidentService: incidentService,
            incidentReadableService: incidentService,
            providerConnectionService: providerService,
            providerConnectionReadableService: providerService
        )

        await viewModel.refreshAll()

        let login = try XCTUnwrap(viewModel.loginEvents.first)
        viewModel.requestMarkAsMe(login)

        guard case .markLoginAsExpected = viewModel.pendingConfirmationAction?.kind else {
            XCTFail("Expected pending mark-as-expected confirmation")
            return
        }

        viewModel.confirmPendingAction()

        let didUpdate = await waitForCondition {
            guard let updated = viewModel.loginEvents.first(where: { $0.id == suspiciousLogin.id }) else {
                return false
            }

            return updated.expected && !updated.suspicious
        }

        XCTAssertTrue(didUpdate)
        XCTAssertNil(viewModel.pendingConfirmationAction)
    }

    func testCancelPendingActionClearsPendingState() async throws {
        let login = LoginEvent(
            id: UUID(),
            provider: .google,
            occurredAt: Date(timeIntervalSince1970: 100),
            device: "Mac",
            ipAddress: "203.0.113.8",
            location: "US",
            reason: "Expected",
            suspicious: false,
            expected: true
        )

        let incident = IncidentCase(
            id: UUID(),
            title: "Open incident",
            severity: .medium,
            createdAt: Date(timeIntervalSince1970: 200),
            status: .open,
            linkedLoginEventID: login.id,
            notes: "note",
            resolvedAt: nil
        )

        let exposureService = StubExposureService(refreshResult: .success([]))
        let loginService = StubLoginActivityService(refreshResult: .success([login]))
        let incidentService = StubIncidentService(incidents: [incident])
        let providerService = StubProviderConnectionService()

        let viewModel = SecurityConsoleViewModel(
            exposureService: exposureService,
            loginActivityService: loginService,
            incidentService: incidentService,
            incidentReadableService: incidentService,
            providerConnectionService: providerService,
            providerConnectionReadableService: providerService
        )

        await viewModel.refreshAll()

        let openIncident = try XCTUnwrap(viewModel.incidents.first)
        viewModel.requestResolveIncident(openIncident)
        XCTAssertNotNil(viewModel.pendingConfirmationAction)

        viewModel.cancelPendingAction()
        XCTAssertNil(viewModel.pendingConfirmationAction)
    }

    private func waitForPresentedError(
        on viewModel: SecurityConsoleViewModel,
        timeoutNanoseconds: UInt64 = 1_000_000_000
    ) async -> SecurityConsoleError? {
        let step: UInt64 = 20_000_000
        var remaining = timeoutNanoseconds

        while remaining > 0 {
            if let error = viewModel.presentedError {
                return error
            }

            try? await Task.sleep(nanoseconds: step)
            if remaining > step {
                remaining -= step
            } else {
                remaining = 0
            }
        }

        return viewModel.presentedError
    }

    private func waitForCondition(
        timeoutNanoseconds: UInt64 = 1_000_000_000,
        condition: @escaping @MainActor () -> Bool
    ) async -> Bool {
        let step: UInt64 = 20_000_000
        var remaining = timeoutNanoseconds

        while remaining > 0 {
            if condition() {
                return true
            }

            try? await Task.sleep(nanoseconds: step)
            if remaining > step {
                remaining -= step
            } else {
                remaining = 0
            }
        }

        return condition()
    }
}

private struct StubError: Error, LocalizedError {
    let message: String

    var errorDescription: String? {
        message
    }
}

private final class RiskRecomputeCounter {
    private(set) var count = 0

    func increment() {
        count += 1
    }
}

private final class EventCounter {
    private(set) var count = 0

    func increment() {
        count += 1
    }
}

private final class StubExposureService: ExposureMonitoringService, @unchecked Sendable {
    let refreshResult: Result<[ExposureRecord], Error>

    init(refreshResult: Result<[ExposureRecord], Error>) {
        self.refreshResult = refreshResult
    }

    func refresh() async throws -> [ExposureRecord] {
        try refreshResult.get()
    }

    func stream() -> AsyncStream<[ExposureRecord]> {
        AsyncStream { continuation in
            continuation.finish()
        }
    }
}

private final class StubLoginActivityService: LoginActivityService, @unchecked Sendable {
    let refreshResult: Result<[LoginEvent], Error>

    init(refreshResult: Result<[LoginEvent], Error>) {
        self.refreshResult = refreshResult
    }

    func refresh() async throws -> [LoginEvent] {
        try refreshResult.get()
    }

    func stream() -> AsyncStream<[LoginEvent]> {
        AsyncStream { continuation in
            continuation.finish()
        }
    }
}

private final class StubIncidentService: IncidentService, IncidentReadableService, @unchecked Sendable {
    let incidents: [IncidentCase]
    let resolveError: (any Error)?

    init(incidents: [IncidentCase], resolveError: (any Error)? = nil) {
        self.incidents = incidents
        self.resolveError = resolveError
    }

    func create(from loginEventID: UUID) async throws -> IncidentCase {
        IncidentCase(
            id: UUID(),
            title: "Created",
            severity: .medium,
            createdAt: Date(),
            status: .open,
            linkedLoginEventID: loginEventID,
            notes: "mock",
            resolvedAt: nil
        )
    }

    func resolve(_ incidentID: UUID) async throws {
        if let resolveError {
            throw resolveError
        }
    }

    func list() async throws -> [IncidentCase] {
        incidents
    }
}

private final class StubProviderConnectionService: ProviderConnectionService, ProviderConnectionReadableService, @unchecked Sendable {
    private let currentConnections: [ProviderConnection]
    private let connectUpdates: [ProviderConnectionUpdate]

    init(
        connections: [ProviderConnection] = [],
        connectUpdates: [ProviderConnectionUpdate] = []
    ) {
        self.currentConnections = connections
        self.connectUpdates = connectUpdates
    }

    func beginConnection(for provider: ProviderID) async -> AsyncStream<ProviderConnectionUpdate> {
        AsyncStream { continuation in
            for update in connectUpdates {
                continuation.yield(update)
            }
            continuation.finish()
        }
    }

    func disconnect(_ provider: ProviderID) async throws {}

    func connections() async throws -> [ProviderConnection] {
        currentConnections
    }
}
