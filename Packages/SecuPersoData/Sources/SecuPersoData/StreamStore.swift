import Foundation

final class StreamStore<Value: Sendable>: @unchecked Sendable {
    private let lock = NSLock()
    private var continuations: [UUID: AsyncStream<Value>.Continuation] = [:]
    private var latestValue: Value

    init(initialValue: Value) {
        self.latestValue = initialValue
    }

    deinit {
        finishAll()
    }

    func makeStream() -> AsyncStream<Value> {
        AsyncStream { continuation in
            let id = UUID()

            lock.lock()
            continuations[id] = continuation
            let initial = latestValue
            lock.unlock()

            continuation.yield(initial)
            continuation.onTermination = { [weak self] _ in
                guard let self else { return }
                self.lock.lock()
                self.continuations.removeValue(forKey: id)
                self.lock.unlock()
            }
        }
    }

    func publish(_ value: Value) {
        lock.lock()
        latestValue = value
        let activeContinuations = Array(continuations.values)
        lock.unlock()

        for continuation in activeContinuations {
            continuation.yield(value)
        }
    }

    func finishAll() {
        lock.lock()
        let activeContinuations = Array(continuations.values)
        continuations.removeAll(keepingCapacity: false)
        lock.unlock()

        for continuation in activeContinuations {
            continuation.finish()
        }
    }
}
