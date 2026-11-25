import Foundation
import GrinderCore

/// The name of the case that verifies `Tests/GrinderCoreTests/GeneratedCases.swift`.
/// Keep it in sync with the string literal in `generatedCasesCheck`: the literal
/// is what the generator scans for, and a drift fails the case itself.
let generatedCaseCheckName = "generated: the XCTest target lists every case"

/// Compare the generated XCTest target with the cases that actually exist.
///
/// `others` holds every case except this one; this case's own name is appended
/// here, so the expected list is complete without calling `allChecks()` (which
/// would recurse).  The XCTest target cannot run on a host without Xcode, so its
/// own `testNothingIsStale` never executes there; this check runs in the
/// portable harness on every host.
func generatedCasesCheck(others: [String]) -> [CheckCase] {
    [
        CheckCase("generated: the XCTest target lists every case") {
            let expected = others + [generatedCaseCheckName]
            let url = repositoryRoot()
                .appendingPathComponent("apps/ios/GrinderCore/Tests/GrinderCoreTests/GeneratedCases.swift")
            let source = try sourceText(at: url)

            let count = try generatedInteger(in: source, label: "generatedCaseCount")
            try checkEqual(count, expected.count, "generatedCaseCount")

            let generated = try generatedNames(in: source)
            try checkEqual(generated.count, Set(generated).count, "the generated file has duplicate names")
            try checkEqual(Set(generated), Set(expected), "the generated cases match allChecks()")
        },
    ]
}

/// Read `static let generatedCaseCount = N`.
private func generatedInteger(in source: String, label: String) throws -> Int {
    guard let marker = source.range(of: "static let \(label) = ") else {
        throw CheckFailure(message: "cannot find \(label)", file: #filePath, line: #line)
    }
    let tail = source[marker.upperBound...]
    let digits = tail.prefix { $0.isNumber }
    guard let value = Int(digits) else {
        throw CheckFailure(message: "\(label) is not a number", file: #filePath, line: #line)
    }
    return value
}

/// Read the string literals of `static let generatedCaseNames = ["a", …]`.
private func generatedNames(in source: String) throws -> [String] {
    guard let marker = source.range(of: "static let generatedCaseNames = [") else {
        throw CheckFailure(message: "cannot find generatedCaseNames", file: #filePath, line: #line)
    }
    guard let end = source.range(of: "\n    ]", range: marker.upperBound..<source.endIndex) else {
        throw CheckFailure(message: "unterminated generatedCaseNames", file: #filePath, line: #line)
    }
    let block = source[marker.upperBound..<end.lowerBound]
    var names: [String] = []
    for line in block.split(separator: "\n") {
        var literal = line.trimmingCharacters(in: .whitespaces)
        guard literal.hasPrefix("\"") else { continue }
        while literal.hasSuffix(",") { literal.removeLast() }
        guard literal.hasSuffix("\""), literal.count >= 2 else { continue }
        literal.removeFirst()
        literal.removeLast()
        names.append(literal.replacingOccurrences(of: "\\\"", with: "\""))
    }
    try check(!names.isEmpty, "generatedCaseNames is empty")
    return names
}
