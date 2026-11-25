import Foundation
import GrinderCore

// MARK: - Network isolation

func isolationChecks() -> [CheckCase] {
    [
        CheckCase("isolation: RFC1918 and loopback are local") {
            for address in ["192.168.1.100", "10.0.0.5", "172.16.4.4", "127.0.0.1", "169.254.1.1"] {
                try check(NetworkIsolation.isPrivateAddress(address), "\(address) should be local")
            }
        },
        CheckCase("isolation: public addresses are not local") {
            for address in ["8.8.8.8", "1.1.1.1", "203.0.113.10"] {
                try check(!NetworkIsolation.isPrivateAddress(address), "\(address) should not be local")
            }
        },
        CheckCase("isolation: IPv6 loopback and ULA are local") {
            for address in ["::1", "fe80::1", "fd00::5", "fc00::9"] {
                try check(NetworkIsolation.isPrivateAddress(address), "\(address) should be local")
            }
            try check(!NetworkIsolation.isPrivateAddress("2001:4860:4860::8888"), "public IPv6")
        },
        CheckCase("isolation: a public literal is refused before sending") {
            var threw = false
            do { try await NetworkIsolation.requireLocalTarget("8.8.8.8") } catch { threw = true }
            try check(threw, "a public target must be refused")
        },
        CheckCase("isolation: a private literal is accepted") {
            try await NetworkIsolation.requireLocalTarget("192.168.1.100")
        },
        CheckCase("transport: a request for another host, port or scheme is refused") {
            let endpoint = try Endpoint(host: "192.168.1.100")
            let transport = URLSessionTransport(endpoint: endpoint, policy: .systemDefault)
            try check(transport.targetsDevice(endpoint.url(path: "/login.php")), "the device is allowed")
            try check(
                !transport.targetsDevice(URL(string: "https://192.168.1.100.evil.example/login.php")!),
                "a longer name is not the device"
            )
            try check(
                !transport.targetsDevice(URL(string: "https://evil.example/login.php")!),
                "another host is refused"
            )
            try check(
                !transport.targetsDevice(URL(string: "http://192.168.1.100/login.php")!),
                "plain HTTP is refused"
            )
            try check(
                !transport.targetsDevice(URL(string: "https://192.168.1.100@evil.example/login.php")!),
                "user info cannot disguise the host"
            )
            try check(
                !transport.targetsDevice(URL(string: "https://192.168.1.100:8443/login.php")!),
                "another port is refused"
            )
            var caught: Error?
            do {
                _ = try await transport.send(
                    TransportRequest(method: "GET", url: URL(string: "https://evil.example/")!)
                )
            } catch {
                caught = error
            }
            if case .notThisDevice = (caught as? TransportError) {} else {
                throw CheckFailure(
                    message: "expected notThisDevice, got \(String(describing: caught))",
                    file: #filePath,
                    line: #line
                )
            }
        },
    ]
}
