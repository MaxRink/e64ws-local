import Foundation

/// A grinder is a LAN appliance, and this app is cloud-free by design.
///
/// Before anything is sent, the target is classified: a numeric address must be
/// private/link-local/loopback, and a host name must resolve only to such
/// addresses.  A target that resolves to the public internet is refused rather
/// than merely warned about, so a mistyped address cannot turn a "local" tool
/// into something that talks to an arbitrary host on the internet.
public enum NetworkIsolation {
    /// True for a bare numeric address (IPv4 or IPv6 literal).
    public static func isNumericAddress(_ host: String) -> Bool {
        if host.contains(":") { return true }
        let parts = host.split(separator: ".")
        return parts.count == 4 && parts.allSatisfy { !$0.isEmpty && $0.allSatisfy(\.isNumber) }
    }

    /// Loopback, RFC 1918, link-local, CGNAT and IPv6 ULA/link-local/loopback.
    public static func isPrivateAddress(_ address: String) -> Bool {
        let bare = address.split(separator: "%").first.map(String.init) ?? address
        if bare.contains(":") {
            let lower = bare.lowercased()
            if lower == "::1" || lower == "::" { return true }
            if lower.hasPrefix("fe80") { return true }   // link-local
            if lower.hasPrefix("fc") || lower.hasPrefix("fd") { return true }  // ULA
            return false
        }
        let parts = bare.split(separator: ".").compactMap { Int($0) }
        guard parts.count == 4, parts.allSatisfy({ (0...255).contains($0) }) else {
            return false
        }
        if parts[0] == 10 { return true }                                  // 10/8
        if parts[0] == 127 { return true }                                 // loopback
        if parts[0] == 0 { return true }                                   // 0/8
        if parts[0] == 169, parts[1] == 254 { return true }                // link-local
        if parts[0] == 172, (16...31).contains(parts[1]) { return true }   // 172.16/12
        if parts[0] == 192, parts[1] == 168 { return true }                // 192.168/16
        if parts[0] == 100, (64...127).contains(parts[1]) { return true }  // CGNAT
        return false
    }

    /// Throw unless every address for `host` is local.  Numeric literals are
    /// checked directly; names are resolved first.
    public static func requireLocalTarget(_ host: String) async throws {
        if isNumericAddress(host) {
            guard isPrivateAddress(host) else {
                throw NetworkIsolationError.globallyRoutable(host, [host])
            }
            return
        }
        let addresses = try await resolve(host)
        guard !addresses.isEmpty else {
            throw NetworkIsolationError.cannotResolve(host)
        }
        guard addresses.allSatisfy(isPrivateAddress) else {
            throw NetworkIsolationError.globallyRoutable(host, addresses)
        }
    }

    /// Resolve every A/AAAA address for `host`, de-duplicated and in order.
    public static func resolve(_ host: String) async throws -> [String] {
        try await withCheckedThrowingContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                continuation.resume(with: Result { try resolveSync(host) })
            }
        }
    }

    static func resolveSync(_ host: String) throws -> [String] {
        var hints = addrinfo(
            ai_flags: AI_ADDRCONFIG,
            ai_family: AF_UNSPEC,
            ai_socktype: SOCK_STREAM,
            ai_protocol: 0,
            ai_addrlen: 0,
            ai_canonname: nil,
            ai_addr: nil,
            ai_next: nil
        )
        var result: UnsafeMutablePointer<addrinfo>?
        let status = getaddrinfo(host, nil, &hints, &result)
        guard status == 0, let first = result else {
            throw NetworkIsolationError.cannotResolve(host)
        }
        defer { freeaddrinfo(first) }

        var addresses: [String] = []
        var cursor: UnsafeMutablePointer<addrinfo>? = first
        while let info = cursor?.pointee {
            var hostname = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            if getnameinfo(
                info.ai_addr,
                info.ai_addrlen,
                &hostname,
                socklen_t(hostname.count),
                nil,
                0,
                NI_NUMERICHOST
            ) == 0 {
                let address = String(cString: hostname)
                if !addresses.contains(address) { addresses.append(address) }
            }
            cursor = info.ai_next
        }
        return addresses
    }
}

public enum NetworkIsolationError: Error, Equatable {
    case cannotResolve(String)
    case globallyRoutable(String, [String])
}

extension NetworkIsolationError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .cannotResolve(let host):
            return "Cannot resolve \(host). Check the address and that you are on the grinder's network."
        case .globallyRoutable(let host, let addresses):
            return "\(host) resolves to a public address (\(addresses.joined(separator: ", "))). "
                + "This app only talks to a grinder on your own network."
        }
    }
}
