// SPDX-License-Identifier: GPL-2.0
// Client for the awusd unix-socket protocol (see src/proto.h): one request line per connection, "OK"/"ERR text",
// then key=value lines and "ap ..." / "profile ..." rows. Requests are never logged (they can carry a passphrase).
import Foundation

struct Reply {
    var ok = false
    var error = ""                       // text after "ERR ", or a transport problem
    var kv: [String: String] = [:]
    var rows: [(kind: String, f: [String: String])] = []
    func int(_ k: String) -> Int? { kv[k].flatMap { Int($0) } }
}

enum Transport { case ok, noDaemon, denied, timeout }

func pctEncode(_ s: String) -> String {
    let safe = Set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._:/,+-")
    var o = ""
    for b in s.utf8 { let c = Character(UnicodeScalar(b)); o += (b < 128 && safe.contains(c)) ? String(c) : String(format: "%%%02X", b) }
    return o
}

func pctDecode(_ s: Substring) -> String {
    var bytes = [UInt8](); let u = Array(s.utf8); var i = 0
    while i < u.count {
        if u[i] == 0x25, i + 2 < u.count, let h = hexv(u[i + 1]), let l = hexv(u[i + 2]) { bytes.append(h << 4 | l); i += 3 }
        else { bytes.append(u[i]); i += 1 }
    }
    return String(decoding: bytes, as: UTF8.self)
}
private func hexv(_ c: UInt8) -> UInt8? {
    switch c { case 48...57: return c - 48; case 65...70: return c - 55; case 97...102: return c - 87; default: return nil }
}

func parseReply(_ text: String) -> Reply {
    var r = Reply()
    var lines = text.split(separator: "\n", omittingEmptySubsequences: true).map(String.init)
    guard !lines.isEmpty else { r.error = "empty reply (is this user allowed? see --sock-uid)"; return r }
    let first = lines.removeFirst()
    if first.hasPrefix("ERR") { r.error = String(first.dropFirst(4)); return r }
    guard first == "OK" else { r.error = "bad reply"; return r }
    r.ok = true
    for l in lines {
        let toks = l.split(separator: " ")
        if let t0 = toks.first, !t0.contains("=") {
            var f: [String: String] = [:]
            for t in toks.dropFirst() { if let eq = t.firstIndex(of: "=") { f[String(t[..<eq])] = pctDecode(t[t.index(after: eq)...]) } }
            r.rows.append((String(t0), f))
        } else if let eq = l.firstIndex(of: "=") {
            r.kv[String(l[..<eq])] = pctDecode(l[l.index(after: eq)...])
        }
    }
    return r
}

final class AwusClient {
    let path: String
    init(path: String) { self.path = path }

    static func defaultPath(_ args: [String]) -> String {
        if let i = args.firstIndex(of: "--sock"), i + 1 < args.count { return args[i + 1] }
        if let e = ProcessInfo.processInfo.environment["AWUS_SOCK"], !e.isEmpty { return e }
        return "/var/run/awusd.sock"
    }

    /// Blocking. `cmd` is the already-built request line (words percent-encoded by `line`). Transport failures set ok=false
    /// and `transport`.
    func send(_ line: String, timeout: Int = 15) -> (Reply, Transport) {
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        if fd < 0 { return (Reply(error: "socket failed"), .noDaemon) }
        defer { close(fd) }
        var one: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size))
        var tv = timeval(tv_sec: timeout, tv_usec: 0)
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let pb = Array(path.utf8)
        guard pb.count < MemoryLayout.size(ofValue: addr.sun_path) else { return (Reply(error: "socket path too long"), .noDaemon) }
        withUnsafeMutableBytes(of: &addr.sun_path) { for (i, b) in pb.enumerated() { $0[i] = b } }
        let rc = withUnsafePointer(to: &addr) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) } }
        if rc != 0 {
            let e = errno
            return (Reply(error: String(cString: strerror(e))), e == EACCES || e == EPERM ? .denied : .noDaemon)
        }
        let data = Array((line + "\n").utf8)
        var sent = 0
        while sent < data.count { let n = data[sent...].withUnsafeBytes { write(fd, $0.baseAddress, $0.count) }; if n <= 0 { return (Reply(error: "write failed"), .denied) }; sent += n }
        var buf = [UInt8](), chunk = [UInt8](repeating: 0, count: 8192)
        while true {
            let n = read(fd, &chunk, chunk.count)
            if n > 0 { buf += chunk[0..<n] } else if n == 0 { break } else { return (Reply(error: "timeout"), .timeout) }
        }
        let r = parseReply(String(decoding: buf, as: UTF8.self))
        return (r, buf.isEmpty ? .denied : .ok)
    }

    /// Build "cmd word... key=value..." with every word and value percent-encoded.
    static func line(_ cmd: String, _ words: [String] = [], _ opts: [(String, String)] = []) -> String {
        ([cmd] + words.map(pctEncode) + opts.map { "\($0.0)=\(pctEncode($0.1))" }).joined(separator: " ")
    }
}
