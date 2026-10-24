// SPDX-License-Identifier: GPL-2.0
import Foundation

let appVersion = "0.1.0"

/// Optional features that other work will wire up. Flip to true and fill in the handler in App.swift (`wps()`, `adhoc()`).
enum Features { static let wps = false, adhoc = false }
let notBuiltYet = "not built yet"

/// 0...5 bars from RSSI in dBm.
func bars(forRSSI r: Int) -> Int {
    switch r { case (-50)...: return 5; case (-60)...: return 4; case (-67)...: return 3; case (-75)...: return 2; case (-85)...: return 1; default: return 0 }
}

struct AP {
    var ssid: String, bssid: String, ch: Int, rssi: Int, sec: String, allowed: Bool
    var secured: Bool { sec != "Open" }
    var is5G: Bool { ch > 14 }
    init(_ f: [String: String]) {
        ssid = f["ssid"] ?? ""; bssid = f["bssid"] ?? ""; ch = Int(f["ch"] ?? "") ?? 0; rssi = Int(f["rssi"] ?? "") ?? -100
        sec = f["sec"] ?? "Open"; allowed = f["ok"] != "0"
    }
}

struct SavedProfile { var ssid: String, security: String, autojoin: Bool, hasKey: Bool
    init(_ f: [String: String]) { ssid = f["ssid"] ?? ""; security = f["security"] ?? "auto"; autojoin = f["autojoin"] != "0"; hasKey = f["key"] == "set" }
}

enum LinkState { case daemonDown(String), denied, noDevice, rfOff, idle, scanning, joining, connected }

struct Status {
    var state: LinkState
    var kv: [String: String] = [:]
    var ssid: String { kv["ssid"] ?? "" }
    var rssi: Int? { kv["rssi_dbm"].flatMap { Int($0) } }
    var ip: String { kv["ip"] ?? "" }
    var isConnecting: Bool { if case .joining = state { return true }; if case .scanning = state { return true }; return false }
    var isConnected: Bool { if case .connected = state { return true }; return false }
    var daemonUp: Bool { if case .daemonDown = state { return false }; if case .denied = state { return false }; return true }
    var rfOn: Bool { kv["rf"] != "off" }

    init(state: LinkState) { self.state = state }
    init(_ r: Reply) {
        kv = r.kv
        switch r.kv["state"] ?? "" {
        case "NO_DEVICE": state = .noDevice
        case "RF_OFF": state = .rfOff
        case "SCANNING": state = .scanning
        case "JOINING": state = .joining
        case "CONNECTED": state = .connected
        default: state = .idle
        }
    }
}

/// Realtek hardware rate code (as reported by awusd's rx_rate_code) to Mbps; HT figures assume 20 MHz, long GI, 1 stream.
func linkSpeedText(code: Int?) -> String {
    guard let c = code else { return "-" }
    let legacy: [Double] = [1, 2, 5.5, 11, 6, 9, 12, 18, 24, 36, 48, 54]
    let mcs: [Double] = [6.5, 13, 19.5, 26, 39, 52, 58.5, 65]
    func f(_ d: Double) -> String { d == d.rounded() ? "\(Int(d))" : "\(d)" }
    if c >= 0 && c < legacy.count { return "\(f(legacy[c])) Mbps" }
    if c >= 12 && c < 20 { return "\(f(mcs[c - 12])) Mbps (HT MCS\(c - 12))" }
    return "rate code \(c)"
}

func channelText(_ ch: Int) -> String { ch > 14 ? "\(ch) (5 GHz)" : "\(ch) (2.4 GHz)" }
