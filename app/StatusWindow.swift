// SPDX-License-Identifier: GPL-2.0
import Cocoa

final class StatusWindow: NSObject, NSWindowDelegate {
    let window: NSWindow
    unowned let ctl: Controller
    var values: [String: NSTextField] = [:]
    let power = NSSlider(value: 32, minValue: 0, maxValue: 63, target: nil, action: nil)
    let powerLabel = NSTextField(labelWithString: "32")
    let country = NSPopUpButton(frame: .zero, pullsDown: false)
    let rows: [(String, String)] = [("state", "State"), ("ssid", "Network"), ("bssid", "BSSID"), ("channel", "Channel"), ("rssi", "Signal"),
        ("speed", "Link speed"), ("security", "Security"), ("ip", "IP address"), ("gateway", "Gateway"), ("lease", "Lease"),
        ("counters", "Counters"), ("driver", "Driver")]

    init(controller: Controller) {
        ctl = controller
        window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 440, height: 440), styleMask: [.titled, .closable], backing: .buffered, defer: false)
        super.init()
        window.title = "AWUS WiFi Status"
        window.isReleasedWhenClosed = false
        window.delegate = self
        let grid = NSGridView()
        for (k, name) in rows {
            let l = NSTextField(labelWithString: name + ":"); l.alignment = .right; l.textColor = .secondaryLabelColor
            let v = NSTextField(labelWithString: "-"); v.isSelectable = true; v.lineBreakMode = .byTruncatingMiddle
            v.font = .monospacedSystemFont(ofSize: 12, weight: .regular)
            values[k] = v
            grid.addRow(with: [l, v])
        }
        power.isContinuous = true; power.target = self; power.action = #selector(powerChanged)
        power.widthAnchor.constraint(equalToConstant: 180).isActive = true
        let pbox = NSStackView(views: [power, powerLabel]); pbox.spacing = 8
        grid.addRow(with: [{ let l = NSTextField(labelWithString: "TX power:"); l.alignment = .right; l.textColor = .secondaryLabelColor; return l }(), pbox])
        country.target = self; country.action = #selector(countryChanged)
        grid.addRow(with: [{ let l = NSTextField(labelWithString: "Country:"); l.alignment = .right; l.textColor = .secondaryLabelColor; return l }(), country])
        grid.column(at: 0).xPlacement = .trailing
        grid.rowSpacing = 6; grid.columnSpacing = 10
        grid.translatesAutoresizingMaskIntoConstraints = false
        let content = NSView(frame: window.contentRect(forFrameRect: window.frame))
        content.addSubview(grid)
        NSLayoutConstraint.activate([grid.topAnchor.constraint(equalTo: content.topAnchor, constant: 18), grid.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 18),
                                     grid.trailingAnchor.constraint(equalTo: content.trailingAnchor, constant: -18), grid.bottomAnchor.constraint(equalTo: content.bottomAnchor, constant: -18)])
        window.contentView = content
        window.center()
    }

    func set(_ k: String, _ s: String?) { values[k]?.stringValue = (s?.isEmpty == false) ? s! : "-" }

    func update(_ st: Status) {
        let k = st.kv
        let stateText: String
        switch st.state {
        case .daemonDown: stateText = "driver not running"
        case .denied: stateText = "driver refuses this user"
        case .noDevice: stateText = "adapter not plugged in"
        case .rfOff: stateText = "Wi-Fi off"
        case .idle: stateText = "not connected"
        case .scanning: stateText = "scanning"
        case .joining: stateText = "joining"
        case .connected: stateText = "connected"
        }
        set("state", stateText)
        set("ssid", k["ssid"]); set("bssid", k["bssid"])
        set("channel", (k["link_channel"] ?? k["channel"]).flatMap { Int($0) }.map { channelText($0) })
        set("rssi", st.rssi.map { "\($0) dBm  (\(bars(forRSSI: $0)) of 5 bars)" })
        set("speed", st.isConnected ? linkSpeedText(code: k["rx_rate_code"].flatMap { Int($0) }) : nil)
        set("security", st.isConnected ? [k["security"], k["pairwise"]].compactMap { $0 }.joined(separator: " / ") : nil)
        set("ip", k["ip"]); set("gateway", k["gateway"])
        set("lease", st.isConnected ? "\(k["lease_age_s"] ?? "?") s of \(k["lease_s"] ?? "?") s, renews \(k["dhcp_renews"] ?? "0"), rebinds \(k["dhcp_rebinds"] ?? "0")" : nil)
        set("counters", st.daemonUp ? "rx from AP \(k["rx_ap_frames"] ?? "0"), connects \(k["connects"] ?? "0"), drops \(k["drops"] ?? "0"), usb errors \(k["usb_errors"] ?? "0")" : nil)
        set("driver", st.daemonUp ? "awusd \(k["version"] ?? "?"), up \(k["uptime_s"] ?? "?") s, \(k["root"] == "1" ? "root (utun)" : "no root: link only")" : nil)
        if let t = k["txpower"].flatMap({ Int($0) }), NSApp.currentEvent?.type != .leftMouseDragged { power.integerValue = t; powerLabel.stringValue = "\(t)" }
        power.isEnabled = k["txpower"] != nil
        if let c = k["country"], country.titleOfSelectedItem != c, country.itemTitles.contains(c) { country.selectItem(withTitle: c) }
    }

    func loadCountries() {
        ctl.request("country get") { [weak self] r, _ in
            guard let self = self, r.ok else { return }
            self.country.removeAllItems()
            self.country.addItems(withTitles: (r.kv["known"] ?? "").split(separator: " ").map(String.init))
            if let c = r.kv["country"] { self.country.selectItem(withTitle: c) }
        }
    }

    @objc func powerChanged() {
        powerLabel.stringValue = "\(power.integerValue)"
        if NSApp.currentEvent?.type == .leftMouseUp {      // send once, when the mouse is released
            ctl.request("txpower set \(power.integerValue)") { [weak self] r, _ in if !r.ok { self?.ctl.failure("Could not set TX power", r) }; self?.ctl.refreshStatus() }
        }
    }

    @objc func countryChanged() {
        guard let cc = country.titleOfSelectedItem else { return }
        ctl.request(AwusClient.line("country", ["set", cc])) { [weak self] r, _ in
            if !r.ok { self?.ctl.failure("Could not set the country", r) }
            self?.ctl.refreshStatus(); self?.ctl.refreshScan()
        }
    }
}
