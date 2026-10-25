// SPDX-License-Identifier: GPL-2.0
import Cocoa

private let startCommand = "sudo launchctl bootstrap system /Library/LaunchDaemons/com.awus.awusd.plist"

final class Controller: NSObject, NSMenuDelegate {
    let client: AwusClient
    let net = DispatchQueue(label: "awus.net", attributes: .concurrent)
    var item: NSStatusItem?
    let menu = NSMenu()
    var status = Status(state: .daemonDown("not asked yet"))
    var aps: [AP] = []
    var profiles: [SavedProfile] = []
    var pending: String?                 // text like "Connecting to X" while a join/rf request of ours is in flight
    var menuOpen = false, pollInFlight = false
    var pollTimer: Timer?, animTimer: Timer?
    var animStep = 0
    var statusWin: StatusWindow?

    init(client: AwusClient) { self.client = client; super.init() }

    // MARK: lifecycle
    func start(openMenu: Bool, openStatus: Bool) {
        item = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        menu.delegate = self
        menu.autoenablesItems = false
        item?.menu = menu
        rebuild()
        poll()
        pollTimer = Timer(timeInterval: 2.0, repeats: true) { [weak self] _ in self?.poll() }
        RunLoop.main.add(pollTimer!, forMode: .common)
        if openMenu { DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) { [weak self] in self?.item?.button?.performClick(nil) } }
        if openStatus { DispatchQueue.main.asyncAfter(deadline: .now() + 1.0) { [weak self] in self?.showStatusWindow() } }
    }

    /// Run `work` off the main thread, then `done` on the main thread, also while a menu is being tracked.
    func request(_ line: String, timeout: Int = 15, _ done: @escaping (Reply, Transport) -> Void) {
        net.async {
            let (r, t) = self.client.send(line, timeout: timeout)
            RunLoop.main.perform(inModes: [.default, .eventTracking, .modalPanel]) { done(r, t) }
        }
    }

    // MARK: polling
    func poll() {
        if menuOpen || pollInFlight { return }
        pollInFlight = true
        refreshStatus { [weak self] in self?.pollInFlight = false }
    }

    func refreshStatus(_ done: (() -> Void)? = nil) {
        request("status") { [weak self] r, t in
            guard let self = self else { return }
            self.status = self.interpret(r, t)
            self.refreshUI()
            done?()
        }
    }

    func interpret(_ r: Reply, _ t: Transport) -> Status {
        switch t {
        case .noDaemon: return Status(state: .daemonDown(r.error))
        case .denied: return Status(state: .denied)
        case .timeout: return Status(state: .daemonDown("timeout"))
        case .ok: return r.ok ? Status(r) : Status(state: .daemonDown(r.error))
        }
    }

    func refreshProfiles(_ done: (() -> Void)? = nil) {
        request("profile list") { [weak self] r, _ in
            if r.ok { self?.profiles = r.rows.filter { $0.kind == "profile" }.map { SavedProfile($0.f) } }
            self?.refreshUI(); done?()
        }
    }

    func refreshScan() {
        guard status.daemonUp, status.rfOn else { return }
        request("scan", timeout: 90) { [weak self] r, _ in
            guard let self = self, r.ok else { return }
            self.aps = r.rows.filter { $0.kind == "ap" }.map { AP($0.f) }
            self.refreshUI()
        }
    }

    // MARK: NSMenuDelegate
    func menuWillOpen(_ m: NSMenu) {
        menuOpen = true
        refreshStatus()
        refreshProfiles()
        refreshScan()
    }
    func menuDidClose(_ m: NSMenu) { menuOpen = false }

    // MARK: icon + menu refresh
    func refreshUI() {
        updateIcon()
        rebuild()
        statusWin?.update(status)
        let busy = pending != nil || status.isConnecting
        if busy && animTimer == nil {
            animTimer = Timer(timeInterval: 0.35, repeats: true) { [weak self] _ in self?.animStep += 1; self?.updateIcon() }
            RunLoop.main.add(animTimer!, forMode: .common)
        } else if !busy, let t = animTimer { t.invalidate(); animTimer = nil }
    }

    func iconAndName() -> (NSImage?, String) {
        if pending != nil || status.isConnecting { let l = animStep % 6; let i = barsImage(level: l); i.accessibilityDescription = "connecting (animated bars)"; return (i, "connecting") }
        switch status.state {
        case .daemonDown, .denied: return (symbol("exclamationmark.triangle", "driver not running"), "driver not running (symbol exclamationmark.triangle)")
        case .noDevice: return (symbol("wifi.slash", "no adapter"), "no adapter (symbol wifi.slash)")
        case .rfOff: return (symbol("wifi.slash", "wifi off"), "wifi off (symbol wifi.slash)")
        case .connected:
            let l = bars(forRSSI: status.rssi ?? -100)
            return (barsImage(level: l), "connected bars=\(l)")
        default: return (barsImage(level: 0), "disconnected bars=0")
        }
    }

    func updateIcon() {
        let (img, _) = iconAndName()
        item?.button?.image = img
        item?.button?.toolTip = statusLine().0
    }

    // MARK: menu content
    func statusLine() -> (String, String?) {
        let target = pending ?? status.kv["reconnecting"] ?? status.kv["ssid"]
        if let p = pending { return (p, nil) }
        switch status.state {
        case .daemonDown: return ("AWUS driver is not running", nil)
        case .denied: return ("Not allowed to talk to the AWUS driver", nil)
        case .noDevice: return ("Adapter not plugged in", nil)
        case .rfOff: return ("Wi-Fi is off", nil)
        case .idle:
            if let r = status.kv["reconnecting"] { return ("Reconnecting to \(r)...", nil) }
            return ("Not connected", nil)
        case .scanning, .joining: return ("Connecting" + (target.map { " to \($0)" } ?? "") + "...", nil)
        case .connected:
            var d = [String]()
            if !status.ip.isEmpty { d.append("IP \(status.ip)") }
            if let r = status.rssi { d.append("\(r) dBm") }
            if let c = status.kv["link_channel"], let n = Int(c) { d.append("ch \(n)") }
            return ("Connected to \(status.ssid)", d.joined(separator: "  -  "))
        }
    }

    func disabled(_ title: String, tip: String? = nil) -> NSMenuItem {
        let i = NSMenuItem(title: title, action: nil, keyEquivalent: "")
        i.isEnabled = false; i.toolTip = tip
        return i
    }
    func action(_ title: String, _ sel: Selector, key: String = "") -> NSMenuItem {
        let i = NSMenuItem(title: title, action: sel, keyEquivalent: key)
        i.target = self; i.isEnabled = true
        return i
    }

    func rebuild() {
        menu.removeAllItems()
        let (line, detail) = statusLine()
        let head = disabled(line)
        head.image = iconAndName().0
        menu.addItem(head)
        if let d = detail { menu.addItem(disabled(d)) }
        menu.addItem(.separator())

        switch status.state {
        case .daemonDown, .denied:
            menu.addItem(action("Start driver...", #selector(startDriver)))
        default:
            menu.addItem(action(status.rfOn ? "Turn Wi-Fi Off" : "Turn Wi-Fi On", #selector(toggleRF)))
            menu.addItem(.separator())
            if status.rfOn, status.kv["device"] != "absent" {
                addNetworks()
            } else if !status.rfOn {
                menu.addItem(disabled("Wi-Fi is off"))
            }
            menu.addItem(action("Join Other Network...", #selector(joinOther)))
            let saved = NSMenuItem(title: "Saved Networks", action: nil, keyEquivalent: "")
            saved.submenu = savedMenu()
            menu.addItem(saved)
            menu.addItem(.separator())
            let wps = NSMenuItem(title: "WPS...", action: Features.wps ? #selector(wpsAction) : nil, keyEquivalent: "")
            wps.target = self; wps.isEnabled = Features.wps; wps.toolTip = Features.wps ? nil : notBuiltYet
            menu.addItem(wps)
            let adhoc = NSMenuItem(title: "Create Ad-hoc Network...", action: Features.adhoc ? #selector(adhocAction) : nil, keyEquivalent: "")
            adhoc.target = self; adhoc.isEnabled = Features.adhoc; adhoc.toolTip = Features.adhoc ? nil : notBuiltYet
            menu.addItem(adhoc)
            menu.addItem(.separator())
            menu.addItem(action("Status...", #selector(showStatusWindow)))
        }
        menu.addItem(action("About AWUS WiFi", #selector(about)))
        menu.addItem(.separator())
        menu.addItem(action("Quit", #selector(quit), key: "q"))
    }

    func addNetworks() {
        let h = disabled("Networks"); h.attributedTitle = NSAttributedString(string: "Networks", attributes: [.font: NSFont.menuBarFont(ofSize: 11), .foregroundColor: NSColor.secondaryLabelColor])
        menu.addItem(h)
        // One row per SSID and band (strongest BSSID); hidden networks (empty SSID) are reachable via Join Other.
        var best: [String: AP] = [:]
        for a in aps where !a.ssid.isEmpty { let k = "\(a.ssid)|\(a.is5G)"; if best[k] == nil || best[k]!.rssi < a.rssi { best[k] = a } }
        let list = best.values.sorted { $0.rssi != $1.rssi ? $0.rssi > $1.rssi : $0.ssid < $1.ssid }
        if list.isEmpty { menu.addItem(disabled(aps.isEmpty ? "Scanning..." : "No networks found")); return }
        for a in list.prefix(25) {
            let current = status.isConnected && status.ssid == a.ssid && (status.kv["link_channel"].flatMap { Int($0) }.map { ($0 > 14) == a.is5G } ?? true)
            let it = NSMenuItem(title: a.ssid, action: a.allowed ? #selector(joinAP(_:)) : nil, keyEquivalent: "")
            it.target = self; it.isEnabled = a.allowed; it.representedObject = a
            it.state = current ? .on : .off
            it.image = barsImage(level: bars(forRSSI: a.rssi), lock: a.secured)
            let tag = (a.is5G ? "5G" : "2.4G") + (a.allowed ? "" : " blocked here")
            let s = NSMutableAttributedString(string: a.ssid, attributes: [.font: NSFont.menuFont(ofSize: 0)])
            s.append(NSAttributedString(string: "   " + tag, attributes: [.font: NSFont.menuFont(ofSize: 11), .foregroundColor: NSColor.secondaryLabelColor]))
            it.attributedTitle = s
            it.toolTip = "\(a.sec)  ch \(a.ch)  \(a.rssi) dBm  \(a.bssid)"
            menu.addItem(it)
        }
    }

    func savedMenu() -> NSMenu {
        let m = NSMenu(); m.autoenablesItems = false
        if profiles.isEmpty { m.addItem(disabled("None")); return m }
        for p in profiles {
            let it = NSMenuItem(title: p.ssid, action: nil, keyEquivalent: "")
            let sub = NSMenu(); sub.autoenablesItems = false
            let j = action("Join", #selector(joinSaved(_:))); j.representedObject = p.ssid; sub.addItem(j)
            let aj = action("Auto-join", #selector(toggleAutojoin(_:))); aj.representedObject = p; aj.state = p.autojoin ? .on : .off; sub.addItem(aj)
            sub.addItem(.separator())
            let rm = action("Remove", #selector(removeProfile(_:))); rm.representedObject = p.ssid; sub.addItem(rm)
            it.submenu = sub
            m.addItem(it)
        }
        return m
    }

    // MARK: actions
    @objc func quit() { NSApp.terminate(nil) }

    @objc func startDriver() {
        var text = "The AWUS driver (awusd) is not running or not reachable at \(client.path).\n\nIf you installed AWUS-WiFi-Driver.pkg it should start by itself. To start it now, run this in Terminal (it asks for your password, this app never does that for you):\n\n\(startCommand)"
        if case .denied = status.state { text = "The driver is running but refuses this user. Its launchd plist must pass --sock-uid with your user id (the installer does this for the user who installed it).\n\nTo fix by hand, edit /Library/LaunchDaemons/com.awus.awusd.plist, add the two arguments --sock-uid \(getuid()) and reload with:\n\nsudo launchctl bootout system/com.awus.awusd; \(startCommand)" }
        let a = NSAlert(); a.messageText = "Start driver"; a.informativeText = text
        a.addButton(withTitle: "Copy Command"); a.addButton(withTitle: "Close")
        NSApp.activate(ignoringOtherApps: true)
        if a.runModal() == .alertFirstButtonReturn { NSPasteboard.general.clearContents(); NSPasteboard.general.setString(startCommand, forType: .string) }
    }

    func failure(_ title: String, _ r: Reply) {
        let a = NSAlert(); a.messageText = title; a.informativeText = r.error.isEmpty ? "unknown error" : r.error; a.alertStyle = .warning
        NSApp.activate(ignoringOtherApps: true); a.runModal()
    }

    @objc func toggleRF() {
        let on = !status.rfOn
        pending = on ? "Turning Wi-Fi on..." : "Turning Wi-Fi off..."
        refreshUI()
        request("rf " + (on ? "on" : "off"), timeout: 60) { [weak self] r, _ in
            self?.pending = nil
            if !r.ok { self?.failure("Could not turn Wi-Fi \(on ? "on" : "off")", r) }
            self?.refreshStatus()
        }
    }

    @objc func joinAP(_ s: NSMenuItem) {
        guard let ap = s.representedObject as? AP else { return }
        if profiles.contains(where: { $0.ssid == ap.ssid }) { doJoin(ssid: ap.ssid, key: nil, sec: nil, hidden: false, remember: false); return }
        if !ap.secured { doJoin(ssid: ap.ssid, key: nil, sec: "open", hidden: false, remember: false); return }
        if ap.sec.contains("802.1X") { joinSheet(prefill: ap.ssid, enterprise: true); return }
        guard let r = askPassword(ssid: ap.ssid, security: ap.sec) else { return }
        doJoin(ssid: ap.ssid, key: r.key, sec: nil, hidden: false, remember: r.remember)
    }

    @objc func joinSaved(_ s: NSMenuItem) {
        if let ssid = s.representedObject as? String { doJoin(ssid: ssid, key: nil, sec: nil, hidden: false, remember: false) }
    }

    func doJoin(ssid: String, key: String?, sec: String?, hidden: Bool, remember: Bool, extra: [(String, String)] = []) {
        var opts: [(String, String)] = [("ssid", ssid)] + extra
        if let k = key, !k.isEmpty { opts.append(("key", k)) }
        if let s = sec { opts.append(("sec", s)) }
        if hidden { opts.append(("hidden", "1")) }
        pending = "Connecting to \(ssid)..."
        refreshUI()
        request(AwusClient.line("join", [], opts), timeout: 120) { [weak self] r, _ in
            guard let self = self else { return }
            self.pending = nil
            if !r.ok { self.failure("Could not join \"\(ssid)\"", r) }
            else if remember {
                var p: [(String, String)] = [("ssid", ssid), ("security", sec ?? "auto")]
                if let k = key, !k.isEmpty { p.append(("key", k)) }
                if hidden { p.append(("hidden", "1")) }
                p += extra
                self.request(AwusClient.line("profile", ["add"], p)) { r2, _ in
                    if !r2.ok { self.failure("Joined, but could not save the network", r2) }
                    self.refreshProfiles()
                }
            }
            self.refreshStatus()
        }
    }

    @objc func joinOther() { joinSheet(prefill: nil, enterprise: false) }

    // The Join Other sheet. "802.1X (Enterprise)" shows the extra fields below; they are ignored for other security types.
    // Certificates are PEM file paths (no PKCS#12). Loopback-tested only: no Enterprise access point has been tried on air.
    func joinSheet(prefill: String?, enterprise: Bool) {
        func field(_ ph: String) -> NSTextField { let f = NSTextField(frame: NSRect(x: 0, y: 0, width: 260, height: 22)); f.placeholderString = ph; return f }
        let ssid = field("Network name"); if let p = prefill { ssid.stringValue = p }
        let sec = NSPopUpButton(frame: NSRect(x: 0, y: 0, width: 260, height: 24), pullsDown: false)
        let secs: [(String, String)] = [("Detect automatically", "auto"), ("Open (no password)", "open"), ("WPA / WPA2 Personal", "wpa2"), ("WPA Personal (older)", "wpa"), ("WEP (open)", "wep"), ("WEP (shared key)", "wep-shared"), ("802.1X (WPA2 Enterprise)", "eap")]
        sec.addItems(withTitles: secs.map { $0.0 })
        if enterprise { sec.selectItem(at: secs.count - 1) }
        let hidden = NSButton(checkboxWithTitle: "Hidden network", target: nil, action: nil)
        let key = NSSecureTextField(frame: NSRect(x: 0, y: 0, width: 260, height: 22)); key.placeholderString = "Password"
        let methods: [(String, String)] = [("PEAP", "peap"), ("TTLS", "ttls"), ("TLS (client certificate)", "tls")]
        let method = NSPopUpButton(frame: NSRect(x: 0, y: 0, width: 260, height: 24), pullsDown: false); method.addItems(withTitles: methods.map { $0.0 })
        let inners: [(String, String)] = [("MS-CHAPv2", "mschapv2"), ("PAP", "pap")]
        let inner = NSPopUpButton(frame: NSRect(x: 0, y: 0, width: 260, height: 24), pullsDown: false); inner.addItems(withTitles: inners.map { $0.0 })
        let identity = field("User name (identity)"), anon = field("Anonymous identity (optional)")
        let ca = field("CA certificate file (.pem)"), cert = field("Client certificate file (.pem, TLS only)"), ckey = field("Client key file (.pem, TLS only)")
        let server = field("Server name to require (optional)")
        let insecure = NSButton(checkboxWithTitle: "Do not verify the server certificate (unsafe)", target: nil, action: nil)
        let rem = NSButton(checkboxWithTitle: "Remember this network", target: nil, action: nil); rem.state = .on
        let form = stack([label("Network name"), ssid, label("Security"), sec, hidden, label("Password"), key,
                          label("802.1X only: method, inner method, identity, files (PEM only, TLS 1.2)"), method, inner, identity, anon, ca, cert, ckey, server, insecure, rem])
        let a = NSAlert(); a.messageText = "Join Other Network"; a.informativeText = "Enter the details of the network."
        a.accessoryView = form; a.addButton(withTitle: "Join"); a.addButton(withTitle: "Cancel")
        a.window.initialFirstResponder = ssid
        NSApp.activate(ignoringOtherApps: true)
        guard a.runModal() == .alertFirstButtonReturn, !ssid.stringValue.isEmpty else { return }
        let s = secs[sec.indexOfSelectedItem].1
        var extra: [(String, String)] = []
        if s == "eap" {
            let m = methods[method.indexOfSelectedItem].1
            guard !identity.stringValue.isEmpty else { failureText("802.1X needs a user name (identity)"); return }
            extra = [("eap_method", m), ("eap_inner", inners[inner.indexOfSelectedItem].1), ("identity", identity.stringValue)]
            if !anon.stringValue.isEmpty { extra.append(("anon", anon.stringValue)) }
            if !ca.stringValue.isEmpty { extra.append(("ca", ca.stringValue)) }
            if m == "tls" { if !cert.stringValue.isEmpty { extra.append(("cert", cert.stringValue)) }; if !ckey.stringValue.isEmpty { extra.append(("client_key", ckey.stringValue)) } }
            if !server.stringValue.isEmpty { extra.append(("server_name", server.stringValue)) }
            if insecure.state == .on { extra.append(("insecure", "1")) }
        }
        doJoin(ssid: ssid.stringValue, key: s == "open" ? nil : key.stringValue, sec: s, hidden: hidden.state == .on, remember: rem.state == .on, extra: extra)
    }

    func failureText(_ t: String) {
        let a = NSAlert(); a.messageText = t; a.runModal()
    }

    func askPassword(ssid: String, security: String) -> (key: String, remember: Bool)? {
        let key = NSSecureTextField(frame: NSRect(x: 0, y: 0, width: 260, height: 22)); key.placeholderString = "Password"
        let rem = NSButton(checkboxWithTitle: "Remember this network", target: nil, action: nil); rem.state = .on
        let a = NSAlert(); a.messageText = "Join \"\(ssid)\""; a.informativeText = "This network (\(security)) needs a password."
        a.accessoryView = stack([key, rem]); a.addButton(withTitle: "Join"); a.addButton(withTitle: "Cancel")
        a.window.initialFirstResponder = key
        NSApp.activate(ignoringOtherApps: true)
        guard a.runModal() == .alertFirstButtonReturn, !key.stringValue.isEmpty else { return nil }
        return (key.stringValue, rem.state == .on)
    }

    func label(_ s: String) -> NSTextField { let l = NSTextField(labelWithString: s); l.font = .systemFont(ofSize: 11); l.textColor = .secondaryLabelColor; return l }
    func stack(_ v: [NSView]) -> NSStackView {
        let s = NSStackView(views: v); s.orientation = .vertical; s.alignment = .leading; s.spacing = 6
        s.frame = NSRect(origin: .zero, size: s.fittingSize); return s
    }

    @objc func toggleAutojoin(_ s: NSMenuItem) {
        guard let p = s.representedObject as? SavedProfile else { return }
        request(AwusClient.line("profile", ["autojoin", p.autojoin ? "off" : "on"], [("ssid", p.ssid)])) { [weak self] r, _ in
            if !r.ok { self?.failure("Could not change auto-join", r) }
            self?.refreshProfiles()
        }
    }

    @objc func removeProfile(_ s: NSMenuItem) {
        guard let ssid = s.representedObject as? String else { return }
        request(AwusClient.line("profile", ["remove"], [("ssid", ssid)])) { [weak self] r, _ in
            if !r.ok { self?.failure("Could not remove the network", r) }
            self?.refreshProfiles()
        }
    }

    /// WPS sheet: push button (press the router's WPS button first, then Start; you have about 2 minutes) or the router's PIN.
    @objc func wpsAction() {
        let mode = NSSegmentedControl(labels: ["Push button", "PIN"], trackingMode: .selectOne, target: nil, action: nil)
        mode.selectedSegment = 0
        let net = NSPopUpButton(frame: NSRect(x: 0, y: 0, width: 260, height: 24), pullsDown: false)
        let names = Array(Set(aps.filter { !$0.ssid.isEmpty }.map { $0.ssid })).sorted()
        net.addItems(withTitles: ["Any router with its button pressed"] + names)
        let pin = NSTextField(frame: NSRect(x: 0, y: 0, width: 260, height: 22)); pin.placeholderString = "Router PIN (4 or 8 digits)"
        let a = NSAlert(); a.messageText = "WPS"
        a.informativeText = "Push button: press the WPS button on your router, then click Start (within 2 minutes).\nPIN: pick the router and type the PIN printed on it."
        a.accessoryView = stack([mode, label("Network"), net, label("PIN (PIN mode only)"), pin])
        a.addButton(withTitle: "Start"); a.addButton(withTitle: "Cancel")
        NSApp.activate(ignoringOtherApps: true)
        guard a.runModal() == .alertFirstButtonReturn else { return }
        var opts: [(String, String)] = []
        let chosen = net.indexOfSelectedItem > 0 ? net.titleOfSelectedItem : nil
        if let c = chosen { opts.append(("ssid", c)) }
        let isPin = mode.selectedSegment == 1
        if isPin {
            let p = pin.stringValue.trimmingCharacters(in: .whitespaces)
            guard !p.isEmpty, chosen != nil else {
                let e = NSAlert(); e.messageText = "WPS PIN needs a network and a PIN"; e.runModal(); return
            }
            opts.append(("pin", p))
        }
        pending = "WPS: talking to the router..."
        refreshUI()
        request(AwusClient.line("wps", [isPin ? "pin" : "pbc"], opts), timeout: 180) { [weak self] r, _ in
            guard let self = self else { return }
            self.pending = nil
            if !r.ok { self.failure("WPS failed", r) }
            else {
                let n = NSAlert(); n.messageText = "WPS worked"
                n.informativeText = "Saved \"\(r.kv["ssid"] ?? "")\" (\(r.kv["security"] ?? "")). It will connect automatically."
                NSApp.activate(ignoringOtherApps: true); n.runModal()
            }
            self.refreshProfiles(); self.refreshStatus()
        }
    }
    @objc func adhocAction() {
        let ssid = NSTextField(frame: NSRect(x: 0, y: 0, width: 260, height: 22)); ssid.placeholderString = "Network name"
        let band = NSPopUpButton(frame: NSRect(x: 0, y: 0, width: 260, height: 24), pullsDown: false)
        let chans: [(String, Int)] = [("2.4 GHz  channel 1", 1), ("2.4 GHz  channel 6", 6), ("2.4 GHz  channel 11", 11), ("5 GHz  channel 36", 36), ("5 GHz  channel 149", 149)]
        band.addItems(withTitles: chans.map { $0.0 }); band.selectItem(at: 2)
        let key = NSSecureTextField(frame: NSRect(x: 0, y: 0, width: 260, height: 22)); key.placeholderString = "WEP key: 5 or 13 characters (blank = open)"
        let a = NSAlert(); a.messageText = "Create Ad-hoc Network"
        a.informativeText = "Other devices can see this network. Only the announcement (beacons) works for now; sharing the internet or a connection over it is not built yet."
        a.accessoryView = stack([label("Network name"), ssid, label("Channel"), band, label("Password (optional, WEP)"), key])
        a.addButton(withTitle: "Create"); a.addButton(withTitle: "Cancel")
        a.window.initialFirstResponder = ssid
        NSApp.activate(ignoringOtherApps: true)
        guard a.runModal() == .alertFirstButtonReturn, !ssid.stringValue.isEmpty else { return }
        var opts: [(String, String)] = [("ssid", ssid.stringValue), ("ch", String(chans[band.indexOfSelectedItem].1))]
        if !key.stringValue.isEmpty { opts.append(("key", key.stringValue)) }
        pending = "Creating ad-hoc network..."
        refreshUI()
        request(AwusClient.line("adhoc", ["create"], opts)) { [weak self] r, _ in
            guard let self = self else { return }
            self.pending = nil
            if !r.ok { self.failure("Could not create the ad-hoc network", r) }
            else {
                let n = NSAlert(); n.messageText = "Ad-hoc network is on"
                n.informativeText = "\"\(r.kv["ssid"] ?? "")\" on channel \(r.kv["channel"] ?? ""). Use Disconnect to stop it."
                NSApp.activate(ignoringOtherApps: true); n.runModal()
            }
            self.refreshStatus()
        }
    }

    @objc func showStatusWindow() {
        if statusWin == nil { statusWin = StatusWindow(controller: self) }
        statusWin?.update(status)
        statusWin?.loadCountries()
        NSApp.activate(ignoringOtherApps: true)
        statusWin?.window.makeKeyAndOrderFront(nil)
    }

    @objc func about() {
        let a = NSAlert(); a.messageText = "AWUS WiFi \(appVersion)"
        let drv = status.daemonUp ? "awusd \(status.kv["version"] ?? "(version not reported)")" : "awusd not running"
        a.informativeText = "Menu-bar front end for the userspace driver of the Alfa AWUS036ACS (RTL8811AU).\nDriver: \(drv)\nSocket: \(client.path)\n\nGPLv2. Nothing here is from the vendor app."
        NSApp.activate(ignoringOtherApps: true); a.runModal()
    }

    // MARK: --dump-menu support
    func loadSync() {
        let (r, t) = client.send("status")
        status = interpret(r, t)
        guard status.daemonUp else { return }
        let (p, _) = client.send("profile list")
        if p.ok { profiles = p.rows.filter { $0.kind == "profile" }.map { SavedProfile($0.f) } }
        if status.rfOn { let (s, _) = client.send("scan", timeout: 90); if s.ok { aps = s.rows.filter { $0.kind == "ap" }.map { AP($0.f) } } }
    }

    func dumpMenu() {
        rebuild()
        let (img, name) = iconAndName()
        print("status icon: \(name)  [\(img?.accessibilityDescription ?? "")]")
        print("tooltip: \(statusLine().0)")
        print("menu:")
        func walk(_ m: NSMenu, _ d: Int) {
            let pad = String(repeating: "  ", count: d)
            for it in m.items {
                if it.isSeparatorItem { print(pad + "----------"); continue }
                var s = pad + (it.state == .on ? "[x] " : "[ ] ") + (it.attributedTitle?.string ?? it.title)
                if let i = it.image?.accessibilityDescription { s += "   <\(i)>" }
                if !it.isEnabled { s += "   (disabled)" }
                if let t = it.toolTip { s += "   tooltip: \"\(t)\"" }
                if !it.keyEquivalent.isEmpty { s += "   key: Cmd-\(it.keyEquivalent)" }
                print(s)
                if let sub = it.submenu { walk(sub, d + 1) }
            }
        }
        walk(menu, 1)
    }
}
