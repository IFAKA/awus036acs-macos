// SPDX-License-Identifier: GPL-2.0
// Template images drawn here or taken from SF Symbols; nothing from the vendor app.
import Cocoa

func symbol(_ name: String, _ desc: String? = nil, pt: CGFloat = 14) -> NSImage? {
    let cfg = NSImage.SymbolConfiguration(pointSize: pt, weight: .regular)
    let i = NSImage(systemSymbolName: name, accessibilityDescription: desc)?.withSymbolConfiguration(cfg)
    i?.isTemplate = true
    return i
}

/// Five ascending bars; the first `level` are solid, the rest faint. `lock` adds a padlock on the right (secured network).
func barsImage(level: Int, lock: Bool = false, height: CGFloat = 14) -> NSImage {
    let bw: CGFloat = 3, gap: CGFloat = 1.5
    let barsW = 5 * bw + 4 * gap
    let w = barsW + (lock ? 4 + height * 0.8 : 0)
    let img = NSImage(size: NSSize(width: w, height: height), flipped: false) { _ in
        for i in 0..<5 {
            let h = 3 + (height - 3) * CGFloat(i) / 4
            let r = NSRect(x: CGFloat(i) * (bw + gap), y: 0, width: bw, height: h)
            NSColor.black.withAlphaComponent(i < level ? 1.0 : 0.28).setFill()
            NSBezierPath(roundedRect: r, xRadius: 0.8, yRadius: 0.8).fill()
        }
        if lock, let l = symbol("lock.fill", pt: height * 0.8) {
            let s = l.size
            l.draw(in: NSRect(x: barsW + 4, y: (height - s.height) / 2, width: s.width, height: s.height))
        }
        return true
    }
    img.isTemplate = true
    img.accessibilityDescription = "bars \(level)" + (lock ? " lock" : "")
    return img
}
