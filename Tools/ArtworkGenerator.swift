// Renders Argus's app icon, mascot images and menu bar glyph as vector art.
// Usage: swift Tools/ArtworkGenerator.swift <Assets.xcassets path> [preview dir]

import AppKit
import CoreGraphics
import ImageIO
import UniformTypeIdentifiers

// MARK: - Palette

func rgb(_ hex: UInt32, _ alpha: CGFloat = 1) -> CGColor {
    CGColor(srgbRed: CGFloat(hex >> 16 & 0xFF) / 255, green: CGFloat(hex >> 8 & 0xFF) / 255, blue: CGFloat(hex & 0xFF) / 255, alpha: alpha)
}

enum Palette {
    static let skyTop = rgb(0x5B4BD6)
    static let skyBottom = rgb(0x1B1756)
    static let glow = rgb(0x9C8CFF, 0.55)
    static let featherBase = rgb(0x0F7F8C)
    static let featherTip = rgb(0x36D9A8)
    static let featherEdge = rgb(0x9CF2D2, 0.55)
    static let gold = rgb(0xF8C94C)
    static let ringTeal = rgb(0x0B4F6C)
    static let bodyLight = rgb(0xFBF8FF)
    static let bodyMid = rgb(0xDCD2FF)
    static let bodyDark = rgb(0xA996F2)
    static let ink = rgb(0x231A4F)
    static let irisTop = rgb(0x43B4FF)
    static let irisBottom = rgb(0x5B3BE0)
    static let cheek = rgb(0xFF7AAE, 0.55)
}

// MARK: - Geometry helpers

func superellipse(_ rect: CGRect, exponent n: CGFloat = 5) -> CGPath {
    let path = CGMutablePath()
    let a = rect.width / 2, b = rect.height / 2
    for i in 0...720 {
        let t = CGFloat(i) / 720 * 2 * .pi
        let c = cos(t), s = sin(t)
        let point = CGPoint(x: rect.midX + a * copysign(pow(abs(c), 2 / n), c),
                            y: rect.midY + b * copysign(pow(abs(s), 2 / n), s))
        i == 0 ? path.move(to: point) : path.addLine(to: point)
    }
    path.closeSubpath()
    return path
}

func circle(_ center: CGPoint, _ r: CGFloat) -> CGRect { CGRect(x: center.x - r, y: center.y - r, width: 2 * r, height: 2 * r) }

let space = CGColorSpace(name: CGColorSpace.sRGB)!

func linearGradient(_ ctx: CGContext, _ colors: [CGColor], from: CGPoint, to: CGPoint) {
    let gradient = CGGradient(colorsSpace: space, colors: colors as CFArray, locations: nil)!
    ctx.drawLinearGradient(gradient, start: from, end: to, options: [.drawsBeforeStartLocation, .drawsAfterEndLocation])
}

func radialGradient(_ ctx: CGContext, _ colors: [CGColor], center: CGPoint, radius: CGFloat, focus: CGPoint? = nil) {
    let gradient = CGGradient(colorsSpace: space, colors: colors as CFArray, locations: nil)!
    ctx.drawRadialGradient(gradient, startCenter: focus ?? center, startRadius: 0, endCenter: center, endRadius: radius,
                           options: [.drawsAfterEndLocation])
}

// MARK: - Pieces

/// A cute eye: white, gradient iris, big pupil, two sparkles. `look` shifts the iris (unit-ish vector).
func drawEye(_ ctx: CGContext, at c: CGPoint, radius r: CGFloat, look: CGVector = .zero, asleep: Bool = false, outline: CGFloat = 0.09) {
    if asleep {
        ctx.saveGState()
        ctx.setStrokeColor(Palette.ink)
        ctx.setLineWidth(max(1, r * 0.2))
        ctx.setLineCap(.round)
        let path = CGMutablePath()
        path.move(to: CGPoint(x: c.x - r * 0.75, y: c.y))
        path.addQuadCurve(to: CGPoint(x: c.x + r * 0.75, y: c.y), control: CGPoint(x: c.x, y: c.y + r * 0.7))
        ctx.addPath(path)
        ctx.strokePath()
        ctx.restoreGState()
        return
    }
    ctx.saveGState()
    // Outline gives definition at small sizes.
    ctx.setFillColor(Palette.ink)
    ctx.fillEllipse(in: circle(c, r * (1 + outline)))
    ctx.addEllipse(in: circle(c, r))
    ctx.clip()
    linearGradient(ctx, [rgb(0xFFFFFF), rgb(0xE6E1FA)], from: CGPoint(x: c.x, y: c.y - r), to: CGPoint(x: c.x, y: c.y + r))
    let irisCenter = CGPoint(x: c.x + look.dx * r * 0.22, y: c.y + look.dy * r * 0.22 + r * 0.06)
    let irisR = r * 0.68
    ctx.saveGState()
    ctx.addEllipse(in: circle(irisCenter, irisR))
    ctx.clip()
    linearGradient(ctx, [Palette.irisTop, Palette.irisBottom], from: CGPoint(x: irisCenter.x, y: irisCenter.y - irisR),
                   to: CGPoint(x: irisCenter.x, y: irisCenter.y + irisR))
    ctx.restoreGState()
    ctx.setFillColor(Palette.ink)
    ctx.fillEllipse(in: circle(irisCenter, r * 0.4))
    ctx.restoreGState()
    ctx.setFillColor(rgb(0xFFFFFF))
    ctx.fillEllipse(in: circle(CGPoint(x: irisCenter.x - r * 0.24, y: irisCenter.y - r * 0.26), r * 0.22))
    ctx.fillEllipse(in: circle(CGPoint(x: irisCenter.x + r * 0.22, y: irisCenter.y + r * 0.2), r * 0.1))
}

/// One peacock feather pointing "up" (−y), rotated about `base`, ending in a watching eye.
func drawFeather(_ ctx: CGContext, base: CGPoint, angle: CGFloat, length L: CGFloat, look: CGVector, asleep: Bool) {
    ctx.saveGState()
    ctx.translateBy(x: base.x, y: base.y)
    ctx.rotate(by: angle)

    ctx.setStrokeColor(Palette.gold.copy(alpha: 0.7)!)
    ctx.setLineWidth(L * 0.018)
    ctx.setLineCap(.round)
    ctx.move(to: CGPoint(x: 0, y: -L * 0.1))
    ctx.addLine(to: CGPoint(x: 0, y: -L * 0.62))
    ctx.strokePath()

    let w = L * 0.2
    let vane = CGMutablePath()
    vane.move(to: CGPoint(x: 0, y: -L * 0.36))
    vane.addCurve(to: CGPoint(x: 0, y: -L * 1.08), control1: CGPoint(x: w * 1.25, y: -L * 0.58), control2: CGPoint(x: w * 1.05, y: -L * 1.0))
    vane.addCurve(to: CGPoint(x: 0, y: -L * 0.36), control1: CGPoint(x: -w * 1.05, y: -L * 1.0), control2: CGPoint(x: -w * 1.25, y: -L * 0.58))
    ctx.saveGState()
    ctx.addPath(vane)
    ctx.clip()
    linearGradient(ctx, [Palette.featherBase, Palette.featherTip], from: CGPoint(x: 0, y: -L * 0.36), to: CGPoint(x: 0, y: -L * 1.05))
    ctx.restoreGState()
    ctx.addPath(vane)
    ctx.setStrokeColor(Palette.featherEdge)
    ctx.setLineWidth(L * 0.012)
    ctx.strokePath()

    let spot = CGPoint(x: 0, y: -L * 0.82)
    ctx.setFillColor(Palette.gold)
    ctx.fillEllipse(in: circle(spot, L * 0.15))
    ctx.setFillColor(Palette.ringTeal)
    ctx.fillEllipse(in: circle(spot, L * 0.125))
    // Counter-rotate so every eye is upright and they look where we want.
    ctx.translateBy(x: spot.x, y: spot.y)
    ctx.rotate(by: -angle)
    drawEye(ctx, at: .zero, radius: L * 0.1, look: look, asleep: asleep, outline: 0.06)
    ctx.restoreGState()
}

/// The creature (no background), drawn in a 1024-unit space centred at (512, 600).
func drawArgus(_ ctx: CGContext, asleep: Bool, detail: Bool) {
    let bodyCenter = CGPoint(x: 512, y: 655)

    // Peacock fan.
    let angles: [CGFloat] = [-68, -45, -22.5, 0, 22.5, 45, 68]
    let looks: [CGVector] = [.init(dx: 0.6, dy: 0.2), .init(dx: 0.5, dy: 0.4), .init(dx: 0.2, dy: 0.5), .init(dx: 0, dy: 0.5),
                             .init(dx: -0.2, dy: 0.5), .init(dx: -0.5, dy: 0.4), .init(dx: -0.6, dy: 0.2)]
    for (i, degrees) in angles.enumerated() {
        let length: CGFloat = abs(degrees) > 60 ? 330 : abs(degrees) > 40 ? 365 : 390
        drawFeather(ctx, base: CGPoint(x: 512, y: 640), angle: degrees * .pi / 180, length: length, look: looks[i], asleep: asleep)
    }

    // Feet.
    ctx.setFillColor(Palette.bodyDark)
    for x in [448.0, 576.0] { ctx.fillEllipse(in: CGRect(x: x - 48, y: 818, width: 96, height: 50)) }

    // Ear tufts.
    for side: CGFloat in [-1, 1] {
        let tuft = CGMutablePath()
        tuft.move(to: CGPoint(x: 512 + side * 95, y: 505))
        tuft.addQuadCurve(to: CGPoint(x: 512 + side * 182, y: 430), control: CGPoint(x: 512 + side * 120, y: 440))
        tuft.addQuadCurve(to: CGPoint(x: 512 + side * 190, y: 560), control: CGPoint(x: 512 + side * 200, y: 500))
        tuft.closeSubpath()
        ctx.saveGState()
        ctx.addPath(tuft)
        ctx.clip()
        linearGradient(ctx, [Palette.bodyDark, Palette.bodyLight], from: CGPoint(x: 512 + side * 185, y: 435), to: CGPoint(x: 512 + side * 110, y: 540))
        ctx.restoreGState()
    }

    // Body with soft shading.
    let bodyRect = CGRect(x: bodyCenter.x - 222, y: bodyCenter.y - 195, width: 444, height: 390)
    ctx.saveGState()
    ctx.setShadow(offset: CGSize(width: 0, height: 14), blur: 28, color: rgb(0x0B0830, 0.45))
    ctx.setFillColor(Palette.bodyMid)
    ctx.fillEllipse(in: bodyRect)
    ctx.restoreGState()
    ctx.saveGState()
    ctx.addEllipse(in: bodyRect)
    ctx.clip()
    radialGradient(ctx, [Palette.bodyLight, Palette.bodyMid, Palette.bodyDark], center: CGPoint(x: 512, y: 640), radius: 300,
                   focus: CGPoint(x: 440, y: 540))
    ctx.setFillColor(rgb(0xFFFFFF, 0.45))
    ctx.fillEllipse(in: CGRect(x: 512 - 130, y: 690, width: 260, height: 170))
    ctx.restoreGState()

    // Face.
    drawEye(ctx, at: CGPoint(x: 440, y: 640), radius: 64, look: CGVector(dx: 0.15, dy: 0.1), asleep: asleep)
    drawEye(ctx, at: CGPoint(x: 584, y: 640), radius: 64, look: CGVector(dx: 0.15, dy: 0.1), asleep: asleep)
    drawEye(ctx, at: CGPoint(x: 512, y: 540), radius: 42, look: CGVector(dx: 0.15, dy: 0.15), asleep: asleep)

    ctx.setFillColor(Palette.cheek)
    ctx.fillEllipse(in: CGRect(x: 366, y: 694, width: 70, height: 40))
    ctx.fillEllipse(in: CGRect(x: 588, y: 694, width: 70, height: 40))

    ctx.setStrokeColor(Palette.ink)
    ctx.setLineWidth(10)
    ctx.setLineCap(.round)
    ctx.setLineJoin(.round)
    let mouth = CGMutablePath()
    mouth.move(to: CGPoint(x: 486, y: 716))
    mouth.addQuadCurve(to: CGPoint(x: 512, y: 722), control: CGPoint(x: 498, y: 734))
    mouth.addQuadCurve(to: CGPoint(x: 538, y: 716), control: CGPoint(x: 526, y: 734))
    ctx.addPath(mouth)
    ctx.strokePath()

    if asleep, detail {
        let font = NSFont.systemFont(ofSize: 74, weight: .heavy)
        drawText(ctx, "z", at: CGPoint(x: 690, y: 470), font: font, color: rgb(0xFFFFFF, 0.95))
        drawText(ctx, "z", at: CGPoint(x: 745, y: 405), font: NSFont.systemFont(ofSize: 52, weight: .heavy), color: rgb(0xFFFFFF, 0.8))
    }
}

func drawText(_ ctx: CGContext, _ text: String, at point: CGPoint, font: NSFont, color: CGColor) {
    let attributed = NSAttributedString(string: text, attributes: [.font: font, .foregroundColor: NSColor(cgColor: color)!])
    let line = CTLineCreateWithAttributedString(attributed)
    ctx.saveGState()
    ctx.textMatrix = CGAffineTransform(scaleX: 1, y: -1) // the context is flipped
    ctx.textPosition = point
    CTLineDraw(line, ctx)
    ctx.restoreGState()
}

func drawIcon(_ ctx: CGContext, detail: Bool) {
    let tile = CGRect(x: 100, y: 100, width: 824, height: 824)
    let shape = superellipse(tile)

    ctx.saveGState()
    ctx.setShadow(offset: CGSize(width: 0, height: 12), blur: 24, color: rgb(0x000000, 0.35))
    ctx.addPath(shape)
    ctx.setFillColor(Palette.skyBottom)
    ctx.fillPath()
    ctx.restoreGState()

    ctx.saveGState()
    ctx.addPath(shape)
    ctx.clip()
    linearGradient(ctx, [Palette.skyTop, Palette.skyBottom], from: CGPoint(x: 512, y: 100), to: CGPoint(x: 512, y: 924))
    radialGradient(ctx, [Palette.glow, rgb(0x9C8CFF, 0)], center: CGPoint(x: 512, y: 560), radius: 430)
    if detail {
        var generator = SeededRandom(seed: 7)
        for _ in 0..<26 {
            let p = CGPoint(x: 140 + generator.next() * 744, y: 130 + generator.next() * 300)
            let r = 2 + generator.next() * 4
            ctx.setFillColor(rgb(0xFFFFFF, 0.35 + generator.next() * 0.5))
            ctx.fillEllipse(in: circle(p, r))
        }
    }
    drawArgus(ctx, asleep: false, detail: detail)
    // A gentle top sheen.
    linearGradient(ctx, [rgb(0xFFFFFF, 0.14), rgb(0xFFFFFF, 0)], from: CGPoint(x: 512, y: 100), to: CGPoint(x: 512, y: 420))
    ctx.restoreGState()

    ctx.addPath(shape)
    ctx.setStrokeColor(rgb(0xFFFFFF, 0.18))
    ctx.setLineWidth(3)
    ctx.strokePath()
}

struct SeededRandom {
    var state: UInt64
    init(seed: UInt64) { state = seed }
    mutating func next() -> CGFloat {
        state = state &* 6364136223846793005 &+ 1442695040888963407
        return CGFloat(state >> 33) / CGFloat(1 << 31)
    }
}

// MARK: - Output

func render(pixels: Int, _ draw: (CGContext) -> Void) -> CGImage {
    let ctx = CGContext(data: nil, width: pixels, height: pixels, bitsPerComponent: 8, bytesPerRow: 0, space: space,
                        bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)!
    ctx.interpolationQuality = .high
    ctx.setShouldAntialias(true)
    let scale = CGFloat(pixels) / 1024
    ctx.translateBy(x: 0, y: CGFloat(pixels))
    ctx.scaleBy(x: scale, y: -scale)
    draw(ctx)
    return ctx.makeImage()!
}

func writePNG(_ image: CGImage, to url: URL) {
    let destination = CGImageDestinationCreateWithURL(url as CFURL, UTType.png.identifier as CFString, 1, nil)!
    CGImageDestinationAddImage(destination, image, nil)
    CGImageDestinationFinalize(destination)
}

func writeJSON(_ object: Any, to url: URL) {
    let data = try! JSONSerialization.data(withJSONObject: object, options: [.prettyPrinted, .sortedKeys])
    try! data.write(to: url)
}

/// 18 pt template glyph for the menu bar: the creature's silhouette with three eye holes.
func writeMenuBarGlyph(to url: URL) {
    var box = CGRect(x: 0, y: 0, width: 18, height: 18)
    let ctx = CGContext(url as CFURL, mediaBox: &box, nil)!
    ctx.beginPDFPage(nil)
    ctx.translateBy(x: 0, y: 18)
    ctx.scaleBy(x: 1, y: -1)
    ctx.setFillColor(rgb(0x000000))
    // Ear tufts.
    let ears = CGMutablePath()
    ears.move(to: CGPoint(x: 4.2, y: 6.0)); ears.addLine(to: CGPoint(x: 2.2, y: 1.6)); ears.addLine(to: CGPoint(x: 7.4, y: 4.6)); ears.closeSubpath()
    ears.move(to: CGPoint(x: 13.8, y: 6.0)); ears.addLine(to: CGPoint(x: 15.8, y: 1.6)); ears.addLine(to: CGPoint(x: 10.6, y: 4.6)); ears.closeSubpath()
    ctx.addPath(ears)
    ctx.fillPath()
    // Body with the eyes punched out (even-odd), then pupils put back in.
    let body = CGMutablePath()
    body.addEllipse(in: CGRect(x: 1.6, y: 4.6, width: 14.8, height: 12.2))
    for (center, r) in [(CGPoint(x: 6.2, y: 11.6), 2.25), (CGPoint(x: 11.8, y: 11.6), 2.25), (CGPoint(x: 9, y: 7.6), 1.6)] {
        body.addEllipse(in: circle(center, r))
    }
    ctx.addPath(body)
    ctx.fillPath(using: .evenOdd)
    for (center, r) in [(CGPoint(x: 6.5, y: 11.9), 1.15), (CGPoint(x: 12.1, y: 11.9), 1.15), (CGPoint(x: 9.25, y: 7.85), 0.8)] {
        ctx.fillEllipse(in: circle(center, r))
    }
    ctx.endPDFPage()
    ctx.closePDF()
}

let arguments = CommandLine.arguments
guard arguments.count >= 2 else {
    print("usage: swift ArtworkGenerator.swift <Assets.xcassets> [preview-dir]")
    exit(1)
}
let assets = URL(fileURLWithPath: arguments[1])
let fm = FileManager.default

// App icon.
let iconSet = assets.appendingPathComponent("AppIcon.appiconset")
try? fm.createDirectory(at: iconSet, withIntermediateDirectories: true)
var images: [[String: String]] = []
for points in [16, 32, 128, 256, 512] {
    for scale in [1, 2] {
        let pixels = points * scale
        let name = "icon_\(points)x\(points)\(scale == 2 ? "@2x" : "").png"
        writePNG(render(pixels: pixels) { drawIcon($0, detail: pixels >= 64) }, to: iconSet.appendingPathComponent(name))
        images.append(["idiom": "mac", "size": "\(points)x\(points)", "scale": "\(scale)x", "filename": name])
    }
}
writeJSON(["images": images, "info": ["author": "xcode", "version": 1]], to: iconSet.appendingPathComponent("Contents.json"))

// Mascot artwork for the app's own UI (transparent background).
for (name, asleep) in [("MascotAwake", false), ("MascotAsleep", true)] {
    let set = assets.appendingPathComponent("\(name).imageset")
    try? fm.createDirectory(at: set, withIntermediateDirectories: true)
    for scale in [1, 2] {
        let image = render(pixels: 320 * scale) { ctx in
            // Frame the creature: it spans roughly x 150…874, y 210…870 in icon space.
            ctx.translateBy(x: 512, y: 512)
            ctx.scaleBy(x: 1.3, y: 1.3)
            ctx.translateBy(x: -512, y: -560)
            drawArgus(ctx, asleep: asleep, detail: true)
        }
        writePNG(image, to: set.appendingPathComponent("\(name)@\(scale)x.png"))
    }
    writeJSON(["images": [["idiom": "universal", "scale": "1x", "filename": "\(name)@1x.png"],
                          ["idiom": "universal", "scale": "2x", "filename": "\(name)@2x.png"]],
               "info": ["author": "xcode", "version": 1]], to: set.appendingPathComponent("Contents.json"))
}

// Menu bar glyph.
let glyphSet = assets.appendingPathComponent("MenuBarGlyph.imageset")
try? fm.createDirectory(at: glyphSet, withIntermediateDirectories: true)
writeMenuBarGlyph(to: glyphSet.appendingPathComponent("MenuBarGlyph.pdf"))
writeJSON(["images": [["idiom": "universal", "filename": "MenuBarGlyph.pdf"]],
           "info": ["author": "xcode", "version": 1],
           "properties": ["preserves-vector-representation": true, "template-rendering-intent": "template"]],
          to: glyphSet.appendingPathComponent("Contents.json"))

if arguments.count >= 3 {
    let preview = URL(fileURLWithPath: arguments[2])
    try? fm.createDirectory(at: preview, withIntermediateDirectories: true)
    writePNG(render(pixels: 1024) { drawIcon($0, detail: true) }, to: preview.appendingPathComponent("icon-1024.png"))
    writePNG(render(pixels: 1024) { ctx in
        ctx.setFillColor(rgb(0xF2F2F7)); ctx.fill(CGRect(x: 0, y: 0, width: 1024, height: 1024))
        // Small sizes side by side, as they'd appear in Finder lists and the Dock.
        for (i, size) in [16, 32, 64, 128, 256].enumerated() {
            let image = render(pixels: size) { drawIcon($0, detail: size >= 64) }
            let x = 40 + CGFloat([0, 40, 100, 200, 360][i])
            ctx.saveGState()
            ctx.translateBy(x: x, y: 700 + CGFloat(size)); ctx.scaleBy(x: 1, y: -1)
            ctx.draw(image, in: CGRect(x: 0, y: 0, width: size, height: size))
            ctx.restoreGState()
        }
        ctx.saveGState(); ctx.translateBy(x: 0, y: 40); ctx.scaleBy(x: 0.6, y: 0.6)
        drawArgus(ctx, asleep: true, detail: true)
        ctx.restoreGState()
    }, to: preview.appendingPathComponent("sizes.png"))
}
print("Artwork written to \(assets.path)")
