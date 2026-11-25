import SwiftUI

/// A labelled schematic of the simulated E64 WS. It is a model, not a photo:
/// the geometry is deliberately simple, but every state shown is live.
struct MachineView: View {
    @EnvironmentObject private var model: GrinderModel

    var body: some View {
        VStack(spacing: 8) {
            TimelineView(.animation(minimumInterval: 0.15)) { timeline in
                Canvas { context, size in
                    draw(context: &context, size: size,
                         time: timeline.date.timeIntervalSince1970)
                }
            }
            .background(Color(nsColor: .controlBackgroundColor))
            .clipShape(RoundedRectangle(cornerRadius: 6))
            .padding(.horizontal, 10)
            .padding(.top, 10)

            HStack(spacing: 18) {
                metric("Model", "E64 WS")
                metric("Live weight", String(format: "%.2f g", model.liveWeight))
                metric("Basket", String(format: "%.1f g", model.baseWeightG))
                metric("Rate", String(format: "%.1f g/s", model.weightRate))
                metric("State", model.grinding ? "grinding" : "idle")
            }
            .padding(.bottom, 10)

            Text("The hopper, burrs, spout and cup are a schematic. Weight comes from the virtual load-cell fixture; the burr animation follows the grind state.")
                .font(.caption2)
                .foregroundStyle(.secondary)
                .padding(.horizontal, 12)
                .padding(.bottom, 8)
        }
    }

    private func metric(_ label: String, _ value: String) -> some View {
        VStack(spacing: 1) {
            Text(label).font(.caption2).foregroundStyle(.secondary)
            Text(value).font(.system(.caption, design: .monospaced).bold())
        }
    }

    private func draw(context: inout GraphicsContext, size: CGSize, time: Double) {
        let w = size.width
        let h = size.height
        context.fill(Path(CGRect(origin: .zero, size: size)),
                     with: .linearGradient(Gradient(colors: [Color(red: 0.09, green: 0.10, blue: 0.12),
                                                            Color(red: 0.04, green: 0.05, blue: 0.06)]),
                                           startPoint: .zero,
                                           endPoint: CGPoint(x: 0, y: h)))

        // Layout: hopper at the top, body, spout, scale at the bottom.
        let bodyW = min(w * 0.46, 210)
        let bodyH = min(h * 0.42, 250)
        let bodyX = (w - bodyW) / 2
        let bodyY = h * 0.30

        // Hopper (trapezoid).
        var hopper = Path()
        hopper.move(to: CGPoint(x: bodyX + bodyW * 0.12, y: bodyY))
        hopper.addLine(to: CGPoint(x: bodyX - bodyW * 0.16, y: bodyY - bodyH * 0.42))
        hopper.addLine(to: CGPoint(x: bodyX + bodyW * 1.16, y: bodyY - bodyH * 0.42))
        hopper.addLine(to: CGPoint(x: bodyX + bodyW * 0.88, y: bodyY))
        hopper.closeSubpath()
        context.fill(hopper, with: .color(Color(red: 0.20, green: 0.22, blue: 0.25)))
        context.stroke(hopper, with: .color(.white.opacity(0.25)), lineWidth: 1.5)

        // Body.
        let body = Path(roundedRect: CGRect(x: bodyX, y: bodyY, width: bodyW, height: bodyH),
                        cornerRadius: 14)
        context.fill(body, with: .linearGradient(
            Gradient(colors: [Color(red: 0.24, green: 0.26, blue: 0.30),
                              Color(red: 0.13, green: 0.14, blue: 0.17)]),
            startPoint: CGPoint(x: bodyX, y: bodyY),
            endPoint: CGPoint(x: bodyX, y: bodyY + bodyH)))
        context.stroke(body, with: .color(.white.opacity(0.20)), lineWidth: 1.5)

        // Display.
        let display = CGRect(x: bodyX + bodyW * 0.12, y: bodyY + bodyH * 0.10,
                             width: bodyW * 0.76, height: bodyH * 0.22)
        context.fill(Path(roundedRect: display, cornerRadius: 5), with: .color(.black))
        context.stroke(Path(roundedRect: display, cornerRadius: 5),
                       with: .color(.white.opacity(0.18)), lineWidth: 1)
        context.draw(Text(model.grinding ? "GRINDING" : "E64 WS")
                        .font(.system(size: 12, weight: .semibold, design: .monospaced))
                        .foregroundColor(model.grinding ? .orange : .white),
                     at: CGPoint(x: display.midX, y: display.midY))
        context.draw(Text(String(format: "%.1f g", model.liveWeight))
                        .font(.system(size: 10, design: .monospaced))
                        .foregroundColor(.white.opacity(0.8)),
                     at: CGPoint(x: display.midX, y: display.midY + 16))

        // Burr assembly.
        let burrCenter = CGPoint(x: bodyX + bodyW / 2, y: bodyY + bodyH * 0.52)
        let burrR = bodyW * 0.24
        context.fill(Path(ellipseIn: CGRect(x: burrCenter.x - burrR, y: burrCenter.y - burrR,
                                            width: burrR * 2, height: burrR * 2)),
                     with: .color(Color(red: 0.35, green: 0.36, blue: 0.39)))
        context.stroke(Path(ellipseIn: CGRect(x: burrCenter.x - burrR, y: burrCenter.y - burrR,
                                              width: burrR * 2, height: burrR * 2)),
                       with: .color(.white.opacity(0.25)), lineWidth: 1)

        let angle = model.grinding ? time * 6.0 : 0.0
        for i in 0..<12 {
            let a = angle + Double(i) * .pi / 6
            var tooth = Path()
            tooth.move(to: CGPoint(x: burrCenter.x + cos(a) * burrR * 0.25,
                                   y: burrCenter.y + sin(a) * burrR * 0.25))
            tooth.addLine(to: CGPoint(x: burrCenter.x + cos(a) * burrR * 0.92,
                                      y: burrCenter.y + sin(a) * burrR * 0.92))
            context.stroke(tooth, with: .color(.white.opacity(0.45)), lineWidth: 1.5)
        }

        // Spout.
        let spoutX = bodyX + bodyW / 2
        var spout = Path()
        spout.move(to: CGPoint(x: spoutX - bodyW * 0.08, y: bodyY + bodyH))
        spout.addLine(to: CGPoint(x: spoutX - bodyW * 0.05, y: bodyY + bodyH + 26))
        spout.addLine(to: CGPoint(x: spoutX + bodyW * 0.05, y: bodyY + bodyH + 26))
        spout.addLine(to: CGPoint(x: spoutX + bodyW * 0.08, y: bodyY + bodyH))
        spout.closeSubpath()
        context.fill(spout, with: .color(Color(red: 0.30, green: 0.31, blue: 0.34)))

        // Scale and cup.
        let cupW = bodyW * 0.48
        let cupH = bodyH * 0.20
        let cupX = w / 2 - cupW / 2
        let cupY = h * 0.86 - cupH
        let cup = Path(roundedRect: CGRect(x: cupX, y: cupY, width: cupW, height: cupH),
                       cornerRadius: 8)
        context.fill(cup, with: .color(Color(red: 0.16, green: 0.17, blue: 0.19)))
        context.stroke(cup, with: .color(.white.opacity(0.25)), lineWidth: 1.2)

        let scale = CGRect(x: w / 2 - cupW * 0.62, y: h * 0.86,
                           width: cupW * 1.24, height: 10)
        context.fill(Path(roundedRect: scale, cornerRadius: 3),
                     with: .color(Color(red: 0.22, green: 0.23, blue: 0.26)))
        context.draw(Text(String(format: "%.2f g", model.liveWeight))
                        .font(.system(size: 16, weight: .bold, design: .monospaced))
                        .foregroundColor(.white),
                     at: CGPoint(x: w / 2, y: h * 0.91))
        context.draw(Text("virtual load cell")
                        .font(.system(size: 9, design: .monospaced))
                        .foregroundColor(.white.opacity(0.5)),
                     at: CGPoint(x: w / 2, y: h * 0.95))

        // Labels.
        context.draw(Text("HOPPER").font(.system(size: 9, weight: .semibold))
                        .foregroundColor(.white.opacity(0.45)),
                     at: CGPoint(x: w / 2, y: bodyY - bodyH * 0.46))
        context.draw(Text("BURRS").font(.system(size: 9, weight: .semibold))
                        .foregroundColor(.white.opacity(0.45)),
                     at: CGPoint(x: burrCenter.x, y: burrCenter.y + burrR + 12))
        context.draw(Text("SPOUT").font(.system(size: 9, weight: .semibold))
                        .foregroundColor(.white.opacity(0.45)),
                     at: CGPoint(x: spoutX + bodyW * 0.22, y: bodyY + bodyH + 16))
    }
}
