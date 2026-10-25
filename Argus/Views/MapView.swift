import ArgusKit
import CoreLocation
import MapKit
import SwiftUI

/// Where in the world your Mac's traffic goes.
struct ConnectionsMapView: View {
    @Environment(AppModel.self) private var model
    @State private var selected: String?
    @State private var position: MapCameraPosition = .region(MKCoordinateRegion(
        center: CLLocationCoordinate2D(latitude: 25, longitude: GeoLocator.home?.longitude ?? 0),
        span: MKCoordinateSpan(latitudeDelta: 130, longitudeDelta: 300)))

    struct CountryStats: Identifiable {
        let country: Country
        var bytes: UInt64 = 0
        var connections = 0
        var blocked = 0
        var programs = Set<String>()
        var servers: [ConnectionRecord] = []

        var id: String { country.code }
    }

    private var stats: [CountryStats] {
        var byCountry: [String: CountryStats] = [:]
        for connection in model.connections.values {
            guard let country = model.geo.country(for: connection) else { continue }
            var entry = byCountry[country.code] ?? CountryStats(country: country)
            entry.bytes += connection.totalBytes
            entry.connections += connection.connectCount
            entry.blocked += connection.denyCount
            entry.programs.insert(connection.processPath)
            entry.servers.append(connection)
            byCountry[country.code] = entry
        }
        return byCountry.values.sorted { $0.bytes > $1.bytes }
    }

    var body: some View {
        let stats = stats
        HSplitView {
            map(stats)
                .frame(minWidth: 420)
            sidebar(stats)
                .frame(minWidth: 260, idealWidth: 300, maxWidth: 380)
        }
        .navigationTitle("World Map")
        .overlay {
            if !model.geo.isReady { LocationDatabasePrompt() }
        }
    }

    private func map(_ stats: [CountryStats]) -> some View {
        let maximum = Double(max(stats.first?.bytes ?? 1, 1))
        let home = GeoLocator.home
        return Map(position: $position) {
            if let home {
                Annotation("This Mac", coordinate: home) {
                    MascotView(size: 34).shadow(radius: 3)
                }
            }
            ForEach(stats) { stat in
                if let coordinate = stat.country.coordinate {
                    if let home {
                        MapPolyline(coordinates: [home, coordinate], contourStyle: .geodesic)
                            .stroke(stat.blocked > 0 && stat.blocked == stat.connections ? Color.denied.opacity(0.5) : Color.accentColor.opacity(0.45),
                                    lineWidth: 1 + 3 * sqrt(Double(stat.bytes) / maximum))
                    }
                    Annotation(stat.country.name, coordinate: coordinate) {
                        let size = 18 + 34 * sqrt(Double(stat.bytes) / maximum)
                        Button {
                            selected = stat.id
                        } label: {
                            ZStack {
                                Circle().fill(Color.accentColor.opacity(selected == stat.id ? 0.55 : 0.3))
                                Circle().strokeBorder(Color.accentColor, lineWidth: selected == stat.id ? 3 : 1.5)
                                Text(stat.country.flag).font(.system(size: size * 0.45))
                            }
                            .frame(width: size, height: size)
                        }
                        .buttonStyle(.plain)
                    }
                }
            }
        }
        .mapStyle(.standard(elevation: .flat, emphasis: .muted, pointsOfInterest: .excludingAll))
        .mapControls {
            MapZoomStepper()
            MapCompass()
        }
    }

    private func sidebar(_ stats: [CountryStats]) -> some View {
        List(selection: $selected) {
            if let code = selected, let stat = stats.first(where: { $0.id == code }) {
                Section("\(stat.country.flag) \(stat.country.name)") {
                    LabeledContent("Data", value: Formatting.bytes(stat.bytes))
                    LabeledContent("Connections", value: stat.connections.formatted())
                    LabeledContent("Programs", value: "\(stat.programs.count)")
                    if stat.blocked > 0 { LabeledContent("Blocked", value: stat.blocked.formatted()) }
                    ForEach(stat.servers.sorted { $0.totalBytes > $1.totalBytes }.prefix(12)) { server in
                        HStack(spacing: 6) {
                            AppIconView(identity: model.identity(for: server.processPath), size: 16)
                            Text(server.remote).lineLimit(1).truncationMode(.middle)
                            Spacer()
                            Text(Formatting.bytes(server.totalBytes)).font(.caption).foregroundStyle(.secondary)
                        }
                    }
                }
            }
            Section("Countries") {
                if stats.isEmpty {
                    Text(model.geo.isReady ? "No connections to place yet." : "Location data isn't downloaded.")
                        .foregroundStyle(.secondary)
                }
                ForEach(stats) { stat in
                    HStack {
                        Text(stat.country.flag)
                        Text(stat.country.name).lineLimit(1)
                        Spacer()
                        Text(Formatting.bytes(stat.bytes)).font(.caption.monospacedDigit()).foregroundStyle(.secondary)
                    }
                    .tag(stat.id)
                }
            }
        }
        .onChange(of: selected) { _, code in
            guard let code, let coordinate = GeoLocator.coordinates[code] else { return }
            withAnimation { position = .camera(MapCamera(centerCoordinate: coordinate, distance: 9_000_000)) }
        }
    }
}

struct LocationDatabasePrompt: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        VStack(spacing: 12) {
            Image(systemName: "globe.europe.africa.fill").font(.system(size: 40)).foregroundStyle(.tint)
            Text("See where your data goes").font(.title2.weight(.semibold))
            Text("Argus can download the public address registrations of the five regional internet registries (about 20 MB) to show which country each server is registered in. Lookups happen on your Mac; nothing about your connections is sent anywhere.")
                .multilineTextAlignment(.center)
                .foregroundStyle(.secondary)
                .frame(maxWidth: 420)
            switch model.geo.status {
            case .working:
                ProgressView("Downloading…")
            case .failed(let message):
                Text(message).foregroundStyle(.orange)
                Button("Try Again") { Task { await model.geo.update() } }
            default:
                Button("Download Location Data") { Task { await model.geo.update() } }
                    .buttonStyle(.borderedProminent)
            }
        }
        .padding(28)
        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 18, style: .continuous))
        .shadow(radius: 20)
    }
}
