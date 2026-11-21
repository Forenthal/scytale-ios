import SwiftUI

/// Temporary screen for the test builds: runs the on-device security checks and shows the results.
struct DiagnosticsView: View {
    @State private var results: [Diagnostics.Result] = []
    @State private var running = false

    var body: some View {
        NavigationStack {
            List {
                Section {
                    Button(running ? "Running…" : "Run all checks") { run() }
                        .disabled(running)
                } footer: {
                    Text("Secure Enclave probe requests Face ID once. All probes self-delete.")
                }
                if !results.isEmpty {
                    Section("Results") {
                        ForEach(results) { r in
                            VStack(alignment: .leading, spacing: 4) {
                                Label(r.name, systemImage: r.passed ? "checkmark.circle.fill" : "xmark.octagon.fill")
                                    .font(.system(.body, design: .monospaced).bold())
                                    .foregroundStyle(r.passed ? Color.green : Color.red)
                                Text(r.detail)
                                    .font(.system(.footnote, design: .monospaced))
                                    .foregroundStyle(.secondary)
                            }
                        }
                    }
                }
            }
            .navigationTitle("Scytale diagnostics")
        }
    }

    private func run() {
        running = true
        results = []
        Task.detached(priority: .userInitiated) {
            var out: [Diagnostics.Result] = []
            out.append(Diagnostics.provenance())
            out.append(Diagnostics.coreSelfTest())
            out.append(Diagnostics.deviceIntegrity())
            out.append(Diagnostics.kdfTiming())
            out.append(Diagnostics.vaultFolder())
            out.append(Diagnostics.fileProtection())
            out.append(Diagnostics.keychain())
            out.append(Diagnostics.noICloud())
            out.append(Diagnostics.secureEnclave())
            let final = out
            await MainActor.run {
                results = final
                running = false
            }
        }
    }
}
