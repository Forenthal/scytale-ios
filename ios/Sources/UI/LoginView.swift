import SwiftUI

struct LoginView: View {
    @ObservedObject var model: AppModel
    @State private var focused: InputField? = .password
    @State private var showDiagnostics = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                HStack {
                    Image(systemName: "lock.fill").foregroundStyle(Theme.green)
                    Text("SCYTALE").font(Theme.title).foregroundStyle(Theme.green)
                }
                .padding(.top, 30)
                if let note = model.startNote {
                    Note(text: note, kind: model.startNoteIsWarning ? .warn : .info)
                }
                SecretBox(label: "Password", field: .password, model: model, allowPaste: true,
                          alarm: model.terminationLevel > 0, focused: $focused) {
                    focused = .code
                }
                TerminationWarning(level: model.terminationLevel)
                if model.config.requireTotp {
                    SecretBox(label: "Authenticator code", field: .code, model: model, keyboard: .numberPad,
                              showCount: 6, allowPaste: true, focused: $focused)
                }
                PrimaryButton(title: "Unlock with Face ID",
                              enabled: model.busy == nil && model.counts[.password, default: 0] > 0
                                  && (!model.config.requireTotp || model.counts[.code, default: 0] == 6)) {
                    focused = nil
                    model.unlock()
                }
                if let busy = model.busy {
                    HStack(spacing: 10) { ProgressView().tint(Theme.green); Note(text: busy) }
                }
                Divider().overlay(Theme.line).padding(.vertical, 6)
                Button("Recovery key") {
                    model.clear(.password, .code)
                    model.startNote = nil
                    model.screen = .setup(recover: true)
                }
                .font(Theme.small).foregroundStyle(Theme.dim)
                .disabled(model.busy != nil)
                Button("Diagnostics") { showDiagnostics = true }
                    .font(Theme.small).foregroundStyle(Theme.dim)
                    .disabled(model.busy != nil)
            }
            .padding(20)
        }
        .sheet(isPresented: $showDiagnostics) { DiagnosticsView() }
    }
}
