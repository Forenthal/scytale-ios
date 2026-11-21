import SwiftUI
import UIKit
import ScytaleCore

enum CoreSelfTest {
    static func run() -> Int32 { scytale_selftest() }
}

final class AppDelegate: NSObject, UIApplicationDelegate {
    func application(_ application: UIApplication,
                     didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]? = nil) -> Bool {
        Integrity.denyDebuggerAttach()
        LoginNotifier.shared.install()
        return true
    }

    /// Third-party keyboards can see everything typed into them; only Apple's keyboard is allowed.
    func application(_ application: UIApplication,
                     shouldAllowExtensionPointIdentifier id: UIApplication.ExtensionPointIdentifier) -> Bool {
        id != .keyboard
    }
}

@main
struct ScytaleApp: App {
    @UIApplicationDelegateAdaptor(AppDelegate.self) private var delegate
    @StateObject private var model = AppModel()
    @Environment(\.scenePhase) private var scenePhase
    @State private var covered = false
    private let idle = Timer.publish(every: 5, on: .main, in: .common).autoconnect()

    var body: some Scene {
        WindowGroup {
            ZStack {
                Theme.background.ignoresSafeArea()
                ScreenShield(content: RootView(model: model)) { isProtected, window in
                    model.shieldProtected = isProtected
                    window?.addGestureRecognizer(ActivityRecognizer { [weak model] in
                        Task { @MainActor in model?.touch() }
                    })
                }
                .ignoresSafeArea()
                // Shown in the app switcher snapshot and whenever the app is not frontmost.
                if covered || model.captured {
                    PrivacyCover(captured: model.captured)
                }
            }
            .preferredColorScheme(.dark)
            .onAppear { if case .boot = model.screen { model.boot() } }
            .onReceive(idle) { _ in model.checkIdle() }
            .onReceive(NotificationCenter.default.publisher(for: UIApplication.userDidTakeScreenshotNotification)) { _ in
                model.screenshotTaken()
            }
            .onReceive(NotificationCenter.default.publisher(for: UIScreen.capturedDidChangeNotification)) { note in
                model.captureChanged((note.object as? UIScreen)?.isCaptured ?? false)
            }
            .onReceive(NotificationCenter.default.publisher(for: UIApplication.protectedDataWillBecomeUnavailableNotification)) { _ in
                model.lock(.deviceLock)
            }
            .onChange(of: scenePhase) { _, phase in
                covered = phase != .active
                switch phase {
                case .background: model.didEnterBackground()
                case .active: model.didBecomeActive()
                default: break
                }
            }
        }
    }
}

struct RootView: View {
    @ObservedObject var model: AppModel

    var body: some View {
        ZStack(alignment: .top) {
            Theme.background.ignoresSafeArea()
            switch model.screen {
            case .boot:
                ProgressView().tint(Theme.green).frame(maxWidth: .infinity, maxHeight: .infinity)
            case .setup(let recover):
                SetupFlow(model: model, recover: recover).id("\(recover)-\(model.setupEpoch)")
            case .login:
                LoginView(model: model)
            case .home:
                HomeView(model: model)
            case .fatal(let message):
                VStack(spacing: 16) {
                    Image(systemName: "exclamationmark.octagon.fill").font(.largeTitle).foregroundStyle(Theme.error)
                    Note(text: message, kind: .error)
                }
                .padding(30)
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            }
            VStack(spacing: 8) {
                if !model.shieldProtected {
                    Banner(text: "SCREEN SHIELD OFFLINE · captures detected, not blocked")
                }
            }
            .padding(.horizontal, 12)
        }
        .foregroundStyle(Theme.text)
    }
}

struct Banner: View {
    let text: String
    var dismiss: (() -> Void)?

    var body: some View {
        HStack(alignment: .top) {
            Text(text).font(Theme.small).foregroundStyle(.black).fixedSize(horizontal: false, vertical: true)
            Spacer(minLength: 8)
            if let dismiss {
                Button(action: dismiss) { Image(systemName: "xmark").foregroundStyle(.black) }
            }
        }
        .padding(10)
        .background(RoundedRectangle(cornerRadius: 8).fill(Theme.warn))
    }
}

struct PrivacyCover: View {
    let captured: Bool

    var body: some View {
        ZStack {
            Theme.background.ignoresSafeArea()
            VStack(spacing: 14) {
                Image(systemName: "lock.fill").font(.system(size: 44)).foregroundStyle(Theme.green)
                if captured {
                    Note(text: "Screen capture active. Vault hidden and locked.", kind: .warn)
                        .multilineTextAlignment(.center)
                }
            }
            .padding(30)
        }
    }
}
