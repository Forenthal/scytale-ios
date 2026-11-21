import Foundation
import UserNotifications

/// Local notifications for every login outcome. Posted by the app on this iPhone: no push service,
/// no Apple server, no network. The text never contains vault content.
final class LoginNotifier: NSObject, UNUserNotificationCenterDelegate {
    static let shared = LoginNotifier()
    private let center = UNUserNotificationCenter.current()

    func install() {
        center.delegate = self
    }

    /// Asks once; afterwards the choice lives in Settings › Notifications › Scytale.
    func requestPermissionIfNeeded() {
        center.getNotificationSettings { s in
            guard s.authorizationStatus == .notDetermined else { return }
            self.center.requestAuthorization(options: [.alert, .sound, .badge]) { _, _ in }
        }
    }

    enum Event {
        case succeeded, failed, terminated

        var title: String {
            switch self {
            case .succeeded: return "Scytale: login succeeded"
            case .failed: return "Scytale: login failed"
            case .terminated: return "Scytale: VAULT TERMINATED"
            }
        }
    }

    func post(_ event: Event) {
        let content = UNMutableNotificationContent()
        content.title = event.title
        let f = DateFormatter()
        f.dateStyle = .medium
        f.timeStyle = .medium
        switch event {
        case .succeeded: content.body = "Vault unlocked at \(f.string(from: Date()))."
        case .failed: content.body = "A login attempt failed at \(f.string(from: Date()))."
        case .terminated: content.body = "15 wrong admin passwords. The vault was destroyed at \(f.string(from: Date()))."
        }
        content.sound = event == .succeeded ? nil : .default
        let request = UNNotificationRequest(identifier: UUID().uuidString, content: content, trigger: nil)
        center.add(request)
    }

    /// Show the banner even while Scytale is open, so every outcome is recorded in Notification Center.
    func userNotificationCenter(_ center: UNUserNotificationCenter, willPresent notification: UNNotification,
                                withCompletionHandler done: @escaping (UNNotificationPresentationOptions) -> Void) {
        done([.banner, .list, .sound])
    }
}
