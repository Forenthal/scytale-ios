import SwiftUI
import UIKit

/// Hosts the whole interface inside the layer iOS uses for secure text fields. iOS leaves that
/// layer out of screenshots, screen recordings, AirPlay and screen sharing, so captures show an
/// empty screen instead of the vault.
///
/// This relies on undocumented iOS behaviour: if a future iOS changes the secure text field's
/// internals, `isProtected` becomes false and the app says so; detection (screenshot / recording
/// notifications) keeps working either way.
struct ScreenShield<Content: View>: UIViewControllerRepresentable {
    let content: Content
    let onReady: (_ isProtected: Bool, _ window: UIWindow?) -> Void

    func makeUIViewController(context: Context) -> ShieldController<Content> {
        ShieldController(root: content, onReady: onReady)
    }

    func updateUIViewController(_ vc: ShieldController<Content>, context: Context) {
        vc.host.rootView = content
    }
}

final class ShieldController<Content: View>: UIViewController {
    let host: UIHostingController<Content>
    private let onReady: (Bool, UIWindow?) -> Void
    private let secureField = UITextField()
    private var reported = false

    init(root: Content, onReady: @escaping (Bool, UIWindow?) -> Void) {
        self.host = UIHostingController(rootView: root)
        self.onReady = onReady
        super.init(nibName: nil, bundle: nil)
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) { fatalError("not used") }

    private var isProtected = false

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = UIColor(Theme.background)
        host.view.backgroundColor = .clear

        secureField.isSecureTextEntry = true
        secureField.isUserInteractionEnabled = false
        secureField.frame = view.bounds
        secureField.layoutIfNeeded()

        let container: UIView
        if let canvas = secureField.subviews.first(where: { String(describing: type(of: $0)).contains("Canvas") })
            ?? secureField.subviews.first {
            canvas.subviews.forEach { $0.removeFromSuperview() }
            canvas.isUserInteractionEnabled = true
            container = canvas
            isProtected = true
        } else {
            container = UIView()
            isProtected = false
        }
        container.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(container)
        NSLayoutConstraint.activate([
            container.topAnchor.constraint(equalTo: view.topAnchor),
            container.bottomAnchor.constraint(equalTo: view.bottomAnchor),
            container.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            container.trailingAnchor.constraint(equalTo: view.trailingAnchor),
        ])

        addChild(host)
        host.view.translatesAutoresizingMaskIntoConstraints = false
        container.addSubview(host.view)
        NSLayoutConstraint.activate([
            host.view.topAnchor.constraint(equalTo: container.topAnchor),
            host.view.bottomAnchor.constraint(equalTo: container.bottomAnchor),
            host.view.leadingAnchor.constraint(equalTo: container.leadingAnchor),
            host.view.trailingAnchor.constraint(equalTo: container.trailingAnchor),
        ])
        host.didMove(toParent: self)
    }

    override func viewDidAppear(_ animated: Bool) {
        super.viewDidAppear(animated)
        if !reported {
            reported = true
            onReady(isProtected, view.window)
        }
    }
}

/// Records every touch anywhere in the window as activity, without interfering with it.
final class ActivityRecognizer: UIGestureRecognizer, UIGestureRecognizerDelegate {
    private let onActivity: () -> Void

    init(onActivity: @escaping () -> Void) {
        self.onActivity = onActivity
        super.init(target: nil, action: nil)
        cancelsTouchesInView = false
        delaysTouchesBegan = false
        delaysTouchesEnded = false
        delegate = self
    }

    override func touchesBegan(_ touches: Set<UITouch>, with event: UIEvent) {
        onActivity()
        state = .failed
    }

    func gestureRecognizer(_ g: UIGestureRecognizer, shouldRecognizeSimultaneouslyWith other: UIGestureRecognizer) -> Bool {
        true
    }
}
