import AVFoundation
import SwiftUI
import UIKit

/// Scytale's own camera. Photos are captured into memory and encrypted straight into the vault:
/// they never touch the Photos library, iCloud Photos or storage. No location is attached.
final class CameraController: NSObject, ObservableObject, AVCapturePhotoCaptureDelegate {
    let session = AVCaptureSession()
    private let output = AVCapturePhotoOutput()
    private let queue = DispatchQueue(label: "com.forenthal.scytale.camera")
    private var input: AVCaptureDeviceInput?

    @Published var status: String?
    @Published var ready = false
    @Published var capturing = false

    /// Called on the main thread with the encoded photo and its file extension.
    var onPhoto: (Data, String) -> Void = { _, _ in }

    func start() {
        switch AVCaptureDevice.authorizationStatus(for: .video) {
        case .authorized:
            configure()
        case .notDetermined:
            AVCaptureDevice.requestAccess(for: .video) { ok in
                DispatchQueue.main.async {
                    if ok { self.configure() } else { self.status = "Camera access denied." }
                }
            }
        default:
            status = "Camera off for Scytale · Settings › Scytale › Camera"
        }
    }

    private func configure(position: AVCaptureDevice.Position = .back) {
        queue.async {
            self.session.beginConfiguration()
            self.session.sessionPreset = .photo
            if let old = self.input { self.session.removeInput(old) }
            guard let device = AVCaptureDevice.default(.builtInWideAngleCamera, for: .video, position: position),
                  let input = try? AVCaptureDeviceInput(device: device),
                  self.session.canAddInput(input) else {
                self.session.commitConfiguration()
                DispatchQueue.main.async { self.status = "Camera unavailable." }
                return
            }
            self.session.addInput(input)
            self.input = input
            if !self.session.outputs.contains(self.output), self.session.canAddOutput(self.output) {
                self.session.addOutput(self.output)
            }
            self.output.maxPhotoQualityPrioritization = .quality
            self.session.commitConfiguration()
            if !self.session.isRunning { self.session.startRunning() }
            DispatchQueue.main.async { self.ready = true }
        }
    }

    func flip() {
        let next: AVCaptureDevice.Position = input?.device.position == .back ? .front : .back
        configure(position: next)
    }

    func capture() {
        guard ready, !capturing else { return }
        capturing = true
        queue.async {
            let heic = self.output.availablePhotoCodecTypes.contains(.hevc)
            let settings = heic ? AVCapturePhotoSettings(format: [AVVideoCodecKey: AVVideoCodecType.hevc])
                                : AVCapturePhotoSettings()
            settings.photoQualityPrioritization = .quality
            self.output.capturePhoto(with: settings, delegate: self)
        }
    }

    func photoOutput(_ output: AVCapturePhotoOutput, didFinishProcessingPhoto photo: AVCapturePhoto, error: Error?) {
        let data = error == nil ? photo.fileDataRepresentation() : nil
        let ext = output.availablePhotoCodecTypes.contains(.hevc) ? "heic" : "jpg"
        DispatchQueue.main.async {
            self.capturing = false
            if let data { self.onPhoto(data, ext) } else { self.status = "Capture failed." }
        }
    }

    func stop() {
        queue.async {
            if self.session.isRunning { self.session.stopRunning() }
        }
    }
}

final class PreviewView: UIView {
    override class var layerClass: AnyClass { AVCaptureVideoPreviewLayer.self }
    var previewLayer: AVCaptureVideoPreviewLayer { layer as! AVCaptureVideoPreviewLayer }
}

struct CameraPreview: UIViewRepresentable {
    let session: AVCaptureSession

    func makeUIView(context: Context) -> PreviewView {
        let v = PreviewView()
        v.previewLayer.session = session
        v.previewLayer.videoGravity = .resizeAspectFill
        return v
    }

    func updateUIView(_ v: PreviewView, context: Context) {}
}

struct CameraView: View {
    @ObservedObject var model: AppModel
    @StateObject private var camera = CameraController()
    @State private var flash = false
    @State private var taken = 0

    var body: some View {
        ZStack {
            Color.black.ignoresSafeArea()
            CameraPreview(session: camera.session).ignoresSafeArea()
            if flash { Color.white.ignoresSafeArea().transition(.opacity) }
            VStack {
                HStack {
                    Button { close() } label: {
                        Image(systemName: "xmark").font(.title2.weight(.semibold)).padding(12)
                    }
                    Spacer()
                    if taken > 0 {
                        Text("\(taken) encrypted").font(Theme.small).foregroundStyle(Theme.green)
                    }
                    Spacer()
                    Button { camera.flip(); model.touch() } label: {
                        Image(systemName: "arrow.triangle.2.circlepath.camera").font(.title2).padding(12)
                    }
                }
                .foregroundStyle(.white)
                .padding(.horizontal, 8)
                if let s = camera.status {
                    Note(text: s, kind: .warn).padding()
                }
                Spacer()
                Note(text: "Direct-to-vault capture · no Photos · no iCloud", kind: .ok, icon: "lock.fill")
                    .multilineTextAlignment(.center)
                    .padding(.horizontal, 24)
                Button { shoot() } label: {
                    ZStack {
                        Circle().stroke(Theme.green, lineWidth: 4).frame(width: 78, height: 78)
                        Circle().fill(camera.capturing ? Theme.dim : Color.white).frame(width: 64, height: 64)
                    }
                }
                .disabled(!camera.ready || camera.capturing)
                .padding(.bottom, 30)
            }
        }
        .onAppear {
            camera.onPhoto = { data, ext in
                model.importCapture(data, ext: ext)
                taken += 1
            }
            camera.start()
        }
        .onDisappear { camera.stop() }
    }

    private func shoot() {
        model.touch()
        camera.capture()
        withAnimation(.easeOut(duration: 0.08)) { flash = true }
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.12) { withAnimation { flash = false } }
    }

    private func close() {
        camera.stop()
        model.showCamera = false
        model.touch()
    }
}
