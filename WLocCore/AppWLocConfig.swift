import Foundation

enum AppWLocConfig {
    static var displayName: String {
        let keys = ["CFBundleDisplayName", "CFBundleName"]
        for key in keys {
            if let value = Bundle.main.object(forInfoDictionaryKey: key) as? String,
               !value.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                return value
            }
        }
        return "WLoc8.com"
    }

    static var rootCertificateDownloadFileName: String {
        return "WLoc8.com-RootCA.cer"
    }

    static let appGroupIdentifier = "group.com.wlocapp.shared"

    static let defaultsSuiteName = appGroupIdentifier
    static let localProxyHost = "127.0.0.1"
    static let localProxyPort: UInt16 = 19090
    static let certificateServerPort: UInt = 18088

    static let appWLocHosts: Set<String> = [
        "gs-loc.apple.com",
        "gs-loc-cn.apple.com"
    ]

    static let wlocPath = "/clls/wloc"
    static let proxyIdentityResourceName = "AppWLocProxy"
    static let rootCertificateResourceName = "AppWLocRootCA"
    static let proxyIdentityPassword = "app-wloc"

    // 集中管理默认定位参数，避免散落在多处硬编码
    static let defaultAltitude: Double = 480
    static let defaultHorizontalAccuracy: Int64 = 39
    static let defaultVerticalAccuracy: Int64 = 1000
}
