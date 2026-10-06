import Foundation
import Security

/// Identifiers derived from how the app was signed, instead of hardcoding ACINQ's.
/// Official builds get the same values as before ("group.co.acinq.phoenix", "XD77LN4376").
/// Sideloading tools (e.g. Sideloader) rename the bundle id and register "group.<bundleId>" under their own team.
enum AppIdentity {

	/// Bundle id of the main app, also when running inside the notification-service-extension.
	static let mainBundleId: String = {
		let id = Bundle.main.bundleIdentifier ?? "co.acinq.phoenix"
		let extSuffix = ".phoenix-notifySrvExt"
		return id.hasSuffix(extSuffix) ? String(id.dropLast(extSuffix.count)) : id
	}()

	static let appGroup = "group.\(mainBundleId)"
	
	/// Sideloaded builds (renamed bundle id) have no iCloud entitlement: any CloudKit call would crash.
	static let hasICloud = mainBundleId == "co.acinq.phoenix"

	/// The signing team id, read from the default keychain access group ("<teamId>.<bundleId>").
	static let teamId: String = {
		let official = "XD77LN4376"
		let query: [String: Any] = [
			kSecClass as String            : kSecClassGenericPassword,
			kSecAttrService as String      : "teamIdProbe",
			kSecAttrAccount as String      : "teamIdProbe",
			kSecAttrAccessible as String   : kSecAttrAccessibleAfterFirstUnlock,
			kSecReturnAttributes as String : true
		]
		var result: CFTypeRef? = nil
		var status = SecItemCopyMatching(query as CFDictionary, &result)
		if status == errSecItemNotFound {
			status = SecItemAdd(query as CFDictionary, &result)
		}
		guard status == errSecSuccess,
		      let attrs = result as? [String: Any],
		      let group = attrs[kSecAttrAccessGroup as String] as? String,
		      let prefix = group.split(separator: ".").first,
		      prefix != "group"
		else {
			return official
		}
		return String(prefix)
	}()
}

enum AccessGroup {
	
	/// Represents the keychain domain for this app.
	/// I.E. can NOT be accessed by our app extensions.
	case appOnly
	
	/// Represents the keychain domain for our app group.
	/// I.E. can be accessed by our app extensions (e.g. notification-service-extension).
	case appAndExtensions
	
	var value: String { switch self {
		case .appOnly          : "\(AppIdentity.teamId).\(AppIdentity.mainBundleId)"
		case .appAndExtensions : AppIdentity.appGroup
	}}
	
	var debugName: String { switch self {
		case .appOnly          : "appOnly"
		case .appAndExtensions : "appAndExtensions"
  }}
}

/// Names of entries stored within the iOS keychain
/// 
enum KeychainKey: CaseIterable {
	case lockingKey
	case softBiometrics
	case passcodeFallback
	case lockPin
	case invalidLockPin
	case spendingPin
	case invalidSpendingPin
	case bip353Address
	
	var prefix: String { switch self {
		case .lockingKey         : return "securityFile_keychain"
		case .softBiometrics     : return "biometrics"
		case .passcodeFallback   : return "passcodeFallback"
		case .lockPin            : return "customPin"
		case .invalidLockPin     : return "invalidPin"
		case .spendingPin        : return "spendingPin"
		case .invalidSpendingPin : return "invalidSpendingPin"
		case .bip353Address      : return "bip353Address"
	}}
	
	var debugName: String { switch self {
		case .lockingKey         : return "lockingKey"
		case .softBiometrics     : return "softBiometrics"
		case .passcodeFallback   : return "passcodeFallback"
		case .lockPin            : return "lockPin"
		case .invalidLockPin     : return "invalidLockPin"
		case .spendingPin        : return "spendingPin"
		case .invalidSpendingPin : return "invalidSpendingPin"
		case .bip353Address      : return "bip353Address"
	}}
	
	/// From before we had a per-wallet design
	var deprecatedValue: String { prefix }
	
	var accessGroup: AccessGroup { switch self {
		case .lockingKey         : return .appAndExtensions
		case .softBiometrics     : return .appOnly
		case .passcodeFallback   : return .appOnly
		case .lockPin            : return .appOnly
		case .invalidLockPin     : return .appOnly
		case .spendingPin        : return .appOnly
		case .invalidSpendingPin : return .appOnly
		case .bip353Address      : return .appOnly
	}}
	
	func account(_ suffix: String) -> String {
		return "\(self.prefix)-\(suffix)"
	}
}

enum KeychainKeyDeprecated: String {
	case lockingKey_biometrics = "securityFile_biometrics"
}
