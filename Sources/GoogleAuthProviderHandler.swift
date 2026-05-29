import Foundation
import Capacitor
import FirebaseCore
import FirebaseAuth
import GoogleSignIn

class GoogleAuthProviderHandler: NSObject {
    var pluginImplementation: FirebaseAuthentication

    init(_ pluginImplementation: FirebaseAuthentication) {
        self.pluginImplementation = pluginImplementation
        super.init()
    }

    func signIn(call: CAPPluginCall) {
        startSignInWithGoogleFlow(call, isLink: false)
    }

    func link(call: CAPPluginCall) {
        startSignInWithGoogleFlow(call, isLink: true)
    }

    func signOut() {
        GIDSignIn.sharedInstance.signOut()
    }

    private func startSignInWithGoogleFlow(_ call: CAPPluginCall, isLink: Bool) {
        guard let clientId = FirebaseApp.app()?.options.clientID else { return }
        let serverClientId = "897570617862-us1o94v3jk286evnqgqttp5pv7ej8k5m.apps.googleusercontent.com"
        let config = GIDConfiguration(clientID: clientId, serverClientID: serverClientId)
        GIDSignIn.sharedInstance.configuration = config
        guard let controller = self.pluginImplementation.getPlugin().bridge?.viewController else { return }
        let scopes = call.getArray("scopes", String.self) ?? []

        DispatchQueue.main.async {
            GIDSignIn.sharedInstance.signIn(withPresenting: controller, hint: nil, additionalScopes: scopes) { [unowned self] result, error in
                if let error = error {
                    if isLink == true {
                        self.pluginImplementation.handleFailedLink(message: nil, error: error)
                    } else {
                        self.pluginImplementation.handleFailedSignIn(message: nil, error: error)
                    }
                    return
                }
                guard let user = result?.user,
                      let idToken = user.idToken?.tokenString
                else { return }
                let accessToken = user.accessToken.tokenString
                let serverAuthCode = result?.serverAuthCode
                let credential = GoogleAuthProvider.credential(withIDToken: idToken, accessToken: accessToken)
                if isLink == true {
                    self.pluginImplementation.handleSuccessfulLink(credential: credential, idToken: idToken, nonce: nil,
                                                                   accessToken: accessToken, serverAuthCode: serverAuthCode, displayName: nil, authorizationCode: nil)
                } else {
                    self.pluginImplementation.handleSuccessfulSignIn(credential: credential, idToken: idToken, nonce: nil,
                                                                     accessToken: accessToken, displayName: nil, authorizationCode: nil, serverAuthCode: serverAuthCode)
                }
            }
        }
    }
}
