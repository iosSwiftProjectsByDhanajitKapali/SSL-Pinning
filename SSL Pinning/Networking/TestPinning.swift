//
//  TestPinning.swift
//  SSL Pinning
//
//  Created by Dhanajit Kapali on 09/03/24.
//

import Foundation

import Foundation

class CertificatePinningDelegate: NSObject, URLSessionDelegate {
    
    // Function to validate the server's SSL certificate
    func validateCertificate(using pinnedCertificateName: String, for challenge: URLAuthenticationChallenge) -> Bool {
        guard
            let serverTrust = challenge.protectionSpace.serverTrust,
            let localCertificatePath = Bundle.main.path(forResource: pinnedCertificateName, ofType: "cer"),
            let localCertificateData = try? Data(contentsOf: URL(fileURLWithPath: localCertificatePath)),
            let localCertificate = SecCertificateCreateWithData(nil, localCertificateData as CFData)
        else {
            return false
        }

        SecTrustSetAnchorCertificates(serverTrust, [localCertificate] as CFArray)
        SecTrustSetAnchorCertificatesOnly(serverTrust, true)

        var trustResult: SecTrustResultType = .unspecified
        SecTrustEvaluate(serverTrust, &trustResult)

        return trustResult == .unspecified || trustResult == .proceed
    }
    
    // URLSessionDelegate method to handle authentication challenges
    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust else {
            completionHandler(.performDefaultHandling, nil)
            return
        }

        let pinnedCertificateName = "run.mocky.io"
        let isCertificateValid = validateCertificate(using: pinnedCertificateName, for: challenge)

        if isCertificateValid {
            let credential = URLCredential(trust: challenge.protectionSpace.serverTrust!)
            completionHandler(.useCredential, credential)
        } else {
            completionHandler(.cancelAuthenticationChallenge, nil)
        }
    }
}

