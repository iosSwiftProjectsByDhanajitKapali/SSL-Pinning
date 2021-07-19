//
//  ServiceManager.swift
//  SSL Pinning
//
//  Created by unthinkable-mac-0025 on 16/07/21.
//

import Foundation
import CommonCrypto
import CryptoKit

class ServiceManager : NSObject{
    
    static let publicKeyHash = "W3J0ds18JL1ILFXwEzj2XB+A3cgYoRoDVA64LgQKMdc="
    private var isCertificatePinning : Bool = false
    
    let rsa2048Asn1Header:[UInt8] = [
    0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
    0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00
    ]
    
    func callAPI(withURL url : URL, isCertificatePinning : Bool, completion: @escaping (String) -> Void){
        
        //create session
        let urlSession = URLSession(configuration: .ephemeral, delegate: self, delegateQueue: nil)
        
        self.isCertificatePinning = isCertificatePinning
        
        var responseMessage = ""
        
        //create the task
        let task = urlSession.dataTask(with: url) { (data, response, error) in
            if error != nil{
                print("error: \(error!.localizedDescription): \(error!)")
                responseMessage = "Pinning failed"
            }
            if let data = data{
                let str = String(decoding: data, as: UTF8.self)
                //print("Received data:\n\(str)")
                
                if isCertificatePinning{
                    responseMessage = "Certificate pinning is successfully completed"
                }else{
                    responseMessage = "Public key pinning is successfully completed"
                }
            }
            DispatchQueue.main.async {
                completion(responseMessage)
            }
        }
        task.resume()
    }
}

extension ServiceManager : URLSessionDelegate{
    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        
        guard let serverTrust = challenge.protectionSpace.serverTrust  else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        
        if self.isCertificatePinning{
            let certificate = SecTrustGetCertificateAtIndex(serverTrust, 0)
            
            //SSL Policies for domain name check
            //let policy = NSMutableArray()
            //policy.add(SecPolicyCreateSSL(true, challenge.protectionSpace.host as CFString))
            
            //Evaluate server certificate
            let isServerTrusted = SecTrustEvaluateWithError(serverTrust, nil)
            
            //Remote certifate data
            let remoteCertificateData : NSData = SecCertificateCopyData(certificate!)
            
            //Local Certificate Data
            let localCertificateData : NSData
            let pathToCertificate = Bundle.main.path(forResource: "google", ofType: "cer")
            localCertificateData = NSData(contentsOfFile: pathToCertificate!)!
            
            //Compare certificate
            if(isServerTrusted && remoteCertificateData.isEqual(to: localCertificateData as Data)){
                
                let credential : URLCredential = URLCredential(trust: serverTrust)
                print("Certificate pinning is successfully completed")
                completionHandler(.useCredential,credential)
                
            }else{
                completionHandler(.cancelAuthenticationChallenge, nil)
            }
        } else {
            if let serverCertificate = SecTrustGetCertificateAtIndex(serverTrust, 0){
                
                //Server Public Key
                let serverPublickey = SecCertificateCopyKey(serverCertificate)
                let serverPublicKeyData = SecKeyCopyExternalRepresentation(serverPublickey!, nil)!
                let data : Data = serverPublicKeyData as Data
                print(data as NSData)
                
                //Create Server Hash Key
                
                //Using CommonCrypto
                //var serverHashKey = sha256(data)
                
                //Using Cryptokit
//                let hashed = SHA256.hash(data: data)
//                let temp = String(describing: hashed)
//                let serverHashKey = hashed.compactMap { String(format: "%02x", $0) }.joined()
//                let stringHash = hashed.map { String(format: "%02hhx", $0) }.joined()
                
                //inserting the hash from terminal
                //serverHashKey = "W3J0ds18JL1ILFXwEzj2XB+A3cgYoRoDVA64LgQKMdc="
                
                //Local Hash key
                let localPublicKey = type(of: self).publicKeyHash
                
                //Comparing the hash of local and server public key
//                if serverHashKey == localPublicKey{
//
//                    // Success! This is our server
//                    print("Public key pinning is successfully completed")
//                    completionHandler(.useCredential, URLCredential(trust: serverTrust))
//                }
            }
        }
        
    } //:urlSession()
}


//MARK: - SHA
extension ServiceManager{
//    private func sha256(_ data : Data) -> String{
//
//        var keyWithHeader = Data(rsa2048Asn1Header)
//        keyWithHeader.append(data)
//
//        var hash = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
//
//        keyWithHeader.withUnsafeBytes {
//            _ = CC_SHA256($0, CC_LONG(keyWithHeader.count), &hash)
//        }
//
//        return Data(hash).base64EncodedString()
//    }
    
//
//    func sha256(_ data: Data) -> String {
//      //let data = stringValue.data(using: String.Encoding.utf8)!
//      var digest = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
//      CC_SHA256((data as NSData).bytes, CC_LONG(data.count), &digest)
//      let hexBytes = digest.map { String(format: "%02hhx", $0) }
//      return hexBytes.joined(separator: "")
//    }
    
//    func sha256(_ data: Data) -> String {
//      let digest = NSMutableData(length: Int(CC_SHA256_DIGEST_LENGTH))!
//      let value = data as NSData
//      let uint8Pointer = UnsafeMutablePointer<UInt8>.allocate(capacity: digest.length)
//      CC_SHA256(value.bytes, CC_LONG(data.count), uint8Pointer)
//      let hashData = value as Data
//        let hashString = hashData.base64EncodedString()
//      return hashString
//    }
    
   
}
