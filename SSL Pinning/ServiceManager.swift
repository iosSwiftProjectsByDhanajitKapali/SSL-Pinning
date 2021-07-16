//
//  ServiceManager.swift
//  SSL Pinning
//
//  Created by unthinkable-mac-0025 on 16/07/21.
//

import Foundation

class ServiceManager : NSObject{
    
    private var isCertificatePinning : Bool = false
    
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
            
        }
        
    } //:urlSession()
}
