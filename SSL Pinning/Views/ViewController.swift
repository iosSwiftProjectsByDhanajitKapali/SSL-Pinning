//
//  ViewController.swift
//  SSL Pinning
//
//  Created by unthinkable-mac-0025 on 16/07/21.
//

import UIKit

class ViewController: UIViewController {

    override func viewDidLoad() {
        super.viewDidLoad()
        
        guard let url = URL(string: "https://www.google.co.uk") else{return}
        
        //sslCertificatePinning(with: url)
        
        //sslPublicKeyHashPinning(with : url)
        
        testSSLCertificatePinning()
        
        //testMethod()
        
    }
    
    func testMethod() {
        let url = URL(string: "https://run.mocky.io/v3/b2e88f01-44a6-4549-b34e-0f6d115502bc")!
        let configuration = URLSessionConfiguration.default
        let delegate = CertificatePinningDelegate()
        let session = URLSession(configuration: configuration, delegate: delegate, delegateQueue: nil)

        let task = session.dataTask(with: url) { (data, response, error) in
            // Handle response
            print("lol")
        }

        task.resume()
    }
    
    func testSSLCertificatePinning() {
        guard let url = URL(string: "https://run.mocky.io/v3/b2e88f01-44a6-4549-b34e-0f6d115502bc") else{ return }
        NetworkManager().dataRequest(url) { result in
            switch result {
            case .success(let success):
                print(success)
            case .failure(let failure):
                print(failure)
            }
        }
    }
    
    ///Function to test SSL Certificate Pinning
    func sslCertificatePinning(with url : URL){
        ServiceManager().callAPI(withURL: url, isCertificatePinning: true) { (resultMessage) in
            
            //Present an alert on completing the API-call
            let alert = UIAlertController(title: "SSL Pinning", message: resultMessage, preferredStyle: .alert)
            alert.addAction(UIAlertAction(title: "OK", style: .default, handler: nil))
            self.present(alert, animated: true, completion: nil)
        }
    }

    ///Function to test SPKI Pinning( Subject Public key Pinning), Here we will Pin the hash of the Public key  of the certificate
    func sslPublicKeyHashPinning(with url : URL){
        ServiceManager().callAPI(withURL: url, isCertificatePinning: false) { (resultMessage) in
            
            //Present an alert on completing the API-call
            let alert = UIAlertController(title: "SSL Pinning", message: resultMessage, preferredStyle: .alert)
            alert.addAction(UIAlertAction(title: "OK", style: .default, handler: nil))
            self.present(alert, animated: true, completion: nil)
        }
    }

}

