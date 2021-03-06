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
        
        sslPublicKeyHashPinning(with : url)
        
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

