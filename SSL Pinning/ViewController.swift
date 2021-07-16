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
        
        ServiceManager().callAPI(withURL: url, isCertificatePinning: true) { (resultMessage) in
            
            //Present an alert on completing the API-call
            let alert = UIAlertController(title: "SSL Pinning", message: resultMessage, preferredStyle: .alert)
            alert.addAction(UIAlertAction(title: "OK", style: .default, handler: nil))
            self.present(alert, animated: true, completion: nil)
        }
    }


}

