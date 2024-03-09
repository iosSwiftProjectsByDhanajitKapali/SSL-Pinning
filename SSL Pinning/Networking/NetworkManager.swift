//
//  NetworkManager.swift
//  SSL Pinning
//
//  Created by Dhanajit Kapali on 09/03/24.
//

import Foundation

protocol APIClient {
    func dataRequest(_ url: URL, onCompletion: @escaping (_ result: Result<PostUserModel, Error>) -> Void)
}

class NetworkManager: NSObject, APIClient {
    
    private lazy var session = URLSession(configuration: .default, delegate: self, delegateQueue: nil)
    
    private let certificates: [Data] = {
        let url = Bundle.main.url(forResource: "run.mocky.io", withExtension: "cer")!
        let data = try! Data(contentsOf: url)
        return [data]
      }()
    
    func dataRequest(_ url: URL, onCompletion: @escaping (_ result: Result<PostUserModel, Error>) -> Void) {
        
        let request = URLRequest(url: url)
        
        self.session.dataTask(with: request) { data, response, error in
            if let err = error {
                onCompletion(.failure(AppError.unknown(err.localizedDescription)))
                return
            }
            
            DispatchQueue.main.async {
                if let decodedData = try? JSONDecoder().decode(PostUserModel.self, from: data!) {
                    onCompletion(.success(decodedData))
                } else {
                    onCompletion(.failure(AppError.decodingError))
                }
            }
        }.resume()
    }
    
}

extension NetworkManager: URLSessionDelegate {
    
    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        
        if let trust = challenge.protectionSpace.serverTrust,
           SecTrustGetCertificateCount(trust) > 0 {
            if let certificate = SecTrustGetCertificateAtIndex(trust, 0) {
                let data = SecCertificateCopyData(certificate) as Data
                
                if certificates.contains(data) {
                    completionHandler(.useCredential, URLCredential(trust: trust))
                    return
                } else {
                    //TODO: Throw SSL Certificate Mismatch
                }
            }
        }
        completionHandler(.cancelAuthenticationChallenge, nil)
    }
}


enum AppError: Error {
    case noData
    case decodingError
    case unknown(String)
}


public struct PostUserModel: Codable {
    let userId: Int?
    let id: Int?
    let title: String?
    let body: String?
}
