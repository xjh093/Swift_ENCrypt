//
//  JH3DES.swift
//  AlgorithmNotes
//
//  Created by HaoCold on 2021/6/18.
//

import Foundation
import CommonCrypto

extension String {
    /// `key` length: `16`(AES-128) or `24`(AES-192) or `32`(AES-256)
    /// `iv` length should equal `key` length
    func jh3des(operation:CCOperation, _ key: String, _ iv: String?) -> String? {
        if let keyData = key.data(using: .utf8) {
            var cryptData: Data?
            
            if operation == kCCEncrypt {
                cryptData = self.data(using: .utf8)
            } else {
                cryptData = Data(base64Encoded: self, options: .ignoreUnknownCharacters)
            }
            
            if cryptData == nil {
                return nil
            }
            
            let algoritm: CCAlgorithm = CCAlgorithm(kCCAlgorithm3DES)
            let option: CCOptions = CCOptions(kCCOptionPKCS7Padding)
            
            let keyBytes = [UInt8](keyData)
            let keyLength = size_t(kCCKeySize3DES)
            
            let dataIn = [UInt8](cryptData!)
            let dataInlength = size_t(cryptData!.count)
            
            let dataOutAvailable = size_t(dataInlength + kCCBlockSize3DES)
            let dataOut = UnsafeMutablePointer<UInt8>.allocate(capacity: dataOutAvailable)
            var dataOutMoved = 0
            
            
            let ivk = iv ?? ""
            let ivData = [UInt8](ivk.data(using: .utf8)!)
            
            
            let cryptStatus = CCCrypt(operation,
                                      algoritm,
                                      option,
                                      keyBytes,
                                      keyLength,
                                      ivData,
                                      dataIn,
                                      dataInlength,
                                      dataOut,
                                      dataOutAvailable,
                                      &dataOutMoved)
            
            var data: Data?
            if CCStatus(cryptStatus) == CCStatus(kCCSuccess) {
                data = Data(bytes: dataOut, count: dataOutMoved)
            }
            dataOut.deallocate()
            
            if data == nil {
                return nil
            }
            
            if operation == kCCEncrypt {
                data = data!.base64EncodedData(options: .lineLength64Characters)
            }
            
            return String(data: data!, encoding: .utf8)
        }
        return nil
    }
}
