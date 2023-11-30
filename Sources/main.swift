print("Hello, world!  DigestAuth")
import AsyncHTTPClient
import Crypto
import Foundation


/*
 1	Make basic HTTP request to remote server (no auth in header)

 2	Server responds with a "401 Unauthorized" status code and a WWW-Authenticate header field (the digest-challenge)

 3	Make 2nd request for same resource but with an Authorization header field in response to the challenge (the digest-response)

 challenge        =  "Digest" digest-challenge
 digest-challenge  = 1#( realm | [ domain ] | nonce |
					 [ opaque ] |[ stale ] | [ algorithm ] |
					 [ qop-options ] | [auth-param] )

 So you need to parse the digest-challenge to get the parameters to be able to generate a digest-reponse for the Authorization request header field with the following syntax:

 
 credentials      = "Digest" digest-response
 digest-response  = 1#( username | realm | nonce | digest-uri
				 | response | [ algorithm ] | [cnonce] |
				 [opaque] | [message-qop] |
					 [nonce-count]  | [auth-param] )

 */




extension DataProtocol {
	var hexString: String {
		let hexLen = self.count * 2
		var hexChars = [UInt8](repeating: 0, count: hexLen)
		var offset = 0
		
		self.regions.forEach { (_) in
			for i in self {
				hexChars[Int(offset * 2)] = itoh((i >> 4) & 0xF)
				hexChars[Int(offset * 2 + 1)] = itoh(i & 0xF)
				offset += 1
			}
		}
		
		return String(bytes: hexChars, encoding: .utf8)!
	}
}

let charA = UInt8(UnicodeScalar("a").value)
let char0 = UInt8(UnicodeScalar("0").value)

func itoh(_ value: UInt8) -> UInt8 {
	return (value > 9) ? (charA + value - 10) : (char0 + value)
}



class DigestAuthSample {
	internal init(serverURL: String, username: String, password: String)  {
		self.serverURL = serverURL
		self.username = username
		self.password = password
	}
	

	enum DigestParameterKey: String, Hashable {
		case nonce
		case qop
		case stale
		case domain
		case realm
		case algorithm
		case opaque
		case cnonce

		case response
		case username
		case digesturi = "digest-uri"
	}
	
	enum HashingAlgorithm: String {
		case MD5 = "MD5"
		case MD5sess = "MD5-sess"
		case unhandled
	}
	
	enum QOPDirective: String {
		case auth = "auth"
		case authInt = "auth-int"
		case unhandled
	}

	var serverURL: String
	var username: String
	var password: String
	
	var httpClient = HTTPClient(eventLoopGroupProvider: .singleton)
	
	func startUp() {
		
	}
	
	func shutdown() async {
		// it is important to shutdown the httpClient after all requests are done, even if one failed
		try! await httpClient.shutdown()
	}
	
	func go() async {
		let authenticateHeaderName = "WWW-Authenticate"
		var digestParamsDict = [DigestParameterKey: String]()
		print("DigestAuthSample going...")
		
		///	Takes a string of the form 'algorithm="MD5"' and turns it into a labelled tuple.
		func paramStringToTuple(_ param: String) -> (key: String, value: String)? {
			//	e.g. algorithm="MD5"
			let keyValueArray = param.components(separatedBy: "=")
			if keyValueArray.count != 2 {
				print("Error: paramter is not correctly formed: \(param)")
				return nil
			}
			let key = keyValueArray[0]
			var value = keyValueArray[1]
			
			//	Value should be wrapped in quote marks (sometimes.  Accept it anyway…)
			if !(value.first == "\"" && value.last == "\"") {
				print("Note: paramter (\(key)) value is not wrapped in quotes: \(value)")
			} else {
				//	Trim quotes
				value = String(value.dropLast())
				value = String(value.dropFirst())
			}
			return (key: key, value: value)
		}
		

		//	Basic request first, no auth yet.
		do {
			let request = HTTPClientRequest(url: serverURL)
			let response = try await httpClient.execute(request, timeout: .seconds(30))
			print("HTTP head", response)
			let body = try await response.body.collect(upTo: 1024 * 1024) // 1 MB
			print(String(buffer: body))
			
			//	should be 401
			if response.status != .unauthorized {
				print("Hmm, we should have had an 'unauthorised' status, but instead we got: \(response.status)")
				return
			}
			
			//	We are unauthorsied.  Look for the digest challenge (WWW-Authenticate header)
			guard let digestChallengeHeader = response.headers[authenticateHeaderName].first else {
				print("Cannot find Authentication Header in response.")
				return
			}
			
			//	Digest Challenge header should start with 'Digest'
			let digestPreamble = "Digest "
			if !digestChallengeHeader.hasPrefix(digestPreamble) {
				print("digestChallenge does not start with '\(digestPreamble)'")
				return
			}
			
			//	Get digest paramters
			let digestChallengeParamsString = digestChallengeHeader.dropFirst(digestPreamble.count)
			let digestParams = digestChallengeParamsString.components(separatedBy: ", ")
			
			for param in digestParams {
				if let paramTuple = paramStringToTuple(param) {
					if let paramKeyEnum = DigestParameterKey(rawValue: paramTuple.key) {
						digestParamsDict[paramKeyEnum] = paramTuple.value
					} else {
						print("We don't have a suitable case in enum type DigestParameterKey for this digest parameter key \(param) !")
					}
				} else {
					print("Badly formed Digest Parameter! \(param)")
				}
			}
			print("Digest Parameters: \(digestParamsDict)")

			/*
			e.g. of digestParamsDict:
			 
			Digest Params: [
				 "nonce": "3ea8908301a9edbc:9a68889df518fb53f8ee363a:18c20795603:f",
				 "qop": "auth",
				 "stale": "FALSE",
				 "domain": "/",
				 "realm": "9a68889df518fb53f8ee363a",
				 "algorithm": "MD5",
				 "opaque": "799d5"
			 ]
			 
			 or:
			 
			 [
			 DigestAuth.DigestAuthSample.DigestParameterKey.stale: "FALSE",
			 DigestAuth.DigestAuthSample.DigestParameterKey.qop: "auth",
			 DigestAuth.DigestAuthSample.DigestParameterKey.nonce: "c098528655cb96a8a9e442ddd2e42564", 
			 DigestAuth.DigestAuthSample.DigestParameterKey.algorithm: "MD5",
			 DigestAuth.DigestAuthSample.DigestParameterKey.realm: "me@kennethreitz.com",
			 DigestAuth.DigestAuthSample.DigestParameterKey.opaque: "8c9c49b7b29ee994e485a3aa0239db31"
			 ]

			 
			 */
			
		} catch {
			print("basic request failed:", error)
			return
		}
		
		//	Make second request, with digest-response in an 'Authorization' header.
		
		//	Do the hashing....
		
		guard let hashingAlgo = HashingAlgorithm(rawValue: digestParamsDict[.algorithm] ?? "") else {
			print("Server using a hashing algorithm that we don't yet handle: \(String(describing: digestParamsDict[.algorithm]))")
			return
		}
		guard let qopDirective = QOPDirective(rawValue: digestParamsDict[.qop] ?? "") else {
			print("Server using a QOP Directive that we don't yet handle: \(String(describing: digestParamsDict[.qop]))")
			return
		}

		print("using hashing algo: \(hashingAlgo) and QOP directive: \(qopDirective)")

		//	The HA1 and HA2 values used in the computation of the response are the hexadecimal representation (in lowercase) of the MD5 hashes respectively.
		
		
		//	Credentials Hash...
		/*
		 If the algorithm directive's value is "MD5" or unspecified, then HA1 is
			HA1 = MD5(username:realm:password)
		 If the algorithm directive's value is "MD5-sess", then HA1 is
			HA1 = MD5(MD5(username:realm:password):nonce:cnonce)
		 */
		
		var ha1_credentialsHash: String
		switch hashingAlgo {
		case .MD5sess:
			//	HA1 = MD5(MD5(username:realm:password):nonce:cnonce)
			let credentialsHash = MD5(string: "\(username):\(digestParamsDict[.realm] ?? ""):\(password)")
			ha1_credentialsHash = MD5(string: "\(credentialsHash):\(digestParamsDict[.nonce] ?? ""):\(digestParamsDict[.cnonce] ?? "")")
		default:
			//	Used when no algo specificed or MD5 specified
			//	HA1 = MD5(username:realm:password)
			ha1_credentialsHash = MD5(string: "\(username):\(digestParamsDict[.realm] ?? ""):\(password)")
		}
		
		//	QOP Hash...
		/*
		 If the qop directive's value is "auth" or is unspecified, then HA2 is
			HA2 = MD5(method:digestURI)
		 If the qop directive's value is "auth-int", then HA2 is
			HA2 = MD5(method:digestURI:MD5(entityBody))
		 */
		var ha2_methodURIHash: String
		switch qopDirective {
		case .authInt:
			//	HA2 = MD5(method:digestURI:MD5(entityBody))
			print("authInt qopDirective unimplemented!!!!  What is entityBody?")
			return
		default:
			//	Used when qop is auth or unspecified
			//	HA2 = MD5(method:digestURI)
			//	FIXME: Method is fixed here.  Also, is this the type of method that they mean?
			ha2_methodURIHash = MD5(string: "GET:\(serverURL)")
		}

		
		//	Response Hash...
		/*
		 If the qop directive's value is "auth" or "auth-int", then compute the response as follows:
			response = MD5(HA1:nonce:nonceCount:cnonce:qop:HA2)
		 If the qop directive is unspecified, then compute the response as follows:
			response = MD5(HA1:nonce:HA2)
		 */
		var responseHash: String
		switch qopDirective {
		case .auth, .authInt:
			//	response = MD5(HA1:nonce:nonceCount:cnonce:qop:HA2)
			//	FIXME: Don't hard-code nonceCount
			/*
			 https://www.rfc-editor.org/rfc/rfc2617#section-3
			 The nc-value is the hexadecimal
				  count of the number of requests (including the current request)
				  that the client has sent with the nonce value in this request.  For
				  example, in the first request sent in response to a given nonce
				  value, the client sends "nc=00000001".
			 */
			let nonceCount = "00000001"
			responseHash = MD5(string: "\(ha1_credentialsHash):\(digestParamsDict[.nonce] ?? ""):\(nonceCount):\(digestParamsDict[.cnonce] ?? ""):\(digestParamsDict[.qop] ?? ""):\(ha2_methodURIHash)")
		default:
			//	Unspecified qopDirective
			//	response = MD5(HA1:nonce:HA2)
			responseHash = MD5(string: "\(ha1_credentialsHash):\(digestParamsDict[.nonce] ?? ""):\(ha2_methodURIHash)")
		}
		
		
		//	Build the new request including the digest response header
		
		//	Build the auth header
		//	https://www.rfc-editor.org/rfc/rfc2617#section-3.2.1
		let authHeaderName = "Authorization"
		var authHeaderString = "Digest "
		
		//	Username
		let digestUsername = "username=\"\(username)\", "
		authHeaderString.append(digestUsername)
		//	Re-use from original response: Realm
		let digestRealm = "realm=\"\(digestParamsDict[.realm] ?? "")\", "
		authHeaderString.append(digestRealm)
		//	Re-use from original response: Nonce
		let digestNonce = "nonce=\"\(digestParamsDict[.nonce] ?? "")\", "
		authHeaderString.append(digestNonce)
		//	The URL that we are requesting
		let digestURI = "uri=\"\(serverURL)\", "
		authHeaderString.append(digestURI)
		//	The hash that we calculated containing the password and other data.
		let digestResponse = "response=\"\(responseHash)\", "
		authHeaderString.append(digestResponse)
		//	Re-use from original response: Algorithm
		//	No quotes for algo
		let digestAlgo = "algorithm=\(digestParamsDict[.algorithm] ?? ""), "
		authHeaderString.append(digestAlgo)

		//	FIXME: Should be a one-time number generated by the client (us).
		//	Client nonce
		let digestCNonce = "cnonce=\"00000000\", "
		if digestParamsDict[.qop] != nil {
			authHeaderString.append(digestCNonce)
		}
		//	Re-use from original response: Opaque
		let digestOpaque = "opaque=\"\(digestParamsDict[.opaque] ?? "")\", "
		authHeaderString.append(digestOpaque)
		//	Re-use from original response: QOP
		let digestQOP = "qop=\"\(digestParamsDict[.qop] ?? "")\", "
		authHeaderString.append(digestQOP)
		//	Last item, no comma at end...
		//	FIXME: Calculate correct nonce count
		let digestNonceCount = "nc=\"\("00000001")\" "
		if digestParamsDict[.qop] != nil {
			authHeaderString.append(digestNonceCount)
		}
		
		print("authorized request header: \(authHeaderString)")

		var authorisedRequest = HTTPClientRequest(url: serverURL)
		authorisedRequest.headers.add(name: authHeaderName, value: authHeaderString)

		do {
			let response = try await httpClient.execute(authorisedRequest, timeout: .seconds(30))

			print("HTTP head", response)
			let body = try await response.body.collect(upTo: 1024 * 1024) // 1 MB
			print(String(buffer: body))

			//	What status did we get back?
			print("Response status: \(response.status)")

		} catch {
			print("authorised request failed:", error)
			return
		}

		
		
	}
	
	func MD5(string: String) -> String {
		let digest = Insecure.MD5.hash(data: Data(string.utf8))
		return digest.map {
			String(format: "%02hhx", $0)
		}.joined()
	}

}



let serverURL = "http://httpbin.org/digest-auth/auth/testUserName/testPassword"
let digestAuthSample = DigestAuthSample(serverURL: serverURL, username: "testUserName", password: "testPassword")
//let digestAuthSample = DigestAuthSample(serverURL: "http://192.168.1.36/ISAPI/Streaming/channels/101/picture", username: "gateControl", password: "badgers123")


digestAuthSample.startUp()

Task{
	await digestAuthSample.go()
	await digestAuthSample.shutdown()
}

RunLoop.main.run(until: .distantFuture)


