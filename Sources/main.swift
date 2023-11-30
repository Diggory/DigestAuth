import AsyncHTTPClient
import Crypto
import Foundation

cavemanLineBreak("Hello, world!  DigestAuth")

/*
 
 PseudoCode
 
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



//	MARK: - Extensions -

extension DataProtocol {
	///	emits data in 0x Hex String format  (0xDEADBEEF etc...)
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

//	MARK: - Global Constants -

let charA = UInt8(UnicodeScalar("a").value)
let char0 = UInt8(UnicodeScalar("0").value)

//	MARK: - Free Functions -

func itoh(_ value: UInt8) -> UInt8 {
	return (value > 9) ? (charA + value - 10) : (char0 + value)
}

///	Takes a Swift String and returns it hashed by MD5 (also in String format)
func MD5(string: String) -> String {
	let digest = Insecure.MD5.hash(data: Data(string.utf8))
	return digest.map {
		String(format: "%02hhx", $0)
	}.joined()
}

///	Prints a new caveman debugging section (spaces out print statements for functions)
func cavemanBreakSection(_ functionName: String) {
	print("")
	print(functionName)
	var number = 0
	var underscore = ""
	repeat {
		underscore += "="
		number += 1
	} while number <= functionName.count - 1

	
	print(underscore)
	print("")
}

///	Prints a newline to separate caveman debugging statements
func cavemanLineBreak(_ functionName: String) {
	print(functionName)
	print(" ")
}


//	MARK: - Classes -

///	A Simple class to demonstrate Digest Auth using async-http-client
class DigestAuthSample {
	typealias DigestParametersDictionary = [DigestParameterKey: String]

	internal init(serverURL: String, username: String, password: String)  {
		self.serverURL = serverURL
		self.username = username
		self.password = password
	}

	///	Keys used in the Digest Header
	///	https://www.rfc-editor.org/rfc/rfc2617#section-3.2.1
	enum DigestParameterKey: String, Hashable {
		//	Response Keys
		
		///	A server-specified data string which should be uniquely generated each time a 401 response is made
		case nonce
		///	a quoted string of one or more tokens indicating the "quality of protection" values supported by the server
		case qop
		///	 A flag, indicating that the previous request from the client was rejected because the nonce value was stale  
		///	 (TRUE/FALSE)
		case stale
		///	A quoted, space-separated list of URIs, as specified in RFC XURI [7], that define the protection space
		case domain
		///	A string to be displayed to users so they know which username and password to use
		case realm
		///	A string indicating a pair of algorithms used to produce the digest and a checksum. 
		///	If this is not present it is assumed to be "MD5"
		case algorithm
		///	A string of data, specified by the server, which should be returned by the client unchanged 
		///	in the Authorization header of subsequent requests with URIs in the same protection space
		case opaque
		
		//	Re-request keys

		///	This MUST be specified if a qop directive is sent (see above), and
		///	MUST NOT be specified if the server did not send a qop directive in
		///	the WWW-Authenticate header field.  The cnonce-value is an opaque
		///	quoted string value provided by the client and used by both client
		///	and server to avoid chosen plaintext attacks
		case cnonce
		///	A string of 32 hex digits computed as defined below, which proves
		///	that the user knows a password
		case response
		///	The user's name in the specified realm.
		case username
		///	The URI from Request-URI of the Request-Line; duplicated here
		///	because proxies are allowed to change the Request-Line in transit.
		case digesturi = "digest-uri"
	}
	
	///	Hashing algorithms  used in Digest Auth
	///	Not exhaustive...
	enum HashingAlgorithm: String {
		case MD5 = "MD5"
		case MD5sess = "MD5-sess"
		case unhandled
	}
	
	///	Quailty of Protections levels used in Digest Auth
	enum QOPDirective: String {
		case auth = "auth"
		case authInt = "auth-int"
		case unhandled
	}

	///	The address of the endpoint that we are trying to reach
	var serverURL: String
	///	The username we will be providing to the server for authentication
	var username: String
	///	The password we will be providing to the server for authentication
	var password: String

	///	Async HTTP client instance
	var httpClient = HTTPClient(eventLoopGroupProvider: .singleton)
		
	///	Currently does nothing…
	func startUp() {
		cavemanBreakSection(#function)
	}
	
	///	Required before we close-down the app - cleans-up the HTTP Client objects…
	func shutdown() async {
		cavemanBreakSection(#function)

		// it is important to shutdown the httpClient after all requests are done, even if one failed
		try! await httpClient.shutdown()
	}
	
	//	Digest Auth manipulation Functions
	
	///	Get the digest auth parameters from the Reponse object that the server gives us
	func digestChallengeParametersDictionary(fromResponse response: HTTPClientResponse) -> DigestParametersDictionary? {
		cavemanBreakSection(#function)
		let authenticateHeaderName = "WWW-Authenticate"
		var digestParamsDict = [DigestParameterKey: String]()

		//	Look for the digest challenge (WWW-Authenticate header)
		guard let digestChallengeHeader = response.headers[authenticateHeaderName].first else {
			print("Cannot find Authentication Header in response.")
			return nil
		}
		
		//	Digest Challenge header should start with 'Digest'
		let digestPreamble = "Digest "
		if !digestChallengeHeader.hasPrefix(digestPreamble) {
			print("digestChallenge does not start with '\(digestPreamble)'")
			return nil
		}
		
		//	Get digest paramters
		let digestChallengeParamsString = digestChallengeHeader.dropFirst(digestPreamble.count)
		let digestParams = digestChallengeParamsString.components(separatedBy: ", ")
		
		for param in digestParams {
			if let paramTuple = digestParamStringToTuple(param) {
				if let paramKeyEnum = DigestParameterKey(rawValue: paramTuple.key) {
					digestParamsDict[paramKeyEnum] = paramTuple.value
				} else {
					print("We don't have a suitable case in enum type DigestParameterKey for this digest parameter key \(param) !")
				}
			} else {
				print("Badly formed Digest Parameter! \(param)")
			}
		}
		
		cavemanLineBreak("Digest Parameters: \(digestParamsDict)")
		return digestParamsDict
	}
	
	
	
	///	Takes a string of the form 'key="value"' and turns it into a labelled tuple.
	func digestParamStringToTuple(_ param: String) -> (key: String, value: String)? {
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
	

	///	Digest Auth Hashing requirements,  reduced to one function.
	func doHashing(withDigestParameters digestParamsDict: DigestParametersDictionary) -> String? {
		cavemanBreakSection(#function)

		guard let hashingAlgo = HashingAlgorithm(rawValue: digestParamsDict[.algorithm] ?? "") else {
			print("Server using a hashing algorithm that we don't yet handle: \(String(describing: digestParamsDict[.algorithm]))")
			return nil
		}
		guard let qopDirective = QOPDirective(rawValue: digestParamsDict[.qop] ?? "") else {
			print("Server using a QOP Directive that we don't yet handle: \(String(describing: digestParamsDict[.qop]))")
			return nil
		}

		cavemanLineBreak("using hashing algo: \(hashingAlgo) and QOP directive: \(qopDirective)")
		
		//	HA1 and HA2 as per: https://en.wikipedia.org/wiki/Digest_access_authentication
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
			return nil
		default:
			//	Used when qop is auth or unspecified
			//	HA2 = MD5(method:digestURI)
			//	FIXME: Method is fixed here.
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
		
		//	We made it here!
		return responseHash
	}
	
	
	///	Create the digest  authorisation header string required to pass back to the server once we have the parameters that it has passed us.
	func buildAuthorisationHeader(digestParameters digestParamsDict: DigestParametersDictionary, responseHashString: String) -> String {
		cavemanBreakSection(#function)
		//	Build the auth header
		//	https://www.rfc-editor.org/rfc/rfc2617#section-3.2.1
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
		//	Absolute URI
		let digestURI = "uri=\"\(serverURL)\", "
		authHeaderString.append(digestURI)

		//	Only the path
//		let fullURL = URL(string:serverURL)
//		if #available(macOS 13.0, *) {
//			let path = fullURL?.path()
//			let digestURI = "uri=\"\(path ?? "/")\", "
//			authHeaderString.append(digestURI)
//		} else {
//			print("I'm not expecting this code to be run before macOS 13...")
//			return
//		}

		//	The hash that we calculated containing the password and other data.
		let digestResponse = "response=\"\(responseHashString)\", "
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

		//	FIXME: Calculate correct nonce count
		//	Last item, no comma at end...
		let digestNonceCount = "nc=\("00000001") "
		if digestParamsDict[.qop] != nil {
			authHeaderString.append(digestNonceCount)
		}
		
		return authHeaderString
	}
	
	
	///	Run the main test - request a resource from an HTTP server that requires digest auth credentials
	func go() async {
		cavemanBreakSection(#function)

		var digestParamsDict = DigestParametersDictionary()
		
		//	Basic request first, no auth yet.
		print("Initial HTTP request without any authorisation.")
		do {
			let request = HTTPClientRequest(url: serverURL)
			let response = try await httpClient.execute(request, timeout: .seconds(30))
			print("HTTP header for first request: ", response)
			let body = try await response.body.collect(upTo: 1024 * 1024) // 1 MB
			print(String(buffer: body))
			print(" ")
			
			//	should be 401
			if response.status != .unauthorized {
				print("Hmm, we should have had an 'unauthorised' status, but instead we got: \(response.status)")
				return
			}
			
			//	Get the Digest Auth paramters from the response headers
			guard let params = digestChallengeParametersDictionary(fromResponse: response) else {
				print("unable to get digest params")
				return
			}
			digestParamsDict = params
			cavemanLineBreak("Digest Parameters: \(String(describing: digestParamsDict))")
		} catch {
			print("basic request failed:", error)
			return
		}
		
		//	Make a second request, with digest-response in an 'Authorization' header.
		
		//	Do the hashing....
		let responseHashString = doHashing(withDigestParameters: digestParamsDict)
		guard responseHashString != nil else {
			print("Unable to build response hashes...")
			return
		}
		
		//	Build the new request including the digest response header
		cavemanBreakSection("Second http request with an auth header…")
		//	Build the auth header
		let authHeaderString = buildAuthorisationHeader(digestParameters: digestParamsDict, responseHashString: responseHashString!)

		cavemanLineBreak("Authorized request header: \(authHeaderString)")
		var authorisedRequest = HTTPClientRequest(url: serverURL)

		///	Name of theHTTP  header in the second HTTP request which inlcludes digest auth information.
		let authHeaderName = "Authorization"
		authorisedRequest.headers.add(name: authHeaderName, value: authHeaderString)
		cavemanLineBreak("All headers: \(authorisedRequest.headers)")

		do {
			let response = try await httpClient.execute(authorisedRequest, timeout: .seconds(30))
			cavemanLineBreak("Authorised HTTP request response: \(response)")

			let body = try await response.body.collect(upTo: 1024 * 1024) // 1 MB
			cavemanLineBreak("Response Body: \(String(buffer: body))")

			//	What status did we get back?
			cavemanLineBreak("Response status: \(response.status)")
		} catch {
			print("authorised request failed:", error)
			return
		}
		
	}
	
}



//	Main entry point.
cavemanBreakSection("Main Entry")

///	Address of the endpoint on the server that we are tesing against
let serverURL = "http://httpbin.org/digest-auth/auth/testUserName/testPassword"
let digestAuthSample = DigestAuthSample(serverURL: serverURL, username: "testUserName", password: "testPassword")
//let digestAuthSample = DigestAuthSample(serverURL: "http://192.168.1.36/ISAPI/Streaming/channels/101/picture", username: "gateControl", password: "badgers123")

digestAuthSample.startUp()

Task{
	await digestAuthSample.go()
	await digestAuthSample.shutdown()
}

cavemanBreakSection("runloop run forever…")
RunLoop.main.run(until: .distantFuture)
cavemanBreakSection("Should never get here…")

