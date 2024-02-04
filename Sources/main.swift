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

//	MARK: - Free Functions -

///	Takes a Swift String and returns it hashed by MD5 (also in String format)
///	Taken from:
///	https://stackoverflow.com/questions/32163848/how-can-i-convert-a-string-to-an-md5-hash-in-ios-using-swift
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


//	MARK: - Extensions -

public extension String {
	///	base64EncodedString
	var base64EncodedString:String{
		if let data = data(using: .utf8){
			return data.base64EncodedString()
		}
		return ""
	}
}

public extension Int {
	
	//	Gives the number of numbers in the integer
	func countOfNumbers() -> Int{
		// Store the total count
		var count = 0
		
		// Store the number
		var num = self
		
		// Checking the number for 0
		// If yes print 1
		if (num == 0){
			return 1
		}
		
		// Check for the positive number
		while (num > 0){
			
			// Divide the num by 10 and store
			// the quotient into the num variable
			num = num / 10
			
			// If the quotient is not zero, then update the
			// count by one. If the quotient is zero,
			// then stop the count
			count += 1
		}
		
		// Return the final count
		return count
	}
}

//	MARK: - Classes -

///	A Simple class to demonstrate Digest Auth using async-http-client
class DigestAuthSample {
	typealias DigestParametersDictionary = [DigestParameterKey: String]

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
	
	internal init(serverURL: String, username: String, password: String)  {
		self.serverURL = serverURL
		self.username = username
		self.password = password
	}


	///	The address of the endpoint that we are trying to reach
	var serverURL: String
	///	The username we will be providing to the server for authentication
	var username: String
	///	The password we will be providing to the server for authentication
	var password: String
	
	///	Keep track of how many times the nonce is used.
	var currentNonce = "" {
		willSet {
			//	If the nonce is the same, increment the nonceCount
			if newValue == currentNonce {
				nonceCount = nonceCount + 1
				print("re-used nonce...")
			} else {
				nonceCount = 1
				print("new nonce...")
			}
		}
	}

	///	Number of times that we have used the same nonce
	var nonceCount = 0

	///	Client (us) nonce
	var cnonce = ""
	
//	The nonce is the random number generated by service, the following generation formula is suggested: nonce = BASE64(time-stamp MD5(time-stamp ":" ETag ":" private-key)). The time-stamp in the formula is the time stamp generated by service or the unique serial No.; the ETag is the value of HTTP ETag header in the request message; the private-key is the data that only known by service.

	
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
		//	Can't use components(separatedBy: "=") as that character can appear in the hash value.
		
		//	Instead find the first "=" and split on that.
		let equalIndex = param.firstIndex(of: "=")
		guard equalIndex != nil else {
			print("Error: paramter is not correctly formed: \(param)")
			return nil
		}
				
		let key = param.prefix(upTo: equalIndex!)
		var value = param.suffix(from: param.index(equalIndex!, offsetBy: 1))
//		print("k/v: \(key)/\(value)")
		
		//	Value should be wrapped in quote marks (sometimes.  Accept it anyway…)
		if !(value.first == "\"" && value.last == "\"") {
			print("Note: paramter (\(key)) value is not wrapped in quotes: \(value)")
		} else {
			//	Trim quotes
			value = value.dropLast()
			value = value.dropFirst()
		}
		return (key: String(key), value: String(value))
	}
	
	///	Sets the cNonce to a hash of a private keya and the timestamp now.
	func regenerateCNonce() {
//		The nonce is the random number generated by service, the following generation formula is suggested: nonce = BASE64(time-stamp MD5(time-stamp ":" ETag ":" private-key)). The time-stamp in the formula is the time stamp generated by service or the unique serial No.; the ETag is the value of HTTP ETag header in the request message; the priviate-key is the data that only known by service.
		
//		cnonce
//			 This MUST be specified if a qop directive is sent (see above), and
//			 MUST NOT be specified if the server did not send a qop directive in
//			 the WWW-Authenticate header field.  The cnonce-value is an opaque
//			 quoted string value provided by the client and used by both client
//			 and server to avoid chosen plaintext attacks, to provide mutual
//			 authentication, and to provide some message integrity protection.
//			 See the descriptions below of the calculation of the response-
//			 digest and request-digest values.
		
		//	BASE64(time-stamp MD5(time-stamp ":" ETag ":" private-key))
		let privateKey = "CAFEBABE"
		let timestamp = Date().timeIntervalSince1970

		let cNonce = "\(timestamp):\(privateKey)"
		let cNonceHash = ("\(timestamp) \(MD5(string: cNonce))")
		let cNonceEncoded = cNonceHash.base64EncodedString
		self.cnonce = cNonceEncoded
	}
	
	///	Returns the Nonce Count as a string, padded with leading Zeros so that the string is 8 chars long
	func paddedNonceCountString() -> String {
		let paddingZeros = 8 - nonceCount.countOfNumbers()
		var returnString = ""
		
		(0..<paddingZeros).forEach{Int in returnString.append("0") }
		returnString.append(String(nonceCount))
		print("paddedNonceCountString: \(returnString)")
		return(returnString)
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
			print("HA1 hash: MD5sess --> HA1 = MD5(MD5(username:realm:password):nonce:cnonce)")
			//	HA1 = MD5(MD5(username:realm:password):nonce:cnonce)
			let credentialsHash = MD5(string: "\(username):\(digestParamsDict[.realm] ?? ""):\(password)")
			ha1_credentialsHash = MD5(string: "\(credentialsHash):\(digestParamsDict[.nonce] ?? ""):\(digestParamsDict[.cnonce] ?? "")")
		default:
			print("HA1 hash: MD5 --> HA1 = MD5(username:realm:password)")
			print("HA1 hash: MD5 --> HA1 = MD5(\(username):\(digestParamsDict[.realm] ?? ""):\(password))")
			//	Used when no algo specificed or MD5 specified
			//	HA1 = MD5(username:realm:password)
			ha1_credentialsHash = MD5(string: "\(username):\(digestParamsDict[.realm] ?? ""):\(password)")
			print("HA1 = \(ha1_credentialsHash)")
		}
		
		//	QOP Hash...
		/*
		 If the qop directive's value is "auth" or is unspecified, then HA2 is
			HA2 = MD5(method:digestURI)
		 If the qop directive's value is "auth-int", then HA2 is
			HA2 = MD5(method:digestURI:MD5(entityBody))
		 */
		var ha2_methodURIHash: String
		let digestURI = relativePath()
		switch qopDirective {
		case .authInt:
			//	HA2 = MD5(method:digestURI:MD5(entityBody))
			print("authInt qopDirective unimplemented!!!!  What is entityBody?")
			return nil
		default:
			//	Used when qop is auth or unspecified
			//	HA2 = MD5(method:digestURI)
			print("HA2 = MD5(method:digestURI)")
			//	FIXME: Method is fixed here.  Also Optional is handled badly...
			if digestURI == nil {
				print("Warning, digestURL is nil! Using '/' instead...")
			}
			print("HA2 = MD5(GET:\(digestURI ?? "/"))")
			ha2_methodURIHash = MD5(string: "GET:\(digestURI ?? "/")")
			print("HA2 = \(ha2_methodURIHash)")
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
			regenerateCNonce()

			//	response = MD5(HA1:nonce:nonceCount:cnonce:qop:HA2)
			print("response = MD5(HA1:nonce:nonceCount:cnonce:qop:HA2)")
			//	FIXME: Don't hard-code nonceCount
			/*
			 https://www.rfc-editor.org/rfc/rfc2617#section-3
			 The nc-value is the hexadecimal
				  count of the number of requests (including the current request)
				  that the client has sent with the nonce value in this request.  For
				  example, in the first request sent in response to a given nonce
				  value, the client sends "nc=00000001".
			 */
			
			responseHash = MD5(string: "\(ha1_credentialsHash):\(digestParamsDict[.nonce] ?? ""):\(paddedNonceCountString()):\(cnonce):\(digestParamsDict[.qop] ?? ""):\(ha2_methodURIHash)")
			print("response = MD5(\(ha1_credentialsHash):\(digestParamsDict[.nonce] ?? ""):\(paddedNonceCountString()):\(cnonce):\(digestParamsDict[.qop]!):\(ha2_methodURIHash))")
			print("responseHash = \(responseHash)")
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
		let digestURIString = relativePath()
		if digestURIString == nil {
			print("digestURIString is NIL!")
		}
		let digestURI = "uri=\"\(digestURIString ?? "/")\", "
		authHeaderString.append(digestURI)
		
		//	The hash that we calculated containing the password and other data.
		let digestResponse = "response=\"\(responseHashString)\", "
		authHeaderString.append(digestResponse)

		//	Re-use from original response: Algorithm
		//	No quotes for algo name
		let digestAlgo = "algorithm=\(digestParamsDict[.algorithm] ?? ""), "
		authHeaderString.append(digestAlgo)

		//	Client nonce
		
		//			 This MUST be specified if a qop directive is sent (see above), and
		//			 MUST NOT be specified if the server did not send a qop directive in
		//			 the WWW-Authenticate header field.
		
		let digestCNonce = "cnonce=\"\(cnonce)\", "
		if digestParamsDict[.qop] != nil {
			authHeaderString.append(digestCNonce)
		}

		//	Re-use from original response: Opaque (if there is one)
		if let opaque = digestParamsDict[.opaque] {
			let digestOpaque = "opaque=\"\(opaque)\", "
			authHeaderString.append(digestOpaque)
		}

		//	Re-use from original response: QOP
		let digestQOP = "qop=\"\(digestParamsDict[.qop] ?? "")\", "
		authHeaderString.append(digestQOP)

		//	Last item, no comma at end...
		let digestNonceCount = "nc=\(paddedNonceCountString()) "
		if digestParamsDict[.qop] != nil {
			authHeaderString.append(digestNonceCount)
		}
		
		return authHeaderString
	}
	
	func relativePath() -> String? {
		let fullURL = URL(string:serverURL)
		if #available(macOS 13.0, *) {
			let path = fullURL?.path()
			return path
		} else {
			print("I'm not expecting this code to be run before macOS 13..!!!!")
			return nil
		}
	}
	
	
	
	func digestAuthRequest(serverUrlString: String, previousResponse: HTTPClientResponse? ) async -> HTTPClientResponse? {
		var digestParamsDict = DigestParametersDictionary()
		
		//	First request is without auth at all
		if previousResponse == nil {
			//	Basic request first, no auth yet.
			print("Initial HTTP request without any authorisation.")
			do {
				let request = HTTPClientRequest(url: serverUrlString)
				let response = try await httpClient.execute(request, timeout: .seconds(30))
				print("HTTP header for first request: ", response)
				let body = try await response.body.collect(upTo: 1024 * 1024) // 1 MB
				print(String(buffer: body))
				print(" ")
				
				//	should be 401
				if response.status != .unauthorized {
					print("Hmm, we should have had an 'unauthorised' status, but instead we got: \(response.status)")
					return nil
				}
				
				//	Correct path
				return response

			} catch {
				print("basic request failed:", error)
				return nil
			}
		}
		
		//	This one is a
		//	Digest Auth request using headers from previous response
		let unauthorisedResponse = previousResponse!
		
		//	Get the Digest Auth paramters from the response headers
		guard let params = digestChallengeParametersDictionary(fromResponse: unauthorisedResponse) else {
			print("unable to get digest params")
			return nil
		}
		if let nonce = params[DigestParameterKey.nonce] {
			currentNonce = nonce
		}
		digestParamsDict = params
		cavemanLineBreak("Digest Parameters: \(String(describing: digestParamsDict))")

		//	Make a second request, with digest-response in an 'Authorization' header.
		
		//	Do the hashing....
		let responseHashString = doHashing(withDigestParameters: digestParamsDict)
		guard responseHashString != nil else {
			print("Unable to build response auth hashes...")
			return nil
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
			
			//	Happy Path
			return response
		} catch {
			print("authorised request failed:", error)
			return nil
		}

//		return nil
	}

	func go2() async {
		guard let noAuthResponse = await digestAuthRequest(serverUrlString: serverURL, previousResponse: nil) else {
			print("Initial unauthorised request failed")
			return
		}
		
		guard let authResponse = await digestAuthRequest(serverUrlString: serverURL, previousResponse: noAuthResponse) else {
			print("authorised request failed")
			return
		}
		
		
		do {
			let body = try await authResponse.body.collect(upTo: 1024 * 1024) // 1 MB
			cavemanLineBreak("Authorised digest auth Response Body: \(String(buffer: body))")
		} catch  {
			print("Authorised digest auth request failed")
			return
		}

		//	What status did we get back?
		cavemanLineBreak("Response status: \(authResponse.status)")
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
			if let nonce = params[DigestParameterKey.nonce] {
				currentNonce = nonce
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
	
	func testHashing() {
		/*
		 
		 HA1 = MD5( "Mufasa:testrealm@host.com:Circle Of Life" )

			   = 939e7578ed9e3c518a452acee763bce9

		   HA2 = MD5( "GET:/dir/index.html" )

			   = 39aff3a2bab6126f332b942af96d3366

		   Response = MD5( "939e7578ed9e3c518a452acee763bce9:\

							dcd98b7102dd2f0e8b11d0f600bfb0c093:\

							00000001:0a4f113b:auth:\

							39aff3a2bab6126f332b942af96d3366" )

					= 6629fae49393a05397450978507c4ef1
		 
		 */
		cavemanBreakSection("Test Hashing")

		var expected = "939e7578ed9e3c518a452acee763bce9"
		var computed = MD5(string: "Mufasa:testrealm@host.com:Circle Of Life")
		print("\(expected) \n vs \n\(computed)")

		expected = "39aff3a2bab6126f332b942af96d3366"
		computed = MD5(string: "GET:/dir/index.html")
		print("\(expected) \n vs \n\(computed)")

	}
	
}



//	Main entry point.
cavemanBreakSection("Main Entry")

//	https://stackoverflow.com/questions/6509278/authentication-test-servers

//	Hikvision NVR
//let digestAuthSample = DigestAuthSample(serverURL: "http://192.168.1.36/ISAPI/Streaming/channels/101/picture", username: "gateControl", password: "badgers123")

//	HTTPBin Test Server
let digestAuthSample = DigestAuthSample(serverURL: "http://httpbin.org/digest-auth/auth/myTestUsername/myTestPassword", username: "myTestUsername", password: "myTestPassword")

//	Local MAMP setup
//let digestAuthSample = DigestAuthSample(serverURL: "http://localhost:8888/dir/index.html", username: "Mufasa", password: "Circle Of Life")



digestAuthSample.startUp()

digestAuthSample.testHashing()

Task{
	await digestAuthSample.go2()
	await digestAuthSample.shutdown()
}


cavemanBreakSection("runloop run forever…")
RunLoop.main.run(until: .distantFuture)
cavemanBreakSection("Should never get here…")

