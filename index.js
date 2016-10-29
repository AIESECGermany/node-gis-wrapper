var request = require('request'),
q = require('yapl');

module.exports = EXPA;

function EXPA(username, password, enforceSSL){

	var _ = this,
	_username = username,
	_password = password,
	_enforceSSL = typeof enforceSSL !== 'boolean' ? true : enforceSSL,
	_baseUrl = 'https://gis-api.aiesec.org/v2',
	_token,
	_jar = request.jar();

	var tokenRequest = function(){
		var deferred = q();
		request.post({
			url: 'https://auth.aiesec.org/users/sign_in',
			form: {
				"user[email]": _username,
				"user[password]": _password
			},
			"rejectUnauthorized": _enforceSSL,
			jar: _jar,
			followAllRedirects: true
		}, function(error, response, body){
			if(error) {
				deferred.reject(error);
			} else {
				deferred.resolve(body, response);
			}
		});
		return deferred.promise;
	};

	/**
	 * generateNewToken()
	 * function that performs a login with GIS auth to get a new access token
	 * @return void
	 */
	 var generateNewToken = function() {
	 	var deferred = q();
	 	tokenRequest().then(function(){
	 		var token = _jar.getCookieString('https://experience.aiesec.org').match('expa_token=(.*)')[1].replace(/;.*/, '');
	 		_token = token;
	 		deferred.resolve(_token);
	 	});
	 	return deferred.promise;
	 };


	 _.getToken = function(){
	 	var deferred = q();
	 	if(_token) {
	 		deferred.resolve(_token);
	 	} else {
	 		_.getNewToken().then(deferred.resolve);
	 	}
	 	return deferred.promise;
	 };

	/**
	 * @return String
	 */
	 _.getNewToken = function() {
	 	var deferred = q();
		generateNewToken.call(_) //provide EXPA as context
		.then(deferred.resolve);
		return deferred.promise;
	};

	_.request = function(uri, options){
		var deferred = q();
		var params = {};
		if (typeof options === 'object') {
			Object.assign(params, options, {uri: uri});
		} else if (typeof uri === 'string') {
			Object.assign(params, {uri: uri});
		} else {
			Object.assign(params, uri);
		}

		params.jar = _jar;
		params.rejectUnauthorized = _enforceSSL;
		if(params.uri.indexOf('http') < 0) params.baseUrl = _baseUrl;

		params.callback = function(err, resp, body){
			if(err) {
				deferred.reject(err);
			} else {
				try{
					var json = JSON.parse(body);
					if(json.status && json.status.code == 401) {
						//if token expired, get new one and retry
						_.getNewToken().then(function(){
							_.request(uri, options)
							.then(deferred.resolve)
							.catch(deferred.reject);
						});
					} else {
						deferred.resolve(json);
					}
				} catch(e) {
					deferred.resolve(body);
				}
				
			}
		};

		_.getToken().then(function(token){
			params.uri += `?access_token=${token}`;
			request(params);
		});

		return deferred.promise;
	};

	_.get = function(url, data){
		return _.request(url, {
			form: data
		});
	};

	return _;
}