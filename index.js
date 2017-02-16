var request = require('request'),
q = require('yapl');

module.exports = EXPA;

function EXPA(username, password, enforceSSL){
	var r = request.defaults({
		rejectUnauthorized: typeof enforceSSL !== 'boolean' ? true : enforceSSL,
		jar: true,
		followAllRedirects: true
	});

	var _ = this,
	_baseUrl = 'https://gis-api.aiesec.org/v2',
	_token;

	var tokenRequest = function(){
		var deferred = q();
		
		r.get('https://auth.aiesec.org/users/sign_in', (error, response, body) => {
			var match = body.match('<meta.*content="(.*)".*name="csrf-token"');

			r.post({
				url: 'https://auth.aiesec.org/users/sign_in',
				form: {
					"user[email]": username,
					"user[password]": password,
					"authenticity_token": match[1],
					"commit": 'Sign in'
				}
			}, function(error, response, body){
				if(error) {
					deferred.reject(error);
				} else {
					response.body = body;
					deferred.resolve(response);
				}
			});

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
	 	tokenRequest().then((response) => {
	 		var cookie = response.req._headers.cookie;
	 		var token = cookie.match('expa_token=(.*)')[1].replace(/;.*/, '');
	 		_token = token;
	 		deferred.resolve(token);
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

	_.post = function(url, data){
		return _.request(url, {
			method: "POST",
			form: data
		});
	};

	_.patch = function(url, data){
		return _.request(url, {
			method: "PATCH",
			form: data
		});
	};

	return _;
}