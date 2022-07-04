const jwt = require('jsonwebtoken');
const { promisify } = require('util')

class JWT {

	static signToken(payload){
		console.log(payload)
		return jwt.sign(payload, process.env.JWT_SECRET, {
			expiresIn: process.env.JWT_EXPIRES_IN
		});
	}

	static async decodeToken(token){
		return await promisify(jwt.verify)(token, process.env.JWT_SECRET);
	}
}

module.exports = JWT;