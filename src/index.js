const jwt = require("jsonwebtoken")

class CoCreateAuth {
    /**
     * config structure 
     * https://www.npmjs.com/package/jsonwebtoken
     {
        key: 'xxxxxx', // any value
        options: {
            algorithm: "HS256",
            expiresIn: "30m",
            issuer: "issuer"
        }
     }
     **/
    
    
    constructor(config) {
        this.config = config
    }
    
    async generateToken({user_id}) {
        console.log('token---+---', {user_id}, this.config)
        const {key, options} = this.config
        const result = {
            token: jwt.sign({user_id}, key, options),
        }
        return result.token;
    }
    
    async getUserId(req) {
        
        try {
            let { user_id } = await this.wsCheck(req)
            return user_id
        } catch (err) {
            return null
        }
    }
    
    getTokenFromCookie(cookie) {
        let token = null;
        if (cookie) {
            cookie.split(';').forEach((c) => {
                try {
                    var parts = c.split('=')
                    if (parts[0].trim() == 'token') {
                        token = decodeURI(parts[1].trim());
                    }
                } catch(err) {
                    console.log(err)
                }
            })
        }
        return token;
    }
    
    async wsCheck(req) {
        const headers = req.headers
        let token = this.getTokenFromCookie(headers.cookie);
        if (!token) {
            token = headers['sec-websocket-protocol'];
        }

        let result = {}
        if (token) {
            result = await this.verifiyToken(token);
        } 
        
        return result;
    }
    
    async httpCheck(req) {
        
    }
    
    async verifiyToken(token) {
        let decoded;
        try {
            decoded = await jwt.verify(token, this.config.key)
        } catch (err) {
            if (err.message === 'jwt expired') {
                console.log('Expired Token')
                return null
            } else if (err.message === 'invalid token') {
                console.log('Invalid Token')
                return null
            } else {
                console.log('invalid token')
                return null;
            }
        }
        return decoded;
    }
}

module.exports = CoCreateAuth;