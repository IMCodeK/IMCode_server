const jwt = require('jsonwebtoken');
require('dotenv').config();
// .env에 존재하는 Key로 암,복호화
const secretKey = process.env.JWT_SECRET;

// jwt 토큰 생성 옵션 (sha-256, 유효기간 1시간, 발급자는 pmos)
const options = {
    algorithm: "HS256",
    expiresIn: "1h",
    issuer: "pmos"
}

module.exports = {
    // 토큰 생성 메소드. 토큰 안에는 사용자의 id, 이름, type이 포함
    sign: (json) => {
        const payload = {
            id : json.id,
            name : json.name,
            type: json.type
        };
        const result = jwt.sign(payload, secretKey, options);
        return result;
    },    
    // 전달받은 토큰을 검증하는 메소드
    verify: (token) => {
        let decoded;
        try{
            decoded = jwt.verify(token, secretKey);
        } catch (err){
            if (err.message === 'jwt expired')
                return -3;
            else if (err.message === 'invalid token')
                return -2;
            else
                return -1;
        }
        return decoded;
        }
    } 
