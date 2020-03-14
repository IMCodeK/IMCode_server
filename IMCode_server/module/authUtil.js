const jwt = require('./jwt');

// jwt token을 이용해 authentication, reading user information를 수행하는 미들웨어
const authUtil = {
    validToken: (req, res, next) => {
        // request header로부터 token을 받는다.
        const token = req.headers.token;
        // token이 없다면 false
        if(!token) {
            return res.status(404).send('empty jwt token');
        } else {
            // token을 verify 하고 return 값을 user에 담는다.
            const user = jwt.verify(token);   
            if(user == -3)
                return res.status(404).send('expired token');   
            else if(user == -2 || user == -1)
                return res.status(404).send('invalid token');
            else     
                req.decoded = user;            
            // request의 decoded에 user 정보를 담고 다음 함수에 넘긴다. 
            next();
        }
    },
    // jwt token이 없는 것을 확인하는 미들웨어(로그인, 회원가입)
    checkNoToken: (req, res, next) => {
        const user = jwt.verify(req.headers.token); 
        // verify 에러가 떠야 정상 동작
        if(user == -1 || user == -2 || user == -3) {
            next();
        // 이미 토큰이 있다면 false
        } else {
            return res.status(404).send('already have token');
        }
    }
};

module.exports = authUtil;