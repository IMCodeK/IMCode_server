// 놓친 파라미터를 검사하는 모듈
module.exports = (obj) => {
    const missParameters = Object.entries(obj)
    .filter(it => it[1] == undefined).map(it => it[0]).join(',');
    return missParameters;
}