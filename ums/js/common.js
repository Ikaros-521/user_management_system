// local storage常量
const userName = 'username';
const ROLES = 'roles';
const tokenKey = 'access_token';
const refreshToken = 'refresh_token';
const EXPIRES = 'expires';

const serverApiUrl = 'http://127.0.0.1:1119';
const localPcApiUrl = 'http://127.0.0.1:1119';

// 获取URL参数
function getQueryVariable(variable) {
    var query = window.location.search.substring(1);
    var vars = query.split("&");
    for (var i = 0; i < vars.length; i++) {
        var pair = vars[i].split("=");
        if (pair[0] == variable) { return decodeURIComponent(pair[1]); }
    }
    return false;
}

// json转urlencoded key=value& 形式
function jsonToUrlEncoded(json) {
    let urlEncoded = '';
    for (let key in json) {
        if (json.hasOwnProperty(key)) {
            if (urlEncoded.length > 0) {
                urlEncoded += '&';
            }
            urlEncoded += encodeURIComponent(key) + '=' + encodeURIComponent(json[key]);
        }
    }
    return urlEncoded;
}

// 统一处理ajax请求返回的错误code
function handleAjaxError(xhr) {
    var error = JSON.parse(xhr.responseText);
    var errorMessage = '';

    switch (xhr.status) {
        case 400:
            errorMessage = '请求无效，请检查输入的数据。';
            break;
        case 401:
            errorMessage = '未授权，请登录后重试。';
            break;
        case 403:
            errorMessage = '禁止访问，您没有权限执行此操作。';
            break;
        case 404:
            errorMessage = '未找到资源，请检查请求的地址。';
            break;
        case 409:
            errorMessage = '冲突，数据可能已存在。';
            break;
        case 500:
            errorMessage = '服务器内部错误，请稍后重试。';
            break;
        default:
            errorMessage = '未知错误，请稍后重试。';
    }

    return errorMessage;
}
