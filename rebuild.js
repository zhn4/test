const crypto = require("crypto");
const axios = require("axios");

const url = "https://dm.aliyuncs.com/";

function request(url, reqBody) {
  return new Promise((resolve, reject) => {
    axios({
      headers: {
        "Content-Type": "application/x-www-form-urlencoded"
      },
      uri: url,
      body: reqBody,
      method: "POST"
    })
    .then((res) => {
      if(res.data.success) {
        resolve(res);
      }else {
        reject(res);
      }
    })
    .catch((err) => {
      reject(err);
    });
  });
};

module.exports.default = function(config, cb) {
  config = config || {};

  const nonce = Date.now(),
        date = new Date(),
        errorMsg = [];

  if (!config.accessKeyID) {
    errorMsg.push("accessKeyID required");
  };
  if (!config.accessKeySecret) {
    errorMsg.push("accessKeySecret required");
  };
  if (!config.accountName) {
    errorMsg.push("accountName required");
  };

  let param = {
    AccessKeyId: config.accessKeyID,
    Format: "JSON",
    AccountName: config.accountName,
    AddressType: typeof config.addressType == "undefined" ? 0 : config.addressType,
    SignatureMethod: "HMAC-SHA1",
    SignatureNonce: nonce,
    SignatureVersion: "1.0",
    TemplateCode: config.templateCode,
    Timestamp: date.toISOString(),
    Version: "2015-11-23"
  };
  switch(config.action) {
    case "single":
      if (!config.toAddress) {
        errorMsg.push("toAddress required");
      };

      param.Action = "single";
      param.ReplyToAddress = !!config.replyToAddress;
      param.ToAddress = config.toAddress;

      if (config.fromAlias) {
        param.FromAlias = config.fromAlias;
      };
      if (config.subject) {
        param.Subject = config.subject;
      };
      if (config.htmlBody) {
        param.HtmlBody = config.htmlBody;
      };
      if (config.textBody) {
        param.TextBody = config.textBody;
      };
      break;
    case "batch":
      if (!config.templateName) {
        errorMsg.push("templateName required");
      };
      if (!config.receiversName) {
        errorMsg.push("receiversName required");
      };

      param.Action = "batch";
      param.TemplateName = config.templateName;
      param.ReceiversName = config.receiversName;
      
      if (config.tagName) {
        param.TagName = config.tagName;
      };
      break;
    default:
      cb("error action", null);
      break;
  }

  if (errorMsg.length) {
    return cb(errorMsg.join(","));
  }
  
  let signStr = [];
  for (let i in param) {
    signStr.push("".concat(encodeURIComponent(i), "=", encodeURIComponent(param[i])));
  }
  signStr.sort();
  signStr = signStr.join("&");
  signStr = "POST&%2F&" + encodeURIComponent(signStr);
  const sign = crypto.createHmac("sha1", config.accessKeySecret + "&")
    .update(signStr)
    .digest("base64");
  const signature = encodeURIComponent(sign);
  let reqBody = ["Signature=" + signature];
  for (let i in param) {
    reqBody.push("".concat(i, "=", param[i]));
  }
  reqBody = reqBody.join("&");

  request(url, reqBody);

};