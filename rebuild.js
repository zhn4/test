const crypto = require('crypto')
const request = require('request')

const url = 'https://dm.aliyuncs.com/'

module.exports = function (config, cb) {
  const nonce = Date.now()// 当前时间距离时间零点（1970年1月1日 00:00:00 UTC）的毫秒数
  const date = new Date()// 当前时间
  const errorMsg = []// 错误信息数组
  config = config || {}// 传入配置

  if (!config.accessKeyID) {
    errorMsg.push('accessKeyID required')
  }

  if (!config.accessKeySecret) {
    errorMsg.push('accessKeySecret required')
  }

  if (!config.accountName) {
    errorMsg.push('accountName required')
  }

  let param = {// 参数对象
    AccessKeyId: config.accessKeyID,
    Format: 'JSON',
    AccountName: config.accountName,
    AddressType: typeof config.addressType == 'undefined' ? 0 : config.addressType,
    SignatureMethod: 'HMAC-SHA1',
    SignatureNonce: nonce,
    SignatureVersion: '1.0',
    TemplateCode: config.templateCode,
    Timestamp: date.toISOString(),
    Version: '2015-11-23'
  }

  switch(config.action) {
    case 'single':// 单独
      param.Action = 'single'
      param.ReplyToAddress = !!config.replyToAddress
      param.ToAddress = config.toAddress

      if (!config.toAddress) {
        errorMsg.push('toAddress required')
      }

      if (config.fromAlias) {
        param.FromAlias = config.fromAlias
      }
      if (config.subject) {
        param.Subject = config.subject
      }
      if (config.htmlBody) {
        param.HtmlBody = config.htmlBody
      }
      if (config.textBody) {
        param.TextBody = config.textBody
      }
      break
    case 'batch':// 批量
      param.Action = 'batch'
      param.TemplateName = config.templateName
      param.ReceiversName = config.receiversName

      if (!config.templateName) {
        errorMsg.push('templateName required')
      }
      if (!config.receiversName) {
        errorMsg.push('receiversName required')
      }
      
      if (config.tagName) {
        param.TagName = config.tagName
      }
      break
    default:
      cb('error action', null)
  }

  if (errorMsg.length) {
    return cb(errorMsg.join(','))
  }

  let signStr = []
  for (let i in param) {// 各项参数转换url编码push到signStr数组
    signStr.push(encodeURIComponent(i) + '=' + encodeURIComponent(param[i]))
  }
  signStr.sort()// 排序
  signStr = signStr.join('&')// 拼接
  signStr = 'POST&%2F&' + encodeURIComponent(signStr)// 拼接

  const sign = crypto.createHmac('sha1', config.accessKeySecret + '&')// 加密
    .update(signStr)// 转换utf-8编码
    .digest('base64')// base64的摘要

  const signature = encodeURIComponent(sign)// 转换url编码

  let reqBody = ['Signature=' + signature]// 请求部分-签名

  for (let i in param) {// 参数的key-value添加到，请求部分-请求参数
    reqBody.push(i + '=' + param[i])
  }

  reqBody = reqBody.join('&')// 请求参数字符串拼接

  request({
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded'
    },
    uri: url,
    body: reqBody,
    method: 'POST'
  }, function (err, res, body) {
    cb(err, body)
  })
}
