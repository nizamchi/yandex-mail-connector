"use strict";
var __create = Object.create;
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getProtoOf = Object.getPrototypeOf;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(
  // If the importer is in node compatibility mode or this is not an ESM
  // file that has been converted to a CommonJS file using a Babel-
  // compatible transform (i.e. "__esModule" has not been set), then set
  // "default" to the CommonJS "module.exports" for node compatibility.
  isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", { value: mod, enumerable: true }) : target,
  mod
));
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);
var smtp_exports = {};
__export(smtp_exports, {
  sendEmail: () => sendEmail
});
module.exports = __toCommonJS(smtp_exports);
var import_nodemailer = __toESM(require("nodemailer"));
async function sendEmail(creds, params) {
  const transport = import_nodemailer.default.createTransport({
    host: creds.smtpHost ?? "smtp.yandex.com",
    port: 465,
    secure: true,
    auth: { type: "OAuth2", user: creds.email, accessToken: creds.oauthToken }
  });
  try {
    const info = await transport.sendMail({
      from: creds.email,
      to: params.to.join(", "),
      cc: params.cc?.join(", "),
      bcc: params.bcc?.join(", "),
      subject: params.subject,
      text: params.text,
      html: params.html,
      replyTo: params.replyTo,
      inReplyTo: params.inReplyTo,
      references: params.references?.join(" ")
    });
    return { success: true, messageId: info.messageId };
  } catch (e) {
    return { success: false, error: e instanceof Error ? e.message : String(e) };
  }
}
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  sendEmail
});
