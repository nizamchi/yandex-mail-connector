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
var token_exports = {};
__export(token_exports, {
  loadCredentials: () => loadCredentials
});
module.exports = __toCommonJS(token_exports);
var import_fs = __toESM(require("fs"));
var import_path = __toESM(require("path"));
function findTokenFile() {
  const candidates = [
    import_path.default.join(__dirname, "..", "token.json"),
    // project root
    import_path.default.join(process.cwd(), "token.json")
    // cwd fallback
  ];
  for (const p of candidates) {
    try {
      import_fs.default.accessSync(p, import_fs.default.constants.R_OK);
      return p;
    } catch {
    }
  }
  return null;
}
function loadCredentials() {
  const tokenFile = findTokenFile();
  if (tokenFile) {
    let raw;
    try {
      raw = JSON.parse(import_fs.default.readFileSync(tokenFile, "utf8"));
    } catch (e) {
      throw new Error(`Failed to read token.json at ${tokenFile}: ${String(e)}`);
    }
    if (!raw.access_token || !raw.email) {
      throw new Error('token.json must contain "access_token" and "email"');
    }
    return {
      email: raw.email,
      oauthToken: raw.access_token,
      imapHost: raw.imap_host,
      smtpHost: raw.smtp_host
    };
  }
  const token = process.env.YANDEX_OAUTH_TOKEN;
  const email = process.env.YANDEX_EMAIL;
  if (token && email) {
    return {
      email,
      oauthToken: token,
      imapHost: process.env.YANDEX_IMAP_HOST,
      smtpHost: process.env.YANDEX_SMTP_HOST
    };
  }
  throw new Error(
    'Yandex Mail credentials not found.\nCreate token.json next to the server:\n  { "access_token": "y0_AgAAA...", "email": "you@yandex.ru" }\nOr set YANDEX_OAUTH_TOKEN + YANDEX_EMAIL env vars.'
  );
}
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  loadCredentials
});
