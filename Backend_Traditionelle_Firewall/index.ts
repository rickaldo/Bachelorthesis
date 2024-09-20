import { fileLogger } from "./logger/logger";
import { checkForAttack } from "./traditional_firewall/index";
import { detectSQLInjection } from "./traditional_firewall/sqlinjection";
import { detectXSS } from "./traditional_firewall/xss";
import { detectPathTraversal } from "./traditional_firewall/pathtraversal";
import { detectCommandInjection } from "./traditional_firewall/commandInjection";
const express = require("express");
const proxy = require("express-http-proxy");

var app = express();

app.use(detectSQLInjection);
app.use(detectCommandInjection);
app.use(detectPathTraversal);
app.use(detectXSS);

app.all(
  "*",
  proxy("http://localhost:3000", {
    filter: function(req, res) {
      var id = req.header("id");
      var url = req.url;

      logValidRequest(id, url);
      return true;
    },
  }),
);

function logValidRequest(id, url) {
  fileLogger.log({
    level: "info",
    message: "Valid request",
    additional: [id, url],
    are: "passed along",
  });
}

app.listen(5050, () => {
  console.log("Listening to Port 5050");
});
