import { fileLogger } from "../logger/logger";
const commandInjectionPattern = /(\b(exec|system|spawn|popen|eval|passthru|shell_exec|pcntl_exec|sh|bash|cmd|powershell|cat|ls|dir|rm|del|cp|mv|wget|curl|chmod|chown|nc|netcat|telnet|python|perl|php|ruby|java|node|gcc|make|nmap|traceroute|whois|nslookup|dig|tshark|tcpdump|strace|lsof|ping|scp|ssh|ftp|tftp|openssl)\b|\||&|;|>|<|`|\$\(.*?\)|\$\{.*?\}|\$|%0A|%0D|%27|%22|%26|%3B|%7C|\s*\|\s*|\s*&&\s*|\s*\|\|\s*|\s*;\s*|\s*>\s*|\s*<\s*|&\s*|>|<)/i;

export function detectCommandInjection(req, res, next) {
  const checkForCommandInjection = (value) => {
    if (typeof value === 'string' && commandInjectionPattern.test(value)) {
      return true;
    }
    return false;
  };

  let url = req.url
  let id = req.headers['id']

  // Check query parameters
  for (const param in req.query) {
    if (checkForCommandInjection(req.query[param])) {
      fileLogger.log({
        level: 'info',
        message: "Command Injection Detected",
        additional: [id, url],
        are: "Request Denied"
      })
      return res.status(400).send('Bad Request');
    }
  }

  // Check body parameters
  for (const param in req.body) {
    if (checkForCommandInjection(req.body[param])) {
      fileLogger.log({
        level: 'info',
        message: "Command Injection Detected",
        additional: [id, url],
        are: "Request Denied"
      })
      return res.status(400).send('Bad Request');
    }
  }

  // Check URL parameters
  for (const param in req.params) {
    if (checkForCommandInjection(req.params[param])) {
      fileLogger.log({
        level: 'info',
        message: "Command Injection Detected",
        additional: [id, url],
        are: "Request Denied"
      })
      return res.status(400).send('Bad Request');
    }
  }
  next();
}


