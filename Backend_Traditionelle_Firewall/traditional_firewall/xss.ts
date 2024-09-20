import { fileLogger } from "../logger/logger";

const xssPattern = /(<script.*?>.*?<\/script.*?>)|(<.*?on\w+.*?=.*?>)|(\b(alert|prompt|confirm)\b)|(\b(src|href)\s*=\s*["']javascript:)|((document|window)\.\w+)|(\b(eval|setTimeout|setInterval|Function)\b)|(<iframe.*?>)|(<object.*?>)|(<embed.*?>)|(<style.*?>.*?<\/style.*?>)|(<img.*?src=.*?>)|(<svg.*?>)|(<link.*?>)|(\bon[a-z]+\s*=)|(\bexpression\s*\()/i;

export function detectXSS(req, res, next) {
  const checkForXSS = (value) => {
    if (typeof value === 'string' && xssPattern.test(value)) {
      return true;
    }
    return false;
  };

  let url = req.url
  let id = req.headers['id']

  // Check query parameters
  for (const param in req.query) {
    if (checkForXSS(req.query[param])) {
      fileLogger.log({
        level: 'info',
        message: "XSS Detected",
        additional: [id, url],
        are: "Request Denied"
      })
      return res.status(400).send('Bad Request');
    }
  }

  // Check body parameters
  for (const param in req.body) {
    if (checkForXSS(req.body[param])) {
      fileLogger.log({
        level: 'info',
        message: "XSS Detected",
        additional: [id, url],
        are: "Request Denied"
      })
      return res.status(400).send('Bad Request');
    }
  }

  // Check URL parameters
  for (const param in req.params) {
    if (checkForXSS(req.params[param])) {
      fileLogger.log({
        level: 'info',
        message: "XSS Detected",
        additional: [id, url],
        are: "Request Denied"
      })
      return res.status(400).send('Bad Request');
    }
  }

  // If no XSS is detected, proceed to the next middleware
  next();
}

