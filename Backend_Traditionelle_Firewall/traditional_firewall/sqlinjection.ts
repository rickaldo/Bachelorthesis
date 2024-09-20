import { fileLogger } from "../logger/logger";

const sqlInjectionPattern = /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|AND|OR|--|;|\/\*|\*\/|\*|EXEC|EXECUTE|xp_cmdshell|sp_executesql|DECLARE|CAST|CONVERT|CHAR|NCHAR|VARCHAR|NVARCHAR|ALTER|CREATE|GRANT|REVOKE|BACKUP|RESTORE|xp_|dbo\.|information_schema|sysobjects|syscolumns)\b|\b(--|\')|(\%27)|(\%3D)|(\%3B)|(\%2F)|(\%2A)|(\%00))+/i;

export function detectSQLInjection(req, res, next) {
  const checkForSQLInjection = (value) => {
    if (typeof value === 'string' && sqlInjectionPattern.test(value)) {
      return true;
    }
    return false;
  };

  let url = req.url
  let id = req.headers['id']

  // Check query parameters
  for (const param in req.query) {
    if (checkForSQLInjection(req.query[param])) {
      fileLogger.log({
        level: 'info',
        message: "SQL-Injection detected",
        additional: [id, url],
        are: "Request Denied"
      })
      return res.status(400).send('Bad Request');
    }
  }

  // Check body parameters
  for (const param in req.body) {
    if (checkForSQLInjection(req.body[param])) {
      fileLogger.log({
        level: 'info',
        message: "SQL-Injection detected",
        additional: [id, url],
        are: "Request Denied"
      })
      return res.status(400).send('Bad Request');
    }
  }

  // Check URL parameters
  for (const param in req.params) {
    if (checkForSQLInjection(req.params[param])) {
      fileLogger.log({
        level: 'info',
        message: "SQL-Injection detected",
        additional: [id, url],
        are: "Request Denied"
      })
      return res.status(400).send('Bad Request');
    }
  }

  // If no SQL Injection is detected, proceed to the next middleware
  next();
}

