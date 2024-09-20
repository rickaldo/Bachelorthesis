import { fileLogger } from "../logger/logger";

const pathTraversalPattern = /(\.\.\/|\.\.\\|%2e%2e%2f|%2e%2e%5c|%2e%2e%2f|%2e%2e%5c|%2e%2e|\/\.\.\/|\\\.\.\\|\/\.\.\\|\\\.\.\/|%2e%2e\/|%2e%2e\\|\/%2e%2e|\\%2e%2e)/i;

export function detectPathTraversal(req, res, next) {
  const checkForPathTraversal = (value) => {
    if (typeof value === 'string' && pathTraversalPattern.test(value)) {
      return true;
    }
    return false;
  };

  let url = req.url
  let id = req.headers['id']

  // Check query parameters
  for (const param in req.query) {
    if (checkForPathTraversal(req.query[param])) {
      fileLogger.log({
        level: 'info',
        message: "Path Traversal Detected",
        additional: [id, url],
        are: "Request Denied"
      })
      return res.status(400).send('Bad Request');
    }
  }

  // Check body parameters
  for (const param in req.body) {
    if (checkForPathTraversal(req.body[param])) {
      fileLogger.log({
        level: 'info',
        message: "Path Traversal Detected",
        additional: [id, url],
        are: "Request Denied"
      })
      return res.status(400).send('Bad Request');
    }
  }

  // Check URL parameters
  for (const param in req.params) {
    if (checkForPathTraversal(req.params[param])) {
      fileLogger.log({
        level: 'info',
        message: "Path Traversal Detected",
        additional: [id, url],
        are: "Request Denied"
      })
      return res.status(400).send('Bad Request');
    }
  }

  // If no Path Traversal is detected, proceed to the next middleware
  next();
}

