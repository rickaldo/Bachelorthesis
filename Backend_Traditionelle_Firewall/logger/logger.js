'use strict';
Object.defineProperty(exports, "__esModule", { value: true });
exports.fileLogger = void 0;
var winston = require("winston");
exports.fileLogger = winston.createLogger({
    level: 'info',
    format: winston.format.combine(winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }), winston.format.errors({ stack: true }), winston.format.splat(), winston.format.json()),
    transports: [
        new winston.transports.Console(),
        new winston.transports.File({ filename: 'error.log', level: 'error' }),
        new winston.transports.File({ filename: 'log.log' }),
    ],
});
