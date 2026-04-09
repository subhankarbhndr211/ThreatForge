'use strict';
const express = require('express');
const router = express.Router();
const { v4: uuidv4 } = require('uuid');
const crypto = require('crypto');
const punycode = require('punycode/');

// Store analysis history (in production, use a database)
const analysisHistory = new Map();
const autoDetections = new Map();
const incidentRecords = new Map();
const responseActions = new Map();
const blockedIndicators = new Map();
const autoState = {
  enabled: false,
  running: false,
  lastRunAt: null,
  lastError: null,
  mailboxChecks: 0,
  eventsProcessed: 0
};
const processedMailIds = new Set();

function normalizeLineEndings(text) {
  return String(text || '').replace(/\r\n/g, '\n').replace(/\r/g, '\n');
}

function decodeQuotedPrintable(text) {
  const source = String(text || '');
  const softBreakRemoved = source.replace(/=\n/g, '');
  return softBreakRemoved.replace(/=([A-Fa-f0-9]{2})/g, (_, hex) => {
    return String.fromCharCode(parseInt(hex, 16));
  });
}

function decodeMimeEncodedWords(text) {
  return String(text || '').replace(/=\?([^?]+)\?([bBqQ])\?([^?]+)\?=/g, (_, _charset, encoding, value) => {
    try {
      if (encoding.toUpperCase() === 'B') {
        return Buffer.from(value, 'base64').toString('utf-8');
      }
      const qpValue = value.replace(/_/g, ' ');
      return decodeQuotedPrintable(qpValue);
    } catch {
      return value;
    }
  });
}

function deobfuscateText(text) {
  let output = String(text || '');
  output = output.replace(/hxxps?:\/\//gi, m => (m.toLowerCase() === 'hxxps://' ? 'https://' : 'http://'));
  output = output.replace(/\[\.\]|\(\.\)|\{\.}/g, '.');
  output = output.replace(/\s(dot)\s/gi, '.');
  output = output.replace(/%3a%2f%2f/gi, '://');
  output = output.replace(/\[at\]/gi, '@');
  output = output.replace(/\[dot\]/gi, '.');
  output = output.replace(/&#46;/g, '.');
  output = output.replace(/&#64;/g, '@');
  output = output.replace(/\\u0040/g, '@');
  output = output.replace(/\\u002e/g, '.');
  output = output.replace(/<br\s*\/?>/gi, ' ');
  output = output.replace(/<[^>]+>/g, '');
  return output;
}

function safeDecodeURIComponent(value) {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

function normalizeDomain(domain) {
  const raw = String(domain || '').trim().toLowerCase().replace(/\.+$/, '');
  if (!raw) return '';
  try {
    return punycode.toUnicode(raw);
  } catch {
    return raw;
  }
}

async function checkDomainAge(domain) {
  try {
    const response = await fetch(`https://rdap.org/domain/${domain}`, {
      signal: AbortSignal.timeout(5000)
    });
    if (response.ok) {
      const data = await response.json();
      const dates = data.events?.filter(e => e.eventType === 'registration') || [];
      if (dates.length > 0) {
        const regDate = new Date(dates[0].eventDate);
        const daysOld = Math.floor((Date.now() - regDate.getTime()) / (1000 * 60 * 60 * 24));
        return { registered: regDate.toISOString().split('T')[0], daysOld, isNew: daysOld < 90 };
      }
    }
  } catch {}
  return { isNew: null };
}

function detectHomographAttack(domain) {
  const homoglyphs = {
    'a': ['а', 'ɑ', 'α'],  // Cyrillic а, Greek alpha
    'e': ['е', 'ε'],        // Cyrillic е, Greek epsilon
    'o': ['о', 'ο', '0'],   // Cyrillic о, Greek omicron, zero
    'c': ['с', 'ϲ'],        // Cyrillic с
    'p': ['р'],             // Cyrillic р
    'y': ['у'],             // Cyrillic у
    'x': ['х'],             // Cyrillic х
    'i': ['і', 'ι', '1'],  // Cyrillic і, Greek iota, one
    'l': ['1', 'І', 'ι'],  // one, Cyrillic І
    's': ['ѕ'],             // Cyrillic ѕ
    't': ['τ'],             // Greek tau
    'n': ['п'],             // Cyrillic п
    'm': ['м'],             // Cyrillic м
    'h': ['һ'],             // Cyrillic һ
    'j': ['ј'],             // Cyrillicј
    'k': ['κ'],             // Greek kappa
  };
  
  const lower = domain.toLowerCase();
  const parts = lower.split('.');
  const baseDomain = parts[0];
  
  for (const [legitChar, lookalikes] of Object.entries(homoglyphs)) {
    for (const lookalike of lookalikes) {
      if (baseDomain.includes(lookalike)) {
        const normalized = baseDomain.split('').map(c => {
          for (const [legit, alts] of Object.entries(homoglyphs)) {
            if (alts.includes(c)) return legit;
          }
          return c;
        }).join('');
        
        for (const [brand, config] of Object.entries(knownBrands)) {
          if (normalized.includes(config.legit)) {
            return { isHomograph: true, brand, normalized };
          }
        }
      }
    }
  }
  return { isHomograph: false };
}

function extractDomainFromUrl(url) {
  try {
    const parsed = new URL(url);
    return parsed.hostname;
  } catch {
    return null;
  }
}

// Free email providers (legitimate but suspicious when used for business impersonation)
const freeEmailProviders = new Set([
  'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'live.com',
  'aol.com', 'icloud.com', 'mail.com', 'protonmail.com', 'zoho.com',
  'yandex.com', 'gmx.com', 'fastmail.com', 'tutanota.com', 'hey.com',
  'proton.me', 'outlook.ie', 'msn.com', 'windowslive.com', 'me.com',
  'mac.com', 'googlemail.com', 'ymail.com', 'rocketmail.com'
]);

const impersonatedBrands = [
  'amazon', 'paypal', 'microsoft', 'apple', 'google', 'facebook', 'meta',
  'netflix', 'bank', 'chase', 'wells fargo', 'bank of america', 'citi',
  'usps', 'fedex', 'ups', 'dhl', 'dropbox', 'adobe', 'linkedin', 'twitter',
  'instagram', 'tiktok', 'spotify', 'ebay', 'shopify', 'coinbase', 'binance',
  'american express', 'amex', 'visa', 'mastercard', 'discover', 'capital one',
  'irs', 'ssa', 'social security', 'treasury', 'microsoft 365', 'office 365',
  'apple id', 'icloud', 'itunes', 'google drive', 'dropbox', 'slack', 'zoom',
  'teamviewer', 'anydesk', 'logmein', 'gotomeeting', 'webex'
];

function detectDisplayNameImpersonation(fromHeader) {
  const results = {
    detected: false,
    brand: null,
    displayName: null,
    realDomain: null,
    description: ''
  };
  
  const fromMatch = fromHeader?.match(/^"?([^"<]+)"?\s*<?([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+)>?/);
  if (!fromMatch) return results;
  
  const displayName = (fromMatch[1] || '').trim();
  const senderEmail = (fromMatch[2] || '').toLowerCase();
  const senderDomain = senderEmail.split('@')[1] || '';
  
  if (!displayName || displayName.length < 3) return results;
  
  const displayLower = displayName.toLowerCase();
  
  for (const brand of impersonatedBrands) {
    if (displayLower.includes(brand) || levenshteinDistance(displayLower, brand) <= 2) {
      const legitDomains = getLegitDomainsForBrand(brand);
      const isFreeEmail = freeEmailProviders.has(senderDomain);
      
      if (!legitDomains.includes(senderDomain) || isFreeEmail) {
        results.detected = true;
        results.brand = brand;
        results.displayName = displayName;
        results.realDomain = senderDomain;
        results.description = `"${displayName}" from ${senderEmail} - impersonates ${brand}`;
        return results;
      }
    }
  }
  
  return results;
}

function getLegitDomainsForBrand(brand) {
  const brandDomains = {
    'amazon': ['amazon.com', 'amazon.co.uk', 'amazon.de', 'amazon.fr', 'amazon.it', 'amazon.es', 'amazon.ca', 'amazon.co.jp', 'amazon.com.au', 'amazon.in', 'amazon.com.mx'],
    'paypal': ['paypal.com', 'paypal.me', 'paypalobjects.com'],
    'microsoft': ['microsoft.com', 'microsoftonline.com', 'office.com', 'office365.com', 'outlook.com', 'live.com', 'bing.com', 'xbox.com', 'azure.com', 'windows.com', 'microsoft365.com'],
    'apple': ['apple.com', 'appleid.apple.com', 'icloud.com', 'me.com', 'mac.com'],
    'google': ['google.com', 'gmail.com', 'googlemail.com', 'youtube.com', 'googleapis.com', 'googleusercontent.com'],
    'facebook': ['facebook.com', 'fb.com', 'meta.com', 'instagram.com', 'whatsapp.com', 'messenger.com'],
    'netflix': ['netflix.com', 'netflix.net', 'nflxvideo.net', 'nflximg.net'],
    'bank': ['bankofamerica.com', 'chase.com', 'wellsfargo.com', 'citibank.com', 'usbank.com', 'capitalone.com', 'pncbank.com'],
    'chase': ['chase.com'],
    'wells fargo': ['wellsfargo.com', 'wellsfargobusiness.com'],
    'bank of america': ['bankofamerica.com', 'bofa.com', 'ml.com'],
    'usps': ['usps.com'],
    'fedex': ['fedex.com', 'fedex.net', 'fedextrack.com'],
    'ups': ['ups.com', 'upsmail.com', 'ups-shipping.com'],
    'dhl': ['dhl.com', 'dhl.net', 'dhlecommerce.com'],
    'dropbox': ['dropbox.com', 'dropboxapi.com', 'getdropbox.com'],
    'adobe': ['adobe.com', 'adobe.net', 'behance.net', 'acrobat.com'],
    'linkedin': ['linkedin.com'],
    'twitter': ['twitter.com', 'x.com', 'twttr.com'],
    'instagram': ['instagram.com', 'i.instagram.com'],
    'tiktok': ['tiktok.com', 'tiktokcdn.com', 'bytedance.com'],
    'spotify': ['spotify.com', 'spotifycdn.com'],
    'ebay': ['ebay.com', 'ebay.co.uk', 'ebay.de', 'ebaymotors.com'],
    'coinbase': ['coinbase.com', 'coinbaseassets.com', 'cb.sv'],
    'binance': ['binance.com', 'binance.us', 'binance.me'],
    'american express': ['americanexpress.com', 'amex.com'],
    'amex': ['americanexpress.com', 'amex.com'],
    'visa': ['visa.com', 'visaeurope.com', 'visaitalia.com'],
    'mastercard': ['mastercard.com', 'mastercard.us', 'mastercardbusiness.com'],
    'discover': ['discover.com', 'discovercard.com'],
    'capital one': ['capitalone.com', 'capitalone360.com'],
    'microsoft 365': ['microsoft.com', 'microsoftonline.com', 'office.com', 'office365.com'],
    'office 365': ['microsoft.com', 'microsoftonline.com', 'office.com', 'office365.com'],
    'apple id': ['apple.com', 'appleid.apple.com'],
    'icloud': ['apple.com', 'icloud.com', 'appleid.apple.com'],
    'itunes': ['apple.com', 'itunes.com', 'appstore.com'],
    'google drive': ['google.com', 'drive.google.com'],
    'slack': ['slack.com', 'slackhq.com'],
    'zoom': ['zoom.us', 'zoomgov.com'],
    'teamviewer': ['teamviewer.com', 'teamviewer.eu'],
    'anydesk': ['anydesk.com', 'anydesk.io'],
  };
  
  return brandDomains[brand.toLowerCase()] || [];
}

function detectSuspiciousSenderDomain(senderDomain, fromHeader = '') {
  const results = {
    suspicious: false,
    reason: '',
    riskIncrease: 0
  };
  
  if (!senderDomain) return results;
  
  const domainLower = senderDomain.toLowerCase();
  
  if (freeEmailProviders.has(domainLower)) {
    results.suspicious = true;
    results.reason = `Free email provider: ${domainLower}`;
    results.riskIncrease = 5;
    return results;
  }
  
  const typoCheck = detectTyposquatting(senderDomain);
  if (typoCheck.isTyposquatting) {
    results.suspicious = true;
    results.reason = `Typosquatting domain (impersonates ${typoCheck.brand})`;
    results.riskIncrease = 50;
    return results;
  }
  
  const fromMatch = fromHeader?.match(/^"?([^"<]+)"?\s*<?[a-zA-Z0-9._%+-]+@/);
  const displayName = fromMatch?.[1]?.toLowerCase() || '';
  
  for (const brand of impersonatedBrands) {
    if (displayName.includes(brand) || levenshteinDistance(displayName, brand) <= 2) {
      const legitDomains = getLegitDomainsForBrand(brand);
      if (!legitDomains.some(d => domainLower === d || domainLower.endsWith('.' + d))) {
        results.suspicious = true;
        results.reason = `Display name claims "${brand}" but sending from unrelated domain: ${domainLower}`;
        results.riskIncrease = 45;
        return results;
      }
    }
  }
  
  return results;
}

function detectQRCodeInContent(body) {
  const results = [];
  const decodedBody = deobfuscateText(decodeQuotedPrintable(String(body || '')));
  
  const qrShorteners = [
    'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'buff.ly',
    'adf.ly', 'bit.do', 'is.gd', 'cli.gk', 'cutt.us', 'short.to',
    'qr.ae', 'qr.gd', 'shor.by'
  ];
  
  const urlPattern = /(https?:\/\/[^\s<>"']+)/gi;
  const urls = decodedBody.match(urlPattern) || [];
  
  for (const url of urls) {
    const urlLower = url.toLowerCase();
    for (const shortener of qrShorteners) {
      if (urlLower.includes(shortener)) {
        results.push({
          type: 'url-shortener',
          url: url,
          shortener: shortener,
          note: 'URL shorteners often used in QR code phishing'
        });
      }
    }
  }
  
  const qrKeywords = [
    /scan\s+(?:this\s+)?qr/i,
    /qr\s*(?:code\s+)?scan/i,
    /use\s+qr/i,
    /qr\s+to\s+(?:login|verify|access)/i,
    /phone\s+scan/i
  ];
  
  for (const pattern of qrKeywords) {
    if (pattern.test(decodedBody)) {
      results.push({
        type: 'qr-reference',
        note: 'QR code reference detected - may contain hidden phishing URL'
      });
      break;
    }
  }
  
  return results;
}

function detectEmbeddedForms(body) {
  const results = {
    detected: false,
    forms: []
  };
  
  const decodedBody = String(body || '');
  
  const sensitiveFieldPatterns = [
    { pattern: /<input[^>]*type=["']?(?:password|passwd|pwd)["']?/gi, field: 'password' },
    { pattern: /<input[^>]*name=["']?(?:password|passwd|pwd|secret)["']?/gi, field: 'password' },
    { pattern: /<input[^>]*type=["']?(?:email|mail)["']?/gi, field: 'email' },
    { pattern: /<input[^>]*name=["']?(?:email|mail|username|user|login)["']?/gi, field: 'email/username' },
    { pattern: /<input[^>]*type=["']?(?:text|tel|number)["']?/gi, field: 'text input' },
    { pattern: /<input[^>]*name=["']?(?:ssn|social|credit|card|cvv|security.?number)["']?/gi, field: 'financial/SSN' },
    { pattern: /<input[^>]*name=["']?(?:otp|code|verification|mfa|two.?factor)["']?/gi, field: 'OTP/MFA code' }
  ];
  
  const formActionPatterns = [
    { pattern: /action=["']([^"']+)["']/gi, type: 'action' },
    { pattern: /form[^>]*action=["']([^"']+)["']/gi, type: 'form-action' }
  ];
  
  const suspiciousActions = [
    'login', 'signin', 'verify', 'confirm', 'account', 'update', 
    'secure', 'auth', 'password', 'credential', 'access', 'submit'
  ];
  
  for (const { pattern, field } of sensitiveFieldPatterns) {
    const matches = decodedBody.match(pattern);
    if (matches && matches.length > 0) {
      const formDetails = {
        field: field,
        count: matches.length,
        type: 'sensitive-input'
      };
      
      for (const { pattern: actionPattern, type } of formActionPatterns) {
        const actionMatches = decodedBody.match(actionPattern);
        if (actionMatches) {
          for (const action of actionMatches) {
            const actionUrl = action.match(/["']([^"']+)["']/)?.[1] || '';
            if (actionUrl) {
              const actionLower = actionUrl.toLowerCase();
              for (const keyword of suspiciousActions) {
                if (actionLower.includes(keyword)) {
                  formDetails.suspiciousAction = actionUrl;
                  formDetails.risk = 'HIGH';
                  break;
                }
              }
              if (formDetails.suspiciousAction) break;
            }
          }
        }
      }
      
      results.detected = true;
      results.forms.push(formDetails);
    }
  }
  
  return results;
}

function detectCalendarInvite(body, headers) {
  const results = {
    detected: false,
    type: null,
    details: {}
  };
  
  const content = headers + '\n' + String(body || '');
  
  const calendarIndicators = [
    { pattern: /method=REQUEST/i, type: 'meeting-request' },
    { pattern: /content-type:\s*text\/calendar/i, type: 'icalendar' },
    { pattern: /begin:\s*VCALENDAR/i, type: 'vcalendar' },
    { pattern: /BEGIN:\s*VEVENT/i, type: 'vevent' },
    { pattern: /ATTENDEE.*mailto:/i, type: 'attendee' },
    { pattern: /ORGANIZER.*mailto:/i, type: 'organizer' }
  ];
  
  for (const { pattern, type } of calendarIndicators) {
    if (pattern.test(content)) {
      results.detected = true;
      results.type = type;
      
      const summaryMatch = content.match(/SUMMARY:([^\r\n]+)/i);
      const locationMatch = content.match(/LOCATION:([^\r\n]+)/i);
      const startMatch = content.match(/DTSTART:([^\r\n]+)/i);
      const endMatch = content.match(/DTEND:([^\r\n]+)/i);
      
      if (summaryMatch) results.details.summary = summaryMatch[1].trim();
      if (locationMatch) results.details.location = locationMatch[1].trim();
      if (startMatch) results.details.start = startMatch[1].trim();
      if (endMatch) results.details.end = endMatch[1].trim();
      
      break;
    }
  }
  
  const suspiciousMeetingKeywords = [
    'urgent meeting', 'mandatory', 'immediate action', 'security incident',
    'account suspended', 'verify identity', 'password expired', 'payment failed',
    'invoice attached', 'wire transfer', 'bank details'
  ];
  
  if (results.detected && results.details.summary) {
    const summaryLower = results.details.summary.toLowerCase();
    for (const keyword of suspiciousMeetingKeywords) {
      if (summaryLower.includes(keyword)) {
        results.details.suspicious = true;
        results.details.suspiciousReason = `Meeting title contains suspicious keyword: "${keyword}"`;
        break;
      }
    }
  }
  
  return results;
}

function detectReplyToMismatch(fromHeader, replyTo, returnPath) {
  const results = {
    mismatch: false,
    from: '',
    replyTo: '',
    returnPath: '',
    description: '',
    highRisk: false
  };
  
  const fromMatch = fromHeader?.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+/);
  const replyToMatch = replyTo?.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+/);
  const returnPathMatch = returnPath?.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+/);
  
  results.from = fromMatch?.[0]?.toLowerCase() || '';
  results.replyTo = replyToMatch?.[0]?.toLowerCase() || '';
  results.returnPath = returnPathMatch?.[0]?.toLowerCase() || '';
  
  const fromDomain = results.from.split('@')[1] || '';
  const replyToDomain = results.replyTo.split('@')[1] || '';
  const returnPathDomain = results.returnPath.split('@')[1] || '';
  
  if (results.replyTo && results.from && replyToDomain !== fromDomain) {
    results.mismatch = true;
    results.description = `Reply-To (${results.replyTo}) differs from From (${results.from})`;
    
    const typoCheck = detectTyposquatting(replyToDomain);
    if (typoCheck.isTyposquatting) {
      results.description += ` - Reply-To domain impersonates ${typoCheck.brand}!`;
      results.highRisk = true;
    }
  }
  
  if (results.returnPath && results.from && returnPathDomain !== fromDomain) {
    if (results.description) results.description += '; ';
    results.mismatch = true;
    results.description += `Return-Path (${results.returnPath}) differs from From (${results.from})`;
    
    const typoCheck = detectTyposquatting(returnPathDomain);
    if (typoCheck.isTyposquatting) {
      results.description += ` - Return-Path domain impersonates ${typoCheck.brand}!`;
      results.highRisk = true;
    }
  }
  
  return results;
}

// Detect typosquatting and brand impersonation
const knownBrands = {
  'amazon': {
    legit: 'amazon',
    typos: ['amaz0n', 'amaozn', 'amazom', 'amazn', 'aamazon', 'anazon', 'an1azon', 'amazonn', 'amazom', 'amaz0n', 'amazn', 'amazonn', 'amaz0n', 'amazo', 'amazn', 'amaz0n', 'amazo', 'amazn', 'amazonn']
  },
  'paypal': {
    legit: 'paypal',
    typos: ['paypa1', 'paypai', 'paypaI', 'payp4l', 'paypai', 'paypa1', 'pyapal', 'paypai', 'paypa1', 'paypaI', 'paypal', 'paypai', 'payp4l', 'pyapal']
  },
  'microsoft': {
    legit: 'microsoft',
    typos: ['micros0ft', 'mircosoft', 'microsft', 'microsfot', 'rnicrosoft', 'mlcrosoft', 'm1crosoft', 'micros0ft', 'm1crosoft', 'mircosoft', 'microsft', 'microsfot', 'rnicrosoft', 'mlcrosoft', 'm1crosoft', 'm1crosoft', 'mlcrosoft']
  },
  'apple': {
    legit: 'apple',
    typos: ['app1e', 'appie', 'appl3', 'aapple', 'appple', 'aple', 'appl3', 'app1e', 'appie', 'appl3', 'apple', 'app1e', 'appie', 'appple', 'aple']
  },
  'google': {
    legit: 'google',
    typos: ['g00gle', 'googIe', 'goog1e', 'go0gle', 'goolge', 'gogle', 'g00g1e', 'g00gie', 'googIe', 'goog1e', 'g00gle', 'goolge', 'gogle', 'g00g1e']
  },
  'facebook': {
    legit: 'facebook',
    typos: ['faceb00k', 'facebok', 'facbook', 'faccebook', 'fac3book', 'fcebook', 'faceb00k', 'facebok', 'facbook', 'faccebook', 'fac3book', 'fcebook']
  },
  'netflix': {
    legit: 'netflix',
    typos: ['netf1ix', 'netfiix', 'netf1ix', 'netfiix', 'nettflix', 'neftlix', 'netf1ix', 'netflixx', 'netf1ix', 'nettflix', 'neftlix']
  },
  'linkedin': {
    legit: 'linkedin',
    typos: ['Iinkedin', 'linkedln', 'linkediin', 'Ilndedin', 'linkdin', 'linkedln', 'linkediin', 'linkdin', 'Iinkedin', 'linkedln']
  },
  'twitter': {
    legit: 'twitter',
    typos: ['twltter', 'twlter', 'twtter', 'twlter', 'twltter', 'twltter', 'twlter', 'twtter']
  },
  'instagram': {
    legit: 'instagram',
    typos: ['1nstagram', 'instagran', 'instagrem', 'instagarm', '1nstagram', 'instagran', 'instagrem', 'instagarm', '1nstagram', 'instagran']
  },
  'whatsapp': {
    legit: 'whatsapp',
    typos: ['whatspp', 'whatsaap', 'whatsap', 'whatspp', 'whatsaap', 'whatspp', 'whatsap', 'whatsaap']
  },
  'dropbox': {
    legit: 'dropbox',
    typos: ['dr0pbox', 'dropb0x', 'drobox', 'dropb0x', 'dr0pbox', 'dropboxx', 'dr0pbox', 'dropb0x', 'drobox']
  },
  'adobe': {
    legit: 'adobe',
    typos: ['ad0be', 'ad0b3', 'adobe', 'ad0be', 'ad0b3', 'ad0be']
  },
  'icloud': {
    legit: 'icloud',
    typos: ['1cloud', 'icl0ud', 'ic10ud', 'icloud', '1cloud', 'icl0ud', 'ic10ud', 'icloud', '1cloud']
  },
  'bankofamerica': {
    legit: 'bankofamerica',
    typos: ['bankofamer1ca', 'bankofamerca', 'bankofarnerica', 'bankofamerca', 'bankofamer1ca', 'bankofamerca', 'bankofarnerica']
  },
  'wellsfargo': {
    legit: 'wellsfargo',
    typos: ['wellsfarg0', 'welsfargo', 'wellsfargoo', 'we11sfargo', 'wellsfarg0', 'welsfargo', 'wellsfargoo', 'we11sfargo']
  },
  'chase': {
    legit: 'chase',
    typos: ['chas3', 'chasse', 'ch4se', 'chase', 'chas3', 'chasse', 'ch4se', 'chas3']
  },
  'usps': {
    legit: 'usps',
    typos: ['uspss', 'usp5', 'usps', 'uspss', 'usp5', 'uspss']
  },
  'fedex': {
    legit: 'fedex',
    typos: ['fed3x', 'fedexx', 'f3dex', 'fedexx', 'fed3x', 'fedexx', 'f3dex']
  },
  'microsoftonline': {
    legit: 'microsoftonline',
    typos: ['microsftonline', 'm1crosoftonline', 'mircosoftonline', 'microsft-onllne', 'microsftonline', 'm1crosoftonline', 'mircosoftonline']
  },
  'appleid': {
    legit: 'appleid',
    typos: ['app1eid', 'appl3id', 'apple1d', 'applei', 'app1eid', 'appl3id', 'apple1d', 'applei', 'app1eid']
  },
  'ebay': {
    legit: 'ebay',
    typos: ['eb4y', '3bay', 'ebayy', 'eb4y', '3bay', 'ebayy', 'eb4y']
  },
  'yahoo': {
    legit: 'yahoo',
    typos: ['yah00', 'yahooo', 'yhoo', 'yaho0', 'yah00', 'yahooo', 'yhoo', 'yaho0', 'yah00']
  },
  'americanexpress': {
    legit: 'americanexpress',
    typos: ['americanexpr3ss', 'amer1canexpress', 'american3xpress', 'ameriicanexpress', 'americanexpressx', 'ameriicanexpress']
  }
};

function detectTyposquatting(domain) {
  const normalizedDomain = normalizeDomain(domain).toLowerCase().replace(/^www\./, '');
  const baseDomain = normalizedDomain.split('.')[0];
  
  // Check for homograph attack (internationalized domain lookalikes)
  const homograph = detectHomographAttack(baseDomain);
  if (homograph.isHomograph) {
    return { isTyposquatting: true, brand: homograph.brand, matchedTypo: baseDomain, type: 'homograph', normalized: homograph.normalized };
  }
  
  for (const [brand, config] of Object.entries(knownBrands)) {
    // Skip if this is the legitimate domain
    if (baseDomain === config.legit || baseDomain === config.legit + 's') {
      continue;
    }
    
    // Check if domain contains any known typo
    for (const typo of config.typos) {
      // Exact match or typo contains baseDomain (subdomain typosquatting)
      if (baseDomain === typo || (baseDomain.includes(typo) && typo.length >= 5)) {
        return { isTyposquatting: true, brand, matchedTypo: typo, type: 'typo-match' };
      }
    }
    
    // Levenshtein distance check for close matches (1-2 character difference)
    if (baseDomain.length >= 4 && baseDomain.length <= config.legit.length + 3) {
      const distance = levenshteinDistance(baseDomain, config.legit);
      // If very close to legitimate brand (distance 1-2) and not the legitimate brand
      if (distance >= 1 && distance <= 2) {
        return { isTyposquatting: true, brand, matchedTypo: baseDomain, distance, type: 'levenshtein' };
      }
    }
  }
  
  // Check for suspicious patterns in the full domain (not just base)
  const suspiciousPatterns = [
    { pattern: /login[\d]*\.[a-z]{2,}$/i, name: 'login-page' },
    { pattern: /secure[\d]*\.[a-z]{2,}$/i, name: 'secure-page' },
    { pattern: /account[\d]*\.[a-z]{2,}$/i, name: 'account-page' },
    { pattern: /verify[\d]*\.[a-z]{2,}$/i, name: 'verify-page' },
    { pattern: /update[\d]*\.[a-z]{2,}$/i, name: 'update-page' },
    { pattern: /confirm[\d]*\.[a-z]{2,}$/i, name: 'confirm-page' },
    { pattern: /support[\d]*\.[a-z]{2,}$/i, name: 'support-page' },
    { pattern: /recovery[\d]*\.[a-z]{2,}$/i, name: 'recovery-page' },
  ];
  
  for (const { pattern, name } of suspiciousPatterns) {
    if (pattern.test(normalizedDomain)) {
      return { isTyposquatting: true, brand: 'suspicious-pattern', matchedTypo: name, type: 'suspicious-pattern' };
    }
  }
  
  // Check for Chinese TLDs with suspicious keywords
  if (/[\u4e00-\u9fa5]/.test(normalizedDomain) && /^(amazon|paypal|microsoft|apple|google|facebook|netflix|bank|login|secure|account)/i.test(baseDomain)) {
    return { isTyposquatting: true, brand: 'asian-impersonation', matchedTypo: 'chinese-tld', type: 'international-typosquat' };
  }
  
  return { isTyposquatting: false };
}

function levenshteinDistance(str1, str2) {
  const m = str1.length;
  const n = str2.length;
  const dp = Array(m + 1).fill(null).map(() => Array(n + 1).fill(0));
  
  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;
  
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      if (str1[i - 1] === str2[j - 1]) {
        dp[i][j] = dp[i - 1][j - 1];
      } else {
        dp[i][j] = 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]);
      }
    }
  }
  return dp[m][n];
}

function extractRedirectTargets(url) {
  const extracted = [];
  try {
    const parsed = new URL(url);
    const redirectParams = [
      'url', 'u', 'target', 'redirect', 'redirect_url', 'redirect_uri',
      'continue', 'next', 'dest', 'destination', 'to', 'link', 'check',
      'redir', 'r', 'goto', 'follow', 'ref', 'reference', 'exit', 'external'
    ];
    for (const key of redirectParams) {
      const val = parsed.searchParams.get(key);
      if (!val) continue;
      const decoded = safeDecodeURIComponent(safeDecodeURIComponent(val));
      const normalized = deobfuscateText(decoded.trim());
      if (/^https?:\/\//i.test(normalized)) {
        extracted.push(normalized);
      }
    }
    // Also try to find URLs in the raw URL text (for double-encoded SafeLinks)
    const rawUrlMatch = url.match(/https?%3A%2F%2F[^\s&]+/gi);
    if (rawUrlMatch) {
      for (const encoded of rawUrlMatch) {
        try {
          const decoded = decodeURIComponent(decodeURIComponent(encoded));
          if (/^https?:\/\//i.test(decoded) && !extracted.includes(decoded)) {
            extracted.push(decoded);
          }
        } catch {}
      }
    }
  } catch {
    // ignore malformed URL
  }
  return extracted;
}

function applyFallbackHeuristics(results, ioc, type) {
  const highRiskTlds = ['cn', 'ru', 'xyz', 'top', 'club', 'online', 'site', 'pw', 'tk', 'ml', 'ga', 'cf', 'gq', 'buzz', 'link', 'work', 'date', 'faith', 'racing', 'win', 'review', 'download', 'trade', 'cc', 'su', 'ru', 'ua', 'by', 'kz'];
  const suspiciousTlds = ['xyz', 'top', 'club', 'online', 'site', 'pw', 'tk', 'ml', 'ga', 'cf', 'gq', 'buzz', 'link', 'work', 'date', 'faith', 'racing', 'win', 'review', 'download', 'trade', 'cc', 'su', 'click', 'loan', 'party', 'racing', 'review', 'science', 'accountant'];
  
  let targetDomain = ioc;
  if (type === 'url') {
    try {
      const parsed = new URL(ioc);
      targetDomain = normalizeDomain(parsed.hostname);
    } catch {
      targetDomain = ioc;
    }
  }
  
  if (!targetDomain) return;
  
  const domainLower = targetDomain.toLowerCase();
  const domainParts = domainLower.split('.');
  const tld = domainParts[domainParts.length - 1];
  const baseDomain = domainParts[0];
  
  // Check typosquatting
  const typoResult = detectTyposquatting(targetDomain);
  if (typoResult.isTyposquatting) {
    results.sources.typosquatting = {
      detected: true,
      brand: typoResult.brand,
      matchedTypo: typoResult.matchedTypo,
      fallback: true
    };
    results.score += 60;
    results.tags.push('typosquatting-detected');
    results.verdict = 'suspicious';
  }
  
  // Check high-risk TLDs
  if (highRiskTlds.includes(tld)) {
    results.tags.push('high-risk-tld');
    results.score += 15;
    if (!results.sources.typosquatting) {
      results.verdict = 'suspicious';
    }
  }
  
  // Check for suspicious TLD + brand keyword combination
  if (suspiciousTlds.includes(tld)) {
    const brandKeywords = ['amazon', 'paypal', 'microsoft', 'apple', 'google', 'facebook', 'netflix', 'bank', 'login', 'secure', 'account', 'verify', 'update'];
    for (const brand of brandKeywords) {
      if (domainLower.includes(brand)) {
        results.tags.push('suspicious-tld-brand');
        results.score += 25;
        if (!results.sources.typosquatting) {
          results.verdict = 'suspicious';
        }
        break;
      }
    }
  }
  
  // Check for homograph attacks
  const homograph = detectHomographAttack(baseDomain);
  if (homograph.isHomograph) {
    results.sources.homograph = {
      detected: true,
      brand: homograph.brand,
      normalized: homograph.normalized,
      fallback: true
    };
    results.score += 50;
    results.tags.push('homograph-attack');
    results.verdict = 'suspicious';
  }
  
  // Check for new domain patterns (numeric prefixes like 40outlook, 1amazon)
  if (/^\d+[a-z]/.test(baseDomain) || /^[a-z]+\d{2,}$/.test(baseDomain)) {
    const commonBrands = ['amazon', 'paypal', 'microsoft', 'apple', 'google', 'outlook', 'facebook', 'netflix'];
    for (const brand of commonBrands) {
      if (baseDomain.includes(brand) || baseDomain.includes(brand.replace(/[aeiou]/g, ''))) {
        results.tags.push('numeric-prefix-suspicious');
        results.score += 20;
        break;
      }
    }
  }
  
  // For IPs, check for suspicious patterns
  if (type === 'ip') {
    const parts = ioc.split('.');
    if (parts.length === 4) {
      // Check for private/invalid IPs
      if (parts[0] === '10' || parts[0] === '172' || parts[0] === '192') {
        results.tags.push('private-ip');
      }
      // Check for suspicious port patterns
      const ipPattern = ioc.match(/\d+\.\d+\.\d+\.\d+/);
      if (ipPattern) {
        // Suspicious: high ports, known malicious ports
        const ports = [4444, 5555, 6666, 7777, 8080, 8443, 8888, 9999];
        // Just flag as suspicious IP for now
        results.tags.push('external-ip');
      }
    }
  }
  
  // Final verdict adjustment based on score
  if (results.score >= 70 || results.tags.includes('typosquatting-detected') || results.tags.includes('homograph-attack')) {
    results.verdict = 'malicious';
  } else if (results.score >= 30) {
    results.verdict = 'suspicious';
  } else if (results.score > 0) {
    results.verdict = 'unknown';
  } else {
    results.verdict = 'clean';
  }
  
  console.log(`[Phishing] Fallback heuristics for ${type} ${ioc.substring(0, 30)}: verdict=${results.verdict}, score=${results.score}, tags=${results.tags.join(',')}`);
}

function mapToMitreTechniques(result, authIssues, enrichedIocs) {
  const techniques = [];
  if ((result?.stats?.urlsFound || 0) > 0) {
    techniques.push({ id: 'T1566.002', name: 'Phishing: Spearphishing Link' });
  }
  if ((result?.attachments?.length || 0) > 0 || (result?.stats?.hashesFound || 0) > 0) {
    techniques.push({ id: 'T1566.001', name: 'Phishing: Spearphishing Attachment' });
  }
  if (authIssues.some(i => /reply-to mismatch/i.test(i)) || result?.emailAnalysis?.replyToMismatch?.mismatch) {
    techniques.push({ id: 'T1036.005', name: 'Match Legitimate Name/Location' });
  }
  if (enrichedIocs.some(i => i.verdict === 'malicious')) {
    techniques.push({ id: 'T1204.001', name: 'User Execution: Malicious Link' });
  }
  if (enrichedIocs.some(i => i.tags?.includes('typosquatting-detected'))) {
    techniques.push({ id: 'T1486', name: 'Data Encrypted for Impact (Phishing Page)' });
  }
  if (enrichedIocs.some(i => i.tags?.includes('new-domain'))) {
    techniques.push({ id: 'T1583.001', name: 'Acquire Infrastructure: Domains' });
  }
  if (authIssues.some(i => /spf fail/i.test(i))) {
    techniques.push({ id: 'T1660', name: 'Suppress Application Function' });
  }
  if (result?.emailAnalysis?.displayNameImpersonation?.detected) {
    techniques.push({ id: 'T1036.007', name: 'Match Legitimate Name/Location' });
    techniques.push({ id: 'T1652', name: 'Exploit Public-Facing Application (Email Spoofing)' });
  }
  if (result?.emailAnalysis?.qrCodeDetection?.length > 0) {
    techniques.push({ id: 'T1204.002', name: 'User Execution: Malicious File' });
    techniques.push({ id: 'T1566.003', name: 'Phishing: Spearphishing via Service' });
  }
  if (result?.emailAnalysis?.senderDomainAnalysis?.suspicious) {
    techniques.push({ id: 'T1586.002', name: 'Compromise Accounts: Email Accounts' });
  }
  if (result?.emailAnalysis?.embeddedForms?.detected) {
    techniques.push({ id: 'T1056.001', name: 'Input Capture: Keylogging' });
    techniques.push({ id: 'T1566.002', name: 'Phishing: Spearphishing Link (Credential Harvesting)' });
  }
  if (result?.emailAnalysis?.calendarInvite?.detected) {
    techniques.push({ id: 'T1195', name: 'Supply Chain Compromise' });
    techniques.push({ id: 'T1193', name: 'Spearphishing Attachment (Calendar Invite)' });
  }
  return techniques;
}

function buildDeterministicTriage(result) {
  const risk = result?.stats?.riskScore || 0;
  const malicious = result?.malicious || 0;
  const suspicious = result?.suspicious || 0;
  const authIssues = result?.authIssues || [];
  const typosquattingIocs = (result?.iocs || []).filter(i => i.tags?.includes('typosquatting-detected'));
  const phishingKeywords = result?.phishingKeywords || [];
  const severity = risk >= 70 ? 'critical' : risk >= 50 ? 'high' : risk >= 25 ? 'medium' : 'low';
  const classification = malicious > 0 || risk >= 70 || typosquattingIocs.length > 0 ? 'phishing' : suspicious > 0 ? 'suspicious' : 'likely-benign';
  const confidence = Math.max(40, Math.min(95, Math.round((risk * 0.7) + (malicious * 8) + (authIssues.length * 5) + (typosquattingIocs.length * 15) + (phishingKeywords.length * 10))));
  const mitre = mapToMitreTechniques(result, authIssues, result?.iocs || []);

  const topFindings = [
    ...authIssues.map(issue => `Email authentication issue: ${issue}`),
    ...(phishingKeywords.length > 0 ? [`⚠️ Phishing language detected: "${phishingKeywords[0].substring(0, 30)}..."`] : []),
    ...(typosquattingIocs.length > 0 ? [`⚠️ Typosquatting detected: ${typosquattingIocs.map(i => i.sources?.typosquatting?.brand || 'Unknown').join(', ')} impersonation`] : []),
    ...(malicious > 0 ? [`${malicious} IOC(s) marked malicious by intel sources`] : []),
    ...(suspicious > 0 ? [`${suspicious} IOC(s) marked suspicious`] : []),
    ...((result?.stats?.urlsFound || 0) > 0 ? [`Contains ${result.stats.urlsFound} URL(s)`] : []),
    ...(result?.emailAnalysis?.displayNameImpersonation?.detected ? [`🎭 Display name impersonation: ${result.emailAnalysis.displayNameImpersonation.description}`] : []),
    ...(result?.emailAnalysis?.replyToMismatch?.mismatch ? [`📧 Reply-To mismatch detected: ${result.emailAnalysis.replyToMismatch.description}`] : []),
    ...(result?.emailAnalysis?.qrCodeDetection?.length > 0 ? [`📱 QR code/URL shortener detected in email body`] : []),
    ...(result?.emailAnalysis?.senderDomainAnalysis?.suspicious ? [`🔎 Suspicious sender domain: ${result.emailAnalysis.senderDomainAnalysis.reason}`] : []),
    ...(result?.emailAnalysis?.embeddedForms?.detected ? [`🔐 Embedded form with credential fields detected`] : []),
    ...(result?.emailAnalysis?.calendarInvite?.detected ? [`📅 Calendar invite detected` + (result.emailAnalysis.calendarInvite.details?.suspicious ? ' - SUSPICIOUS' : '')] : [])
  ].slice(0, 10);

  // Generate targeted recommended actions based on findings
  const recommendedActions = [];
  
  // Always recommend quarantine for any suspicious email
  recommendedActions.push('Quarantine message and block sender domain in secure email gateway');
  
  // Brand impersonation specific
  if (typosquattingIocs.length > 0) {
    const brands = typosquattingIocs.map(i => i.sources?.typosquatting?.brand).filter(Boolean);
    recommendedActions.push(`Alert end users who may have received phishing emails impersonating ${[...new Set(brands)].join('/')} (last 24 hours)`);
  }
  
  // Display name impersonation
  if (result?.emailAnalysis?.displayNameImpersonation?.detected) {
    recommendedActions.push('Warn employees about fake display names in sender addresses');
    recommendedActions.push('Implement DMARC policy to prevent domain spoofing');
  }
  
  // Reply-To mismatch
  if (result?.emailAnalysis?.replyToMismatch?.mismatch) {
    recommendedActions.push('Configure email gateway to flag Reply-To mismatches');
    recommendedActions.push('Educate users to verify Reply-To address before responding');
  }
  
  // QR code / URL shortener
  if (result?.emailAnalysis?.qrCodeDetection?.length > 0) {
    recommendedActions.push('Block or rewrite URL shortener links in email gateway');
    recommendedActions.push('Warn users about scanning QR codes from unexpected emails');
  }
  
  // Suspicious sender domain
  if (result?.emailAnalysis?.senderDomainAnalysis?.suspicious) {
    recommendedActions.push(`Block sender domain in email security gateway`);
  }
  
  // Embedded forms
  if (result?.emailAnalysis?.embeddedForms?.detected) {
    recommendedActions.push('Block emails with embedded forms that request credentials');
    recommendedActions.push('Implement SPF/DKIM/DMARC to prevent email spoofing');
  }
  
  // Calendar invites
  if (result?.emailAnalysis?.calendarInvite?.detected) {
    if (result.emailAnalysis.calendarInvite.details?.suspicious) {
      recommendedActions.push('Alert user about suspicious calendar invite - verify meeting via separate channel');
    }
    recommendedActions.push('Review calendar invite sender and meeting purpose before joining');
  }
  
  // Malicious IOCs
  if (malicious > 0) {
    recommendedActions.push('Block all malicious IOCs in DNS sinkhole, proxy, and firewall');
    recommendedActions.push('Search endpoint telemetry for users who clicked links or downloaded attachments');
  }
  
  // URL shorteners
  const hasShortenedUrls = result?.stats?.urlsFound > 0;
  if (hasShortenedUrls) {
    recommendedActions.push('Decode shortened URLs to identify additional infrastructure');
  }
  
  // Authentication failures
  if (authIssues.some(a => /fail|impostor/i.test(a))) {
    recommendedActions.push('Review email authentication logs (SPF/DKIM/DMARC) for sender domain');
  }
  
  // Generic recommendations
  recommendedActions.push('Reset potentially exposed credentials and enforce MFA challenge');
  recommendedActions.push('Submit confirmed artifacts to MISP and threat intelligence platforms');
  recommendedActions.push('Hunt for IOC matches in SIEM and EDR telemetry (last 30 days)');

  return {
    mode: 'deterministic',
    classification,
    severity,
    confidence,
    topFindings,
    recommendedActions: [...new Set(recommendedActions)].slice(0, 10),
    mitreMapping: mitre
  };
}

async function generateAiTriage(result) {
  const fallback = buildDeterministicTriage(result);
  const apiKey = process.env.OPENAI_API_KEY && !process.env.OPENAI_API_KEY.startsWith('your-')
    ? process.env.OPENAI_API_KEY.trim()
    : null;
  if (!apiKey) return fallback;

  try {
    const prompt = {
      emailStats: result.stats,
      authIssues: result.authIssues,
      iocs: (result.iocs || []).slice(0, 20).map(i => ({
        value: i.value, type: i.type, verdict: i.verdict, score: i.score, tags: i.tags
      })),
      summary: result.summary,
      emailAnalysis: {
        displayNameImpersonation: result.emailAnalysis?.displayNameImpersonation || null,
        replyToMismatch: result.emailAnalysis?.replyToMismatch || null,
        qrCodeDetection: result.emailAnalysis?.qrCodeDetection || [],
        senderDomainAnalysis: result.emailAnalysis?.senderDomainAnalysis || null,
        embeddedForms: result.emailAnalysis?.embeddedForms || null,
        calendarInvite: result.emailAnalysis?.calendarInvite || null
      }
    };

    const response = await fetch('https://api.openai.com/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${apiKey}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        model: process.env.OPENAI_MODEL || 'gpt-4o-mini',
        temperature: 0.2,
        response_format: { type: 'json_object' },
        messages: [
          {
            role: 'system',
            content: 'You are a SOC phishing triage agent. Return compact JSON with keys: classification, severity, confidence, topFindings (array), recommendedActions (array), mitreMapping (array of {id,name}).'
          },
          { role: 'user', content: JSON.stringify(prompt) }
        ]
      }),
      signal: AbortSignal.timeout(8000)
    });

    if (!response.ok) return fallback;
    const json = await response.json();
    const content = json?.choices?.[0]?.message?.content;
    if (!content) return fallback;
    const parsed = JSON.parse(content);
    return {
      mode: 'ai',
      classification: parsed.classification || fallback.classification,
      severity: parsed.severity || fallback.severity,
      confidence: Number.isFinite(parsed.confidence) ? parsed.confidence : fallback.confidence,
      topFindings: Array.isArray(parsed.topFindings) ? parsed.topFindings.slice(0, 8) : fallback.topFindings,
      recommendedActions: Array.isArray(parsed.recommendedActions) ? parsed.recommendedActions.slice(0, 8) : fallback.recommendedActions,
      mitreMapping: Array.isArray(parsed.mitreMapping) ? parsed.mitreMapping : fallback.mitreMapping
    };
  } catch {
    return fallback;
  }
}

function buildReportMarkdown(analysis) {
  const triage = analysis?.triage || buildDeterministicTriage(analysis);
  const lines = [
    `# ThreatForge Phishing Analysis Report`,
    ``,
    `- Analysis ID: ${analysis.id}`,
    `- Title: ${analysis.title || 'N/A'}`,
    `- Timestamp: ${analysis.timestamp}`,
    `- Risk Score: ${analysis.stats?.riskScore || 0}% (${analysis.stats?.threatLevel || 'LOW'})`,
    `- Classification: ${triage.classification}`,
    `- Severity: ${triage.severity}`,
    `- Confidence: ${triage.confidence}`,
    ``,
    `## Key Findings`,
    ...(triage.topFindings || []).map(f => `- ${f}`),
    ``,
    `## Authentication Issues`,
    ...((analysis.authIssues || []).length ? analysis.authIssues.map(i => `- ${i}`) : ['- None']),
    ``,
    analysis.emailAnalysis?.displayNameImpersonation?.detected ? [
      `## Display Name Impersonation`,
      `- Brand: ${analysis.emailAnalysis.displayNameImpersonation.brand}`,
      `- Display Name: ${analysis.emailAnalysis.displayNameImpersonation.displayName}`,
      `- Sender Domain: ${analysis.emailAnalysis.displayNameImpersonation.realDomain}`,
      `- Description: ${analysis.emailAnalysis.displayNameImpersonation.description}`,
      ``
    ].join('\n') + '\n' : '',
    analysis.emailAnalysis?.replyToMismatch?.mismatch ? [
      `## Reply-To / Return-Path Mismatch`,
      `- From: ${analysis.emailAnalysis.replyToMismatch.from}`,
      `- Reply-To: ${analysis.emailAnalysis.replyToMismatch.replyTo}`,
      `- Return-Path: ${analysis.emailAnalysis.replyToMismatch.returnPath}`,
      `- Description: ${analysis.emailAnalysis.replyToMismatch.description}`,
      ``
    ].join('\n') + '\n' : '',
    analysis.emailAnalysis?.qrCodeDetection?.length > 0 ? [
      `## QR Code / URL Shortener Detection`,
      ...analysis.emailAnalysis.qrCodeDetection.map(q => `- ${q.note || q.shortener || 'detected'}`),
      analysis.emailAnalysis.qrCodeDetection.some(q => q.url) ? [
        `  URLs:`,
        ...analysis.emailAnalysis.qrCodeDetection.filter(q => q.url).map(q => `  - ${q.url}`)
      ].join('\n') : '',
      ``
    ].join('\n') + '\n' : '',
    analysis.emailAnalysis?.senderDomainAnalysis?.suspicious ? [
      `## Suspicious Sender Domain`,
      `- Reason: ${analysis.emailAnalysis.senderDomainAnalysis.reason}`,
      ``
    ].join('\n') + '\n' : '',
    analysis.emailAnalysis?.embeddedForms?.detected ? [
      `## Embedded Forms Detected`,
      ...analysis.emailAnalysis.embeddedForms.forms.map(f => `- ${f.count}x ${f.field} field${f.suspiciousAction ? ' - suspicious action: ' + f.suspiciousAction : ''}`),
      ``
    ].join('\n') + '\n' : '',
    analysis.emailAnalysis?.calendarInvite?.detected ? [
      `## Calendar Invite`,
      `- Type: ${analysis.emailAnalysis.calendarInvite.type || 'Unknown'}`,
      ...(analysis.emailAnalysis.calendarInvite.details?.summary ? [`- Summary: ${analysis.emailAnalysis.calendarInvite.details.summary}`] : []),
      ...(analysis.emailAnalysis.calendarInvite.details?.location ? [`- Location: ${analysis.emailAnalysis.calendarInvite.details.location}`] : []),
      ...(analysis.emailAnalysis.calendarInvite.details?.suspicious ? [`- ⚠️ SUSPICIOUS: ${analysis.emailAnalysis.calendarInvite.details.suspiciousReason}`] : []),
      ``
    ].join('\n') + '\n' : '',
    `## IOC Summary`,
    `- Total IOCs: ${analysis.stats?.totalIocs || 0}`,
    `- Malicious: ${analysis.malicious || 0}`,
    `- Suspicious: ${analysis.suspicious || 0}`,
    `- Clean: ${analysis.clean || 0}`,
    ``,
    `## MITRE ATT&CK Mapping`,
    ...((triage.mitreMapping || []).length ? triage.mitreMapping.map(t => `- ${t.id}: ${t.name}`) : ['- None']),
    ``,
    `## Recommended Actions`,
    ...(triage.recommendedActions || []).map(a => `- ${a}`)
  ];
  return lines.join('\n');
}

function normalizeIocValue(value, type) {
  const raw = String(value || '').trim();
  if (!raw) return '';
  if (type === 'domain') return normalizeDomain(raw);
  if (type === 'url') return deobfuscateText(raw);
  if (type === 'hash') return raw.toLowerCase();
  return raw;
}

function buildUniqueIocs(parsed) {
  const allIocs = [
    ...(parsed.ips || []).map(ip => ({ value: ip, type: 'ip' })),
    ...(parsed.domains || []).map(domain => ({ value: domain, type: 'domain' })),
    ...(parsed.urls || []).map(url => ({ value: url, type: 'url' })),
    ...(parsed.hashes || []).map(hash => ({ value: hash, type: 'hash' }))
  ];

  const uniqueIocs = [];
  const seen = new Set();
  for (const ioc of allIocs) {
    const normalized = normalizeIocValue(ioc.value, ioc.type);
    if (!normalized) continue;
    const key = `${ioc.type}:${normalized}`;
    if (!seen.has(key)) {
      seen.add(key);
      uniqueIocs.push({ type: ioc.type, value: normalized });
    }
  }

  return uniqueIocs;
}

function fingerprintMailEvent(event) {
  const subject = String(event.subject || '').trim();
  const sender = String(event.sender || '').trim();
  const recipient = String(event.recipient || '').trim();
  const content = String(event.body || event.content || '').slice(0, 2000);
  return crypto.createHash('sha256').update(`${subject}|${sender}|${recipient}|${content}`).digest('hex');
}

function evaluateAutoDetection(analysisResult, metadata = {}) {
  const risk = analysisResult?.stats?.riskScore || 0;
  const malicious = analysisResult?.malicious || 0;
  const suspicious = analysisResult?.suspicious || 0;
  const threatLevel = analysisResult?.stats?.threatLevel || 'LOW';
  const shouldAlert = malicious > 0 || risk >= 50 || threatLevel === 'CRITICAL' || suspicious >= 2;

  return {
    id: uuidv4(),
    timestamp: new Date().toISOString(),
    shouldAlert,
    severity: threatLevel,
    riskScore: risk,
    malicious,
    suspicious,
    recipient: metadata.recipient || null,
    sender: metadata.sender || null,
    subject: metadata.subject || analysisResult?.title || 'Email Analysis',
    source: metadata.source || 'mail-event',
    analysisId: analysisResult?.id,
    triage: analysisResult?.triage || null,
    summary: analysisResult?.summary || null
  };
}

function extractBlockingIndicators(analysisResult, metadata = {}) {
  const maliciousIocs = (analysisResult?.iocs || []).filter(i => i.verdict === 'malicious');
  const domains = maliciousIocs.filter(i => i.type === 'domain').map(i => i.value);
  const ips = maliciousIocs.filter(i => i.type === 'ip').map(i => i.value);
  const urls = maliciousIocs.filter(i => i.type === 'url').map(i => i.value);
  const sender = metadata.sender || analysisResult?.mailbox?.sender || null;
  return {
    sender,
    domains: [...new Set(domains)],
    ips: [...new Set(ips)],
    urls: [...new Set(urls)]
  };
}

function shouldAutoContain(detection) {
  const risk = detection?.riskScore || 0;
  const severity = String(detection?.severity || '').toUpperCase();
  const triageConfidence = Number(detection?.triage?.confidence || 0);
  return risk >= 75 || severity === 'CRITICAL' || (risk >= 60 && triageConfidence >= 75);
}

function buildIncidentRecord(analysis, detection) {
  return {
    id: `inc-${uuidv4()}`,
    createdAt: new Date().toISOString(),
    status: 'open',
    priority: detection.severity === 'CRITICAL' ? 'P1' : detection.severity === 'HIGH' ? 'P2' : 'P3',
    title: `[AUTO-PHISH] ${detection.subject || analysis?.title || 'Suspicious email detected'}`,
    source: detection.source || 'mail-event',
    detectionId: detection.id,
    analysisId: analysis?.id,
    recipient: detection.recipient,
    sender: detection.sender,
    riskScore: detection.riskScore,
    severity: detection.severity,
    summary: detection.summary,
    triage: detection.triage || null
  };
}

async function sendSocNotifications(incident, detection, analysis) {
  const payload = {
    event: 'phishing_incident_created',
    incident,
    detection,
    analysisSummary: {
      id: analysis?.id,
      title: analysis?.title,
      riskScore: analysis?.stats?.riskScore,
      threatLevel: analysis?.stats?.threatLevel,
      malicious: analysis?.malicious,
      suspicious: analysis?.suspicious
    }
  };

  const webhookUrl = process.env.PHISH_SOC_WEBHOOK_URL || '';
  const slackWebhook = process.env.SLACK_WEBHOOK_URL || '';
  const teamsWebhook = process.env.TEAMS_WEBHOOK_URL || '';

  const results = [];

  if (webhookUrl) {
    try {
      const r = await fetch(webhookUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
        signal: AbortSignal.timeout(8000)
      });
      results.push({ channel: 'webhook', ok: r.ok, status: r.status });
    } catch (e) {
      results.push({ channel: 'webhook', ok: false, error: e.message });
    }
  }

  if (slackWebhook) {
    try {
      const text = `:rotating_light: ThreatForge Auto Incident ${incident.id}\n*${incident.title}*\nSeverity: ${incident.severity} | Risk: ${incident.riskScore}%\nSender: ${incident.sender || 'unknown'} -> Recipient: ${incident.recipient || 'unknown'}`;
      const r = await fetch(slackWebhook, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text }),
        signal: AbortSignal.timeout(8000)
      });
      results.push({ channel: 'slack', ok: r.ok, status: r.status });
    } catch (e) {
      results.push({ channel: 'slack', ok: false, error: e.message });
    }
  }

  if (teamsWebhook) {
    try {
      const r = await fetch(teamsWebhook, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          '@type': 'MessageCard',
          '@context': 'http://schema.org/extensions',
          summary: incident.title,
          themeColor: incident.severity === 'CRITICAL' ? 'FF0000' : incident.severity === 'HIGH' ? 'FF8C00' : 'FFD700',
          title: `ThreatForge Auto Phishing Incident ${incident.id}`,
          text: `${incident.title}\n\nSeverity: ${incident.severity}\nRisk Score: ${incident.riskScore}%\nSender: ${incident.sender || 'unknown'}\nRecipient: ${incident.recipient || 'unknown'}`
        }),
        signal: AbortSignal.timeout(8000)
      });
      results.push({ channel: 'teams', ok: r.ok, status: r.status });
    } catch (e) {
      results.push({ channel: 'teams', ok: false, error: e.message });
    }
  }

  return results;
}

async function executeResponseHooks(incident, detection, analysis) {
  const responseHookUrl = process.env.PHISH_RESPONSE_HOOK_URL || '';
  const indicators = extractBlockingIndicators(analysis, { sender: detection.sender });
  const actionRecord = {
    id: `act-${uuidv4()}`,
    incidentId: incident.id,
    detectionId: detection.id,
    timestamp: new Date().toISOString(),
    mode: shouldAutoContain(detection) ? 'auto-contain' : 'notify-only',
    indicators,
    hookResults: []
  };

  if (!shouldAutoContain(detection)) {
    responseActions.set(actionRecord.id, actionRecord);
    return actionRecord;
  }

  if (responseHookUrl) {
    try {
      const r = await fetch(responseHookUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          action: 'auto_block',
          incident,
          detection,
          indicators
        }),
        signal: AbortSignal.timeout(8000)
      });
      actionRecord.hookResults.push({ channel: 'response-hook', ok: r.ok, status: r.status });
    } catch (e) {
      actionRecord.hookResults.push({ channel: 'response-hook', ok: false, error: e.message });
    }
  }

  const now = new Date().toISOString();
  if (indicators.sender) blockedIndicators.set(`sender:${indicators.sender.toLowerCase()}`, { value: indicators.sender, type: 'sender', blockedAt: now, incidentId: incident.id });
  indicators.domains.forEach(d => blockedIndicators.set(`domain:${d.toLowerCase()}`, { value: d, type: 'domain', blockedAt: now, incidentId: incident.id }));
  indicators.ips.forEach(ip => blockedIndicators.set(`ip:${ip}`, { value: ip, type: 'ip', blockedAt: now, incidentId: incident.id }));
  indicators.urls.forEach(u => blockedIndicators.set(`url:${u}`, { value: u, type: 'url', blockedAt: now, incidentId: incident.id }));

  responseActions.set(actionRecord.id, actionRecord);
  if (responseActions.size > 1000) {
    const firstKey = responseActions.keys().next().value;
    responseActions.delete(firstKey);
  }
  if (blockedIndicators.size > 3000) {
    const firstKey = blockedIndicators.keys().next().value;
    blockedIndicators.delete(firstKey);
  }
  return actionRecord;
}

async function runSocAutomation(analysis, detection) {
  if (!detection?.shouldAlert) return null;
  const incident = buildIncidentRecord(analysis, detection);
  incidentRecords.set(incident.id, incident);
  if (incidentRecords.size > 1000) {
    const firstKey = incidentRecords.keys().next().value;
    incidentRecords.delete(firstKey);
  }

  const notifyResults = await sendSocNotifications(incident, detection, analysis);
  const responseAction = await executeResponseHooks(incident, detection, analysis);

  incident.notifications = notifyResults;
  incident.responseActionId = responseAction?.id || null;
  incidentRecords.set(incident.id, incident);

  return { incident, notifyResults, responseAction };
}

async function buildAnalysisFromMailEvent(mailEvent) {
  const analysisId = uuidv4();
  const startTime = Date.now();
  const title = mailEvent.subject || mailEvent.title || 'Auto-Detected Email';
  const emailHeaders = mailEvent.headers || '';
  const emailContent = mailEvent.body || mailEvent.content || '';

  const parsed = parseEmail(emailContent, emailHeaders);
  const uniqueIocs = buildUniqueIocs(parsed);
  const iocsToEnrich = uniqueIocs.slice(0, 20);
  const enrichedIocs = await Promise.all(iocsToEnrich.map(ioc => enrichIOC(ioc.value, ioc.type)));

  const totalScore = enrichedIocs.reduce((sum, ioc) => sum + ioc.score, 0);
  const maxPossibleScore = enrichedIocs.length * 100;
  const riskScore = maxPossibleScore > 0 ? Math.round((totalScore / maxPossibleScore) * 100) : 0;

  let threatLevel = 'LOW';
  let threatColor = 'green';
  if (riskScore >= 70) {
    threatLevel = 'CRITICAL';
    threatColor = 'red';
  } else if (riskScore >= 50) {
    threatLevel = 'HIGH';
    threatColor = 'orange';
  } else if (riskScore >= 25) {
    threatLevel = 'MEDIUM';
    threatColor = 'yellow';
  }

  const authIssues = [];
  if (parsed.authentication.spf && parsed.authentication.spf.includes('fail')) authIssues.push('SPF check failed');
  if (parsed.authentication.dkim === null) authIssues.push('DKIM signature missing');
  if (parsed.authentication.dkim === 'fail') authIssues.push('DKIM check failed');
  if (parsed.authentication.dmarc && parsed.authentication.dmarc.includes('fail')) authIssues.push('DMARC check failed');
  if (parsed.authentication.replyTo && parsed.authentication.replyTo !== parsed.headers.From) authIssues.push('Reply-To mismatch');

  const result = {
    id: analysisId,
    timestamp: new Date().toISOString(),
    title,
    mode: 'auto-detected',
    mailbox: {
      recipient: mailEvent.recipient || null,
      sender: mailEvent.sender || null,
      source: mailEvent.source || 'mail-event',
      externalId: mailEvent.externalId || null
    },
    stats: {
      totalIocs: uniqueIocs.length,
      ipsFound: parsed.ips.length,
      domainsFound: parsed.domains.length,
      urlsFound: parsed.urls.length,
      hashesFound: parsed.hashes.length,
      enrichedCount: enrichedIocs.length,
      riskScore,
      threatLevel,
      threatColor,
      analysisTimeMs: Date.now() - startTime
      },
      authentication: parsed.authentication,
      authIssues,
      headers: parsed.headers,
      iocs: enrichedIocs,
      suspicious: enrichedIocs.filter(i => i.verdict === 'suspicious').length,
      malicious: enrichedIocs.filter(i => i.verdict === 'malicious').length,
      clean: enrichedIocs.filter(i => i.verdict === 'clean').length,
      summary: generateSummary(parsed, enrichedIocs, authIssues, enrichedAttachments),
      decodedContent: parsed.decodedContent || [],
      attachments: enrichedAttachments,
      attachmentStats: {
        total: enrichedAttachments.length,
        malicious: enrichedAttachments.filter(a => a.verdict === 'malicious').length,
        suspicious: enrichedAttachments.filter(a => a.verdict === 'suspicious').length,
        clean: enrichedAttachments.filter(a => a.verdict === 'clean').length,
        unknown: enrichedAttachments.filter(a => a.verdict === 'unknown').length
      },
      bodyPreview: (parsed.body || '').slice(0, 6000),
      intel: getIntelConfigStatus()
    };
  result.triage = await generateAiTriage(result);

  return result;
}

async function processMailEvent(mailEvent) {
  const fingerprint = fingerprintMailEvent(mailEvent);
  if (processedMailIds.has(fingerprint)) return null;
  processedMailIds.add(fingerprint);
  if (processedMailIds.size > 5000) {
    const first = processedMailIds.values().next().value;
    processedMailIds.delete(first);
  }

  const analysis = await buildAnalysisFromMailEvent(mailEvent);
  analysisHistory.set(analysis.id, analysis);
  if (analysisHistory.size > 100) {
    const firstKey = analysisHistory.keys().next().value;
    analysisHistory.delete(firstKey);
  }

  const detection = evaluateAutoDetection(analysis, {
    recipient: mailEvent.recipient,
    sender: mailEvent.sender,
    subject: mailEvent.subject,
    source: mailEvent.source || 'mail-event'
  });
  autoDetections.set(detection.id, detection);
  if (autoDetections.size > 300) {
    const firstKey = autoDetections.keys().next().value;
    autoDetections.delete(firstKey);
  }

  autoState.eventsProcessed += 1;
  const soc = await runSocAutomation(analysis, detection);
  return { analysis, detection, soc };
}

async function fetchGraphToken() {
  const tenantId = process.env.M365_TENANT_ID;
  const clientId = process.env.M365_CLIENT_ID;
  const clientSecret = process.env.M365_CLIENT_SECRET;
  if (!tenantId || !clientId || !clientSecret) return null;

  const tokenRes = await fetch(`https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      client_id: clientId,
      client_secret: clientSecret,
      scope: 'https://graph.microsoft.com/.default',
      grant_type: 'client_credentials'
    }),
    signal: AbortSignal.timeout(8000)
  });
  if (!tokenRes.ok) return null;
  const tokenData = await tokenRes.json();
  return tokenData.access_token || null;
}

async function pollMailboxForPhishing() {
  if (autoState.running) return;
  const recipients = String(process.env.AUTO_PHISH_MAILBOXES || '')
    .split(',')
    .map(s => s.trim())
    .filter(Boolean);
  if (!recipients.length) return;

  autoState.running = true;
  autoState.enabled = true;
  autoState.lastRunAt = new Date().toISOString();

  try {
    const token = await fetchGraphToken();
    if (!token) {
      autoState.lastError = 'M365 credentials not configured';
      return;
    }

    for (const mailbox of recipients) {
      autoState.mailboxChecks += 1;
      const url = `https://graph.microsoft.com/v1.0/users/${encodeURIComponent(mailbox)}/messages?$top=10&$select=id,subject,bodyPreview,from,receivedDateTime,body`;
      const res = await fetch(url, {
        headers: { Authorization: `Bearer ${token}` },
        signal: AbortSignal.timeout(9000)
      });
      if (!res.ok) continue;
      const data = await res.json();
      const msgs = Array.isArray(data.value) ? data.value : [];
      for (const msg of msgs) {
        const mailEvent = {
          externalId: msg.id,
          subject: msg.subject || 'No subject',
          sender: msg.from?.emailAddress?.address || null,
          recipient: mailbox,
          source: 'm365-graph',
          body: msg.body?.content || msg.bodyPreview || '',
          headers: ''
        };
        await processMailEvent(mailEvent);
      }
    }
    autoState.lastError = null;
  } catch (err) {
    autoState.lastError = err.message;
  } finally {
    autoState.running = false;
    autoState.lastRunAt = new Date().toISOString();
  }
}

function safeDecodeUtf8(buffer) {
  const decoded = buffer.toString('utf-8');
  const printable = decoded.replace(/[^\x09\x0A\x0D\x20-\x7E\u00A0-\u024F]/g, '').length;
  if (/<[a-zA-Z][\s\S]*?>/.test(decoded) && decoded.length > 40) return decoded;
  if (printable >= 16) return decoded;
  const latin = buffer.toString('latin1');
  const latinPrint = latin.replace(/[^\x09\x0A\x0D\x20-\x7E]/g, '').length;
  if (latinPrint >= 16) return latin;
  return null;
}

function padBase64(s) {
  let out = String(s || '').replace(/\s/g, '');
  while (out.length % 4) out += '=';
  return out;
}

function decodeTransferEncodedBlock(raw, encoding) {
  const content = String(raw || '');
  const mode = String(encoding || '').toLowerCase();
  if (!content) return null;

  if (mode.includes('base64')) {
    const cleaned = padBase64(content.replace(/[\r\n\t ]/g, ''));
    if (cleaned.length < 16 || !/^[A-Za-z0-9+/=]+$/.test(cleaned)) {
      return null;
    }
    try {
      return safeDecodeUtf8(Buffer.from(cleaned, 'base64'));
    } catch {
      return null;
    }
  }

  if (mode.includes('quoted-printable')) {
    try {
      return decodeQuotedPrintable(content);
    } catch {
      return null;
    }
  }

  return null;
}

function getIntelConfigStatus() {
  const keyOk = (v) => !!(v && String(v).trim().length > 8 && !String(v).startsWith('your-'));
  const keyMask = (v) => v ? `${v.substring(0, 4)}...${v.substring(v.length - 4)}` : null;
  return {
    virustotal: keyOk(process.env.VT_API_KEY),
    virustotalKey: keyMask(process.env.VT_API_KEY),
    abuseipdb: keyOk(process.env.ABUSEIPDB_KEY),
    abuseipdbKey: keyMask(process.env.ABUSEIPDB_KEY),
    misp: keyOk(process.env.MISP_URL) && keyOk(process.env.MISP_API_KEY),
    malwarebazaar: true,
    threatfox: true,
    openaiTriage: keyOk(process.env.OPENAI_API_KEY)
  };
}

function decodeHtmlEntities(text) {
  return String(text || '')
    .replace(/&nbsp;/gi, ' ')
    .replace(/&amp;/gi, '&')
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>')
    .replace(/&quot;/gi, '"')
    .replace(/&#039;/gi, "'")
    .replace(/&#(\d+);/g, (_, n) => String.fromCharCode(parseInt(n, 10)))
    .replace(/&#x([0-9a-fA-F]+);/g, (_, h) => String.fromCharCode(parseInt(h, 16)));
}

function stripHtmlToText(html) {
  const s = decodeHtmlEntities(String(html || ''))
    .replace(/<script[\s\S]*?<\/script>/gi, ' ')
    .replace(/<style[\s\S]*?<\/style>/gi, ' ')
    .replace(/<br\s*\/?>/gi, '\n')
    .replace(/<\/(p|div|tr|li|h[1-6])>/gi, '\n')
    .replace(/<[^>]+>/g, ' ')
    .replace(/[ \t]+\n/g, '\n')
    .replace(/\n{3,}/g, '\n\n')
    .replace(/[ \t]{2,}/g, ' ')
    .trim();
  return s;
}

function pushDecodedUnique(arr, entry) {
  const content = String(entry.content || '');
  if (!content.trim()) return;
  const key = (entry.type || '') + ':' + content.slice(0, 120);
  if (pushDecodedUnique._seen.has(key)) return;
  pushDecodedUnique._seen.add(key);
  arr.push(entry);
}
pushDecodedUnique._seen = new Set();

function tryDecodeWholeBase64Blob(text) {
  const t = String(text || '').replace(/\r\n/g, '\n').trim();
  const compact = t.replace(/\s/g, '');
  if (compact.length < 48) return null;
  if (!/^[A-Za-z0-9+/]+=*$/.test(compact)) return null;
  try {
    const buf = Buffer.from(padBase64(compact), 'base64');
    if (!buf.length) return null;
    const readable = safeDecodeUtf8(buf);
    if (readable) {
      return {
        type: 'inferred-base64-body',
        label: 'Decoded (inferred base64 body)',
        content: readable.slice(0, 8000),
        fullLength: readable.length
      };
    }
    return {
      type: 'inferred-base64-binary',
      label: 'Decoded base64 (binary / non-text)',
      content: `[${buf.length} bytes] SHA256: ${crypto.createHash('sha256').update(buf).digest('hex')}\nHex preview: ${buf.slice(0, 48).toString('hex')}…`,
      fullLength: buf.length,
      sha256: crypto.createHash('sha256').update(buf).digest('hex')
    };
  } catch {
    return null;
  }
}

function tryQuotedPrintableBody(body) {
  const b = String(body || '');
  if (!/=(?:[0-9A-Fa-f]{2}|\n)/.test(b)) return null;
  const d = decodeQuotedPrintable(b);
  if (!d || d === b || d.length < 12) return null;
  return {
    type: 'inferred-quoted-printable',
    label: 'Decoded (quoted-printable body)',
    content: d.slice(0, 8000),
    fullLength: d.length
  };
}

function augmentDecodedEmailArtifacts(parsed) {
  pushDecodedUnique._seen = new Set();
  const out = [];
  for (const x of parsed.decodedContent || []) {
    pushDecodedUnique(out, {
      type: x.type || 'decoded',
      label: x.label || String(x.type || 'Decoded part'),
      content: x.content || x.decoded || '',
      fullLength: x.fullLength || (x.content || x.decoded || '').length
    });
  }

  const body = parsed.body || '';
  const ct = String(parsed.headers['Content-Type'] || parsed.headers['Content-type'] || '').toLowerCase();

  const qp = tryQuotedPrintableBody(body);
  if (qp) pushDecodedUnique(out, qp);

  const b64 = tryDecodeWholeBase64Blob(body);
  if (b64) pushDecodedUnique(out, b64);

  if (body.includes('<') && (ct.includes('html') || /<\s*html[\s>]/i.test(body) || /<\s*body[\s>]/i.test(body))) {
    const plain = stripHtmlToText(body);
    if (plain.length > 40) {
      pushDecodedUnique(out, {
        type: 'html-to-text',
        label: 'Readable text (HTML stripped)',
        content: plain.slice(0, 8000),
        fullLength: plain.length
      });
    }
  }

  const combined = `${body}\n${JSON.stringify(parsed.headers)}`;
  const fromDetect = detectAndDecodeBase64(combined);
  for (const d of fromDetect.decoded || []) {
    pushDecodedUnique(out, {
      type: 'base64-scan',
      label: 'Decoded (embedded base64)',
      content: d.decoded || d.content || '',
      fullLength: d.length || (d.decoded || '').length
    });
  }
  for (const att of fromDetect.attachments || []) {
    parsed.attachments.push({
      type: att.type || 'binary',
      size: att.size,
      hash: att.hash || null
    });
  }

  parsed.decodedContent = out;

  const plainForIocs = out.map(x => x.content).join('\n');
  if (plainForIocs.length > 20) {
    const extra = extractIOCsFromText(plainForIocs);
    parsed.urls.push(...extra.urls);
    parsed.ips.push(...extra.ips);
    parsed.domains.push(...extra.domains);
    parsed.hashes.push(...extra.hashes);
    parsed.urls = [...new Set(parsed.urls)];
    parsed.ips = [...new Set(parsed.ips)];
    parsed.domains = [...new Set(parsed.domains)];
    parsed.hashes = [...new Set(parsed.hashes)];
  }
}

// Enrich IOCs with multiple sources
async function enrichIOC(ioc, type) {
  const results = {
    value: ioc,
    type: type,
    sources: {},
    score: 0,
    verdict: 'unknown',
    lastSeen: null,
    tags: []
  };
  
  const vtKeyConfigured = !!(process.env.VT_API_KEY && !process.env.VT_API_KEY.startsWith('your-') && process.env.VT_API_KEY.length > 10);
  const abuseKeyConfigured = !!(process.env.ABUSEIPDB_KEY && !process.env.ABUSEIPDB_KEY.startsWith('your-') && process.env.ABUSEIPDB_KEY.length > 10);
  
  try {
    // VirusTotal
    if (vtKeyConfigured) {
      try {
        let vtUrl;
        if (type === 'ip') {
          vtUrl = `https://www.virustotal.com/api/v3/ip_addresses/${ioc}`;
        } else if (type === 'domain') {
          vtUrl = `https://www.virustotal.com/api/v3/domains/${ioc}`;
        } else if (type === 'url') {
          const urlId = Buffer.from(ioc.trim()).toString('base64').replace(/=+$/g, '').replace(/\+/g, '-').replace(/\//g, '_');
          vtUrl = `https://www.virustotal.com/api/v3/urls/${urlId}`;
        } else if (type === 'hash') {
          vtUrl = `https://www.virustotal.com/api/v3/files/${ioc}`;
        }
        
        if (vtUrl) {
          const vtRes = await fetch(vtUrl, {
            headers: { 'x-apikey': process.env.VT_API_KEY.trim() },
            signal: AbortSignal.timeout(8000)
          });
          
          if (vtRes.ok) {
            const vtData = await vtRes.json();
            const stats = vtData.data?.attributes?.last_analysis_stats || {};
            results.sources.virustotal = {
              malicious: stats.malicious || 0,
              suspicious: stats.suspicious || 0,
              harmless: stats.harmless || 0,
              undetected: stats.undetected || 0,
              total: Object.values(stats).reduce((a, b) => a + b, 0)
            };
            results.score += (stats.malicious || 0) * 10;
            if (stats.malicious > 0) results.tags.push('vt-malicious');
            console.log(`[Phishing] VT result for ${type} ${ioc.substring(0, 30)}: ${stats.malicious} mal / ${stats.suspicious} sus`);
          } else if (vtRes.status === 404) {
            results.sources.virustotal = { notFound: true, malicious: 0, suspicious: 0, harmless: 0, undetected: 0, total: 0 };
          } else if (vtRes.status === 429 || vtRes.status === 403) {
            // Quota exceeded or rate limited - don't fail, just skip
            results.sources.virustotal = { rateLimited: true, malicious: 0, suspicious: 0, harmless: 0, undetected: 0, total: 0 };
            console.log(`[Phishing] VT rate limited (${vtRes.status}) - using fallback detection for ${ioc.substring(0, 30)}`);
            // Apply fallback heuristics when VT is unavailable
            applyFallbackHeuristics(results, ioc, type);
          }
        }
      } catch (vtErr) {
        console.log(`[Phishing] VT error for ${ioc}:`, vtErr.message);
      }
    } else {
      console.log(`[Phishing] VT not configured - using fallback heuristics. Key: "${process.env.VT_API_KEY}"`);
      // Apply fallback heuristics when VT is not configured
      applyFallbackHeuristics(results, ioc, type);
    }
    
    // AbuseIPDB (for IPs only)
    if (type === 'ip' && abuseKeyConfigured) {
      try {
        const abuseRes = await fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${ioc}&maxAgeInDays=90`, {
          headers: { 
            'Key': process.env.ABUSEIPDB_KEY.trim(),
            'Accept': 'application/json'
          },
          signal: AbortSignal.timeout(8000)
        });
        
        if (abuseRes.ok) {
          const abuseData = await abuseRes.json();
          results.sources.abuseipdb = {
            abuseScore: abuseData.data?.abuseConfidenceScore || 0,
            country: abuseData.data?.countryCode,
            isp: abuseData.data?.isp,
            totalReports: abuseData.data?.totalReports || 0,
            lastReported: abuseData.data?.lastReportedAt
          };
          results.score += (abuseData.data?.abuseConfidenceScore || 0);
          if (abuseData.data?.abuseConfidenceScore > 50) results.tags.push('abuseipdb-malicious');
          console.log(`[Phishing] AbuseIPDB result for ${ioc}: score ${abuseData.data?.abuseConfidenceScore}`);
        } else if (abuseRes.status === 429 || abuseRes.status === 403) {
          results.sources.abuseipdb = { rateLimited: true, abuseScore: 0 };
          console.log(`[Phishing] AbuseIPDB rate limited (${abuseRes.status})`);
        }
      } catch (abuseErr) {
        console.log(`[Phishing] AbuseIPDB error for ${ioc}:`, abuseErr.message);
      }
    } else if (type === 'ip' && !abuseKeyConfigured) {
      console.log(`[Phishing] AbuseIPDB not configured. Key: "${process.env.ABUSEIPDB_KEY}"`);
    }
    
    // MalwareBazaar (for hashes only)
    if (type === 'hash') {
      try {
        const mbRes = await fetch('https://mb-api.abuse.ch/api/v1/', {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: `query=get_info&hash=${ioc}`,
          signal: AbortSignal.timeout(5000)
        });
        
        if (mbRes.ok) {
          const mbData = await mbRes.json();
          if (mbData.data && mbData.data.length > 0) {
            results.sources.malwarebazaar = {
              firstSeen: mbData.data[0]?.first_seen,
              signature: mbData.data[0]?.signature,
              fileType: mbData.data[0]?.file_type,
              tags: mbData.data[0]?.tags || []
            };
            results.score += 50;
            results.tags.push('malwarebazaar-known');
          }
        }
      } catch (mbErr) {
        console.log(`[Phishing] MalwareBazaar error for ${ioc}:`, mbErr.message);
      }
    }
    
    // ThreatFox (for IPs, domains, URLs)
    if (type !== 'hash') {
      try {
        const tfRes = await fetch('https://threatfox-api.abuse.ch/api/v1/', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ query: 'search_ioc', search_term: ioc }),
          signal: AbortSignal.timeout(5000)
        });
        
        if (tfRes.ok) {
          const tfData = await tfRes.json();
          if (tfData.data && tfData.data.length > 0) {
            results.sources.threatfox = {
              firstSeen: tfData.data[0]?.first_seen,
              malware: tfData.data[0]?.malware,
              confidence: tfData.data[0]?.confidence_level
            };
            results.score += 30;
            results.tags.push('threatfox-known');
          }
        }
      } catch (tfErr) {
        console.log(`[Phishing] ThreatFox error for ${ioc}:`, tfErr.message);
      }
    }
    
    // MISP lookup (if configured)
    const mispConfigured = !!(process.env.MISP_URL && process.env.MISP_API_KEY && 
        !process.env.MISP_URL.includes('your-misp') && 
        !process.env.MISP_API_KEY.includes('your-misp'));
    
    if (mispConfigured) {
      try {
        const mispRes = await fetch(`${process.env.MISP_URL}/attributes/restSearch`, {
          method: 'POST',
          headers: {
            'Authorization': process.env.MISP_API_KEY,
            'Content-Type': 'application/json',
            'Accept': 'application/json'
          },
          body: JSON.stringify({ 
            value: ioc,
            type: type === 'ip' ? 'ip-dst' : 
                  type === 'domain' ? 'domain' : 
                  type === 'url' ? 'url' : 
                  type === 'hash' ? 'md5' : null,
            limit: 10,
            published: true
          }),
          signal: AbortSignal.timeout(5000)
        });
        
        if (mispRes.ok) {
          const mispData = await mispRes.json();
          if (mispData.response && mispData.response.length > 0) {
            const mispEvents = mispData.response;
            const tags = [];
            mispEvents.forEach(event => {
              if (event.Attribute?.tag) {
                tags.push(...event.Attribute.tag.map(t => t.name));
              }
            });
            results.sources.misp = {
              events: mispEvents.length,
              firstSeen: mispEvents[0]?.Event?.date,
              eventIds: mispEvents.slice(0, 3).map(e => e.Event?.id),
              tags: [...new Set(tags)].slice(0, 10)
            };
            results.score += 40;
            results.tags.push('misp-listed');
            console.log(`[Phishing] MISP result for ${type} ${ioc.substring(0, 30)}: ${mispEvents.length} event(s)`);
          } else {
            console.log(`[Phishing] MISP: No results for ${type} ${ioc.substring(0, 30)}`);
          }
        } else if (mispRes.status === 403 || mispRes.status === 401) {
          console.log(`[Phishing] MISP auth failed (${mispRes.status})`);
          results.sources.misp = { error: 'Authentication failed', rateLimited: false };
        } else if (mispRes.status === 429) {
          console.log(`[Phishing] MISP rate limited (${mispRes.status})`);
          results.sources.misp = { error: 'Rate limited', rateLimited: true };
        } else {
          console.log(`[Phishing] MISP error (${mispRes.status})`);
        }
      } catch (mispErr) {
        console.log(`[Phishing] MISP error for ${ioc}:`, mispErr.message);
      }
    }
    
    // Typosquatting detection for domains and URLs
    const typoTarget = type === 'domain' ? ioc : (type === 'url' ? extractDomainFromUrl(ioc) : null);
    if (typoTarget) {
      const typoResult = detectTyposquatting(typoTarget);
      if (typoResult.isTyposquatting) {
        results.sources.typosquatting = {
          detected: true,
          brand: typoResult.brand,
          matchedTypo: typoResult.matchedTypo
        };
        results.score += 60;
        results.tags.push('typosquatting-detected');
        results.verdict = 'suspicious';
      }
      
      // Check for high-risk TLDs
      const domainParts = typoTarget.toLowerCase().split('.');
      const tld = domainParts[domainParts.length - 1];
      const highRiskTlds = ['cn', 'ru', 'xyz', 'top', 'club', 'online', 'site', 'pw', 'tk', 'ml', 'ga', 'cf', 'gq', 'buzz', 'link', 'work', 'date', 'faith', 'racing', 'win', 'review', 'download', 'trade'];
      if (highRiskTlds.includes(tld) && !results.tags.includes('typosquatting-detected')) {
        results.tags.push('high-risk-tld');
        results.score += 15;
      }
    }
    
    // Credential harvesting URL analysis (for URLs only)
    if (type === 'url') {
      const urlLower = ioc.toLowerCase();
      const harvestingIndicators = [];
      
      // Credential harvesting path patterns
      const harvestingPaths = [
        { pattern: /\/login|\/signin|\/sign-in|\/auth|\/account\/verify/gi, name: 'login-path' },
        { pattern: /\/password|\/reset|\/recover|\/forgot/gi, name: 'password-recovery' },
        { pattern: /\/verify|\/confirm|\/validate/gi, name: 'verification-path' },
        { pattern: /\/secure|\/update|\/payment|\/billing/gi, name: 'payment-path' },
        { pattern: /\/capture|\/harvest|\/steal|\/phish/gi, name: 'credential-keyword' },
        { pattern: /form|input|submit|token|session|oauth/gi, name: 'form-submission' }
      ];
      
      for (const hp of harvestingPaths) {
        if (hp.pattern.test(urlLower)) {
          harvestingIndicators.push(hp.name);
        }
      }
      
      // Check for suspicious URL patterns
      if (urlLower.includes('redirect=') || urlLower.includes('continue=') || 
          urlLower.includes('next=') || urlLower.includes('return=')) {
        harvestingIndicators.push('redirect-parameter');
      }
      
      if (urlLower.includes('@') || urlLower.includes('\\x40')) {
        harvestingIndicators.push('email-in-url');
      }
      
      // Shortened URL detection
      const shorteners = ['bit.ly', 'tinyurl', 'goo.gl', 't.co', 'ow.ly', 'buff.ly', 'is.gd', 'adf.ly'];
      if (shorteners.some(s => urlLower.includes(s))) {
        harvestingIndicators.push('url-shortener');
        results.tags.push('url-shortener');
      }
      
      if (harvestingIndicators.length >= 2) {
        results.sources.urlAnalysis = {
          credentialHarvesting: true,
          indicators: harvestingIndicators,
          description: `URL contains ${harvestingIndicators.length} credential harvesting indicators`
        };
        results.score += 40;
        results.tags.push('credential-harvesting-url');
        if (results.verdict !== 'malicious') {
          results.verdict = 'suspicious';
        }
      }
    }
    
    // For new/unseen domains, mark as potentially suspicious
    if (type === 'domain' && !results.sources.virustotal) {
      const typoResult = detectTyposquatting(ioc);
      if (typoResult.isTyposquatting) {
        results.score += 40;
        results.verdict = 'suspicious';
      }
    }
    
    // Check domain age for new domains (domains < 90 days old are suspicious)
    if (type === 'domain') {
      const domainAge = await checkDomainAge(ioc);
      if (domainAge.isNew) {
        results.sources.domainAge = {
          registered: domainAge.registered,
          daysOld: domainAge.daysOld,
          isNew: true
        };
        results.score += 20;
        results.tags.push('new-domain');
      }
    }
    
    // Determine verdict based on score
    if (results.score >= 70 || results.tags.includes('typosquatting-detected')) {
      results.verdict = 'malicious';
    } else if (results.score >= 30 || results.tags.includes('new-domain')) {
      results.verdict = 'suspicious';
    } else if (results.score > 0) {
      results.verdict = 'unknown';
    } else {
      results.verdict = 'clean';
    }
    
  } catch (error) {
    console.error(`[Phishing] Error enriching ${ioc}:`, error.message);
  }
  
  return results;
}

// ===================================================
// API ENDPOINTS
// ===================================================

// POST /api/phishing/enrich - Enrich a single IOC
router.post('/enrich', async (req, res) => {
  const { ioc, type } = req.body || {};
  if (!ioc || !type) {
    return res.status(400).json({ error: 'ioc and type are required' });
  }
  if (!['ip', 'domain', 'url', 'hash'].includes(type)) {
    return res.status(400).json({ error: 'type must be one of ip, domain, url, hash' });
  }

  try {
    const normalizedValue = type === 'domain' ? normalizeDomain(ioc) : deobfuscateText(String(ioc).trim());
    const enriched = await enrichIOC(normalizedValue, type);
    res.json(enriched);
  } catch (error) {
    res.status(500).json({ error: 'enrichment failed', message: error.message });
  }
});

// POST /api/phishing/analyze - Analyze email content/headers
router.post('/analyze', async (req, res) => {
  const { emailContent, emailHeaders, title } = req.body;
  
  if (!emailContent && !emailHeaders) {
    return res.status(400).json({ error: 'Email content or headers required' });
  }
  
  const analysisId = uuidv4();
  const startTime = Date.now();
  
  try {
    console.log(`[Phishing] Analyzing email #${analysisId}`);
    console.log(`[Phishing] VT_API_KEY: "${process.env.VT_API_KEY ? process.env.VT_API_KEY.substring(0, 8) + '...' : 'NOT SET'}"`);
    console.log(`[Phishing] ABUSEIPDB_KEY: "${process.env.ABUSEIPDB_KEY ? 'SET' : 'NOT SET'}"`);
    
    let parsed;
    try {
      // Auto-detect headers: if content contains header lines but headers field is empty
      let actualHeaders = emailHeaders || '';
      let actualContent = emailContent || '';
      
      if (!actualHeaders && actualContent) {
        const lines = actualContent.split(/\r?\n/);
        let headerEndIndex = 0;
        
        // Find the end of headers (first empty line)
        for (let i = 0; i < lines.length; i++) {
          if (lines[i].trim() === '') {
            headerEndIndex = i;
            break;
          }
        }
        
        // If we found headers (at least one header line before empty line)
        if (headerEndIndex > 0) {
          const headerLines = lines.slice(0, headerEndIndex);
          const bodyLines = lines.slice(headerEndIndex + 1);
          
          // Check if header lines look like email headers
          const hasReceivedHeader = headerLines.some(line => /^Received:/i.test(line));
          const hasAuthHeader = headerLines.some(line => /^(Authentication-Results|From|To|Subject|Date):/i.test(line));
          
          if (hasReceivedHeader || hasAuthHeader) {
            actualHeaders = headerLines.join('\n');
            actualContent = bodyLines.join('\n');
          }
        }
      }
      
      parsed = parseEmail(actualContent, actualHeaders);
    } catch (parseErr) {
      console.error('[Phishing] Parse error:', parseErr);
      throw parseErr;
    }
    
    console.log(`[Phishing] Parsed IOCs - IPs: ${parsed.ips?.length || 0}, Domains: ${parsed.domains?.length || 0}, URLs: ${parsed.urls?.length || 0}, Hashes: ${parsed.hashes?.length || 0}`);
    
    const uniqueIocs = buildUniqueIocs(parsed);
    console.log(`[Phishing] Unique IOCs to enrich: ${uniqueIocs.length}`);
    
    // Enrich IOCs in parallel (limit to 20 to avoid rate limiting)
    const iocsToEnrich = uniqueIocs.slice(0, 20);
    console.log(`[Phishing] Starting enrichment for ${iocsToEnrich.length} IOCs...`);
    
    const enrichmentPromises = iocsToEnrich.map(async (ioc) => {
      try {
        const result = await enrichIOC(ioc.value, ioc.type);
        console.log(`[Phishing] Enriched ${ioc.type}: ${ioc.value.substring(0, 30)}... -> VT:${result.sources?.virustotal ? 'yes' : 'no'}, AB:${result.sources?.abuseipdb ? 'yes' : 'no'}, score:${result.score}`);
        return result;
      } catch (err) {
        return { value: ioc.value, type: ioc.type, sources: {}, score: 0, verdict: 'unknown' };
      }
    });
    const enrichedIocs = await Promise.all(enrichmentPromises);
    
    // Deep attachment analysis
    const enrichedAttachments = await analyzeAttachments(parsed.attachments || []);
    
    // Calculate overall risk score
    const iocScore = enrichedIocs.reduce((sum, ioc) => sum + ioc.score, 0);
    const attachmentScore = enrichedAttachments.reduce((sum, att) => sum + att.riskScore, 0);
    const totalScore = iocScore + attachmentScore;
    const maxPossibleScore = (enrichedIocs.length * 100) + (enrichedAttachments.length * 100);
    let riskScore = maxPossibleScore > 0 ? Math.round((totalScore / maxPossibleScore) * 100) : 0;
    
    // Results object for content analysis
    const results = { contentWarnings: [] };
    
    // Determine threat level
    let threatLevel = 'LOW';
    let threatColor = 'green';
    if (riskScore >= 70) {
      threatLevel = 'CRITICAL';
      threatColor = 'red';
    } else if (riskScore >= 50) {
      threatLevel = 'HIGH';
      threatColor = 'orange';
    } else if (riskScore >= 25) {
      threatLevel = 'MEDIUM';
      threatColor = 'yellow';
    }
    
    // Attachment-specific threat level override
    const maliciousAttachments = enrichedAttachments.filter(a => a.verdict === 'malicious');
    const suspiciousAttachments = enrichedAttachments.filter(a => a.verdict === 'suspicious');
    if (maliciousAttachments.length > 0) {
      threatLevel = 'CRITICAL';
      threatColor = 'red';
    } else if (suspiciousAttachments.length > 0 && threatLevel !== 'CRITICAL') {
      threatLevel = 'HIGH';
      threatColor = 'orange';
    }
    
    // Typosquatting = CRITICAL
    const typosquattingIocs = enrichedIocs.filter(ioc => ioc.sources?.typosquatting?.detected);
    if (typosquattingIocs.length > 0) {
      threatLevel = 'CRITICAL';
      threatColor = 'red';
      riskScore = Math.max(riskScore, 85);
    }
    
    // Any malicious IOC = CRITICAL
    const maliciousIocs = enrichedIocs.filter(ioc => ioc.verdict === 'malicious');
    if (maliciousIocs.length > 0) {
      threatLevel = 'CRITICAL';
      threatColor = 'red';
      riskScore = Math.max(riskScore, 80);
    }
    
    // Suspicious IOCs = HIGH
    const suspiciousIocs = enrichedIocs.filter(ioc => ioc.verdict === 'suspicious');
    if (suspiciousIocs.length > 0 && threatLevel !== 'CRITICAL') {
      threatLevel = 'HIGH';
      threatColor = 'orange';
      riskScore = Math.max(riskScore, 50);
    }
    
    // Phishing indicators = HIGH minimum
    const phishingKeywords = parsed.body?.toLowerCase().match(/account.*locked|verify.*account|confirm.*identity|urgent.*action|suspended.*account/i);
    if (phishingKeywords && phishingKeywords.length > 0 && threatLevel !== 'CRITICAL') {
      threatLevel = 'HIGH';
      threatColor = 'orange';
      riskScore = Math.max(riskScore, 40);
    }
    
    // Detect URL shorteners (suspicious for phishing)
    const urlShorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly', 'adf.ly', 'bit.do', 'mcafee.com', 'lnkd.in', 'db.tt', 'qr.ae', 'adcruu', 'goo.gl', 'cli.gs', 'short.to', 'cutt.us'];
    const hasShortenedUrls = parsed.urls?.some(url => urlShorteners.some(s => url.toLowerCase().includes(s)));
    if (hasShortenedUrls && threatLevel !== 'CRITICAL') {
      threatLevel = 'HIGH';
      threatColor = 'orange';
      riskScore = Math.max(riskScore, 30);
    }
    
    // Detect credential harvesting indicators in body
    const credentialHarvesting = parsed.body?.toLowerCase().match(/enter.*password|confirm.*password|update.*payment|credit card|bank account|social security|ssn|login.*credentials|verify.*banking|sensitive.*information|personal.*data/i);
    if (credentialHarvesting && credentialHarvesting.length > 0) {
      riskScore = Math.max(riskScore, 25);
      results.contentWarnings = results.contentWarnings || [];
      results.contentWarnings.push('Credential harvesting content detected in email body');
    }
    
    // Sophisticated URL analysis for credential harvesting
    const urlHarvestingAnalysis = [];
    for (const url of parsed.urls || []) {
      const urlLower = url.toLowerCase();
      const urlIndicators = [];
      
      // Credential harvesting path patterns
      const harvestingPathPatterns = [
        { pattern: /\/login|\/signin|\/sign-in|\/account\/signin/gi, name: 'Login page' },
        { pattern: /\/password|\/reset|\/recover|\/forgot/i, name: 'Password recovery' },
        { pattern: /\/verify|\/confirm|\/validate/i, name: 'Verification page' },
        { pattern: /\/secure|\/security/i, name: 'Security page' },
        { pattern: /\/update|\/payment|\/billing|\/checkout/i, name: 'Payment page' },
        { pattern: /\/account|\/profile|\/settings|\/preferences/i, name: 'Account settings' },
        { pattern: /form|input|submit|token|session/i, name: 'Form submission' }
      ];
      
      for (const hp of harvestingPathPatterns) {
        if (hp.pattern.test(urlLower)) {
          urlIndicators.push(hp.name);
        }
      }
      
      // Suspicious URL patterns
      if (urlLower.includes('redirect=') || urlLower.includes('continue=') || urlLower.includes('return=')) {
        urlIndicators.push('Redirect parameter');
      }
      if (urlLower.includes('@')) {
        urlIndicators.push('Email-in-URL');
      }
      
      // Check for suspicious TLD + brand combination
      const suspiciousCombos = [
        { domains: ['amazon', 'paypal', 'microsoft', 'apple', 'google'], tlds: ['xyz', 'top', 'cn', 'ru', 'cc', 'pw', 'tk', 'ml'] },
        { domains: ['amazon'], tlds: ['xyz', 'top', 'cn', 'cc', 'pw'] }
      ];
      
      for (const combo of suspiciousCombos) {
        for (const brand of combo.domains) {
          if (urlLower.includes(brand)) {
            for (const tld of combo.tlds) {
              if (urlLower.endsWith('.' + tld) || urlLower.includes('.' + brand + '.' + tld)) {
                urlIndicators.push(`Brand + suspicious TLD (.${tld})`);
                break;
              }
            }
          }
        }
      }
      
      if (urlIndicators.length >= 2) {
        urlHarvestingAnalysis.push({
          url: url.length > 80 ? url.substring(0, 80) + '...' : url,
          indicators: urlIndicators
        });
        riskScore = Math.max(riskScore, 30);
        if (threatLevel === 'LOW') {
          threatLevel = 'HIGH';
          threatColor = 'orange';
        }
      }
    }
    
    if (urlHarvestingAnalysis.length > 0) {
      results.contentWarnings = results.contentWarnings || [];
      results.contentWarnings.push(`🚨 Credential harvesting URLs detected: ${urlHarvestingAnalysis.length} suspicious URL(s)`);
    }
    
    // Check authentication results
    const authIssues = [];
    if (parsed.authentication.spf && parsed.authentication.spf.includes('fail')) {
      authIssues.push('SPF check failed');
    }
    if (parsed.authentication.dkim === null) {
      // Only warn about missing DKIM if Authentication-Results didn't say anything
      // (DKIM is optional, so don't alarm if not mentioned)
      const authResultsHeader = parsed.headers?.['Authentication-Results'] || '';
      if (!authResultsHeader.toLowerCase().includes('dkim=')) {
        // Don't show warning if there's no DKIM mention - Outlook emails often don't include it
      }
    } else if (parsed.authentication.dkim === 'fail') {
      authIssues.push('DKIM check failed');
    }
    if (parsed.authentication.dmarc && parsed.authentication.dmarc.includes('fail')) {
      authIssues.push('DMARC check failed');
    }
    if (parsed.authentication.replyTo && parsed.authentication.replyTo !== parsed.headers['From']) {
      authIssues.push('Reply-To mismatch');
    }
    
    // Check for brand impersonation via sender domain
    const fromHeader = parsed.headers?.From || '';
    const senderDomainMatch = fromHeader.match(/@([^>\s]+)/i);
    if (senderDomainMatch) {
      const senderDomain = senderDomainMatch[1].toLowerCase();
      const typoCheck = detectTyposquatting(senderDomain);
      if (typoCheck.isTyposquatting) {
        authIssues.push(`Sender domain impersonates ${typoCheck.brand}`);
        if (threatLevel !== 'CRITICAL') {
          threatLevel = 'HIGH';
          threatColor = 'orange';
          riskScore = Math.max(riskScore, 60);
        }
      }
      
      const suspiciousSender = detectSuspiciousSenderDomain(senderDomain, fromHeader);
      if (suspiciousSender.suspicious) {
        riskScore = Math.max(riskScore, suspiciousSender.riskIncrease);
        if (suspiciousSender.riskIncrease >= 50 || suspiciousSender.riskIncrease >= 40) {
          threatLevel = 'CRITICAL';
          threatColor = 'red';
        } else if (threatLevel !== 'CRITICAL') {
          threatLevel = 'HIGH';
          threatColor = 'orange';
        }
      }
    }
    
    const displayNameImpersonation = detectDisplayNameImpersonation(fromHeader);
    if (displayNameImpersonation.detected) {
      authIssues.push(`Display name impersonation: ${displayNameImpersonation.description}`);
      riskScore = Math.max(riskScore, 50);
      threatLevel = 'CRITICAL';
      threatColor = 'red';
    }
    
    const replyToMismatch = detectReplyToMismatch(
      fromHeader,
      parsed.authentication.replyTo,
      parsed.authentication.returnPath
    );
    if (replyToMismatch.mismatch) {
      authIssues.push(replyToMismatch.description);
      riskScore = Math.max(riskScore, replyToMismatch.highRisk ? 60 : 25);
      if (replyToMismatch.highRisk || threatLevel !== 'CRITICAL') {
        threatLevel = 'HIGH';
        threatColor = 'orange';
      }
    }
    
    const qrCodeDetection = detectQRCodeInContent(parsed.body);
    if (qrCodeDetection.length > 0) {
      results.contentWarnings = results.contentWarnings || [];
      for (const qr of qrCodeDetection) {
        results.contentWarnings.push(qr.note || `URL shortener detected: ${qr.shortener}`);
      }
      riskScore = Math.max(riskScore, 20);
    }
    
    const embeddedForms = detectEmbeddedForms(parsed.body);
    if (embeddedForms.detected) {
      results.contentWarnings = results.contentWarnings || [];
      for (const form of embeddedForms.forms) {
        const riskLevel = form.risk === 'HIGH' ? '🚨' : '⚠️';
        results.contentWarnings.push(`${riskLevel} Embedded form with ${form.field} field(s) detected${form.suspiciousAction ? ' - submits to suspicious URL' : ''}`);
      }
      riskScore = Math.max(riskScore, 35);
      if (threatLevel !== 'CRITICAL') {
        threatLevel = 'HIGH';
        threatColor = 'orange';
      }
    }
    
    const calendarInvite = detectCalendarInvite(parsed.body, emailHeaders);
    if (calendarInvite.detected) {
      results.contentWarnings = results.contentWarnings || [];
      if (calendarInvite.details.suspicious) {
        results.contentWarnings.push(`⚠️ Suspicious calendar invite: ${calendarInvite.details.suspiciousReason}`);
        riskScore = Math.max(riskScore, 30);
      } else {
        results.contentWarnings.push(`📅 Calendar invite detected (${calendarInvite.type})`);
      }
    }
    
    // Check for suspicious email subject patterns
    const subject = parsed.headers?.Subject || '';
    const suspiciousSubjectPatterns = [
      { pattern: /urgent\s*action\s*required/i, message: 'Urgent action required' },
      { pattern: /your\s*account\s*will\s*be\s*(?:suspended|locked|closed)/i, message: 'Account suspension threat' },
      { pattern: /verify\s*your\s*(?:account|identity|information)/i, message: 'Verification request' },
      { pattern: /security\s*alert/i, message: 'Security alert' },
      { pattern: /password\s*(?:reset|change|expired)/i, message: 'Password reset' }
    ];
    for (const { pattern, message } of suspiciousSubjectPatterns) {
      if (pattern.test(subject)) {
        authIssues.push(`Suspicious subject: ${message}`);
        riskScore = Math.max(riskScore, 20);
        break;
      }
    }
    
    // Prepare analysis result
    const result = {
      id: analysisId,
      timestamp: new Date().toISOString(),
      title: title || 'Email Analysis',
      stats: {
        totalIocs: uniqueIocs.length,
        ipsFound: parsed.ips.length,
        domainsFound: parsed.domains.length,
        urlsFound: parsed.urls.length,
        hashesFound: parsed.hashes.length,
        enrichedCount: enrichedIocs.length,
        riskScore,
        threatLevel,
        threatColor,
        analysisTimeMs: Date.now() - startTime
      },
      authentication: parsed.authentication,
      authIssues,
      phishingKeywords: phishingKeywords || [],
      contentWarnings: results.contentWarnings || [],
      headers: parsed.headers,
      iocs: enrichedIocs,
      suspicious: enrichedIocs.filter(i => i.verdict === 'suspicious').length,
      malicious: enrichedIocs.filter(i => i.verdict === 'malicious').length,
      clean: enrichedIocs.filter(i => i.verdict === 'clean').length,
      summary: generateSummary(parsed, enrichedIocs, authIssues),
      decodedContent: parsed.decodedContent || [],
      attachments: parsed.attachments || [],
      bodyPreview: (parsed.body || '').slice(0, 6000),
      intel: getIntelConfigStatus(),
      emailAnalysis: {
        displayNameImpersonation,
        replyToMismatch,
        qrCodeDetection,
        senderDomainAnalysis: senderDomainMatch ? detectSuspiciousSenderDomain(senderDomainMatch[1].toLowerCase(), fromHeader) : null,
        embeddedForms,
        calendarInvite
      }
    };
    result.triage = await generateAiTriage(result);
    
    // Store in history (in production, use database)
    analysisHistory.set(analysisId, result);
    
    // Keep only last 100 analyses
    if (analysisHistory.size > 100) {
      const firstKey = analysisHistory.keys().next().value;
      analysisHistory.delete(firstKey);
    }
    
    res.json(result);
    
  } catch (error) {
    console.error('[Phishing] Analysis error:', error.message);
    res.status(500).json({ 
      error: 'Analysis failed', 
      message: error.message,
      id: analysisId 
    });
  }
});

// Helper to generate summary
function generateSummary(parsed, iocs, authIssues, attachments = []) {
  const lines = [];
  
  if (authIssues.length > 0) {
    lines.push(`⚠️ Authentication issues: ${authIssues.join(', ')}`);
  }
  
  const maliciousIocs = iocs.filter(i => i.verdict === 'malicious');
  if (maliciousIocs.length > 0) {
    lines.push(`🔴 Found ${maliciousIocs.length} malicious IOCs`);
  }
  
  const suspiciousIocs = iocs.filter(i => i.verdict === 'suspicious');
  if (suspiciousIocs.length > 0) {
    lines.push(`🟡 Found ${suspiciousIocs.length} suspicious IOCs`);
  }
  
  // Typosquatting summary
  const typosquattingIocs = iocs.filter(i => i.tags?.includes('typosquatting-detected'));
  if (typosquattingIocs.length > 0) {
    const brands = typosquattingIocs.map(i => i.sources?.typosquatting?.brand).filter(Boolean);
    lines.push(`🚨 Typosquatting: ${brands.join(', ')} impersonation detected`);
  }
  
  // New domain summary
  const newDomainIocs = iocs.filter(i => i.tags?.includes('new-domain'));
  if (newDomainIocs.length > 0) {
    lines.push(`⏰ ${newDomainIocs.length} newly registered domain(s)`);
  }
  
  if (parsed.urls.length > 0) {
    lines.push(`🔗 Contains ${parsed.urls.length} URLs`);
  }
  
  if (parsed.hashes.length > 0) {
    lines.push(`🔑 Contains ${parsed.hashes.length} file hashes`);
  }
  
  // Attachment analysis summary
  if (attachments.length > 0) {
    const maliciousAttachments = attachments.filter(a => a.verdict === 'malicious');
    const suspiciousAttachments = attachments.filter(a => a.verdict === 'suspicious');
    
    if (maliciousAttachments.length > 0) {
      lines.push(`⚠️ ${maliciousAttachments.length} MALICIOUS attachment(s) detected`);
    }
    if (suspiciousAttachments.length > 0) {
      lines.push(`⚠️ ${suspiciousAttachments.length} suspicious attachment(s) detected`);
    }
    
    const executableTypes = attachments.filter(a => 
      ['exe/dll', 'ole', 'scr', 'elf', 'macho'].includes(a.fileType) || 
      a.warnings?.some(w => w.includes('Executable') || w.includes('script'))
    );
    if (executableTypes.length > 0) {
      lines.push(`⚠️ ${executableTypes.length} executable/script attachment(s) detected`);
    }
  }
  
  return lines.join(' · ');
}

// GET /api/phishing/analysis/:id - Get specific analysis
router.get('/analysis/:id', (req, res) => {
  const analysis = analysisHistory.get(req.params.id);
  
  if (!analysis) {
    return res.status(404).json({ error: 'Analysis not found' });
  }
  
  res.json(analysis);
});

// GET /api/phishing/history - Get recent analyses
router.get('/history', (req, res) => {
  const limit = parseInt(req.query.limit) || 20;
  const analyses = Array.from(analysisHistory.values())
    .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
    .slice(0, limit)
    .map(a => ({
      id: a.id,
      timestamp: a.timestamp,
      title: a.title,
      threatLevel: a.stats.threatLevel,
      riskScore: a.stats.riskScore,
      iocCount: a.stats.totalIocs
    }));
  
  res.json({
    total: analysisHistory.size,
    analyses
  });
});

// GET /api/phishing/stats - Get phishing analysis statistics
router.get('/stats', (req, res) => {
  const analyses = Array.from(analysisHistory.values());
  
  const stats = {
    total: analyses.length,
    critical: analyses.filter(a => a.stats.threatLevel === 'CRITICAL').length,
    high: analyses.filter(a => a.stats.threatLevel === 'HIGH').length,
    medium: analyses.filter(a => a.stats.threatLevel === 'MEDIUM').length,
    low: analyses.filter(a => a.stats.threatLevel === 'LOW').length,
    totalIocs: analyses.reduce((sum, a) => sum + a.stats.totalIocs, 0),
    maliciousIocs: analyses.reduce((sum, a) => sum + a.malicious, 0)
  };
  
  res.json(stats);
});
// Add multer for file upload handling
const multer = require('multer');
const upload = multer({ 
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 } // 10MB limit
});

// POST /api/phishing/analyze/upload - Upload and analyze email file
router.post('/analyze/upload', upload.single('file'), async (req, res) => {
  const { title } = req.body;
  const file = req.file;
  
  if (!file) {
    return res.status(400).json({ error: 'No file uploaded' });
  }
  
  const analysisId = uuidv4();
  const startTime = Date.now();
  
  try {
    console.log(`[Phishing] Analyzing uploaded file #${analysisId}: ${file.originalname}`);
    
    let emailContent = '';
    let emailHeaders = '';
    
    // Parse based on file type
    if (file.originalname.endsWith('.eml') || file.originalname.endsWith('.txt')) {
      const content = file.buffer.toString('utf-8');
      
      // Try to separate headers from body
      const parts = content.split('\n\n');
      if (parts.length >= 2) {
        emailHeaders = parts[0];
        emailContent = parts.slice(1).join('\n\n');
      } else {
        emailContent = content;
      }
    } else if (file.originalname.endsWith('.msg')) {
      // For .msg files, we'd need a library like 'msg-parser' or 'node-outlook'
      // For now, return a message about limited support
      return res.status(400).json({ 
        error: 'MSG file parsing requires additional library',
        message: 'Please export the email as .eml format for full analysis'
      });
    }
    
    // Parse the email
    const parsed = parseEmail(emailContent, emailHeaders);
    
    const uniqueIocs = buildUniqueIocs(parsed);
    
    // Enrich IOCs in parallel
    const iocsToEnrich = uniqueIocs.slice(0, 20);
    const enrichmentPromises = iocsToEnrich.map(ioc => enrichIOC(ioc.value, ioc.type));
    const enrichedIocs = await Promise.all(enrichmentPromises);
    
    // Deep attachment analysis
    const enrichedAttachments = await analyzeAttachments(parsed.attachments || []);
    
    // Calculate risk score
    const iocScore = enrichedIocs.reduce((sum, ioc) => sum + ioc.score, 0);
    const attachmentScore = enrichedAttachments.reduce((sum, att) => sum + att.riskScore, 0);
    const totalScore = iocScore + attachmentScore;
    const maxPossibleScore = (enrichedIocs.length * 100) + (enrichedAttachments.length * 100);
    const riskScore = maxPossibleScore > 0 ? Math.round((totalScore / maxPossibleScore) * 100) : 0;
    
    // Determine threat level
    let threatLevel = 'LOW';
    let threatColor = 'green';
    if (riskScore >= 70) {
      threatLevel = 'CRITICAL';
      threatColor = 'red';
    } else if (riskScore >= 50) {
      threatLevel = 'HIGH';
      threatColor = 'orange';
    } else if (riskScore >= 25) {
      threatLevel = 'MEDIUM';
      threatColor = 'yellow';
    }
    
    // Attachment-specific threat level override
    const maliciousAttachments = enrichedAttachments.filter(a => a.verdict === 'malicious');
    const suspiciousAttachments = enrichedAttachments.filter(a => a.verdict === 'suspicious');
    if (maliciousAttachments.length > 0) {
      threatLevel = 'CRITICAL';
      threatColor = 'red';
    } else if (suspiciousAttachments.length > 0 && threatLevel !== 'CRITICAL') {
      threatLevel = 'HIGH';
      threatColor = 'orange';
    }
    
    // Typosquatting = CRITICAL
    const typosquattingIocsUpload = enrichedIocs.filter(ioc => ioc.sources?.typosquatting?.detected);
    if (typosquattingIocsUpload.length > 0) {
      threatLevel = 'CRITICAL';
      threatColor = 'red';
      riskScore = Math.max(riskScore, 85);
    }
    
    // Any malicious IOC = CRITICAL
    const maliciousIocsUpload = enrichedIocs.filter(ioc => ioc.verdict === 'malicious');
    if (maliciousIocsUpload.length > 0) {
      threatLevel = 'CRITICAL';
      threatColor = 'red';
      riskScore = Math.max(riskScore, 80);
    }
    
    // Suspicious IOCs = HIGH
    const suspiciousIocsUpload = enrichedIocs.filter(ioc => ioc.verdict === 'suspicious');
    if (suspiciousIocsUpload.length > 0 && threatLevel !== 'CRITICAL') {
      threatLevel = 'HIGH';
      threatColor = 'orange';
      riskScore = Math.max(riskScore, 50);
    }
    
    // Phishing indicators = HIGH minimum
    const phishingKeywordsUpload = parsed.body?.toLowerCase().match(/account.*locked|verify.*account|confirm.*identity|urgent.*action|suspended.*account/i);
    if (phishingKeywordsUpload && phishingKeywordsUpload.length > 0 && threatLevel !== 'CRITICAL') {
      threatLevel = 'HIGH';
      threatColor = 'orange';
      riskScore = Math.max(riskScore, 40);
    }
    
    // Check authentication
    const authIssues = [];
    if (parsed.authentication.spf && parsed.authentication.spf.includes('fail')) {
      authIssues.push('SPF check failed');
    }
    if (parsed.authentication.dkim === null) {
      authIssues.push('DKIM signature missing');
    }
    if (parsed.authentication.dmarc && parsed.authentication.dmarc.includes('fail')) {
      authIssues.push('DMARC check failed');
    }
    if (parsed.authentication.replyTo && parsed.authentication.replyTo !== parsed.headers['From']) {
      authIssues.push('Reply-To mismatch');
    }
    
    const result = {
      id: analysisId,
      timestamp: new Date().toISOString(),
      filename: file.originalname,
      filesize: file.size,
      title: title || file.originalname,
      stats: {
        totalIocs: uniqueIocs.length,
        ipsFound: parsed.ips.length,
        domainsFound: parsed.domains.length,
        urlsFound: parsed.urls.length,
        hashesFound: parsed.hashes.length,
        enrichedCount: enrichedIocs.length,
        riskScore,
        threatLevel,
        threatColor,
        analysisTimeMs: Date.now() - startTime
      },
      authentication: parsed.authentication,
      authIssues,
      phishingKeywords: phishingKeywordsUpload || [],
      headers: parsed.headers,
      iocs: enrichedIocs,
      suspicious: enrichedIocs.filter(i => i.verdict === 'suspicious').length,
      malicious: enrichedIocs.filter(i => i.verdict === 'malicious').length,
      clean: enrichedIocs.filter(i => i.verdict === 'clean').length,
      summary: generateSummary(parsed, enrichedIocs, authIssues, enrichedAttachments),
      decodedContent: parsed.decodedContent || [],
      attachments: enrichedAttachments,
      attachmentStats: {
        total: enrichedAttachments.length,
        malicious: maliciousAttachments.length,
        suspicious: suspiciousAttachments.length,
        clean: enrichedAttachments.filter(a => a.verdict === 'clean').length,
        unknown: enrichedAttachments.filter(a => a.verdict === 'unknown').length
      },
      bodyPreview: (parsed.body || '').slice(0, 6000),
      intel: getIntelConfigStatus()
    };
    result.triage = await generateAiTriage(result);
    
    // Store in history
    analysisHistory.set(analysisId, result);
    
    // Keep only last 100
    if (analysisHistory.size > 100) {
      const firstKey = analysisHistory.keys().next().value;
      analysisHistory.delete(firstKey);
    }
    
    res.json(result);
    
  } catch (error) {
    console.error('[Phishing] File analysis error:', error.message);
    res.status(500).json({ 
      error: 'Analysis failed', 
      message: error.message,
      id: analysisId 
    });
  }
});

// POST /api/phishing/analysis/:id/triage - regenerate triage for existing result
router.post('/analysis/:id/triage', async (req, res) => {
  const analysis = analysisHistory.get(req.params.id);
  if (!analysis) {
    return res.status(404).json({ error: 'Analysis not found' });
  }
  analysis.triage = await generateAiTriage(analysis);
  analysisHistory.set(req.params.id, analysis);
  return res.json({ id: analysis.id, triage: analysis.triage });
});

// POST /api/phishing/mail-events - ingest mail events from gateway/webhook
router.post('/mail-events', async (req, res) => {
  const body = req.body || {};
  const events = Array.isArray(body.events) ? body.events : [body];
  if (!events.length) {
    return res.status(400).json({ error: 'No events provided' });
  }

  const output = [];
  for (const event of events.slice(0, 50)) {
    if (!event || (!event.body && !event.content && !event.headers)) continue;
    try {
      const processed = await processMailEvent(event);
      if (processed) {
        output.push({
          analysisId: processed.analysis.id,
          detectionId: processed.detection.id,
          shouldAlert: processed.detection.shouldAlert,
          severity: processed.detection.severity,
          riskScore: processed.detection.riskScore
        });
      }
    } catch (err) {
      output.push({ error: err.message, subject: event.subject || null });
    }
  }

  res.json({
    received: events.length,
    processed: output.length,
    detections: output
  });
});

// POST /api/phishing/auto/poll-now - manually trigger mailbox scan
router.post('/auto/poll-now', async (req, res) => {
  await pollMailboxForPhishing();
  res.json({
    status: 'ok',
    autoState
  });
});

// GET /api/phishing/auto/status - current automatic detection status
router.get('/auto/status', (req, res) => {
  res.json({
    autoState,
    detections: autoDetections.size,
    analyses: analysisHistory.size
  });
});

// GET /api/phishing/auto/alerts - recent automatic phishing alerts
router.get('/auto/alerts', (req, res) => {
  const limit = Math.min(parseInt(req.query.limit, 10) || 50, 200);
  const alerts = Array.from(autoDetections.values())
    .filter(d => d.shouldAlert)
    .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
    .slice(0, limit);
  res.json({
    total: alerts.length,
    alerts
  });
});

// GET /api/phishing/incidents - list incident records
router.get('/incidents', (req, res) => {
  const limit = Math.min(parseInt(req.query.limit, 10) || 100, 500);
  const incidents = Array.from(incidentRecords.values())
    .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))
    .slice(0, limit);
  res.json({ total: incidents.length, incidents });
});

// GET /api/phishing/incidents/:id - incident details
router.get('/incidents/:id', (req, res) => {
  const incident = incidentRecords.get(req.params.id);
  if (!incident) return res.status(404).json({ error: 'Incident not found' });
  const responseAction = incident.responseActionId ? responseActions.get(incident.responseActionId) : null;
  res.json({ incident, responseAction });
});

// GET /api/phishing/response-actions - list response actions
router.get('/response-actions', (req, res) => {
  const limit = Math.min(parseInt(req.query.limit, 10) || 100, 500);
  const actions = Array.from(responseActions.values())
    .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
    .slice(0, limit);
  res.json({ total: actions.length, actions });
});

// GET /api/phishing/blocked - currently blocked indicators
router.get('/blocked', (req, res) => {
  const indicators = Array.from(blockedIndicators.values())
    .sort((a, b) => new Date(b.blockedAt) - new Date(a.blockedAt));
  res.json({ total: indicators.length, indicators });
});

// GET /api/phishing/report/:id - report in JSON, Markdown, or CSV
router.get('/report/:id', (req, res) => {
  const analysis = analysisHistory.get(req.params.id);
  if (!analysis) {
    return res.status(404).json({ error: 'Analysis not found' });
  }

  const format = String(req.query.format || 'json').toLowerCase();
  if (format === 'md' || format === 'markdown') {
    const markdown = buildReportMarkdown(analysis);
    res.setHeader('Content-Type', 'text/markdown; charset=utf-8');
    return res.send(markdown);
  }

  if (format === 'csv') {
    const csv = buildReportCSV(analysis);
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="phishing-report-${analysis.id}.csv"`);
    return res.send(csv);
  }

  return res.json({
    reportVersion: '1.0',
    generatedAt: new Date().toISOString(),
    analysisId: analysis.id,
    title: analysis.title,
    summary: analysis.summary,
    stats: analysis.stats,
    authentication: analysis.authentication,
    authIssues: analysis.authIssues,
    triage: analysis.triage || buildDeterministicTriage(analysis),
    iocs: analysis.iocs
  });
});

function buildReportCSV(analysis) {
  const lines = [];
  
  lines.push('ThreatForge Phishing Analysis Report');
  lines.push('');
  lines.push('Metadata');
  lines.push(`Analysis ID,${analysis.id}`);
  lines.push(`Title,${escapeCsv(analysis.title || 'N/A')}`);
  lines.push(`Timestamp,${analysis.timestamp}`);
  lines.push(`Risk Score,${analysis.stats?.riskScore || 0}%`);
  lines.push(`Threat Level,${analysis.stats?.threatLevel || 'LOW'}`);
  lines.push(`Classification,${analysis.triage?.classification || 'unknown'}`);
  lines.push(`Severity,${analysis.triage?.severity || 'unknown'}`);
  lines.push(`Confidence,${analysis.triage?.confidence || 0}%`);
  lines.push('');
  
  lines.push('Authentication Results');
  lines.push(`SPF,${analysis.authentication?.spf || 'Not found'}`);
  lines.push(`DKIM,${analysis.authentication?.dkim || 'Not found'}`);
  lines.push(`DMARC,${analysis.authentication?.dmarc || 'Not found'}`);
  lines.push(`Reply-To,${escapeCsv(analysis.authentication?.replyTo || 'N/A')}`);
  lines.push(`Return-Path,${escapeCsv(analysis.authentication?.returnPath || 'N/A')}`);
  lines.push('');
  
  lines.push('Authentication Issues');
  if ((analysis.authIssues || []).length > 0) {
    analysis.authIssues.forEach(issue => {
      lines.push(`Issue,${escapeCsv(issue)}`);
    });
  } else {
    lines.push('No authentication issues');
  }
  lines.push('');
  
  lines.push('Email Analysis Findings');
  if (analysis.emailAnalysis?.displayNameImpersonation?.detected) {
    lines.push(`Display Name Impersonation,${escapeCsv(analysis.emailAnalysis.displayNameImpersonation.description)}`);
  }
  if (analysis.emailAnalysis?.replyToMismatch?.mismatch) {
    lines.push(`Reply-To Mismatch,${escapeCsv(analysis.emailAnalysis.replyToMismatch.description)}`);
  }
  if ((analysis.emailAnalysis?.qrCodeDetection?.length || 0) > 0) {
    lines.push(`QR Code/URL Shortener,Detected`);
  }
  if (analysis.emailAnalysis?.senderDomainAnalysis?.suspicious) {
    lines.push(`Suspicious Sender,${escapeCsv(analysis.emailAnalysis.senderDomainAnalysis.reason)}`);
  }
  if (analysis.emailAnalysis?.embeddedForms?.detected) {
    analysis.emailAnalysis.embeddedForms.forms.forEach(f => {
      lines.push(`Embedded Form,${f.count}x ${f.field} field${f.suspiciousAction ? ' - suspicious' : ''}`);
    });
  }
  if (analysis.emailAnalysis?.calendarInvite?.detected) {
    lines.push(`Calendar Invite,${analysis.emailAnalysis.calendarInvite.type || 'Unknown'}`);
    if (analysis.emailAnalysis.calendarInvite.details?.suspicious) {
      lines.push(`Calendar Invite Warning,${escapeCsv(analysis.emailAnalysis.calendarInvite.details.suspiciousReason)}`);
    }
  }
  if (!analysis.emailAnalysis?.displayNameImpersonation?.detected && 
      !analysis.emailAnalysis?.replyToMismatch?.mismatch && 
      (analysis.emailAnalysis?.qrCodeDetection?.length || 0) === 0 && 
      !analysis.emailAnalysis?.senderDomainAnalysis?.suspicious &&
      !analysis.emailAnalysis?.embeddedForms?.detected &&
      !analysis.emailAnalysis?.calendarInvite?.detected) {
    lines.push('No special email analysis findings');
  }
  lines.push('');
  
  lines.push('IOCs');
  lines.push('Type,Value,Verdict,Score,Tags,VirusTotal,AbuseIPDB,MalwareBazaar,ThreatFox,Notes');
  (analysis.iocs || []).forEach(ioc => {
    const vt = ioc.sources?.virustotal ? `${ioc.sources.virustotal.positives}/${ioc.sources.virustotal.total}` : 'N/A';
    const abuse = ioc.sources?.abuseipdb ? `${ioc.sources.abuseipdb.abuseScore}/100` : 'N/A';
    const mb = ioc.sources?.malwarebazaar ? 'Found' : 'N/A';
    const tf = ioc.sources?.threatfox ? 'Found' : 'N/A';
    const notes = [
      ioc.sources?.typosquatting?.detected ? `Typosquatting: ${ioc.sources.typosquatting.brand}` : '',
      ioc.sources?.homograph ? 'Homograph Attack' : '',
      ioc.sources?.domainAge?.isNew ? `New Domain: ${ioc.sources.domainAge.daysOld} days` : '',
      ioc.tags?.includes('high-risk-tld') ? 'High-risk TLD' : ''
    ].filter(Boolean).join('; ');
    lines.push(`${ioc.type},${escapeCsv(ioc.value)},${ioc.verdict},${ioc.score},${escapeCsv((ioc.tags || []).join('; '))},${vt},${abuse},${mb},${tf},${escapeCsv(notes)}`);
  });
  lines.push('');
  
  lines.push('IOC Summary');
  lines.push(`Total IOCs,${analysis.stats?.totalIocs || 0}`);
  lines.push(`Malicious,${analysis.malicious || 0}`);
  lines.push(`Suspicious,${analysis.suspicious || 0}`);
  lines.push(`Clean,${analysis.clean || 0}`);
  lines.push('');
  
  lines.push('MITRE ATT&CK Mapping');
  if ((analysis.triage?.mitreMapping || []).length > 0) {
    analysis.triage.mitreMapping.forEach(t => {
      lines.push(`${t.id},${escapeCsv(t.name)}`);
    });
  } else {
    lines.push('No MITRE techniques identified');
  }
  lines.push('');
  
  lines.push('Recommended Actions');
  if ((analysis.triage?.recommendedActions || []).length > 0) {
    analysis.triage.recommendedActions.forEach((action, idx) => {
      lines.push(`${idx + 1},${escapeCsv(action)}`);
    });
  } else {
    lines.push('No recommendations');
  }
  
  return lines.join('\n');
}

function escapeCsv(str) {
  if (!str) return '';
  const escaped = String(str).replace(/"/g, '""');
  return escaped.includes(',') || escaped.includes('"') || escaped.includes('\n') ? `"${escaped}"` : escaped;
}
// Base64 detection and decoding helper
function detectAndDecodeBase64(text) {
  const results = {
    decoded: [],
    attachments: [],
    urls: [],
    ips: [],
    hashes: []
  };
  
  // Base64 patterns
  const base64Patterns = [
    // Standard base64 (long enough only)
    /\b(?:[A-Za-z0-9+/]{4}){12,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?\b/g,
    // Base64 in email attachments
    /Content-Transfer-Encoding: base64[\s\S]*?([A-Za-z0-9+\/\s=]{100,})/gi,
    // Base64 in data URLs
    /data:[^;]+;base64,([A-Za-z0-9+\/=]+)/g
  ];
  
  for (const pattern of base64Patterns) {
    const matches = text.matchAll(pattern);
    for (const match of matches) {
      const base64Str = match[1] || match[0];
      // Clean the string (remove whitespace, newlines)
      const cleanBase64 = base64Str.replace(/\s/g, '');
      
      // Check if it's valid base64 (length multiple of 4, valid chars)
      if (cleanBase64.length % 4 === 0 && /^[A-Za-z0-9+/=]+$/.test(cleanBase64)) {
        try {
          // Decode base64 to text
          const decoded = Buffer.from(cleanBase64, 'base64').toString('utf-8');
          
          // Only add if it contains readable text (allow HTML / punctuation)
          if (decoded.length > 12 && /[\x20-\x7E\u00A0-\u024F]{16,}/.test(decoded)) {
            results.decoded.push({
              original: cleanBase64.substring(0, 100) + '...',
              decoded: decoded.substring(0, 500),
              length: decoded.length
            });
            
            // Recursively scan decoded content for IOCs
            const nestedIocs = extractIOCsFromText(decoded);
            results.urls.push(...nestedIocs.urls);
            results.ips.push(...nestedIocs.ips);
            results.hashes.push(...nestedIocs.hashes);
          }
        } catch (e) {
          // Not valid UTF-8, might be binary (attachment)
          if (cleanBase64.length > 200) {
            // Calculate entropy to detect if it's likely an attachment
            const entropy = calculateEntropy(cleanBase64);
            if (entropy > 5.5) { // High entropy = likely compressed/encrypted/binary
              results.attachments.push({
                type: 'binary',
                size: Math.round(cleanBase64.length * 0.75), // Approximate decoded size
                hash: crypto.createHash('sha256').update(cleanBase64).digest('hex').substring(0, 16) + '...'
              });
            }
          }
        }
      }
    }
  }
  
  return results;
}

// Calculate entropy of a string (to detect binary vs text)
function calculateEntropy(str) {
  const freq = {};
  for (const char of str) {
    freq[char] = (freq[char] || 0) + 1;
  }
  
  let entropy = 0;
  const len = str.length;
  for (const char in freq) {
    const p = freq[char] / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

// Detect file type from magic bytes
function detectFileType(buffer) {
  if (!buffer || buffer.length < 4) return 'unknown';
  
  const bytes = buffer;
  
  if (bytes[0] === 0x4D && bytes[1] === 0x5A) return 'exe/dll'; // PE executable
  if (bytes[0] === 0x7F && bytes[1] === 0x45 && bytes[2] === 0x4C && bytes[3] === 0x46) return 'elf'; // Linux executable
  if (bytes[0] === 0xFE && bytes[1] === 0xED && bytes[2] === 0xFA && bytes[3] === 0xCE) return 'macho'; // macOS
  if (bytes[0] === 0x7F && bytes[1] === 0x45 && bytes[2] === 0x4C && bytes[3] === 0x46) return 'elf';
  if (bytes[0] === 0x50 && bytes[1] === 0x4B) return 'zip/office'; // ZIP-based (docx, xlsx, zip, jar)
  if (bytes[0] === 0xD0 && bytes[1] === 0xCF && bytes[2] === 0x11 && bytes[3] === 0xE0) return 'ole'; // OLE (doc, xls, ppt)
  if (bytes[0] === 0x25 && bytes[1] === 0x50 && bytes[2] === 0x44 && bytes[3] === 0x46) return 'pdf';
  if (bytes[0] === 0x52 && bytes[1] === 0x61 && bytes[2] === 0x72 && bytes[3] === 0x21) return 'rar';
  if (bytes[0] === 0x1F && bytes[1] === 0x8B) return 'gz/tar.gz';
  if (bytes[0] === 0x42 && bytes[1] === 0x4D) return 'bmp';
  if (bytes[0] === 0x47 && bytes[1] === 0x49 && bytes[2] === 0x46) return 'gif';
  if (bytes[0] === 0xFF && bytes[1] === 0xD8 && bytes[2] === 0xFF) return 'jpg';
  if (bytes[0] === 0x89 && bytes[1] === 0x50 && bytes[2] === 0x4E && bytes[3] === 0x47) return 'png';
  if (bytes[0] === 0x49 && bytes[1] === 0x44 && bytes[2] === 0x33) return 'mp3';
  if (bytes[0] === 0x66 && bytes[1] === 0x4C && bytes[2] === 0x61 && bytes[3] === 0x43) return 'flac';
  if (bytes[0] === 0x52 && bytes[1] === 0x49 && bytes[2] === 0x46 && bytes[3] === 0x46) return 'rif'; // RIFF (wav, avi)
  if (bytes[0] === 0x00 && bytes[1] === 0x00 && bytes[2] === 0x01 && bytes[3] === 0x00) return 'ico';
  if (bytes[0] === 0x4F && bytes[1] === 0x62 && bytes[2] === 0x6A && bytes[3] === 0x65) return 'rtf';
  if (bytes[0] === 0x3C && bytes[1] === 0x3F && bytes[2] === 0x78 && bytes[3] === 0x6D) return 'xml/html';
  if (bytes[0] === 0x3C && bytes[1] === 0x48 && bytes[2] === 0x54 && bytes[3] === 0x4D) return 'html';
  if (bytes[0] === 0x3C && bytes[1] === 0x21) return 'html';
  if (bytes[0] === 0x53 && bytes[1] === 0x63 && bytes[2] === 0x72 && bytes[3] === 0x69) return 'scr'; // Scream (scr)
  if (bytes[0] === 0x4D && bytes[1] === 0x53 && bytes[2] === 0x43 && bytes[3] === 0x46) return 'mscf'; // Cabinet
  if (bytes[0] === 0x5A && bytes[1] === 0x77 && bytes[2] === 0x53 && bytes[3] === 0x50) return 'msix';
  if (bytes[0] === 0xEF && bytes[1] === 0xBB && bytes[2] === 0xBF) {
    const nextBytes = buffer.slice(3, 6);
    if (nextBytes[0] === 0x3C && nextBytes[1] === 0x3F) return 'utf8-xml/html';
  }
  
  const entropy = calculateEntropy(buffer.slice(0, Math.min(256, buffer.length)).toString('binary'));
  if (entropy < 4) return 'text';
  
  return 'binary';
}

// Analyze a single attachment with threat intelligence enrichment
async function analyzeAttachment(attachment, vtApiKey) {
  const analysis = {
    hash: attachment.hash,
    size: attachment.size,
    fileType: attachment.fileType,
    name: attachment.name || 'unnamed',
    verdict: 'unknown',
    vtResults: null,
    malwareBazaarResults: null,
    riskScore: 0,
    tags: [],
    isSuspicious: false,
    warnings: []
  };
  
  if (!attachment.hash) return analysis;
  
  const vtKey = vtApiKey || process.env.VT_API_KEY;
  
  // Check VirusTotal
  if (vtKey && !vtKey.startsWith('your-')) {
    try {
      const vtRes = await fetch(`https://www.virustotal.com/api/v3/files/${attachment.hash}`, {
        headers: { 'x-apikey': vtKey },
        signal: AbortSignal.timeout(8000)
      });
      
      if (vtRes.ok) {
        const vtData = await vtRes.json();
        const stats = vtData.data?.attributes?.last_analysis_stats || {};
        const malicious = stats.malicious || 0;
        const suspicious = stats.suspicious || 0;
        const total = Object.values(stats).reduce((a, b) => a + b, 0);
        
        analysis.vtResults = {
          positives: malicious,
          total: total,
          sha256: vtData.data?.id,
          names: vtData.data?.attributes?.names?.slice(0, 5) || [],
          firstSubmitted: vtData.data?.attributes?.first_submission_date,
          lastSubmitted: vtData.data?.attributes?.last_submission_date,
          typeDescription: vtData.data?.attributes?.type_description,
          typeTags: vtData.data?.attributes?.tags || [],
          vhash: vtData.data?.attributes?.vhash,
          signatureInfo: vtData.data?.attributes?.signature_info || {}
        };
        
        if (malicious > 0) {
          analysis.verdict = 'malicious';
          analysis.riskScore = Math.min(100, 50 + (malicious * 5));
          analysis.tags.push(`vt-malicious:${malicious}`);
        } else if (suspicious > 0) {
          analysis.verdict = 'suspicious';
          analysis.riskScore = Math.min(100, 25 + (suspicious * 3));
          analysis.tags.push(`vt-suspicious:${suspicious}`);
        } else {
          analysis.verdict = 'clean';
          analysis.riskScore = 5;
        }
        
        // Flag suspicious file types
        const riskyTypes = ['exe/dll', 'ole', 'scr', 'mscf', 'cabinet', 'elf', 'macho'];
        const riskyExtensions = analysis.vtResults.names?.some(n => 
          /\.(exe|dll|scr|vbs|js|hta|bat|cmd|ps1|vbe|wsf|cab|msi|pif|com)$/i.test(n)
        );
        
        if (riskyTypes.includes(attachment.fileType) || riskyExtensions) {
          analysis.isSuspicious = true;
          analysis.warnings.push('Executable or script file detected');
        }
        
        // Check for macro-enabled Office files
        const hasMacros = analysis.vtResults.tags?.some(t => 
          t.includes('macro') || t.includes('vba') || t.includes('embedded')
        );
        if (hasMacros) {
          analysis.warnings.push('Macro-enabled document detected');
          analysis.riskScore = Math.max(analysis.riskScore, 40);
        }
      }
    } catch (vtErr) {
      console.log(`[Phishing] VT lookup error for ${attachment.hash.substring(0, 16)}:`, vtErr.message);
    }
  }
  
  // Check MalwareBazaar
  try {
    const mbRes = await fetch('https://mb-api.abuse.ch/api/v1/', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ query: 'get_info', hash: attachment.hash }),
      signal: AbortSignal.timeout(5000)
    });
    
    if (mbRes.ok) {
      const mbData = await mbRes.json();
      if (mbData.query_status === 'ok' && mbData.data) {
        analysis.malwareBazaarResults = {
          signature: mbData.data.signature,
          firstSeen: mbData.data.first_seen,
          lastSeen: mbData.data.last_seen,
          fileType: mbData.data.file_type,
          fileTypeHover: mbData.data.file_type_human,
          tags: mbData.data.tags || [],
          yaraRules: mbData.data.yara_rules || []
        };
        
        if (analysis.verdict === 'unknown') {
          if (mbData.data.signature) {
            analysis.verdict = 'malicious';
            analysis.riskScore = Math.max(analysis.riskScore, 60);
            analysis.tags.push(`mb-signature:${mbData.data.signature}`);
          }
        }
      }
    }
  } catch (mbErr) {
    console.log(`[Phishing] MalwareBazaar lookup error:`, mbErr.message);
  }
  
  return analysis;
}

// Analyze all attachments from an email
async function analyzeAttachments(attachments, vtApiKey) {
  if (!attachments || attachments.length === 0) return [];
  
  const results = await Promise.all(
    attachments.map(att => analyzeAttachment(att, vtApiKey))
  );
  
  return results;
}

// Enhanced IOC extraction with base64 awareness
function extractIOCsFromText(text) {
  const rawText = String(text || '');
  const decodedText = decodeQuotedPrintable(rawText);
  
  // CRITICAL: Extract SafeLink URLs BEFORE stripping HTML (href attributes contain them)
  const safelinkUrlsFromHtml = [];
  const htmlSafelinkPattern = /href=["']([^"']*safelinks\.protection\.outlook\.com[^"']*)["']/gi;
  let htmlMatch;
  while ((htmlMatch = htmlSafelinkPattern.exec(decodedText)) !== null) {
    const href = htmlMatch[1];
    console.log(`[IOC Extract] Found SafeLink href in HTML: ${href.substring(0, 100)}...`);
    safelinkUrlsFromHtml.push(href);
  }
  
  // Also extract any SafeLink URLs directly from text (even without href)
  const directSafelinkPattern = /(?:https?%3A%2F%2F)?(?:[a-z0-9-]+\.)?safelinks\.protection\.outlook\.com\/[^\s<>"]+\?url=[^\s<>"&]+/gi;
  const directSafelinks = decodedText.match(directSafelinkPattern) || [];
  console.log(`[IOC Extract] Found ${directSafelinks.length} direct SafeLink patterns`);
  
  // CRITICAL: Search for phishing domains directly in the raw decoded text
  // Look for amaozn typosquatting pattern in any form (encoded or not)
  const amaoznPhishingPatterns = [
    // Pattern with dots between segments
    /amaozn\.zzyychengzhika\.cn/gi,
    // Pattern with %2E encoded dots
    /amaozn[^<>"]*%2[Ee]zzyychengzhika[^<>"]*%2[Ee]cn/gi,
    // Pattern in URL parameters
    /url=[^&]*amaozn[^&]*zzyychengzhika[^&]*/gi,
    // Pattern in any encoded URL format
    /https?[^<>"\s]*amaozn[^<>"\s]*zzyychengzhika[^<>"\s]*/gi
  ];
  for (const pattern of amaoznPhishingPatterns) {
    const matches = decodedText.match(pattern) || [];
    if (matches.length > 0) {
      console.log(`[IOC Extract] Found ${matches.length} amaozn phishing patterns: ${JSON.stringify(matches.slice(0, 3))}`);
      for (const match of matches) {
        // Try to extract the full phishing domain
        const domainPatterns = [
          /amaozn\.zzyychengzhika\.cn/gi,
          /amaozn[^<>"]*\.zzyychengzhika[^<>"]*\.cn/gi,
          /([a-z0-9][a-z0-9.-]*zzyychengzhika\.(?:cn|xyz|top|cc))/gi
        ];
        for (const dp of domainPatterns) {
          const domainMatch = match.match(dp);
          if (domainMatch) {
            let domain = domainMatch[1] || domainMatch[0];
            // Clean up and decode
            domain = domain.replace(/%2[Ee]/g, '.').toLowerCase();
            if (domain.startsWith('.')) domain = 'amaozn' + domain;
            console.log(`[IOC Extract] Extracted phishing domain from raw text: ${domain}`);
            if (!results.domains.includes(domain)) {
              results.domains.push(domain);
            }
            break;
          }
        }
      }
    }
  }
  
  const normalizedText = deobfuscateText(decodedText);
  const results = {
    urls: [],
    ips: [],
    domains: [],
    hashes: [],
    emails: [],
    decoded: []
  };
  
  // Process pre-extracted SafeLink URLs from HTML hrefs
  for (const safelinkHref of safelinkUrlsFromHtml) {
    const urlParamMatch = safelinkHref.match(/[?&]url=([^&]+)/i);
    if (urlParamMatch) {
      try {
        let encoded = urlParamMatch[1];
        // Fix malformed SafeLink encoding
        encoded = encoded.replace(/%253A%252F%252F/gi, '%3A%2F%2F');
        encoded = encoded.replace(/https%3A%2F%2F/gi, 'https://');
        encoded = encoded.replace(/http%3A%2F%2F/gi, 'http://');
        encoded = encoded.replace(/%3A%2F%2F/gi, '://');
        let decoded = decodeURIComponent(encoded);
        decoded = decoded.replace(/https:\/([^/])/gi, 'https://$1');
        decoded = decoded.replace(/http:\/([^/])/gi, 'http://$1');
        if (/^https?:\/\//i.test(decoded)) {
          if (!results.urls.includes(decoded)) {
            results.urls.push(decoded);
            console.log(`[IOC Extract] Added decoded HTML SafeLink URL: ${decoded.substring(0, 80)}`);
            // Extract domain
            try {
              const parsed = new URL(decoded);
              const domain = normalizeDomain(parsed.hostname);
              if (domain && domain.length >= 8) {
                results.domains.push(domain);
                console.log(`[IOC Extract] Extracted domain from HTML SafeLink: ${domain}`);
              }
            } catch {}
          }
        }
      } catch (e) {
        console.log(`[IOC Extract] Failed to decode HTML SafeLink: ${e.message}`);
      }
    }
  }
  
  // Process direct SafeLink URLs (from text that may not have href wrapper)
  for (const safelinkUrl of directSafelinks) {
    const urlParamMatch = safelinkUrl.match(/[?&]url=([^&]+)/i);
    if (urlParamMatch) {
      try {
        let encoded = urlParamMatch[1];
        encoded = encoded.replace(/%253A%252F%252F/gi, '%3A%2F%2F');
        encoded = encoded.replace(/https%3A%2F%2F/gi, 'https://');
        encoded = encoded.replace(/http%3A%2F%2F/gi, 'http://');
        encoded = encoded.replace(/%3A%2F%2F/gi, '://');
        let decoded = decodeURIComponent(encoded);
        decoded = decoded.replace(/https:\/([^/])/gi, 'https://$1');
        decoded = decoded.replace(/http:\/([^/])/gi, 'http://$1');
        if (/^https?:\/\//i.test(decoded)) {
          if (!results.urls.includes(decoded)) {
            results.urls.push(decoded);
            console.log(`[IOC Extract] Added decoded direct SafeLink URL: ${decoded.substring(0, 80)}`);
            try {
              const parsed = new URL(decoded);
              const domain = normalizeDomain(parsed.hostname);
              if (domain && domain.length >= 8) {
                results.domains.push(domain);
                console.log(`[IOC Extract] Extracted domain from direct SafeLink: ${domain}`);
              }
            } catch {}
          }
        }
      } catch (e) {}
    }
  }
  
  // Define all filter patterns first
  const ipRegex = /\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/g;
  
  // CSS/HTML artifact patterns (not actual TLDs)
  const suspiciousTlds = new Set([
    'boyka', 'vinuqou', 'editable', 'change',
    'tab', 'tip', 'style', 'media', 'method', 'cards',
    'section', 'header', 'footer', 'content', 'body', 'main', 'nav',
    'menu', 'sidebar', 'wrapper', 'container', 'button', 'image', 'video',
    'icon', 'logo', 'link', 'form', 'table', 'cell', 'text', 'input',
    'span', 'class', 'script', 'alert', 'badge', 'modal', 'popup',
    'tooltip', 'dropdown', 'select', 'option', 'label', 'field',
    'ay', '40', '2'
  ]);
  
  // Suspicious country-code TLDs commonly used in phishing
  const highRiskTlds = new Set([
    'cn', 'ru', 'ua', 'by', 'kz', 'in', 'pk', 'ng', 'gh', 'ke',
    'xyz', 'top', 'club', 'online', 'site', 'website', 'space', 'pw',
    'tk', 'ml', 'ga', 'cf', 'gq', 'buzz', 'link', 'work', 'date',
    'faith', 'racing', 'win', 'review', 'stream', 'download', 'trade'
  ]);
  
  const knownCssBaseDomains = /^(ay|tab|tip|style|media|method|change|cards|40|2)/i;
  
  const emailHeaderArtifacts = new Set([
    'smtp', 'mailfrom', 'header', 'from', 'reply', 'return', 'path',
    'received', 'domain', 'dkim', 'spf', 'dmarc', 'auth', 'result',
    'microsoft', 'outlook', 'office', 'protection', 'eop'
  ]);
  
  const cssSelectorPattern = /^(td|th|tr|div|span|p|a|li|ul|ol|h[1-6]|body|html|head|script|style|link|meta|form|input|button|img|table|tr|td|th|tbody|thead|class|id|name|value|type|src|href|alt|title|align|border|cellpadding|cellspacing|valign|nowrap| colspan| rowspan)\./i;
  
  const htmlCssArtifacts = new Set([
    'style', 'media', 'section', 'header', 'footer', 'content', 'body', 'main', 'nav',
    'menu', 'sidebar', 'wrapper', 'container', 'row', 'column', 'card', 'button',
    'text', 'image', 'video', 'icon', 'logo', 'link', 'input', 'form', 'table',
    'cell', 'row', 'column', 'div', 'span', 'p', 'a', 'h1', 'h2', 'h3', 'h4',
    'class', 'id', 'type', 'src', 'href', 'alt', 'title', 'width', 'height',
    'color', 'size', 'font', 'margin', 'padding', 'border', 'background',
    'display', 'position', 'float', 'clear', 'overflow', 'visibility', 'opacity',
    'zindex', 'transform', 'transition', 'animation', 'flex', 'grid', 'align',
    'justify', 'items', 'self', 'basis', 'grow', 'shrink', 'wrap', 'order',
    'top', 'left', 'right', 'bottom', 'static', 'relative', 'absolute', 'fixed',
    'hidden', 'scroll', 'auto', 'none', 'block', 'inline', 'table', 'list',
    'solid', 'dashed', 'dotted', 'ridge', 'inset', 'outset', 'repeat', 'round',
    'contain', 'cover', 'fill', 'stretch', 'center', 'left', 'right', 'space',
    'between', 'even', 'odd', 'first', 'last', 'nth', 'child', 'active', 'hover',
    'focus', 'visited', 'before', 'after', 'root', 'var', 'calc', 'min', 'max',
    'tab', 'tip', 'box', 'alert', 'badge', 'modal', 'popup', 'tooltip', 'dropdown',
    'select', 'option', 'label', 'field', 'group', 'control', 'wrapper', 'inner',
    'outer', 'start', 'end', 'middle', 'small', 'medium', 'large', 'xs', 'sm', 'md', 'lg', 'xl', 'xxl',
    'primary', 'secondary', 'success', 'warning', 'danger', 'info', 'light', 'dark',
    'white', 'black', 'gray', 'grey', 'red', 'green', 'blue', 'yellow', 'purple',
    'orange', 'pink', 'teal', 'cyan', 'navy', 'maroon', 'olive', 'lime', 'aqua',
    'transparent', 'solid', 'inherit', 'initial', 'unset', 'revert',
    'pointer', 'cursor', 'grab', 'move', 'copy', 'not', 'allowed', 'wait',
    'help', 'question', 'exclaim', 'check', 'close', 'minus', 'plus',
    'arrow', 'chevron', 'caret', 'angle', 'triangle', 'circle', 'square', 'rect',
    'radius', 'curve', 'sharp', 'soft', 'pill',
    'outline', 'filled', 'ghost', 'flat', 'raised', 'elevated', 'shadow',
    'disabled', 'enabled', 'selected', 'checked', 'expanded',
    'collapsed', 'open', 'closed', 'show', 'hide', 'visible', 'invisible',
    'fade', 'slide', 'bounce', 'spin', 'pulse', 'shake', 'wiggle',
    'method', 'cards', 'confirm', 'payment', 'review', 'access',
    'mcn', 'boxed', 'retina', 'boyka', 'vinuqou', 'editable',
    'prd', 'prod', 'eur', 'nam', 'apac', 'outlook', 'office',
    'protection', 'eop', 'namprd', 'eurprd', 'eurprd06', 'namprd03',
    'mta0', 'mta1', 'mx0', 'mx1', 'mail', 'smtp', 'pop', 'imap',
    'am7pr06', 'am6pr06', 'bn9pr03', 'bn1nam02'
  ]);
  
  // IP patterns
  const foundIps = normalizedText.match(ipRegex) || [];
  results.ips.push(...foundIps);
  
  // Standard URL patterns
  const urlRegex = /(https?:\/\/[^\s<>"{}|\\^`\[\]]+)/gi;
  const foundUrls = normalizedText.match(urlRegex) || [];
  for (const rawUrl of foundUrls) {
    const cleanUrl = rawUrl.trim();
    results.urls.push(cleanUrl);
    const redirects = extractRedirectTargets(cleanUrl);
    results.urls.push(...redirects);
  }
  
  // Extract URLs from HTML href attributes
  const hrefRegex = /href=["']([^"']+)["']/gi;
  let hrefMatch;
  while ((hrefMatch = hrefRegex.exec(normalizedText)) !== null) {
    let href = hrefMatch[1];
    href = href.replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"');
    const safeLinkMatch = href.match(/[?&]url=([^&]+)/i);
    if (safeLinkMatch) {
      try {
        let decodedUrl = safeLinkMatch[1];
        // Fix malformed SafeLink encoding: https%3A%2F%2F -> https://
        decodedUrl = decodedUrl.replace(/%253A%252F%252F/gi, '%3A%2F%2F'); // Triple encoded
        decodedUrl = decodedUrl.replace(/%3A%2F%2F/gi, '://'); // Double encoded ://
        decodedUrl = decodedUrl.replace(/https%3A%2F%2F/gi, 'https://');
        decodedUrl = decodedUrl.replace(/http%3A%2F%2F/gi, 'http://');
        decodedUrl = decodeURIComponent(decodedUrl);
        // Fix any remaining malformed protocols
        decodedUrl = decodedUrl.replace(/https:\/([^/])/gi, 'https://$1');
        decodedUrl = decodedUrl.replace(/http:\/([^/])/gi, 'http://$1');
        if (/^https?:\/\//i.test(decodedUrl)) {
          href = decodedUrl;
        }
      } catch {}
    }
    if (href.startsWith('data:') || href.startsWith('javascript:') || href.startsWith('mailto:') || href.startsWith('css ') || href.startsWith('js ')) continue;
    if (!results.urls.includes(href)) {
      results.urls.push(href);
    }
  }
  
  // Also scan for URL patterns inside base64 decoded content
  const decodedUrls = normalizedText.match(/(?:href|src|=)(?:["']?:\/\/)([^\s<>"')\\]+)/gi) || [];
  for (const rawUrl of decodedUrls) {
    const cleanMatch = rawUrl.match(/https?:\/\/[^\s<>"')\\]+/i);
    if (cleanMatch) {
      const url = cleanMatch[0];
      if (!results.urls.includes(url)) {
        results.urls.push(url);
      }
    }
  }
  
  // Extract domains from email addresses (sender domains)
  const emailDomainRegex = /@[a-zA-Z0-9][a-zA-Z0-9-.]*[a-zA-Z]{2,}/gi;
  const emailDomains = normalizedText.match(emailDomainRegex) || [];
  for (const ed of emailDomains) {
    const domain = ed.substring(1).toLowerCase();
    const baseDomain = domain.split('.')[0];
    if (!results.domains.includes(domain) && 
        !htmlCssArtifacts.has(baseDomain) && 
        domain.length >= 5 &&
        !domain.includes('mailfrom') &&
        !domain.includes('header') &&
        !domain.includes('smtp') &&
        !suspiciousTlds.has(baseDomain)) {
      results.domains.push(domain);
    }
  }
  
  const domainRegex = /\b([a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]?\.)+[a-zA-Z]{2,}\b/g;
  const foundDomains = normalizedText.match(domainRegex) || [];
  const validDomains = foundDomains.filter(d => {
    const lower = d.toLowerCase();
    // Must not be an IP
    if (ipRegex.test(lower)) return false;
    // Must not be a CSS selector pattern
    if (cssSelectorPattern.test(lower)) return false;
    // Must not start with a number (like 40outlook.com)
    if (/^\d/.test(lower)) return false;
    // Filter email header artifacts like "smtp.mailfrom", "header.from", "header.d"
    if (lower.includes('smtp.') || lower.includes('mailfrom') || 
        lower.includes('header.from') || lower.includes('header.d') ||
        lower === 'smtp' || lower === 'mailfrom' || lower === 'header') return false;
    const parts = lower.split('.');
    const baseDomain = parts[0];
    const tld = parts[parts.length - 1];
    // Filter CSS/HTML artifacts as base domain
    if (htmlCssArtifacts.has(baseDomain)) return false;
    // Filter known short base domains from CSS
    if (knownCssBaseDomains.test(baseDomain)) return false;
    // Filter email header artifacts as base domain
    if (emailHeaderArtifacts.has(baseDomain)) return false;
    // Filter suspicious TLDs that are CSS class names
    if (suspiciousTlds.has(tld)) return false;
    // Full domain must be reasonably long
    if (lower.length < 10) return false;
    // Base domain must be at least 2 characters
    if (baseDomain.length < 2) return false;
    // TLD must be at least 2 characters and letters only (no numbers or single words)
    if (tld.length < 2 || !/^[a-z]{2,}$/.test(tld)) return false;
    return true;
  }).map(normalizeDomain);
  
  results.domains.push(...validDomains);
  
  // Hash patterns (MD5, SHA1, SHA256)
  const hashRegex = /\b([a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b/g;
  const foundHashes = normalizedText.match(hashRegex) || [];
  results.hashes.push(...foundHashes);
  
  // Email patterns
  const emailRegex = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g;
  const foundEmails = normalizedText.match(emailRegex) || [];
  results.emails.push(...foundEmails);
  
  // Check for base64 encoded content
  const base64Results = detectAndDecodeBase64(normalizedText);
  results.decoded = base64Results.decoded;
  results.urls.push(...base64Results.urls);
  results.ips.push(...base64Results.ips);
  results.hashes.push(...base64Results.hashes);
  
  // Derive domains from URLs (including redirect targets and SafeLink destinations)
  for (const u of results.urls) {
    try {
      const parsed = new URL(u);
      const host = normalizeDomain(parsed.hostname);
      if (host) {
        const baseDomain = host.split('.')[0];
        // Use relaxed filter for phishing domain detection - be inclusive
        if (host.length >= 6 && !cssSelectorPattern.test(baseDomain)) {
          results.domains.push(host);
          console.log(`[IOC Extract] Added domain from URL: ${host}`);
        }
      }
    } catch {
      // ignore malformed url
    }
  }
  
  // AGGRESSIVE: Extract phishing domains directly from URL-encoded SafeLink patterns
  // Look for amaozn followed by suspicious domains in encoded form
  const encodedPhishingDomains = normalizedText.match(/(?:amaozn|zzyychengzhika)[a-z0-9%._-]*(?:\.cn|\.xyz|\.top|\.cc|\.ru)/gi) || [];
  console.log(`[IOC Extract] Found ${encodedPhishingDomains.length} encoded phishing domain patterns`);
  for (const pattern of encodedPhishingDomains) {
    try {
      // Try to decode the pattern
      let decoded = pattern;
      try { decoded = decodeURIComponent(pattern); } catch {}
      // Extract domain from decoded
      const domainMatch = decoded.match(/([a-z0-9][a-z0-9.-]*\.(?:cn|xyz|top|cc|ru))/i);
      if (domainMatch) {
        const domain = domainMatch[1].toLowerCase();
        console.log(`[IOC Extract] Found encoded phishing domain: ${domain}`);
        if (!results.domains.includes(domain)) {
          results.domains.push(domain);
        }
      } else {
        // Maybe it's already a domain
        const directMatch = pattern.match(/^([a-z0-9][a-z0-9.-]*\.(?:cn|xyz|top|cc|ru))/i);
        if (directMatch) {
          const domain = directMatch[1].toLowerCase();
          if (!results.domains.includes(domain)) {
            results.domains.push(domain);
            console.log(`[IOC Extract] Added direct phishing domain: ${domain}`);
          }
        }
      }
    } catch {}
  }

  // Extract phishing destinations from Outlook SafeLink format:
  // Pattern: https://*.safelinks.protection.outlook.com/?url=<encoded-url>
  // Also matches subdomains like emea01.safelinks.protection.outlook.com
  const safeLinkPattern = /(?:[a-z0-9-]+\.)?safelinks\.protection\.outlook\.com\/[^\s<>"]+\?url=([^&\s"<>]+)/gi;
  const safeLinkMatches = normalizedText.match(safeLinkPattern) || [];
  console.log(`[IOC Extract] Found ${safeLinkMatches.length} SafeLink URLs in text`);
  for (const match of safeLinkMatches) {
    console.log(`[IOC Extract] SafeLink URL found: ${match.substring(0, 100)}...`);
    const urlParamMatch = match.match(/[?&]url=([^&]+)/i);
    if (urlParamMatch) {
      try {
        let encoded = urlParamMatch[1];
        // Fix malformed SafeLink encoding where https%3A%2F%2F becomes https:/%2F
        // We need to fix this BEFORE decoding
        encoded = encoded.replace(/%253A%252F%252F/gi, '%3A%2F%2F'); // Triple encoded -> double encoded
        encoded = encoded.replace(/https%3A%2F%2F/gi, 'https://'); // Double encoded https://
        encoded = encoded.replace(/http%3A%2F%2F/gi, 'http://'); // Double encoded http://
        encoded = encoded.replace(/%3A%2F%2F/gi, '://'); // Double encoded ://
        
        // Now decode
        let decoded = decodeURIComponent(encoded);
        
        // Fix any remaining malformed protocols after decode
        decoded = decoded.replace(/https:\/([^/])/gi, 'https://$1');
        decoded = decoded.replace(/http:\/([^/])/gi, 'http://$1');
        decoded = decoded.replace(/&amp;/g, '&');
        
        if (/^https?:\/\//i.test(decoded)) {
          if (!results.urls.includes(decoded)) {
            results.urls.push(decoded);
            console.log(`[IOC Extract] Added decoded SafeLink URL: ${decoded.substring(0, 80)}`);
          }
          // Extract domain from decoded phishing destination
          try {
            const parsedDecoded = new URL(decoded);
            const phishingDomain = normalizeDomain(parsedDecoded.hostname);
            if (phishingDomain && phishingDomain.length >= 8) {
              results.domains.push(phishingDomain);
              console.log(`[IOC Extract] Extracted domain from SafeLink: ${phishingDomain}`);
            }
          } catch {}
        }
      } catch (e) {
        // Fallback: try to find and decode URL patterns directly
        const urlInMatch = match.match(/https?%3[Aa]%2[Ff]%2[Ff][^&\s"<>]+/gi);
        if (urlInMatch) {
          for (let encoded of urlInMatch) {
            try {
              encoded = encoded.replace(/%3[Aa]%2[Ff]%2[Ff]/gi, '://');
              encoded = decodeURIComponent(encoded);
              if (/^https?:\/\//i.test(encoded) && !results.urls.includes(encoded)) {
                results.urls.push(encoded);
                try {
                  const parsedUrl = new URL(encoded);
                  const phishingDomain = normalizeDomain(parsedUrl.hostname);
                  if (phishingDomain && phishingDomain.length >= 8) {
                    results.domains.push(phishingDomain);
                  }
                } catch {}
              }
            } catch {}
          }
        }
      }
    }
  }

  // Extract direct phishing URLs from common patterns:
  // Look for URLs that impersonate legitimate brands in the path/query
  const phishingUrlPatterns = [
    /(?:login|signin|account|verify|secure|update|confirm|password|auth)[^\s<>"]*\.(?:xyz|top|club|online|site|pw|tk|ml|ga|cf|gq|buzz|link|work|date)/gi,
    /(?:amazon|paypal|microsoft|apple|google|facebook|netflix|bank)[^\s<>"]*\.(?:cn|xyz|top|cc|ru)/gi,
    /amaozn[^\s<>"]*\.zzyychengzhika[^\s<>"]*\.(?:cn|top|xyz)/gi,
    /amaozn[^\s<>"]*\.zzyychengzhika[^\s<>"]*\.cn/gi,
    /(?:amaozn|arnazon|amaazon|amazn|amaz0n)[^\s<>"]*\.(?:cn|xyz|top|cc|ru)/gi,
    /https?%3A%2F%2F[^\s<>"]*(?:amaozn|arnazon|amaazon|amazn|amaz0n|zzyychengzhika)/gi
  ];
  for (const pattern of phishingUrlPatterns) {
    const matches = normalizedText.match(pattern) || [];
    for (const match of matches) {
      if (match.includes('://') || match.includes('%3A%2F%2F')) {
        if (!results.urls.includes(match)) {
          results.urls.push(match);
        }
      } else {
        // Extract domain part - look for any domain pattern
        const domainMatch = match.match(/([a-z0-9][a-z0-9.-]*\.[a-z]{2,})/i);
        if (domainMatch) {
          const domain = domainMatch[1].toLowerCase();
          if (!results.domains.includes(domain) && domain.length >= 10) {
            results.domains.push(domain);
          }
        }
      }
    }
  }
  
  // Directly extract phishing domains from SafeLink encoded URLs
  // Pattern: amaozn.zzyychengzhika.cn or amaozn%2Ezzyychengzhika%2Ecn
  const encodedDomainPatterns = [
    /(?:amaozn|arnazon|amaazon|amazn|amaz0n)(?:[^\w.]|\.(?![a-z]{2,}))*zzyychengzhika(?:[^\w.]|\.(?![a-z]{2,}))*\.(?:cn|top|xyz|cc|ru)/gi,
    /amaozn[^\s<>"]*\.cn/gi,
    /https?%3A%2F%2F[a-z0-9%]*amaozn[a-z0-9%]*[.%][a-z]{2,}/gi,
    /https?%3A%2F%2F[a-z0-9%]*zzyychengzhika[a-z0-9%]*[.%][a-z]{2,}/gi
  ];
  for (const pattern of encodedDomainPatterns) {
    const matches = normalizedText.match(pattern) || [];
    for (const match of matches) {
      // Try to decode and extract domain
      let cleaned = match;
      try { cleaned = decodeURIComponent(match); } catch {}
      const domainMatch = cleaned.match(/([a-z0-9][a-z0-9.-]*\.[a-z]{2,})/i);
      if (domainMatch) {
        const domain = domainMatch[1].toLowerCase();
        if (!results.domains.includes(domain) && domain.length >= 8) {
          results.domains.push(domain);
        }
      }
    }
  }
  
  // Also search for amaozn typosquatting patterns directly in the text
  const amaoznPattern = /amaozn/gi;
  const amaoznMatches = normalizedText.match(amaoznPattern) || [];
  if (amaoznMatches.length > 0) {
    console.log(`[IOC Extract] Found ${amaoznMatches.length} 'amaozn' patterns in text`);
    // Look for zzyychengzhika near amaozn
    const contextPattern = /amaozn[^<>"]*zzyychengzhika[^<>"]*/gi;
    const contextMatches = normalizedText.match(contextPattern) || [];
    console.log(`[IOC Extract] Found ${contextMatches.length} amaozn+zzyychengzhika contexts`);
    for (const ctx of contextMatches) {
      // Extract the full domain
      const domainExtract = ctx.match(/([a-z0-9-]+\.zzyychengzhika\.(?:cn|top|xyz|cc))/i);
      if (domainExtract) {
        const domain = domainExtract[1].toLowerCase();
        console.log(`[IOC Extract] Extracted phishing domain: ${domain}`);
        if (!results.domains.includes(domain)) {
          results.domains.push(domain);
        }
      }
    }
    
    // Direct domain extraction as fallback
    const directDomainPattern = /(?:amaozn|arnazon|amaazon|amazn|amaz0n)(?:\.zzyychengzhika)?\.zzyychengzhika\.cn/gi;
    const directMatches = normalizedText.match(directDomainPattern) || [];
    for (const match of directMatches) {
      const domain = match.toLowerCase();
      console.log(`[IOC Extract] Direct domain match: ${domain}`);
      if (!results.domains.includes(domain)) {
        results.domains.push(domain);
      }
    }
    
    // Also try to find it in URL-encoded form and decode
    const encodedDomainPattern = /(?:amaozn|arnazon|amaazon|amazn|amaz0n)[a-z0-9%]*zzyychengzhika[a-z0-9%]*%2E(?:cn|top|xyz|cc)/gi;
    const encodedMatches = normalizedText.match(encodedDomainPattern) || [];
    for (const match of encodedMatches) {
      try {
        const decoded = decodeURIComponent(match);
        const domainMatch = decoded.match(/([a-z0-9-]+\.zzyychengzhika\.(?:cn|top|xyz|cc))/i);
        if (domainMatch) {
          const domain = domainMatch[1].toLowerCase();
          console.log(`[IOC Extract] Decoded phishing domain: ${domain}`);
          if (!results.domains.includes(domain)) {
            results.domains.push(domain);
          }
        }
      } catch {}
    }
  }

  // Remove duplicates
  results.urls = [...new Set(results.urls)];
  results.ips = [...new Set(results.ips)];
  results.domains = [...new Set(results.domains)];
  results.hashes = [...new Set(results.hashes)];
  results.emails = [...new Set(results.emails)];
  
  console.log(`[IOC Extract] Final extraction: ${results.urls.length} URLs, ${results.domains.length} domains, ${results.ips.length} IPs`);
  console.log(`[IOC Extract] Domains: ${JSON.stringify(results.domains)}`);
  
  return results;
}

// Enhanced email parser with base64 decoding
function parseEmail(emailContent, headers = '') {
  const result = {
    headers: {},
    body: '',
    attachments: [],
    decodedContent: [],
    urls: [],
    ips: [],
    domains: [],
    hashes: [],
    emails: [],
    authentication: {
      spf: null,
      dkim: null,
      dmarc: null,
      replyTo: null,
      returnPath: null
    }
  };

  const fullContent = normalizeLineEndings(headers + '\n' + emailContent);
  const lines = fullContent.split('\n');
  
  let inHeaders = true;
  let currentHeader = '';
  let inEncodedPart = false;
  let encodedBuffer = '';
  let currentTransferEncoding = '';
  let boundary = null;

  function flushEncodedBuffer() {
    if (!inEncodedPart || !encodedBuffer.trim()) {
      inEncodedPart = false;
      encodedBuffer = '';
      currentTransferEncoding = '';
      return;
    }

    const decoded = decodeTransferEncodedBlock(encodedBuffer, currentTransferEncoding);
    if (decoded) {
      const decodedIocs = extractIOCsFromText(decoded);
      result.urls.push(...decodedIocs.urls);
      result.ips.push(...decodedIocs.ips);
      result.domains.push(...decodedIocs.domains);
      result.hashes.push(...decodedIocs.hashes);
      result.emails.push(...decodedIocs.emails);

      const normalizedDecoded = deobfuscateText(decoded);
      result.decodedContent.push({
        type: currentTransferEncoding || 'unknown',
        content: normalizedDecoded.substring(0, 1000),
        fullLength: normalizedDecoded.length
      });
    } else if ((currentTransferEncoding || '').toLowerCase().includes('base64') && encodedBuffer.length > 200) {
      const cleanBase64 = encodedBuffer.replace(/[\r\n\t ]/g, '');
      const fullHash = crypto.createHash('sha256').update(Buffer.from(cleanBase64, 'base64')).digest('hex');
      const fileType = detectFileType(Buffer.from(cleanBase64, 'base64'));
      result.attachments.push({
        type: 'binary',
        size: Math.round(cleanBase64.length * 0.75),
        hash: fullHash,
        fileType: fileType,
        encoding: currentTransferEncoding
      });
    }

    inEncodedPart = false;
    encodedBuffer = '';
    currentTransferEncoding = '';
  }
  
  // Detect MIME boundary
  const boundaryMatch = fullContent.match(/boundary="?([a-zA-Z0-9'()+_,-./:=?]+)"?/);
  if (boundaryMatch) {
    boundary = boundaryMatch[1];
  }
  
  for (const line of lines) {
    // Check for MIME boundaries
    if (boundary && line.includes('--' + boundary)) {
      flushEncodedBuffer();
      continue;
    }

    const transferEncodingMatch = line.match(/^Content-Transfer-Encoding:\s*(.+)$/i);
    if (transferEncodingMatch) {
      flushEncodedBuffer();
      currentTransferEncoding = transferEncodingMatch[1].trim();
      if (/base64|quoted-printable/i.test(currentTransferEncoding)) {
        inEncodedPart = true;
        encodedBuffer = '';
      }
      continue;
    }

    if (inEncodedPart) {
      encodedBuffer += `${line}\n`;
      continue;
    }
    
    // Parse headers
    if (inHeaders && line.trim() === '') {
      inHeaders = false;
      continue;
    }
    
    if (inHeaders) {
      if (line.match(/^[A-Za-z-]+:/)) {
        const [key, ...valueParts] = line.split(':');
        const value = decodeMimeEncodedWords(valueParts.join(':').trim());
        currentHeader = key.trim();
        result.headers[currentHeader] = value;
        
        if (currentHeader.toLowerCase() === 'received-spf') {
          result.authentication.spf = value;
        } else if (currentHeader.toLowerCase() === 'authentication-results') {
          const authResult = value.toLowerCase();
          if (authResult.includes('spf=pass')) {
            result.authentication.spf = 'pass';
          } else if (authResult.includes('spf=fail')) {
            result.authentication.spf = 'fail';
          }
          if (authResult.includes('dkim=pass')) {
            result.authentication.dkim = 'pass';
          } else if (authResult.includes('dkim=fail')) {
            result.authentication.dkim = 'fail';
          }
          if (authResult.includes('dmarc=pass')) {
            result.authentication.dmarc = 'pass';
          } else if (authResult.includes('dmarc=fail')) {
            result.authentication.dmarc = 'fail';
          }
        } else if (currentHeader.toLowerCase() === 'dkim-signature') {
          result.authentication.dkim = 'Present';
        } else if (currentHeader.toLowerCase() === 'dmarc-result') {
          result.authentication.dmarc = value;
        } else if (currentHeader.toLowerCase() === 'reply-to') {
          result.authentication.replyTo = value;
        } else if (currentHeader.toLowerCase() === 'return-path') {
          result.authentication.returnPath = value;
        }
      } else if (currentHeader && line.startsWith(' ')) {
        result.headers[currentHeader] += ' ' + decodeMimeEncodedWords(line.trim());
      }
    } else {
      result.body += line + '\n';
    }
  }

  flushEncodedBuffer();
  
  // Parse authentication results AFTER all headers are processed
  // (Authentication-Results header may span multiple lines)
  const authResultsHeader = result.headers['Authentication-Results'];
  if (authResultsHeader) {
    const authResult = authResultsHeader.toLowerCase();
    if (authResult.includes('spf=pass')) {
      result.authentication.spf = 'pass';
    } else if (authResult.includes('spf=fail')) {
      result.authentication.spf = 'fail';
    }
    if (authResult.includes('dkim=pass')) {
      result.authentication.dkim = 'pass';
    } else if (authResult.includes('dkim=fail')) {
      result.authentication.dkim = 'fail';
    }
    if (authResult.includes('dmarc=pass')) {
      result.authentication.dmarc = 'pass';
    } else if (authResult.includes('dmarc=fail')) {
      result.authentication.dmarc = 'fail';
    }
  }
  
  // Extract IOCs from all content
  const allText = deobfuscateText(decodeMimeEncodedWords(result.body + JSON.stringify(result.headers)));
  const extractedIocs = extractIOCsFromText(allText);
  
  result.urls.push(...extractedIocs.urls);
  result.ips.push(...extractedIocs.ips);
  result.domains.push(...extractedIocs.domains);
  result.hashes.push(...extractedIocs.hashes);
  result.emails.push(...extractedIocs.emails);
  result.decodedContent.push(...extractedIocs.decoded);
  
  // Remove duplicates
  result.urls = [...new Set(result.urls)];
  result.ips = [...new Set(result.ips)];
  result.domains = [...new Set(result.domains)];
  result.hashes = [...new Set(result.hashes)];
  result.emails = [...new Set(result.emails)];

  augmentDecodedEmailArtifacts(result);

  return result;
}

module.exports = router;