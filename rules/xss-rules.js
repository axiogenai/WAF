'use strict';

/**
 * ShieldWall WAF — Cross-Site Scripting (XSS) Rule Signatures
 *
 * Each rule object:
 *   id          – unique rule identifier (XSS-XXXX)
 *   severity    – 'critical' | 'high' | 'medium' | 'low'
 *   description – human-readable explanation
 *   pattern     – RegExp (case-insensitive where appropriate)
 */

const xssRules = [
  // ───────────────────────── Script tags ─────────────────────────
  {
    id: 'XSS-0001',
    severity: 'critical',
    description: 'Inline <script> tag',
    pattern: /<\s*script[\s>]/i,
  },
  {
    id: 'XSS-0002',
    severity: 'critical',
    description: '<script src=…> remote script inclusion',
    pattern: /<\s*script[^>]+src\s*=/i,
  },
  {
    id: 'XSS-0003',
    severity: 'high',
    description: 'Closing </script> tag (fragment injection)',
    pattern: /<\s*\/\s*script\s*>/i,
  },

  // ──────────────────── Event handler attributes ────────────────────
  {
    id: 'XSS-0010',
    severity: 'critical',
    description: 'onerror event handler',
    pattern: /\bon\s*error\s*=/i,
  },
  {
    id: 'XSS-0011',
    severity: 'critical',
    description: 'onload event handler',
    pattern: /\bon\s*load\s*=/i,
  },
  {
    id: 'XSS-0012',
    severity: 'high',
    description: 'onclick event handler',
    pattern: /\bon\s*click\s*=/i,
  },
  {
    id: 'XSS-0013',
    severity: 'high',
    description: 'onmouseover event handler',
    pattern: /\bon\s*mouse\s*over\s*=/i,
  },
  {
    id: 'XSS-0014',
    severity: 'high',
    description: 'onfocus event handler',
    pattern: /\bon\s*focus\s*=/i,
  },
  {
    id: 'XSS-0015',
    severity: 'high',
    description: 'onblur event handler',
    pattern: /\bon\s*blur\s*=/i,
  },
  {
    id: 'XSS-0016',
    severity: 'high',
    description: 'onsubmit event handler',
    pattern: /\bon\s*submit\s*=/i,
  },
  {
    id: 'XSS-0017',
    severity: 'high',
    description: 'onchange event handler',
    pattern: /\bon\s*change\s*=/i,
  },
  {
    id: 'XSS-0018',
    severity: 'high',
    description: 'Generic on<event>= handler pattern',
    pattern: /\bon(abort|animationend|beforeunload|contextmenu|dblclick|drag|dragend|dragenter|dragleave|dragover|dragstart|drop|input|invalid|keydown|keypress|keyup|mousedown|mouseenter|mouseleave|mousemove|mouseout|mouseup|paste|pointerdown|pointerup|reset|resize|scroll|select|touchstart|touchend|touchmove|transitionend|wheel)\s*=/i,
  },

  // ──────────────────── JavaScript URI schemes ────────────────────
  {
    id: 'XSS-0020',
    severity: 'critical',
    description: 'javascript: URI scheme',
    pattern: /javascript\s*:/i,
  },
  {
    id: 'XSS-0021',
    severity: 'high',
    description: 'data:text/html URI (XSS vector)',
    pattern: /data\s*:\s*text\/html/i,
  },
  {
    id: 'XSS-0022',
    severity: 'high',
    description: 'vbscript: URI scheme (IE legacy)',
    pattern: /vbscript\s*:/i,
  },

  // ──────────────────── SVG / XML / MathML injection ────────────────────
  {
    id: 'XSS-0030',
    severity: 'critical',
    description: '<svg onload=…> injection',
    pattern: /<\s*svg[^>]*on\w+\s*=/i,
  },
  {
    id: 'XSS-0031',
    severity: 'high',
    description: '<svg> tag injection',
    pattern: /<\s*svg[\s>/]/i,
  },
  {
    id: 'XSS-0032',
    severity: 'high',
    description: '<math> tag injection (MathML)',
    pattern: /<\s*math[\s>]/i,
  },
  {
    id: 'XSS-0033',
    severity: 'high',
    description: '<xml> or XML data island injection',
    pattern: /<\s*xml[\s>]/i,
  },
  {
    id: 'XSS-0034',
    severity: 'high',
    description: '<iframe> injection',
    pattern: /<\s*iframe[\s>]/i,
  },
  {
    id: 'XSS-0035',
    severity: 'high',
    description: '<embed> or <object> injection',
    pattern: /<\s*(embed|object)[\s>]/i,
  },
  {
    id: 'XSS-0036',
    severity: 'medium',
    description: '<img src=x onerror=…> pattern',
    pattern: /<\s*img[^>]+on\w+\s*=/i,
  },
  {
    id: 'XSS-0037',
    severity: 'medium',
    description: '<body onload=…> injection',
    pattern: /<\s*body[^>]+on\w+\s*=/i,
  },
  {
    id: 'XSS-0038',
    severity: 'medium',
    description: '<details/open/ontoggle> injection',
    pattern: /<\s*details[^>]+on\w+\s*=/i,
  },
  {
    id: 'XSS-0039',
    severity: 'medium',
    description: '<marquee> or <bgsound> injection (legacy)',
    pattern: /<\s*(marquee|bgsound|blink)[\s>]/i,
  },

  // ──────────────────── DOM manipulation ────────────────────
  {
    id: 'XSS-0040',
    severity: 'critical',
    description: 'document.cookie access',
    pattern: /document\s*\.\s*cookie/i,
  },
  {
    id: 'XSS-0041',
    severity: 'critical',
    description: 'document.write() call',
    pattern: /document\s*\.\s*write\s*\(/i,
  },
  {
    id: 'XSS-0042',
    severity: 'high',
    description: 'innerHTML assignment',
    pattern: /\.innerHTML\s*=/i,
  },
  {
    id: 'XSS-0043',
    severity: 'high',
    description: 'eval() call in user input',
    pattern: /\beval\s*\(/i,
  },
  {
    id: 'XSS-0044',
    severity: 'high',
    description: 'setTimeout/setInterval with string arg',
    pattern: /\b(setTimeout|setInterval)\s*\(\s*['"]/i,
  },
  {
    id: 'XSS-0045',
    severity: 'high',
    description: 'window.location manipulation',
    pattern: /window\s*\.\s*location\s*[=.]/i,
  },
  {
    id: 'XSS-0046',
    severity: 'medium',
    description: 'document.domain manipulation',
    pattern: /document\s*\.\s*domain\s*=/i,
  },
  {
    id: 'XSS-0047',
    severity: 'high',
    description: 'outerHTML assignment',
    pattern: /\.outerHTML\s*=/i,
  },
  {
    id: 'XSS-0048',
    severity: 'high',
    description: 'Function constructor call',
    pattern: /\bFunction\s*\(/i,
  },

  // ──────────────────── Encoding bypasses ────────────────────
  {
    id: 'XSS-0050',
    severity: 'high',
    description: 'Hex-encoded < (\\x3c) bypass',
    pattern: /\\x3c/i,
  },
  {
    id: 'XSS-0051',
    severity: 'high',
    description: 'Unicode-encoded < (\\u003c) bypass',
    pattern: /\\u003c/i,
  },
  {
    id: 'XSS-0052',
    severity: 'high',
    description: 'HTML entity < (&#x3C / &#60) bypass',
    pattern: /(&#x0*3[Cc];?|&#0*60;?)/,
  },
  {
    id: 'XSS-0053',
    severity: 'medium',
    description: 'HTML entity > (&#x3E / &#62) bypass',
    pattern: /(&#x0*3[Ee];?|&#0*62;?)/,
  },
  {
    id: 'XSS-0054',
    severity: 'medium',
    description: 'URL-encoded angle brackets (%3C / %3E)',
    pattern: /(%3C|%3E)/i,
  },
  {
    id: 'XSS-0055',
    severity: 'medium',
    description: 'Double URL-encoded angle brackets (%253C / %253E)',
    pattern: /(%253[Cc]|%253[Ee])/i,
  },

  // ──────────────────── Template injection ────────────────────
  {
    id: 'XSS-0060',
    severity: 'high',
    description: 'Server-side template injection: {{ expression }}',
    pattern: /\{\{.*\}\}/,
  },
  {
    id: 'XSS-0061',
    severity: 'high',
    description: 'ES6 template literal injection: ${…}',
    pattern: /\$\{[^}]+\}/,
  },
  {
    id: 'XSS-0062',
    severity: 'medium',
    description: 'Expression Language injection: #{…} or ${…}',
    pattern: /(#\{|%\{)[^}]+\}/,
  },

  // ──────────────────── Miscellaneous bypass patterns ────────────────────
  {
    id: 'XSS-0070',
    severity: 'high',
    description: 'String.fromCharCode() construction',
    pattern: /String\s*\.\s*fromCharCode\s*\(/i,
  },
  {
    id: 'XSS-0071',
    severity: 'high',
    description: 'atob() base64 decode (payload hiding)',
    pattern: /\batob\s*\(/i,
  },
  {
    id: 'XSS-0072',
    severity: 'medium',
    description: '<base href=…> injection (relative URL hijack)',
    pattern: /<\s*base[\s][^>]*href\s*=/i,
  },
  {
    id: 'XSS-0073',
    severity: 'medium',
    description: '<link rel=import> HTML import injection',
    pattern: /<\s*link[^>]+rel\s*=\s*['"]?import/i,
  },
  {
    id: 'XSS-0074',
    severity: 'medium',
    description: '<form action=javascript:> injection',
    pattern: /<\s*form[^>]+action\s*=\s*['"]?javascript/i,
  },
];

module.exports = xssRules;
