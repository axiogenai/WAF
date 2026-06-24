const ca = require('./modules/code-analyzer');
const result = ca.analyzeCode([{filename:'test.js', content: 'eval(userInput); var q = req.query.id; db.exec("SELECT * FROM users WHERE id=" + q);'}]);
console.log('Top-level keys:', Object.keys(result));
console.log('score:', result.score);
console.log('grade:', result.grade);
console.log('riskLevel:', result.riskLevel);
console.log('summary:', JSON.stringify(result.summary));
const items = result.findings || result.vulnerabilities || result.issues || [];
console.log('findings count:', items.length);
if (items.length) {
  const f = items[0];
  console.log('finding[0] keys:', Object.keys(f));
  console.log('finding[0]:', JSON.stringify(f).slice(0, 300));
}
