const ch = require('./modules/code-hardener');
const files = [{filename:'app.js', content: 'const express = require("express"); const app = express(); app.use(express.json()); app.get("/", (req, res) => res.send("hello")); app.listen(3000);'}];
const detection = ch.detectFramework(files);
console.log('detection:', JSON.stringify(detection));
const patches = ch.generatePatches(files, detection.framework);
console.log('patches count:', patches.length);
if (patches.length) {
  console.log('patch[0] keys:', Object.keys(patches[0]));
  console.log('patch[0]:', JSON.stringify(patches[0]).slice(0, 400));
}
