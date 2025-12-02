const fs = require('fs');
const path = require('path');

(async function(){
  const scanDir = process.argv[2];
  const target = process.argv[3] || '';
  if (!scanDir) {
    console.error('Usage: node generate-report.js <scanDir> [target]');
    process.exit(2);
  }

  if (!fs.existsSync(scanDir)) {
    console.error('Scan directory not found:', scanDir);
    process.exit(2);
  }

  // Try to load puppeteer from backend node_modules by running this script from backend cwd.
  let puppeteer;
  try {
    puppeteer = require('puppeteer');
  } catch (e) {
    // Fallback: attempt to require from backend/node_modules sibling folder
    try {
      const altPath = path.resolve(__dirname, '..', '..', 'backend', 'node_modules', 'puppeteer');
      puppeteer = require(altPath);
    } catch (e2) {
      console.error('Puppeteer not found. Install puppeteer in the backend (npm install) or run this script from a folder where puppeteer is resolvable.');
      console.error(e.message);
      process.exit(2);
    }
  }

  const files = fs.readdirSync(scanDir).map(f => ({ name: f, ext: path.extname(f).toLowerCase() }));

  // Build a nicer HTML report
  const css = `body{font-family:Inter,Segoe UI,Arial,Helvetica,sans-serif;margin:24px;color:#1a202c}header{display:flex;align-items:center;justify-content:space-between;margin-bottom:20px}h1{color:#0b5cff}table{border-collapse:collapse;width:100%;margin-top:10px}th,td{border:1px solid #e2e8f0;padding:8px;text-align:left}th{background:#f1f5f9}pre{background:#0f172a;color:#e6f1ff;padding:12px;overflow:auto;border-radius:6px}`;

  const fileRows = files.map(f => `<tr><td>${f.name}</td><td>${f.ext}</td><td><a href="./${encodeURIComponent(f.name)}">View/Download</a></td></tr>`).join('\n');

  const html = `<!doctype html><html><head><meta charset="utf-8"><title>Scan Report</title><style>${css}</style></head><body>
  <header>
    <div>
      <h1>AWSAP Scan Report</h1>
      <div><strong>Target:</strong> ${target}</div>
    </div>
    <div>
      <div>${new Date().toISOString()}</div>
    </div>
  </header>

  <section>
    <h2>External Tool Outputs</h2>
    <table>
      <thead><tr><th>File</th><th>Type</th><th>Action</th></tr></thead>
      <tbody>
        ${fileRows}
      </tbody>
    </table>
  </section>

  <section>
    <h2>Quick Previews</h2>
    ${files.filter(f=>['.txt','.log','.xml','.html','.json'].includes(f.ext)).map(f=>{
      const content = fs.readFileSync(path.join(scanDir, f.name),'utf8');
      return `<h3>${f.name}</h3><pre>${escapeHtml(content.slice(0,5000))}</pre>`;
    }).join('\n')}
  </section>

</body></html>`;

  // Write report.html and copy text files next to it for relative links
  try {
    fs.writeFileSync(path.join(scanDir,'report.html'), html, 'utf8');
    console.log('Wrote report.html');
  } catch (e) {
    console.error('Failed to write report.html:', e.message || e);
  }

  // Launch puppeteer from this process
  try {
    const browser = await puppeteer.launch({ args: ['--no-sandbox','--disable-setuid-sandbox'] });
    const page = await browser.newPage();
    await page.setContent(html, { waitUntil: 'networkidle0' });
    const pdfBuffer = await page.pdf({ format: 'A4', printBackground: true });
    await browser.close();
    fs.writeFileSync(path.join(scanDir,'report.pdf'), pdfBuffer);
    console.log('Wrote report.pdf');
  } catch (e) {
    console.error('PDF creation failed:', e.message || e);
  }

  function escapeHtml(s){
    return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  }

})();
