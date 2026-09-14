/* 预览页逐页截图（README 运行界面图） */
const { chromium } = require("playwright-core");

const EXE = "C:\\Users\\s1mple\\AppData\\Local\\ms-playwright\\chromium-1234\\chrome-win64\\chrome.exe";
const OUT = "C:\\Users\\s1mple\\Desktop\\AgentSafety\\aiguard\\docs\\screenshots";
const URL = "file:///C:/Users/s1mple/Desktop/AgentSafety/aiguard/preview/ui-preview.html";

(async () => {
  const browser = await chromium.launch({ executablePath: EXE, headless: true });
  const page = await browser.newPage({ viewport: { width: 1360, height: 860 }, deviceScaleFactor: 2 });
  await page.goto(URL);
  await page.waitForTimeout(900);
  const pages = ["home", "requests", "rules", "audit", "settings"];
  for (const p of pages) {
    if (p !== "home") {
      await page.click(`.rail-item[data-page="${p}"]`);
      await page.waitForTimeout(450);
    }
    await page.screenshot({ path: `${OUT}/${p}.png` });
    console.log("shot:", p);
  }
  await browser.close();
  console.log("screenshots done");
})().catch((e) => {
  console.error("FAIL:", e.message);
  process.exit(1);
});
