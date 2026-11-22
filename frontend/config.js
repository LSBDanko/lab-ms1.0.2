/**
 * 实验室管理系统 · 前端运行时配置
 * =============================================
 *
 * 本地开发：留空即可。
 *   - 直接打开 frontend/index.html 时，前端使用 http://127.0.0.1:8000
 *   - 通过 FastAPI 的根地址 / 打开时，前端自动使用同源 API
 *
 * GitHub Pages / 静态托管：
 *   将下面改成已经部署好的 FastAPI 公网地址，例如：
 *
 *   window.LAB_API_BASE = 'https://lab-ms-api.onrender.com';
 *
 * 注意：
 *   1. 必须包含 https:// 或 http://
 *   2. 末尾不要带 /api
 *   3. 修改后重新提交并等待 GitHub Pages 部署完成
 */
window.LAB_API_BASE = '';
