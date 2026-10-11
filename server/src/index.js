// Worker 入口。
//
// 只有一个 WebSocket 端点（`GET /`），其余路径一律 404 空 body —— 既没有指纹
// 可抓，也让旧客户端立刻失败而不是静默语义漂移。cron 只做演化与剪枝。

import { handleWebSocket, scheduled as runScheduled } from "./ws.js";

export default {
  async fetch(request, env) {
    try {
      const url = new URL(request.url);
      if (url.pathname === "/" || url.pathname === "") {
        return await handleWebSocket(request, env);
      }
      return new Response(null, { status: 404 });
    } catch {
      // 不泄露内部信息：空 body。
      return new Response(null, { status: 500 });
    }
  },

  async scheduled(event, env) {
    try {
      await runScheduled(env);
    } catch {
      // 吞掉：cron 到点会自动再跑。
    }
  },
};