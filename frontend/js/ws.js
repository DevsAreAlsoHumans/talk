/* WebSocket du chat : cookie de session porté par l'handshake, reconnexion
   backoff, routage des blobs opaques vers decryptMessage / la UI. */

const BASE_BACKOFF_MS = 600;
const MAX_BACKOFF_MS = 30000;
const UNAUTHENTICATED_CLOSE = 4401;

export class ChatSocket {
  constructor(roomId, onMessage, onPresence, onState, onTyping, onReaction) {
    this.roomId = roomId;
    this.onMessage = onMessage;
    this.onPresence = onPresence;
    this.onState = onState;
    this.onTyping = onTyping || (() => {});
    this.onReaction = onReaction || (() => {});
    this.backoff = BASE_BACKOFF_MS;
    this.closed = false;
  }

  get connected() {
    return !!(this.ws && this.ws.readyState === WebSocket.OPEN);
  }

  url() {
    const proto = location.protocol === "https:" ? "wss" : "ws";
    return `${proto}://${location.host}/api/ws?room_id=${encodeURIComponent(this.roomId)}`;
  }

  connect() {
    this.closed = false;
    const ws = new WebSocket(this.url());
    this.ws = ws;
    ws.onopen = () => {
      this.backoff = BASE_BACKOFF_MS;
      this.onState("connecté");
    };
    ws.onmessage = (ev) => this.route(ev.data);
    ws.onclose = (ev) => {
      if (this.closed) return;
      if (ev.code === UNAUTHENTICATED_CLOSE) {
        this.onState("accès refusé : session expirée ou vous n'êtes plus membre");
        return;
      }
      this.onState("reconnexion...");
      setTimeout(() => {
        if (!this.closed) this.connect();
      }, this.backoff);
      this.backoff = Math.min(
        this.backoff * 2 + Math.floor(Math.random() * 400),
        MAX_BACKOFF_MS,
      );
    };
    ws.onerror = () => ws.close();
  }

  route(data) {
    let msg;
    try {
      msg = JSON.parse(data);
    } catch {
      return;
    }
    if (msg && msg.type === "typing") this.onTyping(msg);
    else if (msg && msg.type === "reaction") this.onReaction(msg);
    else if (msg && msg.type === "presence") this.onPresence(msg);
    else if (msg && typeof msg.payload === "string") this.onMessage(msg);
  }

  send(channelId, payload) {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify({ channel: channelId, payload }));
    }
  }

  sendTyping() {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify({ type: "typing" }));
    }
  }

  close() {
    this.closed = true;
    if (this.ws) this.ws.close(1000, "changement de salon");
  }
}