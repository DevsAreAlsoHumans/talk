function connect(path, onMessage) {
  const protocol = window.location.protocol === "https:" ? "wss" : "ws";
  const socket = new WebSocket(`${protocol}://${window.location.host}${path}`);
  socket.onmessage = (event) => onMessage(JSON.parse(event.data));
  return socket;
}

export function connectRoomSocket(roomId, onMessage) {
  return connect(`/ws/rooms/${roomId}`, onMessage);
}

export function connectNotificationsSocket(onMessage) {
  return connect("/ws/notifications", onMessage);
}
