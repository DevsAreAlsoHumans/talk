export function connectRoomSocket(roomId, onMessage) {
  const protocol = window.location.protocol === "https:" ? "wss" : "ws";
  const socket = new WebSocket(`${protocol}://${window.location.host}/ws/rooms/${roomId}`);
  socket.onmessage = (event) => onMessage(JSON.parse(event.data));
  return socket;
}
