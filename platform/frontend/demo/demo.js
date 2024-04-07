let socket = new WebSocket("ws://localhost:8765");

socket.onopen = function(e) {
    console.log("[open] Connection established");
};

socket.onmessage = function(event) {
    let data = JSON.parse(event.data); // 将JSON字符串转为字典
    console.log(`[message] Data received from server: ${JSON.stringify(data)}`);
};

socket.onerror = function(error) {
    console.log(`[error] ${error.message}`);
};

let sniffer_start = function() {
    let data = { source: "sniffer", type: "start" };
    socket.send(JSON.stringify(data))
}
let sniffer_stop = function() {
    let data = { source: "sniffer", type: "stop" };
    socket.send(JSON.stringify(data))
}