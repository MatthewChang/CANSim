Bus bus;
PFont f;
BufferedReader reader;
String line;

String node0QSize = "0";
String node1QSize = "0";
String node2QSize = "0";

MessageType messageType;

int BUS_X_START = 100;
int BUS_X_END = 600;
int BUS_X_MID = (BUS_X_START + BUS_X_END)/2;
int BUS_Y = 400;
int CONNECTOR_LENGTH = 50;
int WIDTH = 700;
int HEIGHT = 700;
int NODE_SIDE_LENGTH = 50;
int AVG_LAT_Y = 100;
int TOTAL_M_Y = 50; 
String average_latency = "0";
String total_messages = "0";
color RED = color(255, 0, 0);
color BLUE = color(0, 0, 255);
color BLACK = color(0, 0, 0);
color WHITE = color(255, 255, 255);
color GREEN = color(0, 255, 0);

String node0Lat = "0";
String node0Tot = "0";

String node1Lat = "0";
String node1Tot = "0";

String node2Lat = "0";
String node2Tot = "0";

void setup() {
  size(WIDTH, HEIGHT);
  f = createFont("Arial", 16, true);
  frameRate(60);
  
  bus = new Bus(BUS_X_START, BUS_X_END, BUS_Y, CONNECTOR_LENGTH);
  reader = createReader("../../../cansim.log");
  
}

void draw() {
  background(0, 0, 0);
  bus.display();
  drawNodes(bus);
  drawNodeNames(bus);
  updateQueueSizes(bus);
  updateNodeInfo(bus);
  textAlign(RIGHT);
  fill(WHITE);
  text("Average Latency: " + average_latency, WIDTH, AVG_LAT_Y);
  text("Total Number of Messages: " + total_messages, WIDTH, TOTAL_M_Y);
  
  
  try {
    line = reader.readLine();
  } catch (IOException e) {
    e.printStackTrace();
    line = null;
  }
  if (line == null) {
    // Stop reading because of an error or file is empty
    noLoop();  
  } else {
    parseLine(line);
    
  }
}

void parseLine(String line) {
  String[] tokens = split(line, ' ');
  textFont(f, 16);  
  textAlign(LEFT);
  fill(WHITE);
  text("Timestep " + tokens[0], 0, 100);
  
  switch(MessageType.valueOf(tokens[1])) {
    case STATUS:
      if (tokens[2].equals("NODE0")) {
        node0QSize = tokens[3];
      } else if (tokens[2].equals("NODE1")) {
        node1QSize = tokens[3];
      } else {
        node2QSize = tokens[3];
      }
      break;
    case MESSAGE:
      if (tokens[2].equals("DATA")) {
        bus.setColor(RED);
      } else if (tokens[2].equals("AUTH")) {
        bus.setColor(BLUE);
      } else {
        bus.setColor(BLACK);
      }
      break;
    case BUS_HEAD:
      break;
    case SAVGLATENCY:
      average_latency = tokens[2];
      break;
    case AVGLATENCY:
    if (tokens[2].equals("NODE0")) {
        node0Lat = tokens[3];
      } else if (tokens[2].equals("NODE1")) {
        node1Lat = tokens[3];
      } else {
        node2Lat = tokens[3];
      }
      break;
    case TOTALM:
    if (tokens[2].equals("NODE0")) {
        node0Tot = tokens[3];
      } else if (tokens[2].equals("NODE1")) {
        node1Tot = tokens[3];
      } else {
        node2Tot = tokens[3];
      }
      break;
    case STOTALM:
      total_messages = tokens[2];
      break;
    case NEWCHANNELCREATION:
      break;
    default:
  }
}

void drawNodes(Bus bus) {
    rectMode(CENTER);
    rect(bus.X_START, bus.Y - bus.CONN_LEN - NODE_SIDE_LENGTH/2, NODE_SIDE_LENGTH, NODE_SIDE_LENGTH);
    rect(bus.X_END, bus.Y - bus.CONN_LEN - NODE_SIDE_LENGTH/2, NODE_SIDE_LENGTH, NODE_SIDE_LENGTH);
    rect(bus.X_MID, bus.Y + bus.CONN_LEN + NODE_SIDE_LENGTH/2, NODE_SIDE_LENGTH, NODE_SIDE_LENGTH); 
}

void drawNodeNames(Bus bus) {
  int OFFSET = 30;
  textAlign(CENTER, CENTER);
  textSize(26);
  fill(GREEN);
  text("Node 0", bus.X_START, bus.Y - bus.CONN_LEN - NODE_SIDE_LENGTH - OFFSET);
  text("Node 1", bus.X_MID, bus.Y + bus.CONN_LEN + NODE_SIDE_LENGTH + OFFSET);
  text("Node 2", bus.X_END, bus.Y - bus.CONN_LEN - NODE_SIDE_LENGTH - OFFSET);
}

void updateNodeInfo(Bus bus) {
  int OFFSET = 30;
  textAlign(CENTER, CENTER);
  textSize(18);
  fill(GREEN);
  text("Total # Messages: " + node0Tot, bus.X_START, bus.Y - bus.CONN_LEN - NODE_SIDE_LENGTH - 2*OFFSET);
  text("Total # Messages: " + node1Tot, bus.X_MID, bus.Y + bus.CONN_LEN + NODE_SIDE_LENGTH + 2*OFFSET);
  text("Total # Messages: " + node2Tot, bus.X_END, bus.Y - bus.CONN_LEN - NODE_SIDE_LENGTH - 2*OFFSET);
  
  text("Avg Latency: " + node0Lat, bus.X_START, bus.Y - bus.CONN_LEN - NODE_SIDE_LENGTH - 3*OFFSET);
  text("Avg Latency: " + node1Lat, bus.X_MID, bus.Y + bus.CONN_LEN + NODE_SIDE_LENGTH + 3*OFFSET);
  text("Avg Latency: " + node2Lat, bus.X_END, bus.Y - bus.CONN_LEN - NODE_SIDE_LENGTH - 3*OFFSET);
}

void updateQueueSizes(Bus bus) {
  textAlign(CENTER, CENTER);
  textSize(32);
  fill(BLACK);
  text(node0QSize, bus.X_START, bus.Y - bus.CONN_LEN - NODE_SIDE_LENGTH/2);
  text(node1QSize, bus.X_MID, bus.Y + bus.CONN_LEN + NODE_SIDE_LENGTH/2 );
  text(node2QSize, bus.X_END, bus.Y - bus.CONN_LEN - NODE_SIDE_LENGTH/2 );

}

