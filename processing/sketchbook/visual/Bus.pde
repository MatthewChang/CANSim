class Bus { 
  int X_START;
  int X_END;
  int Y;
  int CONN_LEN;
  int X_MID;
  color busColor;
  

  Bus(int X_START, int X_END, int Y, int CONN_LEN) { 
    this.X_START = X_START;
    this.X_END = X_END;
    this.Y = Y;
    this.CONN_LEN = CONN_LEN;
    X_MID = (X_START + X_END)/2;
    busColor = BLACK;
  }

  void display() {
    stroke(busColor);
    line(X_START, Y, X_END, Y);
    line(X_START, Y, X_START, Y - CONN_LEN);
    line(X_END, Y, X_END, Y - CONN_LEN);
    line(X_MID, Y, X_MID, Y + CONN_LEN);   
  }
  
  void setColor(color col) {
    this.busColor = col;
  }

}
